#![forbid(unsafe_code)]
#![deny(warnings)]

use std::{
    ffi::OsString,
    io::{self, Write},
    os::fd::OwnedFd,
    process::ExitCode,
    rc::Rc,
    time::{SystemTime, UNIX_EPOCH},
};

use dnfast_executor::{
    ExecutorError, InheritedPlan, MountRoot, RootInputs, Staging, execute_checked_transaction,
    recover_pending_transactions, require_root_resolve_equal,
};
use serde::Serialize;

fn main() -> ExitCode {
    let arguments = match arguments() {
        Ok(arguments) => arguments,
        Err(()) => return emit(Response::failed(ExecutorError::Arguments.to_string()), 1),
    };
    match run(arguments) {
        Ok(outcome) => match outcome.response() {
            Ok(response) => emit(response, 0),
            Err(error) => emit(Response::failed(error.to_string()), 1),
        },
        Err(error) => emit(Response::failed(error.to_string()), 1),
    }
}

fn arguments() -> Result<Vec<String>, ()> {
    std::env::args_os()
        .skip(1)
        .map(OsString::into_string)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ())
}

enum Outcome {
    Aborted(dnfast_solver::CanonicalSolverPlan),
    Executed(dnfast_solver::CanonicalSolverPlan, String),
}

fn run(arguments: Vec<String>) -> Result<Outcome, ExecutorError> {
    if rustix::process::geteuid().as_raw() != 0 {
        return Err(ExecutorError::NotRoot);
    }
    let approval = match arguments.as_slice() {
        [flag, fd] if flag == "--plan-fd" && fd == "3" => Approval::Prompt,
        [flag, fd, value] if flag == "--plan-fd" && fd == "3" && value == "--assumeyes" => {
            Approval::Yes
        }
        [flag, fd, value] if flag == "--plan-fd" && fd == "3" && value == "--assumeno" => {
            Approval::No
        }
        _ => return Err(ExecutorError::Arguments),
    };
    let store = dnfast_state::JournalStore::open_system()
        .map_err(|error| ExecutorError::Plan(error.to_string()))?;
    let plan = InheritedPlan::read()?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| ExecutorError::Plan(error.to_string()))?
        .as_secs();
    let proposal = dnfast_solver::CanonicalSolverPlan::from_canonical_json(plan.bytes(), now)
        .map_err(|error| ExecutorError::Plan(error.to_string()))?;
    // librpm may turn an initial non-blocking RPMDB lock failure into an
    // unbounded wait when stdin is a TTY. Root re-solve and recovery both
    // inspect RPMDB before approval, so temporarily make that whole boundary
    // non-interactive, then restore the exact inherited stdin for the prompt.
    let mut standard_input = DetachedStandardInput::new()?;
    let inputs = RootInputs::open(&proposal)?;
    recover_pending_transactions(&store, inputs.base_arch()?)?;
    let mut staging = Staging::create(plan.bytes())?;
    let mut staged = inputs.stage(&mut staging)?;
    let mut root = MountRoot::create(&staging)?;
    let root_path = root
        .root()
        .to_str()
        .ok_or(ExecutorError::Plan("mount root is not UTF-8".into()))?;
    let inventory = require_root_resolve_equal(&proposal, &staged, root_path)?;
    standard_input.restore()?;
    if !approval.approved()? {
        root.cleanup()?;
        staging.cleanup()?;
        return Ok(Outcome::Aborted(proposal));
    }
    detach_standard_input()?;
    let id = dnfast_state::TransactionId::parse(staging.id())
        .map_err(|error| ExecutorError::Plan(error.to_string()))?;
    let digest = proposal
        .digest()
        .map_err(|error| ExecutorError::Plan(error.to_string()))?;
    let journal = store
        .create(&id, digest.as_str())
        .map_err(|error| ExecutorError::Plan(error.to_string()))?;
    root.allow_writes()?;
    root.verify_unchanged()?;
    let execution = execute_checked_transaction(
        &proposal,
        &mut staged,
        &inventory,
        Rc::new(journal),
        "/",
        &root,
    );
    root.restore_namespace_root()?;
    staging.cleanup()?;
    let inventory_after = execution?;
    republish_planning_inventory_after_transaction(&inventory_after)?;
    root.cleanup()?;
    Ok(Outcome::Executed(proposal, id.as_str().into()))
}

struct DetachedStandardInput {
    inherited: Option<OwnedFd>,
}

impl DetachedStandardInput {
    fn new() -> Result<Self, ExecutorError> {
        let inherited = rustix::io::dup(rustix::stdio::stdin())
            .map_err(|error| ExecutorError::Read(format!("retain stdin failed: {error}")))?;
        detach_standard_input()?;
        Ok(Self {
            inherited: Some(inherited),
        })
    }

    fn restore(&mut self) -> Result<(), ExecutorError> {
        let inherited = self
            .inherited
            .as_ref()
            .ok_or_else(|| ExecutorError::Read("stdin was already restored".into()))?;
        rustix::stdio::dup2_stdin(inherited)
            .map_err(|error| ExecutorError::Read(format!("restore stdin failed: {error}")))?;
        self.inherited.take();
        Ok(())
    }
}

impl Drop for DetachedStandardInput {
    fn drop(&mut self) {
        if let Some(inherited) = self.inherited.as_ref() {
            let _ = rustix::stdio::dup2_stdin(inherited);
        }
    }
}

fn detach_standard_input() -> Result<(), ExecutorError> {
    // librpm intentionally changes a failed non-blocking transaction lock into
    // an unbounded blocking wait when stdin is a TTY. Approval is complete at
    // this point, so retain the native deadline/interrupt contract by giving
    // the transaction phase a non-TTY stdin just like the resident service.
    let null = std::fs::File::open("/dev/null")
        .map_err(|error| ExecutorError::Read(format!("open /dev/null failed: {error}")))?;
    rustix::stdio::dup2_stdin(&null)
        .map_err(|error| ExecutorError::Read(format!("detach stdin failed: {error}")))?;
    Ok(())
}

fn republish_planning_inventory_after_transaction(
    inventory: &dnfast_core::InstalledInventory,
) -> Result<(), ExecutorError> {
    if !std::path::Path::new("/proc/self/fd").is_dir() {
        return Err(ExecutorError::Plan("post-transaction inventory republish requires /proc/self/fd after leaving the transaction chroot".into()));
    }
    let publisher = dnfast_planning::RootPlanningPublisher::system().map_err(|error| {
        ExecutorError::Plan(format!(
            "post-transaction planning publisher open failed: {error}"
        ))
    })?;
    publisher
        .publish_inventory_onto_current(inventory.clone())
        .map_err(|error| {
            ExecutorError::Plan(format!(
                "post-transaction inventory republish failed: {error}"
            ))
        })?;
    Ok(())
}

impl Outcome {
    fn response(self) -> Result<Response, ExecutorError> {
        match self {
            Self::Aborted(plan) => Response::from_plan(plan, Status::Aborted, None),
            Self::Executed(plan, transaction_id) => {
                Response::from_plan(plan, Status::Applied, Some(transaction_id))
            }
        }
    }
}

enum Approval {
    Prompt,
    Yes,
    No,
}

impl Approval {
    fn approved(&self) -> Result<bool, ExecutorError> {
        match self {
            Self::Yes => Ok(true),
            Self::No => Ok(false),
            Self::Prompt => {
                eprint!("dnfast transaction is staged. Continue? [y/N] ");
                io::stderr()
                    .flush()
                    .map_err(|error| ExecutorError::Read(error.to_string()))?;
                let mut reply = String::new();
                io::stdin()
                    .read_line(&mut reply)
                    .map_err(|error| ExecutorError::Read(error.to_string()))?;
                Ok(matches!(reply.trim(), "y" | "Y" | "yes" | "YES"))
            }
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "lowercase")]
enum Status {
    Applied,
    Aborted,
    Failed,
}

#[derive(Serialize)]
struct Action {
    kind: String,
    name: String,
    epoch: String,
    version: String,
    release: String,
    arch: String,
    repo_id: Option<String>,
    reason: String,
}

#[derive(Serialize)]
struct Error {
    code: String,
    message: String,
    context: std::collections::BTreeMap<String, String>,
}

#[derive(Serialize)]
struct Response {
    schema: String,
    command: String,
    status: Status,
    exit_code: u8,
    message: Option<String>,
    plan_digest: Option<String>,
    plan_path: Option<String>,
    transaction_id: Option<String>,
    actions: Vec<Action>,
    errors: Vec<Error>,
}

impl Response {
    fn from_plan(
        plan: dnfast_solver::CanonicalSolverPlan,
        status: Status,
        transaction_id: Option<String>,
    ) -> Result<Self, ExecutorError> {
        let digest = Some(
            plan.digest()
                .map_err(|error| ExecutorError::Plan(error.to_string()))?
                .as_str()
                .into(),
        );
        let actions = plan
            .actions()
            .iter()
            .map(|action| {
                let reason = match action.reason {
                    dnfast_core::PackageReason::User => "user",
                    dnfast_core::PackageReason::Dependency => "dependency",
                    dnfast_core::PackageReason::WeakDependency => "weak_dependency",
                    dnfast_core::PackageReason::External => "external",
                    dnfast_core::PackageReason::Unknown => "unknown",
                }
                .into();
                Action {
                    kind: action.operation.clone(),
                    name: action.name.clone(),
                    epoch: action.target_evra.epoch().to_string(),
                    version: action.target_evra.version().into(),
                    release: action.target_evra.release().into(),
                    arch: action.target_evra.arch().as_rpm_arch().into(),
                    repo_id: action.repo_id.clone(),
                    reason,
                }
            })
            .collect();
        Ok(Self {
            schema: "dnfast.cli.v1".into(),
            command: "apply".into(),
            status,
            exit_code: 0,
            message: None,
            plan_digest: digest,
            plan_path: None,
            transaction_id,
            actions,
            errors: Vec::new(),
        })
    }

    fn failed(message: String) -> Self {
        Self {
            schema: "dnfast.cli.v1".into(),
            command: "apply".into(),
            status: Status::Failed,
            exit_code: 1,
            message: Some(message.clone()),
            plan_digest: None,
            plan_path: None,
            transaction_id: None,
            actions: Vec::new(),
            errors: vec![Error {
                code: "runtime_failure".into(),
                message,
                context: std::collections::BTreeMap::new(),
            }],
        }
    }
}

fn emit(response: Response, exit_code: u8) -> ExitCode {
    match serde_json::to_string(&response) {
        Ok(json) => {
            println!("{json}");
            ExitCode::from(exit_code)
        }
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::from(1)
        }
    }
}
