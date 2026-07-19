mod advisory;
mod group;
mod history;
mod output;
mod planner;
mod repo;

use std::{
    io::{Seek, SeekFrom},
    os::fd::{AsFd, OwnedFd},
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use dnfast_cache::Cache;
use dnfast_core::{Action, PackageSpec, TransactionIntent};
use dnfast_metadata::search;

use crate::{
    args::{
        AdvisoryCommand, Commands, DaemonCommand, GroupCommand, HistoryCommand, ModuleCommand,
        MutationArgs, PlanAction, RepoCommand,
    },
    environment::{cache_directory, library_present},
    rendering::escaped_field,
    response::{Action as ResponseAction, Response},
};

#[derive(Debug)]
pub(crate) struct AppFailure {
    pub(crate) code: u8,
    pub(crate) error_code: &'static str,
    pub(crate) message: String,
}

impl AppFailure {
    pub(crate) fn new(code: u8, message: impl Into<String>) -> Self {
        let error_code = match code {
            2 => "invalid_arguments",
            _ => "runtime_failure",
        };
        Self {
            code,
            error_code,
            message: message.into(),
        }
    }

    pub(crate) fn with_error_code(
        code: u8,
        error_code: &'static str,
        message: impl Into<String>,
    ) -> Self {
        Self {
            code,
            error_code,
            message: message.into(),
        }
    }
}

pub(crate) fn run(command: Commands) -> Result<Response, AppFailure> {
    match command {
        Commands::InternalPublishPlanning {
            published_at_unix,
            generations,
        } => repo::publish_internal(published_at_unix, generations)
            .map(|message| Response::completed("internal-publish-planning", message)),
        Commands::Plan {
            action,
            output,
            repositories,
            packages,
        } => run_plan(action, output, repositories, packages),
        Commands::Apply {
            plan,
            assumeyes,
            assumeno,
        } => run_apply(plan, assumeyes, assumeno),
        Commands::Install(arguments) => run_convenience(PlanAction::Install, arguments),
        Commands::Remove(arguments) => run_convenience(PlanAction::Remove, arguments),
        Commands::Upgrade(arguments) => run_convenience(PlanAction::Upgrade, arguments),
        Commands::Downgrade(arguments) => run_convenience(PlanAction::Downgrade, arguments),
        Commands::Reinstall(arguments) => run_convenience(PlanAction::Reinstall, arguments),
        Commands::DistroSync(arguments) => run_convenience(PlanAction::DistroSync, arguments),
        Commands::Autoremove(arguments) => run_convenience(PlanAction::Autoremove, arguments),
        Commands::Daemon { command } => run_daemon(command),
        Commands::Repo { command } => match command {
            RepoCommand::List {
                repo_dirs,
                releasever,
                basearch,
            } => repo::list(repo_dirs, releasever, basearch)
                .map(|message| Response::completed("repo", message)),
            RepoCommand::Refresh { repositories } => {
                repo::refresh(repositories).map(|message| Response::completed("repo", message))
            }
            RepoCommand::Makecache { repositories } => {
                repo::makecache(repositories).map(|message| Response::completed("repo", message))
            }
        },
        Commands::History { command } => match command {
            HistoryCommand::List { limit, source } => {
                history::list(limit, source).map(|message| Response::completed("history", message))
            }
            HistoryCommand::Info { transaction_id } => history::info(&transaction_id)
                .map(|message| Response::completed("history", message)),
        },
        Commands::Doctor {
            cleanup_stale_inputs,
        } => run_doctor(cleanup_stale_inputs),
        Commands::Search {
            repositories,
            cache_dir,
            query,
        } => run_search(repositories, cache_dir, query),
        Commands::Group { command } => match command {
            GroupCommand::List { repositories } => group::list(repositories),
            GroupCommand::Info { repositories, id } => group::info(repositories, &id),
            GroupCommand::Install(arguments) => group::install(arguments),
            GroupCommand::Remove(arguments) => group::remove(arguments),
        },
        Commands::Environment { command } => match command {
            GroupCommand::List { repositories } => group::list(repositories),
            GroupCommand::Info { repositories, id } => group::info(repositories, &id),
            GroupCommand::Install(arguments) => group::install(arguments),
            GroupCommand::Remove(arguments) => group::remove(arguments),
        }
        .map(|response| response.with_command("environment")),
        Commands::Module { command } => match command {
            ModuleCommand::List { repositories } => group::module_list(repositories),
            ModuleCommand::Info { repositories, spec } => group::module_info(repositories, &spec),
            ModuleCommand::Install(arguments) => group::module_install(arguments),
            ModuleCommand::Enable(arguments) => group::module_mutation("enable", arguments),
            ModuleCommand::Reset(arguments) => group::module_mutation("reset", arguments),
            ModuleCommand::Disable(arguments) => group::module_mutation("disable", arguments),
        },
        Commands::Advisory { command } => match command {
            AdvisoryCommand::List(arguments) => advisory::list(arguments),
            AdvisoryCommand::Info {
                repositories,
                advisories,
            } => advisory::info(repositories, advisories),
            AdvisoryCommand::Upgrade(arguments) => advisory::upgrade(arguments),
        },
    }
}

pub(crate) fn name(command: &Commands) -> &'static str {
    match command {
        Commands::InternalPublishPlanning { .. } => "internal-publish-planning",
        Commands::Plan { .. } => "plan",
        Commands::Apply { .. } => "apply",
        Commands::Install(_) => "install",
        Commands::Remove(_) => "remove",
        Commands::Upgrade(_) => "upgrade",
        Commands::Downgrade(_) => "downgrade",
        Commands::Reinstall(_) => "reinstall",
        Commands::DistroSync(_) => "distro-sync",
        Commands::Autoremove(_) => "autoremove",
        Commands::Daemon { .. } => "daemon",
        Commands::Repo { .. } => "repo",
        Commands::History { .. } => "history",
        Commands::Doctor { .. } => "doctor",
        Commands::Search { .. } => "search",
        Commands::Group { .. } => "group",
        Commands::Environment { .. } => "environment",
        Commands::Module { .. } => "module",
        Commands::Advisory { .. } => "advisory",
    }
}

fn run_apply(plan: PathBuf, assumeyes: bool, assumeno: bool) -> Result<Response, AppFailure> {
    validate_plan_argument(&plan)?;
    if rustix::process::geteuid().as_raw() != 0 {
        return Err(AppFailure::new(1, "apply requires root"));
    }
    let approval = match (assumeyes, assumeno) {
        (false, false) => dnfast_native_sys::ExecutorApproval::Prompt,
        (true, false) => dnfast_native_sys::ExecutorApproval::Yes,
        (false, true) => dnfast_native_sys::ExecutorApproval::No,
        (true, true) => return Err(AppFailure::new(2, "--assumeyes and --assumeno conflict")),
    };
    let plan =
        dnfast_executor::open_plan(&plan).map_err(|error| AppFailure::new(1, error.to_string()))?;
    let mut standard_input = DetachedStandardInput::new()?;
    prepare_before_fixed_executor(&plan)?;
    standard_input.restore()?;
    match dnfast_native_sys::exec_fixed_executor(plan, approval) {
        Ok(()) => Err(AppFailure::new(1, "fixed executor unexpectedly returned")),
        Err(error) => Err(AppFailure::new(1, error.to_string())),
    }
}

fn run_convenience(action: PlanAction, arguments: MutationArgs) -> Result<Response, AppFailure> {
    run_convenience_with_plan(action, arguments, |_| Ok(()))
}

fn run_convenience_with_plan(
    action: PlanAction,
    mut arguments: MutationArgs,
    on_execute: impl FnOnce(Option<&dnfast_solver::CanonicalSolverPlan>) -> Result<(), AppFailure>,
) -> Result<Response, AppFailure> {
    if rustix::process::geteuid().as_raw() != 0 {
        return Err(AppFailure::new(1, "mutation requires root"));
    }
    if matches!(action, PlanAction::Autoremove) {
        arguments.packages = autoremove_packages(arguments.packages)?;
        if arguments.packages.is_empty() {
            on_execute(None)?;
            return Ok(Response::completed(
                "autoremove",
                "no changes; no recorded dependency package is unneeded",
            ));
        }
    }
    let assume_no = arguments.assumeno;
    let native_action = Action::from(action);
    let mut approval = approval(arguments.assumeyes, arguments.assumeno)?;
    let repositories = canonical_repository_ids(arguments.repositories)?;
    // Mutations are one-shot by default: no service is started and no solver
    // pool survives the command.  The explicit `dnfast daemon` commands remain
    // available for operators who intentionally opt into a resident service.
    let local = match dnfast_executor::plan_transaction_without_daemon(
        native_action,
        &arguments.packages,
        &repositories,
    ) {
        Ok(local) => local,
        Err(error) if error.is_no_changes() => {
            on_execute(None)?;
            return Ok(Response::completed(
                action_name(action),
                "no changes; requested state is already satisfied",
            ));
        }
        Err(error) => return Err(AppFailure::new(1, error.to_string())),
    };
    // The local fallback reads RPMDB before it execs the fixed executor.
    // Preserve the inherited terminal for the later approval prompt, but keep
    // librpm non-interactive while this pre-approval root boundary is open.
    let mut standard_input = DetachedStandardInput::new()?;
    let plan = match &local {
        Some(local) => local.plan().clone(),
        None => planner::solve(intent(action, arguments.packages)?, &repositories)?,
    };
    if assume_no {
        return aborted_plan_response(&plan);
    }
    if approval == dnfast_native_sys::ExecutorApproval::Prompt {
        // Match the daemon boundary: the immutable, RPMDB-bound plan is
        // complete before asking, while artifact staging and the independent
        // fixed-executor re-solve happen only after explicit approval.
        standard_input.restore()?;
        if !prompt_local_approval()? {
            return aborted_plan_response(&plan);
        }
        approval = dnfast_native_sys::ExecutorApproval::Yes;
        standard_input = DetachedStandardInput::new()?;
    }
    on_execute(Some(&plan))?;
    match local {
        Some(local) => {
            let compact = local
                .prepare_compact()
                .map_err(|error| AppFailure::new(1, error.to_string()))?;
            let (plan_fd, manifest_fd, artifacts) = compact.into_parts();
            standard_input.restore()?;
            match dnfast_native_sys::exec_fixed_executor_compact(
                plan_fd,
                manifest_fd,
                artifacts,
                approval,
            ) {
                Ok(()) => Err(AppFailure::new(1, "fixed executor unexpectedly returned")),
                Err(error) => Err(AppFailure::new(1, error.to_string())),
            }
        }
        None => {
            let bytes = plan
                .canonical_json()
                .map_err(|error| AppFailure::new(1, error.to_string()))?;
            let mut temporary = tempfile::NamedTempFile::new_in("/var/lib/dnfast")
                .map_err(|error| AppFailure::new(1, error.to_string()))?;
            temporary
                .as_file()
                .set_permissions(std::os::unix::fs::PermissionsExt::from_mode(0o600))
                .map_err(|error| AppFailure::new(1, error.to_string()))?;
            std::io::Write::write_all(&mut temporary.as_file(), &bytes)
                .map_err(|error| AppFailure::new(1, error.to_string()))?;
            temporary
                .as_file()
                .sync_all()
                .map_err(|error| AppFailure::new(1, error.to_string()))?;
            temporary
                .as_file_mut()
                .seek(SeekFrom::Start(0))
                .map_err(|error| AppFailure::new(1, error.to_string()))?;
            let plan_fd = temporary
                .as_file()
                .as_fd()
                .try_clone_to_owned()
                .map_err(|error| AppFailure::new(1, error.to_string()))?;
            prepare_locally_solved_before_fixed_executor(&plan_fd)?;
            standard_input.restore()?;
            match dnfast_native_sys::exec_fixed_executor(plan_fd, approval) {
                Ok(()) => Err(AppFailure::new(1, "fixed executor unexpectedly returned")),
                Err(error) => Err(AppFailure::new(1, error.to_string())),
            }
        }
    }
}

fn autoremove_packages(requested: Vec<String>) -> Result<Vec<String>, AppFailure> {
    let snapshot = dnfast_planning::PlanningSnapshot::open_system()
        .map_err(|error| AppFailure::new(1, error.to_string()))?;
    snapshot
        .revalidate_runtime_bindings()
        .map_err(|error| AppFailure::new(1, error.to_string()))?;
    let candidates = dnfast_state::ReasonStateStore::open_system()
        .and_then(|store| {
            store.autoremove_candidates(
                &snapshot.payload().inventory,
                &snapshot.payload().policy.solver,
            )
        })
        .map_err(|error| AppFailure::new(1, error.to_string()))?;
    if requested.is_empty() {
        return Ok(candidates);
    }
    let allowed = candidates
        .iter()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    if let Some(package) = requested
        .iter()
        .find(|package| !allowed.contains(package.as_str()))
    {
        return Err(AppFailure::with_error_code(
            1,
            "unsafe_autoremove",
            format!("autoremove candidate is not exact dependency-reason state: {package}"),
        ));
    }
    let mut requested = requested;
    requested.sort();
    requested.dedup();
    Ok(requested)
}

const fn action_name(action: PlanAction) -> &'static str {
    match action {
        PlanAction::Install => "install",
        PlanAction::Remove => "remove",
        PlanAction::Upgrade => "upgrade",
        PlanAction::Downgrade => "downgrade",
        PlanAction::Reinstall => "reinstall",
        PlanAction::DistroSync => "distro-sync",
        PlanAction::Autoremove => "autoremove",
    }
}

fn prompt_local_approval() -> Result<bool, AppFailure> {
    eprint!("dnfast transaction is planned. Continue? [y/N] ");
    std::io::Write::flush(&mut std::io::stderr())
        .map_err(|error| AppFailure::new(1, format!("write approval prompt failed: {error}")))?;
    let mut reply = String::new();
    std::io::stdin()
        .read_line(&mut reply)
        .map_err(|error| AppFailure::new(1, format!("read approval failed: {error}")))?;
    Ok(matches!(reply.trim(), "y" | "Y" | "yes" | "YES"))
}

struct DetachedStandardInput {
    inherited: Option<OwnedFd>,
}

impl DetachedStandardInput {
    fn new() -> Result<Self, AppFailure> {
        let inherited = rustix::io::dup(rustix::stdio::stdin())
            .map_err(|error| AppFailure::new(1, format!("retain stdin failed: {error}")))?;
        let null = std::fs::File::open("/dev/null")
            .map_err(|error| AppFailure::new(1, format!("open /dev/null failed: {error}")))?;
        rustix::stdio::dup2_stdin(&null)
            .map_err(|error| AppFailure::new(1, format!("detach stdin failed: {error}")))?;
        Ok(Self {
            inherited: Some(inherited),
        })
    }

    fn restore(&mut self) -> Result<(), AppFailure> {
        let inherited = self
            .inherited
            .as_ref()
            .ok_or_else(|| AppFailure::new(1, "stdin was already restored"))?;
        rustix::stdio::dup2_stdin(inherited)
            .map_err(|error| AppFailure::new(1, format!("restore stdin failed: {error}")))?;
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

fn run_daemon(command: DaemonCommand) -> Result<Response, AppFailure> {
    match command {
        DaemonCommand::Status => dnfast_executor::daemon_status()
            .map(|available| {
                Response::completed(
                    "daemon",
                    format!(
                        "resident_daemon={}",
                        if available {
                            "available"
                        } else {
                            "unavailable"
                        }
                    ),
                )
            })
            .map_err(|error| AppFailure::new(1, error.to_string())),
        DaemonCommand::Warm { repositories } => {
            let repositories = canonical_repository_ids(repositories)?;
            dnfast_executor::warm_daemon(&repositories)
                .map(|cookie| {
                    Response::completed(
                        "daemon",
                        format!("resident_pool=warmed; rpmdb_cookie_sha256={cookie}"),
                    )
                })
                .map_err(|error| AppFailure::new(1, error.to_string()))
        }
    }
}

fn approval(
    assumeyes: bool,
    assumeno: bool,
) -> Result<dnfast_native_sys::ExecutorApproval, AppFailure> {
    match (assumeyes, assumeno) {
        (false, false) => Ok(dnfast_native_sys::ExecutorApproval::Prompt),
        (true, false) => Ok(dnfast_native_sys::ExecutorApproval::Yes),
        (false, true) => Ok(dnfast_native_sys::ExecutorApproval::No),
        (true, true) => Err(AppFailure::new(2, "--assumeyes and --assumeno conflict")),
    }
}

fn prepare_before_fixed_executor(fd: &std::os::fd::OwnedFd) -> Result<(), AppFailure> {
    let bytes = read_retained_plan_bytes(fd)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| AppFailure::new(1, error.to_string()))?
        .as_secs();
    let proposal = dnfast_solver::CanonicalSolverPlan::from_canonical_json(&bytes, now)
        .map_err(|error| AppFailure::new(1, error.to_string()))?;
    let prepared = dnfast_executor::RootInputPreparer::prepare_system(&proposal)
        .map_err(|error| AppFailure::new(1, error.to_string()))?;
    prepared
        .revalidate_before_fd3(&proposal)
        .map_err(|error| AppFailure::new(1, error.to_string()))
}

fn prepare_locally_solved_before_fixed_executor(
    fd: &std::os::fd::OwnedFd,
) -> Result<(), AppFailure> {
    let bytes = read_retained_plan_bytes(fd)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| AppFailure::new(1, error.to_string()))?
        .as_secs();
    let proposal = dnfast_solver::CanonicalSolverPlan::from_canonical_json(&bytes, now)
        .map_err(|error| AppFailure::new(1, error.to_string()))?;
    let prepared = dnfast_executor::RootInputPreparer::prepare_locally_solved_system(&proposal)
        .map_err(|error| AppFailure::new(1, error.to_string()))?;
    prepared
        .revalidate_before_fd3(&proposal)
        .map_err(|error| AppFailure::new(1, error.to_string()))
}

fn read_retained_plan_bytes(fd: &std::os::fd::OwnedFd) -> Result<Vec<u8>, AppFailure> {
    let mut bytes = Vec::new();
    let mut offset = 0_u64;
    let mut chunk = [0_u8; 65_536];
    loop {
        let read = rustix::io::pread(fd, &mut chunk, offset)
            .map_err(|error| AppFailure::new(1, error.to_string()))?;
        if read == 0 {
            break;
        }
        bytes
            .try_reserve(read)
            .map_err(|error| AppFailure::new(1, error.to_string()))?;
        bytes.extend_from_slice(&chunk[..read]);
        if bytes.len() > dnfast_executor::MAX_PLAN_BYTES as usize {
            return Err(AppFailure::new(
                1,
                "plan exceeds the fixed executor size limit",
            ));
        }
        offset = offset
            .checked_add(
                u64::try_from(read).map_err(|error| AppFailure::new(1, error.to_string()))?,
            )
            .ok_or_else(|| AppFailure::new(1, "plan descriptor offset overflow"))?;
    }
    Ok(bytes)
}

fn run_search(
    mut repositories: Vec<String>,
    cache_dir: Option<PathBuf>,
    query: String,
) -> Result<Response, AppFailure> {
    repositories.sort();
    repositories.dedup();
    let cache = Cache::new(cache_directory(cache_dir)?);
    if repositories.is_empty() {
        repositories = cache
            .repositories()
            .map_err(|error| AppFailure::new(1, error.to_string()))?;
        if repositories.is_empty() {
            return Err(AppFailure::new(1, "no cached repositories"));
        }
    }
    let mut matches = Vec::new();
    for repository in repositories {
        let snapshot = cache
            .load(&repository)
            .map_err(|error| AppFailure::new(1, format!("{repository}: {error}")))?;
        for package in search(&snapshot.packages, &query) {
            matches.push(format!(
                "{} {} {}",
                escaped_field(&repository),
                escaped_field(&package.nevra()),
                escaped_field(&package.summary)
            ));
        }
    }
    Ok(Response::completed(
        "search",
        format!("search results: {}", matches.join("; ")),
    ))
}

fn run_plan(
    action: PlanAction,
    output: PathBuf,
    repositories: Vec<String>,
    packages: Vec<String>,
) -> Result<Response, AppFailure> {
    output::validate_new_path(&output)?;
    let repositories = canonical_repository_ids(repositories)?;
    let plan = if rustix::process::geteuid().as_raw() == 0 {
        match dnfast_executor::plan_without_daemon(Action::from(action), &packages, &repositories)
            .map_err(|error| AppFailure::new(1, error.to_string()))?
        {
            Some(local) => local.plan,
            None => planner::solve(intent(action, packages)?, &repositories)?,
        }
    } else {
        planner::solve(intent(action, packages)?, &repositories)?
    };
    let bytes = plan
        .canonical_json()
        .map_err(|error| AppFailure::new(1, error.to_string()))?;
    let actions = plan.actions().iter().map(response_action).collect();
    output::write_new_plan(&output, &bytes)?;
    let digest = plan
        .digest()
        .map_err(|error| AppFailure::new(1, error.to_string()))?
        .as_str()
        .to_owned();
    let path = output
        .to_str()
        .map(str::to_owned)
        .ok_or_else(|| AppFailure::new(2, "output path is not UTF-8"))?;
    Ok(Response::planned("plan", digest, path, actions))
}

fn intent(action: PlanAction, packages: Vec<String>) -> Result<TransactionIntent, AppFailure> {
    let packages = packages
        .into_iter()
        .map(PackageSpec::parse)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| AppFailure::new(2, error.to_string()))?;
    TransactionIntent::new(Action::from(action), packages)
        .map_err(|error| AppFailure::new(2, error.to_string()))
}

fn canonical_repository_ids(mut repositories: Vec<String>) -> Result<Vec<String>, AppFailure> {
    if repositories.iter().any(|repository| {
        repository.is_empty()
            || repository
                .bytes()
                .any(|byte| !(byte.is_ascii_alphanumeric() || b"_.-".contains(&byte)))
    }) {
        return Err(AppFailure::with_error_code(
            2,
            "invalid_repository_selection",
            "repository identifiers must use ASCII letters, digits, dot, underscore, or dash",
        ));
    }
    repositories.sort();
    if repositories.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(AppFailure::with_error_code(
            2,
            "invalid_repository_selection",
            "repository identifiers must be unique",
        ));
    }
    Ok(repositories)
}

fn validate_plan_argument(path: &std::path::Path) -> Result<(), AppFailure> {
    let value = path.to_str().ok_or_else(|| {
        AppFailure::with_error_code(2, "invalid_plan_path", "plan path is not UTF-8")
    })?;
    if !path.is_absolute() || value.chars().any(char::is_control) {
        return Err(AppFailure::with_error_code(
            2,
            "invalid_plan_path",
            "plan path must be absolute UTF-8 without control characters",
        ));
    }
    Ok(())
}

fn response_action(action: &dnfast_solver::ExplainedAction) -> ResponseAction {
    let reason = match action.reason {
        dnfast_core::PackageReason::User => "user",
        dnfast_core::PackageReason::Dependency => "dependency",
        dnfast_core::PackageReason::WeakDependency => "weak_dependency",
        dnfast_core::PackageReason::External => "external",
        dnfast_core::PackageReason::Unknown => "unknown",
    }
    .into();
    ResponseAction {
        kind: action.operation.clone(),
        name: action.name.clone(),
        epoch: action.target_evra.epoch().to_string(),
        version: action.target_evra.version().into(),
        release: action.target_evra.release().into(),
        arch: action.target_evra.arch().as_rpm_arch().into(),
        repo_id: action.repo_id.clone(),
        reason,
    }
}

fn aborted_plan_response(
    plan: &dnfast_solver::CanonicalSolverPlan,
) -> Result<Response, AppFailure> {
    let command = match plan.proposal().intent().action() {
        Action::Install => "install",
        Action::Upgrade => "upgrade",
        Action::Remove => "remove",
        Action::Downgrade => "downgrade",
        Action::Reinstall => "reinstall",
        Action::DistroSync => "distro-sync",
        Action::Autoremove => "autoremove",
    };
    let digest = plan
        .digest()
        .map_err(|error| AppFailure::new(1, error.to_string()))?
        .as_str()
        .to_owned();
    Ok(Response::aborted(
        command,
        digest,
        plan.actions().iter().map(response_action).collect(),
    ))
}

fn run_doctor(cleanup_stale_inputs: bool) -> Result<Response, AppFailure> {
    let fedora_config = std::path::Path::new("/etc/os-release").is_file()
        && ["/etc/yum.repos.d", "/etc/dnf/repos.d"]
            .into_iter()
            .any(|directory| std::path::Path::new(directory).is_dir());
    let libsolv = if library_present("libsolv.so.1") {
        "available"
    } else {
        "unavailable"
    };
    let librpm = if library_present("librpm.so.10") {
        "available"
    } else {
        "unavailable"
    };
    let cleaned = if cleanup_stale_inputs {
        if rustix::process::geteuid().as_raw() != 0 {
            return Err(AppFailure::new(
                1,
                "doctor --cleanup-stale-inputs requires root",
            ));
        }
        Some(
            dnfast_executor::RootInputPreparer::garbage_collect_system()
                .map_err(|error| AppFailure::new(1, error.to_string()))?,
        )
    } else {
        None
    };
    Ok(Response::completed(
        "doctor",
        format!(
            "fedora_config={}; libsolv={libsolv}; librpm={librpm}; metadata_refresh=available; fixed_executor=root_apply_only{}",
            if fedora_config {
                "available"
            } else {
                "unavailable"
            },
            cleaned
                .map(|count| format!("; stale_input_generations_removed={count}"))
                .unwrap_or_default(),
        ),
    ))
}

#[cfg(test)]
mod tests {
    use std::{
        fs::File,
        io::{Read, Seek, SeekFrom, Write},
        os::fd::AsFd,
    };

    use super::read_retained_plan_bytes;

    #[test]
    fn inherited_plan_descriptor_reads_exact_bytes_after_preparation_read() {
        // Given a retained plan descriptor at the offset that fixed-executor inherits.
        let mut plan = tempfile::tempfile().unwrap();
        plan.write_all(b"canonical-plan").unwrap();
        plan.seek(SeekFrom::Start(0)).unwrap();
        let retained = plan.as_fd().try_clone_to_owned().unwrap();

        // When root preparation reads it for re-solve validation.
        let prepared = read_retained_plan_bytes(&retained).unwrap();

        // Then the later inherited descriptor still reads the exact same bytes from offset zero.
        assert_eq!(prepared, b"canonical-plan");
        let inherited = retained.as_fd().try_clone_to_owned().unwrap();
        let mut executor_input = File::from(inherited);
        let mut observed = Vec::new();
        executor_input.read_to_end(&mut observed).unwrap();
        assert_eq!(observed, b"canonical-plan");
    }
}
