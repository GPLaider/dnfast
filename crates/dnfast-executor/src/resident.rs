use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{self, Read, Write},
    os::unix::{
        fs::{FileTypeExt, MetadataExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    rc::Rc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use dnfast_cache::{
    ArtifactCache, ArtifactSpec, CacheError, Digest as ArtifactDigest, HttpArtifactTransport,
    RpmDbCurrentCheck, RpmDbReceiptCache, RpmDbReceiptCheck, RpmDbVerifiedGeneration, SolvCache,
    TransactionRequest,
};
use dnfast_core::{
    Action, Architecture, CanonicalDocument, Evra, InstalledInventory, PackageSpec, SolverPolicy,
    TransactionIntent,
};
use dnfast_native::{
    ExpectedPackage, FileProvider, InventorySnapshot, MappedSelector, NativeContext, Repository,
    VerifiedStagedKey,
};
use dnfast_planning::{PlanningRepository, PlanningSnapshot, SYSTEM_CACHE_PATH};
use dnfast_solver::{
    CandidatePackage, CanonicalSolverPlan, NativePackageEvidence, NativePackageEvidenceParts,
    NativeSolveOutput, PlanBuilder,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    CompactExecution, ExecutorError, MountRoot, StagedArtifact, StagedInputs, Staging,
    execute::run_token_bound,
    recover_pending_transactions,
    staged_inputs::{StagedRepository, apply_module_artifact_policy},
    staging::system_directory,
};

pub const SYSTEM_SOCKET: &str = "/run/dnfast/dnfastd.sock";
const RUNTIME_PATH: [&str; 2] = ["run", "dnfast"];
const MAX_FRAME_BYTES: usize = 24 * 1024 * 1024;
const PLAN_LIFETIME_SECONDS: u64 = 300;
const PROTOCOL_SCHEMA: &str = "dnfast.daemon.v1";
const CONNECT_RETRY_LIMIT: Duration = Duration::from_secs(2);
const CONNECT_RETRY_INTERVAL: Duration = Duration::from_millis(25);
const SYSTEMCTL_PATH: &str = "/usr/bin/systemctl";
const SYSTEM_SERVICE: &str = "dnfastd.service";
const SYSTEM_RPMDB_PATH: &str = "/usr/lib/sysimage/rpm/rpmdb.sqlite";
const SYSTEM_RPMDB_WAL_PATH: &str = "/usr/lib/sysimage/rpm/rpmdb.sqlite-wal";
type MaterializedPaths = (String, String, String);
type MaterializedRepository = MaterializedPaths;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DaemonApproval {
    Prompt,
    Yes,
    No,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaemonOutcome {
    pub command: String,
    pub status: DaemonStatus,
    pub plan_digest: String,
    pub transaction_id: Option<String>,
    pub actions: Vec<DaemonAction>,
}

pub struct DaemonPlan {
    pub plan: CanonicalSolverPlan,
}

pub struct DaemonlessPlan {
    solved: SolvedPlan,
}

impl DaemonlessPlan {
    pub fn plan(&self) -> &CanonicalSolverPlan {
        &self.solved.plan
    }

    pub fn prepare_compact(self) -> Result<CompactExecution, DaemonError> {
        revalidate_solved(&self.solved)?;
        let staged = direct_staged_inputs(&self.solved)?;
        CompactExecution::create(
            &self.solved.plan,
            self.solved.integrity.planning_snapshot_sha256().as_str(),
            self.solved.inventory,
            self.solved.rpmdb_cookie,
            staged,
        )
        .map_err(executor)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DaemonStatus {
    Applied,
    Aborted,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DaemonAction {
    pub kind: String,
    pub name: String,
    pub epoch: String,
    pub version: String,
    pub release: String,
    pub arch: String,
    pub repo_id: Option<String>,
    pub reason: String,
}

#[derive(Debug, Error)]
pub enum DaemonError {
    #[error("solver produced no changes")]
    NoChanges,
    #[error("resident daemon is unavailable")]
    Unavailable,
    #[error("resident daemon requires EUID 0")]
    NotRoot,
    #[error("resident daemon socket is unsafe")]
    UnsafeSocket,
    #[error("resident daemon protocol failed: {0}")]
    Protocol(String),
    #[error("transaction planning failed: {0}")]
    Planning(String),
    #[error("transaction execution failed: {0}")]
    Execution(String),
    #[error("transaction I/O failed: {0}")]
    Io(String),
}

impl DaemonError {
    pub const fn is_unavailable(&self) -> bool {
        matches!(self, Self::Unavailable)
    }

    pub const fn is_no_changes(&self) -> bool {
        matches!(self, Self::NoChanges)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ClientMessage {
    Ping {
        schema: String,
    },
    Warm {
        schema: String,
        repositories: Vec<String>,
    },
    Plan {
        schema: String,
        action: String,
        repositories: Vec<String>,
        packages: Vec<String>,
    },
    Prepare {
        schema: String,
        action: String,
        repositories: Vec<String>,
        packages: Vec<String>,
    },
    Decision {
        schema: String,
        token: String,
        approved: bool,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ServerMessage {
    Pong {
        schema: String,
    },
    Warmed {
        schema: String,
        rpmdb_cookie_sha256: String,
    },
    Planned {
        schema: String,
        plan_base64: String,
        plan_digest: String,
    },
    Prepared {
        schema: String,
        token: String,
        command: String,
        plan_digest: String,
        actions: Vec<DaemonAction>,
    },
    Outcome {
        schema: String,
        command: String,
        status: String,
        plan_digest: String,
        transaction_id: Option<String>,
        actions: Vec<DaemonAction>,
    },
    Failed {
        schema: String,
        message: String,
    },
    Fallback {
        schema: String,
        reason: String,
    },
}

pub fn daemon_status() -> Result<bool, DaemonError> {
    let mut stream = match connect_once() {
        Ok(stream) => stream,
        Err(DaemonError::Unavailable) => return Ok(false),
        Err(error) => return Err(error),
    };
    write_frame(
        &mut stream,
        &ClientMessage::Ping {
            schema: PROTOCOL_SCHEMA.into(),
        },
    )?;
    match read_frame::<ServerMessage>(&mut stream)? {
        ServerMessage::Pong { schema } if schema == PROTOCOL_SCHEMA => Ok(true),
        ServerMessage::Failed { message, .. } => Err(DaemonError::Protocol(message)),
        ServerMessage::Fallback { .. } => Err(DaemonError::Unavailable),
        _ => Err(DaemonError::Protocol("unexpected ping response".into())),
    }
}

pub fn warm_daemon(repositories: &[String]) -> Result<String, DaemonError> {
    let mut stream = connect_retry()?;
    write_frame(
        &mut stream,
        &ClientMessage::Warm {
            schema: PROTOCOL_SCHEMA.into(),
            repositories: repositories.to_vec(),
        },
    )?;
    match read_frame::<ServerMessage>(&mut stream)? {
        ServerMessage::Warmed {
            schema,
            rpmdb_cookie_sha256,
        } if schema == PROTOCOL_SCHEMA => Ok(rpmdb_cookie_sha256),
        ServerMessage::Failed { message, .. } => Err(DaemonError::Protocol(message)),
        ServerMessage::Fallback { .. } => Err(DaemonError::Unavailable),
        _ => Err(DaemonError::Protocol("unexpected warm response".into())),
    }
}

pub fn plan_via_daemon(
    action: Action,
    packages: &[String],
    repositories: &[String],
) -> Result<DaemonPlan, DaemonError> {
    let mut stream = connect_retry()?;
    write_frame(
        &mut stream,
        &ClientMessage::Plan {
            schema: PROTOCOL_SCHEMA.into(),
            action: action_name(action).into(),
            repositories: repositories.to_vec(),
            packages: packages.to_vec(),
        },
    )?;
    match read_frame::<ServerMessage>(&mut stream)? {
        ServerMessage::Planned {
            schema,
            plan_base64,
            plan_digest,
        } if schema == PROTOCOL_SCHEMA => {
            let bytes = STANDARD
                .decode(plan_base64)
                .map_err(|_| DaemonError::Protocol("resident plan is not base64".into()))?;
            let plan =
                CanonicalSolverPlan::from_canonical_json(&bytes, now_unix()?).map_err(planning)?;
            if plan.digest().map_err(planning)?.as_str() != plan_digest {
                return Err(DaemonError::Protocol(
                    "resident plan digest mismatch".into(),
                ));
            }
            Ok(DaemonPlan { plan })
        }
        ServerMessage::Failed { message, .. } => Err(DaemonError::Protocol(message)),
        ServerMessage::Fallback { .. } => Err(DaemonError::Unavailable),
        _ => Err(DaemonError::Protocol(
            "unexpected resident plan response".into(),
        )),
    }
}

/// Builds one plan with the same verified cached pool used by the resident
/// daemon when the service is genuinely unavailable.
///
/// `None` means an absolute selector needs the legacy full-filelists planner.
/// The common path keeps the receipt, immutable solv cache, module policy,
/// compact selector, and final root-state revalidation contracts identical to
/// the daemon path without retaining a pool after the call.
pub fn plan_without_daemon(
    action: Action,
    packages: &[String],
    repositories: &[String],
) -> Result<Option<DaemonPlan>, DaemonError> {
    Ok(
        plan_transaction_without_daemon(action, packages, repositories)?.map(|transaction| {
            DaemonPlan {
                plan: transaction.solved.plan,
            }
        }),
    )
}

/// Builds a one-shot plan plus the state needed for a sealed compact executor
/// handoff. No process or solver pool survives this call.
pub fn plan_transaction_without_daemon(
    action: Action,
    packages: &[String],
    repositories: &[String],
) -> Result<Option<DaemonlessPlan>, DaemonError> {
    if rustix::process::geteuid().as_raw() != 0 {
        return Err(DaemonError::NotRoot);
    }
    canonical_repository_ids(repositories)?;
    let mut planner = ResidentPlanner::default();
    planner.verify_startup(system_architecture()?)?;
    let result = if planner.requires_full_filelists(action, packages, repositories)? {
        Ok(None)
    } else {
        let solved = planner.solve(action, packages.to_vec(), repositories)?;
        revalidate_solved(&solved)?;
        Ok(Some(DaemonlessPlan { solved }))
    };
    drop(planner);
    dnfast_native::release_unused_memory();
    result
}

pub fn transact_via_daemon(
    action: Action,
    packages: &[String],
    repositories: &[String],
    approval: DaemonApproval,
) -> Result<DaemonOutcome, DaemonError> {
    let mut stream = connect_retry()?;
    write_frame(
        &mut stream,
        &ClientMessage::Prepare {
            schema: PROTOCOL_SCHEMA.into(),
            action: action_name(action).into(),
            repositories: repositories.to_vec(),
            packages: packages.to_vec(),
        },
    )?;
    let (token, command, plan_digest, actions) = match read_frame::<ServerMessage>(&mut stream)? {
        ServerMessage::Prepared {
            schema,
            token,
            command,
            plan_digest,
            actions,
        } if schema == PROTOCOL_SCHEMA => (token, command, plan_digest, actions),
        ServerMessage::Failed { message, .. } => return Err(DaemonError::Protocol(message)),
        ServerMessage::Fallback { .. } => return Err(DaemonError::Unavailable),
        _ => return Err(DaemonError::Protocol("unexpected prepare response".into())),
    };
    let approved = match approval {
        DaemonApproval::Yes => true,
        DaemonApproval::No => false,
        DaemonApproval::Prompt => prompt_approval()?,
    };
    write_frame(
        &mut stream,
        &ClientMessage::Decision {
            schema: PROTOCOL_SCHEMA.into(),
            token,
            approved,
        },
    )?;
    match read_frame::<ServerMessage>(&mut stream)? {
        ServerMessage::Outcome {
            schema,
            command: result_command,
            status,
            plan_digest: result_digest,
            transaction_id,
            actions: result_actions,
        } if schema == PROTOCOL_SCHEMA
            && command == result_command
            && plan_digest == result_digest
            && actions == result_actions =>
        {
            let status = match status.as_str() {
                "applied" => DaemonStatus::Applied,
                "aborted" => DaemonStatus::Aborted,
                _ => return Err(DaemonError::Protocol("invalid outcome status".into())),
            };
            Ok(DaemonOutcome {
                command,
                status,
                plan_digest,
                transaction_id,
                actions,
            })
        }
        ServerMessage::Failed { message, .. } => Err(DaemonError::Protocol(message)),
        _ => Err(DaemonError::Protocol("unexpected outcome response".into())),
    }
}

fn prompt_approval() -> Result<bool, DaemonError> {
    eprint!("dnfast transaction is staged. Continue? [y/N] ");
    io::stderr()
        .flush()
        .map_err(|error| DaemonError::Io(error.to_string()))?;
    let mut reply = String::new();
    io::stdin()
        .read_line(&mut reply)
        .map_err(|error| DaemonError::Io(error.to_string()))?;
    Ok(matches!(reply.trim(), "y" | "Y" | "yes" | "YES"))
}

fn connect_once() -> Result<UnixStream, DaemonError> {
    if rustix::process::geteuid().as_raw() != 0 {
        return Err(DaemonError::NotRoot);
    }
    UnixStream::connect(SYSTEM_SOCKET).map_err(|error| match error.kind() {
        io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused => DaemonError::Unavailable,
        _ => DaemonError::Io(error.to_string()),
    })
}

fn connect_retry() -> Result<UnixStream, DaemonError> {
    let mut deadline = Instant::now() + CONNECT_RETRY_LIMIT;
    let mut service_start_requested = false;
    loop {
        match connect_once() {
            Ok(stream) => return Ok(stream),
            // systemd creates RuntimeDirectory before it execs the service.
            // If the installed service is stopped, request one non-blocking
            // activation through a fixed, root-owned binary and then wait for
            // its root-only socket.  Unsupported/non-systemd environments
            // retain the verified one-shot compatibility fallback.
            Err(DaemonError::Unavailable)
                if !Path::new("/run/dnfast").is_dir() && !service_start_requested =>
            {
                service_start_requested = true;
                if !request_system_service_start() {
                    return Err(DaemonError::Unavailable);
                }
                deadline = Instant::now() + CONNECT_RETRY_LIMIT;
            }
            Err(DaemonError::Unavailable) if Instant::now() < deadline => {
                std::thread::sleep(CONNECT_RETRY_INTERVAL);
            }
            Err(error) => return Err(error),
        }
    }
}

fn request_system_service_start() -> bool {
    if !Path::new("/run/systemd/system").is_dir() {
        return false;
    }
    let Ok(metadata) = fs::symlink_metadata(SYSTEMCTL_PATH) else {
        return false;
    };
    if !metadata.file_type().is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || metadata.nlink() != 1
    {
        return false;
    }
    Command::new(SYSTEMCTL_PATH)
        .args([
            "--system",
            "--no-ask-password",
            "--no-block",
            "start",
            SYSTEM_SERVICE,
        ])
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

pub fn serve_system() -> Result<(), DaemonError> {
    if rustix::process::geteuid().as_raw() != 0 {
        return Err(DaemonError::NotRoot);
    }
    let listener = bind_system_socket()?;
    let mut nonce = [0_u8; 32];
    getrandom::fill(&mut nonce).map_err(|error| DaemonError::Io(error.to_string()))?;
    let journal = dnfast_state::JournalStore::open_system()
        .map_err(|error| DaemonError::Execution(error.to_string()))?;
    let mut planner = ResidentPlanner::default();
    planner.verify_startup(system_architecture()?)?;
    let mut state = DaemonState {
        planner,
        journal,
        nonce,
        sequence: 0,
        recovered_architecture: None,
        trace: std::env::var_os("DNFASTD_TRACE").is_some(),
    };
    for accepted in listener.incoming() {
        let mut stream = match accepted {
            Ok(stream) => stream,
            Err(error) => return Err(DaemonError::Io(error.to_string())),
        };
        if !root_peer(&stream)? {
            let _ = write_failed(&mut stream, "daemon accepts only root peers");
            continue;
        }
        if let Err(error) = handle_connection(&mut state, &mut stream) {
            let _ = write_failed(&mut stream, &error.to_string());
        }
        if state.planner.take_trim_pending() {
            // Result bytes have already crossed the socket boundary.  Keep
            // allocator reclamation off the latency-critical solve/response
            // path while preserving the resident memory bound.
            dnfast_native::release_unused_memory();
        }
    }
    Ok(())
}

fn root_peer(stream: &UnixStream) -> Result<bool, DaemonError> {
    rustix::net::sockopt::socket_peercred(stream)
        .map(|credentials| credentials.uid.as_raw() == 0)
        .map_err(|error| DaemonError::Io(error.to_string()))
}

fn bind_system_socket() -> Result<UnixListener, DaemonError> {
    drop(system_directory(&RUNTIME_PATH).map_err(executor)?);
    fs::set_permissions("/run/dnfast", fs::Permissions::from_mode(0o700))
        .map_err(|error| DaemonError::Io(error.to_string()))?;
    let path = Path::new(SYSTEM_SOCKET);
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if !metadata.file_type().is_socket()
            || metadata.uid() != 0
            || metadata.nlink() != 1
            || metadata.mode() & 0o022 != 0
        {
            return Err(DaemonError::UnsafeSocket);
        }
        if UnixStream::connect(path).is_ok() {
            return Err(DaemonError::Protocol(
                "resident daemon is already running".into(),
            ));
        }
        fs::remove_file(path).map_err(|error| DaemonError::Io(error.to_string()))?;
    }
    let listener = UnixListener::bind(path).map_err(|error| DaemonError::Io(error.to_string()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|error| DaemonError::Io(error.to_string()))?;
    Ok(listener)
}

fn handle_connection(state: &mut DaemonState, stream: &mut UnixStream) -> Result<(), DaemonError> {
    match read_frame::<ClientMessage>(stream)? {
        ClientMessage::Ping { schema } => {
            require_schema(&schema)?;
            write_frame(
                stream,
                &ServerMessage::Pong {
                    schema: PROTOCOL_SCHEMA.into(),
                },
            )
        }
        ClientMessage::Warm {
            schema,
            repositories,
        } => {
            require_schema(&schema)?;
            canonical_repository_ids(&repositories)?;
            let cookie = state.planner.warm(&repositories)?;
            write_frame(
                stream,
                &ServerMessage::Warmed {
                    schema: PROTOCOL_SCHEMA.into(),
                    rpmdb_cookie_sha256: format!("{:x}", Sha256::digest(cookie.as_bytes())),
                },
            )
        }
        ClientMessage::Plan {
            schema,
            action,
            repositories,
            packages,
        } => {
            require_schema(&schema)?;
            canonical_repository_ids(&repositories)?;
            let action = parse_action(&action)?;
            if state
                .planner
                .requires_full_filelists(action, &packages, &repositories)?
            {
                return write_frame(
                    stream,
                    &ServerMessage::Fallback {
                        schema: PROTOCOL_SCHEMA.into(),
                        reason: "absolute path selectors require the full filelists planner".into(),
                    },
                );
            }
            let solved = state.planner.solve(action, packages, &repositories)?;
            revalidate_solved(&solved)?;
            let bytes = solved.plan.canonical_json().map_err(planning)?;
            write_frame(
                stream,
                &ServerMessage::Planned {
                    schema: PROTOCOL_SCHEMA.into(),
                    plan_base64: STANDARD.encode(&bytes),
                    plan_digest: solved.plan.digest().map_err(planning)?.0,
                },
            )
        }
        ClientMessage::Prepare {
            schema,
            action,
            repositories,
            packages,
        } => {
            require_schema(&schema)?;
            canonical_repository_ids(&repositories)?;
            let action = parse_action(&action)?;
            if state
                .planner
                .requires_full_filelists(action, &packages, &repositories)?
            {
                return write_frame(
                    stream,
                    &ServerMessage::Fallback {
                        schema: PROTOCOL_SCHEMA.into(),
                        reason: "absolute path selectors require the full filelists planner".into(),
                    },
                );
            }
            let solved = state.planner.solve(action, packages, &repositories)?;
            state.prepare_and_execute(stream, solved)
        }
        ClientMessage::Decision { .. } => Err(DaemonError::Protocol(
            "decision arrived before a prepared transaction".into(),
        )),
    }
}

struct DaemonState {
    planner: ResidentPlanner,
    journal: dnfast_state::JournalStore,
    nonce: [u8; 32],
    sequence: u64,
    recovered_architecture: Option<Architecture>,
    trace: bool,
}

impl DaemonState {
    fn prepare_and_execute(
        &mut self,
        stream: &mut UnixStream,
        solved: SolvedPlan,
    ) -> Result<(), DaemonError> {
        let started = Instant::now();
        let command = action_name(solved.plan.proposal().intent().action()).to_owned();
        let digest = solved.plan.digest().map_err(planning)?.as_str().to_owned();
        let actions = daemon_actions(&solved.plan);
        self.sequence = self.sequence.wrapping_add(1);
        let token = solve_token(
            &self.nonce,
            self.sequence,
            &solved.plan,
            &solved.rpmdb_cookie,
        )?;
        write_frame(
            stream,
            &ServerMessage::Prepared {
                schema: PROTOCOL_SCHEMA.into(),
                token: token.clone(),
                command: command.clone(),
                plan_digest: digest.clone(),
                actions: actions.clone(),
            },
        )?;
        trace_phase(self.trace, started, "prepared-written");
        let approved = match read_frame::<ClientMessage>(stream)? {
            ClientMessage::Decision {
                schema,
                token: returned,
                approved,
            } => {
                require_schema(&schema)?;
                if !secure_equal(token.as_bytes(), returned.as_bytes()) {
                    return Err(DaemonError::Protocol("solve token mismatch".into()));
                }
                approved
            }
            _ => {
                return Err(DaemonError::Protocol(
                    "expected transaction decision".into(),
                ));
            }
        };
        trace_phase(self.trace, started, "decision-read");
        if !approved {
            return write_frame(
                stream,
                &ServerMessage::Outcome {
                    schema: PROTOCOL_SCHEMA.into(),
                    command,
                    status: "aborted".into(),
                    plan_digest: digest,
                    transaction_id: None,
                    actions,
                },
            );
        }
        revalidate_solved(&solved)?;
        trace_phase(self.trace, started, "decision-revalidated");
        let snapshot = PlanningSnapshot::open_system().map_err(planning)?;
        snapshot.revalidate_runtime_bindings().map_err(planning)?;
        trace_phase(self.trace, started, "runtime-bindings-revalidated");
        if PlanningSnapshot::current_system_digest().map_err(planning)?
            != solved.integrity.planning_snapshot_sha256().as_str()
        {
            return Err(DaemonError::Planning(
                "root-published planning snapshot changed before staging".into(),
            ));
        }
        let architecture = solved.policy.base_arch();
        if self.recovered_architecture != Some(architecture) {
            recover_pending_transactions(&self.journal, architecture).map_err(executor)?;
            self.recovered_architecture = Some(architecture);
        }
        trace_phase(self.trace, started, "revalidate-recover");
        let plan_bytes = solved.plan.canonical_json().map_err(planning)?;
        let staging = Staging::create(&plan_bytes).map_err(executor)?;
        let mut staged = direct_staged_inputs(&solved)?;
        let mut root = MountRoot::create(&staging).map_err(executor)?;
        trace_phase(self.trace, started, "stage");
        let id = dnfast_state::TransactionId::parse(staging.id())
            .map_err(|error| DaemonError::Execution(error.to_string()))?;
        let journal = self
            .journal
            .create(&id, &digest)
            .map_err(|error| DaemonError::Execution(error.to_string()))?;
        root.allow_writes().map_err(executor)?;
        root.verify_unchanged().map_err(executor)?;
        trace_phase(self.trace, started, "journal-mount");
        let execution = run_token_bound(
            &solved.plan,
            &mut staged,
            &solved.inventory,
            &solved.rpmdb_cookie,
            Rc::new(journal),
            "/",
            &root,
        );
        trace_phase(self.trace, started, "rpm-execution");
        let restore = root.restore_namespace_root();
        let cleanup = staging.cleanup();
        restore.map_err(executor)?;
        cleanup.map_err(executor)?;
        let inventory_after = execution.map_err(executor)?;
        trace_phase(self.trace, started, "namespace-cleanup");
        let (source_snapshot, published_snapshot) =
            dnfast_planning::RootPlanningPublisher::system()
                .map_err(|error| DaemonError::Execution(error.to_string()))?
                .publish_inventory_onto_current_with_source(inventory_after.clone())
                .map_err(|error| DaemonError::Execution(error.to_string()))?;
        trace_phase(self.trace, started, "inventory-published");
        self.planner.refresh_after_mutation(
            inventory_after,
            &source_snapshot,
            &published_snapshot,
        )?;
        trace_phase(self.trace, started, "resident-refreshed");
        root.cleanup().map_err(executor)?;
        trace_phase(self.trace, started, "root-cleanup");
        write_frame(
            stream,
            &ServerMessage::Outcome {
                schema: PROTOCOL_SCHEMA.into(),
                command,
                status: "applied".into(),
                plan_digest: digest,
                transaction_id: Some(id.as_str().into()),
                actions,
            },
        )
    }
}

fn trace_phase(enabled: bool, started: Instant, phase: &str) {
    if enabled {
        eprintln!(
            "dnfastd_trace phase={phase} elapsed_us={}",
            started.elapsed().as_micros()
        );
    }
}

#[derive(Default)]
struct ResidentPlanner {
    cached: Option<ResidentPool>,
    verified_rpmdb_cookie: Option<String>,
    pending_installed: Option<PendingInstalled>,
}

struct PendingInstalled {
    architecture: Architecture,
    context: NativeContext,
    snapshot: InventorySnapshot,
    receipt_generation: Option<RpmDbVerifiedGeneration>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RpmDbStartupState {
    schema: String,
    native_abi: u32,
    architecture: String,
    rpmdb_cookie: String,
    inventory_sha256: String,
}

struct ResidentPool {
    snapshot: PlanningSnapshot,
    repository_ids: Vec<String>,
    integrity: dnfast_core::PlanIntegrity,
    policy: SolverPolicy,
    repositories: Vec<PlanningRepository>,
    module_artifact_policy: BTreeMap<String, bool>,
    context: NativeContext,
    inventory: InstalledInventory,
    rpmdb_cookie: String,
    rpmdb_generation: Option<RpmDbVerifiedGeneration>,
    last_solve: Option<CachedResidentSolve>,
    trim_pending: bool,
}

struct CachedResidentSolve {
    action: Action,
    packages: Vec<String>,
    plan: CanonicalSolverPlan,
}

struct SolvedPlan {
    plan: CanonicalSolverPlan,
    integrity: dnfast_core::PlanIntegrity,
    policy: SolverPolicy,
    repositories: Vec<PlanningRepository>,
    inventory: InstalledInventory,
    rpmdb_cookie: String,
}

impl ResidentPlanner {
    fn verify_startup(&mut self, architecture: Architecture) -> Result<(), DaemonError> {
        let trace = std::env::var_os("DNFASTD_TRACE").is_some();
        let started = Instant::now();
        let receipts =
            RpmDbReceiptCache::new(SYSTEM_CACHE_PATH, SYSTEM_RPMDB_PATH, SYSTEM_RPMDB_WAL_PATH);
        let published = PlanningSnapshot::open_system().map_err(planning)?;
        if published.payload().policy.solver.base_arch() != architecture {
            return Err(DaemonError::Planning(
                "root-published architecture differs from the native process".into(),
            ));
        }
        match receipts.current().map_err(planning)? {
            RpmDbCurrentCheck::Hit(current) => {
                if let Ok(state) = serde_json::from_str::<RpmDbStartupState>(current.state()) {
                    let inventory = published.payload().inventory.clone();
                    let inventory_sha256 = inventory.canonical_sha256().map_err(planning)?;
                    let candidate = InventorySnapshot {
                        inventory,
                        rpmdb_cookie: state.rpmdb_cookie.clone(),
                    };
                    let binding = rpmdb_receipt_binding(&candidate, architecture)?;
                    let current_binding = receipts.check(&binding).map_err(planning)?;
                    if state.schema == "dnfast-rpmdb-startup-state-v1"
                        && state.native_abi == dnfast_native_sys::ABI_VERSION
                        && state.architecture == architecture.as_rpm_arch()
                        && !state.rpmdb_cookie.is_empty()
                        && state.rpmdb_cookie.len() <= 4096
                        && state.inventory_sha256 == inventory_sha256.as_str()
                        && matches!(
                            current_binding,
                            RpmDbReceiptCheck::Hit(ref generation)
                                if generation == current.generation()
                        )
                    {
                        let mut context =
                            NativeContext::open(architecture, || false).map_err(planning)?;
                        trace_phase(trace, started, "startup-rpmdb-generation-receipt-hit");
                        load_installed_solv_cache(
                            &mut context,
                            &candidate,
                            architecture,
                            trace,
                            started,
                        )?;
                        self.verified_rpmdb_cookie = Some(candidate.rpmdb_cookie.clone());
                        self.pending_installed = Some(PendingInstalled {
                            architecture,
                            context,
                            snapshot: candidate,
                            receipt_generation: Some(current.generation().clone()),
                        });
                        return Ok(());
                    }
                }
                if trace {
                    eprintln!("dnfastd_trace rpmdb_current_receipt_corrupted=true");
                }
            }
            RpmDbCurrentCheck::Miss { corrupted } => {
                if trace {
                    eprintln!("dnfastd_trace rpmdb_current_receipt_corrupted={corrupted}");
                }
            }
            RpmDbCurrentCheck::Unsupported => {}
        }
        let mut context = NativeContext::open(architecture, || false).map_err(planning)?;
        let before = context
            .read_installed_inventory_snapshot()
            .map_err(planning)?;
        trace_phase(trace, started, "startup-rpmdb-opened");
        let binding = rpmdb_receipt_binding(&before, architecture)?;
        let (snapshot, receipt_generation) = match receipts.check(&binding).map_err(planning)? {
            RpmDbReceiptCheck::Hit(generation) => {
                let state = rpmdb_startup_state(&before, architecture)?;
                receipts
                    .publish_current(&generation, &state)
                    .map_err(planning)?;
                trace_phase(trace, started, "startup-rpmdb-receipt-hit");
                (before, Some(generation))
            }
            RpmDbReceiptCheck::Miss {
                generation,
                corrupted,
            } => {
                if trace {
                    eprintln!("dnfastd_trace rpmdb_receipt_corrupted={corrupted}");
                }
                let snapshot = verify_rpmdb_unchanged(&mut context, before)?;
                let state = rpmdb_startup_state(&snapshot, architecture)?;
                receipts
                    .publish_current(&generation, &state)
                    .map_err(planning)?;
                trace_phase(trace, started, "startup-rpmdb-receipt-published");
                (snapshot, Some(generation))
            }
            RpmDbReceiptCheck::Unsupported => {
                let snapshot = verify_rpmdb_unchanged(&mut context, before)?;
                trace_phase(trace, started, "startup-rpmdb-full-verified");
                (snapshot, None)
            }
        };
        if trace && receipt_generation.is_some() {
            trace_phase(trace, started, "startup-rpmdb-generation-verified");
        }
        load_installed_solv_cache(&mut context, &snapshot, architecture, trace, started)?;
        self.verified_rpmdb_cookie = Some(snapshot.rpmdb_cookie.clone());
        self.pending_installed = Some(PendingInstalled {
            architecture,
            context,
            snapshot,
            receipt_generation,
        });
        Ok(())
    }

    fn warm(&mut self, repositories: &[String]) -> Result<&str, DaemonError> {
        self.ensure(repositories)?;
        Ok(&self.cached.as_ref().expect("resident pool").rpmdb_cookie)
    }

    fn requires_full_filelists(
        &mut self,
        action: Action,
        packages: &[String],
        repositories: &[String],
    ) -> Result<bool, DaemonError> {
        if !packages.iter().any(|package| package.starts_with('/')) {
            return Ok(false);
        }
        self.ensure(repositories)?;
        let cached = self.cached.as_ref().expect("resident pool");
        let missing_from_primary = packages.iter().try_fold(false, |missing, selector| {
            if missing || !selector.starts_with('/') {
                Ok(missing)
            } else {
                cached
                    .context
                    .has_provider(selector)
                    .map(|provided| !provided)
                    .map_err(planning)
            }
        })?;
        Ok(missing_from_primary
            && (action != Action::Install
                || cached
                    .repositories
                    .iter()
                    .any(|repository| repository.file_provides.is_none())))
    }

    fn solve(
        &mut self,
        action: Action,
        packages: Vec<String>,
        repositories: &[String],
    ) -> Result<SolvedPlan, DaemonError> {
        let trace = std::env::var_os("DNFASTD_TRACE").is_some();
        let started = Instant::now();
        let packages = packages
            .into_iter()
            .map(PackageSpec::parse)
            .collect::<Result<Vec<_>, _>>()
            .map_err(planning)?;
        let intent = TransactionIntent::new(action, packages).map_err(planning)?;
        self.ensure(repositories)?;
        trace_phase(trace, started, "resident-ensure");
        let cached = self.cached.as_mut().expect("resident pool");
        let names = intent
            .packages()
            .iter()
            .map(|package| package.as_str())
            .collect::<Vec<_>>();
        let now = now_unix()?;
        if let Some(plan) = cached
            .last_solve
            .as_ref()
            .filter(|entry| {
                entry.action == action
                    && entry
                        .packages
                        .iter()
                        .map(String::as_str)
                        .eq(names.iter().copied())
                    && entry.plan.proposal().expires_at_unix() > now
            })
            .map(|entry| entry.plan.clone())
        {
            trace_phase(trace, started, "resident-solve-cache-hit");
            return Ok(SolvedPlan {
                plan,
                integrity: cached.integrity.clone(),
                policy: cached.policy.clone(),
                repositories: cached.repositories.clone(),
                inventory: cached.inventory.clone(),
                rpmdb_cookie: cached.rpmdb_cookie.clone(),
            });
        }
        let policy = cached.policy.clone();
        let mapped = mapped_file_selectors(cached, &names)?;
        let result = match action {
            Action::Install if mapped.is_empty() => {
                cached
                    .context
                    .solve_install_many(&names, policy.install_weak_deps(), policy.best())
            }
            Action::Install => cached.context.solve_install_many_mapped(
                &names,
                policy.install_weak_deps(),
                policy.best(),
                &mapped,
            ),
            Action::Upgrade => cached.context.solve_upgrade_many(&names, policy.best()),
            Action::Downgrade => cached.context.solve_downgrade_many(&names),
            Action::Reinstall => cached.context.solve_reinstall_many(&names),
            Action::DistroSync => cached.context.solve_distro_sync_many(&names, policy.best()),
            Action::Remove => cached.context.solve_erase_many(&names),
            Action::Autoremove => cached.context.solve_autoremove_many(&names),
        }
        .map_err(planning)?;
        cached.trim_pending = true;
        trace_phase(trace, started, "resident-native-solve");
        if trace {
            eprintln!(
                "dnfastd_trace native_actions={} native_decisions={}",
                result.actions.len(),
                result.decisions.len()
            );
        }
        let candidates = selected_candidate_evidence(cached, &result, policy.base_arch())?;
        trace_phase(trace, started, "resident-candidate-evidence");
        let metadata = selected_decision_evidence(cached, &result)?;
        trace_phase(trace, started, "resident-decision-evidence");
        let metadata = metadata
            .iter()
            .map(|(repository, package)| (repository.as_str(), package))
            .collect::<Vec<_>>();
        let transcript = NativeSolveOutput::from_native_compact(
            result,
            cached.integrity.metadata_sha256().as_str().into(),
            &metadata,
            &cached.inventory,
        )
        .map_err(planning)?;
        trace_phase(trace, started, "resident-native-adapter");
        let satisfied_specs = transcript.satisfied_specs().to_vec();
        let resolved = transcript
            .into_resolved_compact(&names, &candidates, &metadata, &cached.inventory)
            .map_err(planning)?;
        trace_phase(trace, started, "resident-resolved");
        let plan = PlanBuilder {
            intent: &intent,
            snapshots: &cached.integrity,
            inventory: &cached.inventory,
            policy: &policy,
            candidates: &candidates,
            expires_at_unix: now.saturating_add(PLAN_LIFETIME_SECONDS),
        }
        .build_with_satisfied(&resolved, &satisfied_specs)
        .map_err(|error| {
            if error == dnfast_solver::PlanError::NoChanges {
                DaemonError::NoChanges
            } else {
                planning(error)
            }
        })?;
        trace_phase(trace, started, "resident-plan-built");
        cached.last_solve = Some(CachedResidentSolve {
            action,
            packages: names.iter().map(|name| (*name).to_owned()).collect(),
            plan: plan.clone(),
        });
        Ok(SolvedPlan {
            plan,
            integrity: cached.integrity.clone(),
            policy,
            repositories: cached.repositories.clone(),
            inventory: cached.inventory.clone(),
            rpmdb_cookie: cached.rpmdb_cookie.clone(),
        })
    }

    fn ensure(&mut self, repositories: &[String]) -> Result<(), DaemonError> {
        let current_digest = PlanningSnapshot::current_system_digest().map_err(planning)?;
        let same_generation = self.cached.as_ref().is_some_and(|cached| {
            cached.repository_ids == repositories
                && cached.integrity.planning_snapshot_sha256().as_str() == current_digest
        });
        let mut receipt_missed = false;
        if same_generation {
            let cached = self.cached.as_mut().expect("resident pool");
            if let Some(generation) = cached.rpmdb_generation.as_ref() {
                let current = RpmDbReceiptCache::new(
                    SYSTEM_CACHE_PATH,
                    SYSTEM_RPMDB_PATH,
                    SYSTEM_RPMDB_WAL_PATH,
                )
                .is_current(generation)
                .map_err(planning)?;
                if current {
                    return Ok(());
                }
                receipt_missed = true;
            } else {
                let current = cached
                    .context
                    .read_installed_inventory_snapshot()
                    .map_err(planning)?;
                if cached.rpmdb_cookie == current.rpmdb_cookie {
                    return Ok(());
                }
            }
        }
        if receipt_missed {
            // A changed or damaged generation receipt must not fall back to a
            // cookie-only acceptance during the rebuild below.
            self.verified_rpmdb_cookie = None;
        }
        let snapshot = PlanningSnapshot::open_system().map_err(planning)?;
        let integrity = snapshot
            .integrity_for_repositories(repositories)
            .map_err(planning)?;
        let (pool, verified_cookie) = build_pool(
            snapshot,
            repositories.to_vec(),
            integrity,
            self.verified_rpmdb_cookie.as_deref(),
            self.pending_installed.take(),
        )?;
        self.verified_rpmdb_cookie = Some(verified_cookie);
        self.cached = Some(pool);
        Ok(())
    }

    fn invalidate(&mut self) {
        self.cached = None;
        self.pending_installed = None;
    }

    fn take_trim_pending(&mut self) -> bool {
        self.cached
            .as_mut()
            .is_some_and(|cached| std::mem::take(&mut cached.trim_pending))
    }

    fn refresh_after_mutation(
        &mut self,
        inventory: InstalledInventory,
        source_snapshot: &str,
        published_snapshot: &str,
    ) -> Result<(), DaemonError> {
        let result =
            self.refresh_after_mutation_inner(inventory, source_snapshot, published_snapshot);
        if result.is_err() {
            self.invalidate();
        }
        result
    }

    fn refresh_after_mutation_inner(
        &mut self,
        inventory: InstalledInventory,
        source_snapshot: &str,
        published_snapshot: &str,
    ) -> Result<(), DaemonError> {
        if self.cached.as_ref().is_some_and(|cached| {
            cached.integrity.planning_snapshot_sha256().as_str() != source_snapshot
        }) {
            self.invalidate();
            return Ok(());
        }
        let cached = self.cached.as_mut().ok_or_else(|| {
            DaemonError::Execution("resident solver pool disappeared after transaction".into())
        })?;
        cached.context.add_installed_rpmdb("/").map_err(planning)?;
        let current = cached
            .context
            .read_installed_inventory_snapshot()
            .map_err(planning)?;
        if current.inventory.canonical_sha256().map_err(planning)?
            != inventory.canonical_sha256().map_err(planning)?
        {
            return Err(DaemonError::Execution(
                "published inventory differs from the post-transaction RPMDB".into(),
            ));
        }
        let inventory_sha256 = inventory.canonical_sha256().map_err(planning)?;
        cached.integrity = dnfast_core::PlanIntegrity::new(
            [
                cached.integrity.policy_sha256().as_str(),
                cached.integrity.trust_sha256().as_str(),
                inventory_sha256.as_str(),
                cached.integrity.metadata_sha256().as_str(),
                published_snapshot,
            ],
            cached.integrity.selected_repositories().to_vec(),
        )
        .map_err(planning)?;
        cached.inventory = inventory;
        cached.rpmdb_cookie.clone_from(&current.rpmdb_cookie);
        cached.rpmdb_generation = None;
        cached.last_solve = None;
        self.verified_rpmdb_cookie = Some(current.rpmdb_cookie);
        Ok(())
    }
}

fn rpmdb_startup_state(
    snapshot: &InventorySnapshot,
    architecture: Architecture,
) -> Result<String, DaemonError> {
    serde_json::to_string(&RpmDbStartupState {
        schema: "dnfast-rpmdb-startup-state-v1".into(),
        native_abi: dnfast_native_sys::ABI_VERSION,
        architecture: architecture.as_rpm_arch().into(),
        rpmdb_cookie: snapshot.rpmdb_cookie.clone(),
        inventory_sha256: snapshot
            .inventory
            .canonical_sha256()
            .map_err(planning)?
            .as_str()
            .into(),
    })
    .map_err(|error| DaemonError::Planning(error.to_string()))
}

fn build_pool(
    snapshot: PlanningSnapshot,
    repository_ids: Vec<String>,
    integrity: dnfast_core::PlanIntegrity,
    verified_rpmdb_cookie: Option<&str>,
    pending_installed: Option<PendingInstalled>,
) -> Result<(ResidentPool, String), DaemonError> {
    let trace = std::env::var_os("DNFASTD_TRACE").is_some();
    let started = Instant::now();
    let policy = snapshot.payload().policy.solver.clone();
    let (mut context, mut current, require_full_verify, rpmdb_generation) = match pending_installed
    {
        Some(mut pending) if pending.architecture == policy.base_arch() => {
            let receipt_current = match pending.receipt_generation.as_ref() {
                Some(generation) => RpmDbReceiptCache::new(
                    SYSTEM_CACHE_PATH,
                    SYSTEM_RPMDB_PATH,
                    SYSTEM_RPMDB_WAL_PATH,
                )
                .is_current(generation)
                .map_err(planning)?,
                None => false,
            };
            if receipt_current {
                trace_phase(trace, started, "resident-build-rpmdb-generation-hit");
                (
                    pending.context,
                    pending.snapshot,
                    false,
                    pending.receipt_generation,
                )
            } else {
                let live = pending
                    .context
                    .read_installed_inventory_snapshot()
                    .map_err(planning)?;
                let require_full_verify = pending.receipt_generation.is_some();
                if same_inventory_generation(&pending.snapshot, &live)? {
                    (pending.context, live, require_full_verify, None)
                } else {
                    let (context, snapshot) = open_installed_context(policy.base_arch())?;
                    (context, snapshot, require_full_verify, None)
                }
            }
        }
        _ => {
            let (context, snapshot) = open_installed_context(policy.base_arch())?;
            (context, snapshot, false, None)
        }
    };
    trace_phase(trace, started, "resident-build-context-open");
    if require_full_verify || verified_rpmdb_cookie != Some(current.rpmdb_cookie.as_str()) {
        current = verify_rpmdb_unchanged(&mut context, current)?;
    }
    trace_phase(trace, started, "resident-build-rpmdb-verified");
    let InventorySnapshot {
        inventory,
        rpmdb_cookie,
    } = current;
    if inventory.canonical_sha256().map_err(planning)?
        != snapshot
            .payload()
            .inventory
            .canonical_sha256()
            .map_err(planning)?
    {
        return Err(DaemonError::Planning(
            "root-published planning snapshot has stale RPMDB inventory".into(),
        ));
    }
    let selected = selected_repositories(&snapshot, &integrity)?;
    let module_catalog = snapshot.module_catalog(&repository_ids).map_err(planning)?;
    let module_artifact_policy = module_catalog
        .artifact_policies(&snapshot.payload().module_state, policy.base_arch())
        .map_err(planning)?;
    trace_phase(trace, started, "resident-build-repositories-selected");
    let workspace = tempfile::tempdir().map_err(|error| DaemonError::Io(error.to_string()))?;
    let solv_cache = SolvCache::new(SYSTEM_CACHE_PATH);
    for (index, repository) in selected.iter().enumerate() {
        let priority = i32::try_from(repository.priority).map_err(planning)?;
        let cost = i32::try_from(repository.cost).map_err(planning)?;
        let (binding, binding_sha256) =
            dnfast_planning::repository_solv_cache_binding(repository, policy.base_arch())
                .map_err(planning)?;
        let cached = match solv_cache.open(&binding_sha256) {
            Ok(cached) => cached,
            Err(CacheError::Corrupt(message)) => {
                if trace {
                    eprintln!(
                        "dnfastd_trace solv_cache_repo={} corrupted={message:?}",
                        repository.id
                    );
                }
                None
            }
            Err(error) => return Err(planning(error)),
        };
        match cached {
            Some(cache) => {
                context
                    .add_repository_solv(&repository.id, priority, cost, cache.file(), &binding)
                    .map_err(planning)?;
                if trace {
                    eprintln!(
                        "dnfastd_trace solv_cache_repo={} verification={:?} sha256={} size={}",
                        repository.id,
                        cache.verification(),
                        cache.sha256(),
                        cache.size()
                    );
                }
                trace_phase(
                    trace,
                    started,
                    &format!("resident-build-{index}-solv-cache-hit"),
                );
            }
            None => {
                let paths = materialize(&snapshot, workspace.path(), index, repository)?;
                trace_phase(
                    trace,
                    started,
                    &format!("resident-build-{index}-materialized"),
                );
                context
                    .add_repository_primary(Repository {
                        id: repository.id.clone(),
                        repomd_path: paths.0,
                        primary_path: paths.1,
                        filelists_path: paths.2,
                        priority,
                        cost,
                    })
                    .map_err(planning)?;
                let staged = solv_cache.stage(&binding_sha256).map_err(planning)?;
                context
                    .write_repository_solv(&repository.id, staged.file(), &binding)
                    .map_err(planning)?;
                let published = staged.commit().map_err(planning)?;
                if trace {
                    eprintln!(
                        "dnfastd_trace solv_cache_repo={} sha256={} size={}",
                        repository.id,
                        published.sha256(),
                        published.size()
                    );
                }
            }
        }
        trace_phase(
            trace,
            started,
            &format!("resident-build-{index}-native-loaded"),
        );
    }
    let module_excludes = module_artifact_policy
        .iter()
        .filter_map(|(artifact, excluded)| excluded.then_some(artifact.clone()))
        .collect::<Vec<_>>();
    context
        .set_module_excludes(&module_excludes)
        .map_err(planning)?;
    context.prepare_solver().map_err(planning)?;
    trace_phase(trace, started, "resident-build-solver-prepared");
    let verified_cookie = rpmdb_cookie.clone();
    let repositories = selected.into_iter().cloned().collect();
    Ok((
        ResidentPool {
            snapshot,
            repository_ids,
            integrity,
            policy,
            repositories,
            module_artifact_policy,
            context,
            inventory,
            rpmdb_cookie,
            rpmdb_generation,
            last_solve: None,
            // Pool construction is the other large transient allocation.
            // Reclaim it after the first response even when that response is
            // only a warm request and does not execute a solve.
            trim_pending: true,
        },
        verified_cookie,
    ))
}

fn open_installed_context(
    architecture: Architecture,
) -> Result<(NativeContext, InventorySnapshot), DaemonError> {
    let mut context = NativeContext::open(architecture, || false).map_err(planning)?;
    context.add_installed_rpmdb("/").map_err(planning)?;
    let snapshot = context
        .read_installed_inventory_snapshot()
        .map_err(planning)?;
    Ok((context, snapshot))
}

fn verify_rpmdb_unchanged(
    context: &mut NativeContext,
    before: InventorySnapshot,
) -> Result<InventorySnapshot, DaemonError> {
    context.verify_installed_rpmdb().map_err(planning)?;
    let after = context
        .read_installed_inventory_snapshot()
        .map_err(planning)?;
    if !same_inventory_generation(&before, &after)? {
        return Err(DaemonError::Planning(
            "RPMDB changed while full verification was in progress".into(),
        ));
    }
    Ok(after)
}

fn same_inventory_generation(
    before: &InventorySnapshot,
    after: &InventorySnapshot,
) -> Result<bool, DaemonError> {
    Ok(before.rpmdb_cookie == after.rpmdb_cookie
        && before.inventory.canonical_sha256().map_err(planning)?
            == after.inventory.canonical_sha256().map_err(planning)?)
}

fn rpmdb_receipt_binding(
    snapshot: &InventorySnapshot,
    architecture: Architecture,
) -> Result<String, DaemonError> {
    let inventory = snapshot.inventory.canonical_sha256().map_err(planning)?;
    let value = format!(
        "dnfast-rpmdb-verification-receipt-v2\nnative_abi={}\narchitecture={}\nrpmdb_cookie={}\ninventory_sha256={}\n",
        dnfast_native_sys::ABI_VERSION,
        architecture.as_rpm_arch(),
        snapshot.rpmdb_cookie,
        inventory.as_str(),
    );
    Ok(hex::encode(Sha256::digest(value.as_bytes())))
}

fn load_installed_solv_cache(
    context: &mut NativeContext,
    snapshot: &InventorySnapshot,
    architecture: Architecture,
    trace: bool,
    started: Instant,
) -> Result<(), DaemonError> {
    let (binding, binding_sha256) =
        dnfast_planning::installed_solv_cache_binding(snapshot, architecture).map_err(planning)?;
    let cache = SolvCache::new(SYSTEM_CACHE_PATH);
    let cached = match cache.open(&binding_sha256) {
        Ok(cached) => cached,
        Err(CacheError::Corrupt(message)) => {
            if trace {
                eprintln!("dnfastd_trace installed_solv_cache_corrupted={message:?}");
            }
            None
        }
        Err(error) => return Err(planning(error)),
    };
    match cached {
        Some(cached) => {
            context
                .add_installed_repository_solv(cached.file(), &binding)
                .map_err(planning)?;
            if trace {
                eprintln!(
                    "dnfastd_trace installed_solv_cache verification={:?} sha256={} size={}",
                    cached.verification(),
                    cached.sha256(),
                    cached.size()
                );
            }
            trace_phase(trace, started, "startup-installed-solv-cache-hit");
        }
        None => {
            context.add_installed_rpmdb("/").map_err(planning)?;
            let staged = cache.stage(&binding_sha256).map_err(planning)?;
            context
                .write_repository_solv("@System", staged.file(), &binding)
                .map_err(planning)?;
            let published = staged.commit().map_err(planning)?;
            if trace {
                eprintln!(
                    "dnfastd_trace installed_solv_cache published_sha256={} size={}",
                    published.sha256(),
                    published.size()
                );
            }
            trace_phase(trace, started, "startup-installed-solv-cache-published");
        }
    }
    Ok(())
}

fn system_architecture() -> Result<Architecture, DaemonError> {
    match std::env::consts::ARCH {
        "aarch64" => Ok(Architecture::Aarch64),
        "x86_64" => Ok(Architecture::X86_64),
        architecture => Err(DaemonError::Planning(format!(
            "unsupported daemon architecture: {architecture}"
        ))),
    }
}

fn revalidate_solved(solved: &SolvedPlan) -> Result<(), DaemonError> {
    solved
        .plan
        .proposal()
        .validate_executable(&solved.policy, now_unix()?)
        .map_err(execution)?;
    if PlanningSnapshot::current_system_digest().map_err(planning)?
        != solved.integrity.planning_snapshot_sha256().as_str()
    {
        return Err(DaemonError::Planning(
            "root-published planning snapshot changed after solve".into(),
        ));
    }
    Ok(())
}

fn direct_staged_inputs(solved: &SolvedPlan) -> Result<StagedInputs, DaemonError> {
    let repositories = solved
        .repositories
        .iter()
        .map(|repository| {
            let keys = repository
                .keys
                .iter()
                .map(|key| {
                    let certificate = STANDARD.decode(&key.certificate_base64).map_err(|_| {
                        DaemonError::Execution(
                            "root-published key certificate is not base64".into(),
                        )
                    })?;
                    Ok(VerifiedStagedKey {
                        bundle_path: key.bundle_path.clone(),
                        certificate,
                    })
                })
                .collect::<Result<Vec<_>, DaemonError>>()?;
            Ok(StagedRepository {
                repository: Repository {
                    id: repository.id.clone(),
                    repomd_path: String::new(),
                    primary_path: String::new(),
                    filelists_path: String::new(),
                    priority: i32::try_from(repository.priority).map_err(execution)?,
                    cost: i32::try_from(repository.cost).map_err(execution)?,
                },
                trust: repository.trust.clone(),
                keys,
                generation_sha256: repository.generation_sha256.clone(),
                origin_sha256: repository.origin.sha256.clone(),
                trust_sha256: repository
                    .trust
                    .canonical_sha256()
                    .map_err(execution)?
                    .as_str()
                    .into(),
            })
        })
        .collect::<Result<Vec<_>, DaemonError>>()?;
    let pending = solved
        .plan
        .actions()
        .iter()
        .filter_map(|action| {
            action.artifact.as_ref().map(|record| {
                let repo_id = action.repo_id.as_deref().ok_or_else(|| {
                    DaemonError::Execution("planned artifact has no repository".into())
                })?;
                let repository = solved
                    .repositories
                    .iter()
                    .find(|repository| repository.id == repo_id)
                    .ok_or_else(|| {
                        DaemonError::Execution("planned artifact repository is absent".into())
                    })?;
                let base = repository
                    .origin
                    .repomd_url
                    .strip_suffix("/repodata/repomd.xml")
                    .ok_or_else(|| {
                        DaemonError::Execution("selected artifact origin is invalid".into())
                    })?;
                let spec = ArtifactSpec::from_selected_mirror(
                    base,
                    &record.location,
                    ArtifactDigest::Sha256(record.checksum_sha256.clone()),
                    record.package_size,
                )
                .map_err(execution)?;
                Ok((action, repository, spec))
            })
        })
        .collect::<Result<Vec<_>, DaemonError>>()?;
    let mut artifacts = Vec::with_capacity(pending.len());
    if !pending.is_empty() {
        let request = TransactionRequest::for_specs(
            &pending
                .iter()
                .map(|(_, _, spec)| spec.clone())
                .collect::<Vec<_>>(),
        )
        .map_err(execution)?;
        let cache = ArtifactCache::new(SYSTEM_CACHE_PATH);
        let mut transaction = cache.begin_transaction(&request).map_err(execution)?;
        let transport = HttpArtifactTransport::new();
        for (action, repository, spec) in pending {
            let cached = transaction.fetch(&spec, &transport).map_err(execution)?;
            let record = action.artifact.as_ref().expect("pending artifact");
            artifacts.push(StagedArtifact {
                file: cached.file().try_clone().map_err(execution)?,
                expected: ExpectedPackage {
                    name: action.name.clone(),
                    epoch: u64::from(action.target_evra.epoch()),
                    version: action.target_evra.version().into(),
                    release: action.target_evra.release().into(),
                    arch: action.target_evra.arch().as_rpm_arch().into(),
                    vendor: action.vendor.clone().ok_or_else(|| {
                        DaemonError::Execution("planned artifact has no vendor".into())
                    })?,
                },
                sha256: record.checksum_sha256.clone(),
                size: record.package_size,
                repo_id: repository.id.clone(),
                generation_sha256: repository.generation_sha256.clone(),
                origin_sha256: repository.origin.sha256.clone(),
                trust_sha256: repository
                    .trust
                    .canonical_sha256()
                    .map_err(execution)?
                    .as_str()
                    .into(),
            });
        }
        if transaction.remaining() != 0 {
            return Err(DaemonError::Execution(
                "artifact transaction did not drain".into(),
            ));
        }
    }
    Ok(StagedInputs {
        policy: solved.policy.clone(),
        repositories,
        candidates: Vec::new(),
        metadata: Vec::new(),
        artifacts,
    })
}

fn selected_repositories<'a>(
    snapshot: &'a PlanningSnapshot,
    integrity: &dnfast_core::PlanIntegrity,
) -> Result<Vec<&'a PlanningRepository>, DaemonError> {
    integrity
        .selected_repositories()
        .iter()
        .map(|binding| {
            snapshot
                .payload()
                .allowed_repositories
                .iter()
                .find(|repository| repository.id == binding.id())
                .ok_or_else(|| {
                    DaemonError::Planning("root-published repository binding disappeared".into())
                })
        })
        .collect()
}

fn materialize(
    snapshot: &PlanningSnapshot,
    root: &Path,
    index: usize,
    repository: &PlanningRepository,
) -> Result<MaterializedRepository, DaemonError> {
    let prefix = format!("repository-{index}");
    let metadata = snapshot
        .materialize_native_primary_unparsed(repository)
        .map_err(planning)?;
    let repomd = write_temp(root, &format!("{prefix}-repomd.xml"), metadata.repomd())?;
    let primary = write_temp(root, &format!("{prefix}-primary.xml"), metadata.primary())?;
    let filelists = write_temp(root, &format!("{prefix}-filelists.xml"), &[])?;
    Ok((display(&repomd)?, display(&primary)?, display(&filelists)?))
}

fn write_temp(root: &Path, name: &str, bytes: &[u8]) -> Result<PathBuf, DaemonError> {
    let path = root.join(name);
    fs::write(&path, bytes).map_err(|error| DaemonError::Io(error.to_string()))?;
    Ok(path)
}

fn display(path: &Path) -> Result<String, DaemonError> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| DaemonError::Planning("temporary metadata path is not UTF-8".into()))
}

fn resident_candidate_for(
    repository: &PlanningRepository,
    item: dnfast_native::RepositoryPackage,
    base_architecture: Architecture,
) -> Result<Option<CandidatePackage>, DaemonError> {
    let (epoch, version, release) = parse_native_evr(&item.evr)?;
    let architecture = match item.arch.as_str() {
        "aarch64" => Architecture::Aarch64,
        "x86_64" => Architecture::X86_64,
        "noarch" => Architecture::Noarch,
        "i686" if base_architecture == Architecture::X86_64 => return Ok(None),
        _ => {
            return Err(DaemonError::Planning(
                "root-published metadata has an unsupported architecture".into(),
            ));
        }
    };
    if item.checksum_sha256.len() != 64
        || !item
            .checksum_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(DaemonError::Planning(
            "native package checksum is not canonical SHA-256".into(),
        ));
    }
    Ok(Some(CandidatePackage {
        name: item.name,
        evra: Evra::new(epoch, version, release, architecture),
        vendor: if item.vendor.is_empty() {
            "unknown".into()
        } else {
            item.vendor
        },
        repo_id: repository.id.clone(),
        priority: repository.priority,
        cost: repository.cost,
        package_size: item.package_size,
        installed_size: item.installed_size,
        checksum_sha256: item.checksum_sha256,
        location: item.location,
        excluded: false,
        modular: false,
    }))
}

fn selected_candidate_evidence(
    cached: &mut ResidentPool,
    result: &dnfast_native::SolveResult,
    base_architecture: Architecture,
) -> Result<Vec<CandidatePackage>, DaemonError> {
    let mut names = BTreeSet::new();
    for (identity, repository) in result.actions.iter().zip(&result.repositories) {
        if repository == "@System" {
            continue;
        }
        let package = cached
            .context
            .repository_package_identity_evidence(repository, identity)
            .map_err(planning)?;
        if native_package_identity(&package)? != *identity {
            return Err(DaemonError::Planning(
                "selected candidate identity changed during extraction".into(),
            ));
        }
        names.insert(package.name);
    }
    let mut candidates = Vec::new();
    for repository in &cached.repositories {
        for name in &names {
            for package in cached
                .context
                .repository_catalog_named(&repository.id, name)
                .map_err(planning)?
            {
                if let Some(candidate) =
                    resident_candidate_for(repository, package, base_architecture)?
                {
                    candidates.push(candidate);
                }
            }
        }
    }
    apply_module_artifact_policy(&mut candidates, &cached.module_artifact_policy);
    Ok(candidates)
}

fn selected_decision_evidence(
    cached: &mut ResidentPool,
    result: &dnfast_native::SolveResult,
) -> Result<Vec<(String, NativePackageEvidence)>, DaemonError> {
    let mut action_repositories = BTreeMap::new();
    for (identity, repository) in result.actions.iter().zip(&result.repositories) {
        // A reinstall emits equal new and installed NEVRAs. Only repository
        // actions can require other transaction actions; installed providers
        // use Decision::provider_installed and never need this lookup.
        if repository == "@System" {
            continue;
        }
        if action_repositories
            .insert(identity.as_str(), repository.as_str())
            .is_some()
        {
            return Err(DaemonError::Planning(
                "native action identity is duplicated".into(),
            ));
        }
    }
    let mut selected = BTreeSet::new();
    for decision in &result.decisions {
        let requiring_repository = action_repositories
            .get(decision.requiring.as_str())
            .copied()
            .ok_or_else(|| {
                DaemonError::Planning("native requiring action has no repository".into())
            })?;
        selected.insert((requiring_repository.to_owned(), decision.requiring.clone()));
        if !decision.provider_installed {
            let provider_repository = action_repositories
                .get(decision.provider.as_str())
                .copied()
                .ok_or_else(|| {
                    DaemonError::Planning("native provider action has no repository".into())
                })?;
            selected.insert((provider_repository.to_owned(), decision.provider.clone()));
        }
    }
    let mut evidence = Vec::with_capacity(selected.len());
    for (repository, identity) in selected {
        let package = cached
            .context
            .repository_package_identity_evidence(&repository, &identity)
            .map_err(planning)?;
        let package_identity = native_package_identity(&package)?;
        if package_identity != identity {
            return Err(DaemonError::Planning(
                "decision evidence ordinal changed identity".into(),
            ));
        }
        let (epoch, version, release) = parse_native_evr(&package.evr)?;
        evidence.push((
            repository,
            NativePackageEvidence::from_native(NativePackageEvidenceParts {
                name: package.name,
                arch: package.arch,
                epoch: epoch.to_string(),
                version,
                release,
                requires: package.requires,
                recommends: package.recommends,
                supplements: package.supplements,
                enhances: package.enhances,
            }),
        ));
    }
    Ok(evidence)
}

fn native_package_identity(
    package: &dnfast_native::RepositoryPackage,
) -> Result<String, DaemonError> {
    let (epoch, version, release) = parse_native_evr(&package.evr)?;
    Ok(format!(
        "{}-{}:{}-{}.{}",
        package.name, epoch, version, release, package.arch
    ))
}

fn parse_native_evr(evr: &str) -> Result<(u32, String, String), DaemonError> {
    let (epoch, version_release) = evr
        .split_once(':')
        .map_or(("0", evr), |(epoch, rest)| (epoch, rest));
    let epoch = epoch
        .parse()
        .map_err(|_| DaemonError::Planning("invalid native package epoch".into()))?;
    let (version, release) = version_release
        .rsplit_once('-')
        .ok_or_else(|| DaemonError::Planning("native package EVR has no release".into()))?;
    if version.is_empty() || release.is_empty() {
        return Err(DaemonError::Planning(
            "native package EVR is incomplete".into(),
        ));
    }
    Ok((epoch, version.into(), release.into()))
}

fn mapped_file_selectors(
    cached: &mut ResidentPool,
    names: &[&str],
) -> Result<Vec<MappedSelector>, DaemonError> {
    let mut mapped = Vec::new();
    for (selector_index, selector) in names.iter().enumerate() {
        if !selector.starts_with('/') || cached.context.has_provider(selector).map_err(planning)? {
            continue;
        }
        let mut providers = Vec::new();
        for repository in &cached.repositories {
            for ordinal in cached
                .snapshot
                .file_providers(repository, selector)
                .map_err(planning)?
            {
                let package = cached
                    .context
                    .repository_package_evidence(&repository.id, ordinal as usize)
                    .map_err(planning)?;
                let identity = native_package_identity(&package)?;
                providers.push(FileProvider {
                    repository_id: repository.id.clone(),
                    package_ordinal: ordinal,
                    expected_identity: identity,
                });
            }
        }
        if !providers.is_empty() {
            providers.sort_by(|left, right| {
                left.repository_id
                    .cmp(&right.repository_id)
                    .then_with(|| left.package_ordinal.cmp(&right.package_ordinal))
            });
            providers.dedup();
            mapped.push(MappedSelector {
                selector_index,
                providers,
            });
        }
    }
    Ok(mapped)
}

fn solve_token(
    nonce: &[u8; 32],
    sequence: u64,
    plan: &CanonicalSolverPlan,
    rpmdb_cookie: &str,
) -> Result<String, DaemonError> {
    let proposal = plan.proposal();
    let mut digest = Sha256::new();
    digest.update(b"dnfast-resident-solve-token-v1");
    frame_digest(&mut digest, nonce)?;
    frame_digest(&mut digest, &sequence.to_be_bytes())?;
    frame_digest(
        &mut digest,
        plan.digest().map_err(planning)?.as_str().as_bytes(),
    )?;
    frame_digest(&mut digest, rpmdb_cookie.as_bytes())?;
    frame_digest(&mut digest, proposal.metadata_sha256().as_str().as_bytes())?;
    frame_digest(&mut digest, proposal.trust_sha256().as_str().as_bytes())?;
    frame_digest(&mut digest, proposal.policy_sha256().as_str().as_bytes())?;
    frame_digest(&mut digest, &proposal.expires_at_unix().to_be_bytes())?;
    Ok(format!("{:x}", digest.finalize()))
}

fn frame_digest(digest: &mut Sha256, bytes: &[u8]) -> Result<(), DaemonError> {
    digest.update(u64::try_from(bytes.len()).map_err(planning)?.to_be_bytes());
    digest.update(bytes);
    Ok(())
}

fn daemon_actions(plan: &CanonicalSolverPlan) -> Vec<DaemonAction> {
    plan.actions()
        .iter()
        .map(|action| DaemonAction {
            kind: action.operation.clone(),
            name: action.name.clone(),
            epoch: action.target_evra.epoch().to_string(),
            version: action.target_evra.version().into(),
            release: action.target_evra.release().into(),
            arch: action.target_evra.arch().as_rpm_arch().into(),
            repo_id: action.repo_id.clone(),
            reason: match action.reason {
                dnfast_core::PackageReason::User => "user",
                dnfast_core::PackageReason::Dependency => "dependency",
                dnfast_core::PackageReason::WeakDependency => "weak_dependency",
                dnfast_core::PackageReason::External => "external",
                dnfast_core::PackageReason::Unknown => "unknown",
            }
            .into(),
        })
        .collect()
}

fn parse_action(value: &str) -> Result<Action, DaemonError> {
    match value {
        "install" => Ok(Action::Install),
        "upgrade" => Ok(Action::Upgrade),
        "remove" => Ok(Action::Remove),
        "downgrade" => Ok(Action::Downgrade),
        "reinstall" => Ok(Action::Reinstall),
        "distro-sync" => Ok(Action::DistroSync),
        "autoremove" => Ok(Action::Autoremove),
        _ => Err(DaemonError::Protocol("invalid transaction action".into())),
    }
}

const fn action_name(action: Action) -> &'static str {
    match action {
        Action::Install => "install",
        Action::Upgrade => "upgrade",
        Action::Remove => "remove",
        Action::Downgrade => "downgrade",
        Action::Reinstall => "reinstall",
        Action::DistroSync => "distro-sync",
        Action::Autoremove => "autoremove",
    }
}

fn canonical_repository_ids(repositories: &[String]) -> Result<(), DaemonError> {
    if repositories.iter().any(|repository| {
        repository.is_empty()
            || repository
                .bytes()
                .any(|byte| !(byte.is_ascii_alphanumeric() || b"_.-".contains(&byte)))
    }) || repositories.windows(2).any(|pair| pair[0] >= pair[1])
    {
        Err(DaemonError::Protocol(
            "repository identifiers must be sorted, unique, and canonical".into(),
        ))
    } else {
        Ok(())
    }
}

#[cfg(test)]
fn paths_require_full_filelists_by(
    packages: &[String],
    primary_contains: impl Fn(&str) -> bool,
) -> bool {
    packages
        .iter()
        .any(|selector| selector.starts_with('/') && !primary_contains(selector))
}

fn require_schema(schema: &str) -> Result<(), DaemonError> {
    if schema == PROTOCOL_SCHEMA {
        Ok(())
    } else {
        Err(DaemonError::Protocol("unsupported protocol schema".into()))
    }
}

fn secure_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |different, (left, right)| different | (left ^ right))
        == 0
}

fn now_unix() -> Result<u64, DaemonError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| DaemonError::Planning(error.to_string()))
}

fn write_failed(stream: &mut UnixStream, message: &str) -> Result<(), DaemonError> {
    write_frame(
        stream,
        &ServerMessage::Failed {
            schema: PROTOCOL_SCHEMA.into(),
            message: message.into(),
        },
    )
}

fn write_frame<T: Serialize>(stream: &mut UnixStream, value: &T) -> Result<(), DaemonError> {
    let bytes =
        serde_json::to_vec(value).map_err(|error| DaemonError::Protocol(error.to_string()))?;
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(DaemonError::Protocol("protocol frame is too large".into()));
    }
    let size = u32::try_from(bytes.len()).map_err(planning)?.to_be_bytes();
    stream
        .write_all(&size)
        .and_then(|()| stream.write_all(&bytes))
        .map_err(|error| DaemonError::Io(error.to_string()))
}

fn read_frame<T: DeserializeOwned>(stream: &mut UnixStream) -> Result<T, DaemonError> {
    let mut size = [0_u8; 4];
    stream
        .read_exact(&mut size)
        .map_err(|error| DaemonError::Io(error.to_string()))?;
    let size = usize::try_from(u32::from_be_bytes(size)).map_err(planning)?;
    if size == 0 || size > MAX_FRAME_BYTES {
        return Err(DaemonError::Protocol("invalid protocol frame size".into()));
    }
    let mut bytes = vec![0_u8; size];
    stream
        .read_exact(&mut bytes)
        .map_err(|error| DaemonError::Io(error.to_string()))?;
    serde_json::from_slice(&bytes).map_err(|error| DaemonError::Protocol(error.to_string()))
}

fn planning(error: impl std::fmt::Display) -> DaemonError {
    DaemonError::Planning(error.to_string())
}

fn execution(error: impl std::fmt::Display) -> DaemonError {
    DaemonError::Execution(error.to_string())
}

fn executor(error: ExecutorError) -> DaemonError {
    DaemonError::Execution(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_frames_round_trip_and_reject_oversize() {
        let (mut left, mut right) = UnixStream::pair().unwrap();
        write_frame(
            &mut left,
            &ClientMessage::Ping {
                schema: PROTOCOL_SCHEMA.into(),
            },
        )
        .unwrap();
        assert!(matches!(
            read_frame::<ClientMessage>(&mut right).unwrap(),
            ClientMessage::Ping { schema } if schema == PROTOCOL_SCHEMA
        ));
        let mut invalid = UnixStream::pair().unwrap();
        invalid
            .0
            .write_all(&u32::MAX.to_be_bytes())
            .expect("oversize prefix");
        assert!(read_frame::<ClientMessage>(&mut invalid.1).is_err());
    }

    #[test]
    fn solve_tokens_bind_cookie_plan_and_sequence() {
        assert!(secure_equal(b"same", b"same"));
        assert!(!secure_equal(b"same", b"diff"));
        assert!(!secure_equal(b"same", b"short"));
    }

    #[test]
    fn repository_ids_require_canonical_sorted_unique_input() {
        assert!(canonical_repository_ids(&["fedora".into(), "updates".into()]).is_ok());
        assert!(canonical_repository_ids(&["updates".into(), "fedora".into()]).is_err());
        assert!(canonical_repository_ids(&["fedora".into(), "fedora".into()]).is_err());
        assert!(canonical_repository_ids(&["../fedora".into()]).is_err());
    }

    #[test]
    fn only_paths_missing_from_primary_require_the_full_filelists_fallback() {
        let primary_contains = |path: &str| path == "/usr/bin/example";
        assert!(!paths_require_full_filelists_by(
            &["/usr/bin/example".into()],
            primary_contains
        ));
        assert!(paths_require_full_filelists_by(
            &["ordinary-package".into(), "/opt/example".into()],
            primary_contains
        ));
        assert!(!paths_require_full_filelists_by(
            &["ordinary-package".into(), "capability(foo) >= 1".into()],
            primary_contains
        ));
    }
}
