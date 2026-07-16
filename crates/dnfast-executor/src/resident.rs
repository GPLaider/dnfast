use std::{
    fs,
    io::{self, Read, Write},
    os::unix::{
        fs::{FileTypeExt, MetadataExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    rc::Rc,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use dnfast_cache::{
    ArtifactCache, ArtifactSpec, Digest as ArtifactDigest, HttpArtifactTransport,
    TransactionRequest,
};
use dnfast_core::{
    Action, Architecture, CanonicalDocument, Evra, InstalledInventory, PackageSpec, SolverPolicy,
    TransactionIntent,
};
use dnfast_native::{
    ExpectedPackage, InventorySnapshot, NativeContext, Repository, VerifiedStagedKey,
};
use dnfast_planning::{PlanningRepository, PlanningSnapshot, SYSTEM_CACHE_PATH};
use dnfast_solver::{CandidatePackage, CanonicalSolverPlan, NativeSolveOutput, PlanBuilder};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    ExecutorError, MountRoot, StagedArtifact, StagedInputs, Staging, execute::run_token_bound,
    recover_pending_transactions, staged_inputs::StagedRepository, staging::system_directory,
};

pub const SYSTEM_SOCKET: &str = "/run/dnfast/dnfastd.sock";
const RUNTIME_PATH: [&str; 2] = ["run", "dnfast"];
const MAX_FRAME_BYTES: usize = 24 * 1024 * 1024;
const PLAN_LIFETIME_SECONDS: u64 = 300;
const PROTOCOL_SCHEMA: &str = "dnfast.daemon.v1";
type MaterializedPaths = (String, String, String);
type MaterializedRepository = (MaterializedPaths, Vec<dnfast_metadata::CompletePackage>);

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
    #[error("resident daemon is unavailable")]
    Unavailable,
    #[error("resident daemon requires EUID 0")]
    NotRoot,
    #[error("resident daemon socket is unsafe")]
    UnsafeSocket,
    #[error("resident daemon protocol failed: {0}")]
    Protocol(String),
    #[error("resident daemon planning failed: {0}")]
    Planning(String),
    #[error("resident daemon execution failed: {0}")]
    Execution(String),
    #[error("resident daemon I/O failed: {0}")]
    Io(String),
}

impl DaemonError {
    pub const fn is_unavailable(&self) -> bool {
        matches!(self, Self::Unavailable)
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
    let mut stream = match connect() {
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
    let mut stream = connect()?;
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
    let mut stream = connect()?;
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

pub fn transact_via_daemon(
    action: Action,
    packages: &[String],
    repositories: &[String],
    approval: DaemonApproval,
) -> Result<DaemonOutcome, DaemonError> {
    let mut stream = connect()?;
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

fn connect() -> Result<UnixStream, DaemonError> {
    if rustix::process::geteuid().as_raw() != 0 {
        return Err(DaemonError::NotRoot);
    }
    UnixStream::connect(SYSTEM_SOCKET).map_err(|error| match error.kind() {
        io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused => DaemonError::Unavailable,
        _ => DaemonError::Io(error.to_string()),
    })
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
            if requires_filelists(&packages) {
                return write_frame(
                    stream,
                    &ServerMessage::Fallback {
                        schema: PROTOCOL_SCHEMA.into(),
                        reason: "absolute path selectors require the full filelists planner".into(),
                    },
                );
            }
            let solved = state
                .planner
                .solve(parse_action(&action)?, packages, &repositories)?;
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
            if requires_filelists(&packages) {
                return write_frame(
                    stream,
                    &ServerMessage::Fallback {
                        schema: PROTOCOL_SCHEMA.into(),
                        reason: "absolute path selectors require the full filelists planner".into(),
                    },
                );
            }
            let action = parse_action(&action)?;
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
        let plan_bytes = solved.plan.canonical_json().map_err(planning)?;
        revalidate_solved(&solved)?;
        let architecture = solved.policy.base_arch();
        if self.recovered_architecture != Some(architecture) {
            recover_pending_transactions(&self.journal, architecture).map_err(executor)?;
            self.recovered_architecture = Some(architecture);
        }
        trace_phase(self.trace, started, "revalidate-recover");
        let staging = Staging::create(&plan_bytes).map_err(executor)?;
        let mut staged = direct_staged_inputs(&solved)?;
        let mut root = MountRoot::create(&staging).map_err(executor)?;
        trace_phase(self.trace, started, "stage");
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
            root.cleanup().map_err(executor)?;
            staging.cleanup().map_err(executor)?;
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
}

struct ResidentPool {
    repository_ids: Vec<String>,
    integrity: dnfast_core::PlanIntegrity,
    policy: SolverPolicy,
    repositories: Vec<PlanningRepository>,
    context: NativeContext,
    inventory: InstalledInventory,
    rpmdb_cookie: String,
    candidates: Vec<CandidatePackage>,
    metadata: Vec<(String, dnfast_metadata::CompletePackage)>,
    last_solve: Option<CachedResidentSolve>,
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
        let mut context = NativeContext::open(architecture, || false).map_err(planning)?;
        context.verify_installed_rpmdb().map_err(planning)?;
        self.verified_rpmdb_cookie = Some(
            context
                .read_installed_inventory_snapshot()
                .map_err(planning)?
                .rpmdb_cookie,
        );
        Ok(())
    }

    fn warm(&mut self, repositories: &[String]) -> Result<&str, DaemonError> {
        self.ensure(repositories)?;
        Ok(&self.cached.as_ref().expect("resident pool").rpmdb_cookie)
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
        let result = match action {
            Action::Install => {
                cached
                    .context
                    .solve_install_many(&names, policy.install_weak_deps(), policy.best())
            }
            Action::Upgrade => cached.context.solve_upgrade_many(&names, policy.best()),
            Action::Remove => cached.context.solve_erase_many(&names),
        }
        .map_err(planning)?;
        trace_phase(trace, started, "resident-native-solve");
        if trace {
            eprintln!(
                "dnfastd_trace native_actions={} native_decisions={}",
                result.actions.len(),
                result.decisions.len()
            );
        }
        let metadata = cached
            .metadata
            .iter()
            .map(|(repository, package)| (repository.as_str(), package))
            .collect::<Vec<_>>();
        let transcript = NativeSolveOutput::from_native(
            result,
            cached.integrity.metadata_sha256().as_str().into(),
            &metadata,
            &cached.inventory,
        )
        .map_err(planning)?;
        trace_phase(trace, started, "resident-native-adapter");
        let satisfied_specs = transcript.satisfied_specs().to_vec();
        let resolved = transcript
            .into_resolved(&names, &cached.candidates, &metadata, &cached.inventory)
            .map_err(planning)?;
        trace_phase(trace, started, "resident-resolved");
        let plan = PlanBuilder {
            intent: &intent,
            snapshots: &cached.integrity,
            inventory: &cached.inventory,
            policy: &policy,
            candidates: &cached.candidates,
            expires_at_unix: now.saturating_add(PLAN_LIFETIME_SECONDS),
        }
        .build_with_satisfied(&resolved, &satisfied_specs)
        .map_err(planning)?;
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
        if same_generation {
            let cached = self.cached.as_mut().expect("resident pool");
            let current = cached
                .context
                .read_installed_inventory_snapshot()
                .map_err(planning)?;
            if cached.rpmdb_cookie == current.rpmdb_cookie {
                return Ok(());
            }
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
        )?;
        self.verified_rpmdb_cookie = Some(verified_cookie);
        self.cached = Some(pool);
        Ok(())
    }

    fn invalidate(&mut self) {
        self.cached = None;
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
        cached.last_solve = None;
        self.verified_rpmdb_cookie = Some(current.rpmdb_cookie);
        Ok(())
    }
}

fn build_pool(
    snapshot: PlanningSnapshot,
    repository_ids: Vec<String>,
    integrity: dnfast_core::PlanIntegrity,
    verified_rpmdb_cookie: Option<&str>,
) -> Result<(ResidentPool, String), DaemonError> {
    let policy = snapshot.payload().policy.solver.clone();
    let mut context = NativeContext::open(policy.base_arch(), || false).map_err(planning)?;
    context.add_installed_rpmdb("/").map_err(planning)?;
    let mut current = context
        .read_installed_inventory_snapshot()
        .map_err(planning)?;
    if verified_rpmdb_cookie != Some(current.rpmdb_cookie.as_str()) {
        let cookie_before = current.rpmdb_cookie.clone();
        context.verify_installed_rpmdb().map_err(planning)?;
        current = context
            .read_installed_inventory_snapshot()
            .map_err(planning)?;
        if current.rpmdb_cookie != cookie_before {
            return Err(DaemonError::Planning(
                "RPMDB changed while full verification was in progress".into(),
            ));
        }
    }
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
    let workspace = tempfile::tempdir().map_err(|error| DaemonError::Io(error.to_string()))?;
    let mut candidates = Vec::new();
    let mut metadata = Vec::new();
    for (index, repository) in selected.iter().enumerate() {
        let (paths, solver_inputs) = materialize(&snapshot, workspace.path(), index, repository)?;
        context
            .add_repository_primary(Repository {
                id: repository.id.clone(),
                repomd_path: paths.0,
                primary_path: paths.1,
                filelists_path: paths.2,
                priority: i32::try_from(repository.priority).map_err(planning)?,
                cost: i32::try_from(repository.cost).map_err(planning)?,
            })
            .map_err(planning)?;
        candidates.extend(candidates_for(
            repository,
            &solver_inputs,
            policy.base_arch(),
        )?);
        metadata.extend(
            solver_inputs
                .iter()
                .cloned()
                .map(|package| (repository.id.clone(), package)),
        );
    }
    let verified_cookie = rpmdb_cookie.clone();
    Ok((
        ResidentPool {
            repository_ids,
            integrity,
            policy,
            repositories: selected.into_iter().cloned().collect(),
            context,
            inventory,
            rpmdb_cookie,
            candidates,
            metadata,
            last_solve: None,
        },
        verified_cookie,
    ))
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
        .materialize_native_primary(repository)
        .map_err(planning)?;
    let repomd = write_temp(root, &format!("{prefix}-repomd.xml"), metadata.repomd())?;
    let primary = write_temp(root, &format!("{prefix}-primary.xml"), metadata.primary())?;
    let filelists = write_temp(
        root,
        &format!("{prefix}-filelists.xml"),
        metadata.filelists(),
    )?;
    Ok((
        (display(&repomd)?, display(&primary)?, display(&filelists)?),
        metadata.solver_inputs().to_vec(),
    ))
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

fn candidates_for(
    repository: &PlanningRepository,
    solver_inputs: &[dnfast_metadata::CompletePackage],
    base_architecture: Architecture,
) -> Result<Vec<CandidatePackage>, DaemonError> {
    let mut candidates = Vec::new();
    for item in solver_inputs {
        let architecture = match item.arch.as_str() {
            "aarch64" => Architecture::Aarch64,
            "x86_64" => Architecture::X86_64,
            "noarch" => Architecture::Noarch,
            "i686" if base_architecture == Architecture::X86_64 => continue,
            _ => {
                return Err(DaemonError::Planning(
                    "root-published metadata has an unsupported architecture".into(),
                ));
            }
        };
        let epoch = item
            .epoch
            .parse()
            .map_err(|_| DaemonError::Planning("invalid metadata epoch".into()))?;
        candidates.push(CandidatePackage {
            name: item.name.clone(),
            evra: Evra::new(
                epoch,
                item.version.clone(),
                item.release.clone(),
                architecture,
            ),
            vendor: if item.vendor.is_empty() {
                "unknown".into()
            } else {
                item.vendor.clone()
            },
            repo_id: repository.id.clone(),
            priority: repository.priority,
            cost: repository.cost,
            package_size: item.package_size,
            installed_size: item.installed_size,
            checksum_sha256: item.checksum.clone(),
            location: item.location.clone(),
            excluded: false,
            modular: false,
        });
    }
    Ok(candidates)
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
        _ => Err(DaemonError::Protocol("invalid transaction action".into())),
    }
}

const fn action_name(action: Action) -> &'static str {
    match action {
        Action::Install => "install",
        Action::Upgrade => "upgrade",
        Action::Remove => "remove",
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

fn requires_filelists(packages: &[String]) -> bool {
    packages.iter().any(|package| package.starts_with('/'))
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
    fn only_absolute_path_intents_require_the_full_filelists_fallback() {
        assert!(requires_filelists(&["/usr/bin/example".into()]));
        assert!(requires_filelists(&[
            "ordinary-package".into(),
            "/opt/example".into()
        ]));
        assert!(!requires_filelists(&[
            "ordinary-package".into(),
            "capability(foo) >= 1".into()
        ]));
    }
}
