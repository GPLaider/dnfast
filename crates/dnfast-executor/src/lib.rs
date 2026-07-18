#![forbid(unsafe_code)]
#![deny(warnings)]

mod compact_inputs;
mod error;
mod execute;
mod input_model;
mod mount_root;
mod plan_fd;
mod recovery;
mod resident;
mod root_inputs;
mod root_preparer;
mod root_resolve;
mod staged_inputs;
mod staging;

pub use compact_inputs::{CompactExecution, CompactTransactionInputs};
pub use error::ExecutorError;
pub use execute::{ExecutionState, run as execute_checked_transaction, run_token_bound};
pub use mount_root::MountRoot;
pub use plan_fd::{InheritedPlan, MAX_PLAN_BYTES, open_plan, validate_plan_path};
pub use recovery::recover_pending_transactions;
pub use resident::{
    DaemonAction, DaemonApproval, DaemonError, DaemonOutcome, DaemonPlan, DaemonStatus,
    DaemonlessPlan, SYSTEM_SOCKET, daemon_status, plan_transaction_without_daemon, plan_via_daemon,
    plan_without_daemon, serve_system, transact_via_daemon, warm_daemon,
};
pub use root_inputs::RootInputs;
pub use root_preparer::{PreparationError, PreparedInputs, RootInputPreparer};
pub use root_resolve::require_equal as require_root_resolve_equal;
pub use staged_inputs::{StagedArtifact, StagedInputs};
pub use staging::Staging;
