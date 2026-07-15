#![forbid(unsafe_code)]
#![deny(warnings)]

mod error;
mod execute;
mod input_model;
mod mount_root;
mod plan_fd;
mod recovery;
mod root_inputs;
mod root_preparer;
mod root_resolve;
mod staged_inputs;
mod staging;

pub use error::ExecutorError;
pub use execute::run as execute_checked_transaction;
pub use mount_root::MountRoot;
pub use plan_fd::{InheritedPlan, MAX_PLAN_BYTES, open_plan, validate_plan_path};
pub use recovery::recover_pending_transactions;
pub use root_inputs::RootInputs;
pub use root_preparer::{PreparationError, PreparedInputs, RootInputPreparer};
pub use root_resolve::require_equal as require_root_resolve_equal;
pub use staged_inputs::{StagedArtifact, StagedInputs};
pub use staging::Staging;
