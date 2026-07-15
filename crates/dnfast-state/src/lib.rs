#![deny(warnings)]

mod error;
mod fault;
mod fs;
mod log;
mod model;
mod reason;
mod recovery;
mod store;

pub use error::StateError;
pub use fault::{FaultPlan, FaultPoint};
pub use log::LogAppend;
pub use model::{CallbackSummary, JournalEntry, NativeResult, ReconcileResult, RecoveryAction, TransactionId, TransactionState};
pub use reason::{InstalledIdentity, PlannedIdentity, ReasonDecision, ReconciledReason, proposals_from_plan, reconcile_reasons};
pub use recovery::{recover, recover_with_staging};
pub use store::{JournalStore, TransactionJournal};
