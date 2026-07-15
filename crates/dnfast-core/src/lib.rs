#![forbid(unsafe_code)]

mod canonical;
mod integrity;
mod intent;
mod inventory;
mod journal;
mod plan;
mod policy;
mod trust;
mod value;

pub use canonical::{CanonicalDocument, MAX_STRING_BYTES};
pub use integrity::{PlanIntegrity, RepositoryBinding};
pub use intent::{Action, IntentError, PackageSpec, TransactionIntent};
pub use inventory::{EraseLookupError, InstalledInventory, InstalledPackage};
pub use journal::{HistoryRecord, JournalRecord, JournalState, ReasonRecord};
pub use plan::{
    ActionProvenance, CanonicalPlan, MAX_PLAN_ACTIONS, PackageAction, PackageOperation,
    PlanEnvelope, canonical_actions,
};
pub use policy::{CandidateAction, PackageReason, RepoPreference, SolverPolicy};
pub use trust::{RepoTrustPolicy, SigningSubkeyRule};
pub use value::{Architecture, DomainError, Evra, Sha256Digest};

pub fn canonical_encode<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, DomainError> {
    canonical::serialize(value)
}
pub fn canonical_decode<T: serde::de::DeserializeOwned + serde::Serialize>(
    bytes: &[u8],
) -> Result<T, DomainError> {
    canonical::parse(bytes)
}
