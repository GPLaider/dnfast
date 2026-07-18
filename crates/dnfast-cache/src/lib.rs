#![forbid(unsafe_code)]

mod artifact;
mod artifact_lock;
mod artifact_store;
mod auxiliary;
mod fs_safety;
mod loading;
mod model;
mod publication;
mod rpmdb_receipt;
mod solv_cache;

use std::path::{Path, PathBuf};

pub use artifact::{
    ArtifactError, ArtifactResponse, ArtifactSpec, ArtifactTransport, Capacity, Digest,
    HttpArtifactTransport, MAX_ARTIFACT_BYTES, MAX_CACHE_BYTES, MAX_TRANSACTION_ARTIFACTS,
    MAX_TRANSACTION_BYTES, TransactionRequest,
};
pub use artifact_store::{ArtifactCache, ArtifactTransaction, CachedArtifact};
pub use model::{
    CacheError, CompleteSnapshot, CurrentGenerationIdentity, OriginError, RepomdAuthentication,
    SelectedOrigin, Snapshot, SnapshotIntegrity, VerifiedBytes, VerifiedCompleteGeneration,
};
pub use rpmdb_receipt::{
    RpmDbCurrentCheck, RpmDbCurrentReceipt, RpmDbReceiptCache, RpmDbReceiptCheck,
    RpmDbVerifiedGeneration,
};
pub use solv_cache::{CachedSolv, SolvCache, StagedSolv};

#[derive(Debug)]
pub struct Cache {
    pub(crate) root: PathBuf,
}

impl Cache {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
}
