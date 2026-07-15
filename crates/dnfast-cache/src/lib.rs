#![forbid(unsafe_code)]

mod fs_safety;
mod artifact;
mod artifact_lock;
mod artifact_store;
mod loading;
mod model;
mod publication;

use std::path::{Path, PathBuf};

pub use model::{CacheError, CompleteSnapshot, OriginError, SelectedOrigin, Snapshot, SnapshotIntegrity, VerifiedBytes, VerifiedCompleteGeneration};
pub use artifact::{
    ArtifactError, ArtifactResponse, ArtifactSpec, ArtifactTransport, Capacity, Digest,
    HttpArtifactTransport, TransactionRequest, MAX_ARTIFACT_BYTES, MAX_CACHE_BYTES,
    MAX_TRANSACTION_ARTIFACTS, MAX_TRANSACTION_BYTES,
};
pub use artifact_store::{ArtifactCache, ArtifactTransaction, CachedArtifact};

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
