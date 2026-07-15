use serde::{Deserialize, Serialize};

use crate::{DomainError, Sha256Digest};

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryBinding {
    id: String,
    generation_sha256: Sha256Digest,
    origin_sha256: Sha256Digest,
    trust_sha256: Sha256Digest,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRepositoryBinding {
    id: String,
    generation_sha256: Sha256Digest,
    origin_sha256: Sha256Digest,
    trust_sha256: Sha256Digest,
}

impl<'de> Deserialize<'de> for RepositoryBinding {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = RawRepositoryBinding::deserialize(deserializer)?;
        Self::new(raw.id, raw.generation_sha256, raw.origin_sha256, raw.trust_sha256).map_err(serde::de::Error::custom)
    }
}

impl RepositoryBinding {
    pub fn new(id: impl Into<String>, generation_sha256: Sha256Digest, origin_sha256: Sha256Digest,
        trust_sha256: Sha256Digest) -> Result<Self, DomainError> {
        let id = id.into();
        if id.is_empty() || id.bytes().any(|byte| !(byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))) {
            return Err(DomainError::InvalidPlan("invalid repository binding identifier"));
        }
        Ok(Self { id, generation_sha256, origin_sha256, trust_sha256 })
    }

    pub fn id(&self) -> &str { &self.id }
    pub fn generation_sha256(&self) -> &Sha256Digest { &self.generation_sha256 }
    pub fn origin_sha256(&self) -> &Sha256Digest { &self.origin_sha256 }
    pub fn trust_sha256(&self) -> &Sha256Digest { &self.trust_sha256 }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanIntegrity {
    policy_sha256: Sha256Digest,
    trust_sha256: Sha256Digest,
    inventory_sha256: Sha256Digest,
    metadata_sha256: Sha256Digest,
    planning_snapshot_sha256: Sha256Digest,
    selected_repositories: Vec<RepositoryBinding>,
}

impl PlanIntegrity {
    pub fn new(digests: [&str; 5], selected_repositories: Vec<RepositoryBinding>) -> Result<Self, DomainError> {
        let value = Self {
            policy_sha256: Sha256Digest::parse(digests[0], "policy_sha256")?,
            trust_sha256: Sha256Digest::parse(digests[1], "trust_sha256")?,
            inventory_sha256: Sha256Digest::parse(digests[2], "inventory_sha256")?,
            metadata_sha256: Sha256Digest::parse(digests[3], "metadata_sha256")?,
            planning_snapshot_sha256: Sha256Digest::parse(digests[4], "planning_snapshot_sha256")?,
            selected_repositories,
        };
        value.validate()?;
        Ok(value)
    }

    pub(crate) fn validate(&self) -> Result<(), DomainError> {
        if self.selected_repositories.is_empty()
            || self.selected_repositories.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(DomainError::NonCanonical);
        }
        Ok(())
    }

    pub fn policy_sha256(&self) -> &Sha256Digest { &self.policy_sha256 }
    pub fn trust_sha256(&self) -> &Sha256Digest { &self.trust_sha256 }
    pub fn inventory_sha256(&self) -> &Sha256Digest { &self.inventory_sha256 }
    pub fn metadata_sha256(&self) -> &Sha256Digest { &self.metadata_sha256 }
    pub fn planning_snapshot_sha256(&self) -> &Sha256Digest { &self.planning_snapshot_sha256 }
    pub fn selected_repositories(&self) -> &[RepositoryBinding] { &self.selected_repositories }

    pub(crate) fn into_parts(self) -> (Sha256Digest, Sha256Digest, Sha256Digest, Sha256Digest, Sha256Digest, Vec<RepositoryBinding>) {
        (self.policy_sha256, self.trust_sha256, self.inventory_sha256, self.metadata_sha256,
            self.planning_snapshot_sha256, self.selected_repositories)
    }

    pub(crate) fn from_parts(policy_sha256: Sha256Digest, trust_sha256: Sha256Digest, inventory_sha256: Sha256Digest,
        metadata_sha256: Sha256Digest, planning_snapshot_sha256: Sha256Digest, selected_repositories: Vec<RepositoryBinding>) -> Self {
        Self { policy_sha256, trust_sha256, inventory_sha256, metadata_sha256, planning_snapshot_sha256, selected_repositories }
    }
}
