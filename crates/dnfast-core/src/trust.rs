use serde::{Deserialize, Serialize};

use crate::{canonical, CanonicalDocument, DomainError, Sha256Digest};

const SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SigningSubkeyRule { PrimaryOnly, AuthorizedSubkeys }

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepoTrustPolicy {
    schema_version: u32,
    repo_id: String,
    key_bundle_sha256: Sha256Digest,
    allowed_primary_fingerprints: Vec<String>,
    signing_subkey_rule: SigningSubkeyRule,
    valid_at_unix: u64,
    require_package_signature: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRepoTrustPolicy {
    schema_version: u32, repo_id: String, key_bundle_sha256: Sha256Digest,
    allowed_primary_fingerprints: Vec<String>, signing_subkey_rule: SigningSubkeyRule,
    valid_at_unix: u64, require_package_signature: bool,
}

impl<'de> Deserialize<'de> for RepoTrustPolicy {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = RawRepoTrustPolicy::deserialize(deserializer)?;
        let value = Self { schema_version: raw.schema_version, repo_id: raw.repo_id,
            key_bundle_sha256: raw.key_bundle_sha256, allowed_primary_fingerprints: raw.allowed_primary_fingerprints,
            signing_subkey_rule: raw.signing_subkey_rule, valid_at_unix: raw.valid_at_unix,
            require_package_signature: raw.require_package_signature };
        value.validate().map_err(serde::de::Error::custom)?;
        Ok(value)
    }
}

impl RepoTrustPolicy {
    pub fn repo_id(&self) -> &str { &self.repo_id }
    pub fn key_bundle_sha256(&self) -> &Sha256Digest { &self.key_bundle_sha256 }
    pub fn allowed_primary_fingerprints(&self) -> &[String] { &self.allowed_primary_fingerprints }
    pub const fn signing_subkey_rule(&self) -> SigningSubkeyRule { self.signing_subkey_rule }
    pub const fn valid_at_unix(&self) -> u64 { self.valid_at_unix }
    pub fn new(
        repo_id: impl Into<String>,
        key_bundle_sha256: impl Into<String>,
        fingerprints: impl IntoIterator<Item = String>,
        signing_subkey_rule: SigningSubkeyRule,
        valid_at_unix: u64,
    ) -> Result<Self, DomainError> {
        let repo_id = repo_id.into();
        if repo_id.is_empty() { return Err(DomainError::Empty { field: "repo_id" }); }
        let mut allowed_primary_fingerprints = fingerprints.into_iter().map(|value| value.to_ascii_uppercase()).collect::<Vec<_>>();
        allowed_primary_fingerprints.sort();
        let value = Self {
            schema_version: SCHEMA_VERSION,
            repo_id,
            key_bundle_sha256: Sha256Digest::parse(key_bundle_sha256, "key_bundle_sha256")?,
            allowed_primary_fingerprints,
            signing_subkey_rule,
            valid_at_unix,
            require_package_signature: true,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self, DomainError> {
        Self::from_canonical_json(bytes)
    }

    fn validate(&self) -> Result<(), DomainError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(DomainError::SchemaVersion { expected: SCHEMA_VERSION, actual: self.schema_version });
        }
        if self.repo_id.is_empty() { return Err(DomainError::Empty { field: "repo_id" }); }
        if self.allowed_primary_fingerprints.is_empty() { return Err(DomainError::Empty { field: "allowed_primary_fingerprints" }); }
        if self.allowed_primary_fingerprints.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(DomainError::Duplicate("primary fingerprint".into()));
        }
        if !self.allowed_primary_fingerprints.iter().all(|fingerprint| fingerprint.len() == 40 && fingerprint.bytes().all(|byte| byte.is_ascii_hexdigit())) {
            return Err(DomainError::InvalidDigest { field: "allowed_primary_fingerprints" });
        }
        if !self.require_package_signature { return Err(DomainError::UnsafeAction("package signatures are mandatory")); }
        Ok(())
    }
}

impl CanonicalDocument for RepoTrustPolicy {
    fn from_canonical_json(bytes: &[u8]) -> Result<Self, DomainError> {
        let value: Self = canonical::parse(bytes)?;
        value.validate()?;
        Ok(value)
    }
    fn to_canonical_json(&self) -> Result<Vec<u8>, DomainError> { self.validate()?; canonical::serialize(self) }
}
