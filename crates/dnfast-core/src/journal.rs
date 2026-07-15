use serde::{Deserialize, Serialize};

use crate::{canonical, CanonicalDocument, DomainError, PackageReason, Sha256Digest};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JournalState {
    Prepared,
    Started,
    RpmResult,
    Reconciled,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct JournalRecord {
    schema_version: u32,
    plan_sha256: Sha256Digest,
    sequence: u64,
    state: JournalState,
}

impl JournalRecord {
    pub fn new(plan_sha256: impl Into<String>, sequence: u64, state: JournalState) -> Result<Self, DomainError> {
        Ok(Self { schema_version: 1, plan_sha256: Sha256Digest::parse(plan_sha256, "plan_sha256")?, sequence, state })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawJournalRecord { schema_version: u32, plan_sha256: Sha256Digest, sequence: u64, state: JournalState }

impl<'de> Deserialize<'de> for JournalRecord {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = RawJournalRecord::deserialize(deserializer)?;
        if raw.schema_version != 1 { return Err(serde::de::Error::custom("unsupported journal schema")); }
        Ok(Self { schema_version: raw.schema_version, plan_sha256: raw.plan_sha256, sequence: raw.sequence, state: raw.state })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryRecord {
    schema_version: u32,
    package_name: String,
    reason: PackageReason,
    state: JournalState,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawHistoryRecord { schema_version: u32, package_name: String, reason: PackageReason, state: JournalState }

impl<'de> Deserialize<'de> for HistoryRecord {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = RawHistoryRecord::deserialize(deserializer)?;
        if raw.schema_version != 1 || raw.package_name.is_empty() { return Err(serde::de::Error::custom("invalid history record")); }
        Ok(Self { schema_version: raw.schema_version, package_name: raw.package_name, reason: raw.reason, state: raw.state })
    }
}

pub type ReasonRecord = HistoryRecord;

impl HistoryRecord {
    pub fn new(package_name: impl Into<String>, reason: PackageReason, state: JournalState) -> Result<Self, DomainError> {
        let package_name = package_name.into();
        if package_name.is_empty() { return Err(DomainError::Empty { field: "package_name" }); }
        Ok(Self { schema_version: 1, package_name, reason, state })
    }
    pub const fn may_autoremove(&self) -> bool {
        false
    }
}

impl CanonicalDocument for JournalRecord {
    fn from_canonical_json(bytes: &[u8]) -> Result<Self, DomainError> {
        let value: Self = canonical::parse(bytes)?;
        if value.schema_version != 1 { return Err(DomainError::SchemaVersion { expected: 1, actual: value.schema_version }); }
        Ok(value)
    }
    fn to_canonical_json(&self) -> Result<Vec<u8>, DomainError> { canonical::serialize(self) }
}

impl CanonicalDocument for HistoryRecord {
    fn from_canonical_json(bytes: &[u8]) -> Result<Self, DomainError> {
        let value: Self = canonical::parse(bytes)?;
        if value.schema_version != 1 { return Err(DomainError::SchemaVersion { expected: 1, actual: value.schema_version }); }
        if value.package_name.is_empty() { return Err(DomainError::Empty { field: "package_name" }); }
        Ok(value)
    }
    fn to_canonical_json(&self) -> Result<Vec<u8>, DomainError> { canonical::serialize(self) }
}
