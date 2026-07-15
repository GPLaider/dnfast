use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::{canonical, CanonicalDocument, DomainError, Evra, Sha256Digest};

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum EraseLookupError {
    #[error("installed instance was not found")] NotFound,
    #[error("installed instance header digest changed")] HeaderMismatch,
    #[error("installed instance identity is ambiguous")] Ambiguous,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledPackage {
    name: String,
    evra: Evra,
    vendor: String,
    db_instance: u64,
    install_time: u64,
    immutable_header_sha256: Sha256Digest,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawInstalledPackage { name: String, evra: Evra, vendor: String, db_instance: u64, install_time: u64, immutable_header_sha256: Sha256Digest }

impl<'de> Deserialize<'de> for InstalledPackage {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = RawInstalledPackage::deserialize(deserializer)?;
        if raw.name.is_empty() { return Err(serde::de::Error::custom("empty package name")); }
        Ok(Self { name: raw.name, evra: raw.evra, vendor: raw.vendor, db_instance: raw.db_instance,
            install_time: raw.install_time, immutable_header_sha256: raw.immutable_header_sha256 })
    }
}

impl InstalledPackage {
    pub fn new(name: impl Into<String>, evra: Evra, vendor: impl Into<String>, db_instance: u64, install_time: u64, digest: impl Into<String>) -> Result<Self, DomainError> {
        let name = name.into();
        let vendor = vendor.into();
        if name.is_empty() { return Err(DomainError::Empty { field: "package_name" }); }
        evra.validate()?;
        Ok(Self { name, evra, vendor, db_instance, install_time, immutable_header_sha256: Sha256Digest::parse(digest, "immutable_header_sha256")? })
    }
    pub fn name(&self) -> &str { &self.name }
    pub fn evra(&self) -> &Evra { &self.evra }
    pub fn vendor(&self) -> &str { &self.vendor }
    pub const fn db_instance(&self) -> u64 { self.db_instance }
    pub const fn install_time(&self) -> u64 { self.install_time }
    pub fn immutable_header_sha256(&self) -> &Sha256Digest { &self.immutable_header_sha256 }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledInventory {
    schema_version: u32,
    install_root: String,
    rpmdb_backend: String,
    rpm_version: String,
    packages: Vec<InstalledPackage>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawInstalledInventory {
    schema_version: u32, install_root: String, rpmdb_backend: String,
    rpm_version: String, packages: Vec<InstalledPackage>,
}

impl<'de> Deserialize<'de> for InstalledInventory {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = RawInstalledInventory::deserialize(deserializer)?;
        let value = Self { schema_version: raw.schema_version, install_root: raw.install_root,
            rpmdb_backend: raw.rpmdb_backend, rpm_version: raw.rpm_version, packages: raw.packages };
        value.validate().map_err(serde::de::Error::custom)?;
        Ok(value)
    }
}

impl InstalledInventory {
    pub fn new(backend: impl Into<String>, rpm_version: impl Into<String>, mut packages: Vec<InstalledPackage>) -> Result<Self, DomainError> {
        packages.sort();
        let mut identities = HashSet::with_capacity(packages.len());
        for package in &packages {
            if !identities.insert(package.db_instance) { return Err(DomainError::Duplicate(format!("rpmdb instance {}", package.db_instance))); }
        }
        let value = Self { schema_version: 1, install_root: "/".into(), rpmdb_backend: backend.into(), rpm_version: rpm_version.into(), packages };
        value.validate()?;
        Ok(value)
    }
    pub fn packages(&self) -> &[InstalledPackage] { &self.packages }
    pub fn install_root(&self) -> &str { &self.install_root }
    pub fn rpmdb_backend(&self) -> &str { &self.rpmdb_backend }
    pub fn rpm_version(&self) -> &str { &self.rpm_version }
    pub fn erase_target(&self, db_instance: u64, header_sha256: &str) -> Result<&InstalledPackage, EraseLookupError> {
        let matches = self.packages.iter().filter(|package| package.db_instance == db_instance).collect::<Vec<_>>();
        match matches.as_slice() {
            [] => Err(EraseLookupError::NotFound),
            [package] if package.immutable_header_sha256.as_str() == header_sha256 => Ok(package),
            [_] => Err(EraseLookupError::HeaderMismatch),
            _ => Err(EraseLookupError::Ambiguous),
        }
    }
    fn validate(&self) -> Result<(), DomainError> {
        if self.schema_version != 1 { return Err(DomainError::SchemaVersion { expected: 1, actual: self.schema_version }); }
        if self.install_root != "/" { return Err(DomainError::InvalidPlan("inventory root must be /")); }
        if self.rpmdb_backend.is_empty() { return Err(DomainError::Empty { field: "rpmdb_backend" }); }
        if self.rpm_version.is_empty() { return Err(DomainError::Empty { field: "rpm_version" }); }
        if self.packages.windows(2).any(|pair| pair[0] >= pair[1]) { return Err(DomainError::NonCanonical); }
        let mut identities = HashSet::with_capacity(self.packages.len());
        for package in &self.packages {
            if !identities.insert(package.db_instance) {
                return Err(DomainError::Duplicate(format!("rpmdb instance {}", package.db_instance)));
            }
        }
        Ok(())
    }
}

impl CanonicalDocument for InstalledInventory {
    fn from_canonical_json(bytes: &[u8]) -> Result<Self, DomainError> { let value: Self = canonical::parse(bytes)?; value.validate()?; Ok(value) }
    fn to_canonical_json(&self) -> Result<Vec<u8>, DomainError> { self.validate()?; canonical::serialize(self) }
}
