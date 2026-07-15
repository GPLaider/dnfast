use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{CanonicalDocument, DomainError, canonical};

const SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Install,
    Upgrade,
    Remove,
}

impl Action {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Install => "install",
            Self::Upgrade => "upgrade",
            Self::Remove => "remove",
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct PackageSpec(String);

impl<'de> Deserialize<'de> for PackageSpec {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(serde::de::Error::custom)
    }
}

impl PackageSpec {
    pub fn parse(value: impl Into<String>) -> Result<Self, IntentError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(IntentError::EmptyPackage);
        }
        if value.trim_start().starts_with('-') {
            return Err(IntentError::OptionLikePackage(value));
        }
        if value.chars().any(char::is_control) {
            return Err(IntentError::ControlCharacter(
                value.escape_default().to_string(),
            ));
        }
        Ok(Self(value))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TransactionIntent {
    schema_version: u32,
    action: Action,
    packages: Vec<PackageSpec>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTransactionIntent {
    schema_version: u32,
    action: Action,
    packages: Vec<PackageSpec>,
}

impl<'de> Deserialize<'de> for TransactionIntent {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = RawTransactionIntent::deserialize(deserializer)?;
        let value = Self {
            schema_version: raw.schema_version,
            action: raw.action,
            packages: raw.packages,
        };
        value.validate().map_err(serde::de::Error::custom)?;
        Ok(value)
    }
}

impl TransactionIntent {
    pub fn new(action: Action, packages: Vec<PackageSpec>) -> Result<Self, IntentError> {
        let mut packages = packages;
        packages.sort_by(|left, right| left.as_str().cmp(right.as_str()));
        let value = Self {
            schema_version: SCHEMA_VERSION,
            action,
            packages,
        };
        value.validate()?;
        Ok(value)
    }
    pub fn from_package_names(action: Action, names: &[&str]) -> Result<Self, IntentError> {
        let packages = names
            .iter()
            .map(|name| PackageSpec::parse(*name))
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(action, packages)
    }
    pub fn from_json(bytes: &[u8]) -> Result<Self, IntentError> {
        Self::from_canonical_json(bytes).map_err(|error| IntentError::Json(error.to_string()))
    }
    pub fn to_json(&self) -> Result<Vec<u8>, IntentError> {
        self.to_canonical_json()
            .map_err(|error| IntentError::Json(error.to_string()))
    }
    pub const fn action(&self) -> Action {
        self.action
    }
    pub fn packages(&self) -> &[PackageSpec] {
        &self.packages
    }
    fn validate(&self) -> Result<(), IntentError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(IntentError::SchemaVersion(self.schema_version));
        }
        if matches!(self.action, Action::Install | Action::Remove) && self.packages.is_empty() {
            return Err(IntentError::MissingPackages(self.action));
        }
        let mut seen = HashSet::with_capacity(self.packages.len());
        if self
            .packages
            .windows(2)
            .any(|pair| pair[0].as_str() >= pair[1].as_str())
        {
            return Err(IntentError::NonCanonicalPackages);
        }
        for package in &self.packages {
            PackageSpec::parse(package.as_str())?;
            if !seen.insert(package.as_str()) {
                return Err(IntentError::DuplicatePackage(package.as_str().to_owned()));
            }
        }
        Ok(())
    }
}

impl CanonicalDocument for TransactionIntent {
    fn from_canonical_json(bytes: &[u8]) -> Result<Self, DomainError> {
        let value: Self = canonical::parse(bytes)?;
        value
            .validate()
            .map_err(|error| DomainError::Json(error.to_string()))?;
        Ok(value)
    }

    fn to_canonical_json(&self) -> Result<Vec<u8>, DomainError> {
        self.validate()
            .map_err(|error| DomainError::Json(error.to_string()))?;
        canonical::serialize(self)
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum IntentError {
    #[error("{0:?} requires at least one package")]
    MissingPackages(Action),
    #[error("package specification cannot be empty")]
    EmptyPackage,
    #[error("package specification cannot start with '-': {0}")]
    OptionLikePackage(String),
    #[error("package specification contains a control character: {0}")]
    ControlCharacter(String),
    #[error("duplicate package specification: {0}")]
    DuplicatePackage(String),
    #[error("unsupported transaction intent schema version: {0}")]
    SchemaVersion(u32),
    #[error("transaction intent JSON rejected: {0}")]
    Json(String),
    #[error("package specifications are not in unique canonical order")]
    NonCanonicalPackages,
}
