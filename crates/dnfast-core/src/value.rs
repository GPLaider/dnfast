use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum DomainError {
    #[error("{field} cannot be empty")]
    Empty { field: &'static str },
    #[error("{field} is not a 64-character hexadecimal SHA-256 digest")]
    InvalidDigest { field: &'static str },
    #[error("unsupported schema version {actual}; expected {expected}")]
    SchemaVersion { expected: u32, actual: u32 },
    #[error("unsupported architecture")]
    Architecture,
    #[error("unsafe solver action: {0}")]
    UnsafeAction(&'static str),
    #[error("duplicate canonical identity: {0}")]
    Duplicate(String),
    #[error("invalid plan: {0}")]
    InvalidPlan(&'static str),
    #[error("JSON boundary rejected input: {0}")]
    Json(String),
    #[error("JSON is not canonical JCS form")]
    NonCanonical,
    #[error("document exceeds 16 MiB")]
    DocumentTooLarge,
    #[error("JSON nesting exceeds depth 32")]
    DepthExceeded,
    #[error("JSON string exceeds 1 MiB")]
    StringTooLarge,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Sha256Digest(String);

impl Sha256Digest {
    pub fn parse(value: impl Into<String>, field: &'static str) -> Result<Self, DomainError> {
        let value = value.into();
        if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(DomainError::InvalidDigest { field });
        }
        Ok(Self(value.to_ascii_lowercase()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for Sha256Digest {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::parse(value, "sha256").map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Architecture {
    Aarch64,
    #[serde(rename = "x86_64")]
    X86_64,
    Noarch,
}

impl Architecture {
    pub const fn as_rpm_arch(self) -> &'static str {
        match self {
            Self::Aarch64 => "aarch64",
            Self::X86_64 => "x86_64",
            Self::Noarch => "noarch",
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Evra {
    epoch: u32,
    version: String,
    release: String,
    arch: Architecture,
}

impl Evra {
    pub fn new(epoch: u32, version: impl Into<String>, release: impl Into<String>, arch: Architecture) -> Self {
        Self { epoch, version: version.into(), release: release.into(), arch }
    }

    pub const fn epoch(&self) -> u32 { self.epoch }
    pub fn version(&self) -> &str { &self.version }
    pub fn release(&self) -> &str { &self.release }
    pub const fn arch(&self) -> Architecture { self.arch }
    pub(crate) fn validate(&self) -> Result<(), DomainError> {
        if self.version.is_empty() { return Err(DomainError::Empty { field: "version" }); }
        if self.release.is_empty() { return Err(DomainError::Empty { field: "release" }); }
        Ok(())
    }
    pub fn is_strictly_newer_than(&self, installed: &Self) -> bool {
        if self.epoch != installed.epoch { return self.epoch > installed.epoch; }
        match rpm_part_cmp(&self.version, &installed.version) {
            std::cmp::Ordering::Equal => rpm_part_cmp(&self.release, &installed.release).is_gt(),
            ordering => ordering.is_gt(),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEvra { epoch: u32, version: String, release: String, arch: Architecture }

impl<'de> Deserialize<'de> for Evra {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = RawEvra::deserialize(deserializer)?;
        let value = Self { epoch: raw.epoch, version: raw.version, release: raw.release, arch: raw.arch };
        value.validate().map_err(serde::de::Error::custom)?;
        Ok(value)
    }
}

fn rpm_part_cmp(left: &str, right: &str) -> std::cmp::Ordering {
    let left = left.as_bytes();
    let right = right.as_bytes();
    let (mut li, mut ri) = (0usize, 0usize);
    loop {
        while li < left.len() && !left[li].is_ascii_alphanumeric() && !matches!(left[li], b'~' | b'^') { li += 1; }
        while ri < right.len() && !right[ri].is_ascii_alphanumeric() && !matches!(right[ri], b'~' | b'^') { ri += 1; }
        if left.get(li) == Some(&b'~') || right.get(ri) == Some(&b'~') {
            match (left.get(li) == Some(&b'~'), right.get(ri) == Some(&b'~')) {
                (true, true) => { li += 1; ri += 1; continue; }
                (true, false) => return std::cmp::Ordering::Less,
                (false, true) => return std::cmp::Ordering::Greater,
                (false, false) => return std::cmp::Ordering::Equal,
            }
        }
        if left.get(li) == Some(&b'^') || right.get(ri) == Some(&b'^') {
            match (left.get(li) == Some(&b'^'), right.get(ri) == Some(&b'^'), li == left.len(), ri == right.len()) {
                (true, true, _, _) => { li += 1; ri += 1; continue; }
                (true, false, _, true) => return std::cmp::Ordering::Greater,
                (false, true, true, _) => return std::cmp::Ordering::Less,
                (true, false, _, false) => return std::cmp::Ordering::Less,
                (false, true, false, _) => return std::cmp::Ordering::Greater,
                _ => return std::cmp::Ordering::Equal,
            }
        }
        if li == left.len() || ri == right.len() { return (left.len() - li).cmp(&(right.len() - ri)); }
        let numeric = left[li].is_ascii_digit();
        if numeric != right[ri].is_ascii_digit() { return if numeric { std::cmp::Ordering::Greater } else { std::cmp::Ordering::Less }; }
        let (ls, rs) = (li, ri);
        while li < left.len() && left[li].is_ascii_digit() == numeric && left[li].is_ascii_alphanumeric() { li += 1; }
        while ri < right.len() && right[ri].is_ascii_digit() == numeric && right[ri].is_ascii_alphanumeric() { ri += 1; }
        let (mut la, mut ra) = (&left[ls..li], &right[rs..ri]);
        if numeric {
            while la.first() == Some(&b'0') { la = &la[1..]; }
            while ra.first() == Some(&b'0') { ra = &ra[1..]; }
            let length = la.len().cmp(&ra.len());
            if !length.is_eq() { return length; }
        }
        let ordering = la.cmp(ra);
        if !ordering.is_eq() { return ordering; }
    }
}
