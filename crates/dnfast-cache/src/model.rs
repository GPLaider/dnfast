use std::{error::Error, fmt};

use dnfast_metadata::{CompletePackage, FileListPackage, MetadataError, Package};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;

#[derive(Debug)]
pub enum CacheError {
    MissingSnapshot(String),
    CacheUpgradeRequired,
    Corrupt(String),
    Io(String),
}

impl fmt::Display for CacheError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "cache error: {self:?}")
    }
}

impl Error for CacheError {}

#[derive(Debug)]
pub struct Snapshot {
    pub digest: String,
    pub packages: Vec<Package>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
/// Byte-integrity scope proved by the cache. This is not publisher or package trust.
pub enum SnapshotIntegrity {
    SearchOnly,
    CompleteMetadata,
}

#[derive(Debug)]
pub struct CompleteSnapshot {
    pub digest: String,
    pub repository: String,
    pub integrity: SnapshotIntegrity,
    pub packages: Vec<Package>,
    pub solver_inputs: Vec<CompletePackage>,
    pub filelists: Vec<FileListPackage>,
    pub source_origin: Option<SelectedOrigin>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RepomdAuthentication {
    TransportOnly,
    OpenPgp {
        primary_fingerprint: String,
        signing_fingerprint: String,
        key_bundle_sha256: String,
        signature_sha256: String,
    },
}

impl RepomdAuthentication {
    pub fn openpgp(
        primary_fingerprint: impl Into<String>,
        signing_fingerprint: impl Into<String>,
        key_bundle_sha256: impl Into<String>,
        signature_sha256: impl Into<String>,
    ) -> Result<Self, CacheError> {
        let value = Self::OpenPgp {
            primary_fingerprint: primary_fingerprint.into().to_ascii_uppercase(),
            signing_fingerprint: signing_fingerprint.into().to_ascii_uppercase(),
            key_bundle_sha256: key_bundle_sha256.into().to_ascii_lowercase(),
            signature_sha256: signature_sha256.into().to_ascii_lowercase(),
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), CacheError> {
        match self {
            Self::TransportOnly => Ok(()),
            Self::OpenPgp {
                primary_fingerprint,
                signing_fingerprint,
                key_bundle_sha256,
                signature_sha256,
            } => {
                if !valid_fingerprint(primary_fingerprint)
                    || !valid_fingerprint(signing_fingerprint)
                    || !valid_digest(key_bundle_sha256)
                    || !valid_digest(signature_sha256)
                {
                    return Err(CacheError::Corrupt(
                        "invalid repomd authentication evidence".into(),
                    ));
                }
                Ok(())
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectedOrigin(String);

impl SelectedOrigin {
    pub fn parse(value: &str) -> Result<Self, OriginError> {
        let parsed = Url::parse(value).map_err(|_| OriginError::Invalid)?;
        if parsed.scheme() != "https"
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || value.contains('\\')
            || parsed.as_str() != value
            || value.strip_suffix("/repodata/repomd.xml").is_none()
        {
            return Err(OriginError::Invalid);
        }
        let base = value
            .strip_suffix("/repodata/repomd.xml")
            .ok_or(OriginError::Invalid)?;
        if base.is_empty() || base.ends_with('/') {
            return Err(OriginError::Invalid);
        }
        Ok(Self(value.into()))
    }

    pub fn repomd_url(&self) -> &str {
        &self.0
    }

    pub fn artifact_base(&self) -> &str {
        self.0
            .strip_suffix("/repodata/repomd.xml")
            .unwrap_or_default()
    }

    pub fn artifact_url(&self, href: &str) -> Result<String, OriginError> {
        if href.is_empty()
            || href.starts_with('/')
            || href.contains('\\')
            || href.contains('?')
            || href.contains('#')
            || href.split('/').any(|part| matches!(part, "" | "." | ".."))
        {
            return Err(OriginError::InvalidArtifactPath);
        }
        Ok(format!("{}/{href}", self.artifact_base()))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OriginError {
    Invalid,
    InvalidArtifactPath,
}

impl fmt::Display for OriginError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid => formatter.write_str("invalid selected repository origin"),
            Self::InvalidArtifactPath => formatter.write_str("invalid repository artifact path"),
        }
    }
}

impl Error for OriginError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedBytes {
    pub(crate) sha256: String,
    pub(crate) size: u64,
    pub(crate) bytes: Vec<u8>,
}

impl VerifiedBytes {
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
    pub const fn size(&self) -> u64 {
        self.size
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[derive(Debug)]
pub struct VerifiedCompleteGeneration {
    pub(crate) digest: String,
    pub(crate) repository: String,
    pub(crate) origin: SelectedOrigin,
    pub(crate) repomd: VerifiedBytes,
    pub(crate) primary: VerifiedBytes,
    pub(crate) filelists: VerifiedBytes,
    pub(crate) solver_inputs: Vec<CompletePackage>,
    pub(crate) filelist_inputs: Vec<FileListPackage>,
    pub(crate) repomd_authentication: RepomdAuthentication,
}

impl VerifiedCompleteGeneration {
    pub fn digest(&self) -> &str {
        &self.digest
    }
    pub fn repository(&self) -> &str {
        &self.repository
    }
    pub fn origin(&self) -> &SelectedOrigin {
        &self.origin
    }
    pub fn repomd(&self) -> &VerifiedBytes {
        &self.repomd
    }
    pub fn primary(&self) -> &VerifiedBytes {
        &self.primary
    }
    pub fn filelists(&self) -> &VerifiedBytes {
        &self.filelists
    }
    pub fn solver_inputs(&self) -> &[CompletePackage] {
        &self.solver_inputs
    }
    pub fn filelist_inputs(&self) -> &[FileListPackage] {
        &self.filelist_inputs
    }
    pub fn repomd_authentication(&self) -> &RepomdAuthentication {
        &self.repomd_authentication
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Manifest {
    pub(crate) version: u32,
    pub(crate) repomd: FileRecord,
    pub(crate) primary: FileRecord,
    pub(crate) search_index: FileRecord,
    pub(crate) repository: FileRecord,
    pub(crate) integrity: SnapshotIntegrity,
    pub(crate) filelists: Option<FileRecord>,
    pub(crate) filelists_index: Option<FileRecord>,
    pub(crate) solver_inputs: Option<FileRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) source_origin: Option<FileRecord>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CurrentPointer {
    pub(crate) version: u32,
    pub(crate) digest: String,
    pub(crate) repomd_authentication: RepomdAuthentication,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FileRecord {
    pub(crate) name: String,
    pub(crate) sha256: String,
    pub(crate) size: u64,
}

pub(crate) fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub(crate) fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_fingerprint(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_lowercase())
}

pub(crate) fn io_error(error: std::io::Error) -> CacheError {
    CacheError::Io(error.to_string())
}

pub(crate) fn metadata_error(error: MetadataError) -> CacheError {
    CacheError::Corrupt(error.to_string())
}
