use std::{
    error::Error,
    fmt,
    fs::File,
    io::{self, ErrorKind, Read},
    os::unix::fs::FileExt,
    sync::Arc,
};

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

#[derive(Clone)]
pub struct VerifiedBytes {
    pub(crate) sha256: String,
    pub(crate) size: u64,
    pub(crate) bytes: Vec<u8>,
    pub(crate) source: Option<VerifiedSource>,
}

/// A checksum-verified immutable cache file held by descriptor and identity.
/// Large primary/filelists payloads use this capability so verification does
/// not force their complete byte vectors to remain resident while libsolv is
/// constructing a repository pool.
#[derive(Clone)]
pub struct VerifiedFile {
    sha256: String,
    size: u64,
    source: VerifiedSource,
}

/// A positional reader pinned to the identity of a verified cache file.
///
/// Positional reads avoid sharing a seek offset with other users of the
/// capability.  The source identity is checked before construction and again
/// at EOF; callers that consume a complete metadata record additionally prove
/// its checksum while streaming.
pub struct VerifiedFileReader {
    source: VerifiedSource,
    offset: u64,
    size: u64,
    finished: bool,
}

#[derive(Clone)]
pub(crate) struct VerifiedSource {
    file: Arc<File>,
    identity: SourceIdentity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SourceIdentity {
    device: u64,
    inode: u64,
    size: i64,
    modified_seconds: i64,
    modified_nanoseconds: u64,
    changed_seconds: i64,
    changed_nanoseconds: u64,
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

    /// Attempts to clone this already verified immutable cache file into an
    /// empty destination inode. Unsupported filesystems return `Ok(false)` so
    /// callers can copy the verified bytes; source mutation always fails.
    #[cfg(target_os = "linux")]
    pub fn try_reflink_to(&self, destination: &File) -> Result<bool, CacheError> {
        let Some(source) = &self.source else {
            return Ok(false);
        };
        try_reflink_source(source, self.size, destination)
    }

    #[cfg(not(target_os = "linux"))]
    pub fn try_reflink_to(&self, _destination: &File) -> Result<bool, CacheError> {
        Ok(false)
    }
}

impl VerifiedFile {
    pub(crate) fn new(sha256: String, size: u64, file: File) -> Result<Self, CacheError> {
        Ok(Self {
            sha256,
            size,
            source: VerifiedSource::new(file)?,
        })
    }

    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    pub const fn size(&self) -> u64 {
        self.size
    }

    /// Opens a bounded streaming view without copying the complete verified
    /// payload into memory. The retained descriptor pins the inode while the
    /// reader independently tracks its positional offset.
    pub fn reader(&self) -> Result<VerifiedFileReader, CacheError> {
        if source_identity(self.source.file.as_ref())? != self.source.identity {
            return Err(CacheError::Corrupt(
                "verified cache source changed before streaming read".into(),
            ));
        }
        Ok(VerifiedFileReader {
            source: self.source.clone(),
            offset: 0,
            size: self.size,
            finished: false,
        })
    }

    /// Reads the already checksum-verified file through its retained
    /// descriptor. Identity is checked before and after the positional read,
    /// so in-place mutation cannot turn the capability into stale evidence.
    pub fn read_all(&self) -> Result<Vec<u8>, CacheError> {
        if source_identity(self.source.file.as_ref())? != self.source.identity {
            return Err(CacheError::Corrupt(
                "verified cache source changed before read".into(),
            ));
        }
        let size =
            usize::try_from(self.size).map_err(|error| CacheError::Corrupt(error.to_string()))?;
        let mut bytes = vec![0_u8; size];
        let mut offset = 0;
        while offset < bytes.len() {
            match self
                .source
                .file
                .read_at(&mut bytes[offset..], offset as u64)
            {
                Ok(0) => {
                    return Err(CacheError::Corrupt(
                        "verified cache source ended during read".into(),
                    ));
                }
                Ok(read) => offset += read,
                Err(error) if error.kind() == ErrorKind::Interrupted => {}
                Err(error) => return Err(io_error(error)),
            }
        }
        if source_identity(self.source.file.as_ref())? != self.source.identity {
            return Err(CacheError::Corrupt(
                "verified cache source changed during read".into(),
            ));
        }
        Ok(bytes)
    }

    #[cfg(target_os = "linux")]
    pub fn try_reflink_to(&self, destination: &File) -> Result<bool, CacheError> {
        try_reflink_source(&self.source, self.size, destination)
    }

    #[cfg(not(target_os = "linux"))]
    pub fn try_reflink_to(&self, _destination: &File) -> Result<bool, CacheError> {
        Ok(false)
    }
}

impl Read for VerifiedFileReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        if self.offset == self.size {
            if !self.finished {
                self.recheck()?;
                self.finished = true;
            }
            return Ok(0);
        }
        let remaining = usize::try_from(self.size - self.offset).unwrap_or(usize::MAX);
        let length = remaining.min(buffer.len());
        let read = self
            .source
            .file
            .read_at(&mut buffer[..length], self.offset)?;
        if read == 0 {
            return Err(io::Error::new(
                ErrorKind::UnexpectedEof,
                "verified cache source ended during streaming read",
            ));
        }
        self.offset = self
            .offset
            .checked_add(read as u64)
            .ok_or_else(|| io::Error::other("verified cache reader offset overflow"))?;
        if self.offset == self.size {
            self.recheck()?;
            self.finished = true;
        }
        Ok(read)
    }
}

impl VerifiedFileReader {
    fn recheck(&self) -> io::Result<()> {
        match source_identity(self.source.file.as_ref()) {
            Ok(identity) if identity == self.source.identity => Ok(()),
            Ok(_) => Err(io::Error::new(
                ErrorKind::InvalidData,
                "verified cache source changed during streaming read",
            )),
            Err(error) => Err(io::Error::new(ErrorKind::InvalidData, error.to_string())),
        }
    }
}

impl fmt::Debug for VerifiedFile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedFile")
            .field("sha256", &self.sha256)
            .field("size", &self.size)
            .finish_non_exhaustive()
    }
}

#[cfg(target_os = "linux")]
fn try_reflink_source(
    source: &VerifiedSource,
    size: u64,
    destination: &File,
) -> Result<bool, CacheError> {
    if source_identity(source.file.as_ref())? != source.identity {
        return Err(CacheError::Corrupt(
            "verified cache source changed before reflink".into(),
        ));
    }
    let target = rustix::fs::fstat(destination).map_err(errno_error)?;
    if target.st_mode & 0o170000 != 0o100000
        || target.st_uid != rustix::process::geteuid().as_raw()
        || target.st_nlink != 1
        || target.st_size != 0
        || target.st_mode & 0o022 != 0
    {
        return Err(CacheError::Corrupt("unsafe reflink destination".into()));
    }
    if rustix::fs::ioctl_ficlone(destination, source.file.as_ref()).is_err() {
        if source_identity(source.file.as_ref())? != source.identity {
            return Err(CacheError::Corrupt(
                "verified cache source changed during reflink attempt".into(),
            ));
        }
        return Ok(false);
    }
    if source_identity(source.file.as_ref())? != source.identity {
        return Err(CacheError::Corrupt(
            "verified cache source changed during reflink".into(),
        ));
    }
    let target = rustix::fs::fstat(destination).map_err(errno_error)?;
    if target.st_size < 0 || target.st_size as u64 != size {
        return Err(CacheError::Corrupt(
            "reflink destination size differs from verified payload".into(),
        ));
    }
    Ok(true)
}

impl fmt::Debug for VerifiedBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedBytes")
            .field("sha256", &self.sha256)
            .field("size", &self.size)
            .field("bytes", &self.bytes)
            .finish_non_exhaustive()
    }
}

impl PartialEq for VerifiedBytes {
    fn eq(&self, other: &Self) -> bool {
        self.sha256 == other.sha256 && self.size == other.size && self.bytes == other.bytes
    }
}

impl Eq for VerifiedBytes {}

impl VerifiedSource {
    pub(crate) fn new(file: File) -> Result<Self, CacheError> {
        let identity = source_identity(&file)?;
        Ok(Self {
            file: Arc::new(file),
            identity,
        })
    }
}

fn source_identity(file: &File) -> Result<SourceIdentity, CacheError> {
    let value = rustix::fs::fstat(file).map_err(errno_error)?;
    if value.st_mode & 0o170000 != 0o100000
        || value.st_uid != rustix::process::geteuid().as_raw()
        || value.st_nlink != 1
        || value.st_mode & 0o022 != 0
        || value.st_size < 0
    {
        return Err(CacheError::Corrupt("unsafe verified cache source".into()));
    }
    Ok(SourceIdentity {
        device: value.st_dev,
        inode: value.st_ino,
        size: value.st_size,
        modified_seconds: value.st_mtime,
        modified_nanoseconds: value.st_mtime_nsec,
        changed_seconds: value.st_ctime,
        changed_nanoseconds: value.st_ctime_nsec,
    })
}

fn errno_error(error: rustix::io::Errno) -> CacheError {
    CacheError::Io(error.to_string())
}

#[derive(Debug)]
pub struct VerifiedCompleteGeneration {
    pub(crate) digest: String,
    pub(crate) repository: String,
    pub(crate) origin: SelectedOrigin,
    pub(crate) repomd: VerifiedBytes,
    pub(crate) primary: VerifiedFile,
    pub(crate) filelists: VerifiedFile,
    pub(crate) primary_identities: Option<Vec<dnfast_metadata::PrimaryPackageIdentity>>,
    pub(crate) primary_files: Option<VerifiedBytes>,
    pub(crate) repomd_authentication: RepomdAuthentication,
}

/// The small, authenticated repository pointer identity. This proves which
/// generation is current, but deliberately does not claim that the generation
/// payload was rehashed; callers needing payload bytes must open the complete
/// verified generation instead.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CurrentGenerationIdentity {
    pub(crate) digest: String,
    pub(crate) repomd_authentication: RepomdAuthentication,
}

impl CurrentGenerationIdentity {
    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub fn repomd_authentication(&self) -> &RepomdAuthentication {
        &self.repomd_authentication
    }
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
    pub fn primary(&self) -> &VerifiedFile {
        &self.primary
    }
    pub fn filelists(&self) -> &VerifiedFile {
        &self.filelists
    }
    /// Returns the immutable, manifest-authenticated identity projection that
    /// was produced while the primary XML was originally checksum-validated.
    /// Versions two and three cache objects do not contain this projection and
    /// callers must validate and parse their primary bytes instead.
    pub fn primary_identities(&self) -> Option<&[dnfast_metadata::PrimaryPackageIdentity]> {
        self.primary_identities.as_deref()
    }
    /// Returns the authenticated fixed-width primary path digest records that
    /// were emitted by the same validation pass as `primary_identities`.
    pub fn primary_files(&self) -> Option<&VerifiedBytes> {
        self.primary_files.as_ref()
    }
    /// Releases the optional derived identity projection after a caller has
    /// published its own checksum-bound capability. Raw metadata and its
    /// retained verification descriptors remain available and unchanged.
    pub fn discard_primary_identities(&mut self) {
        self.primary_identities = None;
    }
    pub fn discard_primary_files(&mut self) {
        self.primary_files = None;
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
    pub(crate) primary_identities: Option<FileRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) primary_files: Option<FileRecord>,
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
