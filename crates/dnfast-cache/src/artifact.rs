use std::{io::Read, time::Duration};

use url::Url;

pub const MAX_ARTIFACT_BYTES: u64 = 8 * 1024 * 1024 * 1024;
pub const MAX_TRANSACTION_BYTES: u64 = 64 * 1024 * 1024 * 1024;
pub const MAX_TRANSACTION_ARTIFACTS: u64 = 100_000;
pub const MAX_CACHE_BYTES: u64 = 128 * 1024 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Digest {
    Sha256(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactSpec {
    pub(crate) url: String,
    pub(crate) digest: String,
    pub(crate) size: u64,
}

impl ArtifactSpec {
    pub fn new(
        repository_base: &str,
        selected_base: &str,
        location: &str,
        digest: Digest,
        size: u64,
    ) -> Result<Self, ArtifactError> {
        if size > MAX_ARTIFACT_BYTES {
            return Err(ArtifactError::Policy("artifact exceeds 8 GiB".into()));
        }
        let repository = parse_base(repository_base)?;
        let selected = parse_base(selected_base)?;
        if origin(&repository) != origin(&selected) {
            return Err(ArtifactError::Policy(
                "selected URL is not same-origin".into(),
            ));
        }
        Self::from_selected_base(selected, location, digest, size)
    }

    pub fn from_selected_mirror(
        selected_mirror: &str,
        location: &str,
        digest: Digest,
        size: u64,
    ) -> Result<Self, ArtifactError> {
        Self::from_selected_base(parse_base(selected_mirror)?, location, digest, size)
    }

    fn from_selected_base(
        selected: Url,
        location: &str,
        digest: Digest,
        size: u64,
    ) -> Result<Self, ArtifactError> {
        if size > MAX_ARTIFACT_BYTES {
            return Err(ArtifactError::Policy("artifact exceeds 8 GiB".into()));
        }
        if location.is_empty()
            || location.starts_with('/')
            || location.contains('\\')
            || location.contains('?')
            || location.contains('#')
            || location.contains('%')
            || location.contains("://")
            || location
                .split('/')
                .any(|part| part.is_empty() || matches!(part, "." | ".."))
        {
            return Err(ArtifactError::Policy(
                "unsafe metadata package location".into(),
            ));
        }
        let Digest::Sha256(value) = digest;
        if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(ArtifactError::Policy("unsupported SHA-256 digest".into()));
        }
        // `Url::join` treats a base without a trailing slash as a file and
        // replaces its final path segment. Selected rpm-md origins are bound
        // as `<repository>/repodata/repomd.xml`, so the derived repository
        // base intentionally has no trailing slash. Make the directory
        // semantics explicit before resolving a package location.
        let mut directory = selected.clone();
        if !directory.path().ends_with('/') {
            let path = format!("{}/", directory.path());
            directory.set_path(&path);
        }
        let url = directory
            .join(location)
            .map_err(|error| ArtifactError::Policy(error.to_string()))?;
        if origin(&url) != origin(&selected) {
            return Err(ArtifactError::Policy(
                "package URL escaped selected origin".into(),
            ));
        }
        Ok(Self {
            url: url.into(),
            digest: value.to_ascii_lowercase(),
            size,
        })
    }
}

fn parse_base(value: &str) -> Result<Url, ArtifactError> {
    let url = Url::parse(value).map_err(|error| ArtifactError::Policy(error.to_string()))?;
    if url.scheme() != "https"
        || url.username() != ""
        || url.password().is_some()
        || url.host_str().is_none()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(ArtifactError::Policy("unsafe HTTPS base URL".into()));
    }
    Ok(url)
}

fn origin(url: &Url) -> (&str, Option<u16>, &str) {
    (
        url.scheme(),
        url.port_or_known_default(),
        url.host_str().unwrap_or_default(),
    )
}

#[derive(Clone, Copy, Debug)]
pub struct Capacity {
    pub cached_bytes: u64,
    pub available_bytes: u64,
}

#[derive(Clone, Debug)]
pub struct TransactionRequest {
    predicted_bytes: u64,
    artifacts: u64,
    pub(crate) identities: Vec<(String, u64)>,
}

impl TransactionRequest {
    pub fn from_totals(predicted_bytes: u64, artifacts: u64) -> Result<Self, ArtifactError> {
        let request = Self {
            predicted_bytes,
            artifacts,
            identities: Vec::new(),
        };
        request.validate(Capacity {
            cached_bytes: 0,
            available_bytes: u64::MAX,
        })?;
        Ok(request)
    }

    pub fn for_specs(specs: &[ArtifactSpec]) -> Result<Self, ArtifactError> {
        let predicted_bytes = specs
            .iter()
            .try_fold(0_u64, |total, spec| total.checked_add(spec.size))
            .ok_or_else(|| ArtifactError::Capacity("transaction byte count overflow".into()))?;
        let artifacts = u64::try_from(specs.len())
            .map_err(|error| ArtifactError::Capacity(error.to_string()))?;
        let mut identities = specs
            .iter()
            .map(|spec| (spec.digest.clone(), spec.size))
            .collect::<Vec<_>>();
        identities.sort();
        if identities.windows(2).any(|window| window[0] == window[1]) {
            return Err(ArtifactError::Capacity(
                "duplicate artifact in transaction".into(),
            ));
        }
        let mut request = Self::from_totals(predicted_bytes, artifacts)?;
        request.identities = identities;
        Ok(request)
    }

    pub fn validate(&self, capacity: Capacity) -> Result<(), ArtifactError> {
        if self.predicted_bytes > MAX_TRANSACTION_BYTES
            || self.artifacts > MAX_TRANSACTION_ARTIFACTS
        {
            return Err(ArtifactError::Capacity(
                "transaction artifact limit exceeded".into(),
            ));
        }
        let cache_after = capacity
            .cached_bytes
            .checked_add(self.predicted_bytes)
            .ok_or_else(|| ArtifactError::Capacity("cache size overflow".into()))?;
        if cache_after > MAX_CACHE_BYTES {
            return Err(ArtifactError::Capacity(
                "artifact cache cap exceeded".into(),
            ));
        }
        let reserve = self
            .predicted_bytes
            .checked_add(
                self.predicted_bytes
                    .checked_add(19)
                    .ok_or_else(|| ArtifactError::Capacity("reserve overflow".into()))?
                    / 20,
            )
            .ok_or_else(|| ArtifactError::Capacity("reserve overflow".into()))?;
        if capacity.available_bytes < reserve {
            return Err(ArtifactError::Capacity(
                "filesystem reserve is insufficient".into(),
            ));
        }
        Ok(())
    }
}

pub struct ArtifactResponse {
    pub status: u16,
    pub body: Box<dyn Read + Send>,
}

pub trait ArtifactTransport {
    fn open(&self, url: &str) -> Result<ArtifactResponse, ArtifactError>;
}

pub struct HttpArtifactTransport {
    agent: ureq::Agent,
}

impl HttpArtifactTransport {
    pub fn new() -> Self {
        Self::with_tls(ureq::tls::RootCerts::PlatformVerifier)
    }

    pub fn with_root_certificate_pem(pem: &[u8]) -> Result<Self, ArtifactError> {
        let certificate = ureq::tls::Certificate::from_pem(pem)
            .map_err(|error| ArtifactError::Policy(error.to_string()))?;
        Ok(Self::with_tls(ureq::tls::RootCerts::new_with_certs(&[
            certificate,
        ])))
    }

    fn with_tls(root_certs: ureq::tls::RootCerts) -> Self {
        use ureq::tls::TlsConfig;
        let agent = ureq::Agent::config_builder()
            .https_only(true)
            .max_redirects(0)
            .max_redirects_will_error(true)
            .timeout_global(Some(Duration::from_secs(45)))
            .tls_config(TlsConfig::builder().root_certs(root_certs).build())
            .build()
            .new_agent();
        Self { agent }
    }
}

impl Default for HttpArtifactTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactTransport for HttpArtifactTransport {
    fn open(&self, url: &str) -> Result<ArtifactResponse, ArtifactError> {
        let response = self
            .agent
            .get(url)
            .header("Accept-Encoding", "identity")
            .call()
            .map_err(|error| ArtifactError::Transport(error.to_string()))?;
        let status = response.status().as_u16();
        Ok(ArtifactResponse {
            status,
            body: Box::new(response.into_body().into_reader()),
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ArtifactError {
    #[error("artifact policy rejected input: {0}")]
    Policy(String),
    #[error("artifact capacity rejected transaction: {0}")]
    Capacity(String),
    #[error("artifact transport failed: {0}")]
    Transport(String),
    #[error("artifact integrity failed: {0}")]
    Integrity(String),
    #[error("artifact filesystem operation failed: {0}")]
    Io(String),
    #[error("artifact cache is busy: {0}")]
    Busy(String),
}
