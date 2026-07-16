use std::path::{Path, PathBuf};

use base64::{Engine, engine::general_purpose::STANDARD};
use dnfast_cache::RepomdAuthentication;
use dnfast_core::{
    CanonicalDocument, InstalledInventory, PlanIntegrity, RepoTrustPolicy, RepositoryBinding,
    SolverPolicy,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::PlanningError;

const LEGACY_SNAPSHOT_SCHEMA_VERSION: u32 = 3;
const SNAPSHOT_SCHEMA_VERSION: u32 = 4;
const MAX_SNAPSHOT_BYTES: usize = 128 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlanningSnapshot {
    schema_version: u32,
    published_at_unix: u64,
    refreshed_repository_ids: Vec<String>,
    payload: PlanningPayload,
    #[serde(skip)]
    planning_root: Option<PathBuf>,
    #[serde(skip)]
    storage_owner: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlanningPayload {
    pub policy: PlanningPolicy,
    pub inventory: InstalledInventory,
    pub allowed_repositories: Vec<PlanningRepository>,
    pub configuration: Vec<PlanningConfiguration>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlanningPolicy {
    pub solver: SolverPolicy,
    pub included_packages: Vec<String>,
    pub installonly_limit: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlanningRepository {
    pub id: String,
    pub priority: u32,
    pub cost: u32,
    pub generation_sha256: String,
    pub origin: PlanningOrigin,
    pub repomd: PlanningBytes,
    pub primary: PlanningBytes,
    pub filelists: PlanningBytes,
    pub trust: RepoTrustPolicy,
    pub keys: Vec<PlanningKey>,
    pub repomd_authentication: RepomdAuthentication,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlanningOrigin {
    pub repomd_url: String,
    pub sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlanningBytes {
    pub sha256: String,
    pub size: u64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub base64: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlanningKey {
    pub bundle_path: String,
    pub certificate_base64: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlanningConfiguration {
    pub id: String,
    pub enabled: bool,
    pub baseurl: Vec<String>,
    pub metalink: Option<String>,
    pub mirrorlist: Option<String>,
    pub priority: u32,
    pub cost: u32,
    pub excludes: Vec<String>,
    pub includes: Vec<String>,
    pub gpgkey: Vec<String>,
    pub allowed_fingerprints: Vec<String>,
    pub repo_gpgcheck: bool,
}

impl PlanningSnapshot {
    pub(crate) fn new(
        published_at_unix: u64,
        payload: PlanningPayload,
    ) -> Result<Self, PlanningError> {
        let refreshed_repository_ids = payload
            .allowed_repositories
            .iter()
            .map(|repository| repository.id.clone())
            .collect();
        Self::new_with_refreshed_repositories(published_at_unix, refreshed_repository_ids, payload)
    }

    pub(crate) fn new_with_refreshed_repositories(
        published_at_unix: u64,
        refreshed_repository_ids: Vec<String>,
        payload: PlanningPayload,
    ) -> Result<Self, PlanningError> {
        let value = Self {
            schema_version: SNAPSHOT_SCHEMA_VERSION,
            published_at_unix,
            refreshed_repository_ids,
            payload,
            planning_root: None,
            storage_owner: 0,
        };
        value.validate()?;
        Ok(value)
    }

    pub const fn published_at_unix(&self) -> u64 {
        self.published_at_unix
    }
    pub fn payload(&self) -> &PlanningPayload {
        &self.payload
    }

    pub(crate) fn attach_storage(&mut self, planning_root: &Path, owner: u32) {
        self.planning_root = Some(planning_root.to_path_buf());
        self.storage_owner = owner;
    }

    pub(crate) fn storage(&self) -> Option<(&Path, u32)> {
        self.planning_root
            .as_deref()
            .map(|root| (root, self.storage_owner))
    }
    pub fn refreshed_repository_ids(&self) -> &[String] {
        &self.refreshed_repository_ids
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, PlanningError> {
        self.validate()?;
        let value = serde_json::to_value(self).map_err(json)?;
        serde_json::to_vec(&value).map_err(json)
    }

    pub fn digest(&self) -> Result<String, PlanningError> {
        Ok(format!("{:x}", Sha256::digest(self.canonical_bytes()?)))
    }

    pub fn integrity_for_repositories(
        &self,
        selected_repository_ids: &[String],
    ) -> Result<PlanIntegrity, PlanningError> {
        self.validate()?;
        let selected = self.selected_repositories(selected_repository_ids)?;
        let policy = self
            .payload
            .policy
            .solver
            .canonical_sha256()
            .map_err(domain)?;
        let inventory = self.payload.inventory.canonical_sha256().map_err(domain)?;
        let snapshot = self.digest()?;
        let metadata = metadata_digest(&selected)?;
        let trust = trust_digest(&selected)?;
        let bindings = selected
            .into_iter()
            .map(|repository| {
                let trust = repository.trust.canonical_sha256()?;
                RepositoryBinding::new(
                    repository.id.clone(),
                    dnfast_core::Sha256Digest::parse(
                        repository.generation_sha256.clone(),
                        "generation_sha256",
                    )?,
                    dnfast_core::Sha256Digest::parse(
                        repository.origin.sha256.clone(),
                        "origin_sha256",
                    )?,
                    trust,
                )
            })
            .collect::<Result<Vec<_>, dnfast_core::DomainError>>()
            .map_err(domain)?;
        PlanIntegrity::new(
            [
                policy.as_str(),
                trust.as_str(),
                inventory.as_str(),
                metadata.as_str(),
                snapshot.as_str(),
            ],
            bindings,
        )
        .map_err(domain)
    }

    pub(crate) fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, PlanningError> {
        if bytes.len() > MAX_SNAPSHOT_BYTES {
            return Err(PlanningError::UnsafeSnapshot(
                "snapshot exceeds maximum size".into(),
            ));
        }
        let value: Self = serde_json::from_slice(bytes).map_err(json)?;
        if value.canonical_bytes()? != bytes {
            return Err(PlanningError::UnsafeSnapshot(
                "snapshot is not canonical JSON".into(),
            ));
        }
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), PlanningError> {
        if !matches!(
            self.schema_version,
            LEGACY_SNAPSHOT_SCHEMA_VERSION | SNAPSHOT_SCHEMA_VERSION
        ) {
            return Err(PlanningError::Input("unsupported snapshot schema".into()));
        }
        if self.payload.allowed_repositories.is_empty()
            || self
                .refreshed_repository_ids
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || self.refreshed_repository_ids.iter().any(|id| {
                !self
                    .payload
                    .allowed_repositories
                    .iter()
                    .any(|repository| repository.id == *id)
            })
            || self
                .payload
                .allowed_repositories
                .windows(2)
                .any(|pair| pair[0].id >= pair[1].id)
            || self
                .payload
                .configuration
                .windows(2)
                .any(|pair| pair[0].id >= pair[1].id)
        {
            return Err(PlanningError::Input(
                "repositories are not canonical".into(),
            ));
        }
        self.payload
            .policy
            .solver
            .ensure_supported()
            .map_err(domain)?;
        self.payload.inventory.canonical_sha256().map_err(domain)?;
        for repository in &self.payload.allowed_repositories {
            validate_repository(repository, self.schema_version)?;
            let configuration = self
                .payload
                .configuration
                .iter()
                .find(|configuration| configuration.id == repository.id)
                .ok_or_else(|| {
                    PlanningError::Input("allowed repository is absent from configuration".into())
                })?;
            if !configuration.enabled
                || configuration.priority != repository.priority
                || configuration.cost != repository.cost
                || configuration.gpgkey
                    != repository
                        .keys
                        .iter()
                        .map(|key| key.bundle_path.clone())
                        .collect::<Vec<_>>()
            {
                return Err(PlanningError::Input(
                    "allowed repository differs from configuration".into(),
                ));
            }
            let mut fingerprints = configuration
                .allowed_fingerprints
                .iter()
                .map(|fingerprint| fingerprint.to_ascii_uppercase())
                .collect::<Vec<_>>();
            fingerprints.sort();
            if fingerprints != repository.trust.allowed_primary_fingerprints() {
                return Err(PlanningError::Input(
                    "repository trust differs from configuration".into(),
                ));
            }
            if configuration.repo_gpgcheck {
                match &repository.repomd_authentication {
                    RepomdAuthentication::OpenPgp {
                        primary_fingerprint,
                        key_bundle_sha256,
                        ..
                    } if fingerprints.contains(primary_fingerprint)
                        && key_bundle_sha256 == repository.trust.key_bundle_sha256().as_str() => {}
                    _ => {
                        return Err(PlanningError::Input(
                            "repository requires authenticated repomd metadata".into(),
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    fn selected_repositories<'a>(
        &'a self,
        selected_repository_ids: &[String],
    ) -> Result<Vec<&'a PlanningRepository>, PlanningError> {
        let mut requested = if selected_repository_ids.is_empty() {
            self.payload
                .allowed_repositories
                .iter()
                .map(|repository| repository.id.clone())
                .collect::<Vec<_>>()
        } else {
            selected_repository_ids.to_vec()
        };
        requested.sort();
        if requested.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(PlanningError::Input(
                "selected repository identifiers are duplicate".into(),
            ));
        }
        requested
            .into_iter()
            .map(|id| {
                self.payload
                    .allowed_repositories
                    .iter()
                    .find(|repository| repository.id == id)
                    .ok_or_else(|| {
                        PlanningError::Input(
                            "selected repository is not root-published and enabled".into(),
                        )
                    })
            })
            .collect()
    }
}

impl PlanningBytes {
    pub(crate) fn from_verified(bytes: &dnfast_cache::VerifiedBytes) -> Self {
        Self {
            sha256: bytes.sha256().into(),
            size: bytes.size(),
            base64: String::new(),
        }
    }

    pub(crate) fn decode_verified(
        &self,
        storage: Option<(&Path, u32)>,
    ) -> Result<Vec<u8>, PlanningError> {
        let decoded = if self.base64.is_empty() {
            let (planning_root, owner) = storage.ok_or_else(|| {
                PlanningError::UnsafeSnapshot(
                    "external snapshot payload has no trusted storage binding".into(),
                )
            })?;
            crate::snapshot_store::read_blob(planning_root, owner, &self.sha256, self.size)?
        } else {
            self.decode()?
        };
        if u64::try_from(decoded.len()).map_err(|error| PlanningError::Input(error.to_string()))?
            != self.size
            || format!("{:x}", Sha256::digest(&decoded)) != self.sha256
        {
            return Err(PlanningError::Input(
                "snapshot payload digest differs".into(),
            ));
        }
        Ok(decoded)
    }

    fn validate_shape(&self, schema_version: u32) -> Result<(), PlanningError> {
        if self.size == 0
            || self.sha256.len() != 64
            || !self
                .sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || (schema_version == LEGACY_SNAPSHOT_SCHEMA_VERSION && self.base64.is_empty())
        {
            return Err(PlanningError::Input(
                "snapshot payload descriptor is invalid".into(),
            ));
        }
        Ok(())
    }

    fn decode(&self) -> Result<Vec<u8>, PlanningError> {
        STANDARD
            .decode(&self.base64)
            .map_err(|_| PlanningError::Input("invalid base64 snapshot payload".into()))
    }
}

fn validate_repository(
    repository: &PlanningRepository,
    schema_version: u32,
) -> Result<(), PlanningError> {
    if repository.id.is_empty()
        || repository.generation_sha256 != repository.repomd.sha256
        || repository.trust.repo_id() != repository.id
        || repository.keys.is_empty()
        || repository
            .keys
            .windows(2)
            .any(|pair| pair[0].bundle_path >= pair[1].bundle_path)
    {
        return Err(PlanningError::Input(
            "repository payload is not canonical".into(),
        ));
    }
    for payload in [
        &repository.repomd,
        &repository.primary,
        &repository.filelists,
    ] {
        payload.validate_shape(schema_version)?;
    }
    if format!(
        "{:x}",
        Sha256::digest(repository.origin.repomd_url.as_bytes())
    ) != repository.origin.sha256
    {
        return Err(PlanningError::Input(
            "selected origin digest differs".into(),
        ));
    }
    dnfast_cache::SelectedOrigin::parse(&repository.origin.repomd_url)
        .map_err(|error| PlanningError::Input(error.to_string()))?;
    repository.trust.canonical_sha256().map_err(domain)?;
    repository
        .repomd_authentication
        .validate()
        .map_err(|error| PlanningError::Input(error.to_string()))?;
    let mut bundle = Sha256::new();
    bundle.update(b"dnfast-key-bundle-v1");
    for key in &repository.keys {
        dnfast_repo::validate_gpgkey_bundle_path(&repository.id, &key.bundle_path)
            .map_err(|_| PlanningError::Input("key bundle path differs from repository".into()))?;
        let certificate = STANDARD
            .decode(&key.certificate_base64)
            .map_err(|_| PlanningError::Input("key certificate is not base64".into()))?;
        frame(&mut bundle, &key.bundle_path, &certificate)?;
    }
    if format!("{:x}", bundle.finalize()) != repository.trust.key_bundle_sha256().as_str() {
        return Err(PlanningError::Input(
            "key bundle differs from trust policy".into(),
        ));
    }
    Ok(())
}

fn domain(error: dnfast_core::DomainError) -> PlanningError {
    PlanningError::Input(error.to_string())
}
fn json(error: serde_json::Error) -> PlanningError {
    PlanningError::Input(error.to_string())
}

fn frame(digest: &mut Sha256, name: &str, bytes: &[u8]) -> Result<(), PlanningError> {
    digest.update(
        u64::try_from(name.len())
            .map_err(|error| PlanningError::Input(error.to_string()))?
            .to_be_bytes(),
    );
    digest.update(name.as_bytes());
    digest.update(
        u64::try_from(bytes.len())
            .map_err(|error| PlanningError::Input(error.to_string()))?
            .to_be_bytes(),
    );
    digest.update(bytes);
    Ok(())
}

fn metadata_digest(repositories: &[&PlanningRepository]) -> Result<String, PlanningError> {
    let mut digest = Sha256::new();
    digest.update(b"dnfast-root-metadata-v3");
    for repository in repositories {
        frame(&mut digest, &repository.id, repository.id.as_bytes())?;
        digest.update(repository.priority.to_be_bytes());
        digest.update(repository.cost.to_be_bytes());
        frame(
            &mut digest,
            &repository.generation_sha256,
            repository.generation_sha256.as_bytes(),
        )?;
        frame(
            &mut digest,
            &repository.origin.sha256,
            repository.origin.sha256.as_bytes(),
        )?;
        let trust = repository.trust.canonical_sha256().map_err(domain)?;
        frame(&mut digest, trust.as_str(), trust.as_str().as_bytes())?;
        for bytes in [
            &repository.repomd,
            &repository.primary,
            &repository.filelists,
        ] {
            frame(&mut digest, &bytes.sha256, bytes.sha256.as_bytes())?;
            digest.update(bytes.size.to_be_bytes());
        }
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn trust_digest(repositories: &[&PlanningRepository]) -> Result<String, PlanningError> {
    let mut digest = Sha256::new();
    digest.update(b"dnfast-root-trust-v3");
    for repository in repositories {
        frame(&mut digest, &repository.id, repository.id.as_bytes())?;
        let trust = repository.trust.canonical_sha256().map_err(domain)?;
        frame(&mut digest, trust.as_str(), trust.as_str().as_bytes())?;
    }
    Ok(format!("{:x}", digest.finalize()))
}
