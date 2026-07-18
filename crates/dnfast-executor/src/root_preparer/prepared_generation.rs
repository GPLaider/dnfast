mod digest;
mod publication;

use std::{
    fs::File,
    io::{Read, Write},
    os::fd::OwnedFd,
};

use base64::Engine as _;
use dnfast_cache::{
    ArtifactCache, ArtifactError, ArtifactSpec, ArtifactTransport, Digest, TransactionRequest,
};
use dnfast_core::CanonicalDocument;
use dnfast_planning::{
    NativeRepositoryXml, PlanningRepository, PlanningSnapshot, SYSTEM_CACHE_PATH,
};
use rustix::{
    fs::{AtFlags, Mode, OFlags, ResolveFlags, fsync, mkdirat, openat, openat2, unlinkat},
    io::Errno,
};
use sha2::{Digest as _, Sha256};

use crate::{
    ExecutorError,
    input_model::{
        InputArtifact, InputFile, InputKey, InputManifest, InputOrigin, InputRepository,
        InputRepositoryTrust,
    },
    root_inputs::INPUT_PATH,
    staging::system_directory,
};

use super::PreparationError;

#[cfg(test)]
pub(crate) use digest::metadata_digest;
use digest::{artifact_key, descriptor};
pub(crate) use digest::{metadata_digest_v4, trust_digest};
#[cfg(test)]
pub(crate) use publication::{Publication, remove_generation};

pub(crate) const PREPARING_PREFIX: &str = ".prepare-";

pub(crate) struct InputDraft {
    pub(crate) parent: OwnedFd,
    directory: OwnedFd,
    root_path: String,
    name: String,
}

pub(crate) struct MaterializedRepository {
    pub(crate) input: InputRepository,
    pub(crate) native_primary: InputFile,
    pub(crate) native_filelists: InputFile,
}

impl InputDraft {
    pub(crate) fn create() -> Result<Self, PreparationError> {
        let parent = system_directory(&INPUT_PATH).map_err(inputs)?;
        Self::create_with_parent(parent, "/var/lib/dnfast/inputs")
    }

    #[cfg(test)]
    pub(crate) fn create_under(parent: OwnedFd, root_path: &str) -> Result<Self, PreparationError> {
        Self::create_with_parent(parent, root_path)
    }

    fn create_with_parent(parent: OwnedFd, root_path: &str) -> Result<Self, PreparationError> {
        for _ in 0..16 {
            let name = format!("{PREPARING_PREFIX}{}", nonce()?);
            match mkdirat(&parent, &name, Mode::from_raw_mode(0o700)) {
                Ok(()) => {
                    let directory = openat2(
                        &parent,
                        &name,
                        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                        Mode::empty(),
                        ResolveFlags::BENEATH
                            | ResolveFlags::NO_SYMLINKS
                            | ResolveFlags::NO_MAGICLINKS,
                    )
                    .map_err(errno)?;
                    return Ok(Self {
                        parent,
                        directory,
                        root_path: root_path.into(),
                        name,
                    });
                }
                Err(Errno::EXIST) => {}
                Err(error) => return Err(errno(error)),
            }
        }
        Err(PreparationError::Publish(
            "could not create unique preparation directory".into(),
        ))
    }

    pub(crate) fn write_repository(
        &mut self,
        snapshot: &PlanningSnapshot,
        repository: &PlanningRepository,
        index: usize,
    ) -> Result<MaterializedRepository, PreparationError> {
        let metadata = snapshot
            .materialize_native_xml(repository)
            .map_err(|error| PreparationError::Snapshot(error.to_string()))?;
        let file_provides = self.write_optional_payload(
            snapshot,
            repository.file_provides.as_ref(),
            &format!("repo-{index}-file-provides"),
        )?;
        let group = self.write_optional_payload(
            snapshot,
            repository.group.as_ref(),
            &format!("repo-{index}-group"),
        )?;
        let modules = self.write_optional_payload(
            snapshot,
            repository.modules.as_ref(),
            &format!("repo-{index}-modules"),
        )?;
        self.write_materialized_repository(
            repository,
            index,
            &metadata,
            file_provides,
            group,
            modules,
        )
    }

    pub(crate) fn write_repository_raw(
        &mut self,
        snapshot: &PlanningSnapshot,
        repository: &PlanningRepository,
        index: usize,
    ) -> Result<InputRepository, PreparationError> {
        let prefix = format!("repo-{index}");
        let repomd =
            self.write_snapshot_payload(snapshot, &repository.repomd, &format!("{prefix}-repomd"))?;
        let primary = self.write_snapshot_payload(
            snapshot,
            &repository.primary,
            &format!("{prefix}-primary"),
        )?;
        let filelists = self.write_snapshot_payload(
            snapshot,
            &repository.filelists,
            &format!("{prefix}-filelists"),
        )?;
        let file_provides = self.write_optional_payload(
            snapshot,
            repository.file_provides.as_ref(),
            &format!("{prefix}-file-provides"),
        )?;
        let group = self.write_optional_payload(
            snapshot,
            repository.group.as_ref(),
            &format!("{prefix}-group"),
        )?;
        let modules = self.write_optional_payload(
            snapshot,
            repository.modules.as_ref(),
            &format!("{prefix}-modules"),
        )?;
        self.repository_input(
            repository,
            index,
            repomd,
            primary,
            filelists,
            file_provides,
            group,
            modules,
        )
    }

    #[cfg(test)]
    pub(crate) fn write_legacy_repository(
        &mut self,
        repository: &PlanningRepository,
        index: usize,
    ) -> Result<MaterializedRepository, PreparationError> {
        let metadata = repository
            .materialize_native_xml()
            .map_err(|error| PreparationError::Snapshot(error.to_string()))?;
        self.write_materialized_repository(repository, index, &metadata, None, None, None)
    }

    fn write_materialized_repository(
        &mut self,
        repository: &PlanningRepository,
        index: usize,
        metadata: &NativeRepositoryXml,
        file_provides: Option<InputFile>,
        group: Option<InputFile>,
        modules: Option<InputFile>,
    ) -> Result<MaterializedRepository, PreparationError> {
        let prefix = format!("repo-{index}");
        let repomd = self.write_bytes(&format!("{prefix}-repomd"), metadata.repomd())?;
        let primary = self.write_bytes(&format!("{prefix}-primary"), metadata.primary_payload())?;
        let filelists =
            self.write_bytes(&format!("{prefix}-filelists"), metadata.filelists_payload())?;
        let native_primary =
            self.write_bytes(&format!("{prefix}-native-primary.xml"), metadata.primary())?;
        let native_filelists = self.write_bytes(
            &format!("{prefix}-native-filelists.xml"),
            metadata.filelists(),
        )?;
        let input = self.repository_input(
            repository,
            index,
            repomd,
            primary,
            filelists,
            file_provides,
            group,
            modules,
        )?;
        Ok(MaterializedRepository {
            input,
            native_primary,
            native_filelists,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn repository_input(
        &mut self,
        repository: &PlanningRepository,
        index: usize,
        repomd: InputFile,
        primary: InputFile,
        filelists: InputFile,
        file_provides: Option<InputFile>,
        group: Option<InputFile>,
        modules: Option<InputFile>,
    ) -> Result<InputRepository, PreparationError> {
        let prefix = format!("repo-{index}");
        let trust_bytes = repository.trust.to_canonical_json().map_err(domain)?;
        let trust_policy = self.write_bytes(&format!("{prefix}-trust.json"), &trust_bytes)?;
        let keys = repository
            .keys
            .iter()
            .enumerate()
            .map(|(key_index, key)| {
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(&key.certificate_base64)
                    .map_err(|_| PreparationError::Snapshot("planning key is not base64".into()))?;
                Ok(InputKey {
                    file: self.write_bytes(&format!("{prefix}-key-{key_index}"), &bytes)?,
                    bundle_path: key.bundle_path.clone(),
                })
            })
            .collect::<Result<Vec<_>, PreparationError>>()?;
        Ok(InputRepository {
            id: repository.id.clone(),
            priority: i32::try_from(repository.priority)
                .map_err(|error| PreparationError::Snapshot(error.to_string()))?,
            cost: i32::try_from(repository.cost)
                .map_err(|error| PreparationError::Snapshot(error.to_string()))?,
            generation_sha256: repository.generation_sha256.clone(),
            origin: InputOrigin {
                repomd_url: repository.origin.repomd_url.clone(),
                sha256: repository.origin.sha256.clone(),
            },
            repomd,
            primary,
            filelists,
            file_provides,
            group,
            modules,
            trust: InputRepositoryTrust {
                policy: trust_policy,
                sha256: repository
                    .trust
                    .canonical_sha256()
                    .map_err(domain)?
                    .as_str()
                    .into(),
                keys,
            },
        })
    }

    fn write_snapshot_payload(
        &mut self,
        snapshot: &PlanningSnapshot,
        payload: &dnfast_planning::PlanningBytes,
        name: &str,
    ) -> Result<InputFile, PreparationError> {
        let bytes = snapshot
            .materialize_payload(payload)
            .map_err(|error| PreparationError::Snapshot(error.to_string()))?;
        self.write_bytes(name, &bytes)
    }

    fn write_optional_payload(
        &mut self,
        snapshot: &PlanningSnapshot,
        payload: Option<&dnfast_planning::PlanningBytes>,
        name: &str,
    ) -> Result<Option<InputFile>, PreparationError> {
        payload
            .map(|payload| {
                snapshot
                    .materialize_payload(payload)
                    .map_err(|error| PreparationError::Snapshot(error.to_string()))
                    .and_then(|bytes| self.write_bytes(name, &bytes))
            })
            .transpose()
    }

    pub(crate) fn fetch_artifacts(
        &mut self,
        proposal: &dnfast_solver::CanonicalSolverPlan,
        repositories: &[InputRepository],
        transport: &dyn ArtifactTransport,
    ) -> Result<Vec<InputArtifact>, PreparationError> {
        let specs = proposal
            .actions()
            .iter()
            .filter_map(|action| {
                action.artifact.as_ref().map(|record| {
                    let repo_id = action.repo_id.as_deref().ok_or_else(|| {
                        PreparationError::Inputs("planned artifact has no repository".into())
                    })?;
                    let repository = repositories
                        .iter()
                        .find(|repository| repository.id == repo_id)
                        .ok_or_else(|| {
                            PreparationError::Inputs("planned artifact repository is absent".into())
                        })?;
                    let base = repository
                        .origin
                        .repomd_url
                        .strip_suffix("/repodata/repomd.xml")
                        .ok_or_else(|| {
                            PreparationError::Inputs("selected artifact origin is invalid".into())
                        })?;
                    let spec = ArtifactSpec::from_selected_mirror(
                        base,
                        &record.location,
                        Digest::Sha256(record.checksum_sha256.clone()),
                        record.package_size,
                    )
                    .map_err(artifact)?;
                    Ok((action, repository, spec))
                })
            })
            .collect::<Result<Vec<_>, PreparationError>>()?;
        if specs.is_empty() {
            return Ok(Vec::new());
        }
        let request = TransactionRequest::for_specs(
            &specs
                .iter()
                .map(|(_, _, spec)| spec.clone())
                .collect::<Vec<_>>(),
        )
        .map_err(artifact)?;
        let cache = ArtifactCache::new(SYSTEM_CACHE_PATH);
        let mut transaction = cache.begin_transaction(&request).map_err(artifact)?;
        let mut artifacts = Vec::with_capacity(specs.len());
        for (index, (action, repository, spec)) in specs.into_iter().enumerate() {
            let cached = transaction.fetch(&spec, transport).map_err(artifact)?;
            let file = self.copy_file(&format!("artifact-{index}"), cached.file())?;
            artifacts.push(InputArtifact {
                file,
                repo_id: repository.id.clone(),
                generation_sha256: repository.generation_sha256.clone(),
                origin_sha256: repository.origin.sha256.clone(),
                trust_sha256: repository.trust.sha256.clone(),
                name: action.name.clone(),
                epoch: action.target_evra.epoch(),
                version: action.target_evra.version().into(),
                release: action.target_evra.release().into(),
                arch: action.target_evra.arch().as_rpm_arch().into(),
                vendor: action.vendor.clone().ok_or_else(|| {
                    PreparationError::Inputs("planned artifact has no vendor".into())
                })?,
            });
        }
        if transaction.remaining() != 0 {
            return Err(PreparationError::Artifact(
                "artifact transaction did not drain".into(),
            ));
        }
        artifacts.sort_by(|left, right| artifact_key(left).cmp(&artifact_key(right)));
        Ok(artifacts)
    }

    #[cfg(test)]
    pub(crate) fn write_payload(
        &mut self,
        name: &str,
        payload: &dnfast_planning::PlanningBytes,
    ) -> Result<InputFile, PreparationError> {
        self.write_bytes(name, &payload_bytes("payload", payload)?)
    }

    pub(crate) fn write_bytes(
        &mut self,
        name: &str,
        bytes: &[u8],
    ) -> Result<InputFile, PreparationError> {
        let fd = openat(
            &self.directory,
            name,
            OFlags::CREATE | OFlags::EXCL | OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .map_err(errno)?;
        let mut file = File::from(fd);
        file.write_all(bytes).map_err(io)?;
        file.sync_all().map_err(io)?;
        descriptor(name, bytes)
    }

    fn copy_file(&mut self, name: &str, source: &File) -> Result<InputFile, PreparationError> {
        let mut source = source.try_clone().map_err(io)?;
        let fd = openat(
            &self.directory,
            name,
            OFlags::CREATE | OFlags::EXCL | OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .map_err(errno)?;
        let mut output = File::from(fd);
        let mut hasher = Sha256::new();
        let mut size = 0_u64;
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let count = source.read(&mut buffer).map_err(io)?;
            if count == 0 {
                break;
            }
            output.write_all(&buffer[..count]).map_err(io)?;
            hasher.update(&buffer[..count]);
            size = size
                .checked_add(
                    u64::try_from(count)
                        .map_err(|error| PreparationError::Publish(error.to_string()))?,
                )
                .ok_or_else(|| PreparationError::Publish("artifact size overflow".into()))?;
        }
        output.sync_all().map_err(io)?;
        Ok(InputFile {
            name: name.into(),
            sha256: format!("{:x}", hasher.finalize()),
            size,
        })
    }

    pub(crate) fn write_manifest(
        &mut self,
        manifest: &InputManifest,
    ) -> Result<(), PreparationError> {
        let bytes = serde_json::to_vec(manifest)
            .map_err(|error| PreparationError::Publish(error.to_string()))?;
        self.write_bytes("manifest.json", &bytes)?;
        fsync(&self.directory).map_err(errno)
    }

    pub(crate) fn open(&self, input: &InputFile) -> Result<File, PreparationError> {
        let fd = openat2(
            &self.directory,
            &input.name,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
        .map_err(errno)?;
        Ok(File::from(fd))
    }

    pub(crate) fn discard_native_metadata(
        &mut self,
        repositories: &[MaterializedRepository],
    ) -> Result<(), PreparationError> {
        for repository in repositories {
            self.remove(&repository.native_primary)?;
            self.remove(&repository.native_filelists)?;
        }
        Ok(())
    }

    fn remove(&mut self, input: &InputFile) -> Result<(), PreparationError> {
        unlinkat(&self.directory, &input.name, AtFlags::empty()).map_err(errno)
    }

    pub(crate) fn absolute_path(&self, name: &str) -> String {
        format!("{}/{}/{}", self.root_path, self.name, name)
    }
}

#[cfg(test)]
pub(crate) fn payload_bytes(
    role: &'static str,
    payload: &dnfast_planning::PlanningBytes,
) -> Result<Vec<u8>, PreparationError> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(&payload.base64)
        .map_err(|_| {
            PreparationError::Snapshot(format!("{role} planning payload is not base64"))
        })?;
    if format!("{:x}", Sha256::digest(&bytes)) == payload.sha256
        && u64::try_from(bytes.len())
            .map_err(|error| PreparationError::Snapshot(error.to_string()))?
            == payload.size
    {
        Ok(bytes)
    } else {
        Err(PreparationError::Snapshot(format!(
            "{role} planning payload digest differs"
        )))
    }
}

fn nonce() -> Result<String, PreparationError> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|error| PreparationError::Publish(error.to_string()))?;
    Ok(hex::encode(bytes))
}

fn artifact(error: ArtifactError) -> PreparationError {
    PreparationError::Artifact(error.to_string())
}
fn domain(error: dnfast_core::DomainError) -> PreparationError {
    PreparationError::Domain(error.to_string())
}
pub(crate) fn inputs(error: ExecutorError) -> PreparationError {
    PreparationError::Inputs(error.to_string())
}
pub(crate) fn io(error: std::io::Error) -> PreparationError {
    PreparationError::Publish(error.to_string())
}
pub(crate) fn errno(error: Errno) -> PreparationError {
    PreparationError::Publish(error.to_string())
}
