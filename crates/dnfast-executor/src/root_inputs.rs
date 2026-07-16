use std::{
    collections::BTreeSet,
    fs::File,
    io::{Read, Seek},
    os::fd::OwnedFd,
};

use dnfast_core::CanonicalDocument;
use dnfast_solver::CanonicalSolverPlan;
use rustix::fs::{FileType, Mode, OFlags, ResolveFlags, fstat, openat2};
use sha2::{Digest, Sha256};

use crate::{
    ExecutorError, StagedInputs, Staging,
    input_model::{InputArtifact, InputFile, InputKey, InputManifest, InputRepository},
    staging::system_directory,
};

pub(crate) const INPUT_PATH: [&str; 4] = ["var", "lib", "dnfast", "inputs"];
const MAX_INPUT_BYTES: u64 = 16 * 1024 * 1024;
const MAX_KEY_BYTES: u64 = 1024 * 1024;

pub struct RootInputs {
    _directory: OwnedFd,
    manifest: InputManifest,
    owner: u32,
}

impl RootInputs {
    pub fn open(plan: &CanonicalSolverPlan) -> Result<Self, ExecutorError> {
        let digest = plan.digest().map_err(|error| inputs(error.to_string()))?;
        let parent = system_directory(&INPUT_PATH)?;
        Self::open_under(&parent, digest.as_str(), plan, 0)
    }

    fn open_under(
        parent: &OwnedFd,
        digest: &str,
        plan: &CanonicalSolverPlan,
        owner: u32,
    ) -> Result<Self, ExecutorError> {
        let directory = openat2(
            parent,
            digest,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
        .map_err(errno)?;
        validate_directory(&directory, owner)?;
        let bytes = read_manifest(&directory, owner)?;
        let manifest: InputManifest =
            serde_json::from_slice(&bytes).map_err(|error| inputs(error.to_string()))?;
        if serde_json::to_vec(&manifest).map_err(|error| inputs(error.to_string()))? != bytes {
            return Err(inputs("manifest is not canonical JSON"));
        }
        validate_manifest(&directory, &manifest, plan, owner)?;
        Ok(Self {
            _directory: directory,
            manifest,
            owner,
        })
    }

    #[cfg(test)]
    pub(crate) fn open_under_for_test(
        parent: &OwnedFd,
        plan: &CanonicalSolverPlan,
    ) -> Result<Self, ExecutorError> {
        let digest = plan.digest().map_err(|error| inputs(error.to_string()))?;
        Self::open_under(
            parent,
            digest.as_str(),
            plan,
            rustix::process::getuid().as_raw(),
        )
    }

    pub fn stage(&self, staging: &mut Staging) -> Result<StagedInputs, ExecutorError> {
        crate::staged_inputs::stage(&self._directory, &self.manifest, staging)
    }

    pub fn stage_token_bound(&self) -> Result<StagedInputs, ExecutorError> {
        crate::staged_inputs::stage_token_bound(&self._directory, &self.manifest)
    }

    pub fn base_arch(&self) -> Result<dnfast_core::Architecture, ExecutorError> {
        Ok(read_policy(&self._directory, &self.manifest.policy, self.owner)?.base_arch())
    }
}

fn validate_manifest(
    directory: &OwnedFd,
    manifest: &InputManifest,
    plan: &CanonicalSolverPlan,
    owner: u32,
) -> Result<(), ExecutorError> {
    validate_manifest_shape(manifest)?;
    let proposal = plan.proposal();
    let policy = read_policy(directory, &manifest.policy, owner)?;
    if policy
        .canonical_sha256()
        .map_err(|error| inputs(error.to_string()))?
        .as_str()
        != proposal.policy_sha256().as_str()
    {
        return Err(inputs("policy digest mismatch"));
    }
    validate_file(&manifest.policy)?;
    validate_retained_file(directory, &manifest.policy, owner)?;
    validate_repositories(directory, &manifest.repositories, owner)?;
    validate_selected_repository_bindings(&manifest.repositories, proposal)?;
    if metadata_digest(&manifest.repositories, manifest.schema_version >= 4)?
        != manifest.metadata_sha256
        || manifest.metadata_sha256 != proposal.metadata_sha256().as_str()
    {
        return Err(inputs("metadata digest mismatch"));
    }
    if trust_digest(&manifest.repositories)? != manifest.trust_sha256
        || manifest.trust_sha256 != proposal.trust_sha256().as_str()
    {
        return Err(inputs("trust digest mismatch"));
    }
    validate_artifacts(
        directory,
        &manifest.artifacts,
        &manifest.repositories,
        plan,
        owner,
    )?;
    validate_descriptor_uniqueness(manifest)?;
    Ok(())
}

fn validate_selected_repository_bindings(
    repositories: &[InputRepository],
    proposal: &dnfast_core::CanonicalPlan,
) -> Result<(), ExecutorError> {
    let selected = proposal.selected_repositories();
    if repositories.len() != selected.len() {
        return Err(inputs(
            "staged repositories differ from selected proposal repositories",
        ));
    }
    for binding in selected {
        let repository = repositories
            .iter()
            .find(|repository| repository.id == binding.id())
            .ok_or_else(|| inputs("selected proposal repository is not staged"))?;
        if repository.generation_sha256 != binding.generation_sha256().as_str()
            || repository.origin.sha256 != binding.origin_sha256().as_str()
            || repository.trust.sha256 != binding.trust_sha256().as_str()
        {
            return Err(inputs(
                "staged repository generation, origin, or trust differs from proposal binding",
            ));
        }
    }
    Ok(())
}

fn validate_manifest_shape(manifest: &InputManifest) -> Result<(), ExecutorError> {
    if !matches!(manifest.schema_version, 3 | 4) || manifest.repositories.is_empty() {
        return Err(inputs("required input is absent"));
    }
    if manifest.schema_version == 3
        && manifest.repositories.iter().any(|repository| {
            repository.file_provides.is_some()
                || repository.group.is_some()
                || repository.modules.is_some()
        })
    {
        return Err(inputs("version three input contains extended metadata"));
    }
    validate_repository_order(&manifest.repositories)?;
    if manifest
        .artifacts
        .windows(2)
        .any(|pair| artifact_key(&pair[0]) >= artifact_key(&pair[1]))
    {
        return Err(inputs("artifact entries are not strictly sorted"));
    }
    Ok(())
}

fn validate_repositories(
    directory: &OwnedFd,
    repositories: &[InputRepository],
    owner: u32,
) -> Result<(), ExecutorError> {
    validate_repository_order(repositories)?;
    for repository in repositories {
        validate_repository_id(&repository.id)?;
        validate_digest(&repository.generation_sha256)?;
        if repository.generation_sha256 != repository.repomd.sha256 {
            return Err(inputs("repository generation differs from repomd"));
        }
        validate_origin(&repository.origin.repomd_url, &repository.origin.sha256)?;
        for file in [
            &repository.repomd,
            &repository.primary,
            &repository.filelists,
            &repository.trust.policy,
        ] {
            validate_file(file)?;
            validate_retained_file(directory, file, owner)?;
        }
        for file in repository
            .file_provides
            .iter()
            .chain(repository.group.iter())
            .chain(repository.modules.iter())
        {
            validate_file(file)?;
            validate_retained_file(directory, file, owner)?;
        }
        let trust = read_trust(directory, &repository.trust.policy, owner)?;
        let trust_sha256 = trust
            .canonical_sha256()
            .map_err(|error| inputs(error.to_string()))?;
        if trust.repo_id() != repository.id
            || trust_sha256.as_str() != repository.trust.sha256
            || repository.trust.policy.sha256 != repository.trust.sha256
        {
            return Err(inputs(
                "repository trust policy differs from repository binding",
            ));
        }
        validate_key_bundle(directory, &repository.trust.keys, &trust, owner)?;
    }
    Ok(())
}

fn validate_repository_order(repositories: &[InputRepository]) -> Result<(), ExecutorError> {
    if repositories.windows(2).any(|pair| pair[0].id >= pair[1].id) {
        return Err(inputs("repository entries are not strictly sorted"));
    }
    Ok(())
}

fn validate_artifacts(
    directory: &OwnedFd,
    artifacts: &[InputArtifact],
    repositories: &[InputRepository],
    plan: &CanonicalSolverPlan,
    owner: u32,
) -> Result<(), ExecutorError> {
    for artifact in artifacts {
        validate_file(&artifact.file)?;
        validate_retained_file(directory, &artifact.file, owner)?;
        let repository = repositories
            .iter()
            .find(|repository| repository.id == artifact.repo_id)
            .ok_or_else(|| inputs("artifact repository is not staged"))?;
        validate_artifact_binding(artifact, repository)?;
        validate_artifact(artifact, plan)?;
    }
    for action in plan
        .actions()
        .iter()
        .filter(|action| action.artifact.is_some())
    {
        let count = artifacts
            .iter()
            .filter(|artifact| validate_artifact_descriptor(artifact, action).is_ok())
            .count();
        if count != 1 {
            return Err(inputs("planned artifact is absent or ambiguous"));
        }
    }
    Ok(())
}

fn artifact_key(artifact: &InputArtifact) -> (&str, &str, u32, &str, &str, &str) {
    (
        &artifact.repo_id,
        &artifact.name,
        artifact.epoch,
        &artifact.version,
        &artifact.release,
        &artifact.file.sha256,
    )
}

fn validate_artifact_binding(
    artifact: &InputArtifact,
    repository: &InputRepository,
) -> Result<(), ExecutorError> {
    if artifact.generation_sha256 != repository.generation_sha256
        || artifact.origin_sha256 != repository.origin.sha256
        || artifact.trust_sha256 != repository.trust.sha256
    {
        return Err(inputs(
            "artifact trust, origin, or generation differs from repository binding",
        ));
    }
    Ok(())
}

fn validate_artifact(
    artifact: &InputArtifact,
    plan: &CanonicalSolverPlan,
) -> Result<(), ExecutorError> {
    let found = plan
        .actions()
        .iter()
        .any(|action| validate_artifact_descriptor(artifact, action).is_ok());
    if found {
        Ok(())
    } else {
        Err(inputs("artifact does not match proposal"))
    }
}

fn validate_artifact_descriptor(
    artifact: &InputArtifact,
    action: &dnfast_solver::ExplainedAction,
) -> Result<(), ExecutorError> {
    let record = action
        .artifact
        .as_ref()
        .ok_or_else(|| inputs("action has no artifact"))?;
    let action_repo = action
        .repo_id
        .as_deref()
        .ok_or_else(|| inputs("action has no repository"))?;
    let action_vendor = action
        .vendor
        .as_deref()
        .ok_or_else(|| inputs("action has no candidate vendor"))?;
    let matches = artifact_matches(
        artifact,
        &action.name,
        &action.target_evra,
        action_repo,
        action_vendor,
        record,
    );
    if matches {
        Ok(())
    } else {
        Err(inputs(
            "artifact repo or metadata provenance differs from proposal",
        ))
    }
}

fn artifact_matches(
    artifact: &InputArtifact,
    action_name: &str,
    action_evra: &dnfast_core::Evra,
    action_repo: &str,
    action_vendor: &str,
    record: &dnfast_solver::ArtifactRecord,
) -> bool {
    record.checksum_sha256 == artifact.file.sha256
        && record.package_size == artifact.file.size
        && action_name == artifact.name
        && action_evra.epoch() == artifact.epoch
        && action_evra.version() == artifact.version
        && action_evra.release() == artifact.release
        && action_repo == artifact.repo_id
        && action_vendor == artifact.vendor
        && artifact.arch == action_evra.arch().as_rpm_arch()
}

fn read_policy(
    directory: &OwnedFd,
    file: &InputFile,
    owner: u32,
) -> Result<dnfast_core::SolverPolicy, ExecutorError> {
    let bytes = read_file(directory, file, MAX_INPUT_BYTES, owner)?;
    dnfast_core::SolverPolicy::from_canonical_json(&bytes)
        .map_err(|error| inputs(error.to_string()))
}

fn read_trust(
    directory: &OwnedFd,
    file: &InputFile,
    owner: u32,
) -> Result<dnfast_core::RepoTrustPolicy, ExecutorError> {
    let bytes = read_file(directory, file, MAX_INPUT_BYTES, owner)?;
    dnfast_core::RepoTrustPolicy::from_canonical_json(&bytes)
        .map_err(|error| inputs(error.to_string()))
}

fn validate_descriptor_uniqueness(manifest: &InputManifest) -> Result<(), ExecutorError> {
    let names = std::iter::once(&manifest.policy)
        .chain(repository_files(&manifest.repositories))
        .chain(repository_trust_files(&manifest.repositories))
        .chain(manifest.artifacts.iter().map(|artifact| &artifact.file))
        .map(|file| &file.name)
        .collect::<BTreeSet<_>>();
    let expected = 1_usize
        .checked_add(repository_files(&manifest.repositories).count())
        .and_then(|count| count.checked_add(manifest.repositories.len()))
        .and_then(|count| {
            count.checked_add(
                manifest
                    .repositories
                    .iter()
                    .map(|repository| repository.trust.keys.len())
                    .sum::<usize>(),
            )
        })
        .and_then(|count| count.checked_add(manifest.artifacts.len()))
        .ok_or_else(|| inputs("input count overflow"))?;
    if names.len() != expected {
        return Err(inputs("duplicate input descriptor"));
    }
    Ok(())
}

fn read_file(
    directory: &OwnedFd,
    file: &InputFile,
    limit: u64,
    owner: u32,
) -> Result<Vec<u8>, ExecutorError> {
    validate_file(file)?;
    let fd = openat2(
        directory,
        &file.name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(errno)?;
    validate_metadata(&fd, file, limit, owner)?;
    let mut bytes = Vec::new();
    File::from(fd)
        .read_to_end(&mut bytes)
        .map_err(|error| inputs(error.to_string()))?;
    if u64::try_from(bytes.len()).map_err(|error| inputs(error.to_string()))? != file.size {
        return Err(inputs("input size mismatch"));
    }
    if format!("{:x}", Sha256::digest(&bytes)) != file.sha256 {
        return Err(inputs("input digest mismatch"));
    }
    Ok(bytes)
}

fn read_manifest(directory: &OwnedFd, owner: u32) -> Result<Vec<u8>, ExecutorError> {
    let fd = openat2(
        directory,
        "manifest.json",
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(errno)?;
    let metadata = fstat(&fd).map_err(errno)?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
        || metadata.st_uid != owner
        || metadata.st_nlink != 1
        || metadata.st_mode & 0o022 != 0
        || metadata.st_size < 0
        || u64::try_from(metadata.st_size).map_err(|error| inputs(error.to_string()))?
            > MAX_INPUT_BYTES
    {
        return Err(inputs("unsafe input manifest"));
    }
    let mut bytes = Vec::new();
    File::from(fd)
        .read_to_end(&mut bytes)
        .map_err(|error| inputs(error.to_string()))?;
    Ok(bytes)
}

fn validate_retained_file(
    directory: &OwnedFd,
    file: &InputFile,
    owner: u32,
) -> Result<(), ExecutorError> {
    let mut file_handle = open_retained_as(directory, file, owner)?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file_handle
            .read(&mut buffer)
            .map_err(|error| inputs(error.to_string()))?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    if format!("{:x}", digest.finalize()) == file.sha256 {
        Ok(())
    } else {
        Err(inputs("retained input digest mismatch"))
    }
}

pub(crate) fn open_retained(directory: &OwnedFd, file: &InputFile) -> Result<File, ExecutorError> {
    open_retained_as(directory, file, 0)
}

fn open_retained_as(
    directory: &OwnedFd,
    file: &InputFile,
    owner: u32,
) -> Result<File, ExecutorError> {
    let fd = openat2(
        directory,
        &file.name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(errno)?;
    validate_metadata(&fd, file, u64::MAX, owner)?;
    let mut result = File::from(fd);
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = result
            .read(&mut buffer)
            .map_err(|error| inputs(error.to_string()))?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    if format!("{:x}", digest.finalize()) != file.sha256 {
        return Err(inputs("retained input digest mismatch"));
    }
    result.rewind().map_err(|error| inputs(error.to_string()))?;
    Ok(result)
}

fn validate_metadata(
    fd: &OwnedFd,
    file: &InputFile,
    limit: u64,
    owner: u32,
) -> Result<(), ExecutorError> {
    let metadata = fstat(fd).map_err(errno)?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
        || metadata.st_uid != owner
        || metadata.st_nlink != 1
        || metadata.st_mode & 0o022 != 0
        || metadata.st_size < 0
        || u64::try_from(metadata.st_size).map_err(|error| inputs(error.to_string()))? != file.size
        || file.size > limit
    {
        return Err(inputs("unsafe input file"));
    }
    Ok(())
}

fn validate_directory(fd: &OwnedFd, owner: u32) -> Result<(), ExecutorError> {
    let metadata = fstat(fd).map_err(errno)?;
    if FileType::from_raw_mode(metadata.st_mode) == FileType::Directory
        && metadata.st_uid == owner
        && metadata.st_mode & 0o022 == 0
    {
        Ok(())
    } else {
        Err(inputs("unsafe input directory"))
    }
}

fn validate_file(file: &InputFile) -> Result<(), ExecutorError> {
    if file.name.is_empty()
        || file.name.contains('/')
        || file.name.contains('\\')
        || file.name == "."
        || file.name == ".."
    {
        return Err(inputs("invalid input descriptor"));
    }
    validate_digest(&file.sha256)
}

fn validate_digest(value: &str) -> Result<(), ExecutorError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        Ok(())
    } else {
        Err(inputs("invalid SHA-256 digest"))
    }
}

fn validate_origin(repomd_url: &str, sha256: &str) -> Result<(), ExecutorError> {
    validate_digest(sha256)?;
    dnfast_cache::SelectedOrigin::parse(repomd_url).map_err(|error| inputs(error.to_string()))?;
    if format!("{:x}", Sha256::digest(repomd_url.as_bytes())) == sha256 {
        Ok(())
    } else {
        Err(inputs("selected origin digest mismatch"))
    }
}

fn validate_key_bundle(
    directory: &OwnedFd,
    keys: &[InputKey],
    trust: &dnfast_core::RepoTrustPolicy,
    owner: u32,
) -> Result<(), ExecutorError> {
    if keys.is_empty()
        || keys
            .windows(2)
            .any(|pair| pair[0].bundle_path >= pair[1].bundle_path)
    {
        return Err(inputs("key bundle is not strictly sorted"));
    }
    let mut digest = Sha256::new();
    digest.update(b"dnfast-key-bundle-v1");
    for key in keys {
        validate_key_path(trust.repo_id(), &key.bundle_path)?;
        validate_file(&key.file)?;
        validate_retained_file(directory, &key.file, owner)?;
        let bytes = read_file(directory, &key.file, MAX_KEY_BYTES, owner)?;
        frame(&mut digest, &key.bundle_path, &bytes)?;
    }
    if format!("{:x}", digest.finalize()) == trust.key_bundle_sha256().as_str() {
        Ok(())
    } else {
        Err(inputs("key bundle digest mismatch"))
    }
}

fn validate_key_path(repository: &str, path: &str) -> Result<(), ExecutorError> {
    dnfast_repo::validate_gpgkey_bundle_path(repository, path)
        .map_err(|_| inputs("key bundle path differs from trust repository"))
}

#[cfg(test)]
mod key_path_tests {
    use super::validate_key_path;

    #[test]
    fn accepts_only_repository_local_or_fixed_system_gpg_key_paths() {
        assert!(validate_key_path("fedora", "/etc/dnfast/keys/fedora/key.asc").is_ok());
        assert!(
            validate_key_path("fedora", "/etc/pki/rpm-gpg/RPM-GPG-KEY-fedora-44-aarch64").is_ok()
        );
        assert!(validate_key_path("fedora", "/etc/passwd").is_err());
        assert!(validate_key_path("fedora", "/etc/dnfast/keys/other/key.asc").is_err());
        assert!(validate_key_path("fedora", "file:///etc/pki/rpm-gpg/key").is_err());
    }
}

fn validate_repository_id(value: &str) -> Result<(), ExecutorError> {
    if value.is_empty()
        || value
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || b"_.-".contains(&byte)))
    {
        Err(inputs("invalid repository descriptor"))
    } else {
        Ok(())
    }
}

fn repository_files(repositories: &[InputRepository]) -> impl Iterator<Item = &InputFile> {
    repositories.iter().flat_map(|repository| {
        std::iter::once(&repository.repomd)
            .chain(std::iter::once(&repository.primary))
            .chain(std::iter::once(&repository.filelists))
            .chain(repository.file_provides.iter())
            .chain(repository.group.iter())
            .chain(repository.modules.iter())
    })
}

fn repository_trust_files(repositories: &[InputRepository]) -> impl Iterator<Item = &InputFile> {
    repositories.iter().flat_map(|repository| {
        std::iter::once(&repository.trust.policy)
            .chain(repository.trust.keys.iter().map(|key| &key.file))
    })
}

fn metadata_digest(
    repositories: &[InputRepository],
    extended: bool,
) -> Result<String, ExecutorError> {
    let mut digest = Sha256::new();
    digest.update(if extended {
        b"dnfast-root-metadata-v4".as_slice()
    } else {
        b"dnfast-root-metadata-v3".as_slice()
    });
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
        frame(
            &mut digest,
            &repository.trust.sha256,
            repository.trust.sha256.as_bytes(),
        )?;
        for file in [
            &repository.repomd,
            &repository.primary,
            &repository.filelists,
        ] {
            frame(&mut digest, &file.sha256, file.sha256.as_bytes())?;
            digest.update(file.size.to_be_bytes());
        }
        if extended {
            for (role, file) in [
                ("file-provides", repository.file_provides.as_ref()),
                ("group", repository.group.as_ref()),
                ("modules", repository.modules.as_ref()),
            ] {
                frame(&mut digest, role, role.as_bytes())?;
                if let Some(file) = file {
                    frame(&mut digest, &file.sha256, file.sha256.as_bytes())?;
                    digest.update(file.size.to_be_bytes());
                }
            }
        }
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn trust_digest(repositories: &[InputRepository]) -> Result<String, ExecutorError> {
    let mut digest = Sha256::new();
    digest.update(b"dnfast-root-trust-v3");
    for repository in repositories {
        frame(&mut digest, &repository.id, repository.id.as_bytes())?;
        frame(
            &mut digest,
            &repository.trust.sha256,
            repository.trust.sha256.as_bytes(),
        )?;
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn frame(digest: &mut Sha256, name: &str, bytes: &[u8]) -> Result<(), ExecutorError> {
    digest.update(
        u64::try_from(name.len())
            .map_err(|error| inputs(error.to_string()))?
            .to_be_bytes(),
    );
    digest.update(name.as_bytes());
    digest.update(
        u64::try_from(bytes.len())
            .map_err(|error| inputs(error.to_string()))?
            .to_be_bytes(),
    );
    digest.update(bytes);
    Ok(())
}

fn inputs(message: impl Into<String>) -> ExecutorError {
    ExecutorError::Inputs(message.into())
}
fn errno(error: rustix::io::Errno) -> ExecutorError {
    inputs(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::{
        InputArtifact, InputFile, InputManifest, artifact_matches, validate_artifact_binding,
        validate_file, validate_key_path, validate_manifest_shape, validate_origin,
        validate_repository_order,
    };
    use crate::input_model::{InputOrigin, InputRepository, InputRepositoryTrust};
    use dnfast_core::{
        Architecture, CanonicalPlan, Evra, PackageAction, PackageReason, PlanIntegrity,
        RepositoryBinding, Sha256Digest, TransactionIntent,
    };
    use dnfast_solver::ArtifactRecord;

    #[test]
    fn descriptor_without_digest_is_rejected() {
        // Given: a root-input descriptor without a content binding.
        let file = InputFile {
            name: "metadata.xml".into(),
            sha256: String::new(),
            size: 1,
        };

        // When: the executor validates the descriptor boundary.
        let result = validate_file(&file);

        // Then: unbound bytes cannot enter the privileged staging path.
        assert!(result.is_err());
    }

    #[test]
    fn key_path_outside_declared_repository_is_rejected() {
        // Given: a manifest key descriptor with a path from another repository.
        let path = "/etc/dnfast/keys/other/allowed.asc";

        // When: the executor binds the key path to the policy repository id.
        let result = validate_key_path("fedora", path);

        // Then: the key cannot be substituted across repository trust domains.
        assert!(result.is_err());
    }

    #[test]
    fn artifact_from_another_manifest_repository_is_rejected() {
        // Given: a plan selected `main`, while a second staged repository claims its RPM.
        let artifact = InputArtifact {
            file: InputFile {
                name: "rpm".into(),
                sha256: "a".repeat(64),
                size: 1,
            },
            generation_sha256: "a".repeat(64),
            origin_sha256: "b".repeat(64),
            trust_sha256: "c".repeat(64),
            name: "dnfast-app".into(),
            epoch: 0,
            version: "1.0".into(),
            release: "1".into(),
            arch: "noarch".into(),
            repo_id: "other".into(),
            vendor: "Dnfast".into(),
        };
        let record = ArtifactRecord {
            checksum_sha256: "a".repeat(64),
            location: "dnfast-app.rpm".into(),
            package_size: 1,
        };

        // When: root staging binds an artifact descriptor to the selected action.
        let result = artifact_matches(
            &artifact,
            "dnfast-app",
            &Evra::new(0, "1.0", "1", Architecture::Noarch),
            "main",
            "Dnfast",
            &record,
        );

        // Then: matching NEVRA and digest alone cannot cross repository domains.
        assert!(!result);
    }

    #[test]
    fn x86_64_artifact_binding_requires_exact_architecture() {
        let artifact = InputArtifact {
            file: InputFile {
                name: "rpm".into(),
                sha256: "a".repeat(64),
                size: 1,
            },
            generation_sha256: "a".repeat(64),
            origin_sha256: "b".repeat(64),
            trust_sha256: "c".repeat(64),
            name: "dnfast-app".into(),
            epoch: 0,
            version: "1.0".into(),
            release: "1".into(),
            arch: "x86_64".into(),
            repo_id: "main".into(),
            vendor: "Dnfast".into(),
        };
        let record = ArtifactRecord {
            checksum_sha256: "a".repeat(64),
            location: "dnfast-app.rpm".into(),
            package_size: 1,
        };
        assert!(artifact_matches(
            &artifact,
            "dnfast-app",
            &Evra::new(0, "1.0", "1", Architecture::X86_64),
            "main",
            "Dnfast",
            &record
        ));
        assert!(!artifact_matches(
            &artifact,
            "dnfast-app",
            &Evra::new(0, "1.0", "1", Architecture::Aarch64),
            "main",
            "Dnfast",
            &record
        ));
    }

    #[test]
    fn repository_entries_must_be_strictly_sorted_for_per_repository_trust_binding() {
        // Given: two otherwise distinct repository trust domains in reverse canonical order.
        let repository = |id: &str| InputRepository {
            id: id.into(),
            priority: 99,
            cost: 1000,
            generation_sha256: "a".repeat(64),
            origin: InputOrigin {
                repomd_url: format!("https://{id}.example/repo/repodata/repomd.xml"),
                sha256: "b".repeat(64),
            },
            repomd: InputFile {
                name: format!("{id}-repomd"),
                sha256: "a".repeat(64),
                size: 1,
            },
            primary: InputFile {
                name: format!("{id}-primary"),
                sha256: "c".repeat(64),
                size: 1,
            },
            filelists: InputFile {
                name: format!("{id}-filelists"),
                sha256: "d".repeat(64),
                size: 1,
            },
            file_provides: None,
            group: None,
            modules: None,
            trust: InputRepositoryTrust {
                policy: InputFile {
                    name: format!("{id}-trust"),
                    sha256: "e".repeat(64),
                    size: 1,
                },
                sha256: "e".repeat(64),
                keys: Vec::new(),
            },
        };
        let repositories = vec![repository("updates"), repository("fedora")];

        // When: root validates the canonical order before reading any trust material.
        let result = validate_repository_order(&repositories);

        // Then: reordered repository records cannot change which keyring proves an artifact.
        assert!(result.is_err());
    }

    #[test]
    fn manifest_v2_unknown_and_duplicate_schema_fields_are_rejected() {
        // Given: a retired v2 document and ambiguous JSON object fields at the untrusted manifest boundary.
        let repository = InputRepository {
            id: "fedora".into(),
            priority: 99,
            cost: 1000,
            generation_sha256: "a".repeat(64),
            origin: InputOrigin {
                repomd_url: "https://fedora.example/repo/repodata/repomd.xml".into(),
                sha256: "b".repeat(64),
            },
            repomd: InputFile {
                name: "fedora-repomd".into(),
                sha256: "a".repeat(64),
                size: 1,
            },
            primary: InputFile {
                name: "fedora-primary".into(),
                sha256: "c".repeat(64),
                size: 1,
            },
            filelists: InputFile {
                name: "fedora-filelists".into(),
                sha256: "d".repeat(64),
                size: 1,
            },
            file_provides: None,
            group: None,
            modules: None,
            trust: InputRepositoryTrust {
                policy: InputFile {
                    name: "fedora-trust".into(),
                    sha256: "e".repeat(64),
                    size: 1,
                },
                sha256: "e".repeat(64),
                keys: Vec::new(),
            },
        };
        let v2 = InputManifest {
            schema_version: 2,
            policy: InputFile {
                name: "policy".into(),
                sha256: "f".repeat(64),
                size: 1,
            },
            metadata_sha256: "a".repeat(64),
            trust_sha256: "b".repeat(64),
            repositories: vec![repository],
            artifacts: Vec::new(),
        };

        // When: root validates the parsed version and serde sees unknown or duplicate keys.
        let result = validate_manifest_shape(&v2);
        let unknown =
            serde_json::from_slice::<InputManifest>(br#"{"schema_version":3,"surprise":true}"#);
        let duplicate =
            serde_json::from_slice::<InputManifest>(br#"{"schema_version":3,"schema_version":3}"#);

        // Then: v2 and ambiguous v3-shaped documents cannot reach retained-FD validation.
        assert!(result.is_err());
        assert!(unknown.is_err());
        assert!(duplicate.is_err());
    }

    #[test]
    fn mutated_origin_and_cross_repository_trust_binding_are_rejected() {
        // Given: one repository's typed origin and another repository's artifact trust coordinates.
        let repository = InputRepository {
            id: "fedora".into(),
            priority: 99,
            cost: 1000,
            generation_sha256: "a".repeat(64),
            origin: InputOrigin {
                repomd_url: "https://fedora.example/repo/repodata/repomd.xml".into(),
                sha256: "b".repeat(64),
            },
            repomd: InputFile {
                name: "fedora-repomd".into(),
                sha256: "a".repeat(64),
                size: 1,
            },
            primary: InputFile {
                name: "fedora-primary".into(),
                sha256: "c".repeat(64),
                size: 1,
            },
            filelists: InputFile {
                name: "fedora-filelists".into(),
                sha256: "d".repeat(64),
                size: 1,
            },
            file_provides: None,
            group: None,
            modules: None,
            trust: InputRepositoryTrust {
                policy: InputFile {
                    name: "fedora-trust".into(),
                    sha256: "e".repeat(64),
                    size: 1,
                },
                sha256: "e".repeat(64),
                keys: Vec::new(),
            },
        };
        let artifact = InputArtifact {
            file: InputFile {
                name: "rpm".into(),
                sha256: "f".repeat(64),
                size: 1,
            },
            repo_id: "fedora".into(),
            generation_sha256: "a".repeat(64),
            origin_sha256: "b".repeat(64),
            trust_sha256: "0".repeat(64),
            name: "dnfast-app".into(),
            epoch: 0,
            version: "1.0".into(),
            release: "1".into(),
            arch: "noarch".into(),
            vendor: "Dnfast".into(),
        };

        // When: root checks the literal origin digest and artifact repository coordinates.
        let origin = validate_origin(&repository.origin.repomd_url, &repository.origin.sha256);
        let binding = validate_artifact_binding(&artifact, &repository);

        // Then: a substituted URL and another trust policy cannot authenticate the artifact.
        assert!(origin.is_err());
        assert!(binding.is_err());
    }

    #[test]
    fn staged_repository_coordinates_must_equal_the_canonical_selected_binding() {
        // Given: a proposal pinning `fedora` to one exact generation, origin, and trust digest.
        let digest = |value: char| value.to_string().repeat(64);
        let binding = RepositoryBinding::new(
            "fedora",
            Sha256Digest::parse(digest('a'), "generation").unwrap(),
            Sha256Digest::parse(digest('b'), "origin").unwrap(),
            Sha256Digest::parse(digest('c'), "trust").unwrap(),
        )
        .unwrap();
        let integrity = PlanIntegrity::new(
            [
                &digest('d'),
                &digest('e'),
                &digest('f'),
                &digest('0'),
                &digest('1'),
            ],
            vec![binding],
        )
        .unwrap();
        let plan = CanonicalPlan::new(
            TransactionIntent::from_package_names(dnfast_core::Action::Install, &["app"]).unwrap(),
            integrity,
            10,
            vec![PackageAction::install_with_vendor(
                "app",
                Evra::new(0, "1", "1", Architecture::Noarch),
                "fedora",
                "Dnfast",
                PackageReason::User,
            )],
        )
        .unwrap();
        let repository = |trust: &str| InputRepository {
            id: "fedora".into(),
            priority: 99,
            cost: 1000,
            generation_sha256: digest('a'),
            origin: InputOrigin {
                repomd_url: "https://fedora.example/repo/repodata/repomd.xml".into(),
                sha256: digest('b'),
            },
            repomd: InputFile {
                name: "fedora-repomd".into(),
                sha256: digest('a'),
                size: 1,
            },
            primary: InputFile {
                name: "fedora-primary".into(),
                sha256: digest('c'),
                size: 1,
            },
            filelists: InputFile {
                name: "fedora-filelists".into(),
                sha256: digest('d'),
                size: 1,
            },
            file_provides: None,
            group: None,
            modules: None,
            trust: InputRepositoryTrust {
                policy: InputFile {
                    name: "fedora-trust".into(),
                    sha256: trust.into(),
                    size: 1,
                },
                sha256: trust.into(),
                keys: Vec::new(),
            },
        };

        // When: root staging compares matching and tampered repository inputs with that proposal.
        let matching =
            super::validate_selected_repository_bindings(&[repository(&digest('c'))], &plan);
        let tampered =
            super::validate_selected_repository_bindings(&[repository(&digest('e'))], &plan);

        // Then: only exact selected coordinates can proceed to retained-FD staging.
        assert!(matching.is_ok());
        assert!(tampered.is_err());
    }
}
