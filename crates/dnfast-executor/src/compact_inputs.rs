use std::{
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    os::fd::OwnedFd,
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use dnfast_core::{CanonicalDocument, InstalledInventory, RepoTrustPolicy, SolverPolicy};
use dnfast_native::{ExpectedPackage, Repository, VerifiedStagedKey};
use dnfast_planning::PlanningSnapshot;
use dnfast_solver::CanonicalSolverPlan;
use rustix::fs::{
    FileType, MemfdFlags, Mode, SealFlags, fchmod, fcntl_add_seals, fcntl_get_seals, fstat,
    memfd_create,
};
use serde::{Deserialize, Serialize};

use crate::{ExecutorError, StagedArtifact, StagedInputs, staged_inputs::StagedRepository};

const COMPACT_SCHEMA_VERSION: u32 = 1;
const MAX_COMPACT_BYTES: u64 = 16 * 1024 * 1024;
const MAX_COMPACT_ARTIFACTS: usize = 1024;
const REQUIRED_SEALS: SealFlags = SealFlags::SEAL
    .union(SealFlags::SHRINK)
    .union(SealFlags::GROW)
    .union(SealFlags::WRITE);

pub struct CompactExecution {
    plan: OwnedFd,
    manifest: OwnedFd,
    artifacts: Vec<OwnedFd>,
}

impl CompactExecution {
    pub(crate) fn create(
        plan: &CanonicalSolverPlan,
        planning_snapshot_sha256: &str,
        inventory: InstalledInventory,
        rpmdb_cookie: String,
        staged: StagedInputs,
    ) -> Result<Self, ExecutorError> {
        if !staged.candidates.is_empty() || !staged.metadata.is_empty() {
            return Err(inputs(
                "compact execution contains duplicated solver evidence",
            ));
        }
        let repositories = staged
            .repositories
            .into_iter()
            .map(|repository| CompactRepository {
                id: repository.repository.id,
                priority: repository.repository.priority,
                cost: repository.repository.cost,
                trust: repository.trust,
                keys: repository
                    .keys
                    .into_iter()
                    .map(|key| CompactKey {
                        bundle_path: key.bundle_path,
                        certificate_base64: STANDARD.encode(key.certificate),
                    })
                    .collect(),
                generation_sha256: repository.generation_sha256,
                origin_sha256: repository.origin_sha256,
                trust_sha256: repository.trust_sha256,
            })
            .collect::<Vec<_>>();
        if staged.artifacts.len() > MAX_COMPACT_ARTIFACTS {
            return Err(inputs("compact execution has too many artifacts"));
        }
        let mut artifact_fds = Vec::with_capacity(staged.artifacts.len());
        let artifacts = staged
            .artifacts
            .into_iter()
            .enumerate()
            .map(|(index, artifact)| {
                artifact_fds.push(OwnedFd::from(artifact.file));
                CompactArtifact {
                    fd_index: u32::try_from(index).expect("artifact count is bounded"),
                    name: artifact.expected.name,
                    epoch: artifact.expected.epoch,
                    version: artifact.expected.version,
                    release: artifact.expected.release,
                    arch: artifact.expected.arch,
                    vendor: artifact.expected.vendor,
                    sha256: artifact.sha256,
                    size: artifact.size,
                    repo_id: artifact.repo_id,
                    generation_sha256: artifact.generation_sha256,
                    origin_sha256: artifact.origin_sha256,
                    trust_sha256: artifact.trust_sha256,
                }
            })
            .collect();
        let manifest = CompactManifest {
            schema_version: COMPACT_SCHEMA_VERSION,
            plan_digest: plan.digest().map_err(plan_error)?.as_str().into(),
            planning_snapshot_sha256: planning_snapshot_sha256.into(),
            rpmdb_cookie,
            inventory,
            policy: staged.policy,
            repositories,
            artifacts,
        };
        manifest.validate_static(plan, artifact_fds.len())?;
        let plan_bytes = plan.canonical_json().map_err(plan_error)?;
        let manifest_bytes = serde_json::to_vec(&manifest).map_err(json)?;
        Ok(Self {
            plan: sealed_memfd("dnfast-plan", &plan_bytes, crate::MAX_PLAN_BYTES)?,
            manifest: sealed_memfd("dnfast-compact-inputs", &manifest_bytes, MAX_COMPACT_BYTES)?,
            artifacts: artifact_fds,
        })
    }

    pub fn into_parts(self) -> (OwnedFd, OwnedFd, Vec<OwnedFd>) {
        (self.plan, self.manifest, self.artifacts)
    }
}

pub struct CompactTransactionInputs {
    staged: StagedInputs,
    inventory: InstalledInventory,
    rpmdb_cookie: String,
    planning_snapshot_sha256: String,
}

impl CompactTransactionInputs {
    pub fn read(
        proposal: &CanonicalSolverPlan,
        artifact_count: usize,
    ) -> Result<Self, ExecutorError> {
        if artifact_count > MAX_COMPACT_ARTIFACTS {
            return Err(inputs("compact artifact count exceeds limit"));
        }
        let descriptor = dnfast_native_sys::take_inherited_compact_fd()
            .map_err(|error| ExecutorError::Read(error.to_string()))?;
        let bytes = read_sealed_memfd(descriptor, MAX_COMPACT_BYTES)?;
        let manifest: CompactManifest = serde_json::from_slice(&bytes).map_err(json)?;
        if serde_json::to_vec(&manifest).map_err(json)? != bytes {
            return Err(inputs("compact manifest is not canonical"));
        }
        manifest.validate_static(proposal, artifact_count)?;
        manifest.revalidate_runtime(proposal)?;
        let artifact_fds = (0..artifact_count)
            .map(|index| {
                dnfast_native_sys::take_inherited_artifact_fd(index)
                    .map(File::from)
                    .map_err(|error| ExecutorError::Read(error.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        manifest.into_transaction(artifact_fds)
    }

    pub fn revalidate_runtime(&self, proposal: &CanonicalSolverPlan) -> Result<(), ExecutorError> {
        revalidate_snapshot_digest(proposal, &self.planning_snapshot_sha256).map(|_| ())
    }

    pub fn staged_mut(&mut self) -> &mut StagedInputs {
        &mut self.staged
    }

    pub fn inventory(&self) -> &InstalledInventory {
        &self.inventory
    }

    pub fn rpmdb_cookie(&self) -> &str {
        &self.rpmdb_cookie
    }

    pub fn into_parts(self) -> (StagedInputs, InstalledInventory, String) {
        (self.staged, self.inventory, self.rpmdb_cookie)
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CompactManifest {
    schema_version: u32,
    plan_digest: String,
    planning_snapshot_sha256: String,
    rpmdb_cookie: String,
    inventory: InstalledInventory,
    policy: SolverPolicy,
    repositories: Vec<CompactRepository>,
    artifacts: Vec<CompactArtifact>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CompactRepository {
    id: String,
    priority: i32,
    cost: i32,
    trust: RepoTrustPolicy,
    keys: Vec<CompactKey>,
    generation_sha256: String,
    origin_sha256: String,
    trust_sha256: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CompactKey {
    bundle_path: String,
    certificate_base64: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CompactArtifact {
    fd_index: u32,
    name: String,
    epoch: u64,
    version: String,
    release: String,
    arch: String,
    vendor: String,
    sha256: String,
    size: u64,
    repo_id: String,
    generation_sha256: String,
    origin_sha256: String,
    trust_sha256: String,
}

impl CompactManifest {
    fn validate_static(
        &self,
        proposal: &CanonicalSolverPlan,
        artifact_count: usize,
    ) -> Result<(), ExecutorError> {
        if self.schema_version != COMPACT_SCHEMA_VERSION
            || self.rpmdb_cookie.is_empty()
            || self.rpmdb_cookie.len() > 4096
            || self.artifacts.len() != artifact_count
            || self.plan_digest != proposal.digest().map_err(plan_error)?.as_str()
            || self.planning_snapshot_sha256
                != proposal
                    .proposal()
                    .integrity()
                    .planning_snapshot_sha256()
                    .as_str()
            || self
                .inventory
                .canonical_sha256()
                .map_err(plan_error)?
                .as_str()
                != proposal.proposal().inventory_sha256().as_str()
            || self.policy.canonical_sha256().map_err(plan_error)?.as_str()
                != proposal.proposal().integrity().policy_sha256().as_str()
        {
            return Err(inputs("compact manifest binding differs from plan"));
        }
        let integrity = proposal.proposal().integrity();
        let bindings = integrity.selected_repositories();
        if self.repositories.len() != bindings.len() {
            return Err(inputs("compact repository count differs from plan"));
        }
        for (repository, binding) in self.repositories.iter().zip(bindings) {
            if repository.id != binding.id()
                || repository.generation_sha256 != binding.generation_sha256().as_str()
                || repository.origin_sha256 != binding.origin_sha256().as_str()
                || repository.trust_sha256 != binding.trust_sha256().as_str()
                || repository.trust.repo_id() != repository.id
                || repository
                    .trust
                    .canonical_sha256()
                    .map_err(plan_error)?
                    .as_str()
                    != repository.trust_sha256
            {
                return Err(inputs("compact repository binding differs from plan"));
            }
        }
        let planned = proposal
            .actions()
            .iter()
            .filter(|action| action.artifact.is_some())
            .collect::<Vec<_>>();
        if planned.len() != self.artifacts.len() {
            return Err(inputs("compact artifact set differs from plan"));
        }
        for (index, (artifact, action)) in self.artifacts.iter().zip(planned).enumerate() {
            let record = action.artifact.as_ref().expect("filtered artifact");
            let repository = self
                .repositories
                .iter()
                .find(|repository| repository.id == artifact.repo_id)
                .ok_or_else(|| inputs("compact artifact repository is absent"))?;
            if usize::try_from(artifact.fd_index).ok() != Some(index)
                || artifact.name != action.name
                || artifact.epoch != u64::from(action.target_evra.epoch())
                || artifact.version != action.target_evra.version()
                || artifact.release != action.target_evra.release()
                || artifact.arch != action.target_evra.arch().as_rpm_arch()
                || action.vendor.as_deref() != Some(artifact.vendor.as_str())
                || action.repo_id.as_deref() != Some(artifact.repo_id.as_str())
                || artifact.sha256 != record.checksum_sha256
                || artifact.size != record.package_size
                || artifact.generation_sha256 != repository.generation_sha256
                || artifact.origin_sha256 != repository.origin_sha256
                || artifact.trust_sha256 != repository.trust_sha256
            {
                return Err(inputs("compact artifact binding differs from plan"));
            }
        }
        Ok(())
    }

    fn revalidate_runtime(&self, proposal: &CanonicalSolverPlan) -> Result<(), ExecutorError> {
        let snapshot = revalidate_snapshot_digest(proposal, &self.planning_snapshot_sha256)?;
        if snapshot.payload().policy.solver != self.policy
            || snapshot.payload().inventory != self.inventory
        {
            return Err(inputs(
                "compact policy or inventory differs from current snapshot",
            ));
        }
        for repository in &self.repositories {
            let current = snapshot
                .payload()
                .allowed_repositories
                .iter()
                .find(|candidate| candidate.id == repository.id)
                .ok_or_else(|| inputs("compact repository is absent from current snapshot"))?;
            if current.priority != u32::try_from(repository.priority).unwrap_or(u32::MAX)
                || current.cost != u32::try_from(repository.cost).unwrap_or(u32::MAX)
                || current.generation_sha256 != repository.generation_sha256
                || current.origin.sha256 != repository.origin_sha256
                || current.trust != repository.trust
                || current.keys.len() != repository.keys.len()
                || current
                    .keys
                    .iter()
                    .zip(&repository.keys)
                    .any(|(left, right)| {
                        left.bundle_path != right.bundle_path
                            || left.certificate_base64 != right.certificate_base64
                    })
            {
                return Err(inputs("compact repository differs from current snapshot"));
            }
        }
        Ok(())
    }

    fn into_transaction(self, files: Vec<File>) -> Result<CompactTransactionInputs, ExecutorError> {
        let repositories = self
            .repositories
            .into_iter()
            .map(|repository| {
                let keys = repository
                    .keys
                    .into_iter()
                    .map(|key| {
                        STANDARD
                            .decode(key.certificate_base64)
                            .map(|certificate| VerifiedStagedKey {
                                bundle_path: key.bundle_path,
                                certificate,
                            })
                            .map_err(|_| inputs("compact key certificate is not base64"))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(StagedRepository {
                    repository: Repository {
                        id: repository.id,
                        repomd_path: String::new(),
                        primary_path: String::new(),
                        filelists_path: String::new(),
                        priority: repository.priority,
                        cost: repository.cost,
                    },
                    trust: repository.trust,
                    keys,
                    generation_sha256: repository.generation_sha256,
                    origin_sha256: repository.origin_sha256,
                    trust_sha256: repository.trust_sha256,
                })
            })
            .collect::<Result<Vec<_>, ExecutorError>>()?;
        let artifacts = self
            .artifacts
            .into_iter()
            .zip(files)
            .map(|(artifact, file)| StagedArtifact {
                file,
                expected: ExpectedPackage {
                    name: artifact.name,
                    epoch: artifact.epoch,
                    version: artifact.version,
                    release: artifact.release,
                    arch: artifact.arch,
                    vendor: artifact.vendor,
                },
                sha256: artifact.sha256,
                size: artifact.size,
                repo_id: artifact.repo_id,
                generation_sha256: artifact.generation_sha256,
                origin_sha256: artifact.origin_sha256,
                trust_sha256: artifact.trust_sha256,
            })
            .collect();
        Ok(CompactTransactionInputs {
            staged: StagedInputs {
                policy: self.policy,
                repositories,
                candidates: Vec::new(),
                metadata: Vec::new(),
                artifacts,
            },
            inventory: self.inventory,
            rpmdb_cookie: self.rpmdb_cookie,
            planning_snapshot_sha256: self.planning_snapshot_sha256,
        })
    }
}

fn revalidate_snapshot_digest(
    proposal: &CanonicalSolverPlan,
    expected: &str,
) -> Result<PlanningSnapshot, ExecutorError> {
    if expected
        != proposal
            .proposal()
            .integrity()
            .planning_snapshot_sha256()
            .as_str()
        || PlanningSnapshot::current_system_digest().map_err(plan_error)? != expected
    {
        return Err(inputs(
            "planning generation changed before compact execution",
        ));
    }
    let snapshot = PlanningSnapshot::open_system().map_err(plan_error)?;
    snapshot.revalidate_runtime_bindings().map_err(plan_error)?;
    if snapshot.digest().map_err(plan_error)? != expected {
        return Err(inputs(
            "planning snapshot changed while compact inputs were opened",
        ));
    }
    Ok(snapshot)
}

fn sealed_memfd(name: &str, bytes: &[u8], maximum: u64) -> Result<OwnedFd, ExecutorError> {
    if bytes.is_empty() || bytes.len() as u64 > maximum {
        return Err(inputs("sealed input size is invalid"));
    }
    let descriptor = memfd_create(
        name,
        MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING | MemfdFlags::NOEXEC_SEAL,
    )
    .map_err(read_error)?;
    fchmod(&descriptor, Mode::from_raw_mode(0o600)).map_err(read_error)?;
    let mut file = File::from(descriptor);
    file.write_all(bytes).map_err(read_error)?;
    file.sync_all().map_err(read_error)?;
    file.seek(SeekFrom::Start(0)).map_err(read_error)?;
    fcntl_add_seals(&file, REQUIRED_SEALS).map_err(read_error)?;
    validate_sealed_memfd(&file, maximum)?;
    Ok(file.into())
}

fn read_sealed_memfd(descriptor: OwnedFd, maximum: u64) -> Result<Vec<u8>, ExecutorError> {
    let mut file = File::from(descriptor);
    validate_sealed_memfd(&file, maximum)?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(read_error)?;
    if bytes.is_empty() || bytes.len() as u64 > maximum {
        return Err(inputs("sealed input size is invalid"));
    }
    Ok(bytes)
}

pub(crate) fn validate_sealed_memfd(
    descriptor: &impl rustix::fd::AsFd,
    maximum: u64,
) -> Result<(), ExecutorError> {
    let metadata = fstat(descriptor).map_err(read_error)?;
    let seals = fcntl_get_seals(descriptor).map_err(read_error)?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
        || metadata.st_uid != rustix::process::geteuid().as_raw()
        || metadata.st_nlink != 0
        || metadata.st_size <= 0
        || metadata.st_size as u64 > maximum
        || !seals.contains(REQUIRED_SEALS)
    {
        return Err(inputs("inherited compact descriptor is not a sealed memfd"));
    }
    Ok(())
}

fn inputs(message: impl Into<String>) -> ExecutorError {
    ExecutorError::Inputs(message.into())
}

fn read_error(error: impl std::fmt::Display) -> ExecutorError {
    ExecutorError::Read(error.to_string())
}

fn json(error: serde_json::Error) -> ExecutorError {
    inputs(error.to_string())
}

fn plan_error(error: impl std::fmt::Display) -> ExecutorError {
    ExecutorError::Plan(error.to_string())
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsFd;

    use super::*;

    #[test]
    fn sealed_memfd_round_trip_is_immutable() {
        let descriptor = sealed_memfd("dnfast-test", b"sealed bytes", 1024).expect("create");
        validate_sealed_memfd(&descriptor, 1024).expect("validate");
        assert_eq!(
            rustix::io::pwrite(&descriptor, b"x", 0).unwrap_err(),
            rustix::io::Errno::PERM
        );
        let duplicate = descriptor.as_fd().try_clone_to_owned().expect("duplicate");
        assert_eq!(
            read_sealed_memfd(duplicate, 1024).expect("read"),
            b"sealed bytes"
        );
    }

    #[test]
    fn ordinary_file_is_not_accepted_as_compact_manifest() {
        let file = tempfile::tempfile().expect("temporary");
        file.set_len(1).expect("size");
        assert!(validate_sealed_memfd(&file, 1024).is_err());
    }
}
