use std::{path::{Path, PathBuf}, process::Command};

use base64::Engine;
use dnfast_cache::{Cache, VerifiedCompleteGeneration};
use dnfast_core::{Architecture, InstalledInventory, RepoPreference, RepoTrustPolicy, SigningSubkeyRule, SolverPolicy};
use dnfast_repo::{KeyBundle, MutationProfile, RepoConfig, key_bundle_digest, load_system_mutation_profile};
use hex::encode;
use rustix::process::geteuid;
#[cfg(test)]
use rustix::process::getuid;

use crate::{
    PlanningConfiguration, PlanningError, PlanningKey, PlanningOrigin, PlanningPayload, PlanningPolicy,
    PlanningRepository, PlanningSnapshot,
    fs::{TrustedDirectory, validate_root_executable, validate_tree},
    snapshot_store::{garbage_collect, open_snapshot, publish_snapshot},
};

pub const SYSTEM_CACHE_PATH: &str = "/var/cache/dnfast";
pub const SYSTEM_PLANNING_PATH: &str = "/var/lib/dnfast/planning";
const SNAPSHOTS_DIRECTORY: &str = "snapshots";
const TRUSTED_RPM_PATH: &str = "/usr/bin/rpm";

#[derive(Clone, Debug)]
pub struct PlanningRoots {
    cache_root: PathBuf,
    planning_root: PathBuf,
}

pub struct RootPlanningPublisher {
    roots: PlanningRoots,
    owner: u32,
    require_root: bool,
}

impl PlanningRoots {
    pub fn system() -> Self {
        Self { cache_root: PathBuf::from(SYSTEM_CACHE_PATH), planning_root: PathBuf::from(SYSTEM_PLANNING_PATH) }
    }

    pub fn cache_root(&self) -> &Path { &self.cache_root }
    pub fn planning_root(&self) -> &Path { &self.planning_root }

    #[cfg(test)]
    pub(crate) fn for_test(base: &Path) -> Self {
        Self { cache_root: base.join("cache"), planning_root: base.join("planning") }
    }
}

impl RootPlanningPublisher {
    pub fn system() -> Result<Self, PlanningError> {
        require_root()?;
        Ok(Self { roots: PlanningRoots::system(), owner: 0, require_root: true })
    }

    pub fn publish_current(&self, published_at_unix: u64) -> Result<String, PlanningError> {
        self.require_publisher()?;
        let profile = load_system_mutation_profile().map_err(|error| PlanningError::Input(error.to_string()))?;
        let host_architecture = host_rpm_architecture()?;
        let mut context = dnfast_native::NativeContext::open(host_architecture, || false)
            .map_err(|error| PlanningError::Input(error.to_string()))?;
        let inventory = context.read_installed_inventory().map_err(|error| PlanningError::Input(error.to_string()))?;
        self.publish(&profile, inventory, published_at_unix, host_architecture)
    }

    pub fn publish_after_verified_refresh(&self, published_at_unix: u64) -> Result<String, PlanningError> {
        self.publish_current(published_at_unix)
    }

    /// Publishes the live RPMDB inventory without changing the current source bindings.
    pub fn publish_inventory_after_transaction(&self) -> Result<String, PlanningError> {
        self.require_publisher()?;
        let host_architecture = host_rpm_architecture()?;
        let mut context = dnfast_native::NativeContext::open(host_architecture, || false)
            .map_err(|error| PlanningError::Input(error.to_string()))?;
        let inventory = context.read_installed_inventory().map_err(|error| PlanningError::Input(error.to_string()))?;
        self.publish_inventory_onto_current(inventory)
    }

    pub fn publish_inventory_onto_current(&self, inventory: InstalledInventory) -> Result<String, PlanningError> {
        self.require_publisher()?;
        let current = open_snapshot(&self.roots, self.owner)?;
        let mut payload = current.payload().clone();
        payload.inventory = inventory;
        self.store_snapshot(PlanningSnapshot::new(current.published_at_unix(), payload)?)
    }

    pub fn prepare_system_cache_for_verified_refresh(&self) -> Result<(), PlanningError> {
        self.require_publisher()?;
        let cache_root = TrustedDirectory::open(&self.roots.cache_root, self.owner, true, 0o700)?;
        cache_root.recheck()?;
        validate_tree(&self.roots.cache_root, self.owner)
    }

    fn publish(
        &self,
        profile: &MutationProfile,
        inventory: InstalledInventory,
        published_at_unix: u64,
        host_architecture: Architecture,
    ) -> Result<String, PlanningError> {
        self.require_publisher()?;
        if self.require_root {
            let public_parent = TrustedDirectory::open(Path::new("/var/lib/dnfast"), self.owner, true, 0o755)?;
            public_parent.set_mode(0o755)?;
        }
        let planning = TrustedDirectory::open(&self.roots.planning_root, self.owner, true, 0o755)?;
        planning.set_mode(0o755)?;
        let snapshots = planning.child(SNAPSHOTS_DIRECTORY, true, 0o755)?;
        let cache_root = TrustedDirectory::open(&self.roots.cache_root, self.owner, true, 0o700)?;
        cache_root.recheck()?;
        validate_tree(&self.roots.cache_root, self.owner)?;
        let snapshot = snapshot_from(profile, inventory, published_at_unix, host_architecture, &Cache::new(&self.roots.cache_root))?;
        validate_tree(&self.roots.cache_root, self.owner)?;
        let bytes = snapshot.canonical_bytes()?;
        let digest = snapshot.digest()?;
        publish_snapshot(&planning, &snapshots, &digest, &bytes)?;
        garbage_collect(&snapshots, &digest)?;
        Ok(digest)
    }

    fn store_snapshot(&self, snapshot: PlanningSnapshot) -> Result<String, PlanningError> {
        self.require_publisher()?;
        if self.require_root {
            let public_parent = TrustedDirectory::open(Path::new("/var/lib/dnfast"), self.owner, true, 0o755)?;
            public_parent.set_mode(0o755)?;
        }
        let planning = TrustedDirectory::open(&self.roots.planning_root, self.owner, true, 0o755)?;
        planning.set_mode(0o755)?;
        let snapshots = planning.child(SNAPSHOTS_DIRECTORY, true, 0o755)?;
        let bytes = snapshot.canonical_bytes()?;
        let digest = snapshot.digest()?;
        publish_snapshot(&planning, &snapshots, &digest, &bytes)?;
        garbage_collect(&snapshots, &digest)?;
        Ok(digest)
    }

    pub fn open_snapshot(&self) -> Result<PlanningSnapshot, PlanningError> {
        open_snapshot(&self.roots, self.owner)
    }

    pub fn revalidate_snapshot(&self, snapshot: &PlanningSnapshot) -> Result<(), PlanningError> {
        self.require_publisher()?;
        let profile = load_system_mutation_profile().map_err(|error| PlanningError::Input(error.to_string()))?;
        let host_architecture = host_rpm_architecture()?;
        let cache_root = TrustedDirectory::open(&self.roots.cache_root, self.owner, false, 0)?;
        cache_root.recheck()?;
        validate_tree(&self.roots.cache_root, self.owner)?;
        let refreshed = snapshot_from(
            &profile,
            snapshot.payload().inventory.clone(),
            snapshot.published_at_unix(),
            host_architecture,
            &Cache::new(&self.roots.cache_root),
        )?;
        validate_tree(&self.roots.cache_root, self.owner)?;
        require_same_source_payload(snapshot, &refreshed)?;
        require_current_snapshot(snapshot, &self.open_snapshot()?)?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn for_test(roots: PlanningRoots) -> Self {
        Self { roots, owner: getuid().as_raw(), require_root: false }
    }

    #[cfg(test)]
    pub(crate) fn open_snapshot_for_test(roots: &PlanningRoots) -> Result<PlanningSnapshot, PlanningError> {
        open_snapshot(roots, 0)
    }

    #[cfg(test)]
    pub(crate) fn open_test_snapshot(&self) -> Result<PlanningSnapshot, PlanningError> {
        self.open_snapshot()
    }

    fn require_publisher(&self) -> Result<(), PlanningError> {
        if self.require_root { require_root()?; }
        Ok(())
    }
}

impl PlanningSnapshot {
    pub fn open_system() -> Result<Self, PlanningError> {
        open_snapshot(&PlanningRoots::system(), 0)
    }

    pub fn revalidate_system_state(&self) -> Result<(), PlanningError> {
        RootPlanningPublisher::system()?.revalidate_snapshot(self)
    }
}

pub fn host_rpm_architecture() -> Result<Architecture, PlanningError> {
    let executable = Path::new(TRUSTED_RPM_PATH);
    validate_root_executable(executable)?;
    let output = Command::new(executable).env_clear().args(["--eval", "%{_arch}"]).output().map_err(|error| PlanningError::Input(error.to_string()))?;
    if !output.status.success() {
        return Err(PlanningError::Input("rpm did not report a host architecture".into()));
    }
    match std::str::from_utf8(&output.stdout).map_err(|error| PlanningError::Input(error.to_string()))?.trim() {
        "aarch64" => Ok(Architecture::Aarch64),
        "x86_64" => Ok(Architecture::X86_64),
        _ => Err(PlanningError::Input("unsupported host RPM architecture".into())),
    }
}

fn snapshot_from(
    profile: &MutationProfile,
    inventory: InstalledInventory,
    published_at_unix: u64,
    host_architecture: Architecture,
    cache: &Cache,
) -> Result<PlanningSnapshot, PlanningError> {
    let configuration = normalized_configuration(profile)?;
    let mut enabled = profile.repositories.iter().filter(|repository| repository.enabled).collect::<Vec<_>>();
    enabled.sort_by(|left, right| left.id.cmp(&right.id));
    if enabled.is_empty() || enabled.windows(2).any(|pair| pair[0].id == pair[1].id) {
        return Err(PlanningError::Input("enabled repositories are absent or duplicate".into()));
    }
    if !profile.main.install_weak_deps || profile.main.best || !profile.main.includepkgs.is_empty() {
        return Err(PlanningError::Input("mutation policy cannot be represented safely".into()));
    }
    let preferences = enabled.iter().map(|repository| RepoPreference::new(&repository.id, u32::from(repository.priority), repository.cost))
        .collect::<Result<Vec<_>, _>>().map_err(domain)?;
    let policy = policy_for(host_architecture, profile, preferences)?;
    let repositories = enabled.into_iter().map(|repository| repository_payload(repository, cache, published_at_unix)).collect::<Result<Vec<_>, _>>()?;
    PlanningSnapshot::new(published_at_unix, PlanningPayload {
        policy: PlanningPolicy { solver: policy, included_packages: profile.main.includepkgs.clone(), installonly_limit: profile.main.installonly_limit },
        inventory,
        allowed_repositories: repositories,
        configuration,
    })
}

fn policy_for(host: Architecture, profile: &MutationProfile, preferences: Vec<RepoPreference>) -> Result<SolverPolicy, PlanningError> {
    let base = match host {
        Architecture::Aarch64 => SolverPolicy::fedora44_aarch64(profile.main.protected_packages.clone(), profile.main.installonlypkgs.clone()),
        Architecture::X86_64 => SolverPolicy::fedora44_x86_64(profile.main.protected_packages.clone(), profile.main.installonlypkgs.clone()),
        Architecture::Noarch => return Err(PlanningError::Input("host RPM architecture cannot be noarch".into())),
    };
    Ok(base.with_repositories(preferences).with_excludes(profile.main.excludepkgs.clone()))
}

fn repository_payload(repository: &RepoConfig, cache: &Cache, valid_at_unix: u64) -> Result<PlanningRepository, PlanningError> {
    if !repository.sslverify || !repository.gpgcheck || !repository.pkg_gpgcheck || repository.repo_gpgcheck
        || repository.allowed_fingerprints.is_empty() || repository.gpgkey.is_empty()
    {
        return Err(PlanningError::Input("repository trust policy is incomplete".into()));
    }
    let paths = repository.gpgkey.iter().map(PathBuf::from).collect::<Vec<_>>();
    let bundle = key_bundle_digest(&repository.id, &paths).map_err(|error| PlanningError::Input(error.to_string()))?;
    if repository.key_bundle_digest != Some(bundle.digest) {
        return Err(PlanningError::Input("repository key bundle changed after profile validation".into()));
    }
    let trust = RepoTrustPolicy::new(&repository.id, encode(bundle.digest), repository.allowed_fingerprints.clone(), SigningSubkeyRule::AuthorizedSubkeys, valid_at_unix).map_err(domain)?;
    let generation = cache.open_current_verified_complete_generation(&repository.id).map_err(|error| PlanningError::Cache(error.to_string()))?;
    generation_payload(repository, generation, trust, bundle)
}

fn generation_payload(
    repository: &RepoConfig,
    generation: VerifiedCompleteGeneration,
    trust: RepoTrustPolicy,
    bundle: KeyBundle,
) -> Result<PlanningRepository, PlanningError> {
    let keys = bundle.paths.iter().zip(bundle.certificates).map(|(path, certificate)| {
        Ok(PlanningKey {
            bundle_path: path.to_str().ok_or_else(|| PlanningError::Input("key path is not UTF-8".into()))?.into(),
            certificate_base64: base64::engine::general_purpose::STANDARD.encode(certificate),
        })
    }).collect::<Result<Vec<_>, PlanningError>>()?;
    if generation.repository() != repository.id {
        return Err(PlanningError::Cache("cache generation repository differs from configuration".into()));
    }
    let origin = generation.origin();
    Ok(PlanningRepository {
        id: repository.id.clone(), priority: u32::from(repository.priority), cost: repository.cost,
        generation_sha256: generation.digest().into(),
        origin: PlanningOrigin { repomd_url: origin.repomd_url().into(), sha256: digest(origin.repomd_url().as_bytes()) },
        repomd: crate::model::PlanningBytes::from_verified(generation.repomd()),
        primary: crate::model::PlanningBytes::from_verified(generation.primary()),
        filelists: crate::model::PlanningBytes::from_verified(generation.filelists()),
        solver_inputs: generation.solver_inputs().to_vec(), filelist_inputs: generation.filelist_inputs().to_vec(), trust, keys,
    })
}

fn normalized_configuration(profile: &MutationProfile) -> Result<Vec<PlanningConfiguration>, PlanningError> {
    let mut result = profile.repositories.iter().map(|repository| PlanningConfiguration {
        id: repository.id.clone(), enabled: repository.enabled, baseurl: repository.baseurl.clone(), metalink: repository.metalink.clone(),
        mirrorlist: repository.mirrorlist.clone(), priority: u32::from(repository.priority), cost: repository.cost,
        excludes: repository.excludepkgs.clone(), includes: repository.includepkgs.clone(), gpgkey: repository.gpgkey.clone(),
        allowed_fingerprints: repository.allowed_fingerprints.clone(),
    }).collect::<Vec<_>>();
    result.sort_by(|left, right| left.id.cmp(&right.id));
    if result.windows(2).any(|pair| pair[0].id == pair[1].id) {
        return Err(PlanningError::Input("configuration repository identifiers are duplicate".into()));
    }
    Ok(result)
}

pub(crate) fn require_same_source_payload(expected: &PlanningSnapshot, refreshed: &PlanningSnapshot) -> Result<(), PlanningError> {
    if expected.payload() == refreshed.payload() { Ok(()) }
    else { Err(PlanningError::Input("root configuration, key bundle, or verified cache generation changed".into())) }
}

pub(crate) fn require_current_snapshot(expected: &PlanningSnapshot, current: &PlanningSnapshot) -> Result<(), PlanningError> {
    if expected == current { Ok(()) }
    else { Err(PlanningError::UnsafeSnapshot("current planning snapshot changed during revalidation".into())) }
}

fn digest(bytes: &[u8]) -> String { use sha2::Digest; format!("{:x}", sha2::Sha256::digest(bytes)) }
fn require_root() -> Result<(), PlanningError> { if geteuid().as_raw() == 0 { Ok(()) } else { Err(PlanningError::NotRoot) } }
fn domain(error: dnfast_core::DomainError) -> PlanningError { PlanningError::Input(error.to_string()) }
