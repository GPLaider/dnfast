use std::{
    path::{Path, PathBuf},
    process::Command,
    sync::{Mutex, OnceLock},
    time::Instant,
};

use base64::Engine;
use dnfast_cache::{Cache, CacheError, SolvCache, VerifiedCompleteGeneration};
use dnfast_core::{
    Architecture, CanonicalDocument, InstalledInventory, RepoPreference, RepoTrustPolicy,
    SigningSubkeyRule, SolverPolicy,
};
use dnfast_repo::{
    KeyBundle, MetadataExpire, MutationProfile, RepoConfig, key_bundle_digest,
    load_system_mutation_profile,
};
use hex::encode;
use rustix::fs::{FlockOperation, flock};
use rustix::process::geteuid;
#[cfg(test)]
use rustix::process::getuid;

use crate::{
    ModuleState, PlanningConfiguration, PlanningError, PlanningKey, PlanningOrigin,
    PlanningPayload, PlanningPolicy, PlanningRepository, PlanningSnapshot,
    fs::{TrustedDirectory, validate_root_executable, validate_tree},
    snapshot_store::{
        current_digest, garbage_collect, garbage_collect_blobs, open_snapshot, publish_snapshot,
    },
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

struct SnapshotHostState {
    inventory: InstalledInventory,
    module_state: ModuleState,
}

struct PublicationLock<'a> {
    directory: &'a TrustedDirectory,
}

impl<'a> PublicationLock<'a> {
    fn acquire(directory: &'a TrustedDirectory) -> Result<Self, PlanningError> {
        directory.recheck()?;
        flock(directory.fd(), FlockOperation::LockExclusive)
            .map_err(|error| PlanningError::Io(error.to_string()))?;
        directory.recheck()?;
        Ok(Self { directory })
    }
}

impl Drop for PublicationLock<'_> {
    fn drop(&mut self) {
        let _ = flock(self.directory.fd(), FlockOperation::Unlock);
    }
}

impl PlanningRoots {
    pub fn system() -> Self {
        Self {
            cache_root: PathBuf::from(SYSTEM_CACHE_PATH),
            planning_root: PathBuf::from(SYSTEM_PLANNING_PATH),
        }
    }

    pub fn cache_root(&self) -> &Path {
        &self.cache_root
    }
    pub fn planning_root(&self) -> &Path {
        &self.planning_root
    }

    #[cfg(test)]
    pub(crate) fn for_test(base: &Path) -> Self {
        Self {
            cache_root: base.join("cache"),
            planning_root: base.join("planning"),
        }
    }
}

impl RootPlanningPublisher {
    pub fn system() -> Result<Self, PlanningError> {
        require_root()?;
        Ok(Self {
            roots: PlanningRoots::system(),
            owner: 0,
            require_root: true,
        })
    }

    pub fn publish_current(&self, published_at_unix: u64) -> Result<String, PlanningError> {
        self.publish_system(published_at_unix, None)
    }

    fn publish_system(
        &self,
        published_at_unix: u64,
        refreshed_generations: Option<&[(String, String)]>,
    ) -> Result<String, PlanningError> {
        self.require_publisher()?;
        // Refresh validation has released its metadata objects by this point,
        // but glibc may retain their arenas. Do not carry that dead resident
        // set into RPMDB inventory and planning publication.
        dnfast_native::release_unused_memory();
        trace_memory("planning:refresh-buffers-released");
        let planning = self.publication_directory()?;
        let _lock = PublicationLock::acquire(&planning)?;
        let profile = load_system_mutation_profile()
            .map_err(|error| PlanningError::Input(error.to_string()))?;
        let host_architecture = host_rpm_architecture()?;
        let mut context = dnfast_native::NativeContext::open(host_architecture, || false)
            .map_err(|error| PlanningError::Input(error.to_string()))?;
        let installed = context
            .read_installed_inventory_snapshot()
            .map_err(|error| PlanningError::Input(error.to_string()))?;
        prewarm_installed_solv_cache(
            &mut context,
            &installed,
            &self.roots.cache_root,
            host_architecture,
        )?;
        let inventory = installed.inventory;
        let refreshed_repository_ids = refreshed_generations.map(|generations| {
            generations
                .iter()
                .map(|(repository, _)| repository.clone())
                .collect::<Vec<_>>()
        });
        self.publish(
            &profile,
            inventory,
            published_at_unix,
            host_architecture,
            refreshed_repository_ids.as_deref(),
            refreshed_generations,
            &planning,
        )
    }

    pub fn publish_after_verified_refresh(
        &self,
        published_at_unix: u64,
        refreshed_generations: &[(String, String)],
    ) -> Result<String, PlanningError> {
        if refreshed_generations.is_empty()
            || refreshed_generations
                .windows(2)
                .any(|pair| pair[0].0 >= pair[1].0)
            || refreshed_generations
                .iter()
                .any(|(_, digest)| !crate::snapshot_store::valid_digest(digest))
        {
            return Err(PlanningError::Input(
                "verified refresh generations are absent or noncanonical".into(),
            ));
        }
        self.publish_system(published_at_unix, Some(refreshed_generations))
    }

    /// Publishes the live RPMDB inventory without changing the current source bindings.
    pub fn publish_inventory_after_transaction(&self) -> Result<String, PlanningError> {
        self.require_publisher()?;
        let host_architecture = host_rpm_architecture()?;
        let mut context = dnfast_native::NativeContext::open(host_architecture, || false)
            .map_err(|error| PlanningError::Input(error.to_string()))?;
        let installed = context
            .read_installed_inventory_snapshot()
            .map_err(|error| PlanningError::Input(error.to_string()))?;
        prewarm_installed_solv_cache(
            &mut context,
            &installed,
            &self.roots.cache_root,
            host_architecture,
        )?;
        self.publish_inventory_onto_current(installed.inventory)
    }

    pub fn publish_inventory_onto_current(
        &self,
        inventory: InstalledInventory,
    ) -> Result<String, PlanningError> {
        self.publish_inventory_onto_current_with_source(inventory)
            .map(|(_, published)| published)
    }

    pub fn publish_inventory_onto_current_with_source(
        &self,
        inventory: InstalledInventory,
    ) -> Result<(String, String), PlanningError> {
        self.require_publisher()?;
        let planning = self.existing_publication_directory()?;
        let _lock = PublicationLock::acquire(&planning)?;
        let current = open_snapshot(&self.roots, self.owner)?;
        let source = current.digest()?;
        let mut payload = current.payload().clone();
        payload.inventory = inventory;
        let published = self.store_snapshot(
            &planning,
            PlanningSnapshot::new_with_refreshed_repositories(
                current.published_at_unix(),
                current.refreshed_repository_ids().to_vec(),
                payload,
            )?,
        )?;
        Ok((source, published))
    }

    pub fn prepare_system_cache_for_verified_refresh(&self) -> Result<(), PlanningError> {
        self.require_publisher()?;
        let cache_root = TrustedDirectory::open(&self.roots.cache_root, self.owner, true, 0o700)?;
        cache_root.recheck()?;
        validate_tree(&self.roots.cache_root, self.owner)
    }

    #[allow(clippy::too_many_arguments)]
    fn publish(
        &self,
        profile: &MutationProfile,
        inventory: InstalledInventory,
        published_at_unix: u64,
        host_architecture: Architecture,
        refreshed_repository_ids: Option<&[String]>,
        refreshed_generations: Option<&[(String, String)]>,
        planning: &TrustedDirectory,
    ) -> Result<String, PlanningError> {
        trace_memory("planning:begin");
        self.require_publisher()?;
        let snapshots = planning.child(SNAPSHOTS_DIRECTORY, true, 0o755)?;
        let current = if planning.read_if_present("current", 65)?.is_some() {
            Some(open_snapshot(&self.roots, self.owner)?)
        } else {
            None
        };
        let module_state = current
            .as_ref()
            .map(|snapshot| snapshot.payload().module_state.clone())
            .unwrap_or_default();
        let cache_root = TrustedDirectory::open(&self.roots.cache_root, self.owner, true, 0o700)?;
        cache_root.recheck()?;
        validate_tree(&self.roots.cache_root, self.owner)?;
        let cache = Cache::new(&self.roots.cache_root);
        let mut snapshot = match (current.as_ref(), refreshed_generations) {
            (Some(current), Some(refreshed_generations)) => match reuse_unchanged_generations(
                profile,
                current,
                inventory.clone(),
                published_at_unix,
                host_architecture,
                &cache,
                refreshed_repository_ids,
                refreshed_generations,
            )? {
                Some(reused) => reused,
                None => snapshot_from(
                    profile,
                    SnapshotHostState {
                        inventory,
                        module_state,
                    },
                    published_at_unix,
                    host_architecture,
                    &cache,
                    refreshed_repository_ids,
                    PlanningStorage {
                        blobs: Some(planning),
                        solv_cache_root: Some(&self.roots.cache_root),
                    },
                )?,
            },
            _ => snapshot_from(
                profile,
                SnapshotHostState {
                    inventory,
                    module_state,
                },
                published_at_unix,
                host_architecture,
                &cache,
                refreshed_repository_ids,
                PlanningStorage {
                    blobs: Some(planning),
                    solv_cache_root: Some(&self.roots.cache_root),
                },
            )?,
        };
        snapshot.attach_storage(&self.roots.planning_root, self.owner);
        snapshot
            .module_catalog(&[])?
            .validate_state(&snapshot.payload().module_state)?;
        prewarm_repository_solv_caches(&snapshot, &self.roots.cache_root)?;
        trace_memory("planning:snapshot-built");
        validate_tree(&self.roots.cache_root, self.owner)?;
        let bytes = snapshot.canonical_bytes()?;
        trace_memory("planning:canonicalized");
        let digest = digest(&bytes);
        publish_snapshot(planning, &snapshots, &digest, &bytes)?;
        garbage_collect(&snapshots, &digest)?;
        garbage_collect_blobs(planning, &snapshots, self.owner)?;
        trace_memory("planning:published");
        Ok(digest)
    }

    fn store_snapshot(
        &self,
        planning: &TrustedDirectory,
        snapshot: PlanningSnapshot,
    ) -> Result<String, PlanningError> {
        self.require_publisher()?;
        let snapshots = planning.child(SNAPSHOTS_DIRECTORY, true, 0o755)?;
        let bytes = snapshot.canonical_bytes()?;
        let digest = digest(&bytes);
        publish_snapshot(planning, &snapshots, &digest, &bytes)?;
        garbage_collect(&snapshots, &digest)?;
        garbage_collect_blobs(planning, &snapshots, self.owner)?;
        Ok(digest)
    }

    pub fn publish_module_state_onto_current(
        &self,
        expected_snapshot: &str,
        module_state: ModuleState,
    ) -> Result<String, PlanningError> {
        self.require_publisher()?;
        let planning = self.existing_publication_directory()?;
        let _lock = PublicationLock::acquire(&planning)?;
        let current = open_snapshot(&self.roots, self.owner)?;
        if current.digest()? != expected_snapshot {
            return Err(PlanningError::Input(
                "planning snapshot changed during module mutation".into(),
            ));
        }
        current.module_catalog(&[])?.validate_state(&module_state)?;
        let mut payload = current.payload().clone();
        payload.module_state = module_state;
        self.store_snapshot(
            &planning,
            PlanningSnapshot::new_with_refreshed_repositories(
                current.published_at_unix(),
                current.refreshed_repository_ids().to_vec(),
                payload,
            )?,
        )
    }

    fn publication_directory(&self) -> Result<TrustedDirectory, PlanningError> {
        if self.require_root {
            let public_parent =
                TrustedDirectory::open(Path::new("/var/lib/dnfast"), self.owner, true, 0o755)?;
            public_parent.set_mode(0o755)?;
        }
        let planning = TrustedDirectory::open(&self.roots.planning_root, self.owner, true, 0o755)?;
        planning.set_mode(0o755)?;
        Ok(planning)
    }

    fn existing_publication_directory(&self) -> Result<TrustedDirectory, PlanningError> {
        TrustedDirectory::open(&self.roots.planning_root, self.owner, false, 0o755)
    }

    pub fn open_snapshot(&self) -> Result<PlanningSnapshot, PlanningError> {
        open_snapshot(&self.roots, self.owner)
    }

    pub fn current_metadata_is_fresh(
        &self,
        requested_repository_ids: &[String],
        now_unix: u64,
    ) -> Result<bool, PlanningError> {
        self.require_publisher()?;
        let profile = load_system_mutation_profile()
            .map_err(|error| PlanningError::Input(error.to_string()))?;
        let snapshot = self.open_snapshot()?;
        if !snapshot.has_current_schema() {
            return Ok(false);
        }
        if snapshot.payload().configuration != normalized_configuration(&profile)?
            || now_unix < snapshot.published_at_unix()
        {
            return Ok(false);
        }
        let host = host_rpm_architecture()?;
        let mut enabled = profile
            .repositories
            .iter()
            .filter(|repository| repository.enabled)
            .collect::<Vec<_>>();
        enabled.sort_by(|left, right| left.id.cmp(&right.id));
        let selected = enabled
            .iter()
            .copied()
            .filter(|repository| {
                requested_repository_ids.is_empty()
                    || requested_repository_ids.contains(&repository.id)
            })
            .collect::<Vec<_>>();
        if selected.is_empty()
            || requested_repository_ids
                .iter()
                .any(|id| !enabled.iter().any(|repository| repository.id == *id))
        {
            return Err(PlanningError::Input(
                "selected repository is not enabled".into(),
            ));
        }
        let preferences = enabled
            .iter()
            .map(|repository| {
                RepoPreference::new(
                    &repository.id,
                    u32::from(repository.priority),
                    repository.cost,
                )
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(domain)?;
        let expected_policy = policy_for(host, &profile, preferences)?;
        if snapshot.payload().policy.solver != expected_policy
            || snapshot.payload().policy.included_packages != profile.main.includepkgs
            || snapshot.payload().policy.installonly_limit != profile.main.installonly_limit
        {
            return Ok(false);
        }
        let age = now_unix - snapshot.published_at_unix();
        for configured in selected {
            if !snapshot.refreshed_repository_ids().contains(&configured.id) {
                return Ok(false);
            }
            match configured.metadata_expire {
                MetadataExpire::AfterSeconds(seconds) if age >= seconds => return Ok(false),
                MetadataExpire::AfterSeconds(_) | MetadataExpire::Never => {}
            }
            let Some(published) = snapshot
                .payload()
                .allowed_repositories
                .iter()
                .find(|repository| repository.id == configured.id)
            else {
                return Ok(false);
            };
            if configured.key_bundle_digest.map(hex::encode).as_deref()
                != Some(published.trust.key_bundle_sha256().as_str())
            {
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub fn revalidate_snapshot(&self, snapshot: &PlanningSnapshot) -> Result<(), PlanningError> {
        self.require_publisher()?;
        let profile = load_system_mutation_profile()
            .map_err(|error| PlanningError::Input(error.to_string()))?;
        let host_architecture = host_rpm_architecture()?;
        let cache_root = TrustedDirectory::open(&self.roots.cache_root, self.owner, false, 0)?;
        cache_root.recheck()?;
        validate_tree(&self.roots.cache_root, self.owner)?;
        let refreshed = snapshot_from(
            &profile,
            SnapshotHostState {
                inventory: snapshot.payload().inventory.clone(),
                module_state: snapshot.payload().module_state.clone(),
            },
            snapshot.published_at_unix(),
            host_architecture,
            &Cache::new(&self.roots.cache_root),
            None,
            PlanningStorage::default(),
        )?;
        validate_tree(&self.roots.cache_root, self.owner)?;
        require_same_source_payload(snapshot, &refreshed)?;
        require_current_snapshot(snapshot, &self.open_snapshot()?)?;
        Ok(())
    }

    /// Revalidates every live authority that can change the meaning or trust
    /// of an already root-published snapshot without reparsing the immutable
    /// multi-hundred-megabyte metadata generation.
    ///
    /// Metadata bytes are content-addressed below the root-owned planning
    /// store and are checked when loaded into the solver.  This gate therefore
    /// checks the current snapshot pointer, repository configuration, solver
    /// policy, host architecture, and live key-bundle bytes.  It is suitable
    /// for the final pre-transaction gate; publication and refresh retain the
    /// full cache-generation reconstruction above.
    pub fn revalidate_runtime_bindings(
        &self,
        snapshot: &PlanningSnapshot,
    ) -> Result<(), PlanningError> {
        self.require_publisher()?;
        let profile = load_system_mutation_profile()
            .map_err(|error| PlanningError::Input(error.to_string()))?;
        if snapshot.payload().configuration != normalized_configuration(&profile)? {
            return Err(PlanningError::Input(
                "root repository configuration changed after publication".into(),
            ));
        }
        let mut enabled = profile
            .repositories
            .iter()
            .filter(|repository| repository.enabled)
            .collect::<Vec<_>>();
        enabled.sort_by(|left, right| left.id.cmp(&right.id));
        let preferences = enabled
            .iter()
            .map(|repository| {
                RepoPreference::new(
                    &repository.id,
                    u32::from(repository.priority),
                    repository.cost,
                )
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(domain)?;
        let expected_policy = policy_for(host_rpm_architecture()?, &profile, preferences)?;
        if snapshot.payload().policy.solver != expected_policy
            || snapshot.payload().policy.included_packages != profile.main.includepkgs
            || snapshot.payload().policy.installonly_limit != profile.main.installonly_limit
        {
            return Err(PlanningError::Input(
                "root solver policy changed after publication".into(),
            ));
        }
        for repository in enabled {
            if !repository.sslverify
                || !repository.gpgcheck
                || !repository.pkg_gpgcheck
                || repository.allowed_fingerprints.is_empty()
                || repository.gpgkey.is_empty()
            {
                return Err(PlanningError::Input(
                    "repository trust policy changed after publication".into(),
                ));
            }
            let paths = repository
                .gpgkey
                .iter()
                .map(PathBuf::from)
                .collect::<Vec<_>>();
            let bundle = key_bundle_digest(&repository.id, &paths)
                .map_err(|error| PlanningError::Input(error.to_string()))?;
            let published = snapshot
                .payload()
                .allowed_repositories
                .iter()
                .find(|published| published.id == repository.id)
                .ok_or_else(|| {
                    PlanningError::Input(
                        "enabled repository disappeared from published snapshot".into(),
                    )
                })?;
            if repository.key_bundle_digest != Some(bundle.digest)
                || encode(bundle.digest) != published.trust.key_bundle_sha256().as_str()
            {
                return Err(PlanningError::Input(
                    "repository key bundle changed after publication".into(),
                ));
            }
        }
        require_current_snapshot(snapshot, &self.open_snapshot()?)
    }

    #[cfg(test)]
    pub(crate) fn for_test(roots: PlanningRoots) -> Self {
        Self {
            roots,
            owner: getuid().as_raw(),
            require_root: false,
        }
    }

    #[cfg(test)]
    pub(crate) fn open_snapshot_for_test(
        roots: &PlanningRoots,
    ) -> Result<PlanningSnapshot, PlanningError> {
        open_snapshot(roots, 0)
    }

    #[cfg(test)]
    pub(crate) fn open_test_snapshot(&self) -> Result<PlanningSnapshot, PlanningError> {
        self.open_snapshot()
    }

    fn require_publisher(&self) -> Result<(), PlanningError> {
        if self.require_root {
            require_root()?;
        }
        Ok(())
    }
}

fn trace_memory(phase: &str) {
    if std::env::var_os("DNFAST_REFRESH_TRACE").is_none() {
        return;
    }
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let fields = status
        .lines()
        .filter(|line| line.starts_with("VmRSS:") || line.starts_with("VmHWM:"))
        .collect::<Vec<_>>()
        .join(" ");
    static START: OnceLock<Instant> = OnceLock::new();
    let elapsed = START.get_or_init(Instant::now).elapsed().as_millis();
    eprintln!("dnfast-refresh-trace phase={phase} elapsed_ms={elapsed} {fields}");
}

impl PlanningSnapshot {
    pub fn open_system() -> Result<Self, PlanningError> {
        open_snapshot(&PlanningRoots::system(), 0)
    }

    pub fn current_system_digest() -> Result<String, PlanningError> {
        current_digest(&PlanningRoots::system(), 0)
    }

    pub fn revalidate_system_state(&self) -> Result<(), PlanningError> {
        RootPlanningPublisher::system()?.revalidate_snapshot(self)
    }

    pub fn revalidate_runtime_bindings(&self) -> Result<(), PlanningError> {
        RootPlanningPublisher::system()?.revalidate_runtime_bindings(self)
    }
}

pub fn host_rpm_architecture() -> Result<Architecture, PlanningError> {
    let executable = Path::new(TRUSTED_RPM_PATH);
    validate_root_executable(executable)?;
    let output = Command::new(executable)
        .env_clear()
        .args(["--eval", "%{_arch}"])
        .output()
        .map_err(|error| PlanningError::Input(error.to_string()))?;
    if !output.status.success() {
        return Err(PlanningError::Input(
            "rpm did not report a host architecture".into(),
        ));
    }
    match std::str::from_utf8(&output.stdout)
        .map_err(|error| PlanningError::Input(error.to_string()))?
        .trim()
    {
        "aarch64" => Ok(Architecture::Aarch64),
        "x86_64" => Ok(Architecture::X86_64),
        _ => Err(PlanningError::Input(
            "unsupported host RPM architecture".into(),
        )),
    }
}

#[derive(Clone, Copy, Default)]
struct PlanningStorage<'a> {
    blobs: Option<&'a TrustedDirectory>,
    solv_cache_root: Option<&'a Path>,
}

fn snapshot_from(
    profile: &MutationProfile,
    host_state: SnapshotHostState,
    published_at_unix: u64,
    host_architecture: Architecture,
    cache: &Cache,
    refreshed_repository_ids: Option<&[String]>,
    storage: PlanningStorage<'_>,
) -> Result<PlanningSnapshot, PlanningError> {
    let SnapshotHostState {
        inventory,
        module_state,
    } = host_state;
    let configuration = normalized_configuration(profile)?;
    let mut enabled = profile
        .repositories
        .iter()
        .filter(|repository| repository.enabled)
        .collect::<Vec<_>>();
    enabled.sort_by(|left, right| left.id.cmp(&right.id));
    if enabled.is_empty() || enabled.windows(2).any(|pair| pair[0].id == pair[1].id) {
        return Err(PlanningError::Input(
            "enabled repositories are absent or duplicate".into(),
        ));
    }
    if !profile.main.install_weak_deps || profile.main.best || !profile.main.includepkgs.is_empty()
    {
        return Err(PlanningError::Input(
            "mutation policy cannot be represented safely".into(),
        ));
    }
    let preferences = enabled
        .iter()
        .map(|repository| {
            RepoPreference::new(
                &repository.id,
                u32::from(repository.priority),
                repository.cost,
            )
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(domain)?;
    let policy = policy_for(host_architecture, profile, preferences)?;
    // Each repository has an independent checksum-bound generation and
    // independent file-provides spools. Build them concurrently so a large
    // Fedora base repository overlaps the smaller updates repository instead
    // of making first publication pay both parse/sort passes serially. The
    // resulting workers are joined in canonical repository order.
    let repositories = std::thread::scope(|scope| {
        enabled
            .into_iter()
            .map(|repository| {
                scope.spawn(move || {
                    repository_payload(
                        repository,
                        cache,
                        published_at_unix,
                        host_architecture,
                        storage,
                    )
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|worker| {
                worker
                    .join()
                    .map_err(|_| PlanningError::Io("repository planning worker panicked".into()))?
            })
            .collect::<Result<Vec<_>, PlanningError>>()
    })?;
    // Repository workers transiently hold decompression, sort, and staging
    // buffers hundreds of MiB larger than the published descriptors. Return
    // those free glibc arenas before the libsolv prewarm phase so the two
    // bounded phases do not stack their resident high-water marks.
    dnfast_native::release_unused_memory();
    trace_memory("planning:repository-buffers-released");
    // No snapshot can refer to these immutable blobs until every repository
    // worker succeeds. Flush the complete batch exactly once before building
    // the publishable snapshot, rather than issuing hundreds of per-blob
    // fsyncs or one filesystem-wide sync per repository.
    if let Some(store) = storage.blobs {
        crate::snapshot_store::sync_blobs(store)?;
    }
    let payload = PlanningPayload {
        policy: PlanningPolicy {
            solver: policy,
            included_packages: profile.main.includepkgs.clone(),
            installonly_limit: profile.main.installonly_limit,
        },
        inventory,
        allowed_repositories: repositories,
        configuration,
        module_state,
    };
    match refreshed_repository_ids {
        Some(ids) => PlanningSnapshot::new_with_refreshed_repositories(
            published_at_unix,
            ids.to_vec(),
            payload,
        ),
        None => PlanningSnapshot::new(published_at_unix, payload),
    }
}

/// Reuses only derived, content-addressed planning blobs when every live
/// authority and immutable cache generation still agrees with the current
/// snapshot. Cache verification errors are propagated; ordinary source
/// changes return `None` and take the complete reconstruction path.
#[allow(clippy::too_many_arguments)]
fn reuse_unchanged_generations(
    profile: &MutationProfile,
    current: &PlanningSnapshot,
    inventory: InstalledInventory,
    published_at_unix: u64,
    host_architecture: Architecture,
    cache: &Cache,
    refreshed_repository_ids: Option<&[String]>,
    refreshed_generations: &[(String, String)],
) -> Result<Option<PlanningSnapshot>, PlanningError> {
    // A schema migration may add checksum-bound roles. Cloning an older
    // repository payload into the new envelope would falsely claim the new
    // schema while omitting those roles, so force one complete reconstruction.
    if !current.has_current_schema() {
        return Ok(None);
    }
    let configuration = normalized_configuration(profile)?;
    if current.payload().configuration != configuration {
        return Ok(None);
    }
    let mut enabled = profile
        .repositories
        .iter()
        .filter(|repository| repository.enabled)
        .collect::<Vec<_>>();
    enabled.sort_by(|left, right| left.id.cmp(&right.id));
    if enabled.is_empty() || enabled.windows(2).any(|pair| pair[0].id == pair[1].id) {
        return Err(PlanningError::Input(
            "enabled repositories are absent or duplicate".into(),
        ));
    }
    if !profile.main.install_weak_deps || profile.main.best || !profile.main.includepkgs.is_empty()
    {
        return Err(PlanningError::Input(
            "mutation policy cannot be represented safely".into(),
        ));
    }
    let preferences = enabled
        .iter()
        .map(|repository| {
            RepoPreference::new(
                &repository.id,
                u32::from(repository.priority),
                repository.cost,
            )
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(domain)?;
    let policy = PlanningPolicy {
        solver: policy_for(host_architecture, profile, preferences)?,
        included_packages: profile.main.includepkgs.clone(),
        installonly_limit: profile.main.installonly_limit,
    };
    if current.payload().policy != policy
        || current.payload().allowed_repositories.len() != enabled.len()
    {
        return Ok(None);
    }

    let mut repositories = Vec::with_capacity(enabled.len());
    for configured in enabled {
        if !configured.sslverify
            || !configured.gpgcheck
            || !configured.pkg_gpgcheck
            || configured.allowed_fingerprints.is_empty()
            || configured.gpgkey.is_empty()
        {
            return Err(PlanningError::Input(
                "repository trust policy is incomplete".into(),
            ));
        }
        let Some(previous) = current
            .payload()
            .allowed_repositories
            .iter()
            .find(|repository| repository.id == configured.id)
        else {
            return Ok(None);
        };
        let repomd = current.materialize_payload(&previous.repomd)?;
        let records = dnfast_metadata::parse_repomd_records(&repomd)
            .map_err(|error| PlanningError::Cache(error.to_string()))?;
        if !auxiliary_descriptor_matches(records.group.as_ref(), previous.group.as_ref())
            || !auxiliary_descriptor_matches(records.modules.as_ref(), previous.modules.as_ref())
            || !auxiliary_descriptor_matches(
                records.updateinfo.as_ref(),
                previous.updateinfo.as_ref(),
            )
        {
            return Ok(None);
        }
        if previous.priority != u32::from(configured.priority)
            || previous.cost != configured.cost
            || previous.file_provides.is_none()
        {
            return Ok(None);
        }
        if !crate::file_provides::current_descriptor_valid(current, previous)? {
            return Ok(None);
        }

        let paths = configured
            .gpgkey
            .iter()
            .map(PathBuf::from)
            .collect::<Vec<_>>();
        let bundle = key_bundle_digest(&configured.id, &paths)
            .map_err(|error| PlanningError::Input(error.to_string()))?;
        if configured.key_bundle_digest != Some(bundle.digest) {
            return Err(PlanningError::Input(
                "repository key bundle changed after profile validation".into(),
            ));
        }
        let trust = RepoTrustPolicy::new(
            &configured.id,
            encode(bundle.digest),
            configured.allowed_fingerprints.clone(),
            SigningSubkeyRule::AuthorizedSubkeys,
            published_at_unix,
        )
        .map_err(domain)?;
        let keys = planning_keys(&bundle)?;
        if previous.keys != keys {
            return Ok(None);
        }

        let identity = cache
            .open_current_generation_identity(&configured.id)
            .map_err(|error| PlanningError::Cache(error.to_string()))?;
        if previous.generation_sha256 != identity.digest() {
            return Ok(None);
        }
        let mut reused = previous.clone();
        match refreshed_generations
            .iter()
            .find(|(repository, _)| repository == &configured.id)
        {
            Some((_, verified_digest)) if verified_digest == identity.digest() => {
                reused.trust = trust;
                reused.repomd_authentication = identity.repomd_authentication().clone();
            }
            Some(_) => return Ok(None),
            None if previous.repomd_authentication == *identity.repomd_authentication() => {}
            None => return Ok(None),
        }
        repositories.push(reused);
    }

    if refreshed_repository_ids
        != Some(
            &refreshed_generations
                .iter()
                .map(|(repository, _)| repository.clone())
                .collect::<Vec<_>>(),
        )
    {
        return Err(PlanningError::Input(
            "verified refresh identities differ from repository selection".into(),
        ));
    }

    let payload = PlanningPayload {
        policy,
        inventory,
        allowed_repositories: repositories,
        configuration,
        module_state: current.payload().module_state.clone(),
    };
    let snapshot = match refreshed_repository_ids {
        Some(ids) => PlanningSnapshot::new_with_refreshed_repositories(
            published_at_unix,
            ids.to_vec(),
            payload,
        ),
        None => PlanningSnapshot::new(published_at_unix, payload),
    }?;
    Ok(Some(snapshot))
}

fn auxiliary_descriptor_matches(
    record: Option<&dnfast_metadata::AuxiliaryRecord>,
    descriptor: Option<&crate::model::PlanningBytes>,
) -> bool {
    match (record, descriptor) {
        (None, None) => true,
        (Some(record), Some(descriptor)) => {
            record.checksum == descriptor.sha256 && record.size == descriptor.size
        }
        _ => false,
    }
}

fn policy_for(
    host: Architecture,
    profile: &MutationProfile,
    preferences: Vec<RepoPreference>,
) -> Result<SolverPolicy, PlanningError> {
    let base = match host {
        Architecture::Aarch64 => SolverPolicy::fedora44_aarch64(
            profile.main.protected_packages.clone(),
            profile.main.installonlypkgs.clone(),
        ),
        Architecture::X86_64 => SolverPolicy::fedora44_x86_64(
            profile.main.protected_packages.clone(),
            profile.main.installonlypkgs.clone(),
        ),
        Architecture::Noarch => {
            return Err(PlanningError::Input(
                "host RPM architecture cannot be noarch".into(),
            ));
        }
    };
    Ok(base
        .with_repositories(preferences)
        .with_excludes(profile.main.excludepkgs.clone()))
}

fn repository_payload(
    repository: &RepoConfig,
    cache: &Cache,
    valid_at_unix: u64,
    host_architecture: Architecture,
    storage: PlanningStorage<'_>,
) -> Result<PlanningRepository, PlanningError> {
    if !repository.sslverify
        || !repository.gpgcheck
        || !repository.pkg_gpgcheck
        || repository.allowed_fingerprints.is_empty()
        || repository.gpgkey.is_empty()
    {
        return Err(PlanningError::Input(
            "repository trust policy is incomplete".into(),
        ));
    }
    let paths = repository
        .gpgkey
        .iter()
        .map(PathBuf::from)
        .collect::<Vec<_>>();
    let bundle = key_bundle_digest(&repository.id, &paths)
        .map_err(|error| PlanningError::Input(error.to_string()))?;
    if repository.key_bundle_digest != Some(bundle.digest) {
        return Err(PlanningError::Input(
            "repository key bundle changed after profile validation".into(),
        ));
    }
    let trust = RepoTrustPolicy::new(
        &repository.id,
        encode(bundle.digest),
        repository.allowed_fingerprints.clone(),
        SigningSubkeyRule::AuthorizedSubkeys,
        valid_at_unix,
    )
    .map_err(domain)?;
    let generation = cache
        .open_current_verified_complete_generation(&repository.id)
        .map_err(|error| PlanningError::Cache(error.to_string()))?;
    let records = dnfast_metadata::parse_repomd_records(generation.repomd().bytes())
        .map_err(|error| PlanningError::Cache(error.to_string()))?;
    let auxiliary = AuxiliaryPayloads {
        group: records
            .group
            .as_ref()
            .map(|record| cache.open_auxiliary(record))
            .transpose()
            .map_err(|error| PlanningError::Cache(error.to_string()))?,
        modules: records
            .modules
            .as_ref()
            .map(|record| cache.open_auxiliary(record))
            .transpose()
            .map_err(|error| PlanningError::Cache(error.to_string()))?,
        updateinfo: records
            .updateinfo
            .as_ref()
            .map(|record| cache.open_auxiliary(record))
            .transpose()
            .map_err(|error| PlanningError::Cache(error.to_string()))?,
    };
    generation_payload(
        repository,
        generation,
        auxiliary,
        trust,
        bundle,
        host_architecture,
        storage,
    )
}

struct AuxiliaryPayloads {
    group: Option<dnfast_cache::VerifiedBytes>,
    modules: Option<dnfast_cache::VerifiedBytes>,
    updateinfo: Option<dnfast_cache::VerifiedBytes>,
}

fn generation_payload(
    repository: &RepoConfig,
    generation: VerifiedCompleteGeneration,
    auxiliary: AuxiliaryPayloads,
    trust: RepoTrustPolicy,
    bundle: KeyBundle,
    host_architecture: Architecture,
    storage: PlanningStorage<'_>,
) -> Result<PlanningRepository, PlanningError> {
    // Primary-only libsolv materialization and filelists hashing consume
    // independent immutable inputs. On a first publication, overlap them so
    // full absolute-file readiness does not pay both CPU passes serially.
    let file_provides = std::thread::scope(|scope| {
        let solv_worker = storage.solv_cache_root.map(|cache_root| {
            scope.spawn(|| {
                prewarm_repository_generation_solv_cache(
                    repository,
                    &generation,
                    cache_root,
                    host_architecture,
                )
            })
        });
        let file_provides = crate::file_provides::build(&generation, storage.blobs)?;
        if let Some(worker) = solv_worker {
            worker
                .join()
                .map_err(|_| PlanningError::Io("repository solv-cache worker panicked".into()))??;
        }
        Ok::<_, PlanningError>(file_provides)
    })?;
    let keys = planning_keys(&bundle)?;
    if generation.repository() != repository.id {
        return Err(PlanningError::Cache(
            "cache generation repository differs from configuration".into(),
        ));
    }
    if let Some(planning) = storage.blobs {
        for payload in [
            generation.repomd(),
            generation.primary(),
            generation.filelists(),
        ] {
            crate::snapshot_store::publish_blob_deferred(
                planning,
                payload.sha256(),
                payload.bytes(),
            )?;
        }
        for payload in auxiliary
            .group
            .iter()
            .chain(auxiliary.modules.iter())
            .chain(auxiliary.updateinfo.iter())
        {
            crate::snapshot_store::publish_blob_deferred(
                planning,
                payload.sha256(),
                payload.bytes(),
            )?;
        }
    }
    let origin = generation.origin();
    Ok(PlanningRepository {
        id: repository.id.clone(),
        priority: u32::from(repository.priority),
        cost: repository.cost,
        generation_sha256: generation.digest().into(),
        origin: PlanningOrigin {
            repomd_url: origin.repomd_url().into(),
            sha256: digest(origin.repomd_url().as_bytes()),
        },
        repomd: crate::model::PlanningBytes::from_verified(generation.repomd()),
        primary: crate::model::PlanningBytes::from_verified(generation.primary()),
        filelists: crate::model::PlanningBytes::from_verified(generation.filelists()),
        file_provides: Some(file_provides),
        group: auxiliary
            .group
            .as_ref()
            .map(crate::model::PlanningBytes::from_verified),
        modules: auxiliary
            .modules
            .as_ref()
            .map(crate::model::PlanningBytes::from_verified),
        updateinfo: auxiliary
            .updateinfo
            .as_ref()
            .map(crate::model::PlanningBytes::from_verified),
        trust,
        keys,
        repomd_authentication: generation.repomd_authentication().clone(),
    })
}

fn planning_keys(bundle: &KeyBundle) -> Result<Vec<PlanningKey>, PlanningError> {
    bundle
        .paths
        .iter()
        .zip(&bundle.certificates)
        .map(|(path, certificate)| {
            Ok(PlanningKey {
                bundle_path: path
                    .to_str()
                    .ok_or_else(|| PlanningError::Input("key path is not UTF-8".into()))?
                    .into(),
                certificate_base64: base64::engine::general_purpose::STANDARD.encode(certificate),
            })
        })
        .collect()
}

fn normalized_configuration(
    profile: &MutationProfile,
) -> Result<Vec<PlanningConfiguration>, PlanningError> {
    let mut result = profile
        .repositories
        .iter()
        .map(|repository| PlanningConfiguration {
            id: repository.id.clone(),
            enabled: repository.enabled,
            baseurl: repository.baseurl.clone(),
            metalink: repository.metalink.clone(),
            mirrorlist: repository.mirrorlist.clone(),
            priority: u32::from(repository.priority),
            cost: repository.cost,
            excludes: repository.excludepkgs.clone(),
            includes: repository.includepkgs.clone(),
            gpgkey: repository.gpgkey.clone(),
            allowed_fingerprints: repository.allowed_fingerprints.clone(),
            repo_gpgcheck: repository.repo_gpgcheck,
        })
        .collect::<Vec<_>>();
    result.sort_by(|left, right| left.id.cmp(&right.id));
    if result.windows(2).any(|pair| pair[0].id == pair[1].id) {
        return Err(PlanningError::Input(
            "configuration repository identifiers are duplicate".into(),
        ));
    }
    Ok(result)
}

pub(crate) fn require_same_source_payload(
    expected: &PlanningSnapshot,
    refreshed: &PlanningSnapshot,
) -> Result<(), PlanningError> {
    if expected.payload() == refreshed.payload() {
        Ok(())
    } else {
        Err(PlanningError::Input(
            "root configuration, key bundle, or verified cache generation changed".into(),
        ))
    }
}

pub(crate) fn require_current_snapshot(
    expected: &PlanningSnapshot,
    current: &PlanningSnapshot,
) -> Result<(), PlanningError> {
    if expected == current {
        Ok(())
    } else {
        Err(PlanningError::UnsafeSnapshot(
            "current planning snapshot changed during revalidation".into(),
        ))
    }
}

fn digest(bytes: &[u8]) -> String {
    use sha2::Digest;
    format!("{:x}", sha2::Sha256::digest(bytes))
}

/// ABI-, architecture-, repository-, and immutable-generation-bound libsolv
/// cache key shared by publication prewarming and one-shot planning.
pub fn repository_solv_cache_binding(
    repository: &PlanningRepository,
    architecture: Architecture,
) -> Result<(Vec<u8>, String), PlanningError> {
    repository_solv_cache_binding_from_parts(
        &repository.id,
        &repository.generation_sha256,
        &repository.primary.sha256,
        repository.primary.size,
        architecture,
    )
}

/// Binding for libsolv's filelists extension.  It is independently
/// content-addressed, but also names the exact main cache generation it is
/// allowed to extend so a valid extension can never be paired with a
/// different solvable range.
pub fn repository_filelists_solv_cache_binding(
    repository: &PlanningRepository,
    architecture: Architecture,
) -> Result<(Vec<u8>, String), PlanningError> {
    repository_filelists_solv_cache_binding_from_parts(
        &repository.id,
        &repository.generation_sha256,
        &repository.primary.sha256,
        repository.primary.size,
        &repository.filelists.sha256,
        repository.filelists.size,
        architecture,
    )
}

fn repository_solv_cache_binding_from_parts(
    repository_id: &str,
    generation_sha256: &str,
    primary_sha256: &str,
    primary_size: u64,
    architecture: Architecture,
) -> Result<(Vec<u8>, String), PlanningError> {
    let binding = format!(
        "dnfast-solv-cache-v2\nnative_abi={}\nlibsolv=0.7.39\narchitecture={}\nrepository={}\ngeneration_sha256={}\nprimary_sha256={}\nprimary_size={}\nlimits_validated=true\n",
        dnfast_native_sys::ABI_VERSION,
        architecture.as_rpm_arch(),
        repository_id,
        generation_sha256,
        primary_sha256,
        primary_size,
    )
    .into_bytes();
    if binding.len() > 4096 {
        return Err(PlanningError::Input(
            "solv cache binding exceeds native limit".into(),
        ));
    }
    let sha256 = digest(&binding);
    Ok((binding, sha256))
}

#[allow(clippy::too_many_arguments)]
fn repository_filelists_solv_cache_binding_from_parts(
    repository_id: &str,
    generation_sha256: &str,
    primary_sha256: &str,
    primary_size: u64,
    filelists_sha256: &str,
    filelists_size: u64,
    architecture: Architecture,
) -> Result<(Vec<u8>, String), PlanningError> {
    let (_, main_binding_sha256) = repository_solv_cache_binding_from_parts(
        repository_id,
        generation_sha256,
        primary_sha256,
        primary_size,
        architecture,
    )?;
    let binding = format!(
        "dnfast-solv-filelists-cache-v1\nnative_abi={}\nlibsolv=0.7.39\narchitecture={}\nrepository={}\ngeneration_sha256={}\nmain_binding_sha256={}\nfilelists_sha256={}\nfilelists_size={}\nlimits_validated=true\n",
        dnfast_native_sys::ABI_VERSION,
        architecture.as_rpm_arch(),
        repository_id,
        generation_sha256,
        main_binding_sha256,
        filelists_sha256,
        filelists_size,
    )
    .into_bytes();
    if binding.len() > 4096 {
        return Err(PlanningError::Input(
            "solv filelists cache binding exceeds native limit".into(),
        ));
    }
    let sha256 = digest(&binding);
    Ok((binding, sha256))
}

fn prewarm_repository_generation_solv_cache(
    repository: &RepoConfig,
    generation: &VerifiedCompleteGeneration,
    cache_root: &Path,
    architecture: Architecture,
) -> Result<(), PlanningError> {
    let (binding, binding_sha256) = repository_solv_cache_binding_from_parts(
        &repository.id,
        generation.digest(),
        generation.primary().sha256(),
        generation.primary().size(),
        architecture,
    )?;
    let cache = SolvCache::new(cache_root);
    let mut main_ready = cache_entry_ready(&cache, &binding_sha256)?;
    if main_ready {
        return Ok(());
    }
    // libsolv's writers transiently retain an entire repository pool. Keep
    // repository-level source validation parallel, but do not stack those
    // high-memory native builders in one process.
    static SOLV_BUILD_LIMIT: Mutex<()> = Mutex::new(());
    let _build = SOLV_BUILD_LIMIT
        .lock()
        .map_err(|_| PlanningError::Io("repository solv-cache lock is poisoned".into()))?;
    // A concurrent publisher may have completed the immutable entry while
    // this worker waited for the in-process memory gate.
    main_ready = cache_entry_ready(&cache, &binding_sha256)?;
    if main_ready {
        return Ok(());
    }
    trace_memory(&format!("planning:solv-build-{}-begin", repository.id));
    let records = dnfast_metadata::parse_repomd_records(generation.repomd().bytes())
        .map_err(|error| PlanningError::Input(error.to_string()))?;
    let workspace = tempfile::tempdir().map_err(|error| PlanningError::Io(error.to_string()))?;
    let repomd = workspace.path().join("repomd.xml");
    let primary_path = workspace.path().join("primary.xml");
    let filelists = workspace.path().join("filelists.xml");
    std::fs::write(&repomd, generation.repomd().bytes())
        .map_err(|error| PlanningError::Io(error.to_string()))?;
    let mut primary_output = std::fs::File::create(&primary_path)
        .map_err(|error| PlanningError::Io(error.to_string()))?;
    dnfast_metadata::copy_primary_record_verified(
        generation.primary().bytes(),
        &records.primary,
        &mut primary_output,
    )
    .map_err(|error| PlanningError::Input(error.to_string()))?;
    drop(primary_output);
    std::fs::write(&filelists, []).map_err(|error| PlanningError::Io(error.to_string()))?;
    let path = |value: &Path| {
        value
            .to_str()
            .map(str::to_owned)
            .ok_or_else(|| PlanningError::Input("temporary metadata path is not UTF-8".into()))
    };
    let mut context = dnfast_native::NativeContext::open(architecture, || false)
        .map_err(|error| PlanningError::Input(error.to_string()))?;
    context
        .add_repository_primary(dnfast_native::Repository {
            id: repository.id.clone(),
            repomd_path: path(&repomd)?,
            primary_path: path(&primary_path)?,
            filelists_path: path(&filelists)?,
            priority: i32::from(repository.priority),
            cost: i32::try_from(repository.cost)
                .map_err(|error| PlanningError::Input(error.to_string()))?,
        })
        .map_err(|error| PlanningError::Input(error.to_string()))?;
    let staged = cache
        .stage(&binding_sha256)
        .map_err(|error| PlanningError::Cache(error.to_string()))?;
    context
        .write_repository_solv(&repository.id, staged.file(), &binding)
        .map_err(|error| PlanningError::Input(error.to_string()))?;
    staged
        .commit()
        .map_err(|error| PlanningError::Cache(error.to_string()))?;
    drop(context);
    dnfast_native::release_unused_memory();
    trace_memory(&format!("planning:solv-build-{}-end", repository.id));
    Ok(())
}

fn cache_entry_ready(cache: &SolvCache, binding_sha256: &str) -> Result<bool, PlanningError> {
    match cache.open(binding_sha256) {
        Ok(Some(_)) => Ok(true),
        Ok(None) | Err(CacheError::Corrupt(_)) => Ok(false),
        Err(error) => Err(PlanningError::Cache(error.to_string())),
    }
}

pub fn installed_solv_cache_binding(
    snapshot: &dnfast_native::InventorySnapshot,
    architecture: Architecture,
) -> Result<(Vec<u8>, String), PlanningError> {
    let inventory = snapshot.inventory.canonical_sha256().map_err(domain)?;
    let binding = format!(
        "dnfast-installed-solv-cache-v3\nnative_abi={}\nlibsolv=0.7.39\narchitecture={}\nrpmdb_cookie_size={}\nrpmdb_cookie_sha256={}\ninventory_sha256={}\nlimits_validated=true\n",
        dnfast_native_sys::ABI_VERSION,
        architecture.as_rpm_arch(),
        snapshot.rpmdb_cookie.len(),
        digest(snapshot.rpmdb_cookie.as_bytes()),
        inventory.as_str(),
    )
    .into_bytes();
    if binding.len() > 4096 {
        return Err(PlanningError::Input(
            "installed solv cache binding exceeds native limit".into(),
        ));
    }
    let sha256 = digest(&binding);
    Ok((binding, sha256))
}

fn prewarm_installed_solv_cache(
    context: &mut dnfast_native::NativeContext,
    snapshot: &dnfast_native::InventorySnapshot,
    cache_root: &Path,
    architecture: Architecture,
) -> Result<(), PlanningError> {
    let (binding, binding_sha256) = installed_solv_cache_binding(snapshot, architecture)?;
    let cache = SolvCache::new(cache_root);
    match cache.open(&binding_sha256) {
        Ok(Some(_)) => return Ok(()),
        Ok(None) | Err(CacheError::Corrupt(_)) => {}
        Err(error) => return Err(PlanningError::Cache(error.to_string())),
    }
    context
        .add_installed_rpmdb("/")
        .map_err(|error| PlanningError::Input(error.to_string()))?;
    let staged = cache
        .stage(&binding_sha256)
        .map_err(|error| PlanningError::Cache(error.to_string()))?;
    context
        .write_repository_solv("@System", staged.file(), &binding)
        .map_err(|error| PlanningError::Input(error.to_string()))?;
    staged
        .commit()
        .map_err(|error| PlanningError::Cache(error.to_string()))?;
    trace_memory("planning:installed-solv-cache-prewarmed");
    Ok(())
}

fn prewarm_repository_solv_caches(
    snapshot: &PlanningSnapshot,
    cache_root: &Path,
) -> Result<(), PlanningError> {
    let cache = SolvCache::new(cache_root);
    for (index, repository) in snapshot.payload().allowed_repositories.iter().enumerate() {
        let (binding, binding_sha256) = repository_solv_cache_binding(
            repository,
            snapshot.payload().policy.solver.base_arch(),
        )?;
        let main_ready = cache_entry_ready(&cache, &binding_sha256)?;
        if main_ready {
            continue;
        }
        let repomd_bytes = snapshot.materialize_payload(&repository.repomd)?;
        let primary_bytes = snapshot.materialize_payload(&repository.primary)?;
        let records = dnfast_metadata::parse_repomd_records(&repomd_bytes)
            .map_err(|error| PlanningError::Input(error.to_string()))?;
        let workspace =
            tempfile::tempdir().map_err(|error| PlanningError::Io(error.to_string()))?;
        let repomd = workspace.path().join("repomd.xml");
        let primary = workspace.path().join("primary.xml");
        let filelists = workspace.path().join("filelists.xml");
        std::fs::write(&repomd, &repomd_bytes)
            .map_err(|error| PlanningError::Io(error.to_string()))?;
        let mut primary_output = std::fs::File::create(&primary)
            .map_err(|error| PlanningError::Io(error.to_string()))?;
        dnfast_metadata::copy_primary_record_verified(
            primary_bytes.as_slice(),
            &records.primary,
            &mut primary_output,
        )
        .map_err(|error| PlanningError::Input(error.to_string()))?;
        drop(primary_output);
        std::fs::write(&filelists, []).map_err(|error| PlanningError::Io(error.to_string()))?;
        let path = |value: &Path| {
            value
                .to_str()
                .map(str::to_owned)
                .ok_or_else(|| PlanningError::Input("temporary metadata path is not UTF-8".into()))
        };
        let mut context = dnfast_native::NativeContext::open(
            snapshot.payload().policy.solver.base_arch(),
            || false,
        )
        .map_err(|error| PlanningError::Input(error.to_string()))?;
        context
            .add_repository_primary(dnfast_native::Repository {
                id: repository.id.clone(),
                repomd_path: path(&repomd)?,
                primary_path: path(&primary)?,
                filelists_path: path(&filelists)?,
                priority: i32::try_from(repository.priority)
                    .map_err(|error| PlanningError::Input(error.to_string()))?,
                cost: i32::try_from(repository.cost)
                    .map_err(|error| PlanningError::Input(error.to_string()))?,
            })
            .map_err(|error| PlanningError::Input(error.to_string()))?;
        let staged = cache
            .stage(&binding_sha256)
            .map_err(|error| PlanningError::Cache(error.to_string()))?;
        context
            .write_repository_solv(&repository.id, staged.file(), &binding)
            .map_err(|error| PlanningError::Input(error.to_string()))?;
        staged
            .commit()
            .map_err(|error| PlanningError::Cache(error.to_string()))?;
        drop(context);
        dnfast_native::release_unused_memory();
        trace_memory(&format!("planning:solv-cache-{index}-prewarmed"));
    }
    Ok(())
}
fn require_root() -> Result<(), PlanningError> {
    if geteuid().as_raw() == 0 {
        Ok(())
    } else {
        Err(PlanningError::NotRoot)
    }
}
fn domain(error: dnfast_core::DomainError) -> PlanningError {
    PlanningError::Input(error.to_string())
}
