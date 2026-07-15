use std::sync::{
    Arc, Mutex, OnceLock,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};
use std::{collections::BTreeSet, rc::Rc};

use dnfast_core::{
    Architecture, CanonicalDocument, EraseLookupError, Evra, InstalledInventory, InstalledPackage,
};
use thiserror::Error;

use crate::{NativeError, TransactionProblem};

const LOCK_TIMEOUT: Duration = Duration::from_secs(30);
const AUTHORITY_NAME: &[u8] = b"dnfast-transaction-v1";
const ADDRESS_IN_USE: i32 = 98;

#[derive(Debug, Error)]
pub enum InventoryError {
    #[error(transparent)]
    Native(#[from] NativeError),
    #[error("invalid installed package: {0}")]
    Domain(#[from] dnfast_core::DomainError),
    #[error("unsupported installed architecture: {0}")]
    Architecture(String),
    #[error("transaction authority failed: errno {0}")]
    Lock(i32),
    #[error("transaction lock deadline exceeded")]
    LockTimeout,
    #[error("transaction wait interrupted before start")]
    Interrupted,
    #[error("installed RPM inventory changed after solve")]
    StaleInventory,
    #[error("RPMDB cookie did not change after a successful mutating transaction")]
    UnchangedCookie,
    #[error("post-transaction RPM identities differ: expected={expected}; actual={actual}")]
    PostTransactionIdentity { expected: String, actual: String },
    #[error("invalid executor state transition")]
    InvalidState,
    #[error("cancellation is too late after transaction start")]
    TooLate,
    #[error("RPM TEST transaction failed with result {0}")]
    TestFailed(i32),
    #[error("checked RPM transaction preflight failed")]
    TransactionPreflight { problems: Vec<TransactionProblem> },
    #[error("real RPM transaction failed after its write boundary")]
    PotentiallyStateful {
        problems: Vec<TransactionProblem>,
        journal_error: Option<String>,
    },
    #[error("installed erase identity changed: {0}")]
    EraseIdentity(#[from] EraseLookupError),
    #[error("invalid installed immutable-header digest")]
    HeaderDigest,
    #[error("invalid native RPM problem list")]
    ProblemList,
    #[error("transaction journal failed: {0}")]
    Journal(String),
    #[error("unsafe RPM database root")]
    UnsafeRoot,
}

pub struct InventoryReader {
    context: crate::NativeContext,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InventorySnapshot {
    pub inventory: InstalledInventory,
    pub rpmdb_cookie: String,
}

#[derive(Clone)]
struct CachedInventory {
    cookie: String,
    inventory: InstalledInventory,
}

static INVENTORY_CACHE: OnceLock<Mutex<Option<CachedInventory>>> = OnceLock::new();

impl InventoryReader {
    pub fn open(architecture: Architecture) -> Result<Self, InventoryError> {
        Ok(Self {
            context: crate::NativeContext::open(architecture, || false)?,
        })
    }

    pub fn read(&mut self) -> Result<InstalledInventory, InventoryError> {
        self.context.read_installed_inventory()
    }

    pub fn read_snapshot(&mut self) -> Result<InventorySnapshot, InventoryError> {
        self.context.read_installed_inventory_snapshot()
    }
}

pub struct KeyringInstalled {
    pub(crate) native: dnfast_native_sys::Keyring,
    pub(crate) allowed_primary_fingerprints: Vec<String>,
}

impl KeyringInstalled {
    #[cfg(feature = "test-fixtures")]
    pub fn fixture() -> Result<Self, InventoryError> {
        Ok(Self {
            native: dnfast_native_sys::Keyring::fixture().map_err(NativeError::from)?,
            allowed_primary_fingerprints: Vec::new(),
        })
    }
}

pub struct ExecutorInventory {
    pub(crate) context: dnfast_native_sys::Context,
    pub(crate) _keyring: KeyringInstalled,
    authority: Option<dnfast_native_sys::Authority>,
    pub(crate) inventory: InstalledInventory,
    pub(crate) state: ExecutionState,
    pub(crate) journal: Option<Rc<dnfast_state::TransactionJournal>>,
    rpmdb_cookie: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionState {
    Prepared,
    Tested,
    TestFailed(i32),
    Started,
    Reconciled,
    Cancelled,
}

impl ExecutorInventory {
    pub fn begin(
        architecture: Architecture,
        keyring: KeyringInstalled,
        expected: &InstalledInventory,
    ) -> Result<Self, InventoryError> {
        Self::begin_at_root(architecture, keyring, expected, "/")
    }

    pub fn begin_at_root(
        architecture: Architecture,
        keyring: KeyringInstalled,
        expected: &InstalledInventory,
        root: &str,
    ) -> Result<Self, InventoryError> {
        Self::begin_controlled(
            architecture,
            keyring,
            expected,
            None,
            root,
            LOCK_TIMEOUT,
            Arc::new(AtomicBool::new(false)),
        )
    }

    pub fn begin_at_root_with_cookie(
        architecture: Architecture,
        keyring: KeyringInstalled,
        expected: &InstalledInventory,
        expected_cookie: &str,
        root: &str,
    ) -> Result<Self, InventoryError> {
        if expected_cookie.is_empty() {
            return Err(InventoryError::StaleInventory);
        }
        Self::begin_controlled(
            architecture,
            keyring,
            expected,
            Some(expected_cookie),
            root,
            LOCK_TIMEOUT,
            Arc::new(AtomicBool::new(false)),
        )
    }

    pub fn begin_interruptible(
        architecture: Architecture,
        keyring: KeyringInstalled,
        expected: &InstalledInventory,
        interrupted: Arc<AtomicBool>,
    ) -> Result<Self, InventoryError> {
        Self::begin_controlled(
            architecture,
            keyring,
            expected,
            None,
            "/",
            LOCK_TIMEOUT,
            interrupted,
        )
    }

    pub fn inventory(&self) -> &InstalledInventory {
        &self.inventory
    }
    pub fn rpm_run_count(&self) -> u64 {
        self.context.rpm_run_count()
    }
    pub fn run_counts(&self) -> (u64, u64) {
        self.context.run_counts()
    }
    pub fn state(&self) -> ExecutionState {
        self.state
    }
    pub fn native_call_order(&self) -> (u64, u64) {
        self.context.inventory_call_order()
    }

    #[cfg(feature = "test-fixtures")]
    pub fn fixture_authority_is_held(&self) -> bool {
        matches!(
            dnfast_native_sys::Authority::acquire(AUTHORITY_NAME),
            Err(ADDRESS_IN_USE)
        )
    }

    pub fn test_transaction(&mut self) -> Result<i32, InventoryError> {
        if self.state != ExecutionState::Prepared {
            return Err(InventoryError::InvalidState);
        }
        let result = self.context.test_run().map_err(NativeError::from)?;
        if result == 0 {
            self.state = ExecutionState::Tested;
            Ok(result)
        } else {
            self.context.end_inventory_write();
            self.authority.take();
            self.state = ExecutionState::TestFailed(result);
            Err(InventoryError::TestFailed(result))
        }
    }

    pub fn run_transaction(&mut self) -> Result<i32, InventoryError> {
        if self.state != ExecutionState::Tested {
            return Err(InventoryError::InvalidState);
        }
        self.state = ExecutionState::Started;
        self.context
            .run()
            .map_err(NativeError::from)
            .map_err(InventoryError::from)
    }

    pub fn request_cancel(&mut self) -> Result<(), InventoryError> {
        match self.state {
            ExecutionState::Prepared | ExecutionState::Tested => {
                self.context.end_inventory_write();
                self.authority.take();
                self.state = ExecutionState::Cancelled;
                Ok(())
            }
            ExecutionState::Started => Err(InventoryError::TooLate),
            ExecutionState::TestFailed(_)
            | ExecutionState::Reconciled
            | ExecutionState::Cancelled => Err(InventoryError::InvalidState),
        }
    }

    pub fn reconcile(&mut self) -> Result<&InstalledInventory, InventoryError> {
        self.reconcile_with_success(true, None, None)
    }

    pub fn reconcile_selected(
        &mut self,
        changed_names: &[String],
    ) -> Result<&InstalledInventory, InventoryError> {
        self.reconcile_with_success(true, Some(changed_names), None)
    }

    pub fn reconcile_selected_expected(
        &mut self,
        changed_names: &[String],
        expected_identities: &[(String, Evra, String)],
    ) -> Result<&InstalledInventory, InventoryError> {
        self.reconcile_with_success(true, Some(changed_names), Some(expected_identities))
    }

    pub fn reconcile_after_failure(&mut self) -> Result<&InstalledInventory, InventoryError> {
        self.reconcile_with_success(false, None, None)
    }

    fn reconcile_with_success(
        &mut self,
        success: bool,
        changed_names: Option<&[String]>,
        expected_identities: Option<&[(String, Evra, String)]>,
    ) -> Result<&InstalledInventory, InventoryError> {
        if self.state != ExecutionState::Started {
            return Err(InventoryError::InvalidState);
        }
        let before = self.inventory.to_canonical_json()?;
        let (inventory, post_cookie) = match changed_names {
            Some(names) => {
                let snapshot = read_locked_selected(&mut self.context, &self.inventory, names)?;
                if self.rpmdb_cookie.as_deref() == Some(snapshot.rpmdb_cookie.as_str()) {
                    return Err(InventoryError::UnchangedCookie);
                }
                (snapshot.inventory, Some(snapshot.rpmdb_cookie))
            }
            None if success => (read_locked(&mut self.context)?, None),
            None => (read_locked_uncached(&mut self.context)?, None),
        };
        if let (Some(names), Some(expected)) = (changed_names, expected_identities) {
            let changed = names.iter().map(String::as_str).collect::<BTreeSet<_>>();
            let mut actual = inventory
                .packages()
                .iter()
                .filter(|package| changed.contains(package.name()))
                .map(|package| {
                    (
                        package.name().to_owned(),
                        package.evra().clone(),
                        package.vendor().to_owned(),
                    )
                })
                .collect::<Vec<_>>();
            let mut expected = expected.to_vec();
            for (_, _, vendor) in &mut actual {
                if vendor == "unknown" {
                    vendor.clear();
                }
            }
            actual.sort();
            expected.sort();
            if actual != expected {
                return Err(InventoryError::PostTransactionIdentity {
                    expected: format_identities(&expected),
                    actual: format_identities(&actual),
                });
            }
        }
        let after = inventory.to_canonical_json()?;
        if let Some(journal) = &self.journal {
            use sha2::{Digest as _, Sha256};
            journal
                .reconcile(dnfast_state::ReconcileResult {
                    inventory_sha256: hex::encode(Sha256::digest(&after)),
                    success,
                    changed_packages: u64::from(before != after),
                })
                .map_err(|error| InventoryError::Journal(error.to_string()))?;
        }
        self.inventory = inventory;
        if post_cookie.is_some() {
            self.rpmdb_cookie = post_cookie;
        }
        self.state = ExecutionState::Reconciled;
        Ok(&self.inventory)
    }

    #[cfg(feature = "test-fixtures")]
    pub fn fixture_fail_next_test(&mut self) {
        self.context.fixture_fail_next_test();
    }

    fn begin_controlled(
        architecture: Architecture,
        _keyring: KeyringInstalled,
        expected: &InstalledInventory,
        expected_cookie: Option<&str>,
        root: &str,
        timeout: Duration,
        interrupted: Arc<AtomicBool>,
    ) -> Result<Self, InventoryError> {
        if rustix::process::geteuid().as_raw() != 0 {
            return Err(InventoryError::Native(NativeError::PermissionDenied));
        }
        if !safe_root(root) {
            return Err(InventoryError::UnsafeRoot);
        }
        let started_at = Instant::now();
        let authority = acquire_authority(timeout, &mut || interrupted.load(Ordering::Acquire))?;
        let native_interrupt = interrupted.clone();
        let mut context = open_executor_context(architecture, move || {
            native_interrupt.load(Ordering::Acquire)
        })?;
        let remaining = timeout.saturating_sub(Instant::now().duration_since(started_at));
        match context
            .begin_inventory_write(&_keyring.native, root, remaining)
            .map_err(NativeError::from)
        {
            Ok(()) => {}
            Err(NativeError::LockTimeout) => return Err(InventoryError::LockTimeout),
            Err(NativeError::Interrupted) => return Err(InventoryError::Interrupted),
            Err(error) => return Err(InventoryError::Native(error)),
        }
        let inventory = match expected_cookie {
            Some(cookie) => read_locked_cookie_bound(&mut context, cookie, expected)?,
            None => read_locked(&mut context)?,
        };
        if expected_cookie.is_none()
            && inventory.to_canonical_json()? != expected.to_canonical_json()?
        {
            context.end_inventory_write();
            return Err(InventoryError::StaleInventory);
        }
        Ok(Self {
            context,
            _keyring,
            authority: Some(authority),
            inventory,
            state: ExecutionState::Prepared,
            journal: None,
            rpmdb_cookie: expected_cookie.map(str::to_owned),
        })
    }
}

fn open_executor_context(
    architecture: Architecture,
    interrupt: impl FnMut() -> bool + 'static,
) -> Result<dnfast_native_sys::Context, InventoryError> {
    let pool = crate::pool_architecture(architecture)?;
    dnfast_native_sys::Context::open(pool, interrupt)
        .map_err(NativeError::from)
        .map_err(InventoryError::from)
}

fn safe_root(root: &str) -> bool {
    root.starts_with('/') && root.split('/').all(|part| part != "..")
}

impl Drop for ExecutorInventory {
    fn drop(&mut self) {
        self.context.end_inventory_write();
    }
}

pub(crate) fn read_from_context(
    context: &mut dnfast_native_sys::Context,
) -> Result<InstalledInventory, InventoryError> {
    read_snapshot_from_context(context).map(|snapshot| snapshot.inventory)
}

pub(crate) fn read_snapshot_from_context(
    context: &mut dnfast_native_sys::Context,
) -> Result<InventorySnapshot, InventoryError> {
    let mut cache = inventory_cache();
    let expected = cache.as_ref().map(|cached| cached.cookie.as_str());
    let read = context
        .read_inventory_cached("/", expected)
        .map_err(NativeError::from)?;
    let cookie = read.cookie.clone();
    let inventory = finish_cached_read(&mut cache, read)?;
    Ok(InventorySnapshot {
        inventory,
        rpmdb_cookie: cookie,
    })
}

fn read_locked(
    context: &mut dnfast_native_sys::Context,
) -> Result<InstalledInventory, InventoryError> {
    let mut cache = inventory_cache();
    let expected = cache.as_ref().map(|cached| cached.cookie.as_str());
    let read = context
        .read_locked_inventory_cached(expected)
        .map_err(NativeError::from)?;
    finish_cached_read(&mut cache, read)
}

fn read_locked_uncached(
    context: &mut dnfast_native_sys::Context,
) -> Result<InstalledInventory, InventoryError> {
    let read = context
        .read_locked_inventory_cached(None)
        .map_err(NativeError::from)?;
    let mut cache = inventory_cache();
    finish_cached_read(&mut cache, read)
}

fn format_identities(identities: &[(String, Evra, String)]) -> String {
    identities
        .iter()
        .map(|(name, evra, vendor)| {
            format!(
                "{name}-{}:{}-{}.{} vendor={vendor:?}",
                evra.epoch(),
                evra.version(),
                evra.release(),
                evra.arch().as_rpm_arch()
            )
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn read_locked_cookie_bound(
    context: &mut dnfast_native_sys::Context,
    expected_cookie: &str,
    expected: &InstalledInventory,
) -> Result<InstalledInventory, InventoryError> {
    let read = context
        .read_locked_inventory_cached(Some(expected_cookie))
        .map_err(NativeError::from)?;
    if read.cookie != expected_cookie || read.inventory.is_some() {
        context.end_inventory_write();
        return Err(InventoryError::StaleInventory);
    }
    let mut cache = inventory_cache();
    *cache = Some(CachedInventory {
        cookie: expected_cookie.into(),
        inventory: expected.clone(),
    });
    Ok(expected.clone())
}

fn read_locked_selected(
    context: &mut dnfast_native_sys::Context,
    before: &InstalledInventory,
    changed_names: &[String],
) -> Result<InventorySnapshot, InventoryError> {
    if changed_names.is_empty() || changed_names.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(InventoryError::InvalidState);
    }
    let names = changed_names.iter().map(String::as_str).collect::<Vec<_>>();
    let read = context
        .read_locked_inventory_selected(&names)
        .map_err(NativeError::from)?;
    let cookie = read.cookie;
    let selected = convert(read.inventory.ok_or(InventoryError::InvalidState)?)?;
    if selected.rpmdb_backend() != before.rpmdb_backend()
        || selected.rpm_version() != before.rpm_version()
    {
        return Err(InventoryError::InvalidState);
    }
    let changed = changed_names
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if selected
        .packages()
        .iter()
        .any(|package| !changed.contains(package.name()))
    {
        return Err(InventoryError::InvalidState);
    }
    let mut packages = before
        .packages()
        .iter()
        .filter(|package| !changed.contains(package.name()))
        .cloned()
        .collect::<Vec<_>>();
    packages.extend_from_slice(selected.packages());
    let inventory =
        InstalledInventory::new(before.rpmdb_backend(), before.rpm_version(), packages)?;
    inventory.canonical_sha256()?;
    *inventory_cache() = Some(CachedInventory {
        cookie: cookie.clone(),
        inventory: inventory.clone(),
    });
    Ok(InventorySnapshot {
        inventory,
        rpmdb_cookie: cookie,
    })
}

fn inventory_cache() -> std::sync::MutexGuard<'static, Option<CachedInventory>> {
    INVENTORY_CACHE
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn finish_cached_read(
    cache: &mut Option<CachedInventory>,
    read: dnfast_native_sys::InventoryRead,
) -> Result<InstalledInventory, InventoryError> {
    if let Some(raw) = read.inventory {
        let inventory = convert(raw)?;
        inventory.canonical_sha256()?;
        *cache = Some(CachedInventory {
            cookie: read.cookie,
            inventory: inventory.clone(),
        });
        return Ok(inventory);
    }
    match cache {
        Some(cached) if cached.cookie == read.cookie => Ok(cached.inventory.clone()),
        _ => Err(InventoryError::InvalidState),
    }
}

fn convert(raw: dnfast_native_sys::Inventory) -> Result<InstalledInventory, InventoryError> {
    let packages = raw
        .packages
        .into_iter()
        .map(|package| {
            let arch = match package.arch.as_str() {
                "aarch64" => Architecture::Aarch64,
                "x86_64" => Architecture::X86_64,
                "noarch" => Architecture::Noarch,
                other => return Err(InventoryError::Architecture(other.into())),
            };
            InstalledPackage::new(
                package.name,
                Evra::new(package.epoch, package.version, package.release, arch),
                package.vendor,
                package.db_instance,
                package.install_time,
                package.immutable_header_sha256,
            )
            .map_err(InventoryError::from)
        })
        .collect::<Result<Vec<_>, _>>()?;
    InstalledInventory::new(raw.backend, raw.rpm_version, packages).map_err(InventoryError::from)
}

fn acquire_authority(
    timeout: Duration,
    interrupted: &mut impl FnMut() -> bool,
) -> Result<dnfast_native_sys::Authority, InventoryError> {
    let started = Instant::now();
    loop {
        if interrupted() {
            return Err(InventoryError::Interrupted);
        }
        match dnfast_native_sys::Authority::acquire(AUTHORITY_NAME) {
            Ok(authority) => return Ok(authority),
            Err(ADDRESS_IN_USE) if started.elapsed() < timeout => {
                std::thread::sleep(Duration::from_millis(10))
            }
            Err(ADDRESS_IN_USE) => return Err(InventoryError::LockTimeout),
            Err(error) => return Err(InventoryError::Lock(error)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn abstract_authority_contention_deadline_release_and_alias_immunity() {
        let _serial = SERIAL.lock().unwrap();
        assert_eq!(LOCK_TIMEOUT, Duration::from_secs(30));
        let first = dnfast_native_sys::Authority::acquire(AUTHORITY_NAME).unwrap();
        let started = Instant::now();
        assert!(matches!(
            acquire_authority(Duration::from_millis(40), &mut || false),
            Err(InventoryError::LockTimeout)
        ));
        assert!(started.elapsed() >= Duration::from_millis(40));
        assert!(dnfast_native_sys::Authority::acquire(b"dnfast-transaction-v1/../alias").is_ok());
        drop(first);
        assert!(acquire_authority(Duration::from_millis(20), &mut || false).is_ok());
    }

    #[test]
    fn interruption_only_applies_while_waiting() {
        let _serial = SERIAL.lock().unwrap();
        let held = dnfast_native_sys::Authority::acquire(AUTHORITY_NAME).unwrap();
        assert!(matches!(
            acquire_authority(Duration::from_secs(1), &mut || true),
            Err(InventoryError::Interrupted)
        ));
        drop(held);
    }

    #[test]
    fn fork_child_cannot_release_parent_authority() {
        dnfast_native_sys::authority_fork_probe(b"dnfast-inventory-fork").unwrap();
    }

    #[test]
    fn authority_holder_process() {
        let Ok(ready) = std::env::var("DNFAST_AUTHORITY_READY") else {
            return;
        };
        let _authority =
            dnfast_native_sys::Authority::acquire(b"dnfast-inventory-sigkill").unwrap();
        std::fs::write(ready, b"ready").unwrap();
        std::thread::sleep(Duration::from_secs(60));
    }

    #[test]
    fn sigkill_releases_kernel_authority() {
        let temp = tempfile::tempdir().unwrap();
        let ready = temp.path().join("ready");
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "inventory::tests::authority_holder_process"])
            .env("DNFAST_AUTHORITY_READY", &ready)
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while !ready.exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(ready.exists());
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(dnfast_native_sys::Authority::acquire(b"dnfast-inventory-sigkill").is_ok());
    }

    #[test]
    fn x86_64_inventory_headers_preserve_the_canonical_architecture() {
        let raw = dnfast_native_sys::Inventory {
            backend: "sqlite".into(),
            rpm_version: "6.0.1".into(),
            packages: vec![dnfast_native_sys::InventoryPackage {
                name: "bash".into(),
                version: "5.2".into(),
                release: "1.fc44".into(),
                arch: "x86_64".into(),
                vendor: "Fedora".into(),
                epoch: 0,
                db_instance: 1,
                install_time: 1,
                immutable_header_sha256: "a".repeat(64),
            }],
        };
        let inventory = convert(raw).unwrap();
        assert_eq!(inventory.packages()[0].evra().arch(), Architecture::X86_64);
        assert!(
            String::from_utf8(inventory.to_canonical_json().unwrap())
                .unwrap()
                .contains("x86_64")
        );
    }

    #[test]
    fn executor_context_when_x86_64_opens_an_x86_64_native_pool() {
        // Given: an executor transaction authorized by an x86_64 policy.
        // When: its native transaction context is created.
        let context = open_executor_context(Architecture::X86_64, || false).unwrap();
        // Then: libsolv receives x86_64 rather than an executor-local default.
        assert_eq!(
            context.pool_architecture().unwrap(),
            dnfast_native_sys::PoolArchitecture::X86_64
        );
    }
}
