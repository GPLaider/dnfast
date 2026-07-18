use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    rc::Rc,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use dnfast_cache::{
    ArtifactCache, ArtifactError, ArtifactResponse, ArtifactSpec, ArtifactTransport, Digest,
    TransactionRequest,
};
use dnfast_core::{RepoTrustPolicy, SigningSubkeyRule};
use dnfast_native::{
    ExecutorInventory, ExpectedPackage, InventoryError, InventoryReader, KeyringInstalled,
};
use dnfast_state::{FaultPlan, FaultPoint, JournalStore, TransactionId, TransactionState};

struct FileTransport(PathBuf);
impl ArtifactTransport for FileTransport {
    fn open(&self, _: &str) -> Result<ArtifactResponse, ArtifactError> {
        Ok(ArtifactResponse {
            status: 200,
            body: Box::new(
                fs::File::open(&self.0)
                    .map_err(|error| ArtifactError::Transport(error.to_string()))?,
            ),
        })
    }
}

fn private(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let (key_source, rpm_source, digest) = (&args[0], &args[1], &args[2]);
    let root = PathBuf::from(format!(
        "/dev/shm/dnfast-journal-probe-{}",
        std::process::id()
    ));
    let repo = format!("journal-{}", std::process::id());
    private(Path::new("/etc/dnfast"))?;
    private(Path::new("/etc/dnfast/keys"))?;
    let keys = PathBuf::from("/etc/dnfast/keys").join(&repo);
    private(&keys)?;
    let key = keys.join("allowed.asc");
    fs::copy(key_source, &key)?;
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600))?;
    let bundle = dnfast_repo::key_bundle_digest(&repo, std::slice::from_ref(&key))?;
    let policy = RepoTrustPolicy::new(
        &repo,
        hex::encode(bundle.digest),
        vec!["2B017A94136265DB56C0CCD6DF21D1EED6503531".into()],
        SigningSubkeyRule::AuthorizedSubkeys,
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
    )?;
    let size = fs::metadata(rpm_source)?.len();
    let spec = ArtifactSpec::new(
        "https://fixture.invalid/",
        "https://fixture.invalid/",
        "package.rpm",
        Digest::Sha256(digest.clone()),
        size,
    )?;
    let request = TransactionRequest::for_specs(std::slice::from_ref(&spec))?;
    let cache = ArtifactCache::new(root.join("cache"));
    let mut cache_tx = cache.begin_transaction(&request)?;
    let artifact = cache_tx.fetch(&spec, &FileTransport(rpm_source.into()))?;
    let keyring = KeyringInstalled::from_repository(&policy, &repo, std::slice::from_ref(&key))?;
    let verified = keyring.verify_artifact(
        &artifact,
        &ExpectedPackage {
            name: "dnfast-noarch".into(),
            epoch: 0,
            version: "1.0".into(),
            release: "1".into(),
            arch: "noarch".into(),
            vendor: "unknown".into(),
        },
        SigningSubkeyRule::AuthorizedSubkeys,
    )?;
    let mut reader = InventoryReader::open(dnfast_core::Architecture::Aarch64)?;
    let before = reader.read()?;

    let faults = Arc::new(FaultPlan::none());
    let failed_store = JournalStore::with_faults(&root.join("failed"), Arc::clone(&faults))?;
    let failed_id = TransactionId::parse("01890f6e-7b2c-7cc0-98c4-dc0c0c07398f")?;
    let failed = Rc::new(failed_store.create(&failed_id, digest)?);
    faults.arm(FaultPoint::Write);
    let mut rejected = ExecutorInventory::begin(
        dnfast_core::Architecture::Aarch64,
        KeyringInstalled::from_repository(&policy, &repo, std::slice::from_ref(&key))?,
        &before,
    )?;
    rejected.add_install(
        &artifact,
        &verified,
        dnfast_native::TransactionInstallMode::Install,
    )?;
    rejected.bind_journal(Rc::clone(&failed))?;
    rejected.prepare_checked_transaction()?;
    rejected.test_checked_transaction()?;
    assert!(matches!(
        rejected.run_checked_transaction(),
        Err(InventoryError::TransactionPreflight { .. } | InventoryError::Native(_))
    ));
    assert_eq!(rejected.transaction_counts().real_run, 0);
    assert_eq!(
        failed.entries()?.last().unwrap().state,
        TransactionState::Prepared
    );
    drop(rejected);

    let store = JournalStore::open(&root.join("success"))?;
    let id = TransactionId::parse("01890f6e-7b2c-7cc0-98c4-dc0c0c073990")?;
    let journal = Rc::new(store.create(&id, digest)?);
    let mut execution =
        ExecutorInventory::begin(dnfast_core::Architecture::Aarch64, keyring, &before)?;
    execution.add_install(
        &artifact,
        &verified,
        dnfast_native::TransactionInstallMode::Install,
    )?;
    execution.bind_journal(Rc::clone(&journal))?;
    execution.prepare_checked_transaction()?;
    assert!(execution.fixture_authority_is_held());
    execution.test_checked_transaction()?;
    assert!(execution.fixture_authority_is_held());
    execution.run_checked_transaction()?;
    assert!(execution.fixture_authority_is_held());
    execution.verify_transaction_db()?;
    assert!(execution.fixture_authority_is_held());
    execution.reconcile()?;
    assert!(execution.fixture_authority_is_held());
    let entries = journal.entries()?;
    assert_eq!(execution.transaction_counts().real_run, 1);
    assert_eq!(entries[1].state, TransactionState::Started);
    assert_eq!(entries[2].state, TransactionState::RpmResult);
    assert_eq!(entries[3].state, TransactionState::Reconciled);
    println!(
        "journal_abort_real0=true durable_started_before_real=true result_after_real=true authority_all_phases={}",
        execution.fixture_authority_is_held()
    );
    drop(execution);
    let after = reader.read()?;
    let mut replacement = ExecutorInventory::begin(
        dnfast_core::Architecture::Aarch64,
        KeyringInstalled::from_repository(&policy, &repo, std::slice::from_ref(&key))?,
        &after,
    )?;
    replacement.request_cancel()?;
    println!("authority_released_after_write_end=true");
    fs::remove_dir_all(root)?;
    fs::remove_dir_all(keys)?;
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
