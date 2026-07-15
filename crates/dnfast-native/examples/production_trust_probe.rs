use std::{
    fs,
    io::{Read, Seek, SeekFrom, Write},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use dnfast_cache::{
    ArtifactCache, ArtifactResponse, ArtifactSpec, ArtifactTransport, Digest, TransactionRequest,
};
use dnfast_core::{CanonicalDocument, RepoTrustPolicy, SigningSubkeyRule};
use dnfast_native::{ExecutorInventory, ExpectedPackage, InventoryReader, KeyringInstalled};
use sha2::{Digest as _, Sha256};

struct FileTransport {
    path: PathBuf,
}

impl ArtifactTransport for FileTransport {
    fn open(&self, _url: &str) -> Result<ArtifactResponse, dnfast_cache::ArtifactError> {
        let file = fs::File::open(&self.path)
            .map_err(|error| dnfast_cache::ArtifactError::Transport(error.to_string()))?;
        Ok(ArtifactResponse {
            status: 200,
            body: Box::new(file),
        })
    }
}

fn private_dir(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn rejected_mutation(
    keyring: &KeyringInstalled,
    path: &Path,
    label: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let bytes = fs::read(path)?;
    let digest = hex::encode(Sha256::digest(&bytes));
    let cache_root = PathBuf::from(format!(
        "/dev/shm/dnfast-task12-{label}-{}",
        std::process::id()
    ));
    private_dir(&cache_root)?;
    let size = u64::try_from(bytes.len())?;
    let spec = ArtifactSpec::new(
        "https://fixture.invalid/",
        "https://fixture.invalid/",
        "mutated.rpm",
        Digest::Sha256(digest),
        size,
    )?;
    let request = TransactionRequest::for_specs(std::slice::from_ref(&spec))?;
    let cache = ArtifactCache::new(&cache_root);
    let mut transaction = cache.begin_transaction(&request)?;
    let artifact = transaction.fetch(&spec, &FileTransport { path: path.into() })?;
    let retained_root = cache_root.with_extension("retained");
    fs::rename(&cache_root, &retained_root)?;
    private_dir(&cache_root)?;
    let expected = ExpectedPackage {
        name: "dnfast-app".into(),
        epoch: 0,
        version: "1.0".into(),
        release: "1".into(),
        arch: "noarch".into(),
        vendor: "unknown".into(),
    };
    if keyring
        .verify_artifact(&artifact, &expected, SigningSubkeyRule::AuthorizedSubkeys)
        .is_ok()
    {
        return Err(format!("{label} mutation accepted").into());
    }
    fs::remove_dir_all(&cache_root)?;
    fs::remove_dir_all(&retained_root)?;
    println!("mutation_{label}=rejected retained_fd=true");
    Ok(())
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let source_key = PathBuf::from(args.next().ok_or("missing key")?);
    let source_rpm = PathBuf::from(args.next().ok_or("missing rpm")?);
    let rpm_digest = args.next().ok_or("missing digest")?;
    let repo_id = format!("task12-{}", std::process::id());
    let key_root = PathBuf::from("/etc/dnfast/keys").join(&repo_id);
    private_dir(Path::new("/etc/dnfast"))?;
    private_dir(Path::new("/etc/dnfast/keys"))?;
    private_dir(&key_root)?;
    let key_path = key_root.join("00-allowed.asc");
    fs::copy(&source_key, &key_path)?;
    fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))?;
    let paths = vec![key_path.clone()];
    let bundle = dnfast_repo::key_bundle_digest(&repo_id, &paths)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let policy = RepoTrustPolicy::new(
        &repo_id,
        hex::encode(bundle.digest),
        vec!["2B017A94136265DB56C0CCD6DF21D1EED6503531".into()],
        SigningSubkeyRule::AuthorizedSubkeys,
        now,
    )?;
    let symlink_path = key_root.join("symlink.asc");
    std::os::unix::fs::symlink(&key_path, &symlink_path)?;
    if KeyringInstalled::from_repository(&policy, &repo_id, &[symlink_path.clone()]).is_ok() {
        return Err("key symlink accepted".into());
    }
    fs::remove_file(&symlink_path)?;
    let hardlink_path = key_root.join("hardlink.asc");
    fs::hard_link(&key_path, &hardlink_path)?;
    if KeyringInstalled::from_repository(&policy, &repo_id, &paths).is_ok() {
        return Err("key hardlink accepted".into());
    }
    fs::remove_file(&hardlink_path)?;
    let second_path = key_root.join("01-allowed.asc");
    fs::copy(&source_key, &second_path)?;
    fs::set_permissions(&second_path, fs::Permissions::from_mode(0o600))?;
    let ordered = vec![key_path.clone(), second_path.clone()];
    let ordered_bundle = dnfast_repo::key_bundle_digest(&repo_id, &ordered)?;
    let ordered_policy = RepoTrustPolicy::new(
        &repo_id,
        hex::encode(ordered_bundle.digest),
        vec!["2B017A94136265DB56C0CCD6DF21D1EED6503531".into()],
        SigningSubkeyRule::AuthorizedSubkeys,
        now,
    )?;
    if KeyringInstalled::from_repository(
        &ordered_policy,
        &repo_id,
        &[second_path.clone(), key_path.clone()],
    )
    .is_ok()
    {
        return Err("key order mismatch accepted".into());
    }
    fs::remove_file(&second_path)?;
    let moved_root = key_root.with_extension("moved");
    fs::rename(&key_root, &moved_root)?;
    std::os::unix::fs::symlink(&moved_root, &key_root)?;
    if KeyringInstalled::from_repository(&policy, &repo_id, &paths).is_ok() {
        return Err("key ancestor swap accepted".into());
    }
    fs::remove_file(&key_root)?;
    fs::rename(&moved_root, &key_root)?;
    let cache_root = PathBuf::from(format!(
        "/dev/shm/dnfast-task12-cache-{}",
        std::process::id()
    ));
    private_dir(&cache_root)?;
    let size = fs::metadata(&source_rpm)?.len();
    let spec = ArtifactSpec::new(
        "https://fixture.invalid/",
        "https://fixture.invalid/",
        "dnfast-app.rpm",
        Digest::Sha256(rpm_digest),
        size,
    )?;
    let request = TransactionRequest::for_specs(std::slice::from_ref(&spec))?;
    let cache = ArtifactCache::new(&cache_root);
    let mut transaction = cache.begin_transaction(&request)?;
    let artifact = transaction.fetch(
        &spec,
        &FileTransport {
            path: source_rpm.clone(),
        },
    )?;
    let old_tree = cache_root.with_extension("retained");
    fs::rename(&cache_root, &old_tree)?;
    private_dir(&cache_root)?;
    let mut retained = artifact.file();
    retained.seek(SeekFrom::End(-1))?;
    let keyring = KeyringInstalled::from_repository(&policy, &repo_id, &paths)?;
    let verified = keyring.verify_artifact(
        &artifact,
        &ExpectedPackage {
            name: "dnfast-app".into(),
            epoch: 0,
            version: "1.0".into(),
            release: "1".into(),
            arch: "noarch".into(),
            vendor: "unknown".into(),
        },
        policy.signing_subkey_rule(),
    )?;
    let mutation_root = PathBuf::from(format!(
        "/dev/shm/dnfast-task12-mutations-{}",
        std::process::id()
    ));
    private_dir(&mutation_root)?;
    let truncated = mutation_root.join("truncated.rpm");
    fs::copy(&source_rpm, &truncated)?;
    let original_size = fs::metadata(&truncated)?.len();
    fs::OpenOptions::new()
        .write(true)
        .open(&truncated)?
        .set_len(original_size - 1)?;
    rejected_mutation(&keyring, &truncated, "truncate")?;
    let grown = mutation_root.join("grown.rpm");
    fs::copy(&source_rpm, &grown)?;
    fs::OpenOptions::new()
        .append(true)
        .open(&grown)?
        .write_all(b"growth")?;
    rejected_mutation(&keyring, &grown, "growth")?;
    fs::remove_dir_all(&mutation_root)?;
    let mut reader = InventoryReader::open(dnfast_core::Architecture::Aarch64)?;
    let before = reader.read()?;
    let before_json = before.to_canonical_json()?;
    let execution = ExecutorInventory::begin(dnfast_core::Architecture::Aarch64, keyring, &before)?;
    let order = execution.native_call_order();
    if order.0 == 0 || order.1 == 0 || order.0 >= order.1 {
        return Err("keyring was not installed before rpmdb".into());
    }
    drop(execution);
    let after = reader.read()?;
    if before_json != after.to_canonical_json()? {
        return Err("rpm inventory changed".into());
    }
    let mut first = [0_u8; 4];
    let mut retained = artifact.file();
    retained.seek(SeekFrom::Start(0))?;
    retained.read_exact(&mut first)?;
    if &first != b"\xed\xab\xee\xdb" {
        return Err("retained artifact changed".into());
    }
    fs::remove_dir_all(&key_root)?;
    fs::remove_dir_all(&cache_root)?;
    fs::remove_dir_all(&old_tree)?;
    println!(
        "production=true primary={} signing={} keyring_sequence={} rpmdb_sequence={} inventory_unchanged=true retained_fd=true",
        verified.primary_fingerprint, verified.signing_fingerprint, order.0, order.1
    );
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
