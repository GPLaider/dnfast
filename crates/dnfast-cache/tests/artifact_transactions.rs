use std::{
    io::{BufRead, Cursor, Read, Write},
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use dnfast_cache::{
    ArtifactCache, ArtifactError, ArtifactResponse, ArtifactSpec, ArtifactTransport, Digest,
    MAX_CACHE_BYTES, TransactionRequest,
};
use sha2::{Digest as _, Sha256};

struct BytesTransport<'a> {
    bytes: &'a [u8],
}
impl ArtifactTransport for BytesTransport<'_> {
    fn open(&self, _url: &str) -> Result<ArtifactResponse, ArtifactError> {
        Ok(ArtifactResponse {
            status: 200,
            body: Box::new(Cursor::new(self.bytes.to_vec())),
        })
    }
}

struct CountingTransport {
    calls: Arc<AtomicUsize>,
}
impl ArtifactTransport for CountingTransport {
    fn open(&self, _url: &str) -> Result<ArtifactResponse, ArtifactError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(ArtifactError::Transport("unexpected network call".into()))
    }
}

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn spec(name: &str, bytes: &[u8]) -> ArtifactSpec {
    ArtifactSpec::new(
        "https://repo.example/",
        "https://repo.example/",
        name,
        Digest::Sha256(digest(bytes)),
        bytes.len() as u64,
    )
    .unwrap()
}

#[test]
fn exact_cache_boundary_accepts_two_artifacts_in_one_reservation() {
    // Given
    let temp = tempfile::tempdir().unwrap();
    let directory = temp.path().join("artifacts/sha256");
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::File::create(directory.join("unbound-cache-entry"))
        .unwrap()
        .set_len(MAX_CACHE_BYTES - 2)
        .unwrap();
    let first = spec("a.rpm", b"a");
    let second = spec("b.rpm", b"b");
    let request = TransactionRequest::for_specs(&[first.clone(), second.clone()]).unwrap();
    // When
    let mut transaction = ArtifactCache::new(temp.path())
        .begin_transaction(&request)
        .unwrap();
    let first_result = transaction.fetch(&first, &BytesTransport { bytes: b"a" });
    let second_result = transaction.fetch(&second, &BytesTransport { bytes: b"b" });
    // Then
    assert!(first_result.is_ok());
    assert!(second_result.is_ok());
    assert_eq!(transaction.remaining(), 0);
}

#[test]
fn partial_failure_retries_pending_artifact_and_rejects_replay() {
    // Given
    let temp = tempfile::tempdir().unwrap();
    let first = spec("a.rpm", b"a");
    let second = spec("b.rpm", b"b");
    let request = TransactionRequest::for_specs(&[first.clone(), second.clone()]).unwrap();
    let cache = ArtifactCache::new(temp.path());
    let mut transaction = cache.begin_transaction(&request).unwrap();
    // When
    transaction
        .fetch(&first, &BytesTransport { bytes: b"a" })
        .unwrap();
    let failed = transaction.fetch(&second, &BytesTransport { bytes: b"x" });
    let retried = transaction.fetch(&second, &BytesTransport { bytes: b"b" });
    let replayed = transaction.fetch(&first, &BytesTransport { bytes: b"a" });
    drop(transaction);
    let calls = Arc::new(AtomicUsize::new(0));
    let mut reopened = cache
        .begin_transaction(&TransactionRequest::for_specs(std::slice::from_ref(&first)).unwrap())
        .unwrap();
    let existing = reopened.fetch(
        &first,
        &CountingTransport {
            calls: Arc::clone(&calls),
        },
    );
    // Then
    assert!(matches!(failed, Err(ArtifactError::Integrity(_))));
    assert!(retried.is_ok());
    assert!(matches!(replayed, Err(ArtifactError::Capacity(_))));
    assert!(existing.is_ok());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn concurrent_transactions_cannot_oversubscribe_cache_cap() {
    // Given
    let temp = tempfile::tempdir().unwrap();
    let directory = temp.path().join("artifacts/sha256");
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::File::create(directory.join("unbound-cache-entry"))
        .unwrap()
        .set_len(MAX_CACHE_BYTES - 1024)
        .unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    // When
    let handles = ["1".repeat(64), "2".repeat(64)].map(|digest_value| {
        let root = temp.path().to_path_buf();
        let calls = Arc::clone(&calls);
        std::thread::spawn(move || {
            let artifact = ArtifactSpec::new(
                "https://repo.example/",
                "https://repo.example/",
                "p.rpm",
                Digest::Sha256(digest_value),
                2048,
            )
            .unwrap();
            let request = TransactionRequest::for_specs(std::slice::from_ref(&artifact)).unwrap();
            ArtifactCache::new(root)
                .begin_transaction(&request)
                .map(|_| ())
                .map_err(|error| {
                    let _ = calls;
                    error
                })
        })
    });
    let results = handles.map(|handle| handle.join().unwrap());
    // Then
    assert!(results.into_iter().all(|result| matches!(
        result,
        Err(ArtifactError::Capacity(_) | ArtifactError::Busy(_))
    )));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn nested_sessions_fail_busy_and_drop_or_panic_releases_reservation() {
    // Given
    let temp = tempfile::tempdir().unwrap();
    let artifact = spec("a.rpm", b"a");
    let request = TransactionRequest::for_specs(std::slice::from_ref(&artifact)).unwrap();
    let first_cache = ArtifactCache::new(temp.path());
    let second_cache = ArtifactCache::new(temp.path());
    let first = first_cache.begin_transaction(&request).unwrap();
    // When
    let started = Instant::now();
    let nested = second_cache.begin_transaction(&request);
    let elapsed = started.elapsed();
    drop(first);
    let panic_result = std::panic::catch_unwind(|| {
        let _held = first_cache.begin_transaction(&request).unwrap();
        panic!("injected transaction panic");
    });
    let reopened = second_cache.begin_transaction(&request);
    // Then
    assert!(matches!(nested, Err(ArtifactError::Busy(_))));
    assert!(elapsed < Duration::from_millis(100));
    assert!(panic_result.is_err());
    assert!(reopened.is_ok());
}

#[test]
fn verified_capability_starts_at_offset_zero() {
    // Given
    let temp = tempfile::tempdir().unwrap();
    let artifact = spec("header.rpm", b"RPMH");
    let request = TransactionRequest::for_specs(std::slice::from_ref(&artifact)).unwrap();
    let cache = ArtifactCache::new(temp.path());
    // When
    let mut first_session = cache.begin_transaction(&request).unwrap();
    let first = first_session
        .fetch(&artifact, &BytesTransport { bytes: b"RPMH" })
        .unwrap();
    drop(first_session);
    let mut second_session = cache.begin_transaction(&request).unwrap();
    let existing = second_session
        .fetch(
            &artifact,
            &CountingTransport {
                calls: Arc::new(AtomicUsize::new(0)),
            },
        )
        .unwrap();
    let mut first_bytes = [0_u8; 4];
    let mut existing_bytes = [0_u8; 4];
    first
        .file()
        .try_clone()
        .unwrap()
        .read_exact(&mut first_bytes)
        .unwrap();
    existing
        .file()
        .try_clone()
        .unwrap()
        .read_exact(&mut existing_bytes)
        .unwrap();
    // Then
    assert_eq!(&first_bytes, b"RPMH");
    assert_eq!(&existing_bytes, b"RPMH");
}

#[test]
fn cross_process_contention_times_out_then_releases() {
    if std::env::var_os("DNFAST_LOCK_CHILD").is_some() {
        let root = std::env::var("DNFAST_LOCK_ROOT").unwrap();
        let artifact = spec("a.rpm", b"a");
        let request = TransactionRequest::for_specs(std::slice::from_ref(&artifact)).unwrap();
        let _session = ArtifactCache::new(root)
            .begin_transaction(&request)
            .unwrap();
        println!("LOCK_READY");
        std::io::stdout().flush().unwrap();
        let mut byte = [0_u8; 1];
        let _ = std::io::stdin().read(&mut byte);
        return;
    }
    // Given
    let temp = tempfile::tempdir().unwrap();
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "cross_process_contention_times_out_then_releases",
            "--nocapture",
        ])
        .env("DNFAST_LOCK_CHILD", "1")
        .env("DNFAST_LOCK_ROOT", temp.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut output = std::io::BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    while output.read_line(&mut line).unwrap() != 0 {
        if line.contains("LOCK_READY") {
            break;
        }
        line.clear();
    }
    let artifact = spec("a.rpm", b"a");
    let request = TransactionRequest::for_specs(std::slice::from_ref(&artifact)).unwrap();
    // When
    let started = Instant::now();
    let contended = ArtifactCache::new(temp.path()).begin_transaction(&request);
    let elapsed = started.elapsed();
    drop(child.stdin.take());
    let status = child.wait().unwrap();
    let released = ArtifactCache::new(temp.path()).begin_transaction(&request);
    // Then
    assert!(
        matches!(contended, Err(ArtifactError::Busy(_))),
        "{:?}",
        contended.as_ref().err()
    );
    assert!(elapsed >= Duration::from_secs(2));
    assert!(elapsed < Duration::from_secs(3));
    assert!(status.success());
    assert!(released.is_ok());
}

#[test]
fn many_distinct_caches_hold_sessions_without_false_busy() {
    // Given
    let temp = tempfile::tempdir().unwrap();
    let artifact = spec("a.rpm", b"a");
    let request = TransactionRequest::for_specs(std::slice::from_ref(&artifact)).unwrap();
    // Each live session intentionally retains several descriptors for its
    // anchored directory, lock, marker, and path/inode authorities.  Keep the
    // stress case large without making it depend on the caller's RLIMIT_NOFILE.
    let nofile = rustix::process::getrlimit(rustix::process::Resource::Nofile)
        .current
        .unwrap_or(u64::MAX);
    let session_count = usize::try_from(nofile.saturating_sub(64) / 6)
        .unwrap_or(256)
        .min(256);
    assert!(
        session_count >= 32,
        "RLIMIT_NOFILE is too small for the cache-session stress test: {nofile}"
    );
    // When
    let sessions = (0..session_count)
        .map(|index| {
            ArtifactCache::new(temp.path().join(index.to_string())).begin_transaction(&request)
        })
        .collect::<Vec<_>>();
    // Then
    assert!(
        sessions.iter().all(Result::is_ok),
        "unexpected session failure with RLIMIT_NOFILE={nofile}: {:?}",
        sessions.iter().find_map(|result| result.as_ref().err()),
    );
}

#[test]
fn malicious_transaction_controls_fail_closed_without_scrubbing() {
    // Given
    let artifact = spec("a.rpm", b"a");
    let request = TransactionRequest::for_specs(std::slice::from_ref(&artifact)).unwrap();
    let hidden = tempfile::tempdir().unwrap();
    let hidden_directory = hidden.path().join("artifacts/sha256");
    std::fs::create_dir_all(&hidden_directory).unwrap();
    std::fs::File::create(hidden_directory.join(".transaction-hidden"))
        .unwrap()
        .set_len(MAX_CACHE_BYTES)
        .unwrap();
    // When
    let hidden_result = ArtifactCache::new(hidden.path()).begin_transaction(&request);
    // Then
    assert!(matches!(hidden_result, Err(ArtifactError::Capacity(_))));

    // Given
    let malformed = tempfile::tempdir().unwrap();
    let malformed_directory = malformed.path().join("artifacts/sha256");
    std::fs::create_dir_all(&malformed_directory).unwrap();
    let malformed_path = malformed_directory.join(".transaction-owner-malformed");
    std::fs::write(&malformed_path, []).unwrap();
    // When
    let malformed_result = ArtifactCache::new(malformed.path()).begin_transaction(&request);
    // Then
    assert!(matches!(malformed_result, Err(ArtifactError::Io(_))));
    assert!(malformed_path.exists());

    // Given
    let mut child = Command::new("sleep").arg("30").spawn().unwrap();
    let child_pid = i32::try_from(child.id()).unwrap();
    let stat = std::fs::read_to_string(format!("/proc/{child_pid}/stat")).unwrap();
    let start = stat
        .rsplit_once(')')
        .unwrap()
        .1
        .split_whitespace()
        .nth(19)
        .unwrap();
    let marker = format!(".transaction-owner-{child_pid}-{start}");
    for kind in ["symlink", "hardlink", "nonzero", "mode"] {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("artifacts/sha256");
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join(&marker);
        match kind {
            "symlink" => std::os::unix::fs::symlink("/dev/null", &path).unwrap(),
            "hardlink" => {
                let source = root.path().join("source");
                std::fs::write(&source, []).unwrap();
                std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o600)).unwrap();
                std::fs::hard_link(source, &path).unwrap();
            }
            "nonzero" => {
                std::fs::write(&path, b"x").unwrap();
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            }
            "mode" => {
                std::fs::write(&path, []).unwrap();
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            }
            _ => unreachable!(),
        }
        // When
        let result = ArtifactCache::new(root.path()).begin_transaction(&request);
        // Then
        assert!(matches!(result, Err(ArtifactError::Io(_))), "{kind}");
        assert!(
            std::fs::symlink_metadata(&path).is_ok(),
            "{kind} was scrubbed"
        );
    }
    child.kill().unwrap();
    child.wait().unwrap();
}

#[test]
fn nonzero_existing_lock_is_rejected_without_truncation() {
    // Given
    let temp = tempfile::tempdir().unwrap();
    let directory = temp.path().join("artifacts/sha256");
    std::fs::create_dir_all(&directory).unwrap();
    let lock = directory.join(".transaction-lock");
    let file = std::fs::File::create(&lock).unwrap();
    file.set_len(MAX_CACHE_BYTES).unwrap();
    std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o600)).unwrap();
    let artifact = spec("a.rpm", b"a");
    let request = TransactionRequest::for_specs(std::slice::from_ref(&artifact)).unwrap();
    // When
    let result = ArtifactCache::new(temp.path()).begin_transaction(&request);
    // Then
    assert!(matches!(result, Err(ArtifactError::Io(_))));
    assert_eq!(std::fs::metadata(lock).unwrap().len(), MAX_CACHE_BYTES);
}

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
