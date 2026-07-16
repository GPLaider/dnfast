use dnfast_cache::{
    ArtifactCache, ArtifactError, ArtifactResponse, ArtifactSpec, ArtifactTransport, Capacity,
    Digest, MAX_ARTIFACT_BYTES, MAX_CACHE_BYTES, MAX_TRANSACTION_ARTIFACTS, MAX_TRANSACTION_BYTES,
    TransactionRequest,
};
use sha2::{Digest as _, Sha256};
use std::{
    io::{Cursor, Read, Seek},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
};

struct BytesTransport<'a> {
    bytes: &'a [u8],
    calls: AtomicUsize,
    status: u16,
}

struct RecordingTransport<'a> {
    bytes: &'a [u8],
    url: Mutex<Option<String>>,
}

impl ArtifactTransport for RecordingTransport<'_> {
    fn open(&self, url: &str) -> Result<ArtifactResponse, ArtifactError> {
        *self.url.lock().unwrap() = Some(url.into());
        Ok(ArtifactResponse {
            status: 200,
            body: Box::new(Cursor::new(self.bytes.to_vec())),
        })
    }
}
impl ArtifactTransport for BytesTransport<'_> {
    fn open(&self, _url: &str) -> Result<ArtifactResponse, ArtifactError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(ArtifactResponse {
            status: self.status,
            body: Box::new(Cursor::new(self.bytes.to_vec())),
        })
    }
}

struct SwappingTransport {
    directory: std::path::PathBuf,
    attacker: std::path::PathBuf,
    bytes: &'static [u8],
}

impl ArtifactTransport for SwappingTransport {
    fn open(&self, _url: &str) -> Result<ArtifactResponse, ArtifactError> {
        std::fs::rename(&self.directory, self.directory.with_extension("moved")).unwrap();
        std::os::unix::fs::symlink(&self.attacker, &self.directory).unwrap();
        Ok(ArtifactResponse {
            status: 200,
            body: Box::new(Cursor::new(self.bytes)),
        })
    }
}

struct ReadSwappingTransport {
    directory: std::path::PathBuf,
    attacker: std::path::PathBuf,
    bytes: &'static [u8],
}

impl ArtifactTransport for ReadSwappingTransport {
    fn open(&self, _url: &str) -> Result<ArtifactResponse, ArtifactError> {
        Ok(ArtifactResponse {
            status: 200,
            body: Box::new(ReadSwapper {
                directory: self.directory.clone(),
                attacker: self.attacker.clone(),
                bytes: Some(self.bytes),
            }),
        })
    }
}

struct ReadSwapper {
    directory: std::path::PathBuf,
    attacker: std::path::PathBuf,
    bytes: Option<&'static [u8]>,
}

impl Read for ReadSwapper {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let Some(bytes) = self.bytes.take() else {
            return Ok(0);
        };
        std::fs::rename(&self.directory, self.directory.with_extension("moved"))?;
        std::os::unix::fs::symlink(&self.attacker, &self.directory)?;
        buffer[..bytes.len()].copy_from_slice(bytes);
        Ok(bytes.len())
    }
}

struct GateTransport {
    begun: mpsc::Sender<()>,
    release: std::sync::Mutex<Option<mpsc::Receiver<()>>>,
}

impl ArtifactTransport for GateTransport {
    fn open(&self, _url: &str) -> Result<ArtifactResponse, ArtifactError> {
        let release = self.release.lock().unwrap().take().unwrap();
        Ok(ArtifactResponse {
            status: 200,
            body: Box::new(GateReader {
                begun: self.begun.clone(),
                release: Some(release),
            }),
        })
    }
}

struct GateReader {
    begun: mpsc::Sender<()>,
    release: Option<mpsc::Receiver<()>>,
}

impl Read for GateReader {
    fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
        self.begun.send(()).map_err(std::io::Error::other)?;
        self.release
            .take()
            .unwrap()
            .recv()
            .map_err(std::io::Error::other)?;
        Ok(0)
    }
}
fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn object_count(path: &std::path::Path) -> usize {
    std::fs::read_dir(path)
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .filter(|entry| {
                    !entry
                        .file_name()
                        .to_string_lossy()
                        .starts_with(".transaction-")
                })
                .count()
        })
        .unwrap_or(0)
}

fn fetch_one(
    cache: &ArtifactCache,
    spec: &ArtifactSpec,
    transport: &dyn ArtifactTransport,
) -> Result<dnfast_cache::CachedArtifact, ArtifactError> {
    let request = TransactionRequest::for_specs(std::slice::from_ref(spec))?;
    let mut transaction = cache.begin_transaction(&request)?;
    transaction.fetch(spec, transport)
}

#[test]
fn accepts_exact_numeric_boundaries_and_rejects_plus_one() {
    // Given
    let exact =
        TransactionRequest::from_totals(MAX_TRANSACTION_BYTES, MAX_TRANSACTION_ARTIFACTS).unwrap();
    let capacity = Capacity {
        cached_bytes: MAX_CACHE_BYTES - MAX_TRANSACTION_BYTES,
        available_bytes: MAX_TRANSACTION_BYTES + MAX_TRANSACTION_BYTES.div_ceil(20),
    };
    // When
    let result = exact.validate(capacity);
    // Then
    assert!(result.is_ok());
    assert!(TransactionRequest::from_totals(MAX_TRANSACTION_BYTES + 1, 1).is_err());
    assert!(TransactionRequest::from_totals(1, MAX_TRANSACTION_ARTIFACTS + 1).is_err());
    assert!(
        TransactionRequest::from_totals(1, 1)
            .unwrap()
            .validate(Capacity {
                cached_bytes: MAX_CACHE_BYTES,
                available_bytes: u64::MAX
            })
            .is_err()
    );
    assert!(
        ArtifactSpec::new(
            "https://repo.example/x/",
            "https://repo.example/x/",
            "p.rpm",
            Digest::Sha256("0".repeat(64)),
            MAX_ARTIFACT_BYTES
        )
        .is_ok()
    );
    assert!(
        ArtifactSpec::new(
            "https://repo.example/x/",
            "https://repo.example/x/",
            "p.rpm",
            Digest::Sha256("0".repeat(64)),
            MAX_ARTIFACT_BYTES + 1
        )
        .is_err()
    );
}

#[test]
fn reserve_failure_happens_before_network() {
    // Given
    let transport = BytesTransport {
        bytes: b"rpm",
        calls: AtomicUsize::new(0),
        status: 200,
    };
    let temp = tempfile::tempdir().unwrap();
    let cache = ArtifactCache::new(temp.path());
    // When
    let result = cache.begin_transaction(&TransactionRequest::from_totals(0, 1).unwrap());
    // Then
    assert!(matches!(result, Err(ArtifactError::Capacity(_))));
    assert_eq!(transport.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn streams_exact_object_and_rejects_integrity_failures_without_partial_publish() {
    // Given
    let temp = tempfile::tempdir().unwrap();
    let cache = ArtifactCache::new(temp.path());
    let good = b"rpm payload";
    let spec = ArtifactSpec::new(
        "https://repo.example/base/",
        "https://repo.example/base/",
        "Packages/p.rpm",
        Digest::Sha256(digest(good)),
        good.len() as u64,
    )
    .unwrap();
    // When
    let path = fetch_one(
        &cache,
        &spec,
        &BytesTransport {
            bytes: good,
            calls: AtomicUsize::new(0),
            status: 200,
        },
    )
    .unwrap();
    // Then
    let mut accepted = path.file().try_clone().unwrap();
    accepted.rewind().unwrap();
    let mut accepted_bytes = Vec::new();
    accepted.read_to_end(&mut accepted_bytes).unwrap();
    assert_eq!(accepted_bytes, good);
    #[cfg(unix)]
    assert_eq!(
        path.file().metadata().unwrap().permissions().mode() & 0o777,
        0o600
    );
    for (bytes, status) in [
        (b"short".as_slice(), 200),
        (b"rpm payload!".as_slice(), 200),
        (b"rpm payloae".as_slice(), 200),
        (good.as_slice(), 302),
    ] {
        let other = tempfile::tempdir().unwrap();
        let result = fetch_one(
            &ArtifactCache::new(other.path()),
            &spec,
            &BytesTransport {
                bytes,
                calls: AtomicUsize::new(0),
                status,
            },
        );
        assert!(result.is_err());
        assert_eq!(object_count(&other.path().join("artifacts/sha256")), 0);
    }
}

#[test]
fn rejects_cross_origin_and_unsafe_locations() {
    // Given
    let digest = Digest::Sha256("0".repeat(64));
    // When
    let results = [
        ("https://evil.example/", "p.rpm"),
        ("https://repo.example/", "https://evil.example/p.rpm"),
        ("https://repo.example/", "../p.rpm"),
    ]
    .map(|(selected, location)| {
        ArtifactSpec::new(
            "https://repo.example/",
            selected,
            location,
            digest.clone(),
            1,
        )
    });
    // Then
    assert!(results.into_iter().all(|result| result.is_err()));
    assert!(
        ArtifactSpec::from_selected_mirror("https://mirror.example/repo/", "p.rpm", digest, 1)
            .is_ok()
    );
}

#[test]
fn selected_mirror_without_trailing_slash_retains_final_directory() {
    // Given
    let temp = tempfile::tempdir().unwrap();
    let bytes = b"rpm";
    let spec = ArtifactSpec::from_selected_mirror(
        "https://mirror.example/repo/os",
        "Packages/p.rpm",
        Digest::Sha256(digest(bytes)),
        bytes.len() as u64,
    )
    .unwrap();
    let transport = RecordingTransport {
        bytes,
        url: Mutex::new(None),
    };
    // When
    fetch_one(&ArtifactCache::new(temp.path()), &spec, &transport).unwrap();
    // Then
    assert_eq!(
        transport.url.lock().unwrap().as_deref(),
        Some("https://mirror.example/repo/os/Packages/p.rpm")
    );
}

#[test]
fn concurrent_duplicate_downloads_converge_to_one_inode() {
    // Given
    let temp = tempfile::tempdir().unwrap();
    let cache = Arc::new(ArtifactCache::new(temp.path()));
    let bytes = b"concurrent rpm";
    let spec = Arc::new(
        ArtifactSpec::new(
            "https://repo.example/",
            "https://repo.example/",
            "p.rpm",
            Digest::Sha256(digest(bytes)),
            bytes.len() as u64,
        )
        .unwrap(),
    );
    // When
    let handles = (0..4)
        .map(|_| {
            let cache = Arc::clone(&cache);
            let spec = Arc::clone(&spec);
            std::thread::spawn(move || {
                fetch_one(
                    &cache,
                    &spec,
                    &BytesTransport {
                        bytes,
                        calls: AtomicUsize::new(0),
                        status: 200,
                    },
                )
            })
        })
        .collect::<Vec<_>>();
    let initial = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect::<Vec<_>>();
    let mut paths = Vec::new();
    for result in initial {
        match result {
            Ok(path) => paths.push(path),
            Err(ArtifactError::Busy(_)) => paths.push(
                fetch_one(
                    &cache,
                    &spec,
                    &BytesTransport {
                        bytes,
                        calls: AtomicUsize::new(0),
                        status: 200,
                    },
                )
                .unwrap(),
            ),
            Err(error) => panic!("unexpected duplicate download error: {error}"),
        }
    }
    // Then
    let inode = paths[0].file().metadata().unwrap().ino();
    assert!(
        paths
            .iter()
            .all(|path| path.file().metadata().unwrap().ino() == inode)
    );
    assert_eq!(object_count(&temp.path().join("artifacts/sha256")), 1);
}

#[test]
fn rejects_hardlinked_existing_object_before_reuse() {
    // Given
    let temp = tempfile::tempdir().unwrap();
    let bytes = b"linked rpm";
    let spec = ArtifactSpec::new(
        "https://repo.example/",
        "https://repo.example/",
        "p.rpm",
        Digest::Sha256(digest(bytes)),
        bytes.len() as u64,
    )
    .unwrap();
    let directory = temp.path().join("artifacts/sha256");
    std::fs::create_dir_all(&directory).unwrap();
    let source = temp.path().join("attacker");
    std::fs::write(&source, bytes).unwrap();
    std::fs::hard_link(&source, directory.join(digest(bytes))).unwrap();
    // When
    let result = fetch_one(
        &ArtifactCache::new(temp.path()),
        &spec,
        &BytesTransport {
            bytes,
            calls: AtomicUsize::new(0),
            status: 200,
        },
    );
    // Then
    assert!(matches!(result, Err(ArtifactError::Integrity(_))));
}

#[test]
fn directory_swap_during_transport_cannot_publish_to_attacker() {
    // Given
    let temp = tempfile::tempdir().unwrap();
    let attacker = tempfile::tempdir().unwrap();
    let bytes = b"swap rpm";
    let spec = ArtifactSpec::new(
        "https://repo.example/",
        "https://repo.example/",
        "p.rpm",
        Digest::Sha256(digest(bytes)),
        bytes.len() as u64,
    )
    .unwrap();
    let directory = temp.path().join("artifacts/sha256");
    // When
    let result = fetch_one(
        &ArtifactCache::new(temp.path()),
        &spec,
        &SwappingTransport {
            directory,
            attacker: attacker.path().into(),
            bytes,
        },
    );
    // Then
    assert!(matches!(result, Err(ArtifactError::Io(_))));
    assert_eq!(std::fs::read_dir(attacker.path()).unwrap().count(), 0);
}

#[test]
fn directory_swap_during_body_read_cannot_return_attacker_path() {
    // Given
    let temp = tempfile::tempdir().unwrap();
    let attacker = tempfile::tempdir().unwrap();
    let bytes = b"body swap rpm";
    let expected = digest(bytes);
    std::fs::write(attacker.path().join(&expected), b"malicious").unwrap();
    let spec = ArtifactSpec::new(
        "https://repo.example/",
        "https://repo.example/",
        "p.rpm",
        Digest::Sha256(expected.clone()),
        bytes.len() as u64,
    )
    .unwrap();
    let directory = temp.path().join("artifacts/sha256");
    // When
    let result = fetch_one(
        &ArtifactCache::new(temp.path()),
        &spec,
        &ReadSwappingTransport {
            directory: directory.clone(),
            attacker: attacker.path().into(),
            bytes,
        },
    );
    // Then
    assert!(matches!(result, Err(ArtifactError::Io(_))));
    assert_eq!(
        std::fs::read(attacker.path().join(expected)).unwrap(),
        b"malicious"
    );
    assert!(
        !directory
            .with_extension("moved")
            .join(digest(bytes))
            .exists()
    );
}

#[test]
fn interrupted_stream_has_no_named_staging_file() {
    // Given
    let temp = tempfile::tempdir().unwrap();
    let spec = ArtifactSpec::new(
        "https://repo.example/",
        "https://repo.example/",
        "p.rpm",
        Digest::Sha256(digest(b"x")),
        1,
    )
    .unwrap();
    let (begun_tx, begun_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let root = temp.path().to_path_buf();
    // When
    let handle = std::thread::spawn(move || {
        fetch_one(
            &ArtifactCache::new(&root),
            &spec,
            &GateTransport {
                begun: begun_tx,
                release: std::sync::Mutex::new(Some(release_rx)),
            },
        )
    });
    begun_rx.recv().unwrap();
    let visible = object_count(&temp.path().join("artifacts/sha256"));
    release_tx.send(()).unwrap();
    let result = handle.join().unwrap();
    // Then
    assert_eq!(visible, 0);
    assert!(matches!(result, Err(ArtifactError::Integrity(_))));
    assert_eq!(object_count(&temp.path().join("artifacts/sha256")), 0);
}

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};
