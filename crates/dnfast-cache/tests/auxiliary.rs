use std::os::unix::fs::{PermissionsExt, symlink};

use dnfast_cache::{Cache, CacheError};
use dnfast_metadata::AuxiliaryRecord;
use sha2::{Digest, Sha256};

fn record(bytes: &[u8]) -> AuxiliaryRecord {
    AuxiliaryRecord {
        href: "repodata/comps.xml.zst".into(),
        checksum: hex::encode(Sha256::digest(bytes)),
        size: bytes.len() as u64,
    }
}

fn object(root: &std::path::Path, record: &AuxiliaryRecord) -> std::path::PathBuf {
    root.join("auxiliary/sha256").join(&record.checksum)
}

#[test]
fn auxiliary_payload_is_private_content_addressed_and_tamper_evident() {
    let directory = tempfile::tempdir().expect("cache root");
    let cache = Cache::new(directory.path());
    let bytes = b"checksum-bound-comps";
    let record = record(bytes);
    let published = cache
        .publish_auxiliary(&record, bytes)
        .expect("publish auxiliary");
    assert_eq!(published.bytes(), bytes);
    assert_eq!(
        std::fs::metadata(object(directory.path(), &record))
            .expect("object")
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    let payload = object(directory.path(), &record).join("payload");
    assert_eq!(
        std::fs::metadata(&payload)
            .expect("payload")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let mut corrupted = bytes.to_vec();
    corrupted[0] ^= 1;
    std::fs::write(&payload, corrupted).expect("tamper payload");
    assert!(matches!(
        cache.open_auxiliary(&record),
        Err(CacheError::Corrupt(_))
    ));
}

#[test]
fn auxiliary_open_rejects_symlink_wrong_mode_and_hardlinked_payload() {
    let bytes = b"auxiliary-security";
    let record = record(bytes);

    let symlinked = tempfile::tempdir().expect("symlink cache");
    let attacker = tempfile::tempdir().expect("attacker");
    std::fs::create_dir_all(symlinked.path().join("auxiliary/sha256")).expect("object parent");
    symlink(attacker.path(), object(symlinked.path(), &record)).expect("object symlink");
    assert!(
        Cache::new(symlinked.path())
            .open_auxiliary(&record)
            .is_err()
    );

    let wrong_mode = tempfile::tempdir().expect("mode cache");
    let cache = Cache::new(wrong_mode.path());
    cache
        .publish_auxiliary(&record, bytes)
        .expect("publish mode fixture");
    std::fs::set_permissions(
        object(wrong_mode.path(), &record),
        std::fs::Permissions::from_mode(0o777),
    )
    .expect("unsafe mode");
    assert!(cache.open_auxiliary(&record).is_err());

    let hardlinked = tempfile::tempdir().expect("hardlink cache");
    let cache = Cache::new(hardlinked.path());
    cache
        .publish_auxiliary(&record, bytes)
        .expect("publish hardlink fixture");
    std::fs::hard_link(
        object(hardlinked.path(), &record).join("payload"),
        hardlinked.path().join("attacker-link"),
    )
    .expect("hardlink payload");
    assert!(cache.open_auxiliary(&record).is_err());
}

#[test]
fn competing_auxiliary_publishers_converge_on_one_complete_object() {
    let directory = tempfile::tempdir().expect("cache root");
    let bytes = b"racing-auxiliary".to_vec();
    let record = record(&bytes);
    let mut workers = Vec::new();
    for _ in 0..16 {
        let root = directory.path().to_path_buf();
        let bytes = bytes.clone();
        let record = record.clone();
        workers.push(std::thread::spawn(move || {
            Cache::new(root)
                .publish_auxiliary(&record, &bytes)
                .map(|payload| payload.bytes().to_vec())
        }));
    }
    for worker in workers {
        assert_eq!(
            worker.join().expect("publisher thread").expect("publish"),
            bytes
        );
    }
    let entries = std::fs::read_dir(directory.path().join("auxiliary/sha256"))
        .expect("object listing")
        .collect::<Result<Vec<_>, _>>()
        .expect("entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(
        Cache::new(directory.path())
            .open_auxiliary(&record)
            .expect("final object")
            .bytes(),
        bytes
    );
}
