use std::{fs, path::PathBuf};

use dnfast_cache::{Cache, CacheError, SnapshotIntegrity};
use sha2::{Digest, Sha256};

fn metadata(build: &str) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/rpm")
        .join(build)
        .join("repos/main/repodata");
    (
        fs::read(root.join("repomd.xml")).expect("repomd fixture"),
        fs::read(root.join("primary.xml.zst")).expect("primary fixture"),
        fs::read(root.join("filelists.xml.zst")).expect("filelists fixture"),
    )
}

fn object(root: &std::path::Path, digest: &str) -> PathBuf {
    root.join("objects/sha256").join(digest)
}

#[test]
fn opens_each_complete_generation_by_repomd_digest() {
    // Given
    let directory = tempfile::tempdir().expect("temporary cache");
    let cache = Cache::new(directory.path());
    let build9 = metadata("generated-build9");
    let build10 = metadata("generated-build10");

    // When
    let first = cache
        .publish_complete("main", &build9.0, &build9.1, &build9.2)
        .expect("build9");
    let second = cache
        .publish_complete("main", &build10.0, &build10.1, &build10.2)
        .expect("build10");

    // Then
    assert_ne!(first.digest, second.digest);
    assert_eq!(
        cache
            .open_by_digest(&first.digest)
            .expect("old object")
            .digest,
        first.digest
    );
    assert_eq!(
        cache.load("main").expect("current search").digest,
        second.digest
    );
    assert_eq!(second.integrity, SnapshotIntegrity::CompleteMetadata);
    assert_eq!(second.repository, "main");
    assert_eq!(second.solver_inputs.len(), second.filelists.len());
}

#[test]
fn same_generation_reuses_canonical_persisted_origin_on_reload() {
    let directory = tempfile::tempdir().expect("temporary cache");
    let cache = Cache::new(directory.path());
    let build = metadata("generated-build10");
    let first = cache
        .publish_complete_with_origin(
            "main",
            &build.0,
            &build.1,
            &build.2,
            Some("https://one.example/fedora/repodata/repomd.xml"),
        )
        .unwrap();
    let second = cache
        .publish_complete_with_origin(
            "main",
            &build.0,
            &build.1,
            &build.2,
            Some("https://two.example/fedora/repodata/repomd.xml"),
        )
        .unwrap();
    let reloaded = Cache::new(directory.path())
        .open_by_digest(&first.digest)
        .unwrap();
    assert_eq!(second.source_origin, first.source_origin);
    assert_eq!(reloaded.source_origin, first.source_origin);
}

#[test]
fn complete_publication_rejects_mixed_generations_without_changing_current() {
    // Given
    let directory = tempfile::tempdir().expect("temporary cache");
    let cache = Cache::new(directory.path());
    let build9 = metadata("generated-build9");
    let build10 = metadata("generated-build10");
    let current = cache
        .publish_complete("main", &build9.0, &build9.1, &build9.2)
        .expect("build9")
        .digest;

    // When
    let result = cache.publish_complete("main", &build10.0, &build10.1, &build9.2);

    // Then
    assert!(matches!(result, Err(CacheError::Corrupt(_))));
    assert_eq!(
        cache.load("main").expect("previous current").digest,
        current
    );
}

#[test]
fn legacy_manifest_requires_explicit_refresh() {
    // Given
    let directory = tempfile::tempdir().expect("temporary cache");
    let cache = Cache::new(directory.path());
    let digest = "a".repeat(64);
    let object = directory.path().join("objects/sha256").join(&digest);
    fs::create_dir_all(&object).expect("legacy object directory");
    fs::write(
        object.join("manifest.json"),
        br#"{"repomd":{},"primary":{},"packages":{}}"#,
    )
    .expect("legacy manifest");

    // When
    let result = cache.open_by_digest(&digest);

    // Then
    assert!(matches!(result, Err(CacheError::CacheUpgradeRequired)));
}

#[cfg(unix)]
#[test]
fn open_by_digest_rejects_symlinked_metadata() {
    use std::os::unix::fs::symlink;

    // Given
    let directory = tempfile::tempdir().expect("temporary cache");
    let cache = Cache::new(directory.path());
    let build10 = metadata("generated-build10");
    let snapshot = cache
        .publish_complete("main", &build10.0, &build10.1, &build10.2)
        .expect("build10");
    let object = directory
        .path()
        .join("objects/sha256")
        .join(&snapshot.digest);
    fs::remove_file(object.join("filelists")).expect("remove object file");
    symlink("primary", object.join("filelists")).expect("symlink fixture");

    // When
    let result = cache.open_by_digest(&snapshot.digest);

    // Then
    assert!(matches!(result, Err(CacheError::Corrupt(_))));
}

#[test]
fn interrupted_staging_is_unreachable_and_preserves_current() {
    // Given
    let directory = tempfile::tempdir().expect("temporary cache");
    let cache = Cache::new(directory.path());
    let build9 = metadata("generated-build9");
    let current = cache
        .publish_complete("main", &build9.0, &build9.1, &build9.2)
        .expect("build9")
        .digest;
    let abandoned = directory.path().join("objects/sha256/.staging-interrupted");
    fs::create_dir(&abandoned).expect("interrupted staging fixture");
    fs::write(abandoned.join("manifest.json"), b"partial").expect("partial fixture");

    // When
    let loaded = cache.load("main").expect("previous generation");

    // Then
    assert_eq!(loaded.digest, current);
    assert!(matches!(
        cache.open_by_digest(&"b".repeat(64)),
        Err(CacheError::Io(_))
    ));
}

#[test]
fn concurrent_competing_generations_never_publish_partial_state() {
    // Given
    let directory = tempfile::tempdir().expect("temporary cache");
    let root = directory.path().to_path_buf();
    let generations = [metadata("generated-build9"), metadata("generated-build10")];

    // When
    let handles = (0..4)
        .map(|index| {
            let root = root.clone();
            let generation = generations[index % generations.len()].clone();
            std::thread::spawn(move || {
                Cache::new(root).publish_complete(
                    "main",
                    &generation.0,
                    &generation.1,
                    &generation.2,
                )
            })
        })
        .collect::<Vec<_>>();
    let results = handles
        .into_iter()
        .map(|handle| {
            handle
                .join()
                .expect("publisher thread")
                .expect("publication")
                .digest
        })
        .collect::<Vec<_>>();

    // Then
    assert_eq!(
        results
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        2
    );
    let cache = Cache::new(&root);
    let current = cache.load("main").expect("current");
    assert!(results.contains(&current.digest));
    for digest in results {
        cache
            .open_by_digest(&digest)
            .expect("complete competing object");
    }
}

#[test]
fn every_complete_metadata_file_is_revalidated_on_open() {
    // Given
    let directory = tempfile::tempdir().expect("temporary cache");
    let cache = Cache::new(directory.path());
    let build10 = metadata("generated-build10");
    let snapshot = cache
        .publish_complete("main", &build10.0, &build10.1, &build10.2)
        .expect("build10");
    let primary = directory
        .path()
        .join("objects/sha256")
        .join(&snapshot.digest)
        .join("primary");
    fs::write(primary, b"same generation claimed, wrong bytes").expect("corrupt fixture");

    // When
    let result = cache.open_by_digest(&snapshot.digest);

    // Then
    assert!(matches!(result, Err(CacheError::Corrupt(_))));
}

#[test]
fn version_one_unknown_duplicate_and_extra_manifest_shapes_reject() {
    let directory = tempfile::tempdir().expect("temporary cache");
    let cache = Cache::new(directory.path());
    let build10 = metadata("generated-build10");
    let snapshot = cache
        .publish_complete("main", &build10.0, &build10.1, &build10.2)
        .expect("build10");
    let manifest = object(directory.path(), &snapshot.digest).join("manifest.json");
    let original = fs::read_to_string(&manifest).expect("manifest");
    fs::write(
        &manifest,
        original.replacen("\"version\":3", "\"version\":1", 1),
    )
    .expect("v1");
    assert!(matches!(
        cache.open_by_digest(&snapshot.digest),
        Err(CacheError::CacheUpgradeRequired)
    ));
    fs::write(&manifest, original.replacen("{", "{\"unknown\":true,", 1)).expect("unknown");
    assert!(matches!(
        cache.open_by_digest(&snapshot.digest),
        Err(CacheError::Corrupt(_))
    ));
    fs::write(&manifest, original.replacen("{", "{\"version\":3,", 1)).expect("duplicate");
    assert!(matches!(
        cache.open_by_digest(&snapshot.digest),
        Err(CacheError::Corrupt(_))
    ));
    fs::write(&manifest, &original).expect("restore");
    fs::write(
        object(directory.path(), &snapshot.digest).join("extra"),
        b"extra",
    )
    .expect("extra");
    assert!(matches!(
        cache.open_by_digest(&snapshot.digest),
        Err(CacheError::Corrupt(_))
    ));
}

#[test]
fn forged_search_index_and_updated_manifest_hash_reject() {
    let directory = tempfile::tempdir().expect("temporary cache");
    let cache = Cache::new(directory.path());
    let build10 = metadata("generated-build10");
    let snapshot = cache
        .publish_complete("main", &build10.0, &build10.1, &build10.2)
        .expect("build10");
    let object = object(directory.path(), &snapshot.digest);
    let packages = object.join("packages.json");
    let forged = b"[]";
    fs::write(&packages, forged).expect("forged index");
    let manifest = object.join("manifest.json");
    let mut value: serde_json::Value =
        serde_json::from_slice(&fs::read(&manifest).expect("manifest")).expect("json");
    value["search_index"]["sha256"] = hex::encode(Sha256::digest(forged)).into();
    value["search_index"]["size"] = forged.len().into();
    fs::write(manifest, serde_json::to_vec(&value).expect("json")).expect("updated manifest");
    assert!(matches!(
        cache.open_by_digest(&snapshot.digest),
        Err(CacheError::Corrupt(_))
    ));
}

#[test]
fn manifest_larger_than_eight_mib_rejects_before_deserialization() {
    let directory = tempfile::tempdir().expect("temporary cache");
    let cache = Cache::new(directory.path());
    let build10 = metadata("generated-build10");
    let snapshot = cache
        .publish_complete("main", &build10.0, &build10.1, &build10.2)
        .expect("build10");
    fs::write(
        object(directory.path(), &snapshot.digest).join("manifest.json"),
        vec![b' '; 8 * 1024 * 1024 + 1],
    )
    .expect("oversize manifest");
    assert!(matches!(
        cache.open_by_digest(&snapshot.digest),
        Err(CacheError::Corrupt(_))
    ));
}

#[cfg(unix)]
#[test]
fn hardlinked_object_file_rejects() {
    let directory = tempfile::tempdir().expect("temporary cache");
    let cache = Cache::new(directory.path());
    let build10 = metadata("generated-build10");
    let snapshot = cache
        .publish_complete("main", &build10.0, &build10.1, &build10.2)
        .expect("build10");
    let primary = object(directory.path(), &snapshot.digest).join("primary");
    let outside = directory.path().join("outside");
    fs::hard_link(&primary, &outside).expect("hardlink fixture");
    assert!(matches!(
        cache.open_by_digest(&snapshot.digest),
        Err(CacheError::Corrupt(_))
    ));
}

#[test]
fn rename_faults_preserve_current_and_clean_staging() {
    let directory = tempfile::tempdir().expect("temporary cache");
    let cache = Cache::new(directory.path());
    let build9 = metadata("generated-build9");
    let build10 = metadata("generated-build10");
    let old = cache
        .publish_complete("main", &build9.0, &build9.1, &build9.2)
        .expect("old")
        .digest;
    fs::write(directory.path().join(".fail-before-object-rename"), b"1").expect("fault marker");
    assert!(
        cache
            .publish_complete("main", &build10.0, &build10.1, &build10.2)
            .is_err()
    );
    fs::remove_file(directory.path().join(".fail-before-object-rename")).expect("remove marker");
    assert_eq!(cache.load("main").expect("old current").digest, old);
    assert!(
        !directory
            .path()
            .join("objects/sha256")
            .read_dir()
            .expect("objects")
            .any(|entry| entry
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .starts_with(".staging-"))
    );
    fs::write(directory.path().join(".fail-before-current-rename"), b"1").expect("fault marker");
    assert!(
        cache
            .publish_complete("main", &build10.0, &build10.1, &build10.2)
            .is_err()
    );
    fs::remove_file(directory.path().join(".fail-before-current-rename")).expect("remove marker");
    assert_eq!(cache.load("main").expect("old current").digest, old);
}

#[test]
fn same_repomd_different_repository_race_has_one_truthful_winner() {
    let directory = tempfile::tempdir().expect("temporary cache");
    let root = directory.path().to_path_buf();
    let generation = metadata("generated-build10");
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let handles = ["one", "two"].map(|repository| {
        let root = root.clone();
        let generation = generation.clone();
        let barrier = std::sync::Arc::clone(&barrier);
        std::thread::spawn(move || {
            barrier.wait();
            Cache::new(root).publish_complete(
                repository,
                &generation.0,
                &generation.1,
                &generation.2,
            )
        })
    });
    let results = handles.map(|handle| handle.join().expect("publisher"));
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(CacheError::Corrupt(_))))
            .count(),
        1
    );
    let cache = Cache::new(&root);
    let repositories = cache.repositories().expect("repositories");
    assert_eq!(repositories.len(), 1);
    cache.load(&repositories[0]).expect("winner pointer");
}

#[test]
fn same_repomd_different_integrity_race_has_one_truthful_winner() {
    let directory = tempfile::tempdir().expect("temporary cache");
    let root = directory.path().to_path_buf();
    let generation = metadata("generated-build10");
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let complete = {
        let root = root.clone();
        let generation = generation.clone();
        let barrier = std::sync::Arc::clone(&barrier);
        std::thread::spawn(move || {
            barrier.wait();
            Cache::new(root)
                .publish_complete("main", &generation.0, &generation.1, &generation.2)
                .map(|snapshot| snapshot.integrity)
        })
    };
    let search = {
        let root = root.clone();
        let generation = generation.clone();
        let barrier = std::sync::Arc::clone(&barrier);
        std::thread::spawn(move || {
            barrier.wait();
            Cache::new(root)
                .publish("main", &generation.0, &generation.1)
                .map(|_| SnapshotIntegrity::SearchOnly)
        })
    };
    let results = [
        complete.join().expect("complete"),
        search.join().expect("search"),
    ];
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(CacheError::Corrupt(_))))
            .count(),
        1
    );
    let cache = Cache::new(&root);
    let current = cache.load("main").expect("winner pointer");
    let opened = cache
        .open_by_digest(&current.digest)
        .expect("winner object");
    assert_eq!(
        opened.integrity,
        *results
            .iter()
            .find_map(|result| result.as_ref().ok())
            .expect("winner integrity")
    );
}
