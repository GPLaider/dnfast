use std::{fs, path::PathBuf};

use dnfast_cache::{Cache, CacheError, SelectedOrigin};

fn metadata() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/rpm/generated-build10/repos/main/repodata");
    (
        fs::read(root.join("repomd.xml")).unwrap(),
        fs::read(root.join("primary.xml.zst")).unwrap(),
        fs::read(root.join("filelists.xml.zst")).unwrap(),
    )
}

#[test]
fn verified_complete_generation_owns_revalidated_bytes_and_typed_origin() {
    // Given
    let directory = tempfile::tempdir().unwrap();
    let cache = Cache::new(directory.path());
    let metadata = metadata();
    let snapshot = cache
        .publish_complete_with_origin(
            "main",
            &metadata.0,
            &metadata.1,
            &metadata.2,
            Some("https://mirror.example/fedora/repodata/repomd.xml"),
        )
        .unwrap();

    // When
    let generation = cache
        .open_verified_complete_generation(&snapshot.digest)
        .unwrap();

    // Then
    assert_eq!(generation.repository(), "main");
    assert_eq!(generation.repomd().bytes(), metadata.0);
    assert_eq!(
        generation.primary().read_all().expect("primary"),
        metadata.1
    );
    assert_eq!(
        generation.filelists().read_all().expect("filelists"),
        metadata.2
    );
    assert_eq!(
        generation.origin().artifact_base(),
        "https://mirror.example/fedora"
    );
    assert_eq!(
        generation
            .origin()
            .artifact_url("packages/ripgrep.rpm")
            .unwrap(),
        "https://mirror.example/fedora/packages/ripgrep.rpm"
    );
}

#[test]
fn selected_origin_rejects_non_https_non_repomd_and_ambiguous_forms() {
    // Given / When / Then
    for value in [
        "http://mirror.example/fedora/repodata/repomd.xml",
        "https://user@mirror.example/fedora/repodata/repomd.xml",
        "https://mirror.example/fedora/repodata/repomd.xml?token=secret",
        "https://mirror.example/fedora/repodata/repomd.xml#fragment",
        "https://mirror.example/fedora/repodata/primary.xml.zst",
        "https://mirror.example/fedora/repodata/repomd.xml/",
    ] {
        assert!(SelectedOrigin::parse(value).is_err(), "{value}");
    }
    assert!(
        SelectedOrigin::parse("https://mirror.example/fedora/repodata/repomd.xml")
            .unwrap()
            .artifact_url("../escape.rpm")
            .is_err()
    );
}

#[test]
fn complete_publication_rejects_untyped_origin_before_creating_an_object() {
    let directory = tempfile::tempdir().unwrap();
    let cache = Cache::new(directory.path());
    let metadata = metadata();
    for origin in [
        "http://mirror.example/fedora/repodata/repomd.xml",
        "https://mirror.example/fedora/repodata/primary.xml.zst",
    ] {
        assert!(
            cache
                .publish_complete_with_origin(
                    "main",
                    &metadata.0,
                    &metadata.1,
                    &metadata.2,
                    Some(origin)
                )
                .is_err()
        );
    }
    assert!(!directory.path().join("objects/sha256").exists());
}

#[test]
fn verified_complete_generation_rejects_missing_or_mutated_origin_without_returning_data() {
    // Given
    let absent_directory = tempfile::tempdir().unwrap();
    let cache = Cache::new(absent_directory.path());
    let metadata = metadata();
    let absent = cache
        .publish_complete("main", &metadata.0, &metadata.1, &metadata.2)
        .unwrap();
    let missing = cache.open_verified_complete_generation(&absent.digest);
    let present_directory = tempfile::tempdir().unwrap();
    let present_cache = Cache::new(present_directory.path());
    let present = present_cache
        .publish_complete_with_origin(
            "main",
            &metadata.0,
            &metadata.1,
            &metadata.2,
            Some("https://mirror.example/fedora/repodata/repomd.xml"),
        )
        .unwrap();

    // When
    let origin = present_directory
        .path()
        .join("objects/sha256")
        .join(&present.digest)
        .join("source-origin");
    fs::write(
        origin,
        b"https://mirror.example/changed/repodata/repomd.xml",
    )
    .unwrap();
    let mutated = present_cache.open_verified_complete_generation(&present.digest);

    // Then
    assert!(matches!(missing, Err(CacheError::Corrupt(_))));
    assert!(matches!(mutated, Err(CacheError::Corrupt(_))));
}
