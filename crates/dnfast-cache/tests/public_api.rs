use std::{fs, path::Path};

use dnfast_cache::{Cache, CacheError};
use sha2::{Digest, Sha256};

fn generation(name: &str) -> (Vec<u8>, Vec<u8>) {
    let primary = format!(
        r#"<metadata xmlns="http://linux.duke.edu/metadata/common" packages="1"><package type="rpm"><name>{name}</name><arch>aarch64</arch><version epoch="0" ver="1.0" rel="1.fc44"/><summary>{name} package</summary></package></metadata>"#
    )
    .into_bytes();
    let checksum = hex::encode(Sha256::digest(&primary));
    let repomd = format!(
        r#"<repomd xmlns="http://linux.duke.edu/metadata/repo"><data type="primary"><checksum type="sha256">{checksum}</checksum><open-checksum type="sha256">{checksum}</open-checksum><location href="repodata/primary.xml"/><size>{}</size><open-size>{}</open-size></data></repomd>"#,
        primary.len(),
        primary.len()
    )
    .into_bytes();
    (repomd, primary)
}

fn publish(cache: &Cache, repository: &str, name: &str) -> dnfast_cache::Snapshot {
    let (repomd, primary) = generation(name);
    cache
        .publish(repository, &repomd, &primary)
        .expect("valid metadata must publish")
}

fn repository_directory(root: &Path, repository: &str) -> std::path::PathBuf {
    root.join("repos")
        .join(hex::encode(Sha256::digest(repository.as_bytes())))
}

#[test]
fn new_preserves_root_and_debug_representation() {
    // Given
    let directory = tempfile::tempdir().expect("temporary directory must be available");

    // When
    let cache = Cache::new(directory.path());

    // Then
    assert_eq!(cache.root(), directory.path());
    assert_eq!(
        format!("{cache:?}"),
        format!("Cache {{ root: {:?} }}", directory.path())
    );
}

#[test]
fn publish_returns_public_snapshot_fields() {
    // Given
    let directory = tempfile::tempdir().expect("temporary directory must be available");
    let cache = Cache::new(directory.path());

    // When
    let snapshot = publish(&cache, "fedora", "ripgrep");

    // Then
    assert_eq!(snapshot.digest.len(), 64);
    assert_eq!(snapshot.packages.len(), 1);
    assert_eq!(snapshot.packages[0].name, "ripgrep");
    assert!(format!("{snapshot:?}").starts_with("Snapshot { digest: "));
}

#[test]
fn publish_rejects_malformed_metadata_as_corrupt() {
    // Given
    let directory = tempfile::tempdir().expect("temporary directory must be available");
    let cache = Cache::new(directory.path());

    // When
    let result = cache.publish("fedora", b"not xml", b"not primary");

    // Then
    assert!(matches!(result, Err(CacheError::Corrupt(_))));
}

#[test]
fn load_returns_published_snapshot() {
    // Given
    let directory = tempfile::tempdir().expect("temporary directory must be available");
    let cache = Cache::new(directory.path());
    let published = publish(&cache, "fedora", "ripgrep");

    // When
    let loaded = cache.load("fedora").expect("published snapshot must load");

    // Then
    assert_eq!(loaded.digest, published.digest);
    assert_eq!(loaded.packages, published.packages);
}

#[test]
fn load_reports_missing_snapshot_with_repository() {
    // Given
    let directory = tempfile::tempdir().expect("temporary directory must be available");
    let cache = Cache::new(directory.path());

    // When
    let result = cache.load("missing");

    // Then
    assert!(matches!(result, Err(CacheError::MissingSnapshot(name)) if name == "missing"));
}

#[test]
fn load_reports_corrupt_pointer() {
    // Given
    let directory = tempfile::tempdir().expect("temporary directory must be available");
    let cache = Cache::new(directory.path());
    publish(&cache, "fedora", "ripgrep");
    fs::write(
        repository_directory(directory.path(), "fedora").join("current"),
        "../escape\n",
    )
    .expect("fixture pointer must be writable");

    // When
    let result = cache.load("fedora");

    // Then
    assert!(
        matches!(result, Err(CacheError::Corrupt(message)) if message == "invalid current digest")
    );
}

#[test]
fn repositories_are_empty_before_first_publication() {
    // Given
    let directory = tempfile::tempdir().expect("temporary directory must be available");
    let cache = Cache::new(directory.path());

    // When
    let repositories = cache
        .repositories()
        .expect("absent repository directory is valid");

    // Then
    assert!(repositories.is_empty());
}

#[test]
fn repositories_are_sorted_and_deduplicated() {
    // Given
    let directory = tempfile::tempdir().expect("temporary directory must be available");
    let cache = Cache::new(directory.path());
    publish(&cache, "updates", "two");
    publish(&cache, "fedora", "one");
    publish(&cache, "updates", "three");

    // When
    let repositories = cache.repositories().expect("valid cache must enumerate");

    // Then
    assert_eq!(repositories, ["fedora", "updates"]);
}

#[test]
fn repositories_report_io_error_for_unreadable_shape() {
    // Given
    let directory = tempfile::tempdir().expect("temporary directory must be available");
    fs::write(directory.path().join("repos"), b"not a directory")
        .expect("fixture file must be writable");
    let cache = Cache::new(directory.path());

    // When
    let result = cache.repositories();

    // Then
    assert!(matches!(result, Err(CacheError::Io(_))));
}

#[test]
fn cache_error_display_and_source_are_stable() {
    // Given
    let errors = [
        CacheError::MissingSnapshot("fedora".into()),
        CacheError::Corrupt("bad manifest".into()),
        CacheError::Io("disk full".into()),
    ];

    // When
    let rendered: Vec<String> = errors.iter().map(ToString::to_string).collect();

    // Then
    assert_eq!(
        rendered,
        [
            "cache error: MissingSnapshot(\"fedora\")",
            "cache error: Corrupt(\"bad manifest\")",
            "cache error: Io(\"disk full\")",
        ]
    );
    assert!(
        errors
            .iter()
            .all(|error| std::error::Error::source(error).is_none())
    );
}

#[cfg(unix)]
#[test]
fn load_rejects_symlinked_current_pointer() {
    use std::os::unix::fs::symlink;

    // Given
    let directory = tempfile::tempdir().expect("temporary directory must be available");
    let cache = Cache::new(directory.path());
    publish(&cache, "fedora", "ripgrep");
    let repository = repository_directory(directory.path(), "fedora");
    fs::remove_file(repository.join("current")).expect("current fixture must be removable");
    symlink("repo-id", repository.join("current")).expect("symlink fixture must be creatable");

    // When
    let result = cache.load("fedora");

    // Then
    assert!(
        matches!(result, Err(CacheError::Corrupt(message)) if message == "current is not a regular file")
    );
}
