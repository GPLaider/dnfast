use std::fs;

use dnfast_cache::{Cache, CacheError, Snapshot};
use dnfast_metadata::{Package, search};
use sha2::{Digest, Sha256};

fn package(name: &str) -> Package {
    Package {
        name: name.into(),
        arch: "aarch64".into(),
        epoch: "0".into(),
        version: "1.0".into(),
        release: "1.fc44".into(),
        summary: format!("{name} package"),
    }
}

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

fn publish(cache: &Cache, repository: &str, name: &str) -> Snapshot {
    let (repomd, primary) = generation(name);
    cache
        .publish(repository, &repomd, &primary)
        .expect("valid generation must publish")
}

#[test]
fn publishes_content_addressed_snapshot_and_loads_offline() {
    let directory = tempfile::tempdir().expect("temporary directory must be available");
    let cache = Cache::new(directory.path());
    let published = publish(&cache, "fedora", "ripgrep");
    let digest = published.digest;

    let snapshot = cache.load("fedora").expect("published snapshot must load");

    assert_eq!(snapshot.digest, digest);
    assert_eq!(snapshot.packages, [package("ripgrep")]);
    assert_eq!(search(&snapshot.packages, "ripgrep")[0].name, "ripgrep");
    assert!(
        directory
            .path()
            .join("objects/sha256")
            .join(&digest)
            .is_dir()
    );
}

#[test]
fn publishing_new_generation_atomically_changes_current() {
    let directory = tempfile::tempdir().expect("temporary directory must be available");
    let cache = Cache::new(directory.path());
    let first = publish(&cache, "fedora", "one").digest;

    let second = publish(&cache, "fedora", "two").digest;

    assert_ne!(first, second);
    let snapshot = cache.load("fedora").expect("latest snapshot must load");
    assert_eq!(snapshot.digest, second);
    assert_eq!(snapshot.packages[0].name, "two");
    assert!(directory.path().join("objects/sha256").join(first).is_dir());
}

#[test]
fn corrupt_current_pointer_fails_closed() {
    let directory = tempfile::tempdir().expect("temporary directory must be available");
    let cache = Cache::new(directory.path());
    publish(&cache, "fedora", "one");
    let repository_key = hex::encode(Sha256::digest(b"fedora"));

    fs::write(
        directory
            .path()
            .join("repos")
            .join(repository_key)
            .join("current"),
        "../escape",
    )
    .expect("fixture pointer must be writable");

    assert!(matches!(cache.load("fedora"), Err(CacheError::Corrupt(_))));
}

#[test]
fn enumerates_published_repositories_deterministically() {
    let directory = tempfile::tempdir().expect("temporary directory must be available");
    let cache = Cache::new(directory.path());
    publish(&cache, "updates", "two");
    publish(&cache, "fedora", "one");

    let repositories = cache.repositories().expect("cache must enumerate");

    assert_eq!(repositories, ["fedora", "updates"]);
}

#[cfg(unix)]
#[test]
fn all_created_cache_directories_are_owner_only() {
    use std::os::unix::fs::PermissionsExt;

    let parent = tempfile::tempdir().expect("temporary directory must be available");
    let root = parent.path().join("new-cache");
    let cache = Cache::new(&root);

    publish(&cache, "fedora", "one");

    for path in [
        root.clone(),
        root.join("objects"),
        root.join("objects/sha256"),
        root.join("repos"),
    ] {
        assert_eq!(
            fs::metadata(path)
                .expect("cache directory must exist")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }
}
