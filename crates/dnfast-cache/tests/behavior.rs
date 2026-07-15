use std::fs;

use dnfast_cache::{Cache, CacheError, Snapshot};
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

fn publish(cache: &Cache, repository: &str, name: &str) -> Snapshot {
    let (repomd, primary) = generation(name);
    cache
        .publish(repository, &repomd, &primary)
        .expect("valid generation must publish")
}

#[test]
fn publishing_new_generation_changes_current_and_retains_old_object() {
    // Given
    let directory = tempfile::tempdir().expect("temporary directory must be available");
    let cache = Cache::new(directory.path());
    let first = publish(&cache, "fedora", "one").digest;

    // When
    let second = publish(&cache, "fedora", "two").digest;

    // Then
    assert_ne!(first, second);
    let snapshot = cache.load("fedora").expect("latest snapshot must load");
    assert_eq!(snapshot.digest, second);
    assert_eq!(snapshot.packages[0].name, "two");
    assert!(directory.path().join("objects/sha256").join(first).is_dir());
}

#[test]
fn publication_rejects_primary_not_bound_to_repomd() {
    // Given
    let directory = tempfile::tempdir().expect("temporary directory must be available");
    let cache = Cache::new(directory.path());
    let (repomd, _) = generation("one");
    let (_, unrelated_primary) = generation("two");

    // When
    let result = cache.publish("fedora", &repomd, &unrelated_primary);

    // Then
    assert!(matches!(result, Err(CacheError::Corrupt(_))));
    assert!(
        cache
            .repositories()
            .expect("cache must enumerate")
            .is_empty()
    );
}

#[cfg(unix)]
#[test]
fn publication_rejects_symlinked_cache_ancestor() {
    use std::os::unix::fs::symlink;

    // Given
    let directory = tempfile::tempdir().expect("temporary directory must be available");
    let real = directory.path().join("real");
    fs::create_dir(&real).expect("real directory must be creatable");
    let linked = directory.path().join("linked");
    symlink(&real, &linked).expect("symlink fixture must be creatable");
    let cache = Cache::new(linked.join("cache"));
    let (repomd, primary) = generation("one");

    // When
    let result = cache.publish("fedora", &repomd, &primary);

    // Then
    assert!(matches!(result, Err(CacheError::Corrupt(_))));
}

#[cfg(unix)]
#[test]
fn publication_creates_owner_only_directories() {
    use std::os::unix::fs::PermissionsExt;

    // Given
    let parent = tempfile::tempdir().expect("temporary directory must be available");
    let root = parent.path().join("new-cache");
    let cache = Cache::new(&root);

    // When
    publish(&cache, "fedora", "one");

    // Then
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

#[cfg(unix)]
#[test]
fn publication_accepts_existing_owner_owned_0700_cache_with_one_directory_link() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    // Given
    let parent = if rustix::process::geteuid().as_raw() == 0 {
        std::path::Path::new("/var/cache")
    } else {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
    };
    let directory = tempfile::Builder::new()
        .prefix(".dnfast-cache-safety-")
        .tempdir_in(parent)
        .expect("cache fixture directory must be creatable");
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
        .expect("cache fixture mode must be set");
    let metadata = fs::metadata(directory.path()).expect("cache fixture metadata must be readable");
    assert_eq!(metadata.uid(), rustix::process::geteuid().as_raw());
    assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
    if metadata.nlink() != 1 {
        return;
    }
    let cache = Cache::new(directory.path());

    // When
    let (repomd, primary) = generation("one");
    let result = cache.publish("fedora", &repomd, &primary);

    // Then
    result.expect("a safe owner-owned 0700 cache root must be accepted");
}

#[cfg(unix)]
#[test]
fn publication_accepts_existing_non_writable_group_and_world_cache_modes() {
    use std::os::unix::fs::PermissionsExt;

    for (index, mode) in [0o750, 0o755].into_iter().enumerate() {
        let directory = tempfile::tempdir().expect("temporary directory must be available");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(mode))
            .expect("cache fixture mode must be set");
        let cache = Cache::new(directory.path());
        let (repomd, primary) = generation(&format!("safe-mode-{index}"));

        cache
            .publish("fedora", &repomd, &primary)
            .expect("an owner-owned cache root without group/world write access must be accepted");
    }
}

#[cfg(unix)]
#[test]
fn publication_rejects_unsafe_existing_cache_root_shapes() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    // Given
    let directory = tempfile::tempdir().expect("temporary directory must be available");
    let writable = directory.path().join("writable");
    fs::create_dir(&writable).expect("writable fixture directory must be creatable");
    fs::set_permissions(&writable, fs::Permissions::from_mode(0o720))
        .expect("writable fixture mode must be set");
    let regular = directory.path().join("regular");
    fs::write(&regular, b"not a cache directory").expect("regular fixture must be writable");
    let real = directory.path().join("real");
    fs::create_dir(&real).expect("real fixture directory must be creatable");
    let linked = directory.path().join("linked");
    symlink(&real, &linked).expect("symlink fixture must be creatable");
    let (repomd, primary) = generation("one");

    // When
    let results = [&writable, &regular, &linked]
        .map(|root| Cache::new(root).publish("fedora", &repomd, &primary));

    // Then
    assert!(results.iter().all(Result::is_err));
}

#[test]
fn load_rejects_corrupt_cached_package_bytes() {
    // Given
    let directory = tempfile::tempdir().expect("temporary directory must be available");
    let cache = Cache::new(directory.path());
    let snapshot = publish(&cache, "fedora", "one");
    fs::write(
        directory
            .path()
            .join("objects/sha256")
            .join(snapshot.digest)
            .join("packages.json"),
        b"corrupt",
    )
    .expect("fixture object must be writable");

    // When
    let result = cache.load("fedora");

    // Then
    assert!(matches!(result, Err(CacheError::Corrupt(_))));
}
