use std::process::Command;

use dnfast_cache::{ArtifactCache, ArtifactError, ArtifactSpec, Digest, TransactionRequest};

fn request() -> TransactionRequest {
    let artifact = ArtifactSpec::new(
        "https://repo.example/",
        "https://repo.example/",
        "a.rpm",
        Digest::Sha256("0".repeat(64)),
        1,
    )
    .unwrap();
    TransactionRequest::for_specs(&[artifact]).unwrap()
}

#[test]
fn established_session_survives_lock_path_replacement() {
    if std::env::var_os("DNFAST_REPLACEMENT_CHILD").is_some() {
        let root = std::env::var("DNFAST_REPLACEMENT_ROOT").unwrap();
        match ArtifactCache::new(root).begin_transaction(&request()) {
            Ok(_) => println!("ACQUIRED"),
            Err(ArtifactError::Busy(_)) => println!("BUSY"),
            Err(error) => panic!("unexpected child error: {error}"),
        }
        return;
    }
    // Given
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("alias");
    std::fs::create_dir(temp.path().join("bridge")).unwrap();
    let first = ArtifactCache::new(&root).begin_transaction(&request()).unwrap();
    let directory = root.join("artifacts/sha256");
    std::fs::rename(directory.join(".transaction-lock"), directory.join(".transaction-lock.old")).unwrap();
    let replacement = std::fs::File::create(directory.join(".transaction-lock")).unwrap();
    std::fs::set_permissions(directory.join(".transaction-lock"), std::fs::Permissions::from_mode(0o600)).unwrap();
    drop(replacement);
    // When
    let parent = temp.path().to_string_lossy();
    let aliases = [
        temp.path().join("bridge/../alias"),
        temp.path().join("alias/."),
        std::path::PathBuf::from(format!("{parent}//alias")),
    ];
    let held = aliases.iter().map(|alias| run_child(alias)).collect::<Vec<_>>();
    // Then
    assert!(held.iter().all(|result| result == "BUSY"));
    assert_eq!(first.remaining(), 1);
    drop(first);
    assert_eq!(run_child(&aliases[0]), "ACQUIRED");
}

#[test]
fn root_crossing_and_non_utf8_cache_paths_reject_before_creation() {
    // Given
    let crossing = ArtifactCache::new("/../../tmp/dnfast-cross-root");
    let invalid = std::path::PathBuf::from(std::ffi::OsString::from_vec(b"/tmp/dnfast-\xff".to_vec()));
    // When
    let crossing_result = crossing.begin_transaction(&request());
    let invalid_result = ArtifactCache::new(invalid).begin_transaction(&request());
    // Then
    assert!(matches!(crossing_result, Err(ArtifactError::Policy(_))));
    assert!(matches!(invalid_result, Err(ArtifactError::Policy(_))));
}

#[test]
fn filesystem_root_aliases_and_existing_wrong_mode_fail_without_chmod() {
    // Given
    let root_mode = std::fs::metadata("/").unwrap().permissions().mode();
    let artifacts_before = std::fs::symlink_metadata("/artifacts").ok().map(|metadata| (metadata.ino(), metadata.mode()));
    let temp = tempfile::tempdir().unwrap();
    let existing = temp.path().join("existing");
    std::fs::create_dir(&existing).unwrap();
    std::fs::set_permissions(&existing, std::fs::Permissions::from_mode(0o777)).unwrap();
    // When
    let direct = ArtifactCache::new("/").begin_transaction(&request());
    let alias = ArtifactCache::new("/tmp/..").begin_transaction(&request());
    let wrong_mode = ArtifactCache::new(&existing).begin_transaction(&request());
    // Then
    assert!(matches!(direct, Err(ArtifactError::Policy(_))));
    assert!(matches!(alias, Err(ArtifactError::Policy(_))));
    assert!(matches!(wrong_mode, Err(ArtifactError::Io(_))));
    assert_eq!(std::fs::metadata("/").unwrap().permissions().mode(), root_mode);
    assert_eq!(std::fs::metadata(&existing).unwrap().permissions().mode() & 0o777, 0o777);
    assert_eq!(std::fs::symlink_metadata("/artifacts").ok().map(|metadata| (metadata.ino(), metadata.mode())), artifacts_before);
}

#[test]
fn newly_created_cache_tree_is_private_and_usable() {
    // Given
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("new/inner/cache");
    // When
    let session = ArtifactCache::new(&root).begin_transaction(&request());
    // Then
    assert!(session.is_ok());
    for path in [temp.path().join("new"), temp.path().join("new/inner"), root] {
        assert_eq!(std::fs::metadata(path).unwrap().permissions().mode() & 0o777, 0o700);
    }
}

fn run_child(root: &std::path::Path) -> String {
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "established_session_survives_lock_path_replacement", "--nocapture"])
        .env("DNFAST_REPLACEMENT_CHILD", "1")
        .env("DNFAST_REPLACEMENT_ROOT", root)
        .output()
        .unwrap();
    assert!(output.status.success());
    String::from_utf8(output.stdout).unwrap().lines()
        .find(|line| matches!(*line, "BUSY" | "ACQUIRED"))
        .unwrap()
        .to_owned()
}

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};
#[cfg(unix)]
use std::os::unix::ffi::OsStringExt;
