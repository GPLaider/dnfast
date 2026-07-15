use std::{process::Command, time::{Duration, Instant}};

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
fn nested_busy_does_not_release_live_parent_process_lock() {
    if std::env::var_os("DNFAST_REENTRANT_CHILD").is_some() {
        let root = std::env::var("DNFAST_REENTRANT_ROOT").unwrap();
        match ArtifactCache::new(root).begin_transaction(&request()) {
            Ok(_) => println!("ACQUIRED"),
            Err(ArtifactError::Busy(_)) => println!("BUSY"),
            Err(error) => panic!("unexpected child error: {error}"),
        }
        return;
    }
    // Given
    let temp = tempfile::tempdir().unwrap();
    let cache = ArtifactCache::new(temp.path());
    let first = cache.begin_transaction(&request()).unwrap();
    // When
    let nested = cache.begin_transaction(&request());
    let started = Instant::now();
    let held = run_child(temp.path());
    let elapsed = started.elapsed();
    // Then
    assert!(matches!(nested, Err(ArtifactError::Busy(_))));
    assert_eq!(held.trim(), "BUSY");
    assert!(elapsed >= Duration::from_secs(2));
    assert!(elapsed < Duration::from_secs(3));
    assert_eq!(first.remaining(), 1);
    drop(first);
    assert_eq!(run_child(temp.path()).trim(), "ACQUIRED");
}

fn run_child(root: &std::path::Path) -> String {
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "nested_busy_does_not_release_live_parent_process_lock", "--nocapture"])
        .env("DNFAST_REENTRANT_CHILD", "1")
        .env("DNFAST_REENTRANT_ROOT", root)
        .output()
        .unwrap();
    assert!(output.status.success());
    String::from_utf8(output.stdout).unwrap().lines()
        .find(|line| matches!(*line, "BUSY" | "ACQUIRED"))
        .unwrap()
        .to_owned()
}
