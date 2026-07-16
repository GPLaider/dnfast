use std::{env, fs};

use dnfast_cache::{Cache, RepomdAuthentication};

#[test]
#[ignore = "requires DNFAST_REAL_REPOMD, DNFAST_REAL_PRIMARY, and DNFAST_REAL_FILELISTS"]
fn publishes_real_fedora_metadata_with_full_verification() {
    let repomd = fs::read(env::var_os("DNFAST_REAL_REPOMD").expect("DNFAST_REAL_REPOMD"))
        .expect("read repomd");
    let primary = fs::read(env::var_os("DNFAST_REAL_PRIMARY").expect("DNFAST_REAL_PRIMARY"))
        .expect("read primary");
    let filelists = fs::read(env::var_os("DNFAST_REAL_FILELISTS").expect("DNFAST_REAL_FILELISTS"))
        .expect("read filelists");
    let directory = tempfile::tempdir().expect("cache directory");
    let snapshot = Cache::new(directory.path())
        .publish_verified_complete_fast(
            "fedora-real",
            &repomd,
            &primary,
            &filelists,
            Some("https://mirror.example/fedora/repodata/repomd.xml"),
            RepomdAuthentication::TransportOnly,
        )
        .expect("publish verified Fedora metadata");
    assert!(!snapshot.digest.is_empty());
    assert!(!snapshot.packages.is_empty());
}
