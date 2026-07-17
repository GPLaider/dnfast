use std::path::{Path, PathBuf};

use dnfast_core::Architecture;
use dnfast_native::{NativeContext, Repository};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/rpm/generated-build10/repos/main/repodata")
        .join(name)
}

fn primary_only_repository(directory: &tempfile::TempDir) -> Repository {
    let primary = std::process::Command::new("/usr/bin/zstd")
        .args(["-qdc", &fixture("primary.xml.zst").display().to_string()])
        .output()
        .expect("run zstd");
    assert!(primary.status.success(), "decode fixture primary");
    let primary_path = directory.path().join("primary.xml");
    std::fs::write(&primary_path, primary.stdout).expect("materialized primary");
    Repository {
        id: "main".into(),
        repomd_path: fixture("repomd.xml").display().to_string(),
        primary_path: primary_path.display().to_string(),
        filelists_path: directory.path().join("unused").display().to_string(),
        priority: 99,
        cost: 1000,
    }
}

#[test]
fn solv_cache_round_trip_preserves_packages_relations_and_solves() {
    let directory = tempfile::tempdir().expect("temporary metadata");
    let binding = b"dnfast native solv cache fixture v1";
    let cache = tempfile::tempfile().expect("cache file");
    let mut source = NativeContext::open(Architecture::Aarch64, || false).expect("source");
    source
        .add_repository_primary(primary_only_repository(&directory))
        .expect("primary repository");
    let source_packages = source.repository_packages("main").expect("source packages");
    assert!(!source_packages.is_empty());
    assert!(source_packages.iter().any(|package| {
        package.name == "dnfast-app"
            && package
                .requires
                .iter()
                .any(|relation| relation.starts_with("dnfast-dep "))
    }));
    source
        .write_repository_solv("main", &cache, binding)
        .expect("write cache");
    source.prepare_solver().expect("prepare source");
    let source_solve = source
        .solve_install_many(&["dnfast-app"], true, true)
        .expect("source solve");

    let mut loaded = NativeContext::open(Architecture::Aarch64, || false).expect("loaded");
    loaded
        .add_repository_solv("main", 99, 1000, &cache, binding)
        .expect("load cache");
    assert_eq!(
        loaded.repository_packages("main").expect("cached packages"),
        source_packages
    );
    loaded.prepare_solver().expect("prepare cached");
    assert!(loaded.has_provider("dnfast-app").expect("provider query"));
    let cached_solve = loaded
        .solve_install_many(&["dnfast-app"], true, true)
        .expect("cached solve");
    assert_eq!(cached_solve.actions, source_solve.actions);
    assert_eq!(cached_solve.decisions, source_solve.decisions);

    let mut rejected = NativeContext::open(Architecture::Aarch64, || false).expect("rejected");
    assert!(
        rejected
            .add_repository_solv("main", 99, 1000, &cache, b"wrong binding")
            .is_err()
    );
}
