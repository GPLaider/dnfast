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

fn installed_repository(directory: &tempfile::TempDir) -> Repository {
    let mut repository = primary_only_repository(directory);
    let filelists = std::process::Command::new("/usr/bin/zstd")
        .args(["-qdc", &fixture("filelists.xml.zst").display().to_string()])
        .output()
        .expect("run zstd");
    assert!(filelists.status.success(), "decode fixture filelists");
    let filelists_path = directory.path().join("filelists.xml");
    std::fs::write(&filelists_path, filelists.stdout).expect("materialized filelists");
    repository.filelists_path = filelists_path.display().to_string();
    repository
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
    let selected = cached_solve
        .actions
        .iter()
        .zip(&cached_solve.repositories)
        .find(|(identity, repository)| {
            repository.as_str() == "main" && identity.starts_with("dnfast-app-")
        })
        .expect("selected repository action");
    let selected_evidence = loaded
        .repository_package_identity_evidence("main", selected.0)
        .expect("identity-selected evidence");
    assert_eq!(selected_evidence.name, "dnfast-app");
    assert!(!selected_evidence.requires.is_empty());
    let named = loaded
        .repository_catalog_named("main", "dnfast-app")
        .expect("name-selected catalog");
    assert!(!named.is_empty());
    assert!(named.iter().all(|package| package.name == "dnfast-app"));
    assert!(named.iter().all(|package| package.requires.is_empty()));
    assert!(
        loaded
            .repository_catalog_named("main", "absent-package")
            .expect("absent name selection")
            .is_empty()
    );
    assert!(
        loaded
            .repository_package_identity_evidence("main", "absent-0:1-1.noarch")
            .is_err()
    );

    let mut rejected = NativeContext::open(Architecture::Aarch64, || false).expect("rejected");
    assert!(
        rejected
            .add_repository_solv("main", 99, 1000, &cache, b"wrong binding")
            .is_err()
    );
}

#[test]
fn filelists_extension_cache_round_trip_is_binding_checked_and_provides_paths() {
    let directory = tempfile::tempdir().expect("temporary metadata");
    let main_binding = b"dnfast native main solv fixture v1";
    let extension_binding = b"dnfast native filelists solv fixture v1";
    let main_cache = tempfile::tempfile().expect("main cache file");
    let extension_cache = tempfile::tempfile().expect("extension cache file");
    let repository = installed_repository(&directory);
    let filelists = std::fs::File::open(&repository.filelists_path).expect("filelists XML");

    let mut source = NativeContext::open(Architecture::Aarch64, || false).expect("source");
    source
        .add_repository_primary(primary_only_repository(&directory))
        .expect("primary repository");
    source
        .write_repository_solv("main", &main_cache, main_binding)
        .expect("main cache");
    source
        .extend_repository_filelists("main", &filelists)
        .expect("filelists extension");
    source
        .write_repository_solv_extension("main", &extension_cache, extension_binding)
        .expect("extension cache");
    source.prepare_solver().expect("source solver");
    let source_solve = source
        .solve_install("/usr/share/dnfast/provided", false, true)
        .expect("source filelist solve");
    assert_eq!(source_solve.actions.len(), 1);
    assert!(matches!(
        source_solve.actions[0].as_str(),
        "dnfast-file-collision-0:1.0-1.noarch" | "dnfast-file-provider-0:1.0-1.noarch"
    ));

    let mut loaded = NativeContext::open(Architecture::Aarch64, || false).expect("loaded");
    loaded
        .add_repository_solv("main", 99, 1000, &main_cache, main_binding)
        .expect("main cache load");
    loaded
        .add_repository_solv_extension("main", &extension_cache, extension_binding)
        .expect("extension cache load");
    loaded.prepare_solver().expect("loaded solver");
    let loaded_solve = loaded
        .solve_install("/usr/share/dnfast/provided", false, true)
        .expect("loaded filelist solve");
    assert_eq!(loaded_solve.actions, source_solve.actions);
    assert_eq!(loaded_solve.repositories, source_solve.repositories);

    let mut rejected = NativeContext::open(Architecture::Aarch64, || false).expect("rejected");
    rejected
        .add_repository_solv("main", 99, 1000, &main_cache, main_binding)
        .expect("main cache load");
    assert!(
        rejected
            .add_repository_solv_extension("main", &extension_cache, b"wrong binding")
            .is_err()
    );
}

#[test]
fn installed_solv_cache_restores_the_pool_installed_repository() {
    let directory = tempfile::tempdir().expect("temporary metadata");
    let binding = b"dnfast installed solv cache fixture v1";
    let cache = tempfile::tempfile().expect("cache file");
    let mut source = NativeContext::open(Architecture::Aarch64, || false).expect("source");
    source
        .add_installed_repository(installed_repository(&directory))
        .expect("installed repository");
    source
        .write_repository_solv("main", &cache, binding)
        .expect("write installed cache");

    let mut loaded = NativeContext::open(Architecture::Aarch64, || false).expect("loaded");
    loaded
        .add_installed_repository_solv(&cache, binding)
        .expect("load installed cache");
    loaded
        .prepare_solver()
        .expect("prepare cached installed pool");
    assert!(
        loaded
            .has_provider("dnfast-app")
            .expect("installed provider")
    );
    let solve = loaded
        .solve_install_many(&["dnfast-app"], true, true)
        .expect("already installed solve");
    assert!(solve.actions.is_empty());
}
