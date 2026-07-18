use dnfast_core::{
    Action, Architecture, CanonicalPlan, Evra, InstalledInventory, InstalledPackage, PackageAction,
    PackageReason, PlanIntegrity, RepositoryBinding, Sha256Digest, SolverPolicy, TransactionIntent,
};
use dnfast_state::ReasonStateStore;
use std::os::unix::fs::PermissionsExt;

const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const C: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

#[test]
fn exact_reason_state_records_dependencies_and_carries_them_across_replacement() {
    let directory = tempfile::tempdir().unwrap();
    let store = ReasonStateStore::open(&directory.path().join("reasons")).unwrap();
    let policy = SolverPolicy::fedora44_x86_64(vec![], vec![]);
    let before = inventory(vec![package("root", "1", 1, A)]);
    let installed = inventory(vec![
        package("root", "1", 1, A),
        package("dependency", "1", 2, B),
    ]);
    let install = plan(
        Action::Install,
        &["root"],
        vec![PackageAction::install_with_vendor(
            "dependency",
            evra("1"),
            "fedora",
            "Fedora",
            PackageReason::Dependency,
        )],
    );
    store
        .record_success(&before, &installed, &install, &policy)
        .unwrap();
    assert_eq!(
        store.autoremove_candidates(&installed, &policy).unwrap(),
        vec!["dependency"]
    );

    let upgraded = inventory(vec![
        package("root", "1", 1, A),
        package("dependency", "2", 3, C),
    ]);
    let upgrade = plan(
        Action::Upgrade,
        &[],
        vec![
            PackageAction::upgrade_with_identity(
                "dependency",
                evra("1"),
                evra("2"),
                "fedora",
                "Fedora",
                "Fedora",
                PackageReason::User,
                2,
                B,
            )
            .unwrap(),
        ],
    );
    store
        .record_success(&installed, &upgraded, &upgrade, &policy)
        .unwrap();
    assert_eq!(
        store.autoremove_candidates(&upgraded, &policy).unwrap(),
        vec!["dependency"]
    );
}

#[test]
fn missing_or_protected_reason_state_fails_closed() {
    let directory = tempfile::tempdir().unwrap();
    let store = ReasonStateStore::open(&directory.path().join("reasons")).unwrap();
    let installed = inventory(vec![package("protected", "1", 1, A)]);
    let policy = SolverPolicy::fedora44_x86_64(vec!["protected".into()], vec![]);
    assert!(
        store
            .autoremove_candidates(&installed, &policy)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn retained_reason_state_fd_is_not_redirected_by_path_replacement() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("reasons");
    let retained = directory.path().join("retained");
    let store = ReasonStateStore::open(&path).unwrap();

    std::fs::rename(&path, &retained).unwrap();
    std::fs::create_dir(&path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();

    let policy = SolverPolicy::fedora44_x86_64(vec![], vec![]);
    let before = inventory(vec![package("root", "1", 1, A)]);
    let after = inventory(vec![
        package("root", "1", 1, A),
        package("dependency", "1", 2, B),
    ]);
    let install = plan(
        Action::Install,
        &["root"],
        vec![PackageAction::install_with_vendor(
            "dependency",
            evra("1"),
            "fedora",
            "Fedora",
            PackageReason::Dependency,
        )],
    );
    store
        .record_success(&before, &after, &install, &policy)
        .unwrap();

    assert!(retained.join("state.json").is_file());
    assert!(!path.join("state.json").exists());
    assert_eq!(
        store.autoremove_candidates(&after, &policy).unwrap(),
        vec!["dependency"]
    );
    assert!(
        ReasonStateStore::open(&path)
            .unwrap()
            .autoremove_candidates(&after, &policy)
            .unwrap()
            .is_empty()
    );
}

fn plan(action: Action, names: &[&str], actions: Vec<PackageAction>) -> CanonicalPlan {
    CanonicalPlan::new(
        TransactionIntent::from_package_names(action, names).unwrap(),
        integrity(),
        10,
        actions,
    )
    .unwrap()
}

fn integrity() -> PlanIntegrity {
    let binding = RepositoryBinding::new(
        "fedora",
        Sha256Digest::parse(A, "generation_sha256").unwrap(),
        Sha256Digest::parse(B, "origin_sha256").unwrap(),
        Sha256Digest::parse(C, "trust_sha256").unwrap(),
    )
    .unwrap();
    PlanIntegrity::new([A, B, C, A, B], vec![binding]).unwrap()
}

fn evra(version: &str) -> Evra {
    Evra::new(0, version, "1", Architecture::X86_64)
}

fn package(name: &str, version: &str, instance: u64, digest: &str) -> InstalledPackage {
    InstalledPackage::new(name, evra(version), "Fedora", instance, instance, digest).unwrap()
}

fn inventory(packages: Vec<InstalledPackage>) -> InstalledInventory {
    InstalledInventory::new("sqlite", "6", packages).unwrap()
}
