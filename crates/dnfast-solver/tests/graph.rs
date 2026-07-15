use dnfast_core::{
    Action, Architecture, Evra, InstalledInventory, PackageSpec, RepositoryBinding, Sha256Digest,
    SolverPolicy, TransactionIntent,
};
use dnfast_solver::{
    CandidatePackage, DependencyEdge, DependencyKind, IntegritySnapshots, PlanBuilder,
    RequestedRelation, ResolvedAction, ResolvedOperation,
};

fn digest(byte: char) -> String {
    byte.to_string().repeat(64)
}
fn snapshots() -> IntegritySnapshots {
    let binding = RepositoryBinding::new(
        "main",
        Sha256Digest::parse(digest('5'), "generation_sha256").unwrap(),
        Sha256Digest::parse(digest('6'), "origin_sha256").unwrap(),
        Sha256Digest::parse(digest('7'), "trust_sha256").unwrap(),
    )
    .unwrap();
    IntegritySnapshots::new(
        [
            &digest('1'),
            &digest('2'),
            &digest('3'),
            &digest('4'),
            &digest('8'),
        ],
        vec![binding],
    )
    .unwrap()
}
fn candidate(name: &str) -> CandidatePackage {
    CandidatePackage {
        name: name.into(),
        evra: Evra::new(0, "1", "1", Architecture::Noarch),
        vendor: "Fedora".into(),
        repo_id: "main".into(),
        priority: 99,
        cost: 1000,
        package_size: 1,
        installed_size: 1,
        checksum_sha256: digest('a'),
        location: format!("packages/{name}.rpm"),
        excluded: false,
        modular: false,
    }
}
fn action(name: &str, parents: &[(&str, DependencyKind)], prose: &str) -> ResolvedAction {
    ResolvedAction {
        operation: ResolvedOperation::Install,
        name: name.into(),
        requested: parents.is_empty(),
        requested_spec: parents
            .is_empty()
            .then(|| PackageSpec::parse(name).unwrap()),
        requested_relation: false,
        candidate: Some(candidate(name)),
        installed_instance: None,
        installed_header_sha256: None,
        installed_vendor: None,
        dependency_edges: parents
            .iter()
            .map(|(parent, kind)| DependencyEdge {
                parent: (*parent).into(),
                kind: *kind,
            })
            .collect(),
        required_by_remaining: vec![],
        unresolved_dependencies: vec![],
        provenance: None,
        introduced_by_requested: false,
        solver_rule: prose.into(),
    }
}
fn build<'a>(
    intent: &'a TransactionIntent,
    candidates: &'a [CandidatePackage],
    inventory: &'a InstalledInventory,
    snapshots: &'a IntegritySnapshots,
    policy: &'a SolverPolicy,
) -> PlanBuilder<'a> {
    PlanBuilder {
        intent,
        candidates,
        inventory,
        snapshots,
        policy,
        expires_at_unix: 100,
    }
}

#[test]
fn missing_parent_self_edge_and_disconnected_cycle_reject() {
    let intent = TransactionIntent::from_package_names(Action::Install, &["app"]).unwrap();
    let inventory = InstalledInventory::new("sqlite", "6.0.1", vec![]).unwrap();
    let snapshots = snapshots();
    let policy = SolverPolicy::fedora44_aarch64(vec![], vec![]);
    let candidates = [
        candidate("app"),
        candidate("orphan"),
        candidate("x"),
        candidate("y"),
    ];
    let builder = build(&intent, &candidates, &inventory, &snapshots, &policy);
    assert!(
        builder
            .build(&[
                action("app", &[], "root"),
                action("orphan", &[("ghost", DependencyKind::Strong)], "ghost")
            ])
            .is_err()
    );
    assert!(
        builder
            .build(&[action("app", &[("app", DependencyKind::Strong)], "self")])
            .is_err()
    );
    assert!(
        builder
            .build(&[
                action("app", &[], "root"),
                action("x", &[("y", DependencyKind::Strong)], "cycle"),
                action("y", &[("x", DependencyKind::Strong)], "cycle")
            ])
            .is_err()
    );
}

#[test]
fn typed_edges_override_misleading_prose_and_shared_dep_reaches_two_roots() {
    let intent =
        TransactionIntent::from_package_names(Action::Install, &["app-a", "app-b"]).unwrap();
    let inventory = InstalledInventory::new("sqlite", "6.0.1", vec![]).unwrap();
    let snapshots = snapshots();
    let policy = SolverPolicy::fedora44_aarch64(vec![], vec![]);
    let candidates = [candidate("app-a"), candidate("app-b"), candidate("shared")];
    let plan = build(&intent, &candidates, &inventory, &snapshots, &policy)
        .build(&[
            action("app-b", &[], "root"),
            action(
                "shared",
                &[
                    ("app-b", DependencyKind::Weak),
                    ("app-a", DependencyKind::Weak),
                ],
                "STRONG prose ignored",
            ),
            action("app-a", &[], "root"),
        ])
        .unwrap();
    assert_eq!(plan.actions()[0].name(), "shared");
    assert_eq!(
        plan.actions()[0].relation(),
        &RequestedRelation::WeakDependency
    );
    let strong = build(&intent, &candidates, &inventory, &snapshots, &policy)
        .build(&[
            action("app-a", &[], "root"),
            action("app-b", &[], "root"),
            action(
                "shared",
                &[("app-a", DependencyKind::Strong)],
                "weak prose ignored",
            ),
        ])
        .unwrap();
    assert_eq!(
        strong
            .actions()
            .iter()
            .find(|item| item.name() == "shared")
            .unwrap()
            .relation(),
        &RequestedRelation::Dependency
    );
}

#[test]
fn explicitly_requested_dependency_keeps_user_reason_and_dependency_order() {
    let intent = TransactionIntent::from_package_names(Action::Install, &["app", "dep"]).unwrap();
    let inventory = InstalledInventory::new("sqlite", "6.0.1", vec![]).unwrap();
    let snapshots = snapshots();
    let policy = SolverPolicy::fedora44_aarch64(vec![], vec![]);
    let candidates = [candidate("app"), candidate("dep")];
    let mut dep = action(
        "dep",
        &[("app", DependencyKind::Strong)],
        "dependency and explicit",
    );
    dep.requested = true;
    dep.requested_spec = Some(PackageSpec::parse("dep").unwrap());
    let plan = build(&intent, &candidates, &inventory, &snapshots, &policy)
        .build(&[action("app", &[], "root"), dep])
        .unwrap();
    assert_eq!(plan.actions()[0].name(), "dep");
    assert_eq!(plan.actions()[0].relation(), &RequestedRelation::Requested);
}
