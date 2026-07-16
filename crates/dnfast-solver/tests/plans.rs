use dnfast_core::{
    Action, Architecture, Evra, InstalledInventory, InstalledPackage, PackageSpec,
    RepositoryBinding, Sha256Digest, SolverPolicy, TransactionIntent,
};
use dnfast_solver::{
    CandidatePackage, DependencyEdge, DependencyKind, IntegritySnapshots, PlanBuilder,
    ReSolveContract, ResolvedAction, ResolvedOperation,
};

fn digest(byte: char) -> String {
    byte.to_string().repeat(64)
}
fn candidate(name: &str, version: &str, repo: &str, priority: u32, cost: u32) -> CandidatePackage {
    CandidatePackage {
        name: name.into(),
        evra: Evra::new(0, version, "1", Architecture::Noarch),
        vendor: "Fedora".into(),
        repo_id: repo.into(),
        priority,
        cost,
        package_size: 42,
        installed_size: 84,
        checksum_sha256: digest('a'),
        location: format!("packages/{name}-{version}.rpm"),
        excluded: false,
        modular: false,
    }
}
fn snapshots() -> IntegritySnapshots {
    snapshots_for(&["aaa", "fedora", "zzz"])
}
fn snapshots_for(repository_ids: &[&str]) -> IntegritySnapshots {
    let bindings = repository_ids
        .iter()
        .map(|id| {
            RepositoryBinding::new(
                *id,
                Sha256Digest::parse(digest('5'), "generation_sha256").unwrap(),
                Sha256Digest::parse(digest('6'), "origin_sha256").unwrap(),
                Sha256Digest::parse(digest('7'), "trust_sha256").unwrap(),
            )
            .unwrap()
        })
        .collect();
    IntegritySnapshots::new(
        [
            &digest('1'),
            &digest('2'),
            &digest('3'),
            &digest('4'),
            &digest('8'),
        ],
        bindings,
    )
    .unwrap()
}
fn install(name: &str, package: CandidatePackage, requested_by: Option<&str>) -> ResolvedAction {
    ResolvedAction {
        operation: ResolvedOperation::Install,
        name: name.into(),
        requested: requested_by.is_none(),
        requested_spec: requested_by
            .is_none()
            .then(|| PackageSpec::parse(name).unwrap()),
        requested_relation: false,
        candidate: Some(package),
        installed_instance: None,
        installed_header_sha256: None,
        installed_vendor: None,
        dependency_edges: requested_by
            .map(|parent| {
                vec![DependencyEdge {
                    parent: parent.into(),
                    kind: DependencyKind::Strong,
                }]
            })
            .unwrap_or_default(),
        required_by_remaining: Vec::new(),
        unresolved_dependencies: Vec::new(),
        provenance: None,
        introduced_by_requested: false,
        solver_rule: if requested_by.is_some() {
            "dependency requires capability"
        } else {
            "requested package selection"
        }
        .into(),
    }
}
fn inventory(packages: Vec<InstalledPackage>) -> InstalledInventory {
    InstalledInventory::new("sqlite", "6.0.1", packages).unwrap()
}
fn policy() -> SolverPolicy {
    SolverPolicy::fedora44_aarch64(vec!["dnfast".into()], vec!["kernel".into()])
}

#[test]
fn canonical_proposal_digest_is_stable_for_equivalent_solver_action_order() {
    // Given: one solver result expressed in two equivalent action orders.
    let intent = TransactionIntent::from_package_names(Action::Install, &["app"]).unwrap();
    let app = candidate("app", "1", "fedora", 99, 1000);
    let dependency = candidate("dependency", "1", "fedora", 99, 1000);
    let candidates = [app.clone(), dependency.clone()];
    let actions = [
        install("app", app, None),
        install("dependency", dependency, Some("app")),
    ];
    let state = inventory(Vec::new());
    let integrity = snapshots();
    let solver_policy = policy();
    let builder = PlanBuilder {
        intent: &intent,
        snapshots: &integrity,
        inventory: &state,
        policy: &solver_policy,
        candidates: &candidates,
        expires_at_unix: 100,
    };

    // When: the public plan builder constructs each canonical proposal.
    let forward = builder.build(&actions).unwrap();
    let reverse = builder
        .build(&[actions[1].clone(), actions[0].clone()])
        .unwrap();

    // Then: the observable canonical proposal and digest remain identical.
    assert_eq!(
        forward.canonical_json().unwrap(),
        reverse.canonical_json().unwrap()
    );
    assert_eq!(forward.digest().unwrap(), reverse.digest().unwrap());
}

#[test]
fn solver_rejects_candidate_from_a_repository_outside_the_selected_snapshot_subset() {
    // Given: an exact planning integrity selection containing only `fedora`.
    let intent = TransactionIntent::from_package_names(Action::Install, &["app"]).unwrap();
    let candidate = candidate("app", "1", "updates", 99, 1000);
    let candidates = [candidate.clone()];
    let inventory = inventory(Vec::new());
    let integrity = snapshots_for(&["fedora"]);
    let policy = policy();
    let builder = PlanBuilder {
        intent: &intent,
        snapshots: &integrity,
        inventory: &inventory,
        policy: &policy,
        candidates: &candidates,
        expires_at_unix: 100,
    };

    // When: solver construction receives a candidate from an unselected repository.
    let result = builder.build(&[install("app", candidate, None)]);

    // Then: solving stops before a canonical proposal is created.
    assert!(
        matches!(result, Err(dnfast_solver::PlanError::RepositoryNotSelected(repository)) if repository == "updates")
    );
}

#[test]
fn app_dependency_plan_is_byte_identical_and_matches_golden() {
    let intent = TransactionIntent::from_package_names(Action::Install, &["dnfast-app"]).unwrap();
    let app = candidate("dnfast-app", "1.0", "fedora", 99, 1000);
    let dependency = candidate("dnfast-dependency", "1.0", "fedora", 99, 1000);
    let candidates = vec![app.clone(), dependency.clone()];
    let actions = vec![
        install("dnfast-app", app, None),
        install("dnfast-dependency", dependency, Some("dnfast-app")),
    ];
    let state = inventory(Vec::new());
    let snapshots = snapshots();
    let policy = policy();
    let builder = PlanBuilder {
        intent: &intent,
        snapshots: &snapshots,
        inventory: &state,
        policy: &policy,
        candidates: &candidates,
        expires_at_unix: 100,
    };
    let first = builder.build(&actions).unwrap();
    let second = builder
        .build(&actions.into_iter().rev().collect::<Vec<_>>())
        .unwrap();
    assert_eq!(
        first.canonical_json().unwrap(),
        second.canonical_json().unwrap()
    );
    assert_eq!(first.digest().unwrap(), second.digest().unwrap());
    assert_eq!(
        String::from_utf8(first.canonical_json().unwrap()).unwrap(),
        include_str!("golden/app-dependency.json").trim_end()
    );
    ReSolveContract::require_equal(&first, &second).unwrap();
    assert_eq!(
        dnfast_solver::CanonicalSolverPlan::from_canonical_json(
            &first.canonical_json().unwrap(),
            100
        )
        .unwrap(),
        first
    );
    assert!(
        dnfast_solver::CanonicalSolverPlan::from_canonical_json(
            &first.canonical_json().unwrap(),
            101
        )
        .is_err()
    );
}

#[test]
fn highest_evr_then_priority_cost_and_repo_ties_are_enforced() {
    let intent = TransactionIntent::from_package_names(Action::Install, &["app"]).unwrap();
    let old = candidate("app", "1", "aaa", 1, 1);
    let expensive = candidate("app", "2", "zzz", 99, 1000);
    let preferred = candidate("app", "2", "aaa", 10, 50);
    let candidates = vec![old, expensive, preferred.clone()];
    let state = inventory(Vec::new());
    let snapshots = snapshots();
    let policy = policy();
    let builder = PlanBuilder {
        intent: &intent,
        snapshots: &snapshots,
        inventory: &state,
        policy: &policy,
        candidates: &candidates,
        expires_at_unix: 100,
    };
    assert!(builder.build(&[install("app", preferred, None)]).is_ok());
    assert!(
        builder
            .build(&[install("app", candidates[1].clone(), None)])
            .is_err()
    );
}

#[test]
fn validated_dependency_may_use_a_constraint_compatible_non_latest_candidate() {
    let intent = TransactionIntent::from_package_names(Action::Install, &["app"]).unwrap();
    let app = candidate("app", "1", "fedora", 99, 1000);
    let dependency_v1 = candidate("dependency", "1", "fedora", 99, 1000);
    let dependency_v2 = candidate("dependency", "2", "fedora", 99, 1000);
    let candidates = [app.clone(), dependency_v1.clone(), dependency_v2];
    let state = inventory(Vec::new());
    let snapshots = snapshots();
    let policy = policy();
    let builder = PlanBuilder {
        intent: &intent,
        snapshots: &snapshots,
        inventory: &state,
        policy: &policy,
        candidates: &candidates,
        expires_at_unix: 100,
    };
    assert!(
        builder
            .build(&[
                install("app", app, None),
                install("dependency", dependency_v1, Some("app")),
            ])
            .is_ok()
    );
}

#[test]
fn exact_native_relation_may_select_h1_while_bare_h1_stays_non_preferred() {
    // Given: H2 is the global name preference, while H1 is a one-to-one exact relation result.
    let h1 = candidate("app", "1", "fedora", 99, 1000);
    let h2 = candidate("app", "2", "fedora", 99, 1000);
    let candidates = [h1.clone(), h2.clone()];
    let inventory = inventory(Vec::new());
    let snapshots = snapshots();
    let policy = policy();
    let relation_intent =
        TransactionIntent::from_package_names(Action::Install, &["app = 1"]).unwrap();
    let bare_intent = TransactionIntent::from_package_names(Action::Install, &["app"]).unwrap();
    let relation_builder = PlanBuilder {
        intent: &relation_intent,
        snapshots: &snapshots,
        inventory: &inventory,
        policy: &policy,
        candidates: &candidates,
        expires_at_unix: 100,
    };
    let bare_builder = PlanBuilder {
        intent: &bare_intent,
        snapshots: &snapshots,
        inventory: &inventory,
        policy: &policy,
        candidates: &candidates,
        expires_at_unix: 100,
    };
    let mut relation_h1 = install("app", h1.clone(), None);
    relation_h1.requested_spec = Some(PackageSpec::parse("app = 1").unwrap());
    relation_h1.requested_relation = true;

    // When: the planner receives the relation H1 result and bare H1/H2 results.
    let relation = relation_builder.build(&[relation_h1]);
    let bare_h1 = bare_builder.build(&[install("app", h1, None)]);
    let bare_h2 = bare_builder.build(&[install("app", h2, None)]);

    // Then: only the exact native relation is allowed to override global preference.
    assert!(relation.is_ok());
    assert!(matches!(bare_h1, Err(dnfast_solver::PlanError::NonPreferred(name)) if name == "app"));
    assert!(bare_h2.is_ok());
}

#[test]
fn protected_and_reverse_dependency_removals_fail_before_plan() {
    let package = InstalledPackage::new(
        "dnfast",
        Evra::new(0, "1", "1", Architecture::Aarch64),
        "Fedora",
        7,
        8,
        digest('b'),
    )
    .unwrap();
    let other = InstalledPackage::new(
        "other",
        Evra::new(0, "1", "1", Architecture::Aarch64),
        "Fedora",
        8,
        8,
        digest('c'),
    )
    .unwrap();
    let state = inventory(vec![package, other]);
    let snapshots = snapshots();
    let policy = policy();
    let intent = TransactionIntent::from_package_names(Action::Remove, &["dnfast"]).unwrap();
    let builder = PlanBuilder {
        intent: &intent,
        snapshots: &snapshots,
        inventory: &state,
        policy: &policy,
        candidates: &[],
        expires_at_unix: 100,
    };
    let action = ResolvedAction {
        operation: ResolvedOperation::Remove,
        name: "dnfast".into(),
        requested: true,
        requested_spec: Some(PackageSpec::parse("dnfast").unwrap()),
        requested_relation: false,
        candidate: None,
        installed_instance: Some(7),
        installed_header_sha256: None,
        installed_vendor: Some("Fedora".into()),
        dependency_edges: vec![],
        required_by_remaining: Vec::new(),
        unresolved_dependencies: Vec::new(),
        provenance: None,
        introduced_by_requested: false,
        solver_rule: "requested removal".into(),
    };
    assert!(builder.build(std::slice::from_ref(&action)).is_err());
    let mut reverse = action;
    reverse.name = "other".into();
    reverse.installed_instance = Some(8);
    reverse.required_by_remaining.push("consumer".into());
    assert!(builder.build(&[reverse]).is_err());
}

#[test]
fn excluded_modular_and_unsafe_upgrade_candidates_fail_closed() {
    let installed = InstalledPackage::new(
        "app",
        Evra::new(0, "2", "1", Architecture::Noarch),
        "Fedora",
        9,
        8,
        digest('b'),
    )
    .unwrap();
    let state = inventory(vec![installed]);
    let snapshots = snapshots();
    let policy = policy();
    let intent = TransactionIntent::from_package_names(Action::Upgrade, &[]).unwrap();
    for mutation in 0..3 {
        let mut package = candidate(
            "app",
            if mutation == 2 { "1" } else { "3" },
            "fedora",
            99,
            1000,
        );
        if mutation == 0 {
            package.excluded = true;
        }
        if mutation == 1 {
            package.modular = true;
        }
        let candidates = vec![package.clone()];
        let builder = PlanBuilder {
            intent: &intent,
            snapshots: &snapshots,
            inventory: &state,
            policy: &policy,
            candidates: &candidates,
            expires_at_unix: 100,
        };
        let action = ResolvedAction {
            operation: ResolvedOperation::Upgrade,
            name: "app".into(),
            requested: true,
            requested_spec: None,
            requested_relation: false,
            candidate: Some(package),
            installed_instance: Some(9),
            installed_header_sha256: None,
            installed_vendor: Some("Fedora".into()),
            dependency_edges: vec![],
            required_by_remaining: Vec::new(),
            unresolved_dependencies: Vec::new(),
            provenance: None,
            introduced_by_requested: false,
            solver_rule: "upgrade newest".into(),
        };
        assert!(builder.build(&[action]).is_err());
    }
    let mut switched = candidate("app", "3", "fedora", 99, 1000);
    switched.vendor = "Other".into();
    let candidates = vec![switched.clone()];
    let builder = PlanBuilder {
        intent: &intent,
        snapshots: &snapshots,
        inventory: &state,
        policy: &policy,
        candidates: &candidates,
        expires_at_unix: 100,
    };
    let action = ResolvedAction {
        operation: ResolvedOperation::Upgrade,
        name: "app".into(),
        requested: true,
        requested_spec: None,
        requested_relation: false,
        candidate: Some(switched),
        installed_instance: Some(9),
        installed_header_sha256: None,
        installed_vendor: Some("Fedora".into()),
        dependency_edges: vec![],
        required_by_remaining: Vec::new(),
        unresolved_dependencies: Vec::new(),
        provenance: None,
        introduced_by_requested: false,
        solver_rule: "upgrade newest".into(),
    };
    assert!(builder.build(&[action]).is_err());
}

#[test]
fn root_resolve_contract_rejects_any_action_change() {
    let intent = TransactionIntent::from_package_names(Action::Install, &["app"]).unwrap();
    let first = candidate("app", "1", "fedora", 99, 1000);
    let second = candidate("app", "2", "fedora", 99, 1000);
    let state = inventory(Vec::new());
    let snapshots = snapshots();
    let policy = policy();
    let build = |package: CandidatePackage, candidates: &[CandidatePackage]| {
        PlanBuilder {
            intent: &intent,
            snapshots: &snapshots,
            inventory: &state,
            policy: &policy,
            candidates,
            expires_at_unix: 100,
        }
        .build(&[install("app", package, None)])
        .unwrap()
    };
    let proposed_candidates = [first.clone()];
    let root_candidates = [second.clone()];
    let proposed = build(first, &proposed_candidates);
    let root = build(second, &root_candidates);
    assert!(ReSolveContract::require_equal(&proposed, &root).is_err());
}

#[test]
fn successful_remove_and_upgrade_use_installed_inventory_and_goldens() {
    let old = InstalledPackage::new(
        "app",
        Evra::new(0, "1", "1", Architecture::Noarch),
        "Fedora",
        9,
        8,
        digest('b'),
    )
    .unwrap();
    let state = inventory(vec![old]);
    let snapshots = snapshots();
    let policy = policy();
    let remove_intent = TransactionIntent::from_package_names(Action::Remove, &["app"]).unwrap();
    let remove = ResolvedAction {
        operation: ResolvedOperation::Remove,
        name: "app".into(),
        requested: true,
        requested_spec: Some(PackageSpec::parse("app").unwrap()),
        requested_relation: false,
        candidate: None,
        installed_instance: Some(9),
        installed_header_sha256: None,
        installed_vendor: Some("Fedora".into()),
        dependency_edges: vec![],
        required_by_remaining: vec![],
        unresolved_dependencies: vec![],
        provenance: None,
        introduced_by_requested: false,
        solver_rule: "requested removal with no remaining reverse dependency".into(),
    };
    let remove_plan = PlanBuilder {
        intent: &remove_intent,
        snapshots: &snapshots,
        inventory: &state,
        policy: &policy,
        candidates: &[],
        expires_at_unix: 100,
    }
    .build(&[remove])
    .unwrap();
    assert_eq!(
        String::from_utf8(remove_plan.canonical_json().unwrap()).unwrap(),
        include_str!("golden/remove.json").trim_end()
    );
    let target = candidate("app", "2", "fedora", 99, 1000);
    let candidates = [target.clone()];
    let upgrade_intent = TransactionIntent::from_package_names(Action::Upgrade, &["app"]).unwrap();
    let upgrade = ResolvedAction {
        operation: ResolvedOperation::Upgrade,
        name: "app".into(),
        requested: true,
        requested_spec: Some(PackageSpec::parse("app").unwrap()),
        requested_relation: false,
        candidate: Some(target),
        installed_instance: Some(9),
        installed_header_sha256: None,
        installed_vendor: Some("Fedora".into()),
        dependency_edges: vec![],
        required_by_remaining: vec![],
        unresolved_dependencies: vec![],
        provenance: None,
        introduced_by_requested: false,
        solver_rule: "strictly newer candidate".into(),
    };
    let upgrade_plan = PlanBuilder {
        intent: &upgrade_intent,
        snapshots: &snapshots,
        inventory: &state,
        policy: &policy,
        candidates: &candidates,
        expires_at_unix: 100,
    }
    .build(&[upgrade])
    .unwrap();
    assert_eq!(
        String::from_utf8(upgrade_plan.canonical_json().unwrap()).unwrap(),
        include_str!("golden/upgrade.json").trim_end()
    );
}

#[test]
fn intent_coverage_duplicates_conflicts_and_unresolved_fail_before_plan() {
    let intent = TransactionIntent::from_package_names(Action::Install, &["app"]).unwrap();
    let package = candidate("app", "1", "fedora", 99, 1000);
    let candidates = [package.clone()];
    let state = inventory(vec![]);
    let snapshots = snapshots();
    let policy = policy();
    let builder = PlanBuilder {
        intent: &intent,
        snapshots: &snapshots,
        inventory: &state,
        policy: &policy,
        candidates: &candidates,
        expires_at_unix: 100,
    };
    assert!(builder.build(&[]).is_err());
    let good = install("app", package.clone(), None);
    assert!(builder.build(&[good.clone(), good.clone()]).is_err());
    let mut unrelated = good.clone();
    unrelated.name = "other".into();
    unrelated.candidate.as_mut().unwrap().name = "other".into();
    assert!(builder.build(&[unrelated]).is_err());
    let mut unresolved = good.clone();
    unresolved
        .unresolved_dependencies
        .push("missing(cap)".into());
    assert!(builder.build(&[unresolved]).is_err());
    let mut conflict = good;
    conflict.operation = ResolvedOperation::Remove;
    assert!(builder.build(&[conflict]).is_err());
}

#[test]
fn install_intent_may_resolve_to_strict_upgrade_of_requested_package() {
    let installed = InstalledPackage::new(
        "app",
        Evra::new(0, "1", "1", Architecture::Noarch),
        "Fedora",
        4,
        1,
        digest('b'),
    )
    .unwrap();
    let state = inventory(vec![installed]);
    let snapshots = snapshots();
    let policy = policy();
    let intent = TransactionIntent::from_package_names(Action::Install, &["app"]).unwrap();
    let target = candidate("app", "2", "fedora", 99, 1000);
    let candidates = [target.clone()];
    let builder = PlanBuilder {
        intent: &intent,
        snapshots: &snapshots,
        inventory: &state,
        policy: &policy,
        candidates: &candidates,
        expires_at_unix: 100,
    };
    let action = ResolvedAction {
        operation: ResolvedOperation::Upgrade,
        name: "app".into(),
        requested: true,
        requested_spec: Some(PackageSpec::parse("app").unwrap()),
        requested_relation: false,
        candidate: Some(target),
        installed_instance: Some(4),
        installed_header_sha256: None,
        installed_vendor: Some("Fedora".into()),
        dependency_edges: vec![],
        required_by_remaining: vec![],
        unresolved_dependencies: vec![],
        provenance: None,
        introduced_by_requested: false,
        solver_rule: "install or update".into(),
    };
    assert!(builder.build(&[action]).is_ok());
}

#[test]
fn ambiguous_duplicate_overflow_and_arch_switch_candidates_fail_closed() {
    let intent = TransactionIntent::from_package_names(Action::Install, &["app"]).unwrap();
    let package = candidate("app", "1", "fedora", 99, 1000);
    let state = inventory(vec![]);
    let snapshots = snapshots();
    let policy = policy();
    let duplicates = [package.clone(), package.clone()];
    let builder = PlanBuilder {
        intent: &intent,
        snapshots: &snapshots,
        inventory: &state,
        policy: &policy,
        candidates: &duplicates,
        expires_at_unix: 100,
    };
    assert!(
        builder
            .build(&[install("app", package.clone(), None)])
            .is_err()
    );
    let mut ambiguous = package.clone();
    ambiguous.checksum_sha256 = digest('f');
    let ambiguous_set = [package.clone(), ambiguous];
    let builder = PlanBuilder {
        candidates: &ambiguous_set,
        ..builder
    };
    assert!(
        builder
            .build(&[install("app", package.clone(), None)])
            .is_err()
    );
    let mut huge = package.clone();
    huge.package_size = u64::MAX;
    let huge_set = [huge.clone()];
    let builder = PlanBuilder {
        candidates: &huge_set,
        ..builder
    };
    assert!(builder.build(&[install("app", huge, None)]).is_err());
    let installed = InstalledPackage::new(
        "app",
        Evra::new(0, "1", "1", Architecture::Noarch),
        "Fedora",
        7,
        8,
        digest('b'),
    )
    .unwrap();
    let upgrade_state = inventory(vec![installed]);
    let mut switched = candidate("app", "2", "fedora", 99, 1000);
    switched.evra = Evra::new(0, "2", "1", Architecture::Aarch64);
    let switched_set = [switched.clone()];
    let upgrade_intent = TransactionIntent::from_package_names(Action::Upgrade, &["app"]).unwrap();
    let builder = PlanBuilder {
        intent: &upgrade_intent,
        inventory: &upgrade_state,
        candidates: &switched_set,
        snapshots: &snapshots,
        policy: &policy,
        expires_at_unix: 100,
    };
    let action = ResolvedAction {
        operation: ResolvedOperation::Upgrade,
        name: "app".into(),
        requested: true,
        requested_spec: Some(PackageSpec::parse("app").unwrap()),
        requested_relation: false,
        candidate: Some(switched),
        installed_instance: Some(7),
        installed_header_sha256: None,
        installed_vendor: Some("Fedora".into()),
        dependency_edges: vec![],
        required_by_remaining: vec![],
        unresolved_dependencies: vec![],
        provenance: None,
        introduced_by_requested: false,
        solver_rule: "upgrade".into(),
    };
    assert!(builder.build(&[action]).is_err());
}

#[test]
fn repeated_permutations_keep_dependency_first_canonical_bytes() {
    let intent = TransactionIntent::from_package_names(Action::Install, &["app"]).unwrap();
    let app = candidate("app", "1", "fedora", 99, 1000);
    let dep = candidate("dep", "1", "fedora", 99, 1000);
    let candidates = [app.clone(), dep.clone()];
    let state = inventory(vec![]);
    let snapshots = snapshots();
    let policy = policy();
    let builder = PlanBuilder {
        intent: &intent,
        snapshots: &snapshots,
        inventory: &state,
        policy: &policy,
        candidates: &candidates,
        expires_at_unix: 100,
    };
    let actions = [install("app", app, None), install("dep", dep, Some("app"))];
    let expected = builder.build(&actions).unwrap().canonical_json().unwrap();
    assert_eq!(builder.build(&actions).unwrap().actions()[0].name(), "dep");
    for index in 0..100 {
        let input = if index % 2 == 0 {
            actions.clone()
        } else {
            [actions[1].clone(), actions[0].clone()]
        };
        assert_eq!(
            builder.build(&input).unwrap().canonical_json().unwrap(),
            expected
        );
    }
}

#[test]
fn installonly_running_kernel_and_remove_execution_order_fail_or_order_exactly() {
    let kernel = InstalledPackage::new(
        "kernel",
        Evra::new(0, "1", "1", Architecture::Aarch64),
        "Fedora",
        1,
        1,
        digest('a'),
    )
    .unwrap();
    let app = InstalledPackage::new(
        "app",
        Evra::new(0, "1", "1", Architecture::Noarch),
        "Fedora",
        2,
        1,
        digest('b'),
    )
    .unwrap();
    let dep = InstalledPackage::new(
        "dep",
        Evra::new(0, "1", "1", Architecture::Noarch),
        "Fedora",
        3,
        1,
        digest('c'),
    )
    .unwrap();
    let state = inventory(vec![kernel, app, dep]);
    let snapshots = snapshots();
    let policy = policy().with_running_kernel_name("kernel");
    let kernel_intent = TransactionIntent::from_package_names(Action::Remove, &["kernel"]).unwrap();
    let remove = |name: &str, instance, parent: Option<&str>, introduced| ResolvedAction {
        operation: ResolvedOperation::Remove,
        requested: parent.is_none(),
        requested_spec: parent.is_none().then(|| PackageSpec::parse(name).unwrap()),
        requested_relation: false,
        name: name.into(),
        candidate: None,
        installed_instance: Some(instance),
        installed_header_sha256: None,
        installed_vendor: Some("Fedora".into()),
        dependency_edges: parent
            .map(|value| {
                vec![DependencyEdge {
                    parent: value.into(),
                    kind: DependencyKind::Strong,
                }]
            })
            .unwrap_or_default(),
        required_by_remaining: vec![],
        unresolved_dependencies: vec![],
        provenance: None,
        introduced_by_requested: introduced,
        solver_rule: "safe erase order".into(),
    };
    let builder = PlanBuilder {
        intent: &kernel_intent,
        snapshots: &snapshots,
        inventory: &state,
        policy: &policy,
        candidates: &[],
        expires_at_unix: 100,
    };
    assert!(builder.build(&[remove("kernel", 1, None, false)]).is_err());
    let intent = TransactionIntent::from_package_names(Action::Remove, &["app"]).unwrap();
    let builder = PlanBuilder {
        intent: &intent,
        ..builder
    };
    let plan = builder
        .build(&[
            remove("dep", 3, Some("app"), true),
            remove("app", 2, None, false),
        ])
        .unwrap();
    assert_eq!(plan.actions()[0].name(), "app");
    assert_eq!(plan.actions()[1].name(), "dep");
}

#[test]
fn artifact_total_accepts_exact_cap_and_rejects_plus_one() {
    let intent = TransactionIntent::from_package_names(Action::Install, &["app"]).unwrap();
    let mut exact = candidate("app", "1", "fedora", 99, 1000);
    exact.package_size = dnfast_solver::MAX_PLAN_ARTIFACT_BYTES;
    let state = inventory(vec![]);
    let snapshots = snapshots();
    let policy = policy();
    let exact_set = [exact.clone()];
    let builder = PlanBuilder {
        intent: &intent,
        snapshots: &snapshots,
        inventory: &state,
        policy: &policy,
        candidates: &exact_set,
        expires_at_unix: 100,
    };
    assert!(builder.build(&[install("app", exact, None)]).is_ok());
    let mut over = candidate("app", "1", "fedora", 99, 1000);
    over.package_size = dnfast_solver::MAX_PLAN_ARTIFACT_BYTES + 1;
    let over_set = [over.clone()];
    let builder = PlanBuilder {
        candidates: &over_set,
        ..builder
    };
    assert!(builder.build(&[install("app", over, None)]).is_err());
}
