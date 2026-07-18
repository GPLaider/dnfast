use dnfast_core::{
    Action, Architecture, CandidateAction, CanonicalDocument, Evra, InstalledInventory,
    InstalledPackage, PackageAction, PackageReason, PlanIntegrity, RepoPreference, RepoTrustPolicy,
    RepositoryBinding, Sha256Digest, SigningSubkeyRule, SolverPolicy, TransactionIntent,
};

fn digest(byte: char) -> String {
    std::iter::repeat_n(byte, 64).collect()
}

fn integrity(digests: [&str; 4]) -> PlanIntegrity {
    let snapshot = digest('f');
    let binding = RepositoryBinding::new(
        "fedora",
        Sha256Digest::parse(digest('a'), "generation_sha256").unwrap(),
        Sha256Digest::parse(digest('b'), "origin_sha256").unwrap(),
        Sha256Digest::parse(digest('c'), "trust_sha256").unwrap(),
    )
    .unwrap();
    PlanIntegrity::new(
        [digests[0], digests[1], digests[2], digests[3], &snapshot],
        vec![binding],
    )
    .unwrap()
}

#[test]
fn canonical_boundary_rejects_noncanonical_and_bounded_inputs() {
    let intent = TransactionIntent::from_package_names(Action::Install, &["bash"]).unwrap();
    let canonical = intent.to_canonical_json().unwrap();
    let spaced = [b" ".as_slice(), canonical.as_slice()].concat();
    let deep = format!("{}0{}", "[".repeat(33), "]".repeat(33));
    let long_string = format!(
        r#"{{"schema_version":1,"action":"install","packages":["{}"]}}"#,
        "a".repeat(1_048_577)
    );
    let oversized = vec![b' '; 16 * 1024 * 1024 + 1];
    let noninteger = br#"{"action":"install","packages":["bash"],"schema_version":1.0}"#;
    assert!(TransactionIntent::from_canonical_json(&spaced).is_err());
    assert!(TransactionIntent::from_canonical_json(deep.as_bytes()).is_err());
    assert!(TransactionIntent::from_canonical_json(long_string.as_bytes()).is_err());
    assert!(TransactionIntent::from_canonical_json(&oversized).is_err());
    assert!(TransactionIntent::from_canonical_json(noninteger).is_err());
}

#[test]
fn canonical_boundary_rejects_duplicate_keys_and_unsorted_arrays() {
    let duplicate =
        br#"{"action":"install","packages":["bash"],"schema_version":1,"schema_version":1}"#;
    let unsorted = br#"{"action":"install","packages":["zlib","bash"],"schema_version":1}"#;
    assert!(TransactionIntent::from_canonical_json(duplicate).is_err());
    assert!(TransactionIntent::from_canonical_json(unsorted).is_err());
}

#[test]
fn repo_preference_orders_priority_then_cost_then_id() {
    let mut repos = [
        RepoPreference::new("z", 10, 10).unwrap(),
        RepoPreference::new("a", 10, 10).unwrap(),
        RepoPreference::new("cheap", 10, 1).unwrap(),
        RepoPreference::new("priority", 1, 99).unwrap(),
    ];
    repos.sort();
    assert_eq!(
        repos
            .iter()
            .map(RepoPreference::repo_id)
            .collect::<Vec<_>>(),
        vec!["priority", "cheap", "a", "z"]
    );
}

#[test]
fn candidate_upgrade_rejects_evr_vendor_and_arch_switches() {
    let policy = SolverPolicy::fedora44_aarch64(vec!["dnfast".into()], vec!["kernel".into()]);
    let installed = Evra::new(1, "2.0", "1", Architecture::Aarch64);
    let newer = Evra::new(1, "2.1", "1", Architecture::Aarch64);
    let older = Evra::new(1, "1.9", "1", Architecture::Aarch64);
    assert!(
        policy
            .validate_upgrade(&CandidateAction::upgrade(
                installed.clone(),
                newer,
                "fedora",
                "fedora"
            ))
            .is_ok()
    );
    assert!(
        policy
            .validate_upgrade(&CandidateAction::upgrade(
                installed.clone(),
                older,
                "fedora",
                "fedora"
            ))
            .is_err()
    );
    assert!(
        policy
            .validate_upgrade(&CandidateAction::upgrade(
                installed.clone(),
                installed.clone(),
                "fedora",
                "other"
            ))
            .is_err()
    );
    assert!(
        policy
            .validate_upgrade(&CandidateAction::upgrade(
                installed,
                Evra::new(1, "2.1", "1", Architecture::Noarch),
                "fedora",
                "fedora"
            ))
            .is_err()
    );
}

#[test]
fn x86_64_policy_and_evra_are_canonical_and_do_not_fall_back_to_aarch64() {
    // Given
    let policy = SolverPolicy::fedora44_x86_64(vec!["dnfast".into()], vec!["kernel".into()]);
    let installed = Evra::new(0, "1", "1", Architecture::X86_64);
    let candidate = Evra::new(0, "2", "1", Architecture::X86_64);

    // When
    let encoded = policy.to_canonical_json().unwrap();

    // Then
    assert!(String::from_utf8(encoded).unwrap().contains("x86_64"));
    assert!(
        policy
            .validate_upgrade(&CandidateAction::upgrade(
                installed, candidate, "fedora", "fedora"
            ))
            .is_ok()
    );
}

#[test]
fn x86_64_install_remove_and_upgrade_plans_are_executable() {
    let policy = SolverPolicy::fedora44_x86_64(vec![], vec![]);
    let installed = Evra::new(0, "1", "1", Architecture::X86_64);
    let target = Evra::new(0, "2", "1", Architecture::X86_64);
    let policy_digest = digest('a');
    let trust_digest = digest('b');
    let inventory_digest = digest('c');
    let metadata_digest = digest('d');
    let bindings = [
        policy_digest.as_str(),
        trust_digest.as_str(),
        inventory_digest.as_str(),
        metadata_digest.as_str(),
    ];
    let install = dnfast_core::CanonicalPlan::new(
        TransactionIntent::from_package_names(Action::Install, &["bash"]).unwrap(),
        integrity(bindings),
        10,
        vec![PackageAction::install_with_vendor(
            "bash",
            target.clone(),
            "fedora",
            "Fedora",
            PackageReason::User,
        )],
    )
    .unwrap();
    let remove = dnfast_core::CanonicalPlan::new(
        TransactionIntent::from_package_names(Action::Remove, &["bash"]).unwrap(),
        integrity(bindings),
        10,
        vec![
            PackageAction::remove_with_identity(
                "bash",
                installed.clone(),
                "Fedora",
                PackageReason::User,
                1,
                digest('e'),
            )
            .unwrap(),
        ],
    )
    .unwrap();
    let upgrade = dnfast_core::CanonicalPlan::new(
        TransactionIntent::from_package_names(Action::Upgrade, &[]).unwrap(),
        integrity(bindings),
        10,
        vec![
            PackageAction::upgrade_with_identity(
                "bash",
                installed,
                target,
                "fedora",
                "Fedora",
                "Fedora",
                PackageReason::User,
                1,
                digest('e'),
            )
            .unwrap(),
        ],
    )
    .unwrap();
    for plan in [install, remove, upgrade] {
        assert!(plan.validate_executable(&policy, 0).is_ok());
        assert!(
            String::from_utf8(plan.to_canonical_json().unwrap())
                .unwrap()
                .contains("x86_64")
        );
    }
}

#[test]
fn upgrade_accepts_dependency_install_but_rejects_unrelated_user_install() {
    let policy = SolverPolicy::fedora44_x86_64(vec![], vec![]);
    let intent = TransactionIntent::from_package_names(Action::Upgrade, &[]).unwrap();
    let policy_digest = digest('a');
    let trust_digest = digest('b');
    let inventory_digest = digest('c');
    let metadata_digest = digest('d');
    let bindings = [
        policy_digest.as_str(),
        trust_digest.as_str(),
        inventory_digest.as_str(),
        metadata_digest.as_str(),
    ];
    let dependency = PackageAction::install_with_vendor(
        "replacement-library",
        Evra::new(0, "2", "1", Architecture::X86_64),
        "fedora",
        "Fedora",
        PackageReason::Dependency,
    );
    let unrelated = PackageAction::install_with_vendor(
        "unrelated",
        Evra::new(0, "1", "1", Architecture::X86_64),
        "fedora",
        "Fedora",
        PackageReason::User,
    );
    let dependency_plan =
        dnfast_core::CanonicalPlan::new(intent.clone(), integrity(bindings), 10, vec![dependency])
            .unwrap();
    let unrelated_plan =
        dnfast_core::CanonicalPlan::new(intent, integrity(bindings), 10, vec![unrelated]).unwrap();
    assert!(dependency_plan.validate_executable(&policy, 0).is_ok());
    assert!(unrelated_plan.validate_executable(&policy, 0).is_err());
}

#[test]
fn canonical_bytes_are_identical_one_hundred_times_and_safety_fields_change_digest() {
    let first = RepoTrustPolicy::new(
        "fedora",
        digest('a'),
        vec!["A".repeat(40)],
        SigningSubkeyRule::AuthorizedSubkeys,
        10,
    )
    .unwrap();
    let expected = first.to_canonical_json().unwrap();
    for _ in 0..100 {
        assert_eq!(first.to_canonical_json().unwrap(), expected);
    }
    let variants = [
        RepoTrustPolicy::new(
            "updates",
            digest('a'),
            vec!["A".repeat(40)],
            SigningSubkeyRule::AuthorizedSubkeys,
            10,
        )
        .unwrap(),
        RepoTrustPolicy::new(
            "fedora",
            digest('b'),
            vec!["A".repeat(40)],
            SigningSubkeyRule::AuthorizedSubkeys,
            10,
        )
        .unwrap(),
        RepoTrustPolicy::new(
            "fedora",
            digest('a'),
            vec!["B".repeat(40)],
            SigningSubkeyRule::AuthorizedSubkeys,
            10,
        )
        .unwrap(),
        RepoTrustPolicy::new(
            "fedora",
            digest('a'),
            vec!["A".repeat(40)],
            SigningSubkeyRule::PrimaryOnly,
            10,
        )
        .unwrap(),
        RepoTrustPolicy::new(
            "fedora",
            digest('a'),
            vec!["A".repeat(40)],
            SigningSubkeyRule::AuthorizedSubkeys,
            11,
        )
        .unwrap(),
    ];
    for variant in variants {
        assert_ne!(
            first.canonical_sha256().unwrap(),
            variant.canonical_sha256().unwrap()
        );
    }
}

#[test]
fn canonical_policy_rejects_unsafe_flags_and_plan_rejects_expiry_and_action_limit() {
    let policy = SolverPolicy::fedora44_aarch64(vec![], vec![]);
    let mut tree = serde_json::to_value(&policy).unwrap();
    tree["allow_vendor_change"] = serde_json::Value::Bool(true);
    let unsafe_bytes = serde_json::to_vec(&tree).unwrap();
    let actions = (0..=100_000)
        .map(|index| {
            PackageAction::install(
                format!("pkg{index:06}"),
                Evra::new(0, "1", "1", Architecture::Aarch64),
                "fedora",
                PackageReason::Dependency,
            )
        })
        .collect();
    let intent = TransactionIntent::from_package_names(Action::Upgrade, &[]).unwrap();
    assert!(SolverPolicy::from_canonical_json(&unsafe_bytes).is_err());
    assert!(
        dnfast_core::CanonicalPlan::new(
            intent.clone(),
            integrity([&digest('a'), &digest('b'), &digest('c'), &digest('d')]),
            1,
            actions
        )
        .is_err()
    );
    let plan = dnfast_core::CanonicalPlan::new(
        intent,
        integrity([&digest('a'), &digest('b'), &digest('c'), &digest('d')]),
        1,
        vec![],
    )
    .unwrap();
    assert!(plan.validate_now(2).is_err());
}

#[test]
fn proposal_without_snapshot_and_repository_pins_is_rejected_at_the_public_json_boundary() {
    // Given: a currently valid v1 proposal with only aggregate integrity digests.
    let v1 = br#"{"actions":[],"expires_at_unix":10,"install_root":"/","intent":{"action":"install","packages":["bash"],"schema_version":1},"inventory_sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","metadata_sha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","policy_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","schema_version":1,"trust_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}"#;

    // When: an untrusted caller submits the canonical v1 bytes to the proposal boundary.
    let result = dnfast_core::CanonicalPlan::from_canonical_json_at(v1, 1);

    // Then: missing planning snapshot and selected repository bindings must fail before execution.
    assert!(result.is_err());
}

#[test]
fn rpm_evr_comparison_matches_epoch_tilde_caret_numeric_alpha_and_release_rules() {
    let cases = [
        (
            Evra::new(1, "1", "1", Architecture::Aarch64),
            Evra::new(0, "99", "9", Architecture::Aarch64),
        ),
        (
            Evra::new(0, "1.0", "1", Architecture::Aarch64),
            Evra::new(0, "1.0~rc1", "1", Architecture::Aarch64),
        ),
        (
            Evra::new(0, "1.0^git1", "1", Architecture::Aarch64),
            Evra::new(0, "1.0", "1", Architecture::Aarch64),
        ),
        (
            Evra::new(0, "1.0.10", "1", Architecture::Aarch64),
            Evra::new(0, "1.0.2", "1", Architecture::Aarch64),
        ),
        (
            Evra::new(0, "1.0", "2.fc44", Architecture::Aarch64),
            Evra::new(0, "1.0", "1.fc44", Architecture::Aarch64),
        ),
        (
            Evra::new(0, "1.0a", "1", Architecture::Aarch64),
            Evra::new(0, "1.0", "1", Architecture::Aarch64),
        ),
    ];
    for (newer, older) in cases {
        assert!(newer.is_strictly_newer_than(&older));
        assert!(!older.is_strictly_newer_than(&newer));
    }
}

#[test]
fn raw_policy_rejects_nonfrozen_flags_empty_names_and_running_kernel_removal() {
    let policy = SolverPolicy::fedora44_aarch64(vec!["dnfast".into()], vec!["kernel".into()])
        .with_running_kernel_name("kernel-core");
    let bytes = policy.to_canonical_json().unwrap();
    for (field, value) in [("install_weak_deps", false), ("best", true)] {
        let mut tree = serde_json::from_slice::<serde_json::Value>(&bytes).unwrap();
        tree[field] = serde_json::Value::Bool(value);
        assert!(SolverPolicy::from_canonical_json(&serde_json::to_vec(&tree).unwrap()).is_err());
    }
    let mut tree = serde_json::from_slice::<serde_json::Value>(&bytes).unwrap();
    tree["protected_packages"] = serde_json::json!([""]);
    assert!(SolverPolicy::from_canonical_json(&serde_json::to_vec(&tree).unwrap()).is_err());
    assert!(
        policy
            .validate_removal("kernel-core", PackageReason::User)
            .is_err()
    );
}

#[test]
fn executable_upgrade_enforces_intent_evr_vendor_and_arch_in_the_plan() {
    let policy = SolverPolicy::fedora44_aarch64(vec![], vec![]);
    let intent = TransactionIntent::from_package_names(Action::Upgrade, &[]).unwrap();
    let installed = Evra::new(0, "1", "1", Architecture::Aarch64);
    let good = PackageAction::upgrade_with_identity(
        "bash",
        installed.clone(),
        Evra::new(0, "2", "1", Architecture::Aarch64),
        "fedora",
        "fedora",
        "fedora",
        PackageReason::User,
        1,
        digest('e'),
    )
    .unwrap();
    let bad = PackageAction::upgrade_with_identity(
        "bash",
        installed.clone(),
        Evra::new(0, "0", "1", Architecture::Aarch64),
        "fedora",
        "fedora",
        "other",
        PackageReason::User,
        1,
        digest('e'),
    )
    .unwrap();
    let good_plan = dnfast_core::CanonicalPlan::new(
        intent.clone(),
        integrity([&digest('a'), &digest('b'), &digest('c'), &digest('d')]),
        10,
        vec![good],
    )
    .unwrap();
    let bad_plan = dnfast_core::CanonicalPlan::new(
        intent,
        integrity([&digest('a'), &digest('b'), &digest('c'), &digest('d')]),
        10,
        vec![bad],
    )
    .unwrap();
    assert!(good_plan.validate_executable(&policy, 1).is_ok());
    assert!(bad_plan.validate_executable(&policy, 1).is_err());
}

#[test]
fn every_plan_binding_changes_digest_and_root_tampering_is_rejected() {
    let intent = TransactionIntent::from_package_names(Action::Install, &["bash"]).unwrap();
    let action = PackageAction::install_with_vendor(
        "bash",
        Evra::new(0, "1", "1", Architecture::Aarch64),
        "fedora",
        "Fedora",
        PackageReason::User,
    );
    let base = dnfast_core::CanonicalPlan::new(
        intent.clone(),
        integrity([&digest('a'), &digest('b'), &digest('c'), &digest('d')]),
        10,
        vec![action.clone()],
    )
    .unwrap();
    let variants = [
        dnfast_core::CanonicalPlan::new(
            intent.clone(),
            integrity([&digest('e'), &digest('b'), &digest('c'), &digest('d')]),
            10,
            vec![action.clone()],
        )
        .unwrap(),
        dnfast_core::CanonicalPlan::new(
            intent.clone(),
            integrity([&digest('a'), &digest('e'), &digest('c'), &digest('d')]),
            10,
            vec![action.clone()],
        )
        .unwrap(),
        dnfast_core::CanonicalPlan::new(
            intent.clone(),
            integrity([&digest('a'), &digest('b'), &digest('e'), &digest('d')]),
            10,
            vec![action.clone()],
        )
        .unwrap(),
        dnfast_core::CanonicalPlan::new(
            intent.clone(),
            integrity([&digest('a'), &digest('b'), &digest('c'), &digest('e')]),
            10,
            vec![action.clone()],
        )
        .unwrap(),
        dnfast_core::CanonicalPlan::new(
            intent.clone(),
            integrity([&digest('a'), &digest('b'), &digest('c'), &digest('d')]),
            11,
            vec![action.clone()],
        )
        .unwrap(),
        dnfast_core::CanonicalPlan::new(
            intent,
            integrity([&digest('a'), &digest('b'), &digest('c'), &digest('d')]),
            10,
            vec![PackageAction::install_with_vendor(
                "bash",
                Evra::new(0, "2", "1", Architecture::Aarch64),
                "fedora",
                "Fedora",
                PackageReason::User,
            )],
        )
        .unwrap(),
    ];
    for variant in variants {
        assert_ne!(
            base.canonical_sha256().unwrap(),
            variant.canonical_sha256().unwrap()
        );
    }
    let tampered = String::from_utf8(base.to_canonical_json().unwrap())
        .unwrap()
        .replace("\"install_root\":\"/\"", "\"install_root\":\"/tmp\"");
    assert!(dnfast_core::CanonicalPlan::from_canonical_json_at(tampered.as_bytes(), 1).is_err());
}

#[test]
fn planning_snapshot_and_each_repository_coordinate_change_the_proposal_digest() {
    // Given: a removal proposal whose digest is independent of package candidate selection.
    let binding = |id: &str, coordinates: [char; 3]| {
        RepositoryBinding::new(
            id,
            Sha256Digest::parse(digest(coordinates[0]), "generation_sha256").unwrap(),
            Sha256Digest::parse(digest(coordinates[1]), "origin_sha256").unwrap(),
            Sha256Digest::parse(digest(coordinates[2]), "trust_sha256").unwrap(),
        )
        .unwrap()
    };
    let integrity = |snapshot: char, repositories| {
        PlanIntegrity::new(
            [
                &digest('a'),
                &digest('b'),
                &digest('c'),
                &digest('d'),
                &digest(snapshot),
            ],
            repositories,
        )
        .unwrap()
    };
    let intent = TransactionIntent::from_package_names(Action::Remove, &["bash"]).unwrap();
    let action = PackageAction::remove_with_identity(
        "bash",
        Evra::new(0, "1", "1", Architecture::Aarch64),
        "Fedora",
        PackageReason::User,
        1,
        digest('f'),
    )
    .unwrap();
    let base = dnfast_core::CanonicalPlan::new(
        intent.clone(),
        integrity('1', vec![binding("fedora", ['2', '3', '4'])]),
        10,
        vec![action.clone()],
    )
    .unwrap();

    // When: snapshot, generation, origin, trust, or canonical selected repository set changes.
    let variants = [
        dnfast_core::CanonicalPlan::new(
            intent.clone(),
            integrity('9', vec![binding("fedora", ['2', '3', '4'])]),
            10,
            vec![action.clone()],
        )
        .unwrap(),
        dnfast_core::CanonicalPlan::new(
            intent.clone(),
            integrity('1', vec![binding("fedora", ['9', '3', '4'])]),
            10,
            vec![action.clone()],
        )
        .unwrap(),
        dnfast_core::CanonicalPlan::new(
            intent.clone(),
            integrity('1', vec![binding("fedora", ['2', '9', '4'])]),
            10,
            vec![action.clone()],
        )
        .unwrap(),
        dnfast_core::CanonicalPlan::new(
            intent.clone(),
            integrity('1', vec![binding("fedora", ['2', '3', '9'])]),
            10,
            vec![action.clone()],
        )
        .unwrap(),
        dnfast_core::CanonicalPlan::new(
            intent,
            integrity('1', vec![binding("updates", ['2', '3', '4'])]),
            10,
            vec![action],
        )
        .unwrap(),
    ];

    // Then: no stale snapshot or repository coordinate can retain the original digest.
    for variant in variants {
        assert_ne!(
            base.canonical_sha256().unwrap(),
            variant.canonical_sha256().unwrap()
        );
    }
}

#[test]
fn proposal_rejects_missing_unknown_duplicate_or_reordered_repository_bindings() {
    // Given: a v2 proposal with two strictly ordered root-published repository bindings.
    let binding = |id: &str, generation: char, origin: char, trust: char| {
        RepositoryBinding::new(
            id,
            Sha256Digest::parse(digest(generation), "generation_sha256").unwrap(),
            Sha256Digest::parse(digest(origin), "origin_sha256").unwrap(),
            Sha256Digest::parse(digest(trust), "trust_sha256").unwrap(),
        )
        .unwrap()
    };
    let integrity = PlanIntegrity::new(
        [
            &digest('a'),
            &digest('b'),
            &digest('c'),
            &digest('d'),
            &digest('e'),
        ],
        vec![
            binding("fedora", '1', '2', '3'),
            binding("updates", '4', '5', '6'),
        ],
    )
    .unwrap();
    let intent = TransactionIntent::from_package_names(Action::Remove, &["bash"]).unwrap();
    let action = PackageAction::remove_with_identity(
        "bash",
        Evra::new(0, "1", "1", Architecture::Aarch64),
        "Fedora",
        PackageReason::User,
        1,
        digest('f'),
    )
    .unwrap();
    let proposal = dnfast_core::CanonicalPlan::new(intent, integrity, 10, vec![action]).unwrap();
    let canonical = proposal.to_canonical_json().unwrap();

    // When: an untrusted proposal omits, extends, duplicates, or reorders its binding set.
    let mut missing = serde_json::from_slice::<serde_json::Value>(&canonical).unwrap();
    missing
        .as_object_mut()
        .unwrap()
        .remove("planning_snapshot_sha256");
    let mut unknown = serde_json::from_slice::<serde_json::Value>(&canonical).unwrap();
    unknown["surprise"] = serde_json::Value::Bool(true);
    let mut duplicate = serde_json::from_slice::<serde_json::Value>(&canonical).unwrap();
    let duplicated = duplicate["selected_repositories"][0].clone();
    duplicate["selected_repositories"]
        .as_array_mut()
        .unwrap()
        .push(duplicated);
    let mut reordered = serde_json::from_slice::<serde_json::Value>(&canonical).unwrap();
    reordered["selected_repositories"]
        .as_array_mut()
        .unwrap()
        .reverse();

    // Then: all ambiguous or unpinned forms are rejected at the public canonical boundary.
    for malformed in [missing, unknown, duplicate, reordered] {
        assert!(
            dnfast_core::CanonicalPlan::from_canonical_json(
                &serde_json::to_vec(&malformed).unwrap()
            )
            .is_err()
        );
    }
}

#[test]
fn inventory_rpmdb_binding_changes_digest_and_invalid_identity_is_rejected() {
    let package = InstalledPackage::new(
        "bash",
        Evra::new(0, "1", "1", Architecture::Aarch64),
        "Fedora",
        1,
        1,
        digest('a'),
    )
    .unwrap();
    let sqlite = InstalledInventory::new("rpm.sqlite", "6.0.1", vec![package.clone()]).unwrap();
    let ndb = InstalledInventory::new("ndb", "6.0.1", vec![package.clone()]).unwrap();
    assert_ne!(
        sqlite.canonical_sha256().unwrap(),
        ndb.canonical_sha256().unwrap()
    );
    assert!(
        InstalledInventory::new("rpm.sqlite", "6.0.1", vec![package.clone(), package]).is_err()
    );
    assert!(InstalledInventory::new("", "6.0.1", vec![]).is_err());
}
