use dnfast_core::{
    Action, Architecture, CandidateAction, CanonicalDocument, Evra, InstalledInventory,
    InstalledPackage, PackageAction, PackageReason, RepoTrustPolicy, SolverPolicy,
    TransactionIntent, canonical_actions,
};

#[test]
fn erase_lookup_requires_exact_instance_and_header_digest() {
    let package = InstalledPackage::new(
        "demo",
        Evra::new(0, "1", "1", Architecture::Noarch),
        "Fedora",
        7,
        9,
        "a".repeat(64),
    )
    .unwrap();
    let inventory = InstalledInventory::new("sqlite", "6.0.1", vec![package]).unwrap();
    assert_eq!(
        inventory.erase_target(7, &"a".repeat(64)).unwrap().name(),
        "demo"
    );
    assert!(matches!(
        inventory.erase_target(8, &"a".repeat(64)),
        Err(dnfast_core::EraseLookupError::NotFound)
    ));
    assert!(matches!(
        inventory.erase_target(7, &"b".repeat(64)),
        Err(dnfast_core::EraseLookupError::HeaderMismatch)
    ));
    let duplicate = InstalledPackage::new(
        "other",
        Evra::new(0, "1", "1", Architecture::Noarch),
        "Fedora",
        7,
        10,
        "b".repeat(64),
    )
    .unwrap();
    assert!(
        InstalledInventory::new(
            "sqlite",
            "6.0.1",
            vec![inventory.packages()[0].clone(), duplicate]
        )
        .is_err()
    );
}

#[test]
fn installed_vendor_absence_is_bound_without_unknown_substitution() {
    let package = InstalledPackage::new(
        "gpg-pubkey",
        Evra::new(0, "1", "1", Architecture::Noarch),
        "",
        7,
        9,
        "a".repeat(64),
    )
    .unwrap();
    let inventory = InstalledInventory::new("sqlite", "6.0.1", vec![package]).unwrap();
    assert_eq!(inventory.packages()[0].vendor(), "");
    assert_eq!(
        InstalledInventory::from_canonical_json(&inventory.to_canonical_json().unwrap()).unwrap(),
        inventory
    );
    let action = PackageAction::remove_with_identity(
        "gpg-pubkey",
        Evra::new(0, "1", "1", Architecture::Noarch),
        "",
        PackageReason::User,
        7,
        "a".repeat(64),
    )
    .unwrap();
    assert!(canonical_actions(vec![action]).is_ok());
}

fn digest(byte: char) -> String {
    std::iter::repeat_n(byte, 64).collect()
}

#[test]
fn trust_policy_rejects_unknown_schema_and_unknown_fields() {
    let unknown_version = format!(
        r#"{{"schema_version":2,"repo_id":"fedora","key_bundle_sha256":"{}","allowed_primary_fingerprints":["{}"],"signing_subkey_rule":"authorized_subkeys","valid_at_unix":1,"require_package_signature":true}}"#,
        digest('a'),
        digest('B')
    );
    let unknown_field = unknown_version.replace(
        "\"schema_version\":2",
        "\"schema_version\":1,\"surprise\":true",
    );
    assert!(RepoTrustPolicy::from_json(unknown_version.as_bytes()).is_err());
    assert!(RepoTrustPolicy::from_json(unknown_field.as_bytes()).is_err());
    let duplicate = format!(
        r#"{{"allowed_primary_fingerprints":["{0}","{0}"],"key_bundle_sha256":"{1}","repo_id":"fedora","require_package_signature":true,"schema_version":1,"signing_subkey_rule":"authorized_subkeys","valid_at_unix":1}}"#,
        "A".repeat(40),
        digest('a')
    );
    assert!(RepoTrustPolicy::from_canonical_json(duplicate.as_bytes()).is_err());
}

#[test]
fn solver_policy_validates_explicit_replacement_direction_and_identity() {
    let policy = SolverPolicy::fedora44_aarch64(vec!["kernel".into()], vec!["dnfast".into()]);
    let old = Evra::new(0, "2", "1", Architecture::Noarch);
    let older = Evra::new(0, "1", "1", Architecture::Noarch);
    assert!(
        policy
            .validate_downgrade(&CandidateAction::downgrade(
                old.clone(),
                older,
                "Fedora",
                "Fedora",
            ))
            .is_ok()
    );
    assert!(
        policy
            .validate_reinstall(&CandidateAction::reinstall(
                old.clone(),
                old,
                "Fedora",
                "Fedora",
            ))
            .is_ok()
    );
    assert!(
        policy
            .validate_action(&CandidateAction::distro_sync())
            .is_err()
    );
    assert!(
        policy
            .validate_action(&CandidateAction::vendor_switch())
            .is_err()
    );
    assert!(
        policy
            .validate_action(&CandidateAction::arch_switch())
            .is_err()
    );
}

#[test]
fn inventory_and_actions_have_canonical_domain_order() {
    let z = InstalledPackage::new(
        "zlib",
        Evra::new(0, "1", "1", Architecture::Aarch64),
        "Fedora",
        2,
        9,
        digest('a'),
    )
    .unwrap();
    let a = InstalledPackage::new(
        "bash",
        Evra::new(0, "2", "1", Architecture::Aarch64),
        "Fedora",
        1,
        8,
        digest('b'),
    )
    .unwrap();
    let inventory = InstalledInventory::new("rpm.sqlite", "6.0.1", vec![z, a]).unwrap();
    let actions = vec![
        PackageAction::remove_with_identity(
            "zlib",
            Evra::new(0, "1", "1", Architecture::Aarch64),
            "Fedora",
            PackageReason::Dependency,
            2,
            digest('a'),
        )
        .unwrap(),
        PackageAction::install(
            "bash",
            Evra::new(0, "2", "1", Architecture::Aarch64),
            "fedora",
            PackageReason::User,
        ),
    ];
    let ordered = canonical_actions(actions).unwrap();
    assert_eq!(inventory.packages()[0].name(), "bash");
    assert_eq!(ordered[0].name(), "bash");
    assert_eq!(inventory.install_root(), "/");
}

#[test]
fn inventory_digest_memoization_is_not_serialized_or_semantic_state() {
    let package = InstalledPackage::new(
        "bash",
        Evra::new(0, "5.2", "1", Architecture::X86_64),
        "Fedora",
        1,
        8,
        digest('a'),
    )
    .unwrap();
    let inventory = InstalledInventory::new("rpm.sqlite", "6.0.1", vec![package]).unwrap();

    let first = inventory.canonical_sha256().unwrap();
    let second = inventory.canonical_sha256().unwrap();
    let bytes = inventory.to_canonical_json().unwrap();
    let reparsed = InstalledInventory::from_canonical_json(&bytes).unwrap();

    assert_eq!(first, second);
    assert_eq!(reparsed, inventory);
    assert_eq!(reparsed.canonical_sha256().unwrap(), first);
    assert!(
        !std::str::from_utf8(&bytes)
            .unwrap()
            .contains("canonical_sha256")
    );
}

#[test]
fn unknown_or_external_reason_is_never_autoremovable() {
    assert!(!PackageReason::Unknown.is_autoremove_candidate());
    assert!(!PackageReason::External.is_autoremove_candidate());
    assert!(PackageReason::Dependency.is_autoremove_candidate());
}

#[test]
fn protected_installonly_and_untrusted_reasons_cannot_be_removed() {
    let policy = SolverPolicy::fedora44_aarch64(vec!["dnfast".into()], vec!["kernel".into()]);
    assert!(
        policy
            .validate_removal("dnfast", PackageReason::User)
            .is_err()
    );
    assert!(
        policy
            .validate_removal("kernel", PackageReason::User)
            .is_err()
    );
    assert!(
        policy
            .validate_removal("bash", PackageReason::Unknown)
            .is_err()
    );
    assert!(
        policy
            .validate_removal("bash", PackageReason::External)
            .is_err()
    );
}

#[test]
fn transaction_intent_round_trips_with_schema_version() {
    let intent = TransactionIntent::from_package_names(Action::Install, &["bash"]).unwrap();
    let bytes = intent.to_json().unwrap();
    assert_eq!(TransactionIntent::from_json(&bytes).unwrap(), intent);
    assert!(
        std::str::from_utf8(&bytes)
            .unwrap()
            .contains("\"schema_version\":1")
    );
}

#[test]
fn install_remove_and_upgrade_intents_enforce_package_contracts() {
    assert!(TransactionIntent::from_package_names(Action::Install, &["bash"]).is_ok());
    assert!(TransactionIntent::from_package_names(Action::Remove, &["bash"]).is_ok());
    assert!(TransactionIntent::from_package_names(Action::Upgrade, &[]).is_ok());
    assert!(TransactionIntent::from_package_names(Action::Install, &[]).is_err());
}

#[test]
fn malformed_package_specs_and_duplicates_are_rejected() {
    assert!(TransactionIntent::from_package_names(Action::Install, &["--all"]).is_err());
    assert!(TransactionIntent::from_package_names(Action::Install, &["bad\0name"]).is_err());
    assert!(TransactionIntent::from_package_names(Action::Install, &["bash", "bash"]).is_err());
}
