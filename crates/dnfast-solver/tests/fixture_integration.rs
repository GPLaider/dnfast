use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use serde::Deserialize;
use sha2::{Digest, Sha256};

use dnfast_core::{
    Action, Architecture, CanonicalDocument, CanonicalPlan, Evra, InstalledInventory, PackageSpec,
    RepositoryBinding, Sha256Digest, SolverPolicy, TransactionIntent,
};
use dnfast_metadata::{decode_record, parse_primary_records, parse_repomd_records};
use dnfast_solver::{
    CandidatePackage, DependencyEdge, DependencyKind, IntegritySnapshots, NativeAction,
    NativeSolveOutput, PlanBuilder, ResolvedAction, ResolvedOperation,
};

fn fixture(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/rpm/generated-build10/repos/main")
        .join(path)
}
fn digest(byte: char) -> String {
    byte.to_string().repeat(64)
}
fn evidence(path: &str) -> Vec<u8> {
    std::fs::read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/evidence")
            .join(path),
    )
    .unwrap()
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

#[derive(Deserialize)]
struct InventoryReceipt {
    source_transcript_sha256: String,
    inventory: InstalledInventory,
}

#[test]
fn real_todo2a_primary_drives_app_dependency_plan_and_failures_do_not_download() {
    let repomd = std::fs::read(fixture("repodata/repomd.xml")).unwrap();
    let records = parse_repomd_records(&repomd).unwrap();
    let compressed = std::fs::read(fixture(&records.primary.href)).unwrap();
    let opened = decode_record(&compressed, &records.primary).unwrap();
    let packages = parse_primary_records(opened.as_slice()).unwrap();
    let candidates = packages
        .iter()
        .filter(|item| matches!(item.name.as_str(), "dnfast-app" | "dnfast-dep"))
        .map(|item| CandidatePackage {
            name: item.name.clone(),
            evra: Evra::new(
                item.epoch.parse().unwrap(),
                &item.version,
                &item.release,
                match item.arch.as_str() {
                    "aarch64" => Architecture::Aarch64,
                    "x86_64" => Architecture::X86_64,
                    "noarch" => Architecture::Noarch,
                    other => panic!("unsupported fixture architecture: {other}"),
                },
            ),
            vendor: if item.vendor.is_empty() {
                "unknown".into()
            } else {
                item.vendor.clone()
            },
            repo_id: "main".into(),
            priority: 99,
            cost: 1000,
            package_size: item.package_size,
            installed_size: item.installed_size,
            checksum_sha256: item.checksum.clone(),
            location: item.location.clone(),
            excluded: false,
            modular: false,
        })
        .collect::<Vec<_>>();
    assert_eq!(candidates.len(), 2);
    let app = candidates
        .iter()
        .find(|item| item.name == "dnfast-app")
        .unwrap()
        .clone();
    let dep = candidates
        .iter()
        .find(|item| item.name == "dnfast-dep")
        .unwrap()
        .clone();
    let intent = TransactionIntent::from_package_names(Action::Install, &["dnfast-app"]).unwrap();
    let snapshots = snapshots();
    let inventory = InstalledInventory::new("sqlite", "6.0.1", vec![]).unwrap();
    let policy = SolverPolicy::fedora44_aarch64(vec!["dnfast".into()], vec!["kernel".into()]);
    let builder = PlanBuilder {
        intent: &intent,
        snapshots: &snapshots,
        inventory: &inventory,
        policy: &policy,
        candidates: &candidates,
        expires_at_unix: 100,
    };
    let action = |name: &str, package, parent: Option<&str>| ResolvedAction {
        operation: ResolvedOperation::Install,
        requested: parent.is_none(),
        requested_spec: parent.is_none().then(|| PackageSpec::parse(name).unwrap()),
        requested_relation: false,
        name: name.into(),
        candidate: Some(package),
        installed_instance: None,
        installed_header_sha256: None,
        installed_vendor: None,
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
        introduced_by_requested: false,
        solver_rule: if parent.is_some() {
            "requires dnfast-dep"
        } else {
            "requested"
        }
        .into(),
    };
    let plan = builder
        .build(&[
            action("dnfast-app", app, None),
            action("dnfast-dep", dep, Some("dnfast-app")),
        ])
        .unwrap();
    assert_eq!(plan.actions()[0].name(), "dnfast-dep");
    let downloads = AtomicUsize::new(0);
    let mut protected = candidates[0].clone();
    protected.excluded = true;
    let failure_candidates = [protected.clone()];
    let failure = PlanBuilder {
        candidates: &failure_candidates,
        ..builder
    }
    .build(&[action(&protected.name.clone(), protected, None)]);
    assert!(failure.is_err());
    assert_eq!(downloads.load(Ordering::SeqCst), 0);
    let native: NativeSolveOutput =
        serde_json::from_slice(include_bytes!("fixtures/native-build10-app.json")).unwrap();
    assert_eq!(
        format!(
            "{:x}",
            Sha256::digest(evidence("task-8-native-causal-decisions.raw.log"))
        ),
        native.source_transcript_sha256
    );
    let native_metadata = packages
        .iter()
        .map(|item| ("main", item))
        .collect::<Vec<_>>();
    let direct = NativeSolveOutput::from_native(
        dnfast_native::SolveResult {
            actions: native
                .actions
                .iter()
                .map(|item| item.nevra.clone())
                .collect(),
            repositories: native
                .actions
                .iter()
                .map(|item| item.repository.clone())
                .collect(),
            kinds: native
                .actions
                .iter()
                .map(|item| item.kind.clone())
                .collect(),
            obsoletes: vec![None; native.actions.len()],
            requested_specs: native
                .actions
                .iter()
                .map(|item| {
                    item.requested_spec
                        .as_ref()
                        .map(|spec| spec.as_str().to_owned())
                })
                .collect(),
            requested_relation_kinds: native
                .actions
                .iter()
                .map(|item| item.requested_relation)
                .collect(),
            satisfied_specs: vec![],
            problems: vec![],
            decisions: vec![dnfast_native::SolveDecision {
                requiring: "dnfast-app-0:1.0-1.noarch".into(),
                provider: "dnfast-dep-0:1.0-1.noarch".into(),
                relation: "dnfast-dep >= 1.0".into(),
                weak: false,
                provider_installed: false,
            }],
        },
        native.source_transcript_sha256.clone(),
        &native_metadata,
        &inventory,
    )
    .unwrap();
    assert_eq!(direct, native);
    let native_plan = builder
        .build(
            &native
                .into_resolved(&["dnfast-app"], &candidates, &native_metadata, &inventory)
                .unwrap(),
        )
        .unwrap();
    assert_eq!(
        native_plan
            .actions()
            .iter()
            .map(|item| item.name())
            .collect::<Vec<_>>(),
        ["dnfast-dep", "dnfast-app"]
    );
}

#[test]
fn reverse_weak_supplement_decision_keeps_the_native_plan_connected() {
    let repomd = std::fs::read(fixture("repodata/repomd.xml")).unwrap();
    let records = parse_repomd_records(&repomd).unwrap();
    let compressed = std::fs::read(fixture(&records.primary.href)).unwrap();
    let opened = decode_record(&compressed, &records.primary).unwrap();
    let packages = parse_primary_records(opened.as_slice()).unwrap();
    let selected = ["dnfast-app", "dnfast-obsoletes", "dnfast-weak-app"];
    let candidates = packages
        .iter()
        .filter(|item| selected.contains(&item.name.as_str()))
        .map(|item| CandidatePackage {
            name: item.name.clone(),
            evra: Evra::new(
                item.epoch.parse().unwrap(),
                &item.version,
                &item.release,
                Architecture::Noarch,
            ),
            vendor: if item.vendor.is_empty() {
                "unknown".into()
            } else {
                item.vendor.clone()
            },
            repo_id: "main".into(),
            priority: 99,
            cost: 1000,
            package_size: item.package_size,
            installed_size: item.installed_size,
            checksum_sha256: item.checksum.clone(),
            location: item.location.clone(),
            excluded: false,
            modular: false,
        })
        .collect::<Vec<_>>();
    assert_eq!(candidates.len(), 3);
    let metadata = packages
        .iter()
        .map(|item| ("main", item))
        .collect::<Vec<_>>();
    let inventory = InstalledInventory::new("sqlite", "6.0.1", vec![]).unwrap();
    let native = NativeSolveOutput::from_native(
        dnfast_native::SolveResult {
            actions: vec![
                "dnfast-obsoletes-0:2.0-1.noarch".into(),
                "dnfast-weak-app-0:1.0-1.noarch".into(),
                "dnfast-app-0:1.0-1.noarch".into(),
            ],
            repositories: vec!["main".into(), "main".into(), "main".into()],
            kinds: vec!["install".into(), "install".into(), "install".into()],
            obsoletes: vec![None, None, None],
            requested_specs: vec![None, None, Some("dnfast-app".into())],
            requested_relation_kinds: vec![false, false, false],
            satisfied_specs: vec![],
            problems: vec![],
            decisions: vec![
                dnfast_native::SolveDecision {
                    requiring: "dnfast-weak-app-0:1.0-1.noarch".into(),
                    provider: "dnfast-obsoletes-0:2.0-1.noarch".into(),
                    relation: "dnfast-dep".into(),
                    weak: true,
                    provider_installed: false,
                },
                dnfast_native::SolveDecision {
                    requiring: "dnfast-app-0:1.0-1.noarch".into(),
                    provider: "dnfast-weak-app-0:1.0-1.noarch".into(),
                    relation: "dnfast-app".into(),
                    weak: true,
                    provider_installed: false,
                },
                dnfast_native::SolveDecision {
                    requiring: "dnfast-app-0:1.0-1.noarch".into(),
                    provider: "dnfast-obsoletes-0:2.0-1.noarch".into(),
                    relation: "dnfast-dep >= 1.0".into(),
                    weak: false,
                    provider_installed: false,
                },
            ],
        },
        digest('d'),
        &metadata,
        &inventory,
    )
    .unwrap();
    let resolved = native
        .into_resolved(&["dnfast-app"], &candidates, &metadata, &inventory)
        .unwrap();
    let supplement = resolved
        .iter()
        .find(|item| item.name == "dnfast-weak-app")
        .unwrap();
    assert_eq!(
        supplement.dependency_edges,
        [DependencyEdge {
            parent: "dnfast-app".into(),
            kind: DependencyKind::Weak
        }]
    );
    let intent = TransactionIntent::from_package_names(Action::Install, &["dnfast-app"]).unwrap();
    let snapshots = snapshots();
    let policy = SolverPolicy::fedora44_aarch64(vec![], vec![]);
    let plan = PlanBuilder {
        intent: &intent,
        snapshots: &snapshots,
        inventory: &inventory,
        policy: &policy,
        candidates: &candidates,
        expires_at_unix: 100,
    }
    .build(&resolved);
    assert!(
        plan.is_ok(),
        "reverse weak decision must make every selected action reachable: {plan:?}"
    );
}

#[test]
fn selector_provenance_covers_relation_specs_exactly_once() {
    let inventory = InstalledInventory::new("sqlite", "6.0.1", vec![]).unwrap();
    let candidate = CandidatePackage {
        name: "dnfast-upgrade".into(),
        evra: Evra::new(0, "1.0", "1", Architecture::Noarch),
        vendor: "Dnfast".into(),
        repo_id: "main".into(),
        priority: 99,
        cost: 1000,
        package_size: 1,
        installed_size: 1,
        checksum_sha256: digest('a'),
        location: "dnfast-upgrade-1.0-1.noarch.rpm".into(),
        excluded: false,
        modular: false,
    };
    let h2 = CandidatePackage {
        evra: Evra::new(0, "2.0", "1", Architecture::Noarch),
        location: "dnfast-upgrade-2.0-1.noarch.rpm".into(),
        ..candidate.clone()
    };
    let action = |nevra: &str, requested_spec: Option<&str>, requested_relation| NativeAction {
        kind: "install".into(),
        repository: "main".into(),
        nevra: nevra.into(),
        old_nevra: None,
        installed_instance: None,
        installed_header_sha256: None,
        requested_spec: requested_spec.map(PackageSpec::parse).transpose().unwrap(),
        requested_relation,
        provenance: None,
        transaction_counterpart_nevra: None,
    };
    let output = |actions| NativeSolveOutput {
        source_transcript_sha256: digest('b'),
        actions,
        decisions: vec![],
        satisfied_specs: vec![],
    };
    let relation = "dnfast-upgrade = 1.0-1";
    let resolved = output(vec![action(
        "dnfast-upgrade-0:1.0-1.noarch",
        Some(relation),
        true,
    )])
    .into_resolved(
        &[relation],
        &[candidate.clone(), h2.clone()],
        &[],
        &inventory,
    )
    .unwrap();
    assert_eq!(
        resolved[0].requested_spec.as_ref().map(PackageSpec::as_str),
        Some(relation)
    );
    assert!(resolved[0].requested_relation);
    let intent = TransactionIntent::from_package_names(Action::Install, &[relation]).unwrap();
    let plan = PlanBuilder {
        intent: &intent,
        snapshots: &snapshots(),
        inventory: &inventory,
        policy: &SolverPolicy::fedora44_aarch64(vec![], vec![]),
        candidates: &[candidate.clone(), h2.clone()],
        expires_at_unix: 100,
    }
    .build(&resolved);
    assert!(plan.is_ok());
    let snapshots = snapshots();
    let policy = SolverPolicy::fedora44_aarch64(vec![], vec![]);
    let builder = PlanBuilder {
        intent: &intent,
        snapshots: &snapshots,
        inventory: &inventory,
        policy: &policy,
        candidates: &[candidate.clone(), h2.clone()],
        expires_at_unix: 100,
    };
    let mut missing = resolved.clone();
    missing[0].requested_spec = None;
    assert!(builder.build(&missing).is_err());
    let mut unknown = resolved.clone();
    unknown[0].requested_spec = Some(PackageSpec::parse("other").unwrap());
    assert!(builder.build(&unknown).is_err());
    let mut duplicate = resolved.clone();
    let mut second_candidate = candidate.clone();
    second_candidate.name = "second".into();
    second_candidate.location = "second-1.0-1.noarch.rpm".into();
    let mut second = resolved[0].clone();
    second.name = "second".into();
    second.candidate = Some(second_candidate.clone());
    duplicate.push(second);
    let duplicate_builder = PlanBuilder {
        candidates: &[candidate.clone(), second_candidate],
        ..builder
    };
    assert!(duplicate_builder.build(&duplicate).is_err());
    assert!(
        output(vec![action("dnfast-upgrade-0:1.0-1.noarch", None, false)])
            .into_resolved(&[relation], &[], &[], &inventory)
            .is_err()
    );
    assert!(
        output(vec![action(
            "dnfast-upgrade-0:1.0-1.noarch",
            Some("other"),
            false
        )])
        .into_resolved(&[relation], &[], &[], &inventory)
        .is_err()
    );
    assert!(
        output(vec![
            action("dnfast-upgrade-0:1.0-1.noarch", Some(relation), true),
            action("other-0:1.0-1.noarch", Some(relation), true)
        ])
        .into_resolved(&[relation], &[], &[], &inventory)
        .is_err()
    );
    assert!(
        output(vec![action(
            "dnfast-upgrade-0:1.0-1.noarch",
            Some(relation),
            true
        )])
        .into_resolved(&[relation, relation], &[], &[], &inventory)
        .is_err()
    );
    assert!(
        output(vec![action("dnfast-upgrade-0:1.0-1.noarch", None, true)])
            .into_resolved(&[], &[], &[], &inventory)
            .is_err()
    );

    let already = PackageSpec::parse("already-installed").unwrap();
    let mixed_output = NativeSolveOutput {
        source_transcript_sha256: digest('b'),
        actions: vec![action(
            "dnfast-upgrade-0:1.0-1.noarch",
            Some(relation),
            true,
        )],
        decisions: vec![],
        satisfied_specs: vec![already.clone()],
    };
    let mixed_resolved = mixed_output
        .clone()
        .into_resolved(
            &[relation, already.as_str()],
            &[candidate.clone(), h2.clone()],
            &[],
            &inventory,
        )
        .unwrap();
    let mixed_intent =
        TransactionIntent::from_package_names(Action::Install, &[relation, already.as_str()])
            .unwrap();
    let mixed_builder = PlanBuilder {
        intent: &mixed_intent,
        snapshots: &snapshots,
        inventory: &inventory,
        policy: &policy,
        candidates: &[candidate.clone(), h2.clone()],
        expires_at_unix: 100,
    };
    assert!(
        mixed_builder
            .build_with_satisfied(&mixed_resolved, mixed_output.satisfied_specs())
            .is_ok()
    );
    assert!(
        mixed_builder
            .build_with_satisfied(&mixed_resolved, &[])
            .is_err()
    );

    let bare = "dnfast-upgrade";
    let bare_intent = TransactionIntent::from_package_names(Action::Install, &[bare]).unwrap();
    let bare_builder = PlanBuilder {
        intent: &bare_intent,
        snapshots: &snapshots,
        inventory: &inventory,
        policy: &policy,
        candidates: &[candidate.clone(), h2.clone()],
        expires_at_unix: 100,
    };
    let bare_h1 = output(vec![action(
        "dnfast-upgrade-0:1.0-1.noarch",
        Some(bare),
        false,
    )])
    .into_resolved(&[bare], &[candidate.clone(), h2.clone()], &[], &inventory)
    .unwrap();
    assert!(
        matches!(bare_builder.build(&bare_h1), Err(dnfast_solver::PlanError::NonPreferred(name)) if name == "dnfast-upgrade")
    );
    let bare_h2 = output(vec![action(
        "dnfast-upgrade-0:2.0-1.noarch",
        Some(bare),
        false,
    )])
    .into_resolved(&[bare], &[candidate.clone(), h2], &[], &inventory)
    .unwrap();
    assert!(bare_builder.build(&bare_h2).is_ok());
}

#[test]
fn native_self_provided_requirement_does_not_create_a_self_ordering_edge() {
    let inventory = InstalledInventory::new("sqlite", "6.0.1", vec![]).unwrap();
    let repomd = std::fs::read(fixture("repodata/repomd.xml")).unwrap();
    let records = parse_repomd_records(&repomd).unwrap();
    let compressed = std::fs::read(fixture(&records.primary.href)).unwrap();
    let opened = decode_record(&compressed, &records.primary).unwrap();
    let mut package = parse_primary_records(opened.as_slice())
        .unwrap()
        .into_iter()
        .find(|item| item.name == "dnfast-app")
        .unwrap();
    let relation = package.provides[0].clone();
    package.requires = vec![relation.clone()];
    let nevra = format!(
        "{}-{}:{}-{}.{}",
        package.name, package.epoch, package.version, package.release, package.arch
    );
    let candidate = CandidatePackage {
        name: package.name.clone(),
        evra: Evra::new(
            package.epoch.parse().unwrap(),
            package.version.clone(),
            package.release.clone(),
            Architecture::Noarch,
        ),
        vendor: package.vendor.clone(),
        repo_id: "main".into(),
        priority: 99,
        cost: 1000,
        package_size: package.package_size,
        installed_size: package.installed_size,
        checksum_sha256: package.checksum.clone(),
        location: package.location.clone(),
        excluded: false,
        modular: false,
    };
    let output = NativeSolveOutput {
        source_transcript_sha256: digest('d'),
        actions: vec![NativeAction {
            kind: "install".into(),
            repository: "main".into(),
            nevra: nevra.clone(),
            old_nevra: None,
            installed_instance: None,
            installed_header_sha256: None,
            requested_spec: Some(PackageSpec::parse(package.name.clone()).unwrap()),
            requested_relation: false,
            provenance: None,
            transaction_counterpart_nevra: None,
        }],
        decisions: vec![dnfast_solver::NativeDecision {
            requiring_nevra: nevra.clone(),
            requiring_repo: "main".into(),
            requirement: relation,
            kind: DependencyKind::Strong,
            provider_nevra: nevra,
            provider_repo: "main".into(),
            provider_installed: false,
        }],
        satisfied_specs: vec![],
    };
    let metadata = [("main", &package)];
    let resolved = output
        .into_resolved(
            &[package.name.as_str()],
            &[candidate],
            &metadata,
            &inventory,
        )
        .unwrap();
    assert!(resolved[0].dependency_edges.is_empty());
}

#[test]
fn frozen_todo9_inventory_reader_output_feeds_remove_and_upgrade_plans() {
    let receipt: InventoryReceipt =
        serde_json::from_slice(include_bytes!("fixtures/inventory-reader-fedora44.json")).unwrap();
    assert_eq!(
        receipt.source_transcript_sha256,
        "b171221fe196809116ece6f9714a299b3e0342ee6bf7dfc4ed12507f9fbf359e"
    );
    assert_eq!(
        format!(
            "{:x}",
            Sha256::digest(evidence("task-9-fedora44-inventory.raw.log"))
        ),
        receipt.source_transcript_sha256
    );
    let snapshots = snapshots();
    let policy = SolverPolicy::fedora44_aarch64(vec![], vec![]);
    let old = &receipt.inventory.packages()[0];
    assert_eq!(old.vendor(), "Dnfast Original");
    let remove_intent =
        TransactionIntent::from_package_names(Action::Remove, &["dnfast-upgrade"]).unwrap();
    let base = |operation, candidate| ResolvedAction {
        operation,
        name: "dnfast-upgrade".into(),
        requested: true,
        requested_spec: Some(PackageSpec::parse("dnfast-upgrade").unwrap()),
        requested_relation: false,
        candidate,
        installed_instance: Some(old.db_instance()),
        installed_header_sha256: None,
        installed_vendor: Some(old.vendor().into()),
        dependency_edges: vec![],
        required_by_remaining: vec![],
        unresolved_dependencies: vec![],
        provenance: None,
        introduced_by_requested: false,
        solver_rule: "Todo9 inventory identity".into(),
    };
    let remove = PlanBuilder {
        intent: &remove_intent,
        snapshots: &snapshots,
        inventory: &receipt.inventory,
        policy: &policy,
        candidates: &[],
        expires_at_unix: 100,
    }
    .build(&[base(ResolvedOperation::Remove, None)]);
    assert!(remove.is_ok());
    let target = CandidatePackage {
        name: "dnfast-upgrade".into(),
        evra: Evra::new(0, "2.0", "1", Architecture::Noarch),
        vendor: "Dnfast Original".into(),
        repo_id: "main".into(),
        priority: 99,
        cost: 1000,
        package_size: 1,
        installed_size: 1,
        checksum_sha256: digest('a'),
        location: "dnfast-upgrade-2.0-1.noarch.rpm".into(),
        excluded: false,
        modular: false,
    };
    let candidates = [target.clone()];
    let upgrade_intent =
        TransactionIntent::from_package_names(Action::Upgrade, &["dnfast-upgrade"]).unwrap();
    let upgrade = PlanBuilder {
        intent: &upgrade_intent,
        snapshots: &snapshots,
        inventory: &receipt.inventory,
        policy: &policy,
        candidates: &candidates,
        expires_at_unix: 100,
    }
    .build(&[base(ResolvedOperation::Upgrade, Some(target))]);
    assert!(upgrade.is_ok());
    let transcript = receipt.source_transcript_sha256.clone();
    let native_remove = NativeSolveOutput::from_native(
        dnfast_native::SolveResult {
            actions: vec!["dnfast-upgrade-0:1.0-1.noarch".into()],
            repositories: vec!["@System".into()],
            kinds: vec!["erase".into()],
            obsoletes: vec![None],
            requested_specs: vec![Some("dnfast-upgrade".into())],
            requested_relation_kinds: vec![false],
            satisfied_specs: vec![],
            problems: vec![],
            decisions: vec![],
        },
        transcript.clone(),
        &[],
        &receipt.inventory,
    )
    .unwrap();
    let remove_resolved = native_remove
        .into_resolved(&["dnfast-upgrade"], &[], &[], &receipt.inventory)
        .unwrap();
    assert_eq!(remove_resolved[0].installed_instance, Some(456));
    assert!(
        PlanBuilder {
            intent: &remove_intent,
            snapshots: &snapshots,
            inventory: &receipt.inventory,
            policy: &policy,
            candidates: &[],
            expires_at_unix: 100
        }
        .build(&remove_resolved)
        .is_ok()
    );
    let native_upgrade = NativeSolveOutput::from_native(
        dnfast_native::SolveResult {
            actions: vec![
                "dnfast-upgrade-0:2.0-1.noarch".into(),
                "dnfast-upgrade-0:1.0-1.noarch".into(),
            ],
            repositories: vec!["main".into(), "@System".into()],
            kinds: vec!["upgrade".into(), "upgraded".into()],
            obsoletes: vec![
                Some("dnfast-upgrade-0:1.0-1.noarch".into()),
                Some("dnfast-upgrade-0:2.0-1.noarch".into()),
            ],
            requested_specs: vec![Some("dnfast-upgrade".into()), None],
            requested_relation_kinds: vec![false, false],
            satisfied_specs: vec![],
            problems: vec![],
            decisions: vec![],
        },
        transcript.clone(),
        &[],
        &receipt.inventory,
    )
    .unwrap();
    assert_eq!(native_upgrade.actions.len(), 1);
    assert_eq!(
        native_upgrade.actions[0].old_nevra.as_deref(),
        Some("dnfast-upgrade-0:1.0-1.noarch")
    );
    let upgraded = native_upgrade
        .into_resolved(&["dnfast-upgrade"], &candidates, &[], &receipt.inventory)
        .unwrap();
    assert!(
        PlanBuilder {
            intent: &upgrade_intent,
            snapshots: &snapshots,
            inventory: &receipt.inventory,
            policy: &policy,
            candidates: &candidates,
            expires_at_unix: 100
        }
        .build(&upgraded)
        .is_ok()
    );
    let native_upgrade_all = NativeSolveOutput::from_native(
        dnfast_native::SolveResult {
            actions: vec![
                "dnfast-upgrade-0:2.0-1.noarch".into(),
                "dnfast-upgrade-0:1.0-1.noarch".into(),
            ],
            repositories: vec!["main".into(), "@System".into()],
            kinds: vec!["upgrade".into(), "upgraded".into()],
            obsoletes: vec![
                Some("dnfast-upgrade-0:1.0-1.noarch".into()),
                Some("dnfast-upgrade-0:2.0-1.noarch".into()),
            ],
            requested_specs: vec![None, None],
            requested_relation_kinds: vec![false, false],
            satisfied_specs: vec![],
            problems: vec![],
            decisions: vec![],
        },
        transcript.clone(),
        &[],
        &receipt.inventory,
    )
    .unwrap();
    let upgraded_all = native_upgrade_all
        .into_resolved(&[], &candidates, &[], &receipt.inventory)
        .unwrap();
    assert!(upgraded_all[0].requested);
    assert!(upgraded_all[0].requested_spec.is_none());
    let upgrade_all_intent = TransactionIntent::from_package_names(Action::Upgrade, &[]).unwrap();
    assert!(
        PlanBuilder {
            intent: &upgrade_all_intent,
            snapshots: &snapshots,
            inventory: &receipt.inventory,
            policy: &policy,
            candidates: &candidates,
            expires_at_unix: 100
        }
        .build(&upgraded_all)
        .is_ok()
    );
    let duplicate = InstalledInventory::new(
        "sqlite",
        "6.0.1",
        vec![
            old.clone(),
            dnfast_core::InstalledPackage::new(
                "dnfast-upgrade",
                old.evra().clone(),
                old.vendor(),
                999,
                old.install_time() + 1,
                digest('e'),
            )
            .unwrap(),
        ],
    )
    .unwrap();
    let ambiguous = NativeSolveOutput::from_native(
        dnfast_native::SolveResult {
            actions: vec!["dnfast-upgrade-0:1.0-1.noarch".into()],
            repositories: vec!["@System".into()],
            kinds: vec!["erase".into()],
            obsoletes: vec![None],
            requested_specs: vec![Some("dnfast-upgrade".into())],
            requested_relation_kinds: vec![false],
            satisfied_specs: vec![],
            problems: vec![],
            decisions: vec![],
        },
        transcript,
        &[],
        &duplicate,
    );
    assert!(matches!(
        ambiguous,
        Err(dnfast_solver::PlanError::AmbiguousInstalled(_))
    ));
    let dep = dnfast_core::InstalledPackage::new(
        "dnfast-dep",
        Evra::new(0, "1.0", "1", Architecture::Noarch),
        "unknown",
        777,
        1,
        digest('d'),
    )
    .unwrap();
    let obsoletes_inventory =
        InstalledInventory::new("sqlite", "6.0.1", vec![old.clone(), dep]).unwrap();
    let obsoletes_result = dnfast_native::SolveResult {
        actions: vec![
            "dnfast-obsoletes-0:2.0-1.noarch".into(),
            "dnfast-dep-0:1.0-1.noarch".into(),
        ],
        repositories: vec!["main".into(), "@System".into()],
        kinds: vec!["obsoletes".into(), "obsoleted".into()],
        obsoletes: vec![
            Some("dnfast-dep-0:1.0-1.noarch".into()),
            Some("dnfast-obsoletes-0:2.0-1.noarch".into()),
        ],
        requested_specs: vec![Some("replacement".into()), None],
        requested_relation_kinds: vec![false, false],
        satisfied_specs: vec![],
        problems: vec![],
        decisions: vec![],
    };
    let paired =
        NativeSolveOutput::from_native(obsoletes_result, digest('f'), &[], &obsoletes_inventory)
            .unwrap();
    assert_eq!(paired.actions.len(), 2);
    assert!(paired.actions.iter().any(|item| matches!(
        item.provenance,
        Some(dnfast_solver::ActionProvenance::ObsoletedBy { .. })
    )));
    let missing_pair = NativeSolveOutput::from_native(
        dnfast_native::SolveResult {
            actions: vec!["dnfast-obsoletes-0:2.0-1.noarch".into()],
            repositories: vec!["main".into()],
            kinds: vec!["obsoletes".into()],
            obsoletes: vec![None],
            requested_specs: vec![None],
            requested_relation_kinds: vec![false],
            satisfied_specs: vec![],
            problems: vec![],
            decisions: vec![],
        },
        digest('f'),
        &[],
        &obsoletes_inventory,
    );
    assert!(matches!(
        missing_pair,
        Err(dnfast_solver::PlanError::InstalledMissing(_))
    ));
}

#[test]
fn native_multi_obsoletion_is_visible_typed_and_atomic() {
    let old_a = dnfast_core::InstalledPackage::new(
        "old-a",
        Evra::new(0, "1", "1", Architecture::Noarch),
        "unknown",
        31,
        1,
        digest('a'),
    )
    .unwrap();
    let old_b = dnfast_core::InstalledPackage::new(
        "old-b",
        Evra::new(0, "1", "1", Architecture::Noarch),
        "unknown",
        32,
        1,
        digest('b'),
    )
    .unwrap();
    let inventory = InstalledInventory::new("sqlite", "6.0.1", vec![old_a, old_b]).unwrap();
    let result = dnfast_native::SolveResult {
        actions: vec![
            "replacement-0:2-1.noarch".into(),
            "old-a-0:1-1.noarch".into(),
            "old-b-0:1-1.noarch".into(),
        ],
        repositories: vec!["main".into(), "@System".into(), "@System".into()],
        kinds: vec!["obsoletes".into(), "obsoleted".into(), "obsoleted".into()],
        obsoletes: vec![
            Some("old-a-0:1-1.noarch".into()),
            Some("replacement-0:2-1.noarch".into()),
            Some("replacement-0:2-1.noarch".into()),
        ],
        requested_specs: vec![Some("replacement".into()), None, None],
        requested_relation_kinds: vec![false, false, false],
        satisfied_specs: vec![],
        problems: vec![],
        decisions: vec![],
    };
    let native = NativeSolveOutput::from_native(result, digest('c'), &[], &inventory).unwrap();
    let replacement = CandidatePackage {
        name: "replacement".into(),
        evra: Evra::new(0, "2", "1", Architecture::Noarch),
        vendor: "unknown".into(),
        repo_id: "main".into(),
        priority: 99,
        cost: 1000,
        package_size: 7,
        installed_size: 9,
        checksum_sha256: digest('d'),
        location: "replacement-2-1.noarch.rpm".into(),
        excluded: false,
        modular: false,
    };
    let candidates = [replacement];
    let resolved = native
        .into_resolved(&["replacement"], &candidates, &[], &inventory)
        .unwrap();
    assert_eq!(resolved.len(), 3);
    assert_eq!(
        resolved
            .iter()
            .filter(|item| item.operation == ResolvedOperation::Remove)
            .count(),
        2
    );
    let intent = TransactionIntent::from_package_names(Action::Install, &["replacement"]).unwrap();
    let snapshots = snapshots();
    let policy = SolverPolicy::fedora44_aarch64(vec![], vec![]);
    let builder = PlanBuilder {
        intent: &intent,
        snapshots: &snapshots,
        inventory: &inventory,
        policy: &policy,
        candidates: &candidates,
        expires_at_unix: 100,
    };
    let plan = builder.build(&resolved).unwrap();
    assert_eq!(
        plan.actions()
            .iter()
            .map(|item| item.name())
            .collect::<Vec<_>>(),
        ["replacement", "old-a", "old-b"]
    );
    let mut tampered = resolved.clone();
    tampered[1].provenance = Some(dnfast_solver::ActionProvenance::ObsoletedBy {
        parent_action_identity: "main:forged-0:1-1.noarch".into(),
    });
    assert!(matches!(
        builder.build(&tampered),
        Err(dnfast_solver::PlanError::MissingParent(_))
    ));
    let protected = SolverPolicy::fedora44_aarch64(vec!["old-b".into()], vec![]);
    let blocked = PlanBuilder {
        policy: &protected,
        ..builder
    }
    .build(&resolved);
    let downloads = AtomicUsize::new(0);
    assert!(blocked.is_err());
    assert_eq!(downloads.load(Ordering::SeqCst), 0);
    let core_json = String::from_utf8(plan.proposal().to_canonical_json().unwrap()).unwrap();
    let tampered_json = core_json.replace(
        "main:replacement-0:2-1.noarch",
        "main:forged-0:000000002-1.noarch",
    );
    let tampered_core = CanonicalPlan::from_canonical_json(tampered_json.as_bytes()).unwrap();
    assert!(tampered_core.validate_executable(&policy, 0).is_err());
    assert_eq!(
        String::from_utf8(plan.canonical_json().unwrap()).unwrap(),
        include_str!("golden/obsoletes-multiple.json").trim_end()
    );
}
