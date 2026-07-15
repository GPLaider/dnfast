use std::collections::{BTreeMap, BTreeSet};

use dnfast_core::{Architecture, Evra, InstalledInventory, InstalledPackage, PackageReason};
use dnfast_state::{PlannedIdentity, ReasonDecision, reconcile_reasons};

const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

#[test]
fn reasons_derive_only_from_actual_post_run_instances() {
    let before = inventory(vec![package("old", 1, A)]);
    let after = inventory(vec![package("old", 1, A), package("new", 2, B)]);
    let proposed = BTreeMap::from([(planned("new"), PackageReason::Dependency), (planned("missing"), PackageReason::Dependency)]);
    let reconciled = reconcile_reasons(&before, &after, &proposed, &BTreeSet::new(), &BTreeSet::new());
    assert_eq!(reconciled.len(), 2);
    assert_eq!(reconciled[0].decision, ReasonDecision::Record(PackageReason::Dependency));
    assert_eq!(reconciled[1].decision, ReasonDecision::Keep(PackageReason::External));
}

#[test]
fn external_protected_and_installonly_are_always_kept() {
    let before = inventory(vec![]);
    let after = inventory(vec![package("external", 1, A), package("kernel", 2, B)]);
    let proposed = BTreeMap::from([(planned("external"), PackageReason::Unknown), (planned("kernel"), PackageReason::Dependency)]);
    let results = reconcile_reasons(&before, &after, &proposed, &BTreeSet::new(), &BTreeSet::from(["kernel".into()]));
    assert!(results.iter().all(|record| matches!(record.decision, ReasonDecision::Keep(_))));
}

#[test]
fn one_planned_nevra_is_consumed_by_only_one_post_run_instance() {
    let before = inventory(vec![]);
    let after = inventory(vec![package("duplicate", 1, A), package("duplicate", 2, B)]);
    let proposed = BTreeMap::from([(planned("duplicate"), PackageReason::Dependency)]);
    let results = reconcile_reasons(&before, &after, &proposed, &BTreeSet::new(), &BTreeSet::new());
    assert_eq!(results.iter().filter(|record| record.decision == ReasonDecision::Record(PackageReason::Dependency)).count(), 1);
    assert_eq!(results.iter().filter(|record| record.decision == ReasonDecision::Keep(PackageReason::External)).count(), 1);
}

fn package(name: &str, instance: u64, digest: &str) -> InstalledPackage {
    InstalledPackage::new(name, Evra::new(0, "1", "1", Architecture::Aarch64), "Fedora", instance, instance, digest).unwrap()
}
fn inventory(packages: Vec<InstalledPackage>) -> InstalledInventory { InstalledInventory::new("sqlite", "6", packages).unwrap() }
fn planned(name: &str) -> PlannedIdentity { PlannedIdentity { package_name: name.into(), target_evra: Evra::new(0, "1", "1", Architecture::Aarch64) } }
