use std::collections::{BTreeMap, BTreeSet};

use dnfast_core::{CanonicalPlan, Evra, InstalledInventory, PackageOperation, PackageReason};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReasonDecision { Record(PackageReason), Keep(PackageReason) }

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct InstalledIdentity { pub db_instance: u64, pub header_sha256: String }

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PlannedIdentity { pub package_name: String, pub target_evra: Evra }

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReconciledReason { pub identity: InstalledIdentity, pub package_name: String, pub decision: ReasonDecision }

pub fn proposals_from_plan(plan: &CanonicalPlan) -> BTreeMap<PlannedIdentity, PackageReason> {
    plan.actions().iter().filter(|action| action.operation() != PackageOperation::Remove).map(|action| (
        PlannedIdentity { package_name: action.name().into(), target_evra: action.target_evra().clone() }, action.reason()
    )).collect()
}

pub fn reconcile_reasons(
    before: &InstalledInventory,
    after: &InstalledInventory,
    proposed: &BTreeMap<PlannedIdentity, PackageReason>,
    protected: &BTreeSet<String>,
    installonly: &BTreeSet<String>,
) -> Vec<ReconciledReason> {
    let before_ids = before.packages().iter().map(|package| (package.db_instance(), package.immutable_header_sha256().as_str())).collect::<BTreeSet<_>>();
    let mut remaining = proposed.clone();
    after.packages().iter().map(|package| {
        let name = package.name();
        let key = PlannedIdentity { package_name: name.into(), target_evra: package.evra().clone() };
        let is_new = !before_ids.contains(&(package.db_instance(), package.immutable_header_sha256().as_str()));
        let decision = if protected.contains(name) || installonly.contains(name) {
            ReasonDecision::Keep(PackageReason::User)
        } else if let Some(reason) = if is_new { remaining.remove(&key) } else { None } {
            match reason {
                PackageReason::External | PackageReason::Unknown => ReasonDecision::Keep(reason),
                PackageReason::User | PackageReason::Dependency | PackageReason::WeakDependency => ReasonDecision::Record(reason),
            }
        } else { ReasonDecision::Keep(PackageReason::External) };
        ReconciledReason { identity: InstalledIdentity { db_instance: package.db_instance(), header_sha256: package.immutable_header_sha256().as_str().into() }, package_name: name.into(), decision }
    }).collect()
}
