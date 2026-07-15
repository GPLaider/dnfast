use dnfast_core::{Evra, PackageReason, PackageSpec, PlanIntegrity};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidatePackage {
    pub name: String,
    pub evra: Evra,
    pub vendor: String,
    pub repo_id: String,
    pub priority: u32,
    pub cost: u32,
    pub package_size: u64,
    pub installed_size: u64,
    pub checksum_sha256: String,
    pub location: String,
    pub excluded: bool,
    pub modular: bool,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ResolvedOperation { Install, Upgrade, Remove }

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyKind { Strong, Weak }

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DependencyEdge { pub parent: String, pub kind: DependencyKind }

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ActionProvenance { ObsoletedBy { parent_action_identity: String } }

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedAction {
    pub operation: ResolvedOperation,
    pub name: String,
    pub requested: bool,
    pub requested_spec: Option<PackageSpec>,
    pub requested_relation: bool,
    pub candidate: Option<CandidatePackage>,
    pub installed_instance: Option<u64>,
    pub installed_header_sha256: Option<String>,
    pub installed_vendor: Option<String>,
    pub dependency_edges: Vec<DependencyEdge>,
    pub provenance: Option<ActionProvenance>,
    pub required_by_remaining: Vec<String>,
    pub unresolved_dependencies: Vec<String>,
    pub introduced_by_requested: bool,
    pub solver_rule: String,
}

pub type IntegritySnapshots = PlanIntegrity;

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactRecord {
    pub checksum_sha256: String,
    pub location: String,
    pub package_size: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestedRelation { Requested, Dependency, WeakDependency }

impl RequestedRelation {
    pub(crate) const fn reason(&self) -> PackageReason {
        match self {
            Self::Requested => PackageReason::User,
            Self::Dependency => PackageReason::Dependency,
            Self::WeakDependency => PackageReason::WeakDependency,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlanProtection {
    pub installonly: bool,
    pub protected: bool,
    pub running_kernel: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExplainedAction {
    pub operation: String,
    pub name: String,
    pub target_evra: Evra,
    pub installed_evra: Option<Evra>,
    pub installed_instance: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub installed_header_sha256: Option<String>,
    pub installed_vendor: Option<String>,
    pub vendor: Option<String>,
    pub repo_id: Option<String>,
    pub reason: PackageReason,
    pub relation: RequestedRelation,
    pub requested_by: Option<String>,
    pub dependency_edges: Vec<DependencyEdge>,
    pub provenance: Option<ActionProvenance>,
    pub package_size: u64,
    pub installed_size: u64,
    pub artifact: Option<ArtifactRecord>,
    pub protection: PlanProtection,
    pub explanation: String,
}

impl ExplainedAction {
    pub fn name(&self) -> &str { &self.name }
    pub const fn relation(&self) -> &RequestedRelation { &self.relation }
}
