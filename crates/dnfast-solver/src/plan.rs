use std::cmp::Ordering;

use dnfast_core::{
    CanonicalDocument, CanonicalPlan, InstalledInventory, PackageAction, SolverPolicy,
    TransactionIntent,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    ArtifactRecord, CandidatePackage, ExplainedAction, IntegritySnapshots, PlanError,
    PlanProtection, RequestedRelation, ResolvedAction, ResolvedOperation,
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalSolverPlan {
    schema: String,
    proposal: CanonicalPlan,
    actions: Vec<ExplainedAction>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPlan {
    schema: String,
    proposal: CanonicalPlan,
    actions: Vec<ExplainedAction>,
}

impl<'de> Deserialize<'de> for CanonicalSolverPlan {
    fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        let raw = RawPlan::deserialize(decoder)?;
        let value = Self {
            schema: raw.schema,
            proposal: raw.proposal,
            actions: raw.actions,
        };
        value.validate().map_err(serde::de::Error::custom)?;
        Ok(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanDigest(pub String);

pub struct PlanBuilder<'a> {
    pub intent: &'a TransactionIntent,
    pub snapshots: &'a IntegritySnapshots,
    pub inventory: &'a InstalledInventory,
    pub policy: &'a SolverPolicy,
    pub candidates: &'a [CandidatePackage],
    pub expires_at_unix: u64,
}

impl PlanBuilder<'_> {
    pub fn build(&self, resolved: &[ResolvedAction]) -> Result<CanonicalSolverPlan, PlanError> {
        self.policy
            .ensure_supported()
            .map_err(|error| PlanError::Unsafe(error.to_string()))?;
        crate::preflight::validate_inputs(self, resolved)?;
        let actions = resolved
            .iter()
            .map(|item| self.action(item))
            .collect::<Result<Vec<_>, _>>()?;
        let actions = crate::preflight::execution_order(resolved, actions)?;
        let core_actions = actions
            .iter()
            .map(core_action)
            .collect::<Result<Vec<_>, _>>()?;
        let proposal = CanonicalPlan::new(
            self.intent.clone(),
            self.snapshots.clone(),
            self.expires_at_unix,
            core_actions,
        )
        .map_err(|error| PlanError::Canonical(error.to_string()))?;
        proposal
            .validate_executable(self.policy, 0)
            .map_err(|error| PlanError::Unsafe(error.to_string()))?;
        let plan = CanonicalSolverPlan {
            schema: "dnfast.explained-plan.v1".into(),
            proposal,
            actions,
        };
        plan.validate()?;
        Ok(plan)
    }

    fn action(&self, resolved: &ResolvedAction) -> Result<ExplainedAction, PlanError> {
        if resolved.solver_rule.is_empty() {
            return Err(PlanError::Invalid("missing solver explanation"));
        }
        let installed = resolved
            .installed_instance
            .map(|id| {
                self.inventory
                    .packages()
                    .iter()
                    .find(|item| item.db_instance() == id)
                    .ok_or_else(|| PlanError::InstalledMissing(resolved.name.clone()))
            })
            .transpose()?;
        let relation = if resolved.requested {
            RequestedRelation::Requested
        } else if resolved.provenance.is_some() {
            RequestedRelation::Dependency
        } else if resolved
            .dependency_edges
            .iter()
            .all(|edge| edge.kind == crate::DependencyKind::Weak)
        {
            RequestedRelation::WeakDependency
        } else {
            RequestedRelation::Dependency
        };
        match resolved.operation {
            ResolvedOperation::Remove => self.remove(resolved, installed, relation),
            ResolvedOperation::Install | ResolvedOperation::Upgrade => {
                self.install_or_upgrade(resolved, installed, relation)
            }
        }
    }

    fn remove(
        &self,
        resolved: &ResolvedAction,
        installed: Option<&dnfast_core::InstalledPackage>,
        relation: RequestedRelation,
    ) -> Result<ExplainedAction, PlanError> {
        let installed =
            installed.ok_or_else(|| PlanError::InstalledMissing(resolved.name.clone()))?;
        if installed.name() != resolved.name {
            return Err(PlanError::Invalid("installed package name mismatch"));
        }
        if !resolved.required_by_remaining.is_empty()
            || (relation != RequestedRelation::Requested
                && !resolved.introduced_by_requested
                && resolved.provenance.is_none())
        {
            return Err(PlanError::Unsafe(format!(
                "reverse dependency requires {}",
                resolved.name
            )));
        }
        self.policy
            .validate_planned_removal(&resolved.name, relation.reason())
            .map_err(|error| PlanError::Unsafe(error.to_string()))?;
        Ok(ExplainedAction {
            operation: "remove".into(),
            name: resolved.name.clone(),
            target_evra: installed.evra().clone(),
            installed_evra: Some(installed.evra().clone()),
            installed_instance: Some(installed.db_instance()),
            installed_header_sha256: Some(installed.immutable_header_sha256().as_str().into()),
            vendor: None,
            installed_vendor: resolved.installed_vendor.clone(),
            repo_id: None,
            reason: relation.reason(),
            relation,
            requested_by: resolved
                .dependency_edges
                .first()
                .map(|edge| edge.parent.clone()),
            dependency_edges: resolved.dependency_edges.clone(),
            provenance: resolved.provenance.clone(),
            package_size: 0,
            installed_size: 0,
            artifact: None,
            protection: self.protection(&resolved.name),
            explanation: resolved.solver_rule.clone(),
        })
    }

    fn install_or_upgrade(
        &self,
        resolved: &ResolvedAction,
        installed: Option<&dnfast_core::InstalledPackage>,
        relation: RequestedRelation,
    ) -> Result<ExplainedAction, PlanError> {
        let candidate = resolved
            .candidate
            .as_ref()
            .ok_or(PlanError::Invalid("missing candidate"))?;
        self.validate_candidate(
            candidate,
            installed,
            resolved.installed_vendor.as_deref(),
            resolved.requested && resolved.requested_spec.is_some() && resolved.requested_relation,
        )?;
        if candidate.name != resolved.name {
            return Err(PlanError::Invalid("candidate name mismatch"));
        }
        if matches!(resolved.operation, ResolvedOperation::Upgrade) {
            let previous =
                installed.ok_or_else(|| PlanError::InstalledMissing(resolved.name.clone()))?;
            let installed_vendor = resolved
                .installed_vendor
                .as_deref()
                .ok_or(PlanError::Invalid("missing installed vendor"))?;
            self.policy
                .validate_planned_upgrade(
                    previous.evra(),
                    &candidate.evra,
                    installed_vendor,
                    &candidate.vendor,
                )
                .map_err(|error| PlanError::Unsafe(error.to_string()))?;
        } else if installed.is_some() {
            return Err(PlanError::Invalid("install action already installed"));
        }
        let operation = if matches!(resolved.operation, ResolvedOperation::Upgrade) {
            "upgrade"
        } else {
            "install"
        };
        Ok(ExplainedAction {
            operation: operation.into(),
            name: resolved.name.clone(),
            target_evra: candidate.evra.clone(),
            installed_evra: installed.map(|item| item.evra().clone()),
            installed_instance: installed.map(dnfast_core::InstalledPackage::db_instance),
            installed_header_sha256: installed
                .map(|item| item.immutable_header_sha256().as_str().into()),
            installed_vendor: resolved.installed_vendor.clone(),
            vendor: Some(candidate.vendor.clone()),
            repo_id: Some(candidate.repo_id.clone()),
            reason: relation.reason(),
            relation,
            requested_by: resolved
                .dependency_edges
                .first()
                .map(|edge| edge.parent.clone()),
            dependency_edges: resolved.dependency_edges.clone(),
            provenance: resolved.provenance.clone(),
            package_size: candidate.package_size,
            installed_size: candidate.installed_size,
            artifact: Some(ArtifactRecord {
                checksum_sha256: digest(&candidate.checksum_sha256)?,
                location: candidate.location.clone(),
                package_size: candidate.package_size,
            }),
            protection: self.protection(&resolved.name),
            explanation: resolved.solver_rule.clone(),
        })
    }

    fn validate_candidate(
        &self,
        candidate: &CandidatePackage,
        installed: Option<&dnfast_core::InstalledPackage>,
        installed_vendor: Option<&str>,
        exact_requested_relation: bool,
    ) -> Result<(), PlanError> {
        if candidate.modular {
            return Err(PlanError::Modular(candidate.name.clone()));
        }
        if candidate.excluded || self.policy.is_excluded(&candidate.name) {
            return Err(PlanError::Excluded(candidate.name.clone()));
        }
        if candidate.location.starts_with('/')
            || candidate.location.contains("..")
            || candidate.location.contains("//")
            || candidate.location.contains('\\')
            || candidate.location.chars().any(char::is_control)
        {
            return Err(PlanError::Invalid("unsafe artifact location"));
        }
        let preferred = self
            .candidates
            .iter()
            .filter(|item| item.name == candidate.name && !item.excluded && !item.modular)
            .filter(|item| {
                installed.is_none_or(|current| item.evra.arch() == current.evra().arch())
            })
            .filter(|item| installed_vendor.is_none_or(|vendor| item.vendor == vendor))
            .max_by(|left, right| candidate_cmp(left, right));
        if preferred != Some(candidate) && !exact_requested_relation {
            return Err(PlanError::NonPreferred(candidate.name.clone()));
        }
        Ok(())
    }

    fn protection(&self, name: &str) -> PlanProtection {
        PlanProtection {
            installonly: self.policy.is_installonly(name),
            protected: self.policy.is_protected(name),
            running_kernel: self.policy.is_running_kernel(name),
        }
    }
}

fn candidate_cmp(left: &CandidatePackage, right: &CandidatePackage) -> Ordering {
    if left.evra != right.evra {
        if left.evra.is_strictly_newer_than(&right.evra) {
            return Ordering::Greater;
        }
        if right.evra.is_strictly_newer_than(&left.evra) {
            return Ordering::Less;
        }
    }
    right
        .priority
        .cmp(&left.priority)
        .then_with(|| right.cost.cmp(&left.cost))
        .then_with(|| right.repo_id.cmp(&left.repo_id))
        .then_with(|| right.location.cmp(&left.location))
}

fn digest(value: &str) -> Result<String, PlanError> {
    if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(value.to_ascii_lowercase())
    } else {
        Err(PlanError::Invalid("invalid SHA-256 digest"))
    }
}

impl CanonicalSolverPlan {
    pub fn canonical_json(&self) -> Result<Vec<u8>, PlanError> {
        self.validate()?;
        let tree =
            serde_json::to_value(self).map_err(|error| PlanError::Canonical(error.to_string()))?;
        serde_json::to_vec(&tree).map_err(|error| PlanError::Canonical(error.to_string()))
    }
    pub fn digest(&self) -> Result<PlanDigest, PlanError> {
        Ok(PlanDigest(format!(
            "{:x}",
            Sha256::digest(self.canonical_json()?)
        )))
    }
    pub fn from_canonical_json(bytes: &[u8], now_unix: u64) -> Result<Self, PlanError> {
        if bytes.len() > 16 * 1024 * 1024 {
            return Err(PlanError::Invalid("plan exceeds 16 MiB"));
        }
        let value: Self = serde_json::from_slice(bytes)
            .map_err(|error| PlanError::Canonical(error.to_string()))?;
        if value.canonical_json()? != bytes {
            return Err(PlanError::Canonical("non-canonical JSON".into()));
        }
        value
            .proposal
            .validate_now(now_unix)
            .map_err(|error| PlanError::Canonical(error.to_string()))?;
        Ok(value)
    }
    pub fn actions(&self) -> &[ExplainedAction] {
        &self.actions
    }
    pub fn proposal(&self) -> &CanonicalPlan {
        &self.proposal
    }
    fn validate(&self) -> Result<(), PlanError> {
        if self.schema != "dnfast.explained-plan.v1" {
            return Err(PlanError::Invalid("schema"));
        }
        self.proposal
            .to_canonical_json()
            .map_err(|error| PlanError::Canonical(error.to_string()))?;
        if self.proposal.actions().len() != self.actions.len() {
            return Err(PlanError::Invalid("proposal action mismatch"));
        }
        let mut left = self
            .proposal
            .actions()
            .iter()
            .map(serde_json::to_value)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| PlanError::Canonical(error.to_string()))?;
        let mut right = self
            .actions
            .iter()
            .map(core_action)
            .map(|item| {
                item.and_then(|action| {
                    serde_json::to_value(action)
                        .map_err(|error| PlanError::Canonical(error.to_string()))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        left.sort_by_key(serde_json::Value::to_string);
        right.sort_by_key(serde_json::Value::to_string);
        if left != right {
            return Err(PlanError::Invalid("proposal action mismatch"));
        }
        Ok(())
    }
}

impl PlanDigest {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn core_action(action: &ExplainedAction) -> Result<PackageAction, PlanError> {
    match action.operation.as_str() {
        "install" => Ok(PackageAction::install_with_vendor(
            &action.name,
            action.target_evra.clone(),
            action
                .repo_id
                .as_deref()
                .ok_or(PlanError::Invalid("missing repo"))?,
            action
                .vendor
                .as_deref()
                .ok_or(PlanError::Invalid("missing vendor"))?,
            action.reason,
        )),
        "upgrade" => PackageAction::upgrade_with_identity(
            &action.name,
            action
                .installed_evra
                .clone()
                .ok_or(PlanError::Invalid("missing installed EVRA"))?,
            action.target_evra.clone(),
            action
                .repo_id
                .as_deref()
                .ok_or(PlanError::Invalid("missing repo"))?,
            action
                .installed_vendor
                .as_deref()
                .ok_or(PlanError::Invalid("missing installed vendor"))?,
            action
                .vendor
                .as_deref()
                .ok_or(PlanError::Invalid("missing candidate vendor"))?,
            action.reason,
            action
                .installed_instance
                .ok_or(PlanError::Invalid("missing installed instance"))?,
            action
                .installed_header_sha256
                .as_deref()
                .ok_or(PlanError::Invalid("missing installed header"))?,
        )
        .map_err(|error| PlanError::Canonical(error.to_string())),
        "remove" => match &action.provenance {
            Some(crate::ActionProvenance::ObsoletedBy {
                parent_action_identity,
            }) => PackageAction::remove_obsoleted_with_identity(
                &action.name,
                action.target_evra.clone(),
                action
                    .installed_vendor
                    .as_deref()
                    .ok_or(PlanError::Invalid("missing installed vendor"))?,
                action.reason,
                action
                    .installed_instance
                    .ok_or(PlanError::Invalid("missing installed instance"))?,
                action
                    .installed_header_sha256
                    .as_deref()
                    .ok_or(PlanError::Invalid("missing installed header"))?,
                parent_action_identity.clone(),
            )
            .map_err(|error| PlanError::Canonical(error.to_string())),
            None => PackageAction::remove_with_identity(
                &action.name,
                action.target_evra.clone(),
                action
                    .installed_vendor
                    .as_deref()
                    .ok_or(PlanError::Invalid("missing installed vendor"))?,
                action.reason,
                action
                    .installed_instance
                    .ok_or(PlanError::Invalid("missing installed instance"))?,
                action
                    .installed_header_sha256
                    .as_deref()
                    .ok_or(PlanError::Invalid("missing installed header"))?,
            )
            .map_err(|error| PlanError::Canonical(error.to_string())),
        },
        _ => Err(PlanError::Invalid("unknown operation")),
    }
}

pub struct ReSolveContract;
impl ReSolveContract {
    pub fn require_equal(
        proposed: &CanonicalSolverPlan,
        root: &CanonicalSolverPlan,
    ) -> Result<(), PlanError> {
        if proposed.canonical_json()? == root.canonical_json()? {
            Ok(())
        } else {
            Err(PlanError::ReSolveMismatch)
        }
    }
}
