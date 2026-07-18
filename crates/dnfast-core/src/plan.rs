use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::{
    Action, CanonicalDocument, DomainError, Evra, PackageReason, PlanIntegrity, RepositoryBinding,
    Sha256Digest, TransactionIntent, canonical,
};

pub const MAX_PLAN_ACTIONS: usize = 100_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PackageOperation {
    Install,
    Upgrade,
    Downgrade,
    Reinstall,
    Remove,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ActionProvenance {
    ObsoletedBy { parent_action_identity: String },
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackageAction {
    operation: PackageOperation,
    name: String,
    target_evra: Evra,
    installed_evra: Option<Evra>,
    #[serde(skip_serializing_if = "Option::is_none")]
    installed_instance: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    installed_header_sha256: Option<Sha256Digest>,
    installed_vendor: Option<String>,
    candidate_vendor: Option<String>,
    repo_id: Option<String>,
    reason: PackageReason,
    provenance: Option<ActionProvenance>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPackageAction {
    operation: PackageOperation,
    name: String,
    target_evra: Evra,
    installed_evra: Option<Evra>,
    installed_instance: Option<u64>,
    installed_header_sha256: Option<Sha256Digest>,
    installed_vendor: Option<String>,
    candidate_vendor: Option<String>,
    repo_id: Option<String>,
    reason: PackageReason,
    provenance: Option<ActionProvenance>,
}

impl<'de> Deserialize<'de> for PackageAction {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = RawPackageAction::deserialize(deserializer)?;
        let value = Self {
            operation: raw.operation,
            name: raw.name,
            target_evra: raw.target_evra,
            installed_evra: raw.installed_evra,
            installed_instance: raw.installed_instance,
            installed_header_sha256: raw.installed_header_sha256,
            installed_vendor: raw.installed_vendor,
            candidate_vendor: raw.candidate_vendor,
            repo_id: raw.repo_id,
            reason: raw.reason,
            provenance: raw.provenance,
        };
        value.validate().map_err(serde::de::Error::custom)?;
        Ok(value)
    }
}

impl PackageAction {
    pub const fn operation(&self) -> PackageOperation {
        self.operation
    }
    pub fn target_evra(&self) -> &Evra {
        &self.target_evra
    }
    pub const fn reason(&self) -> PackageReason {
        self.reason
    }
    pub const fn installed_instance(&self) -> Option<u64> {
        self.installed_instance
    }
    pub fn installed_header_sha256(&self) -> Option<&Sha256Digest> {
        self.installed_header_sha256.as_ref()
    }
    pub fn install(
        name: impl Into<String>,
        evra: Evra,
        repo_id: impl Into<String>,
        reason: PackageReason,
    ) -> Self {
        Self {
            operation: PackageOperation::Install,
            name: name.into(),
            target_evra: evra,
            installed_evra: None,
            installed_instance: None,
            installed_header_sha256: None,
            installed_vendor: None,
            candidate_vendor: Some("unknown".into()),
            repo_id: Some(repo_id.into()),
            reason,
            provenance: None,
        }
    }
    pub fn install_with_vendor(
        name: impl Into<String>,
        evra: Evra,
        repo_id: impl Into<String>,
        vendor: impl Into<String>,
        reason: PackageReason,
    ) -> Self {
        Self {
            operation: PackageOperation::Install,
            name: name.into(),
            target_evra: evra,
            installed_evra: None,
            installed_instance: None,
            installed_header_sha256: None,
            installed_vendor: None,
            candidate_vendor: Some(vendor.into()),
            repo_id: Some(repo_id.into()),
            reason,
            provenance: None,
        }
    }
    pub fn remove(name: impl Into<String>, evra: Evra, reason: PackageReason) -> Self {
        Self {
            operation: PackageOperation::Remove,
            name: name.into(),
            target_evra: evra.clone(),
            installed_evra: Some(evra),
            installed_instance: None,
            installed_header_sha256: None,
            installed_vendor: Some("unknown".into()),
            candidate_vendor: None,
            repo_id: None,
            reason,
            provenance: None,
        }
    }
    pub fn remove_with_vendor(
        name: impl Into<String>,
        evra: Evra,
        vendor: impl Into<String>,
        reason: PackageReason,
    ) -> Self {
        Self {
            operation: PackageOperation::Remove,
            name: name.into(),
            target_evra: evra.clone(),
            installed_evra: Some(evra),
            installed_instance: None,
            installed_header_sha256: None,
            installed_vendor: Some(vendor.into()),
            candidate_vendor: None,
            repo_id: None,
            reason,
            provenance: None,
        }
    }
    pub fn upgrade(
        name: impl Into<String>,
        installed_evra: Evra,
        target_evra: Evra,
        repo_id: impl Into<String>,
        installed_vendor: impl Into<String>,
        candidate_vendor: impl Into<String>,
        reason: PackageReason,
    ) -> Self {
        Self {
            operation: PackageOperation::Upgrade,
            name: name.into(),
            target_evra,
            installed_evra: Some(installed_evra),
            installed_instance: None,
            installed_header_sha256: None,
            installed_vendor: Some(installed_vendor.into()),
            candidate_vendor: Some(candidate_vendor.into()),
            repo_id: Some(repo_id.into()),
            reason,
            provenance: None,
        }
    }
    pub fn downgrade(
        name: impl Into<String>,
        installed_evra: Evra,
        target_evra: Evra,
        repo_id: impl Into<String>,
        installed_vendor: impl Into<String>,
        candidate_vendor: impl Into<String>,
        reason: PackageReason,
    ) -> Self {
        Self {
            operation: PackageOperation::Downgrade,
            name: name.into(),
            target_evra,
            installed_evra: Some(installed_evra),
            installed_instance: None,
            installed_header_sha256: None,
            installed_vendor: Some(installed_vendor.into()),
            candidate_vendor: Some(candidate_vendor.into()),
            repo_id: Some(repo_id.into()),
            reason,
            provenance: None,
        }
    }
    pub fn reinstall(
        name: impl Into<String>,
        installed_evra: Evra,
        target_evra: Evra,
        repo_id: impl Into<String>,
        installed_vendor: impl Into<String>,
        candidate_vendor: impl Into<String>,
        reason: PackageReason,
    ) -> Self {
        Self {
            operation: PackageOperation::Reinstall,
            name: name.into(),
            target_evra,
            installed_evra: Some(installed_evra),
            installed_instance: None,
            installed_header_sha256: None,
            installed_vendor: Some(installed_vendor.into()),
            candidate_vendor: Some(candidate_vendor.into()),
            repo_id: Some(repo_id.into()),
            reason,
            provenance: None,
        }
    }
    pub fn remove_obsoleted(
        name: impl Into<String>,
        evra: Evra,
        vendor: impl Into<String>,
        reason: PackageReason,
        parent_action_identity: String,
    ) -> Self {
        Self {
            operation: PackageOperation::Remove,
            name: name.into(),
            target_evra: evra.clone(),
            installed_evra: Some(evra),
            installed_instance: None,
            installed_header_sha256: None,
            installed_vendor: Some(vendor.into()),
            candidate_vendor: None,
            repo_id: None,
            reason,
            provenance: Some(ActionProvenance::ObsoletedBy {
                parent_action_identity,
            }),
        }
    }
    pub fn remove_with_identity(
        name: impl Into<String>,
        evra: Evra,
        vendor: impl Into<String>,
        reason: PackageReason,
        instance: u64,
        header_sha256: impl Into<String>,
    ) -> Result<Self, DomainError> {
        Ok(Self {
            operation: PackageOperation::Remove,
            name: name.into(),
            target_evra: evra.clone(),
            installed_evra: Some(evra),
            installed_instance: Some(instance),
            installed_header_sha256: Some(Sha256Digest::parse(
                header_sha256,
                "installed_header_sha256",
            )?),
            installed_vendor: Some(vendor.into()),
            candidate_vendor: None,
            repo_id: None,
            reason,
            provenance: None,
        })
    }
    pub fn remove_obsoleted_with_identity(
        name: impl Into<String>,
        evra: Evra,
        vendor: impl Into<String>,
        reason: PackageReason,
        instance: u64,
        header_sha256: impl Into<String>,
        parent_action_identity: String,
    ) -> Result<Self, DomainError> {
        Ok(Self {
            operation: PackageOperation::Remove,
            name: name.into(),
            target_evra: evra.clone(),
            installed_evra: Some(evra),
            installed_instance: Some(instance),
            installed_header_sha256: Some(Sha256Digest::parse(
                header_sha256,
                "installed_header_sha256",
            )?),
            installed_vendor: Some(vendor.into()),
            candidate_vendor: None,
            repo_id: None,
            reason,
            provenance: Some(ActionProvenance::ObsoletedBy {
                parent_action_identity,
            }),
        })
    }
    #[allow(clippy::too_many_arguments)]
    pub fn upgrade_with_identity(
        name: impl Into<String>,
        installed_evra: Evra,
        target_evra: Evra,
        repo_id: impl Into<String>,
        installed_vendor: impl Into<String>,
        candidate_vendor: impl Into<String>,
        reason: PackageReason,
        instance: u64,
        header_sha256: impl Into<String>,
    ) -> Result<Self, DomainError> {
        Ok(Self {
            operation: PackageOperation::Upgrade,
            name: name.into(),
            target_evra,
            installed_evra: Some(installed_evra),
            installed_instance: Some(instance),
            installed_header_sha256: Some(Sha256Digest::parse(
                header_sha256,
                "installed_header_sha256",
            )?),
            installed_vendor: Some(installed_vendor.into()),
            candidate_vendor: Some(candidate_vendor.into()),
            repo_id: Some(repo_id.into()),
            reason,
            provenance: None,
        })
    }
    #[allow(clippy::too_many_arguments)]
    pub fn downgrade_with_identity(
        name: impl Into<String>,
        installed_evra: Evra,
        target_evra: Evra,
        repo_id: impl Into<String>,
        installed_vendor: impl Into<String>,
        candidate_vendor: impl Into<String>,
        reason: PackageReason,
        instance: u64,
        header_sha256: impl Into<String>,
    ) -> Result<Self, DomainError> {
        Ok(Self {
            operation: PackageOperation::Downgrade,
            name: name.into(),
            target_evra,
            installed_evra: Some(installed_evra),
            installed_instance: Some(instance),
            installed_header_sha256: Some(Sha256Digest::parse(
                header_sha256,
                "installed_header_sha256",
            )?),
            installed_vendor: Some(installed_vendor.into()),
            candidate_vendor: Some(candidate_vendor.into()),
            repo_id: Some(repo_id.into()),
            reason,
            provenance: None,
        })
    }
    #[allow(clippy::too_many_arguments)]
    pub fn reinstall_with_identity(
        name: impl Into<String>,
        installed_evra: Evra,
        target_evra: Evra,
        repo_id: impl Into<String>,
        installed_vendor: impl Into<String>,
        candidate_vendor: impl Into<String>,
        reason: PackageReason,
        instance: u64,
        header_sha256: impl Into<String>,
    ) -> Result<Self, DomainError> {
        Ok(Self {
            operation: PackageOperation::Reinstall,
            name: name.into(),
            target_evra,
            installed_evra: Some(installed_evra),
            installed_instance: Some(instance),
            installed_header_sha256: Some(Sha256Digest::parse(
                header_sha256,
                "installed_header_sha256",
            )?),
            installed_vendor: Some(installed_vendor.into()),
            candidate_vendor: Some(candidate_vendor.into()),
            repo_id: Some(repo_id.into()),
            reason,
            provenance: None,
        })
    }
    pub fn name(&self) -> &str {
        &self.name
    }
    fn action_identity(&self) -> Option<String> {
        self.repo_id.as_ref().map(|repo| {
            format!(
                "{repo}:{}-{}:{}-{}.{}",
                self.name,
                self.target_evra.epoch(),
                self.target_evra.version(),
                self.target_evra.release(),
                self.target_evra.arch().as_rpm_arch()
            )
        })
    }
    fn validate(&self) -> Result<(), DomainError> {
        if self.name.is_empty() {
            return Err(DomainError::Empty {
                field: "action_name",
            });
        }
        self.target_evra.validate()?;
        match self.operation {
            PackageOperation::Install
            | PackageOperation::Upgrade
            | PackageOperation::Downgrade
            | PackageOperation::Reinstall
                if self.repo_id.as_deref().is_none_or(str::is_empty) =>
            {
                Err(DomainError::InvalidPlan(
                    "install/replacement action requires repo",
                ))
            }
            PackageOperation::Remove if self.repo_id.is_some() => {
                Err(DomainError::InvalidPlan("remove action cannot have repo"))
            }
            PackageOperation::Remove
                if matches!(
                    self.reason,
                    PackageReason::Unknown | PackageReason::External
                ) =>
            {
                Err(DomainError::UnsafeAction("package reason requires keep"))
            }
            PackageOperation::Install
                if self.installed_evra.is_some()
                    || self.installed_instance.is_some()
                    || self.installed_header_sha256.is_some()
                    || self.installed_vendor.is_some() =>
            {
                Err(DomainError::InvalidPlan(
                    "install cannot carry installed package",
                ))
            }
            PackageOperation::Install
                if self.candidate_vendor.as_deref().is_none_or(str::is_empty) =>
            {
                Err(DomainError::InvalidPlan(
                    "install requires candidate vendor",
                ))
            }
            PackageOperation::Upgrade
            | PackageOperation::Downgrade
            | PackageOperation::Reinstall
                if self.installed_evra.is_none()
                    || self.installed_vendor.is_none()
                    || self.candidate_vendor.as_deref().is_none_or(str::is_empty)
                    || self.installed_instance.is_none()
                    || self.installed_header_sha256.is_none() =>
            {
                Err(DomainError::InvalidPlan(
                    "replacement requires installed and candidate identity",
                ))
            }
            PackageOperation::Remove
                if self.installed_evra.as_ref() != Some(&self.target_evra)
                    || self.installed_vendor.is_none()
                    || self.installed_instance.is_none()
                    || self.installed_header_sha256.is_none() =>
            {
                Err(DomainError::InvalidPlan(
                    "remove requires exact installed identity",
                ))
            }
            PackageOperation::Remove if self.candidate_vendor.is_some() => Err(
                DomainError::InvalidPlan("remove cannot carry candidate vendor"),
            ),
            PackageOperation::Install
            | PackageOperation::Upgrade
            | PackageOperation::Downgrade
            | PackageOperation::Reinstall
                if self.provenance.is_some() =>
            {
                Err(DomainError::InvalidPlan(
                    "install/replacement cannot carry side-effect provenance",
                ))
            }
            PackageOperation::Install
            | PackageOperation::Upgrade
            | PackageOperation::Downgrade
            | PackageOperation::Reinstall
            | PackageOperation::Remove => Ok(()),
        }
    }
}

pub fn canonical_actions(
    mut actions: Vec<PackageAction>,
) -> Result<Vec<PackageAction>, DomainError> {
    if actions.len() > MAX_PLAN_ACTIONS {
        return Err(DomainError::InvalidPlan("action limit exceeded"));
    }
    actions.sort();
    let mut identities = HashSet::with_capacity(actions.len());
    for action in &actions {
        action.validate()?;
        let identity = (&action.operation, &action.name, &action.target_evra);
        if !identities.insert(identity) {
            return Err(DomainError::Duplicate(action.name.clone()));
        }
    }
    Ok(actions)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlanEnvelope {
    schema_version: u32,
    install_root: String,
    intent: TransactionIntent,
    policy_sha256: Sha256Digest,
    trust_sha256: Sha256Digest,
    inventory_sha256: Sha256Digest,
    metadata_sha256: Sha256Digest,
    planning_snapshot_sha256: Sha256Digest,
    selected_repositories: Vec<RepositoryBinding>,
    expires_at_unix: u64,
    actions: Vec<PackageAction>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPlanEnvelope {
    schema_version: u32,
    install_root: String,
    intent: TransactionIntent,
    policy_sha256: Sha256Digest,
    trust_sha256: Sha256Digest,
    inventory_sha256: Sha256Digest,
    metadata_sha256: Sha256Digest,
    planning_snapshot_sha256: Sha256Digest,
    selected_repositories: Vec<RepositoryBinding>,
    expires_at_unix: u64,
    actions: Vec<PackageAction>,
}

impl<'de> Deserialize<'de> for PlanEnvelope {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = RawPlanEnvelope::deserialize(deserializer)?;
        let value = Self {
            schema_version: raw.schema_version,
            install_root: raw.install_root,
            intent: raw.intent,
            policy_sha256: raw.policy_sha256,
            trust_sha256: raw.trust_sha256,
            inventory_sha256: raw.inventory_sha256,
            metadata_sha256: raw.metadata_sha256,
            planning_snapshot_sha256: raw.planning_snapshot_sha256,
            selected_repositories: raw.selected_repositories,
            expires_at_unix: raw.expires_at_unix,
            actions: raw.actions,
        };
        value.validate_now(0).map_err(serde::de::Error::custom)?;
        Ok(value)
    }
}

pub type CanonicalPlan = PlanEnvelope;

impl PlanEnvelope {
    pub fn new(
        intent: TransactionIntent,
        integrity: PlanIntegrity,
        expires_at_unix: u64,
        actions: Vec<PackageAction>,
    ) -> Result<Self, DomainError> {
        integrity.validate()?;
        let (
            policy_sha256,
            trust_sha256,
            inventory_sha256,
            metadata_sha256,
            planning_snapshot_sha256,
            selected_repositories,
        ) = integrity.into_parts();
        Ok(Self {
            schema_version: 2,
            install_root: "/".into(),
            intent,
            policy_sha256,
            trust_sha256,
            inventory_sha256,
            metadata_sha256,
            planning_snapshot_sha256,
            selected_repositories,
            expires_at_unix,
            actions: canonical_actions(actions)?,
        })
    }
    pub fn validate_now(&self, now_unix: u64) -> Result<(), DomainError> {
        if self.schema_version != 2 {
            return Err(DomainError::SchemaVersion {
                expected: 2,
                actual: self.schema_version,
            });
        }
        if self.install_root != "/" {
            return Err(DomainError::InvalidPlan("install root must be /"));
        }
        self.integrity().validate()?;
        if now_unix > self.expires_at_unix {
            return Err(DomainError::InvalidPlan("plan expired"));
        }
        if self.actions.len() > MAX_PLAN_ACTIONS
            || self.actions.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(DomainError::NonCanonical);
        }
        for action in &self.actions {
            action.validate()?;
            if let Some(repository) = &action.repo_id {
                if !self
                    .selected_repositories
                    .iter()
                    .any(|binding| binding.id() == repository)
                {
                    return Err(DomainError::InvalidPlan(
                        "action repository is not selected",
                    ));
                }
            }
        }
        Ok(())
    }
    pub const fn requested_action(&self) -> Action {
        self.intent.action()
    }
    pub fn intent(&self) -> &TransactionIntent {
        &self.intent
    }
    pub fn actions(&self) -> &[PackageAction] {
        &self.actions
    }
    pub fn policy_sha256(&self) -> &Sha256Digest {
        &self.policy_sha256
    }
    pub fn trust_sha256(&self) -> &Sha256Digest {
        &self.trust_sha256
    }
    pub fn inventory_sha256(&self) -> &Sha256Digest {
        &self.inventory_sha256
    }
    pub fn metadata_sha256(&self) -> &Sha256Digest {
        &self.metadata_sha256
    }
    pub fn planning_snapshot_sha256(&self) -> &Sha256Digest {
        &self.planning_snapshot_sha256
    }
    pub fn selected_repositories(&self) -> &[RepositoryBinding] {
        &self.selected_repositories
    }
    pub fn integrity(&self) -> PlanIntegrity {
        PlanIntegrity::from_parts(
            self.policy_sha256.clone(),
            self.trust_sha256.clone(),
            self.inventory_sha256.clone(),
            self.metadata_sha256.clone(),
            self.planning_snapshot_sha256.clone(),
            self.selected_repositories.clone(),
        )
    }
    pub const fn expires_at_unix(&self) -> u64 {
        self.expires_at_unix
    }
    pub fn validate_executable(
        &self,
        policy: &crate::SolverPolicy,
        now_unix: u64,
    ) -> Result<(), DomainError> {
        self.validate_now(now_unix)?;
        policy.validate()?;
        let parent_identities = self
            .actions
            .iter()
            .filter_map(PackageAction::action_identity)
            .collect::<HashSet<_>>();
        for action in &self.actions {
            let ordinary = matches!(
                (self.intent.action(), action.operation),
                (
                    Action::Install,
                    PackageOperation::Install | PackageOperation::Upgrade
                ) | (Action::Upgrade, PackageOperation::Upgrade)
                    | (Action::Remove, PackageOperation::Remove)
                    | (Action::Downgrade, PackageOperation::Downgrade)
                    | (Action::Reinstall, PackageOperation::Reinstall)
                    | (
                        Action::DistroSync,
                        PackageOperation::Upgrade
                            | PackageOperation::Downgrade
                            | PackageOperation::Reinstall
                    )
                    | (Action::Autoremove, PackageOperation::Remove)
            );
            let side_effect = matches!((&action.provenance, action.operation),
                (Some(ActionProvenance::ObsoletedBy { parent_action_identity }), PackageOperation::Remove)
                    if self.intent.action() != Action::Remove && parent_identities.contains(parent_action_identity)
                        && matches!(action.reason, PackageReason::Dependency | PackageReason::WeakDependency));
            if !ordinary && !side_effect {
                return Err(DomainError::InvalidPlan(
                    "intent and package operation differ",
                ));
            }
            if ordinary && action.provenance.is_some() {
                return Err(DomainError::InvalidPlan("unexpected action provenance"));
            }
            if self.intent.action() == Action::Autoremove
                && !action.reason.is_autoremove_candidate()
            {
                return Err(DomainError::UnsafeAction(
                    "autoremove requires dependency reason",
                ));
            }
            match action.operation {
                PackageOperation::Remove => policy.validate_removal(&action.name, action.reason)?,
                PackageOperation::Upgrade => {
                    let candidate = crate::CandidateAction::upgrade(
                        action
                            .installed_evra
                            .clone()
                            .ok_or(DomainError::InvalidPlan("missing installed EVRA"))?,
                        action.target_evra.clone(),
                        action
                            .installed_vendor
                            .clone()
                            .ok_or(DomainError::InvalidPlan("missing installed vendor"))?,
                        action
                            .candidate_vendor
                            .clone()
                            .ok_or(DomainError::InvalidPlan("missing candidate vendor"))?,
                    );
                    policy.validate_upgrade(&candidate)?;
                }
                PackageOperation::Downgrade => {
                    let candidate = crate::CandidateAction::downgrade(
                        action
                            .installed_evra
                            .clone()
                            .ok_or(DomainError::InvalidPlan("missing installed EVRA"))?,
                        action.target_evra.clone(),
                        action
                            .installed_vendor
                            .clone()
                            .ok_or(DomainError::InvalidPlan("missing installed vendor"))?,
                        action
                            .candidate_vendor
                            .clone()
                            .ok_or(DomainError::InvalidPlan("missing candidate vendor"))?,
                    );
                    policy.validate_downgrade(&candidate)?;
                }
                PackageOperation::Reinstall => {
                    let candidate = crate::CandidateAction::reinstall(
                        action
                            .installed_evra
                            .clone()
                            .ok_or(DomainError::InvalidPlan("missing installed EVRA"))?,
                        action.target_evra.clone(),
                        action
                            .installed_vendor
                            .clone()
                            .ok_or(DomainError::InvalidPlan("missing installed vendor"))?,
                        action
                            .candidate_vendor
                            .clone()
                            .ok_or(DomainError::InvalidPlan("missing candidate vendor"))?,
                    );
                    policy.validate_reinstall(&candidate)?;
                }
                PackageOperation::Install => {}
            }
        }
        Ok(())
    }
}

impl PlanEnvelope {
    pub fn from_canonical_json_at(bytes: &[u8], now_unix: u64) -> Result<Self, DomainError> {
        let value: Self = canonical::parse(bytes)?;
        value.validate_now(now_unix)?;
        Ok(value)
    }
}

impl CanonicalDocument for PlanEnvelope {
    fn from_canonical_json(bytes: &[u8]) -> Result<Self, DomainError> {
        let value: Self = canonical::parse(bytes)?;
        value.validate_now(0)?;
        Ok(value)
    }
    fn to_canonical_json(&self) -> Result<Vec<u8>, DomainError> {
        self.validate_now(0)?;
        canonical::serialize(self)
    }
}
