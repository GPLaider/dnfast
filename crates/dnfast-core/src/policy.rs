use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{Architecture, CanonicalDocument, DomainError, Evra, canonical};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PackageReason {
    User,
    Dependency,
    WeakDependency,
    External,
    #[serde(other)]
    Unknown,
}

impl PackageReason {
    pub const fn is_autoremove_candidate(self) -> bool {
        matches!(self, Self::Dependency | Self::WeakDependency)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CandidateAction {
    Replace {
        operation: ReplacementOperation,
        installed: Evra,
        candidate: Evra,
        installed_vendor: String,
        candidate_vendor: String,
    },
    Deferred(&'static str),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplacementOperation {
    Upgrade,
    Downgrade,
    Reinstall,
}

impl CandidateAction {
    pub fn upgrade(
        installed: Evra,
        candidate: Evra,
        installed_vendor: impl Into<String>,
        candidate_vendor: impl Into<String>,
    ) -> Self {
        Self::Replace {
            operation: ReplacementOperation::Upgrade,
            installed,
            candidate,
            installed_vendor: installed_vendor.into(),
            candidate_vendor: candidate_vendor.into(),
        }
    }
    pub fn downgrade(
        installed: Evra,
        candidate: Evra,
        installed_vendor: impl Into<String>,
        candidate_vendor: impl Into<String>,
    ) -> Self {
        Self::Replace {
            operation: ReplacementOperation::Downgrade,
            installed,
            candidate,
            installed_vendor: installed_vendor.into(),
            candidate_vendor: candidate_vendor.into(),
        }
    }
    pub fn reinstall(
        installed: Evra,
        candidate: Evra,
        installed_vendor: impl Into<String>,
        candidate_vendor: impl Into<String>,
    ) -> Self {
        Self::Replace {
            operation: ReplacementOperation::Reinstall,
            installed,
            candidate,
            installed_vendor: installed_vendor.into(),
            candidate_vendor: candidate_vendor.into(),
        }
    }
    pub const fn distro_sync() -> Self {
        Self::Deferred("distro-sync")
    }
    pub const fn vendor_switch() -> Self {
        Self::Deferred("vendor switch")
    }
    pub const fn arch_switch() -> Self {
        Self::Deferred("architecture switch")
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepoPreference {
    priority: u32,
    cost: u32,
    repo_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRepoPreference {
    priority: u32,
    cost: u32,
    repo_id: String,
}

impl<'de> Deserialize<'de> for RepoPreference {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = RawRepoPreference::deserialize(deserializer)?;
        Self::new(raw.repo_id, raw.priority, raw.cost).map_err(serde::de::Error::custom)
    }
}

impl RepoPreference {
    pub fn new(repo_id: impl Into<String>, priority: u32, cost: u32) -> Result<Self, DomainError> {
        let repo_id = repo_id.into();
        if repo_id.is_empty() {
            return Err(DomainError::Empty { field: "repo_id" });
        }
        Ok(Self {
            priority,
            cost,
            repo_id,
        })
    }
    pub fn repo_id(&self) -> &str {
        &self.repo_id
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SolverPolicy {
    schema_version: u32,
    install_weak_deps: bool,
    best: bool,
    base_arch: Architecture,
    allowed_arches: BTreeSet<Architecture>,
    allow_multilib: bool,
    allow_vendor_change: bool,
    upgrade_only: bool,
    repo_preferences: Vec<RepoPreference>,
    protected_packages: BTreeSet<String>,
    installonly_packages: BTreeSet<String>,
    running_kernel_name: Option<String>,
    excludes: BTreeSet<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSolverPolicy {
    schema_version: u32,
    install_weak_deps: bool,
    best: bool,
    base_arch: Architecture,
    allowed_arches: Vec<Architecture>,
    allow_multilib: bool,
    allow_vendor_change: bool,
    upgrade_only: bool,
    repo_preferences: Vec<RepoPreference>,
    protected_packages: Vec<String>,
    installonly_packages: Vec<String>,
    running_kernel_name: Option<String>,
    excludes: Vec<String>,
}

impl<'de> Deserialize<'de> for SolverPolicy {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = RawSolverPolicy::deserialize(deserializer)?;
        let allowed_arches = raw.allowed_arches.iter().copied().collect::<BTreeSet<_>>();
        let protected_packages = raw
            .protected_packages
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        let installonly_packages = raw
            .installonly_packages
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        let excludes = raw.excludes.iter().cloned().collect::<BTreeSet<_>>();
        if allowed_arches.len() != raw.allowed_arches.len()
            || protected_packages.len() != raw.protected_packages.len()
            || installonly_packages.len() != raw.installonly_packages.len()
            || excludes.len() != raw.excludes.len()
        {
            return Err(serde::de::Error::custom("duplicate solver policy entry"));
        }
        let value = Self {
            schema_version: raw.schema_version,
            install_weak_deps: raw.install_weak_deps,
            best: raw.best,
            base_arch: raw.base_arch,
            allowed_arches,
            allow_multilib: raw.allow_multilib,
            allow_vendor_change: raw.allow_vendor_change,
            upgrade_only: raw.upgrade_only,
            repo_preferences: raw.repo_preferences,
            protected_packages,
            installonly_packages,
            running_kernel_name: raw.running_kernel_name,
            excludes,
        };
        value.validate().map_err(serde::de::Error::custom)?;
        Ok(value)
    }
}

impl SolverPolicy {
    pub fn fedora44_aarch64(protected: Vec<String>, installonly: Vec<String>) -> Self {
        Self::fedora44(Architecture::Aarch64, protected, installonly)
    }
    pub fn fedora44_x86_64(protected: Vec<String>, installonly: Vec<String>) -> Self {
        Self::fedora44(Architecture::X86_64, protected, installonly)
    }
    fn fedora44(base_arch: Architecture, protected: Vec<String>, installonly: Vec<String>) -> Self {
        Self {
            schema_version: 1,
            install_weak_deps: true,
            best: false,
            base_arch,
            allowed_arches: [base_arch, Architecture::Noarch].into(),
            allow_multilib: false,
            allow_vendor_change: false,
            upgrade_only: true,
            repo_preferences: Vec::new(),
            protected_packages: protected.into_iter().collect(),
            installonly_packages: installonly.into_iter().collect(),
            running_kernel_name: None,
            excludes: BTreeSet::new(),
        }
    }
    pub fn with_repositories(mut self, mut repositories: Vec<RepoPreference>) -> Self {
        repositories.sort();
        self.repo_preferences = repositories;
        self
    }
    pub fn with_excludes(mut self, excludes: impl IntoIterator<Item = String>) -> Self {
        self.excludes = excludes.into_iter().collect();
        self
    }
    pub fn with_running_kernel_name(mut self, package_name: impl Into<String>) -> Self {
        self.running_kernel_name = Some(package_name.into());
        self
    }
    pub const fn validate_action(&self, action: &CandidateAction) -> Result<(), DomainError> {
        match action {
            CandidateAction::Replace { .. } => Ok(()),
            CandidateAction::Deferred(name) => Err(DomainError::UnsafeAction(name)),
        }
    }
    pub fn ensure_supported(&self) -> Result<(), DomainError> {
        self.validate()
    }
    pub const fn install_weak_deps(&self) -> bool {
        self.install_weak_deps
    }
    pub const fn best(&self) -> bool {
        self.best
    }
    pub const fn base_arch(&self) -> Architecture {
        self.base_arch
    }
    pub fn is_excluded(&self, name: &str) -> bool {
        self.excludes.contains(name)
    }
    pub fn is_protected(&self, name: &str) -> bool {
        self.protected_packages.contains(name)
    }
    pub fn is_installonly(&self, name: &str) -> bool {
        self.installonly_packages.contains(name)
    }
    pub fn is_running_kernel(&self, name: &str) -> bool {
        self.running_kernel_name.as_deref() == Some(name)
    }
    pub fn validate_planned_removal(
        &self,
        name: &str,
        reason: PackageReason,
    ) -> Result<(), DomainError> {
        self.validate_removal(name, reason)
    }
    pub fn validate_planned_upgrade(
        &self,
        installed: &Evra,
        candidate: &Evra,
        installed_vendor: &str,
        candidate_vendor: &str,
    ) -> Result<(), DomainError> {
        self.validate_upgrade(&CandidateAction::upgrade(
            installed.clone(),
            candidate.clone(),
            installed_vendor,
            candidate_vendor,
        ))
    }
    pub fn validate_upgrade(&self, action: &CandidateAction) -> Result<(), DomainError> {
        let CandidateAction::Replace {
            operation: ReplacementOperation::Upgrade,
            installed,
            candidate,
            installed_vendor,
            candidate_vendor,
        } = action
        else {
            return self.validate_action(action);
        };
        installed.validate()?;
        candidate.validate()?;
        if installed.arch() != candidate.arch() {
            return Err(DomainError::UnsafeAction("architecture switch"));
        }
        if installed_vendor != candidate_vendor {
            return Err(DomainError::UnsafeAction("vendor switch"));
        }
        if !candidate.is_strictly_newer_than(installed) {
            return Err(DomainError::UnsafeAction("candidate is not newer"));
        }
        Ok(())
    }
    pub fn validate_downgrade(&self, action: &CandidateAction) -> Result<(), DomainError> {
        let CandidateAction::Replace {
            operation: ReplacementOperation::Downgrade,
            installed,
            candidate,
            installed_vendor,
            candidate_vendor,
        } = action
        else {
            return self.validate_action(action);
        };
        self.validate_replacement_identity(
            installed,
            candidate,
            installed_vendor,
            candidate_vendor,
        )?;
        if !installed.is_strictly_newer_than(candidate) {
            return Err(DomainError::UnsafeAction("candidate is not older"));
        }
        Ok(())
    }
    pub fn validate_reinstall(&self, action: &CandidateAction) -> Result<(), DomainError> {
        let CandidateAction::Replace {
            operation: ReplacementOperation::Reinstall,
            installed,
            candidate,
            installed_vendor,
            candidate_vendor,
        } = action
        else {
            return self.validate_action(action);
        };
        self.validate_replacement_identity(
            installed,
            candidate,
            installed_vendor,
            candidate_vendor,
        )?;
        if installed != candidate {
            return Err(DomainError::UnsafeAction("reinstall candidate differs"));
        }
        Ok(())
    }
    fn validate_replacement_identity(
        &self,
        installed: &Evra,
        candidate: &Evra,
        installed_vendor: &str,
        candidate_vendor: &str,
    ) -> Result<(), DomainError> {
        installed.validate()?;
        candidate.validate()?;
        if installed.arch() != candidate.arch() {
            return Err(DomainError::UnsafeAction("architecture switch"));
        }
        if installed_vendor != candidate_vendor {
            return Err(DomainError::UnsafeAction("vendor switch"));
        }
        Ok(())
    }
    pub fn validate_removal(&self, name: &str, reason: PackageReason) -> Result<(), DomainError> {
        if self.protected_packages.contains(name) {
            return Err(DomainError::UnsafeAction("protected package removal"));
        }
        if self.installonly_packages.contains(name) {
            return Err(DomainError::UnsafeAction("installonly package removal"));
        }
        if self.running_kernel_name.as_deref() == Some(name) {
            return Err(DomainError::UnsafeAction("running kernel removal"));
        }
        match reason {
            PackageReason::User | PackageReason::Dependency | PackageReason::WeakDependency => {
                Ok(())
            }
            PackageReason::External | PackageReason::Unknown => {
                Err(DomainError::UnsafeAction("package reason requires keep"))
            }
        }
    }
    pub(crate) fn validate(&self) -> Result<(), DomainError> {
        if self.schema_version != 1 {
            return Err(DomainError::SchemaVersion {
                expected: 1,
                actual: self.schema_version,
            });
        }
        let expected_arches = match self.base_arch {
            Architecture::Aarch64 => [Architecture::Aarch64, Architecture::Noarch].into(),
            Architecture::X86_64 => [Architecture::X86_64, Architecture::Noarch].into(),
            Architecture::Noarch => return Err(DomainError::Architecture),
        };
        if self.allowed_arches != expected_arches {
            return Err(DomainError::Architecture);
        }
        if !self.install_weak_deps
            || self.best
            || self.allow_multilib
            || self.allow_vendor_change
            || !self.upgrade_only
        {
            return Err(DomainError::UnsafeAction("unsafe solver policy"));
        }
        if self
            .repo_preferences
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        {
            return Err(DomainError::NonCanonical);
        }
        if self
            .repo_preferences
            .iter()
            .any(|repo| repo.repo_id.is_empty())
        {
            return Err(DomainError::Empty { field: "repo_id" });
        }
        if self
            .protected_packages
            .iter()
            .chain(&self.installonly_packages)
            .chain(&self.excludes)
            .any(String::is_empty)
            || self
                .running_kernel_name
                .as_ref()
                .is_some_and(String::is_empty)
        {
            return Err(DomainError::Empty {
                field: "solver package name",
            });
        }
        Ok(())
    }
}

impl CanonicalDocument for SolverPolicy {
    fn from_canonical_json(bytes: &[u8]) -> Result<Self, DomainError> {
        let value: Self = canonical::parse(bytes)?;
        value.validate()?;
        Ok(value)
    }
    fn to_canonical_json(&self) -> Result<Vec<u8>, DomainError> {
        self.validate()?;
        canonical::serialize(self)
    }
}
