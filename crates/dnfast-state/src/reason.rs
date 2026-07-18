use std::{
    collections::{BTreeMap, BTreeSet},
    os::fd::OwnedFd,
    path::Path,
};

use dnfast_core::{CanonicalPlan, Evra, InstalledInventory, PackageOperation, PackageReason};
use rustix::fs::{FlockOperation, flock};
use serde::{Deserialize, Serialize};

use crate::{StateError, fs};

const SYSTEM_REASON_ROOT: &str = "/var/lib/dnfast/reasons";
const STATE_FILE: &str = "state.json";
const MAX_STATE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_RECORDS: usize = 200_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReasonDecision {
    Record(PackageReason),
    Keep(PackageReason),
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct InstalledIdentity {
    pub db_instance: u64,
    pub header_sha256: String,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PlannedIdentity {
    pub package_name: String,
    pub target_evra: Evra,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReconciledReason {
    pub identity: InstalledIdentity,
    pub package_name: String,
    pub decision: ReasonDecision,
}

pub fn proposals_from_plan(plan: &CanonicalPlan) -> BTreeMap<PlannedIdentity, PackageReason> {
    plan.actions()
        .iter()
        .filter(|action| action.operation() != PackageOperation::Remove)
        .map(|action| {
            (
                PlannedIdentity {
                    package_name: action.name().into(),
                    target_evra: action.target_evra().clone(),
                },
                action.reason(),
            )
        })
        .collect()
}

pub fn reconcile_reasons(
    before: &InstalledInventory,
    after: &InstalledInventory,
    proposed: &BTreeMap<PlannedIdentity, PackageReason>,
    protected: &BTreeSet<String>,
    installonly: &BTreeSet<String>,
) -> Vec<ReconciledReason> {
    let before_ids = before
        .packages()
        .iter()
        .map(|package| {
            (
                package.db_instance(),
                package.immutable_header_sha256().as_str(),
            )
        })
        .collect::<BTreeSet<_>>();
    let mut remaining = proposed.clone();
    after
        .packages()
        .iter()
        .map(|package| {
            let name = package.name();
            let key = PlannedIdentity {
                package_name: name.into(),
                target_evra: package.evra().clone(),
            };
            let is_new = !before_ids.contains(&(
                package.db_instance(),
                package.immutable_header_sha256().as_str(),
            ));
            let decision = if protected.contains(name) || installonly.contains(name) {
                ReasonDecision::Keep(PackageReason::User)
            } else if let Some(reason) = if is_new { remaining.remove(&key) } else { None } {
                match reason {
                    PackageReason::External | PackageReason::Unknown => {
                        ReasonDecision::Keep(reason)
                    }
                    PackageReason::User
                    | PackageReason::Dependency
                    | PackageReason::WeakDependency => ReasonDecision::Record(reason),
                }
            } else {
                ReasonDecision::Keep(PackageReason::External)
            };
            ReconciledReason {
                identity: InstalledIdentity {
                    db_instance: package.db_instance(),
                    header_sha256: package.immutable_header_sha256().as_str().into(),
                },
                package_name: name.into(),
                decision,
            }
        })
        .collect()
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
struct ReasonRecord {
    db_instance: u64,
    header_sha256: String,
    package_name: String,
    reason: PackageReason,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ReasonState {
    schema_version: u32,
    records: Vec<ReasonRecord>,
}

impl Default for ReasonState {
    fn default() -> Self {
        Self {
            schema_version: 1,
            records: Vec::new(),
        }
    }
}

pub struct ReasonStateStore {
    root: OwnedFd,
}

struct ReasonStateLock<'a>(&'a OwnedFd);

impl<'a> ReasonStateLock<'a> {
    fn acquire(root: &'a OwnedFd) -> Result<Self, StateError> {
        flock(root, FlockOperation::LockExclusive).map_err(crate::error::errno)?;
        Ok(Self(root))
    }
}

impl Drop for ReasonStateLock<'_> {
    fn drop(&mut self) {
        let _ = flock(self.0, FlockOperation::Unlock);
    }
}

impl ReasonStateStore {
    pub fn open_system() -> Result<Self, StateError> {
        if rustix::process::geteuid().as_raw() != 0 {
            return Err(StateError::UnsafePath(
                "system package reason state requires root".into(),
            ));
        }
        Self::open(Path::new(SYSTEM_REASON_ROOT))
    }

    pub fn open(root: &Path) -> Result<Self, StateError> {
        Ok(Self {
            root: fs::open_or_create_root(root)?,
        })
    }

    pub fn record_success(
        &self,
        before: &InstalledInventory,
        after: &InstalledInventory,
        plan: &CanonicalPlan,
        policy: &dnfast_core::SolverPolicy,
    ) -> Result<(), StateError> {
        let _lock = ReasonStateLock::acquire(&self.root)?;
        let state = self.read()?;
        let existing = state
            .records
            .into_iter()
            .map(|record| ((record.db_instance, record.header_sha256.clone()), record))
            .collect::<BTreeMap<_, _>>();
        let protected = after
            .packages()
            .iter()
            .filter(|package| policy.is_protected(package.name()))
            .map(|package| package.name().to_owned())
            .collect::<BTreeSet<_>>();
        let installonly = after
            .packages()
            .iter()
            .filter(|package| {
                policy.is_installonly(package.name()) || policy.is_running_kernel(package.name())
            })
            .map(|package| package.name().to_owned())
            .collect::<BTreeSet<_>>();
        let proposed = proposals_from_plan(plan);
        let reconciled = reconcile_reasons(before, after, &proposed, &protected, &installonly);
        let replacement_reasons = plan
            .actions()
            .iter()
            .filter(|action| action.operation() != PackageOperation::Install)
            .filter_map(|action| {
                let instance = action.installed_instance()?;
                let header = action.installed_header_sha256()?.as_str();
                let previous = existing.get(&(instance, header.to_owned()))?;
                Some((
                    PlannedIdentity {
                        package_name: action.name().to_owned(),
                        target_evra: action.target_evra().clone(),
                    },
                    previous.reason,
                ))
            })
            .collect::<BTreeMap<_, _>>();
        let after_by_identity = after
            .packages()
            .iter()
            .map(|package| {
                (
                    (
                        package.db_instance(),
                        package.immutable_header_sha256().as_str(),
                    ),
                    package,
                )
            })
            .collect::<BTreeMap<_, _>>();
        let mut records = Vec::with_capacity(reconciled.len());
        for item in reconciled {
            let package = after_by_identity
                .get(&(
                    item.identity.db_instance,
                    item.identity.header_sha256.as_str(),
                ))
                .ok_or_else(|| StateError::Corrupt("reconciled package disappeared".into()))?;
            let exact = (
                item.identity.db_instance,
                item.identity.header_sha256.clone(),
            );
            let target = PlannedIdentity {
                package_name: item.package_name.clone(),
                target_evra: package.evra().clone(),
            };
            let reason = if policy.is_protected(&item.package_name)
                || policy.is_installonly(&item.package_name)
                || policy.is_running_kernel(&item.package_name)
            {
                PackageReason::User
            } else if let Some(reason) = replacement_reasons.get(&target) {
                *reason
            } else if let Some(record) = existing.get(&exact) {
                record.reason
            } else {
                match item.decision {
                    ReasonDecision::Record(reason) | ReasonDecision::Keep(reason) => reason,
                }
            };
            records.push(ReasonRecord {
                db_instance: item.identity.db_instance,
                header_sha256: item.identity.header_sha256,
                package_name: item.package_name,
                reason,
            });
        }
        records.sort();
        self.write(&ReasonState {
            schema_version: 1,
            records,
        })
    }

    pub fn autoremove_candidates(
        &self,
        inventory: &InstalledInventory,
        policy: &dnfast_core::SolverPolicy,
    ) -> Result<Vec<String>, StateError> {
        let _lock = ReasonStateLock::acquire(&self.root)?;
        let state = self.read()?;
        let installed = inventory
            .packages()
            .iter()
            .map(|package| {
                (
                    (
                        package.db_instance(),
                        package.immutable_header_sha256().as_str(),
                    ),
                    package,
                )
            })
            .collect::<BTreeMap<_, _>>();
        let mut names = Vec::new();
        for record in state.records {
            let Some(package) = installed.get(&(record.db_instance, record.header_sha256.as_str()))
            else {
                continue;
            };
            if package.name() != record.package_name
                || !record.reason.is_autoremove_candidate()
                || policy.is_protected(package.name())
                || policy.is_installonly(package.name())
                || policy.is_running_kernel(package.name())
            {
                continue;
            }
            names.push(record.package_name);
        }
        names.sort();
        if names.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(StateError::Corrupt(
                "autoremove package name has multiple installed identities".into(),
            ));
        }
        Ok(names)
    }

    fn read(&self) -> Result<ReasonState, StateError> {
        let Some(bytes) = fs::read_optional_bounded(&self.root, STATE_FILE, MAX_STATE_BYTES)?
        else {
            return Ok(ReasonState::default());
        };
        let state: ReasonState = dnfast_core::canonical_decode(&bytes)
            .map_err(|error| StateError::Corrupt(error.to_string()))?;
        if dnfast_core::canonical_encode(&state)
            .map_err(|error| StateError::Corrupt(error.to_string()))?
            != bytes
        {
            return Err(StateError::Corrupt(
                "package reason state is not canonical JSON".into(),
            ));
        }
        validate_state(&state)?;
        Ok(state)
    }

    fn write(&self, state: &ReasonState) -> Result<(), StateError> {
        validate_state(state)?;
        let bytes = dnfast_core::canonical_encode(state)
            .map_err(|error| StateError::Corrupt(error.to_string()))?;
        if bytes.len() as u64 > MAX_STATE_BYTES {
            return Err(StateError::Limit("package reason state"));
        }
        fs::write_atomic_replacing(&self.root, STATE_FILE, &bytes)
    }
}

fn validate_state(state: &ReasonState) -> Result<(), StateError> {
    if state.schema_version != 1 || state.records.len() > MAX_RECORDS {
        return Err(StateError::Corrupt(
            "invalid package reason state bounds".into(),
        ));
    }
    if state.records.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(StateError::Corrupt(
            "package reason records are not canonical".into(),
        ));
    }
    let mut identities = BTreeSet::new();
    for record in &state.records {
        if record.db_instance == 0
            || record.header_sha256.len() != 64
            || !record
                .header_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            || record.package_name.is_empty()
            || record.package_name.len() > 4096
            || record
                .package_name
                .bytes()
                .any(|byte| !(byte.is_ascii_alphanumeric() || b"+._-".contains(&byte)))
            || !identities.insert((record.db_instance, record.header_sha256.as_str()))
        {
            return Err(StateError::Corrupt("invalid package reason record".into()));
        }
    }
    Ok(())
}
