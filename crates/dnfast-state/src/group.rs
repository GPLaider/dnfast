use std::{
    collections::{BTreeMap, BTreeSet},
    os::fd::OwnedFd,
    path::{Path, PathBuf},
};

use rustix::fs::{FlockOperation, flock};
use serde::{Deserialize, Serialize};

use crate::{JournalStore, StateError, TransactionState, fs};

const SYSTEM_GROUP_ROOT: &str = "/var/lib/dnfast/groups";
const SYSTEM_JOURNAL_ROOT: &str = "/var/lib/dnfast/transactions";
const STATE_FILE: &str = "state.json";
const MAX_STATE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_GROUPS: usize = 4096;
const MAX_PACKAGES: usize = 65_536;
const MAX_PENDING: usize = 128;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupRecord {
    pub id: String,
    pub owned_packages: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum MutationKind {
    Install,
    Remove,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PendingMutation {
    plan_sha256: String,
    kind: MutationKind,
    groups: BTreeMap<String, Vec<String>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    introduced_packages: Vec<String>,
    seen_transaction_ids: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct GroupState {
    schema_version: u32,
    groups: BTreeMap<String, Vec<String>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    introduced_packages: Vec<String>,
    pending: Vec<PendingMutation>,
}

impl Default for GroupState {
    fn default() -> Self {
        Self {
            schema_version: 2,
            groups: BTreeMap::new(),
            introduced_packages: Vec::new(),
            pending: Vec::new(),
        }
    }
}

pub struct GroupStateStore {
    root: OwnedFd,
    journal_root: PathBuf,
}

struct GroupStateLock<'a>(&'a OwnedFd);

impl<'a> GroupStateLock<'a> {
    fn acquire(root: &'a OwnedFd) -> Result<Self, StateError> {
        flock(root, FlockOperation::LockExclusive).map_err(crate::error::errno)?;
        Ok(Self(root))
    }
}

impl Drop for GroupStateLock<'_> {
    fn drop(&mut self) {
        let _ = flock(self.0, FlockOperation::Unlock);
    }
}

impl GroupStateStore {
    pub fn open_system() -> Result<Self, StateError> {
        if rustix::process::geteuid().as_raw() != 0 {
            return Err(StateError::UnsafePath(
                "system group state requires root".into(),
            ));
        }
        Self::open_with_journal(Path::new(SYSTEM_GROUP_ROOT), Path::new(SYSTEM_JOURNAL_ROOT))
    }

    pub fn open_with_journal(root: &Path, journal_root: &Path) -> Result<Self, StateError> {
        Ok(Self {
            root: fs::open_or_create_root(root)?,
            journal_root: journal_root.to_path_buf(),
        })
    }

    pub fn installed_group_ids(&self) -> Result<Vec<String>, StateError> {
        let _lock = GroupStateLock::acquire(&self.root)?;
        let state = self.reconcile_locked()?;
        Ok(state.groups.into_keys().collect())
    }

    pub fn packages_to_remove(&self, group_ids: &[String]) -> Result<Vec<String>, StateError> {
        validate_ids(group_ids)?;
        let _lock = GroupStateLock::acquire(&self.root)?;
        let state = self.reconcile_locked()?;
        let removing = group_ids.iter().collect::<BTreeSet<_>>();
        let retained = state
            .groups
            .iter()
            .filter(|(id, _)| !removing.contains(id))
            .flat_map(|(_, packages)| packages.iter())
            .collect::<BTreeSet<_>>();
        let mut removable = state
            .groups
            .iter()
            .filter(|(id, _)| removing.contains(id))
            .flat_map(|(_, packages)| packages.iter())
            .filter(|package| {
                !retained.contains(package)
                    && state.introduced_packages.binary_search(package).is_ok()
            })
            .cloned()
            .collect::<Vec<_>>();
        removable.sort();
        removable.dedup();
        Ok(removable)
    }

    pub fn apply_install_now(
        &self,
        records: &[GroupRecord],
        introduced_packages: &[String],
    ) -> Result<(), StateError> {
        validate_sorted_ids(introduced_packages)?;
        let _lock = GroupStateLock::acquire(&self.root)?;
        let mut state = self.reconcile_locked()?;
        apply_install(&mut state, canonical_records(records)?, introduced_packages);
        self.write(&state)
    }

    pub fn apply_remove_now(&self, group_ids: &[String]) -> Result<(), StateError> {
        validate_ids(group_ids)?;
        let _lock = GroupStateLock::acquire(&self.root)?;
        let mut state = self.reconcile_locked()?;
        apply_remove(&mut state, group_ids);
        self.write(&state)
    }

    pub fn record_pending_install(
        &self,
        plan_sha256: &str,
        records: &[GroupRecord],
        introduced_packages: &[String],
    ) -> Result<(), StateError> {
        validate_sorted_ids(introduced_packages)?;
        self.record_pending(
            plan_sha256,
            MutationKind::Install,
            canonical_records(records)?,
            introduced_packages.to_vec(),
        )
    }

    pub fn record_pending_remove(
        &self,
        plan_sha256: &str,
        group_ids: &[String],
    ) -> Result<(), StateError> {
        validate_ids(group_ids)?;
        self.record_pending(
            plan_sha256,
            MutationKind::Remove,
            group_ids
                .iter()
                .map(|id| (id.clone(), Vec::new()))
                .collect(),
            Vec::new(),
        )
    }

    fn record_pending(
        &self,
        plan_sha256: &str,
        kind: MutationKind,
        groups: BTreeMap<String, Vec<String>>,
        introduced_packages: Vec<String>,
    ) -> Result<(), StateError> {
        validate_digest(plan_sha256)?;
        let _lock = GroupStateLock::acquire(&self.root)?;
        let mut state = self.reconcile_locked()?;
        if state.pending.len() >= MAX_PENDING {
            return Err(StateError::Limit("pending group mutations"));
        }
        let journal = JournalStore::open(&self.journal_root)?;
        let seen_transaction_ids = journal
            .transaction_ids()?
            .into_iter()
            .map(|id| id.as_str().to_owned())
            .collect();
        state.pending.push(PendingMutation {
            plan_sha256: plan_sha256.into(),
            kind,
            groups,
            introduced_packages,
            seen_transaction_ids,
        });
        validate_state(&state)?;
        self.write(&state)
    }

    fn reconcile_locked(&self) -> Result<GroupState, StateError> {
        let mut state = self.read()?;
        if state.pending.is_empty() {
            return Ok(state);
        }
        let journal = JournalStore::open(&self.journal_root)?;
        let ids = journal.transaction_ids()?;
        let mut retained = Vec::new();
        let mut changed = false;
        let pending = std::mem::take(&mut state.pending);
        for mutation in pending {
            let seen = mutation
                .seen_transaction_ids
                .iter()
                .map(String::as_str)
                .collect::<BTreeSet<_>>();
            let mut terminal = None;
            for id in ids.iter().filter(|id| !seen.contains(id.as_str())) {
                let entries = journal.open_transaction(id)?.entries()?;
                if entries.first().map(|entry| entry.plan_sha256.as_str())
                    != Some(mutation.plan_sha256.as_str())
                {
                    continue;
                }
                let Some(last) = entries.last() else { continue };
                if last.state != TransactionState::Reconciled {
                    continue;
                }
                let succeeded = entries.iter().any(|entry| {
                    entry.state == TransactionState::RpmResult
                        && entry
                            .native_result
                            .as_ref()
                            .is_some_and(|result| result.return_code == 0)
                }) && last
                    .reconciliation
                    .as_ref()
                    .is_some_and(|result| result.success);
                terminal = Some(succeeded);
                break;
            }
            match terminal {
                Some(true) => {
                    changed = true;
                    match mutation.kind {
                        MutationKind::Install => apply_install(
                            &mut state,
                            mutation.groups,
                            &mutation.introduced_packages,
                        ),
                        MutationKind::Remove => {
                            let ids = mutation.groups.into_keys().collect::<Vec<_>>();
                            apply_remove(&mut state, &ids);
                        }
                    }
                }
                Some(false) => changed = true,
                None => retained.push(mutation),
            }
        }
        state.pending = retained;
        validate_state(&state)?;
        if changed {
            self.write(&state)?;
        }
        Ok(state)
    }

    fn read(&self) -> Result<GroupState, StateError> {
        let Some(bytes) = fs::read_optional_bounded(&self.root, STATE_FILE, MAX_STATE_BYTES)?
        else {
            return Ok(GroupState::default());
        };
        let mut state: GroupState = dnfast_core::canonical_decode(&bytes)
            .map_err(|error| StateError::Corrupt(error.to_string()))?;
        if dnfast_core::canonical_encode(&state)
            .map_err(|error| StateError::Corrupt(error.to_string()))?
            != bytes
        {
            return Err(StateError::Corrupt(
                "group state is not canonical JSON".into(),
            ));
        }
        migrate(&mut state)?;
        validate_state(&state)?;
        Ok(state)
    }

    fn write(&self, state: &GroupState) -> Result<(), StateError> {
        validate_state(state)?;
        let bytes = dnfast_core::canonical_encode(state)
            .map_err(|error| StateError::Corrupt(error.to_string()))?;
        if bytes.len() as u64 > MAX_STATE_BYTES {
            return Err(StateError::Limit("group state"));
        }
        fs::write_atomic_replacing(&self.root, STATE_FILE, &bytes)
    }
}

fn canonical_records(records: &[GroupRecord]) -> Result<BTreeMap<String, Vec<String>>, StateError> {
    let mut result = BTreeMap::new();
    for record in records {
        validate_id(&record.id)?;
        let mut packages = record.owned_packages.clone();
        packages.sort();
        packages.dedup();
        if packages.iter().any(|package| validate_id(package).is_err())
            || result.insert(record.id.clone(), packages).is_some()
        {
            return Err(StateError::Corrupt("invalid group record".into()));
        }
    }
    Ok(result)
}

fn apply_install(
    state: &mut GroupState,
    groups: BTreeMap<String, Vec<String>>,
    introduced_packages: &[String],
) {
    for (id, packages) in groups {
        let owned = state.groups.entry(id).or_default();
        owned.extend(packages);
        owned.sort();
        owned.dedup();
    }
    state
        .introduced_packages
        .extend(introduced_packages.iter().cloned());
    state.introduced_packages.sort();
    state.introduced_packages.dedup();
}

fn apply_remove(state: &mut GroupState, group_ids: &[String]) {
    let removing = group_ids.iter().collect::<BTreeSet<_>>();
    let retained = state
        .groups
        .iter()
        .filter(|(id, _)| !removing.contains(id))
        .flat_map(|(_, packages)| packages.iter())
        .collect::<BTreeSet<_>>();
    let released = state
        .groups
        .iter()
        .filter(|(id, _)| removing.contains(id))
        .flat_map(|(_, packages)| packages.iter())
        .filter(|package| !retained.contains(package))
        .collect::<BTreeSet<_>>();
    state
        .introduced_packages
        .retain(|package| !released.contains(package));
    for id in group_ids {
        state.groups.remove(id);
    }
}

fn migrate(state: &mut GroupState) -> Result<(), StateError> {
    match state.schema_version {
        1 => {
            state.introduced_packages = state
                .groups
                .values()
                .flatten()
                .cloned()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            for mutation in &mut state.pending {
                if mutation.kind == MutationKind::Install {
                    mutation.introduced_packages = mutation
                        .groups
                        .values()
                        .flatten()
                        .cloned()
                        .collect::<BTreeSet<_>>()
                        .into_iter()
                        .collect();
                }
            }
            state.schema_version = 2;
            Ok(())
        }
        2 => Ok(()),
        _ => Err(StateError::Corrupt("unsupported group state schema".into())),
    }
}

fn validate_state(state: &GroupState) -> Result<(), StateError> {
    if state.schema_version != 2
        || state.groups.len() > MAX_GROUPS
        || state.pending.len() > MAX_PENDING
    {
        return Err(StateError::Corrupt("invalid group state bounds".into()));
    }
    let package_count = state.groups.values().map(Vec::len).sum::<usize>()
        + state.introduced_packages.len()
        + state
            .pending
            .iter()
            .flat_map(|mutation| mutation.groups.values())
            .map(Vec::len)
            .sum::<usize>()
        + state
            .pending
            .iter()
            .map(|mutation| mutation.introduced_packages.len())
            .sum::<usize>();
    if package_count > MAX_PACKAGES {
        return Err(StateError::Limit("group packages"));
    }
    for (id, packages) in &state.groups {
        validate_id(id)?;
        validate_sorted_ids(packages)?;
    }
    validate_sorted_ids(&state.introduced_packages)?;
    let group_packages = state.groups.values().flatten().collect::<BTreeSet<_>>();
    if state
        .introduced_packages
        .iter()
        .any(|package| !group_packages.contains(package))
    {
        return Err(StateError::Corrupt(
            "introduced package has no installed group owner".into(),
        ));
    }
    for mutation in &state.pending {
        validate_digest(&mutation.plan_sha256)?;
        if mutation.groups.is_empty() {
            return Err(StateError::Corrupt("empty pending group mutation".into()));
        }
        for (id, packages) in &mutation.groups {
            validate_id(id)?;
            validate_sorted_ids(packages)?;
        }
        validate_sorted_ids(&mutation.introduced_packages)?;
        let mutation_packages = mutation.groups.values().flatten().collect::<BTreeSet<_>>();
        if (mutation.kind == MutationKind::Remove && !mutation.introduced_packages.is_empty())
            || mutation
                .introduced_packages
                .iter()
                .any(|package| !mutation_packages.contains(package))
        {
            return Err(StateError::Corrupt(
                "invalid introduced packages in pending group mutation".into(),
            ));
        }
        if mutation
            .seen_transaction_ids
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        {
            return Err(StateError::Corrupt(
                "noncanonical pending transaction ids".into(),
            ));
        }
    }
    Ok(())
}

fn validate_ids(values: &[String]) -> Result<(), StateError> {
    validate_sorted_ids(values)
}

fn validate_sorted_ids(values: &[String]) -> Result<(), StateError> {
    if values.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(StateError::Corrupt("identifiers are not canonical".into()));
    }
    for value in values {
        validate_id(value)?;
    }
    Ok(())
}

fn validate_id(value: &str) -> Result<(), StateError> {
    if value.is_empty()
        || value.len() > 4096
        || value
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || b"+._-".contains(&byte)))
    {
        Err(StateError::Corrupt(
            "invalid group or package identifier".into(),
        ))
    } else {
        Ok(())
    }
}

fn validate_digest(value: &str) -> Result<(), StateError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        Ok(())
    } else {
        Err(StateError::Corrupt("invalid SHA-256".into()))
    }
}
