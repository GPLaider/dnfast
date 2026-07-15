use std::{collections::BTreeSet, os::fd::OwnedFd, path::Path, sync::Arc};

use rustix::fs::{FlockOperation, flock};

use crate::{
    CallbackSummary, FaultPlan, JournalEntry, LogAppend, NativeResult, ReconcileResult, StateError,
    TransactionId, TransactionState, error::errno, fs, log, model::MAX_RECORD_BYTES,
};

pub struct JournalStore {
    root: OwnedFd,
    faults: Arc<FaultPlan>,
}

impl JournalStore {
    pub fn open_system() -> Result<Self, StateError> {
        if rustix::process::geteuid().as_raw() != 0 {
            return Err(StateError::UnsafePath(
                "system journal requires root".into(),
            ));
        }
        Self::open(Path::new("/var/lib/dnfast/transactions"))
    }

    pub fn open(path: &Path) -> Result<Self, StateError> {
        Self::with_faults(path, Arc::new(FaultPlan::none()))
    }
    pub fn with_faults(path: &Path, faults: Arc<FaultPlan>) -> Result<Self, StateError> {
        Ok(Self {
            root: fs::open_or_create_root(path)?,
            faults,
        })
    }

    pub fn create(
        &self,
        id: &TransactionId,
        plan_sha256: &str,
    ) -> Result<TransactionJournal, StateError> {
        validate_digest(plan_sha256)?;
        let directory = fs::create_transaction(&self.root, id.as_str(), &self.faults)?;
        let journal = TransactionJournal::lock(directory, self.faults.clone())?;
        if let Err(error) = journal.publish(JournalEntry {
            schema_version: 1,
            transaction_id: id.as_str().into(),
            plan_sha256: plan_sha256.into(),
            sequence: 0,
            state: TransactionState::Prepared,
            native_result: None,
            reconciliation: None,
        }) {
            drop(journal);
            fs::remove_failed_transaction(&self.root, id.as_str())?;
            return Err(error);
        }
        Ok(journal)
    }

    pub fn open_transaction(&self, id: &TransactionId) -> Result<TransactionJournal, StateError> {
        TransactionJournal::lock(
            fs::open_transaction(&self.root, id.as_str())?,
            self.faults.clone(),
        )
    }

    pub fn transaction_ids(&self) -> Result<Vec<TransactionId>, StateError> {
        fs::child_names(&self.root)?
            .into_iter()
            .map(|name| TransactionId::parse(&name))
            .collect()
    }
}

pub struct TransactionJournal {
    directory: OwnedFd,
    faults: Arc<FaultPlan>,
}

impl TransactionJournal {
    fn lock(directory: OwnedFd, faults: Arc<FaultPlan>) -> Result<Self, StateError> {
        match flock(&directory, FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => Ok(Self { directory, faults }),
            Err(rustix::io::Errno::WOULDBLOCK) => Err(StateError::Busy),
            Err(error) => Err(errno(error)),
        }
    }

    pub fn entries(&self) -> Result<Vec<JournalEntry>, StateError> {
        load_entries(&self.directory)
    }

    pub fn mark_started(&self) -> Result<(), StateError> {
        self.transition(TransactionState::Started, None, None)
    }

    pub fn record_rpm_result(
        &self,
        return_code: i32,
        callbacks: CallbackSummary,
    ) -> Result<(), StateError> {
        self.record_rpm_result_with_problems(return_code, callbacks, Vec::new())
    }

    pub fn record_rpm_result_with_problems(
        &self,
        return_code: i32,
        callbacks: CallbackSummary,
        problems: Vec<String>,
    ) -> Result<(), StateError> {
        self.transition(
            TransactionState::RpmResult,
            Some(NativeResult {
                return_code,
                callbacks,
                problems,
            }),
            None,
        )
    }

    pub fn rpm_result_encoded_len(
        &self,
        return_code: i32,
        callbacks: CallbackSummary,
        problems: Vec<String>,
    ) -> Result<usize, StateError> {
        let entries = self.entries()?;
        let previous = entries
            .last()
            .ok_or_else(|| StateError::Corrupt("journal is empty".into()))?;
        let entry = JournalEntry {
            schema_version: 1,
            transaction_id: previous.transaction_id.clone(),
            plan_sha256: previous.plan_sha256.clone(),
            sequence: previous.sequence + 1,
            state: TransactionState::RpmResult,
            native_result: Some(NativeResult {
                return_code,
                callbacks,
                problems,
            }),
            reconciliation: None,
        };
        Ok(canonical_bytes(&entry)?.len())
    }

    pub fn reconcile(&self, result: ReconcileResult) -> Result<(), StateError> {
        validate_digest(&result.inventory_sha256)?;
        self.transition(TransactionState::Reconciled, None, Some(result))
    }

    pub fn append_event(&self, bytes: &[u8]) -> Result<LogAppend, StateError> {
        log::append(&self.directory, bytes)
    }

    fn transition(
        &self,
        next: TransactionState,
        native_result: Option<NativeResult>,
        reconciliation: Option<ReconcileResult>,
    ) -> Result<(), StateError> {
        let entries = self.entries()?;
        let previous = entries
            .last()
            .ok_or_else(|| StateError::Corrupt("journal is empty".into()))?;
        let legal = matches!(
            (previous.state, next),
            (TransactionState::Prepared, TransactionState::Started)
                | (TransactionState::Started, TransactionState::RpmResult)
                | (TransactionState::RpmResult, TransactionState::Reconciled)
        );
        if !legal {
            return Err(StateError::Transition(format!(
                "{:?} -> {next:?}",
                previous.state
            )));
        }
        let sequence = previous
            .sequence
            .checked_add(1)
            .ok_or_else(|| StateError::Corrupt("sequence overflow".into()))?;
        self.publish(JournalEntry {
            schema_version: 1,
            transaction_id: previous.transaction_id.clone(),
            plan_sha256: previous.plan_sha256.clone(),
            sequence,
            state: next,
            native_result,
            reconciliation,
        })
    }

    fn publish(&self, entry: JournalEntry) -> Result<(), StateError> {
        validate_entry(&entry)?;
        let bytes = canonical_bytes(&entry)?;
        if bytes.len() as u64 > MAX_RECORD_BYTES {
            return Err(StateError::Limit("record"));
        }
        fs::write_record(&self.directory, entry.sequence, &bytes, &self.faults)
    }
}

fn load_entries(directory: &OwnedFd) -> Result<Vec<JournalEntry>, StateError> {
    let names = fs::child_names(directory)?;
    let mut records = Vec::new();
    let mut sequences = BTreeSet::new();
    for name in names.into_iter().filter(|name| name.ends_with(".json")) {
        let bytes = fs::read_bounded(directory, &name, MAX_RECORD_BYTES)?;
        let entry: JournalEntry = dnfast_core::canonical_decode(&bytes)
            .map_err(|error| StateError::Corrupt(error.to_string()))?;
        let canonical = canonical_bytes(&entry)?;
        if canonical != bytes {
            return Err(StateError::Corrupt("record is not canonical JSON".into()));
        }
        validate_entry(&entry)?;
        if name != format!("{:020}.json", entry.sequence) || !sequences.insert(entry.sequence) {
            return Err(StateError::Corrupt(
                "duplicate or mismatched sequence".into(),
            ));
        }
        records.push(entry);
    }
    records.sort_by_key(|entry| entry.sequence);
    if records.is_empty()
        || records
            .iter()
            .enumerate()
            .any(|(index, entry)| entry.sequence != index as u64)
    {
        return Err(StateError::Corrupt(
            "torn or missing journal sequence".into(),
        ));
    }
    for pair in records.windows(2) {
        validate_pair(&pair[0], &pair[1])?;
    }
    Ok(records)
}

fn canonical_bytes(entry: &JournalEntry) -> Result<Vec<u8>, StateError> {
    dnfast_core::canonical_encode(entry).map_err(|error| StateError::Corrupt(error.to_string()))
}

fn validate_pair(previous: &JournalEntry, next: &JournalEntry) -> Result<(), StateError> {
    let same =
        previous.transaction_id == next.transaction_id && previous.plan_sha256 == next.plan_sha256;
    let transition = matches!(
        (previous.state, next.state),
        (TransactionState::Prepared, TransactionState::Started)
            | (TransactionState::Started, TransactionState::RpmResult)
            | (TransactionState::RpmResult, TransactionState::Reconciled)
    );
    if !same || !transition {
        return Err(StateError::Corrupt("invalid persisted transition".into()));
    }
    Ok(())
}

fn validate_entry(entry: &JournalEntry) -> Result<(), StateError> {
    if entry.schema_version != 1 {
        return Err(StateError::Corrupt("unsupported schema".into()));
    }
    TransactionId::parse(&entry.transaction_id)?;
    validate_digest(&entry.plan_sha256)?;
    let payload = match entry.state {
        TransactionState::Prepared | TransactionState::Started => {
            entry.native_result.is_none() && entry.reconciliation.is_none()
        }
        TransactionState::RpmResult => {
            entry.native_result.is_some() && entry.reconciliation.is_none()
        }
        TransactionState::Reconciled => {
            entry.native_result.is_none() && entry.reconciliation.is_some()
        }
    };
    if !payload {
        return Err(StateError::Corrupt("state payload mismatch".into()));
    }
    if entry.native_result.as_ref().is_some_and(|result| {
        result.problems.len() > 16
            || result
                .problems
                .iter()
                .any(|problem| problem.len() > dnfast_core::MAX_STRING_BYTES)
    }) {
        return Err(StateError::Limit("native problems"));
    }
    Ok(())
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
