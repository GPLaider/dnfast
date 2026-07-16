use dnfast_state::{JournalEntry, JournalStore, TransactionId, TransactionState};

use super::AppFailure;

pub(super) fn list(limit: u16) -> Result<String, AppFailure> {
    require_root()?;
    let store = JournalStore::open_system().map_err(state_failure)?;
    list_from(&store, usize::from(limit))
}

pub(super) fn info(transaction_id: &str) -> Result<String, AppFailure> {
    let id = TransactionId::parse(transaction_id)
        .map_err(|_| AppFailure::new(2, "transaction id must be a canonical UUIDv7"))?;
    require_root()?;
    let store = JournalStore::open_system().map_err(state_failure)?;
    info_from(&store, &id)
}

fn list_from(store: &JournalStore, limit: usize) -> Result<String, AppFailure> {
    let mut ids = store.transaction_ids().map_err(state_failure)?;
    ids.sort_by(|left, right| right.as_str().cmp(left.as_str()));
    let mut rows = Vec::new();
    for id in ids.into_iter().take(limit) {
        let journal = store.open_transaction(&id).map_err(state_failure)?;
        let entries = journal.entries().map_err(state_failure)?;
        let last = entries
            .last()
            .ok_or_else(|| AppFailure::new(1, "transaction journal is empty"))?;
        rows.push(summary(last));
    }
    if rows.is_empty() {
        Ok("history transactions: none".into())
    } else {
        Ok(format!("history transactions: {}", rows.join("; ")))
    }
}

fn info_from(store: &JournalStore, id: &TransactionId) -> Result<String, AppFailure> {
    let journal = store.open_transaction(id).map_err(state_failure)?;
    let entries = journal.entries().map_err(state_failure)?;
    let plan = entries
        .first()
        .ok_or_else(|| AppFailure::new(1, "transaction journal is empty"))?
        .plan_sha256
        .clone();
    let sequence = entries
        .iter()
        .map(entry_detail)
        .collect::<Vec<_>>()
        .join("; ");
    Ok(format!(
        "transaction={} plan_sha256={plan}; {sequence}",
        id.as_str()
    ))
}

fn summary(entry: &JournalEntry) -> String {
    let mut result = format!(
        "id={} state={} sequence={} plan_sha256={}",
        entry.transaction_id,
        state_name(entry.state),
        entry.sequence,
        entry.plan_sha256
    );
    if let Some(reconciliation) = &entry.reconciliation {
        result.push_str(&format!(
            " success={} changed_packages={}",
            reconciliation.success, reconciliation.changed_packages
        ));
    }
    result
}

fn entry_detail(entry: &JournalEntry) -> String {
    let mut result = format!(
        "sequence={} state={}",
        entry.sequence,
        state_name(entry.state)
    );
    if let Some(native) = &entry.native_result {
        result.push_str(&format!(
            " return_code={} problems={}",
            native.return_code,
            native.problems.len()
        ));
    }
    if let Some(reconciliation) = &entry.reconciliation {
        result.push_str(&format!(
            " success={} changed_packages={} inventory_sha256={}",
            reconciliation.success,
            reconciliation.changed_packages,
            reconciliation.inventory_sha256
        ));
    }
    result
}

const fn state_name(state: TransactionState) -> &'static str {
    match state {
        TransactionState::Prepared => "prepared",
        TransactionState::Started => "started",
        TransactionState::RpmResult => "rpm_result",
        TransactionState::Reconciled => "reconciled",
    }
}

fn require_root() -> Result<(), AppFailure> {
    if rustix::process::geteuid().as_raw() == 0 {
        Ok(())
    } else {
        Err(AppFailure::new(1, "history requires root"))
    }
}

fn state_failure(error: dnfast_state::StateError) -> AppFailure {
    AppFailure::new(1, error.to_string())
}

#[cfg(test)]
mod tests {
    use dnfast_state::{CallbackSummary, JournalStore, ReconcileResult, TransactionId};

    use super::{info_from, list_from};

    #[test]
    fn history_lists_and_explains_the_verified_journal_sequence() {
        let temporary = tempfile::tempdir().expect("temporary journal");
        let store = JournalStore::open(&temporary.path().join("transactions")).expect("store");
        let id = TransactionId::parse("018f1f2e-7b3c-7abc-8def-0123456789ab").expect("UUIDv7");
        let journal = store.create(&id, &"a".repeat(64)).expect("create journal");
        journal.mark_started().expect("started");
        journal
            .record_rpm_result(
                0,
                CallbackSummary {
                    pretrans: 0,
                    pre: 1,
                    post: 1,
                    triggers: 0,
                    payload: 1,
                    database: 1,
                    script_log_truncated: false,
                },
            )
            .expect("RPM result");
        journal
            .reconcile(ReconcileResult {
                inventory_sha256: "b".repeat(64),
                success: true,
                changed_packages: 1,
            })
            .expect("reconcile");
        drop(journal);

        let listed = list_from(&store, 20).expect("history list");
        assert!(listed.contains("state=reconciled sequence=3"));
        assert!(listed.contains("success=true changed_packages=1"));
        let detail = info_from(&store, &id).expect("history info");
        assert!(detail.contains("sequence=2 state=rpm_result return_code=0 problems=0"));
        assert!(detail.contains("sequence=3 state=reconciled success=true changed_packages=1"));
    }
}
