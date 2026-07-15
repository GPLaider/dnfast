use std::path::Path;

use crate::{
    CallbackSummary, RecoveryAction, StateError, TransactionId, TransactionJournal,
    TransactionState, fs,
};

pub fn recover(journal: &TransactionJournal) -> Result<RecoveryAction, StateError> {
    let entries = journal.entries()?;
    let final_entry = entries
        .last()
        .ok_or_else(|| StateError::Corrupt("journal is empty".into()))?;
    match final_entry.state {
        TransactionState::Prepared => Ok(RecoveryAction::CleanupRevalidateAndReapprove),
        TransactionState::Started => {
            journal.record_rpm_result(
                -1,
                CallbackSummary {
                    pretrans: 0,
                    pre: 0,
                    post: 0,
                    triggers: 0,
                    payload: 0,
                    database: 0,
                    script_log_truncated: false,
                },
            )?;
            Ok(RecoveryAction::ReconcileOnly)
        }
        TransactionState::RpmResult => Ok(RecoveryAction::ReconcileOnly),
        TransactionState::Reconciled => final_entry
            .reconciliation
            .clone()
            .map(RecoveryAction::Terminal)
            .ok_or_else(|| StateError::Corrupt("terminal result missing".into())),
    }
}

pub fn recover_with_staging(
    journal: &TransactionJournal,
    staging_root: &Path,
    id: &TransactionId,
) -> Result<RecoveryAction, StateError> {
    let action = recover(journal)?;
    if action == RecoveryAction::CleanupRevalidateAndReapprove {
        match fs::cleanup_private_child(staging_root, id.as_str()) {
            Ok(()) => {}
            Err(StateError::Io(message)) if message.contains("No such file") => {}
            Err(error) => return Err(error),
        }
    }
    Ok(action)
}
