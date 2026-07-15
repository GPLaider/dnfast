use std::path::Path;

use dnfast_core::CanonicalDocument;
use dnfast_state::{JournalStore, ReconcileResult, RecoveryAction, recover_with_staging};
use sha2::Digest;

use crate::ExecutorError;

const STAGING_ROOT: &str = "/var/lib/dnfast/staging";

pub fn recover_pending_transactions(
    store: &JournalStore,
    architecture: dnfast_core::Architecture,
) -> Result<(), ExecutorError> {
    for id in store.transaction_ids().map_err(state)? {
        let journal = store.open_transaction(&id).map_err(state)?;
        match recover_with_staging(&journal, Path::new(STAGING_ROOT), &id).map_err(state)? {
            RecoveryAction::CleanupRevalidateAndReapprove | RecoveryAction::Terminal(_) => {}
            RecoveryAction::ReconcileOnly => {
                let mut reader =
                    dnfast_native::InventoryReader::open(architecture).map_err(inventory)?;
                let current = reader.read().map_err(inventory)?;
                let bytes = current
                    .to_canonical_json()
                    .map_err(|error| ExecutorError::Plan(error.to_string()))?;
                journal
                    .reconcile(ReconcileResult {
                        inventory_sha256: format!("{:x}", sha2::Sha256::digest(bytes)),
                        success: false,
                        changed_packages: 0,
                    })
                    .map_err(state)?;
            }
        }
    }
    Ok(())
}

fn state(error: dnfast_state::StateError) -> ExecutorError {
    ExecutorError::Plan(error.to_string())
}
fn inventory(error: dnfast_native::InventoryError) -> ExecutorError {
    ExecutorError::Plan(error.to_string())
}
