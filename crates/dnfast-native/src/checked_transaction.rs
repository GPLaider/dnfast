use std::os::fd::AsRawFd;
use std::rc::Rc;

use dnfast_cache::CachedArtifact;
use dnfast_core::InstalledPackage;

use crate::{
    ExecutionState, ExecutorInventory, InventoryError, NativeError, TransactionCounts,
    TransactionProblem, VerifiedArtifact,
};

impl ExecutorInventory {
    pub fn bind_journal(
        &mut self,
        journal: Rc<dnfast_state::TransactionJournal>,
    ) -> Result<(), InventoryError> {
        if self.state != ExecutionState::Prepared || self.journal.is_some() {
            return Err(InventoryError::InvalidState);
        }
        let callback = Rc::clone(&journal);
        self.context
            .set_transaction_start_callback(move || callback.mark_started().is_ok());
        self.journal = Some(journal);
        Ok(())
    }
    pub fn transaction_counts(&self) -> TransactionCounts {
        self.context.transaction_counts().into()
    }

    pub fn add_install(
        &mut self,
        artifact: &CachedArtifact,
        verified: &VerifiedArtifact,
        upgrade: bool,
    ) -> Result<(), InventoryError> {
        if self.state != ExecutionState::Prepared {
            return Err(InventoryError::InvalidState);
        }
        let package = &verified.package;
        let expected = dnfast_native_sys::VerifiedPackage {
            name: package.name.clone(),
            epoch: package.epoch.to_string(),
            version: package.version.clone(),
            release: package.release.clone(),
            arch: package.arch.clone(),
            vendor: package.vendor.clone(),
            primary_fingerprint: verified.primary_fingerprint.clone(),
            signing_fingerprint: verified.signing_fingerprint.clone(),
        };
        let digest: [u8; 32] = hex::decode(&verified.artifact_sha256)
            .map_err(|_| InventoryError::HeaderDigest)?
            .try_into()
            .map_err(|_| InventoryError::HeaderDigest)?;
        self.context
            .transaction_add_install(
                &self._keyring.native,
                artifact.file().as_raw_fd(),
                &expected,
                &digest,
                verified.artifact_size,
                upgrade,
            )
            .map_err(NativeError::from)
            .map_err(InventoryError::from)
    }

    pub fn add_erase(&mut self, installed: &InstalledPackage) -> Result<(), InventoryError> {
        if self.state != ExecutionState::Prepared {
            return Err(InventoryError::InvalidState);
        }
        self.inventory.erase_target(
            installed.db_instance(),
            installed.immutable_header_sha256().as_str(),
        )?;
        let bytes = hex::decode(installed.immutable_header_sha256().as_str())
            .map_err(|_| InventoryError::HeaderDigest)?;
        let digest: [u8; 32] = bytes.try_into().map_err(|_| InventoryError::HeaderDigest)?;
        self.context
            .transaction_add_erase(installed.db_instance(), &digest)
            .map_err(NativeError::from)
            .map_err(InventoryError::from)
    }

    pub fn prepare_checked_transaction(&mut self) -> Result<(), InventoryError> {
        if self.state != ExecutionState::Prepared {
            return Err(InventoryError::InvalidState);
        }
        match self.context.transaction_prepare() {
            Ok(()) => Ok(()),
            Err(error) => match self.problems()? {
                problems if problems.is_empty() => Err(NativeError::from(error).into()),
                problems => Err(InventoryError::TransactionPreflight { problems }),
            },
        }
    }

    pub fn test_checked_transaction(&mut self) -> Result<i32, InventoryError> {
        if self.state != ExecutionState::Prepared {
            return Err(InventoryError::InvalidState);
        }
        match self.context.transaction_test() {
            Ok(result) => {
                self.state = ExecutionState::Tested;
                Ok(result)
            }
            Err(error) => match self.problems()? {
                problems if problems.is_empty() => Err(NativeError::from(error).into()),
                problems => Err(InventoryError::TransactionPreflight { problems }),
            },
        }
    }

    pub fn run_checked_transaction(&mut self) -> Result<i32, InventoryError> {
        if self.state != ExecutionState::Tested {
            return Err(InventoryError::InvalidState);
        }
        match self.context.transaction_run() {
            Ok(result) => {
                if self.context.transaction_counts().real_run != 1 {
                    return Err(InventoryError::TransactionPreflight {
                        problems: self.problems()?,
                    });
                }
                self.state = ExecutionState::Started;
                match self.record_result(result) {
                    Ok(()) => Ok(result),
                    Err(error) => Err(InventoryError::PotentiallyStateful {
                        problems: self.problems()?,
                        journal_error: Some(error.to_string()),
                    }),
                }
            }
            Err(error) if self.context.transaction_counts().real_run == 0 => {
                match self.problems()? {
                    problems if problems.is_empty() => Err(NativeError::from(error).into()),
                    problems => Err(InventoryError::TransactionPreflight { problems }),
                }
            }
            Err(_) => {
                self.state = ExecutionState::Started;
                let problems = self.problems()?;
                let journal_error = self.record_result(-1).err().map(|error| error.to_string());
                Err(InventoryError::PotentiallyStateful {
                    problems,
                    journal_error,
                })
            }
        }
    }

    pub fn verify_transaction_db(&mut self) -> Result<(), InventoryError> {
        if self.state != ExecutionState::Started {
            return Err(InventoryError::InvalidState);
        }
        self.context
            .transaction_verify_db()
            .map_err(NativeError::from)
            .map_err(InventoryError::from)
    }

    fn problems(&self) -> Result<Vec<TransactionProblem>, InventoryError> {
        self.context
            .transaction_problems()
            .map_err(NativeError::from)
            .map_err(InventoryError::from)?
            .into_iter()
            .map(|value| TransactionProblem::new(value).map_err(|_| InventoryError::ProblemList))
            .collect()
    }

    fn record_result(&self, return_code: i32) -> Result<(), InventoryError> {
        let Some(journal) = &self.journal else {
            return Ok(());
        };
        let counts = self.context.transaction_counts();
        let callbacks = dnfast_state::CallbackSummary {
            pretrans: 0,
            pre: 0,
            post: counts.script_stop,
            triggers: 0,
            payload: counts.package_stop,
            database: 0,
            script_log_truncated: false,
        };
        journal
            .record_rpm_result_with_problems(
                return_code,
                callbacks,
                self.context
                    .transaction_problems()
                    .map_err(NativeError::from)
                    .map_err(InventoryError::from)?,
            )
            .map_err(|error| InventoryError::Journal(error.to_string()))
    }
}
