use serde::{Deserialize, Serialize};

use crate::StateError;

pub const MAX_RECORD_BYTES: u64 = 8 * 1024 * 1024;
pub const MAX_LOG_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransactionId(String);

impl TransactionId {
    pub fn parse(value: &str) -> Result<Self, StateError> {
        let bytes = value.as_bytes();
        let hyphens = [8, 13, 18, 23];
        let shape = bytes.len() == 36 && bytes.iter().enumerate().all(|(index, byte)| {
            if hyphens.contains(&index) { *byte == b'-' } else { byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase() }
        });
        if !shape || bytes.get(14) != Some(&b'7') || !matches!(bytes.get(19), Some(b'8' | b'9' | b'a' | b'b')) {
            return Err(StateError::Corrupt("transaction id is not canonical UUIDv7".into()));
        }
        Ok(Self(value.into()))
    }
    pub fn as_str(&self) -> &str { &self.0 }
}

pub use dnfast_core::JournalState as TransactionState;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CallbackSummary {
    pub pretrans: u64, pub pre: u64, pub post: u64, pub triggers: u64,
    pub payload: u64, pub database: u64, pub script_log_truncated: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeResult { pub return_code: i32, pub callbacks: CallbackSummary, pub problems: Vec<String> }

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReconcileResult { pub inventory_sha256: String, pub success: bool, pub changed_packages: u64 }

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct JournalEntry {
    pub schema_version: u32, pub transaction_id: String, pub plan_sha256: String,
    pub sequence: u64, pub state: TransactionState,
    #[serde(skip_serializing_if = "Option::is_none")] pub native_result: Option<NativeResult>,
    #[serde(skip_serializing_if = "Option::is_none")] pub reconciliation: Option<ReconcileResult>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecoveryAction { CleanupRevalidateAndReapprove, ReconcileOnly, Terminal(ReconcileResult) }
