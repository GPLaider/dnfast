use thiserror::Error;

/// Mutation failures before and after the real RPM run boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransactionFailureClass {
    Preflight,
    PotentiallyStateful,
}

impl TransactionFailureClass {
    /// A returned real-run failure is always potentially stateful.
    pub const fn from_real_result(_result: i32) -> Self {
        Self::PotentiallyStateful
    }
}

/// A non-empty RPM problem preserved without filtering.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransactionProblem(String);

impl TransactionProblem {
    /// Parses a native problem at the FFI boundary.
    pub fn new(value: impl Into<String>) -> Result<Self, TransactionProblemError> {
        let value = value.into();
        if value.is_empty() || value.len() > 4096 || value.contains('\0') {
            return Err(TransactionProblemError);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
#[error("RPM transaction problem is empty or contains NUL")]
pub struct TransactionProblemError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransactionCounts {
    pub fd_open: u64,
    pub fd_close: u64,
    pub open_attempted: u64,
    pub open_failed: u64,
    pub rewind_attempted: u64,
    pub rewind_succeeded: u64,
    pub rewind_failed: u64,
    pub close_attempted: u64,
    pub close_failed: u64,
    pub script_start: u64,
    pub script_stop: u64,
    pub package_stop: u64,
    pub test_run: u64,
    pub real_run: u64,
}

impl From<dnfast_native_sys::TransactionCounts> for TransactionCounts {
    fn from(value: dnfast_native_sys::TransactionCounts) -> Self {
        Self {
            fd_open: value.fd_open,
            fd_close: value.fd_close,
            open_attempted: value.open_attempted,
            open_failed: value.open_failed,
            rewind_attempted: value.rewind_attempted,
            rewind_succeeded: value.rewind_succeeded,
            rewind_failed: value.rewind_failed,
            close_attempted: value.close_attempted,
            close_failed: value.close_failed,
            script_start: value.script_start,
            script_stop: value.script_stop,
            package_stop: value.package_stop,
            test_run: value.test_run,
            real_run: value.real_run,
        }
    }
}
