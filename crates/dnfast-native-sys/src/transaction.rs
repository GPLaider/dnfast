use std::ffi::{CStr, c_char};

use crate::keyring::{RawKeyring, RawVerifiedPackage};
use crate::{
    Context, Keyring, NativeError, RawContext, RawError, VerifiedPackage, empty_error, status_error,
};

#[repr(C)]
#[derive(Clone, Copy)]
struct RawCounts {
    fd_open: u64,
    fd_close: u64,
    open_attempted: u64,
    open_failed: u64,
    rewind_attempted: u64,
    rewind_succeeded: u64,
    rewind_failed: u64,
    close_attempted: u64,
    close_failed: u64,
    script_start: u64,
    script_stop: u64,
    package_stop: u64,
    test_run: u64,
    real_run: u64,
}

#[repr(C)]
struct RawInstall {
    package: RawVerifiedPackage,
    artifact_sha256: [u8; 32],
    artifact_size: u64,
    upgrade: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransactionCounts {
    pub fd_open: u64,
    pub fd_close: u64,
    pub script_start: u64,
    pub open_attempted: u64,
    pub open_failed: u64,
    pub rewind_attempted: u64,
    pub rewind_succeeded: u64,
    pub rewind_failed: u64,
    pub close_attempted: u64,
    pub close_failed: u64,
    pub script_stop: u64,
    pub package_stop: u64,
    pub test_run: u64,
    pub real_run: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransactionPhase {
    Preflight,
    Started,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransactionInstallMode {
    Install = 0,
    Upgrade = 1,
    Reinstall = 2,
    Downgrade = 3,
}

#[cfg(test)]
mod mode_tests {
    use super::TransactionInstallMode;

    #[test]
    fn install_modes_have_fixed_native_values() {
        assert_eq!(TransactionInstallMode::Install as u8, 0);
        assert_eq!(TransactionInstallMode::Upgrade as u8, 1);
        assert_eq!(TransactionInstallMode::Reinstall as u8, 2);
        assert_eq!(TransactionInstallMode::Downgrade as u8, 3);
    }
}

unsafe extern "C" {
    fn dnfast_transaction_add_install(
        context: *mut RawContext,
        keyring: *mut RawKeyring,
        fd: i32,
        expected: *const RawInstall,
        error: *mut RawError,
    ) -> i32;
    fn dnfast_transaction_add_erase(
        context: *mut RawContext,
        instance: u64,
        digest: *const u8,
        error: *mut RawError,
    ) -> i32;
    fn dnfast_transaction_prepare(context: *mut RawContext, error: *mut RawError) -> i32;
    fn dnfast_transaction_test(
        context: *mut RawContext,
        result: *mut i32,
        error: *mut RawError,
    ) -> i32;
    fn dnfast_transaction_run(
        context: *mut RawContext,
        result: *mut i32,
        error: *mut RawError,
    ) -> i32;
    fn dnfast_transaction_verify_db(context: *mut RawContext, error: *mut RawError) -> i32;
    fn dnfast_transaction_problem_count(context: *const RawContext) -> usize;
    fn dnfast_transaction_problem(context: *const RawContext, index: usize) -> *const c_char;
    fn dnfast_transaction_get_counts(context: *const RawContext) -> RawCounts;
    fn dnfast_transaction_get_phase(context: *const RawContext) -> i32;
    fn dnfast_transaction_fixture_fail_callback(context: *mut RawContext, point: u8);
}

impl Context {
    pub fn transaction_add_install(
        &mut self,
        keyring: &Keyring,
        fd: i32,
        expected: &VerifiedPackage,
        digest: &[u8; 32],
        size: u64,
        upgrade: bool,
    ) -> Result<(), NativeError> {
        self.transaction_add_install_mode(
            keyring,
            fd,
            expected,
            digest,
            size,
            if upgrade {
                TransactionInstallMode::Upgrade
            } else {
                TransactionInstallMode::Install
            },
        )
    }

    pub fn transaction_add_install_mode(
        &mut self,
        keyring: &Keyring,
        fd: i32,
        expected: &VerifiedPackage,
        digest: &[u8; 32],
        size: u64,
        mode: TransactionInstallMode,
    ) -> Result<(), NativeError> {
        let expected = RawInstall {
            package: RawVerifiedPackage::from_verified(expected)?,
            artifact_sha256: *digest,
            artifact_size: size,
            upgrade: mode as u8,
        };
        let mut error = empty_error();
        // SAFETY: [Category 8 — FFI boundary UB] all pointers remain live for this
        // synchronous call; native duplicates the fd and copies the identity.
        let status = unsafe {
            dnfast_transaction_add_install(
                self.raw.as_ptr(),
                keyring.raw.as_ptr(),
                fd,
                &expected,
                &mut error,
            )
        };
        if status == 0 {
            Ok(())
        } else {
            Err(status_error(status, &mut error))
        }
    }

    pub fn transaction_add_erase(
        &mut self,
        instance: u64,
        digest: &[u8; 32],
    ) -> Result<(), NativeError> {
        let mut error = empty_error();
        // SAFETY: [Category 8 — FFI boundary UB] digest is an initialized fixed
        // array and the native context is uniquely borrowed.
        let status = unsafe {
            dnfast_transaction_add_erase(self.raw.as_ptr(), instance, digest.as_ptr(), &mut error)
        };
        if status == 0 {
            Ok(())
        } else {
            Err(status_error(status, &mut error))
        }
    }

    pub fn transaction_prepare(&mut self) -> Result<(), NativeError> {
        self.transaction_status(|context, error| unsafe {
            dnfast_transaction_prepare(context, error)
        })
    }

    pub fn transaction_test(&mut self) -> Result<i32, NativeError> {
        self.transaction_result(|context, result, error| unsafe {
            dnfast_transaction_test(context, result, error)
        })
    }

    pub fn transaction_run(&mut self) -> Result<i32, NativeError> {
        self.transaction_result(|context, result, error| unsafe {
            dnfast_transaction_run(context, result, error)
        })
    }

    pub fn transaction_verify_db(&mut self) -> Result<(), NativeError> {
        self.transaction_status(|context, error| unsafe {
            dnfast_transaction_verify_db(context, error)
        })
    }

    pub fn transaction_problems(&self) -> Result<Vec<String>, NativeError> {
        // SAFETY: [Category 8 — FFI boundary UB] immutable getters borrow the live context.
        let count = unsafe { dnfast_transaction_problem_count(self.raw.as_ptr()) };
        (0..count)
            .map(|index| {
                // SAFETY: native returns context-owned strings for bounded indexes.
                let value = unsafe { dnfast_transaction_problem(self.raw.as_ptr(), index) };
                if value.is_null() {
                    return Err(invalid_result());
                }
                // SAFETY: successful native problem entries are NUL terminated.
                unsafe { CStr::from_ptr(value) }
                    .to_str()
                    .map(str::to_owned)
                    .map_err(|_| invalid_result())
            })
            .collect()
    }

    pub fn transaction_counts(&self) -> TransactionCounts {
        // SAFETY: immutable plain-value getter on a live context.
        let value = unsafe { dnfast_transaction_get_counts(self.raw.as_ptr()) };
        TransactionCounts {
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

    pub fn transaction_phase(&self) -> Result<TransactionPhase, NativeError> {
        // SAFETY: immutable integer getter on a live context.
        match unsafe { dnfast_transaction_get_phase(self.raw.as_ptr()) } {
            0 => Ok(TransactionPhase::Preflight),
            1 => Ok(TransactionPhase::Started),
            _ => Err(invalid_result()),
        }
    }

    pub fn fixture_fail_transaction_callback(&mut self, point: u8) {
        // SAFETY: [Category 8 — FFI boundary UB] fixture mutation uses a live,
        // uniquely borrowed context before a synchronous transaction call.
        unsafe { dnfast_transaction_fixture_fail_callback(self.raw.as_ptr(), point) }
    }

    fn transaction_status(
        &mut self,
        call: impl FnOnce(*mut RawContext, *mut RawError) -> i32,
    ) -> Result<(), NativeError> {
        let mut error = empty_error();
        let status = call(self.raw.as_ptr(), &mut error);
        if status == 0 {
            Ok(())
        } else {
            Err(status_error(status, &mut error))
        }
    }

    fn transaction_result(
        &mut self,
        call: impl FnOnce(*mut RawContext, *mut i32, *mut RawError) -> i32,
    ) -> Result<i32, NativeError> {
        let mut error = empty_error();
        let mut result = 0;
        let status = call(self.raw.as_ptr(), &mut result, &mut error);
        if status == 0 {
            Ok(result)
        } else {
            Err(status_error(status, &mut error))
        }
    }
}

fn invalid_result() -> NativeError {
    NativeError {
        status: 7,
        component: "rpm".into(),
        symbol: "transaction".into(),
        message: "invalid native transaction result".into(),
    }
}
