use std::ffi::{c_char, CStr};
use std::ptr::NonNull;

use sha2::{Digest, Sha256};

use crate::{c_string, empty_error, status_error, Context, Keyring, NativeError, RawContext, RawError};
use crate::keyring::RawKeyring;

#[repr(C)]
struct RawInventoryRecord {
    name: *const c_char,
    version: *const c_char,
    release: *const c_char,
    arch: *const c_char,
    vendor: *const c_char,
    epoch: u32,
    db_instance: u64,
    install_time: u64,
    immutable_header: *const u8,
    immutable_header_size: usize,
}

unsafe extern "C" {
    fn dnfast_inventory_read(context: *mut RawContext, root: *const c_char, error: *mut RawError) -> i32;
    fn dnfast_inventory_backend(context: *const RawContext) -> *const c_char;
    fn dnfast_inventory_rpm_version(context: *const RawContext) -> *const c_char;
    fn dnfast_inventory_count(context: *const RawContext) -> usize;
    fn dnfast_inventory_get(context: *const RawContext, index: usize) -> *const RawInventoryRecord;
    fn dnfast_inventory_write_begin(context: *mut RawContext, keyring: *mut RawKeyring, root: *const c_char, timeout_milliseconds: u64, error: *mut RawError) -> i32;
    fn dnfast_inventory_read_locked(context: *mut RawContext, error: *mut RawError) -> i32;
    fn dnfast_inventory_write_end(context: *mut RawContext);
    fn dnfast_inventory_rpm_run_count(context: *const RawContext) -> u64;
    fn dnfast_inventory_test_count(context: *const RawContext) -> u64;
    fn dnfast_inventory_real_count(context: *const RawContext) -> u64;
    fn dnfast_inventory_test_run(context: *mut RawContext, result: *mut i32, error: *mut RawError) -> i32;
    fn dnfast_inventory_run(context: *mut RawContext, result: *mut i32, error: *mut RawError) -> i32;
    fn dnfast_inventory_keyring_sequence(context: *const RawContext) -> u64;
    fn dnfast_inventory_rpmdb_sequence(context: *const RawContext) -> u64;
    fn dnfast_inventory_fixture_fail_next_test(context: *mut RawContext);
    fn dnfast_inventory_fixture_reset_global_counts();
    fn dnfast_inventory_fixture_global_test_count() -> u64;
    fn dnfast_inventory_fixture_global_real_count() -> u64;
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Inventory { pub backend: String, pub rpm_version: String, pub packages: Vec<InventoryPackage> }

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct InventoryPackage {
    pub name: String, pub version: String, pub release: String, pub arch: String,
    pub vendor: String,
    pub epoch: u32, pub db_instance: u64, pub install_time: u64,
    pub immutable_header_sha256: String,
}

impl Context {
    pub fn read_inventory(&mut self, root: &str) -> Result<Inventory, NativeError> {
        let root = c_string(root)?;
        let mut error = empty_error();
        // SAFETY: [Category 8 — FFI boundary UB] root and error are live for
        // the synchronous call and unique access serializes context mutation.
        let status = unsafe { dnfast_inventory_read(self.raw.as_ptr(), root.as_ptr(), &mut error) };
        if status != 0 { return Err(status_error(status, &mut error)); }
        self.copy_inventory()
    }

    pub fn begin_inventory_write(&mut self, keyring: &Keyring, root: &str, timeout: std::time::Duration) -> Result<(), NativeError> {
        let root = c_string(root)?;
        let mut error = empty_error();
        // SAFETY: [Category 8 — FFI boundary UB] arguments are live for the
        // synchronous call and the native context is uniquely borrowed.
        let milliseconds = u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX);
        let status = unsafe { dnfast_inventory_write_begin(self.raw.as_ptr(), keyring.raw.as_ptr(), root.as_ptr(), milliseconds, &mut error) };
        if status == 0 { Ok(()) } else { Err(status_error(status, &mut error)) }
    }

    pub fn read_locked_inventory(&mut self) -> Result<Inventory, NativeError> {
        let mut error = empty_error();
        // SAFETY: [Category 8 — FFI boundary UB] unique access and the native
        // write-context state satisfy the synchronous call contract.
        let status = unsafe { dnfast_inventory_read_locked(self.raw.as_ptr(), &mut error) };
        if status != 0 { return Err(status_error(status, &mut error)); }
        self.copy_inventory()
    }

    pub fn end_inventory_write(&mut self) {
        // SAFETY: [Category 8 — FFI boundary UB] teardown is idempotent on this
        // live, uniquely borrowed context.
        unsafe { dnfast_inventory_write_end(self.raw.as_ptr()) }
    }

    pub fn rpm_run_count(&self) -> u64 {
        // SAFETY: [Category 8 — FFI boundary UB] immutable getter on live context.
        unsafe { dnfast_inventory_rpm_run_count(self.raw.as_ptr()) }
    }

    pub fn run_counts(&self) -> (u64, u64) {
        // SAFETY: [Category 8 — FFI boundary UB] immutable getters on live context.
        unsafe { (dnfast_inventory_test_count(self.raw.as_ptr()), dnfast_inventory_real_count(self.raw.as_ptr())) }
    }

    pub fn test_run(&mut self) -> Result<i32, NativeError> {
        let mut error = empty_error();
        let mut result = 0;
        // SAFETY: [Category 8 — FFI boundary UB] unique live context and both
        // out-parameters remain initialized and live for the call.
        let status = unsafe { dnfast_inventory_test_run(self.raw.as_ptr(), &mut result, &mut error) };
        if status == 0 { Ok(result) } else { Err(status_error(status, &mut error)) }
    }

    pub fn inventory_call_order(&self) -> (u64, u64) {
        // SAFETY: [Category 8 — FFI boundary UB] immutable getters on live context.
        unsafe { (dnfast_inventory_keyring_sequence(self.raw.as_ptr()), dnfast_inventory_rpmdb_sequence(self.raw.as_ptr())) }
    }

    pub fn run(&mut self) -> Result<i32, NativeError> {
        let mut error = empty_error();
        let mut result = 0;
        // SAFETY: [Category 8 — FFI boundary UB] unique live context and both
        // out-parameters remain initialized for the non-cancellable call.
        let status = unsafe { dnfast_inventory_run(self.raw.as_ptr(), &mut result, &mut error) };
        if status == 0 { Ok(result) } else { Err(status_error(status, &mut error)) }
    }

    pub fn fixture_fail_next_test(&mut self) {
        // SAFETY: [Category 8 — FFI boundary UB] fixture flag mutation on the
        // unique live context occurs before any concurrent native call.
        unsafe { dnfast_inventory_fixture_fail_next_test(self.raw.as_ptr()) }
    }

    fn copy_inventory(&self) -> Result<Inventory, NativeError> {
        // SAFETY: context-owned strings are copied before any later mutation.
        let backend = unsafe { copy_string(dnfast_inventory_backend(self.raw.as_ptr()))? };
        // SAFETY: context-owned strings are copied before any later mutation.
        let rpm_version = unsafe { copy_string(dnfast_inventory_rpm_version(self.raw.as_ptr()))? };
        // SAFETY: self.raw is live and uniquely borrowed.
        let count = unsafe { dnfast_inventory_count(self.raw.as_ptr()) };
        let mut packages = Vec::with_capacity(count);
        for index in 0..count { packages.push(self.copy_package(index)?); }
        Ok(Inventory { backend, rpm_version, packages })
    }

    fn copy_package(&self, index: usize) -> Result<InventoryPackage, NativeError> {
        // SAFETY: caller's index is bounded by the previously returned count.
        let raw = unsafe { dnfast_inventory_get(self.raw.as_ptr(), index) };
        let raw = NonNull::new(raw.cast_mut()).ok_or_else(null_result)?;
        // SAFETY: record storage remains live and immutable during this copy.
        let item = unsafe { raw.as_ref() };
        if item.immutable_header.is_null() || item.immutable_header_size == 0 { return Err(null_result()); }
        // SAFETY: native contract exposes this exact initialized byte range.
        let bytes = unsafe { std::slice::from_raw_parts(item.immutable_header, item.immutable_header_size) };
        Ok(InventoryPackage {
            // SAFETY: record strings are live NUL-terminated allocations.
            name: unsafe { copy_string(item.name)? },
            // SAFETY: record strings are live NUL-terminated allocations.
            version: unsafe { copy_string(item.version)? },
            // SAFETY: record strings are live NUL-terminated allocations.
            release: unsafe { copy_string(item.release)? },
            // SAFETY: record strings are live NUL-terminated allocations.
            arch: unsafe { copy_string(item.arch)? },
            // SAFETY: record strings are live NUL-terminated allocations.
            vendor: unsafe { copy_string(item.vendor)? },
            epoch: item.epoch, db_instance: item.db_instance, install_time: item.install_time,
            immutable_header_sha256: format!("{:x}", Sha256::digest(bytes)),
        })
    }
}

fn null_result() -> NativeError { NativeError { status: 7, component: "dnfast".into(), symbol: "inventory".into(), message: "native inventory result was null".into() } }

unsafe fn copy_string(pointer: *const c_char) -> Result<String, NativeError> {
    if pointer.is_null() { return Err(null_result()); }
    // SAFETY: caller establishes a live NUL-terminated native string.
    unsafe { CStr::from_ptr(pointer) }.to_str().map(str::to_owned).map_err(|_| NativeError {
        status: 7, component: "rpmdb".into(), symbol: "utf8".into(),
        message: "installed header contains non-UTF-8 text".into(),
    })
}

pub(crate) unsafe fn fixture_reset_global_counts() {
    // SAFETY: caller restricts this fixture-only global operation to serialized QA.
    unsafe { dnfast_inventory_fixture_reset_global_counts() }
}

pub(crate) unsafe fn fixture_global_counts() -> (u64, u64) {
    // SAFETY: atomic getters require no caller-provided memory.
    unsafe { (dnfast_inventory_fixture_global_test_count(), dnfast_inventory_fixture_global_real_count()) }
}

pub fn fixture_reset_inventory_counts() {
    // SAFETY: [Category 8 — FFI boundary UB] atomic native fixture reset has no pointers.
    unsafe { fixture_reset_global_counts() }
}

pub fn fixture_inventory_counts() -> (u64, u64) {
    // SAFETY: [Category 8 — FFI boundary UB] atomic native fixture getters have no pointers.
    unsafe { fixture_global_counts() }
}
