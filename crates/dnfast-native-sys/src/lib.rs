use std::ffi::{CStr, CString, c_char, c_void};
use std::marker::PhantomData;
use std::ptr::NonNull;
use std::rc::Rc;

mod authority;
pub use authority::{Authority, fork_probe as authority_fork_probe};
mod executor_fd;
pub use executor_fd::{ExecutorApproval, exec_fixed_executor, take_inherited_plan_fd};
mod inventory;
pub use inventory::{
    Inventory, InventoryPackage, InventoryRead, fixture_inventory_counts,
    fixture_reset_inventory_counts,
};
mod keyring;
pub use keyring::{Keyring, VerifiedPackage};
mod transaction;
pub use transaction::{TransactionCounts, TransactionPhase};
mod callback_state;
mod error_impl;
use callback_state::{CallbackState, interrupt_trampoline, transaction_start_trampoline};

pub const ABI_VERSION: u32 = 3;

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PoolArchitecture {
    Aarch64 = 1,
    X86_64 = 2,
}

#[repr(C)]
pub(crate) struct RawContext {
    _private: [u8; 0],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RawLimits {
    abi_version: u32,
    max_packages: u32,
    max_relations_per_package: u32,
    pool_architecture: u32,
    max_metadata_bytes: u64,
}

#[repr(C)]
struct RawCallbacks {
    abi_version: u32,
    user_data: *mut c_void,
    interrupt: Option<unsafe extern "C" fn(*mut c_void) -> i32>,
    transaction_start: Option<unsafe extern "C" fn(*mut c_void) -> i32>,
}

#[repr(C)]
struct RawRepoInput {
    abi_version: u32,
    id: *const c_char,
    repomd_path: *const c_char,
    primary_path: *const c_char,
    filelists_path: *const c_char,
    priority: i32,
    cost: i32,
    installed: u8,
}

#[repr(C)]
struct RawSolveRequest {
    abi_version: u32,
    names: *const *const c_char,
    name_count: usize,
    install_weak_deps: u8,
    best: u8,
}

#[repr(C)]
pub(crate) struct RawError {
    status: i32,
    component: *mut c_char,
    symbol: *mut c_char,
    message: *mut c_char,
}

unsafe extern "C" {
    fn dnfast_limits_default() -> RawLimits;
    fn dnfast_context_open(
        limits: *const RawLimits,
        callbacks: *const RawCallbacks,
        context: *mut *mut RawContext,
        error: *mut RawError,
    ) -> i32;
    fn dnfast_context_check(context: *mut RawContext, error: *mut RawError) -> i32;
    fn dnfast_context_pool_architecture(context: *const RawContext) -> *const c_char;
    fn dnfast_solver_add_repo(
        context: *mut RawContext,
        input: *const RawRepoInput,
        error: *mut RawError,
    ) -> i32;
    fn dnfast_solver_add_repo_primary(
        context: *mut RawContext,
        input: *const RawRepoInput,
        error: *mut RawError,
    ) -> i32;
    fn dnfast_solver_add_rpmdb(
        context: *mut RawContext,
        root: *const c_char,
        error: *mut RawError,
    ) -> i32;
    fn dnfast_solver_solve_operation(
        context: *mut RawContext,
        request: *const RawSolveRequest,
        operation: u8,
        error: *mut RawError,
    ) -> i32;
    fn dnfast_solver_action_count(context: *const RawContext) -> usize;
    fn dnfast_solver_action(context: *const RawContext, index: usize) -> *const c_char;
    fn dnfast_solver_action_repo(context: *const RawContext, index: usize) -> *const c_char;
    fn dnfast_solver_action_kind(context: *const RawContext, index: usize) -> *const c_char;
    fn dnfast_solver_action_obsoletes(context: *const RawContext, index: usize) -> *const c_char;
    fn dnfast_solver_action_requested_spec(
        context: *const RawContext,
        index: usize,
    ) -> *const c_char;
    fn dnfast_solver_action_requested_relation_kind(context: *const RawContext, index: usize)
    -> u8;
    fn dnfast_solver_satisfied_spec_count(context: *const RawContext) -> usize;
    fn dnfast_solver_satisfied_spec(context: *const RawContext, index: usize) -> *const c_char;
    fn dnfast_solver_decision_count(context: *const RawContext) -> usize;
    fn dnfast_solver_decision_requiring(context: *const RawContext, index: usize) -> *const c_char;
    fn dnfast_solver_decision_provider(context: *const RawContext, index: usize) -> *const c_char;
    fn dnfast_solver_decision_relation(context: *const RawContext, index: usize) -> *const c_char;
    fn dnfast_solver_decision_kind(context: *const RawContext, index: usize) -> u8;
    fn dnfast_solver_decision_provider_installed(context: *const RawContext, index: usize) -> u8;
    fn dnfast_solver_problem_count(context: *const RawContext) -> usize;
    fn dnfast_solver_problem(context: *const RawContext, index: usize) -> *const c_char;
    fn dnfast_context_free(context: *mut RawContext);
    fn dnfast_error_free(error: *mut RawError);
}

pub struct Context {
    pub(crate) raw: NonNull<RawContext>,
    pub(crate) _callback: Box<CallbackState>,
    _thread_affine: PhantomData<Rc<()>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SolveOperation {
    Install,
    Erase,
    Upgrade,
}

#[derive(Debug, Eq, PartialEq)]
pub struct NativeError {
    pub status: i32,
    pub component: String,
    pub symbol: String,
    pub message: String,
}

impl Context {
    pub fn open(
        architecture: PoolArchitecture,
        interrupt: impl FnMut() -> bool + 'static,
    ) -> Result<Self, NativeError> {
        Self::open_with_limits(architecture, interrupt, Limits::default())
    }

    pub fn open_with_limits(
        architecture: PoolArchitecture,
        interrupt: impl FnMut() -> bool + 'static,
        configured: Limits,
    ) -> Result<Self, NativeError> {
        let mut callback = Box::new(CallbackState {
            interrupt: Box::new(interrupt),
            transaction_start: Box::new(|| true),
        });
        // SAFETY: [Category 8 — FFI boundary UB] C returns a fully initialized value.
        let defaults = unsafe { dnfast_limits_default() };
        let limits = RawLimits {
            abi_version: ABI_VERSION,
            max_packages: configured.max_packages,
            max_relations_per_package: configured.max_relations_per_package,
            pool_architecture: architecture as u32,
            max_metadata_bytes: configured.max_metadata_bytes,
        };
        let _ = defaults;
        let callbacks = RawCallbacks {
            abi_version: ABI_VERSION,
            user_data: (&mut *callback as *mut CallbackState).cast(),
            interrupt: Some(interrupt_trampoline),
            transaction_start: Some(transaction_start_trampoline),
        };
        let mut raw = std::ptr::null_mut();
        let mut error = RawError {
            status: 0,
            component: std::ptr::null_mut(),
            symbol: std::ptr::null_mut(),
            message: std::ptr::null_mut(),
        };
        // SAFETY: [Categories 5 and 8 — invalid values/FFI] all pointers target live,
        // initialized values and C writes only the out parameters during this call.
        let status = unsafe { dnfast_context_open(&limits, &callbacks, &mut raw, &mut error) };
        if status != 0 {
            return Err(take_error(&mut error));
        }
        let raw = NonNull::new(raw).ok_or_else(|| NativeError {
            status: 7,
            component: "dnfast".into(),
            symbol: String::new(),
            message: "native success returned null context".into(),
        })?;
        Ok(Self {
            raw,
            _callback: callback,
            _thread_affine: PhantomData,
        })
    }

    pub fn check(&mut self) -> Result<bool, NativeError> {
        let mut error = RawError {
            status: 0,
            component: std::ptr::null_mut(),
            symbol: std::ptr::null_mut(),
            message: std::ptr::null_mut(),
        };
        // SAFETY: [Categories 3 and 8 — dangling/FFI] `self.raw` is owned and live,
        // and mutable access enforces the C context's single-threaded call discipline.
        let status = unsafe { dnfast_context_check(self.raw.as_ptr(), &mut error) };
        match status {
            0 => Ok(false),
            5 => Ok(true),
            _ => Err(take_error(&mut error)),
        }
    }

    pub fn pool_architecture(&self) -> Result<PoolArchitecture, NativeError> {
        let value = unsafe { dnfast_context_pool_architecture(self.raw.as_ptr()) };
        if value.is_null() {
            return Err(NativeError {
                status: 7,
                component: "dnfast".into(),
                symbol: "pool_architecture".into(),
                message: "native pool architecture was null".into(),
            });
        }
        match unsafe { CStr::from_ptr(value) }.to_bytes() {
            b"aarch64" => Ok(PoolArchitecture::Aarch64),
            b"x86_64" => Ok(PoolArchitecture::X86_64),
            _ => Err(NativeError {
                status: 7,
                component: "dnfast".into(),
                symbol: "pool_architecture".into(),
                message: "native pool architecture was unsupported".into(),
            }),
        }
    }

    pub fn add_repo(&mut self, repo: &RepoInput) -> Result<(), NativeError> {
        self.add_repo_kind(repo, false, true)
    }

    pub fn add_repo_primary(&mut self, repo: &RepoInput) -> Result<(), NativeError> {
        self.add_repo_kind(repo, false, false)
    }

    pub fn add_installed_repo(&mut self, repo: &RepoInput) -> Result<(), NativeError> {
        self.add_repo_kind(repo, true, true)
    }

    fn add_repo_kind(
        &mut self,
        repo: &RepoInput,
        installed: bool,
        include_filelists: bool,
    ) -> Result<(), NativeError> {
        let id = c_string(&repo.id)?;
        let repomd = c_string(&repo.repomd_path)?;
        let primary = c_string(&repo.primary_path)?;
        let filelists = c_string(&repo.filelists_path)?;
        let input = RawRepoInput {
            abi_version: ABI_VERSION,
            id: id.as_ptr(),
            repomd_path: repomd.as_ptr(),
            primary_path: primary.as_ptr(),
            filelists_path: filelists.as_ptr(),
            priority: repo.priority,
            cost: repo.cost,
            installed: u8::from(installed),
        };
        let mut error = empty_error();
        // SAFETY: [Category 8 — FFI boundary UB] strings and input remain live for
        // the synchronous call; the native context is uniquely borrowed.
        let status = unsafe {
            if include_filelists {
                dnfast_solver_add_repo(self.raw.as_ptr(), &input, &mut error)
            } else {
                dnfast_solver_add_repo_primary(self.raw.as_ptr(), &input, &mut error)
            }
        };
        if status == 0 {
            Ok(())
        } else {
            Err(status_error(status, &mut error))
        }
    }

    pub fn add_rpmdb(&mut self, root: &str) -> Result<(), NativeError> {
        let root = c_string(root)?;
        let mut error = empty_error();
        // SAFETY: [Category 8 — FFI boundary UB] root is NUL-terminated and live
        // for the synchronous call; the context is uniquely borrowed.
        let status =
            unsafe { dnfast_solver_add_rpmdb(self.raw.as_ptr(), root.as_ptr(), &mut error) };
        if status == 0 {
            Ok(())
        } else {
            Err(status_error(status, &mut error))
        }
    }

    pub fn solve_install(
        &mut self,
        name: &str,
        weak: bool,
        best: bool,
    ) -> Result<SolveOutput, NativeError> {
        self.solve_install_many(&[name], weak, best)
    }

    pub fn solve_install_many(
        &mut self,
        names: &[&str],
        weak: bool,
        best: bool,
    ) -> Result<SolveOutput, NativeError> {
        self.solve_with_operation(names, weak, best, SolveOperation::Install)
    }

    pub fn solve_with_operation(
        &mut self,
        names: &[&str],
        weak: bool,
        best: bool,
        operation: SolveOperation,
    ) -> Result<SolveOutput, NativeError> {
        if names.is_empty() && operation != SolveOperation::Upgrade {
            return Err(NativeError {
                status: 1,
                component: "dnfast".into(),
                symbol: String::new(),
                message: "empty solve request".into(),
            });
        }
        let strings: Vec<_> = names
            .iter()
            .map(|name| c_string(name))
            .collect::<Result<_, _>>()?;
        let pointers: Vec<_> = strings.iter().map(|name| name.as_ptr()).collect();
        let request = RawSolveRequest {
            abi_version: ABI_VERSION,
            names: pointers.as_ptr(),
            name_count: pointers.len(),
            install_weak_deps: u8::from(weak),
            best: u8::from(best),
        };
        let mut error = empty_error();
        let operation = match operation {
            SolveOperation::Install => 0,
            SolveOperation::Erase => 1,
            SolveOperation::Upgrade => 2,
        };
        // SAFETY: [Category 8 — FFI boundary UB] request is valid for this
        // synchronous call and native result storage remains context-owned.
        let status = unsafe {
            dnfast_solver_solve_operation(self.raw.as_ptr(), &request, operation, &mut error)
        };
        if status != 0 {
            return Err(status_error(status, &mut error));
        }
        Ok(SolveOutput {
            actions: copy_items(self.raw, 0)?,
            repositories: copy_items(self.raw, 1)?,
            kinds: copy_items(self.raw, 2)?,
            obsoletes: copy_obsoletes(self.raw),
            requested_specs: copy_requested_specs(self.raw)?,
            requested_relation_kinds: copy_requested_relation_kinds(self.raw)?,
            satisfied_specs: copy_satisfied_specs(self.raw)?,
            problems: copy_items(self.raw, 3)?,
            decisions: copy_decisions(self.raw)?,
        })
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct Limits {
    pub max_packages: u32,
    pub max_relations_per_package: u32,
    pub max_metadata_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_packages: 2_000_000,
            max_relations_per_package: 16_384,
            max_metadata_bytes: 17_179_869_184,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RepoInput {
    pub id: String,
    pub repomd_path: String,
    pub primary_path: String,
    pub filelists_path: String,
    pub priority: i32,
    pub cost: i32,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SolveOutput {
    pub actions: Vec<String>,
    pub repositories: Vec<String>,
    pub kinds: Vec<String>,
    pub obsoletes: Vec<Option<String>>,
    pub requested_specs: Vec<Option<String>>,
    pub requested_relation_kinds: Vec<bool>,
    pub satisfied_specs: Vec<String>,
    pub problems: Vec<String>,
    pub decisions: Vec<DecisionOutput>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DecisionOutput {
    pub requiring: String,
    pub provider: String,
    pub relation: String,
    pub weak: bool,
    pub provider_installed: bool,
}

pub(crate) fn empty_error() -> RawError {
    RawError {
        status: 0,
        component: std::ptr::null_mut(),
        symbol: std::ptr::null_mut(),
        message: std::ptr::null_mut(),
    }
}

pub(crate) fn status_error(status: i32, raw: &mut RawError) -> NativeError {
    if raw.status != 0 {
        take_error(raw)
    } else {
        NativeError {
            status,
            component: "dnfast".into(),
            symbol: String::new(),
            message: "native operation interrupted".into(),
        }
    }
}

pub(crate) fn c_string(value: &str) -> Result<CString, NativeError> {
    CString::new(value).map_err(|_| NativeError {
        status: 1,
        component: "dnfast".into(),
        symbol: String::new(),
        message: "string contains NUL".into(),
    })
}

fn copy_items(raw: NonNull<RawContext>, mode: u8) -> Result<Vec<String>, NativeError> {
    // SAFETY: [Categories 3 and 8 — dangling/FFI] raw is a live owned context;
    // native getters return context-owned NUL strings copied before mutation.
    let count = unsafe {
        if mode < 3 {
            dnfast_solver_action_count(raw.as_ptr())
        } else {
            dnfast_solver_problem_count(raw.as_ptr())
        }
    };
    let mut output = Vec::with_capacity(count);
    for index in 0..count {
        // SAFETY: same invariant as above; index is bounded by native count.
        let item = unsafe {
            match mode {
                0 => dnfast_solver_action(raw.as_ptr(), index),
                1 => dnfast_solver_action_repo(raw.as_ptr(), index),
                2 => dnfast_solver_action_kind(raw.as_ptr(), index),
                _ => dnfast_solver_problem(raw.as_ptr(), index),
            }
        };
        if item.is_null() {
            return Err(NativeError {
                status: 7,
                component: "dnfast".into(),
                symbol: "result".into(),
                message: "native result was null".into(),
            });
        }
        // SAFETY: native contract guarantees a valid NUL string for every item.
        output.push(
            unsafe { CStr::from_ptr(item) }
                .to_string_lossy()
                .into_owned(),
        );
    }
    Ok(output)
}

fn copy_obsoletes(raw: NonNull<RawContext>) -> Vec<Option<String>> {
    // SAFETY: raw is live and each non-null pointer is context-owned.
    let count = unsafe { dnfast_solver_action_count(raw.as_ptr()) };
    (0..count)
        .map(|index| {
            // SAFETY: index is bounded by the native action count.
            let pointer = unsafe { dnfast_solver_action_obsoletes(raw.as_ptr(), index) };
            (!pointer.is_null()).then(|| {
                // SAFETY: non-null native action strings are NUL-terminated and live.
                unsafe { CStr::from_ptr(pointer) }
                    .to_string_lossy()
                    .into_owned()
            })
        })
        .collect()
}

fn copy_requested_specs(raw: NonNull<RawContext>) -> Result<Vec<Option<String>>, NativeError> {
    // SAFETY: [Category 8 — FFI boundary UB] raw is a live context and the C
    // getter returns either NULL or a context-owned NUL string before mutation.
    let count = unsafe { dnfast_solver_action_count(raw.as_ptr()) };
    (0..count)
        .map(|index| {
            // SAFETY: index is bounded by the native action count.
            let pointer = unsafe { dnfast_solver_action_requested_spec(raw.as_ptr(), index) };
            copy_requested_spec(pointer)
        })
        .collect()
}

fn copy_requested_relation_kinds(raw: NonNull<RawContext>) -> Result<Vec<bool>, NativeError> {
    // SAFETY: [Category 8 — FFI boundary UB] raw is live and the scalar getter
    // reads only a bounded context-owned provenance array.
    let count = unsafe { dnfast_solver_action_count(raw.as_ptr()) };
    (0..count)
        .map(|index| {
            // SAFETY: index is bounded by the native action count.
            match unsafe { dnfast_solver_action_requested_relation_kind(raw.as_ptr(), index) } {
                0 => Ok(false),
                1 => Ok(true),
                _ => Err(NativeError {
                    status: 7,
                    component: "dnfast".into(),
                    symbol: "requested_relation_kind".into(),
                    message: "native requested selector kind is invalid".into(),
                }),
            }
        })
        .collect()
}

fn copy_satisfied_specs(raw: NonNull<RawContext>) -> Result<Vec<String>, NativeError> {
    // SAFETY: [Category 8 — FFI boundary UB] raw owns stable no-op selector
    // strings until the next solve or context destruction.
    let count = unsafe { dnfast_solver_satisfied_spec_count(raw.as_ptr()) };
    (0..count)
        .map(|index| {
            // SAFETY: index is bounded by the native satisfied selector count.
            let pointer = unsafe { dnfast_solver_satisfied_spec(raw.as_ptr(), index) };
            copy_requested_spec(pointer)?.ok_or_else(|| NativeError {
                status: 7,
                component: "dnfast".into(),
                symbol: "satisfied_spec".into(),
                message: "native satisfied selector was null".into(),
            })
        })
        .collect()
}

fn copy_requested_spec(pointer: *const c_char) -> Result<Option<String>, NativeError> {
    if pointer.is_null() {
        return Ok(None);
    }
    // SAFETY: [Category 8 — FFI boundary UB] this boundary accepts only a
    // non-null C string returned by the getter, which owns it until mutation.
    unsafe { CStr::from_ptr(pointer) }
        .to_str()
        .map(|value| Some(value.to_owned()))
        .map_err(|_| NativeError {
            status: 7,
            component: "dnfast".into(),
            symbol: "requested_spec".into(),
            message: "native requested selector is not UTF-8".into(),
        })
}

fn copy_decisions(raw: NonNull<RawContext>) -> Result<Vec<DecisionOutput>, NativeError> {
    // SAFETY: [Categories 3 and 8 — dangling/FFI] raw owns stable decision
    // storage until the next solve or context destruction.
    let count = unsafe { dnfast_solver_decision_count(raw.as_ptr()) };
    let mut output = Vec::with_capacity(count);
    for index in 0..count {
        // SAFETY: index is bounded and every text pointer is context-owned.
        let pointers = unsafe {
            [
                dnfast_solver_decision_requiring(raw.as_ptr(), index),
                dnfast_solver_decision_provider(raw.as_ptr(), index),
                dnfast_solver_decision_relation(raw.as_ptr(), index),
            ]
        };
        if pointers.iter().any(|item| item.is_null()) {
            return Err(NativeError {
                status: 7,
                component: "dnfast".into(),
                symbol: "decision".into(),
                message: "native decision was null".into(),
            });
        }
        let text = |pointer| {
            // SAFETY: native decision strings remain NUL-terminated and live.
            unsafe { CStr::from_ptr(pointer) }
                .to_string_lossy()
                .into_owned()
        };
        // SAFETY: scalar getters have no pointer dereference beyond live context.
        let (kind, installed) = unsafe {
            (
                dnfast_solver_decision_kind(raw.as_ptr(), index),
                dnfast_solver_decision_provider_installed(raw.as_ptr(), index),
            )
        };
        output.push(DecisionOutput {
            requiring: text(pointers[0]),
            provider: text(pointers[1]),
            relation: text(pointers[2]),
            weak: kind == 1,
            provider_installed: installed == 1,
        });
    }
    Ok(output)
}

fn take_error(raw: &mut RawError) -> NativeError {
    fn text(pointer: *const c_char) -> String {
        if pointer.is_null() {
            return String::new();
        }
        // SAFETY: [Category 8 — FFI boundary UB] native errors own NUL-terminated
        // strings until `dnfast_error_free`, and this copy occurs before that call.
        unsafe { CStr::from_ptr(pointer) }
            .to_string_lossy()
            .into_owned()
    }
    let error = NativeError {
        status: raw.status,
        component: text(raw.component),
        symbol: text(raw.symbol),
        message: text(raw.message),
    };
    // SAFETY: [Category 12 — invalid free] `raw` was initialized by the ABI and
    // this function consumes its owned strings exactly once.
    unsafe { dnfast_error_free(raw) };
    error
}

impl Drop for Context {
    fn drop(&mut self) {
        // SAFETY: [Categories 3 and 12 — dangling/double free] `raw` is uniquely
        // owned by this Context and Drop runs exactly once.
        unsafe { dnfast_context_free(self.raw.as_ptr()) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x86_64_context_selects_the_x86_64_native_pool() {
        let context = Context::open(PoolArchitecture::X86_64, || false).unwrap();
        assert_eq!(
            context.pool_architecture().unwrap(),
            PoolArchitecture::X86_64
        );
    }

    #[test]
    fn requested_spec_when_native_getter_returns_null_maps_to_none() {
        assert_eq!(copy_requested_spec(std::ptr::null()).unwrap(), None);
    }
}
