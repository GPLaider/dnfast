use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};

use crate::NativeError;

unsafe extern "C" {
    fn dnfast_executor_take_plan_fd() -> i32;
    fn dnfast_executor_exec_fixed(plan_fd: i32, approval: u8) -> i32;
    fn dnfast_executor_exec_compact(
        plan_fd: i32,
        manifest_fd: i32,
        artifact_fds: *const i32,
        artifact_count: usize,
        approval: u8,
    ) -> i32;
    fn dnfast_executor_take_compact_fd() -> i32;
    fn dnfast_executor_take_artifact_fd(index: usize) -> i32;
}

pub fn exec_fixed_executor_compact(
    plan: OwnedFd,
    manifest: OwnedFd,
    artifacts: Vec<OwnedFd>,
    approval: ExecutorApproval,
) -> Result<(), NativeError> {
    let plan_fd = plan.as_raw_fd();
    let manifest_fd = manifest.as_raw_fd();
    let artifact_fds = artifacts.iter().map(AsRawFd::as_raw_fd).collect::<Vec<_>>();
    // SAFETY: [Category 8 — FFI boundary UB] every descriptor remains owned by
    // this frame until C either replaces the process or returns, and the slice
    // pointer is valid for exactly artifact_fds.len() integers.
    if unsafe {
        dnfast_executor_exec_compact(
            plan_fd,
            manifest_fd,
            artifact_fds.as_ptr(),
            artifact_fds.len(),
            approval.raw(),
        )
    } < 0
    {
        return Err(NativeError {
            status: 1,
            component: "executor".into(),
            symbol: "execve-compact".into(),
            message: "compact fixed executor launch failed".into(),
        });
    }
    Err(NativeError {
        status: 1,
        component: "executor".into(),
        symbol: "execve-compact".into(),
        message: "compact fixed executor unexpectedly returned".into(),
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutorApproval {
    Prompt,
    Yes,
    No,
}

impl ExecutorApproval {
    const fn raw(self) -> u8 {
        match self {
            Self::Prompt => 0,
            Self::Yes => 1,
            Self::No => 2,
        }
    }
}

pub fn exec_fixed_executor(plan: OwnedFd, approval: ExecutorApproval) -> Result<(), NativeError> {
    let plan_fd = plan.into_raw_fd();
    // SAFETY: [Category 8 — FFI boundary UB] ownership of a valid descriptor
    // moves to C, which either replaces this process or returns a launch error.
    if unsafe { dnfast_executor_exec_fixed(plan_fd, approval.raw()) } < 0 {
        return Err(NativeError {
            status: 1,
            component: "executor".into(),
            symbol: "execve".into(),
            message: "fixed executor launch failed".into(),
        });
    }
    Err(NativeError {
        status: 1,
        component: "executor".into(),
        symbol: "execve".into(),
        message: "fixed executor unexpectedly returned".into(),
    })
}

pub fn take_inherited_plan_fd() -> Result<OwnedFd, NativeError> {
    // SAFETY: [Category 8 — FFI boundary UB] the C function receives no Rust
    // pointers and returns either -1 or a fresh CLOEXEC descriptor it owns.
    let raw = unsafe { dnfast_executor_take_plan_fd() };
    if raw < 0 {
        return Err(NativeError {
            status: 1,
            component: "executor".into(),
            symbol: "fd3".into(),
            message: "missing or invalid inherited plan descriptor".into(),
        });
    }
    // SAFETY: [Category 12 — invalid free] the C wrapper returned a fresh
    // descriptor via F_DUPFD_CLOEXEC, transferring its single close duty here.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

pub fn take_inherited_compact_fd() -> Result<OwnedFd, NativeError> {
    // SAFETY: [Category 8 — FFI boundary UB] no Rust pointers cross this call.
    let raw = unsafe { dnfast_executor_take_compact_fd() };
    owned_inherited(raw, "fd4")
}

pub fn take_inherited_artifact_fd(index: usize) -> Result<OwnedFd, NativeError> {
    // SAFETY: [Category 8 — FFI boundary UB] no Rust pointers cross this call.
    let raw = unsafe { dnfast_executor_take_artifact_fd(index) };
    owned_inherited(raw, "artifact-fd")
}

fn owned_inherited(raw: i32, symbol: &str) -> Result<OwnedFd, NativeError> {
    if raw < 0 {
        return Err(NativeError {
            status: 1,
            component: "executor".into(),
            symbol: symbol.into(),
            message: "missing or invalid inherited descriptor".into(),
        });
    }
    // SAFETY: [Category 12 — invalid free] C returned a fresh descriptor and
    // transferred its single close duty to this OwnedFd.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

#[cfg(test)]
mod tests {
    use super::ExecutorApproval;

    #[test]
    fn approval_modes_have_fixed_native_values() {
        assert_eq!(ExecutorApproval::Prompt.raw(), 0);
        assert_eq!(ExecutorApproval::Yes.raw(), 1);
        assert_eq!(ExecutorApproval::No.raw(), 2);
    }
}
