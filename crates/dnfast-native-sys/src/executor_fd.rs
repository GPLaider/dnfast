use std::os::fd::{FromRawFd, IntoRawFd, OwnedFd};

use crate::NativeError;

unsafe extern "C" {
    fn dnfast_executor_take_plan_fd() -> i32;
    fn dnfast_executor_exec_fixed(plan_fd: i32, approval: u8) -> i32;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutorApproval { Prompt, Yes, No }

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
        return Err(NativeError { status: 1, component: "executor".into(),
            symbol: "execve".into(), message: "fixed executor launch failed".into() });
    }
    Err(NativeError { status: 1, component: "executor".into(), symbol: "execve".into(),
        message: "fixed executor unexpectedly returned".into() })
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

pub fn take_inherited_plan_fd() -> Result<OwnedFd, NativeError> {
    // SAFETY: [Category 8 — FFI boundary UB] the C function receives no Rust
    // pointers and returns either -1 or a fresh CLOEXEC descriptor it owns.
    let raw = unsafe { dnfast_executor_take_plan_fd() };
    if raw < 0 {
        return Err(NativeError { status: 1, component: "executor".into(),
            symbol: "fd3".into(), message: "missing or invalid inherited plan descriptor".into() });
    }
    // SAFETY: [Category 12 — invalid free] the C wrapper returned a fresh
    // descriptor via F_DUPFD_CLOEXEC, transferring its single close duty here.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}
