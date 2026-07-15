use std::{
    ffi::c_void,
    panic::{AssertUnwindSafe, catch_unwind},
};

use crate::Context;

pub(crate) struct CallbackState {
    pub(crate) interrupt: Box<dyn FnMut() -> bool>,
    pub(crate) transaction_start: Box<dyn FnMut() -> bool>,
}

pub(crate) unsafe extern "C" fn interrupt_trampoline(user_data: *mut c_void) -> i32 {
    // SAFETY: [Category 8 — FFI boundary UB] Context owns this stable Box until
    // native teardown and C invokes it synchronously on the owner thread.
    let state = unsafe { &mut *user_data.cast::<CallbackState>() };
    match catch_unwind(AssertUnwindSafe(|| (state.interrupt)())) {
        Ok(true) => 5,
        Ok(false) => 0,
        Err(_) => 4,
    }
}

pub(crate) unsafe extern "C" fn transaction_start_trampoline(user_data: *mut c_void) -> i32 {
    // SAFETY: [Category 8 — FFI boundary UB] Context owns this stable Box until
    // native teardown and C invokes it synchronously on the owner thread.
    let state = unsafe { &mut *user_data.cast::<CallbackState>() };
    match catch_unwind(AssertUnwindSafe(|| (state.transaction_start)())) {
        Ok(true) => 0,
        Ok(false) | Err(_) => 4,
    }
}

impl Context {
    pub fn set_transaction_start_callback(&mut self, callback: impl FnMut() -> bool + 'static) {
        self._callback.transaction_start = Box::new(callback);
    }
}
