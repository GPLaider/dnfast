use std::sync::atomic::{AtomicU8, Ordering};

use crate::StateError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum FaultPoint { None, Create, Write, FileSync, Publish, DirectorySync }

pub struct FaultPlan { point: AtomicU8 }

impl FaultPlan {
    pub const fn none() -> Self { Self { point: AtomicU8::new(FaultPoint::None as u8) } }
    pub const fn once(point: FaultPoint) -> Self { Self { point: AtomicU8::new(point as u8) } }
    pub fn arm(&self, point: FaultPoint) { self.point.store(point as u8, Ordering::SeqCst); }
    pub(crate) fn check(&self, point: FaultPoint) -> Result<(), StateError> {
        if self.point.compare_exchange(point as u8, FaultPoint::None as u8, Ordering::SeqCst, Ordering::SeqCst).is_ok() {
            return Err(StateError::Io(format!("injected {point:?} failure")));
        }
        Ok(())
    }
}

impl Default for FaultPlan { fn default() -> Self { Self::none() } }
