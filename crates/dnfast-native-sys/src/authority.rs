use std::os::raw::{c_char, c_int};

unsafe extern "C" {
    fn dnfast_lock_acquire(name: *const c_char, length: usize) -> c_int;
    fn dnfast_lock_release(fd: c_int);
    fn dnfast_lock_fork_probe(name: *const c_char, length: usize) -> c_int;
}

pub fn fork_probe(name: &[u8]) -> Result<(), i32> {
    let result = unsafe { dnfast_lock_fork_probe(name.as_ptr().cast(), name.len()) };
    if result == 0 { Ok(()) } else { Err(-result) }
}

#[derive(Debug)]
pub struct Authority {
    fd: c_int,
    creator_pid: u32,
}

impl Authority {
    pub fn acquire(name: &[u8]) -> Result<Self, i32> {
        let result = unsafe { dnfast_lock_acquire(name.as_ptr().cast(), name.len()) };
        if result >= 0 {
            Ok(Self {
                fd: result,
                creator_pid: std::process::id(),
            })
        } else {
            Err(-result)
        }
    }
}

impl Drop for Authority {
    fn drop(&mut self) {
        if std::process::id() == self.creator_pid {
            unsafe { dnfast_lock_release(self.fd) };
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn raw_fork_child_drops_inherited_authority() {
        super::fork_probe(b"dnfast-raw-fork-probe").unwrap();
    }
}
