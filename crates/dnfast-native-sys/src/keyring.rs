use std::marker::PhantomData;
use std::ptr::NonNull;
use std::rc::Rc;

use crate::{NativeError, RawError, empty_error, status_error};

#[repr(C)]
struct RawKeyBlob {
    data: *const u8,
    length: usize,
}

#[repr(C)]
pub(crate) struct RawVerifiedPackage {
    name: [std::ffi::c_char; 256],
    epoch: [std::ffi::c_char; 32],
    version: [std::ffi::c_char; 256],
    release: [std::ffi::c_char; 256],
    arch: [std::ffi::c_char; 64],
    vendor: [std::ffi::c_char; 256],
    primary_fingerprint: [std::ffi::c_char; 41],
    signing_fingerprint: [std::ffi::c_char; 41],
}

impl RawVerifiedPackage {
    pub(crate) fn from_verified(value: &VerifiedPackage) -> Result<Self, NativeError> {
        let mut raw = Self {
            name: [0; 256],
            epoch: [0; 32],
            version: [0; 256],
            release: [0; 256],
            arch: [0; 64],
            primary_fingerprint: [0; 41],
            vendor: [0; 256],
            signing_fingerprint: [0; 41],
        };
        copy(&mut raw.name, &value.name)?;
        copy(&mut raw.epoch, &value.epoch)?;
        copy(&mut raw.version, &value.version)?;
        copy(&mut raw.release, &value.release)?;
        copy(&mut raw.arch, &value.arch)?;
        copy(&mut raw.vendor, &value.vendor)?;
        copy(&mut raw.primary_fingerprint, &value.primary_fingerprint)?;
        copy(&mut raw.signing_fingerprint, &value.signing_fingerprint)?;
        Ok(raw)
    }
}

fn copy<const N: usize>(
    target: &mut [std::ffi::c_char; N],
    value: &str,
) -> Result<(), NativeError> {
    if value.as_bytes().contains(&0) || value.len() >= N {
        return Err(NativeError {
            status: 1,
            component: "rpm".into(),
            symbol: "transaction".into(),
            message: "invalid package identity".into(),
        });
    }
    for (index, byte) in value.bytes().enumerate() {
        target[index] = std::ffi::c_char::try_from(byte).map_err(|_| NativeError {
            status: 1,
            component: "rpm".into(),
            symbol: "transaction".into(),
            message: "non-ASCII package identity".into(),
        })?;
    }
    Ok(())
}

#[repr(C)]
pub(crate) struct RawKeyring {
    _private: [u8; 0],
}

unsafe extern "C" {
    fn dnfast_keyring_fixture_open(output: *mut *mut RawKeyring, error: *mut RawError) -> i32;
    fn dnfast_keyring_open(
        keys: *const RawKeyBlob,
        count: usize,
        output: *mut *mut RawKeyring,
        error: *mut RawError,
    ) -> i32;
    fn dnfast_keyring_verify_fd(
        keyring: *mut RawKeyring,
        fd: i32,
        package: *mut RawVerifiedPackage,
        error: *mut RawError,
    ) -> i32;
    fn dnfast_keyring_free(keyring: *mut RawKeyring);
}

pub struct Keyring {
    pub(crate) raw: NonNull<RawKeyring>,
    _thread_affine: PhantomData<Rc<()>>,
}

impl Keyring {
    pub fn open(keys: &[&[u8]]) -> Result<Self, NativeError> {
        let blobs = keys
            .iter()
            .map(|key| RawKeyBlob {
                data: key.as_ptr(),
                length: key.len(),
            })
            .collect::<Vec<_>>();
        let mut raw = std::ptr::null_mut();
        let mut error = empty_error();
        // SAFETY: [Category 8 — FFI boundary UB] every blob borrows live bytes
        // for this synchronous call and both out-pointers are initialized.
        let status =
            unsafe { dnfast_keyring_open(blobs.as_ptr(), blobs.len(), &mut raw, &mut error) };
        if status != 0 {
            return Err(status_error(status, &mut error));
        }
        NonNull::new(raw)
            .map(|raw| Self {
                raw,
                _thread_affine: PhantomData,
            })
            .ok_or_else(|| NativeError {
                status: 7,
                component: "rpm".into(),
                symbol: "rpmKeyringNew".into(),
                message: "null keyring".into(),
            })
    }

    pub fn verify_fd(&self, fd: std::os::fd::RawFd) -> Result<VerifiedPackage, NativeError> {
        let mut package = RawVerifiedPackage {
            name: [0; 256],
            epoch: [0; 32],
            version: [0; 256],
            release: [0; 256],
            arch: [0; 64],
            vendor: [0; 256],
            primary_fingerprint: [0; 41],
            signing_fingerprint: [0; 41],
        };
        let mut error = empty_error();
        // SAFETY: [Category 8 — FFI boundary UB] keyring and output are live;
        // native duplicates fd and never assumes ownership of the caller fd.
        let status =
            unsafe { dnfast_keyring_verify_fd(self.raw.as_ptr(), fd, &mut package, &mut error) };
        if status != 0 {
            return Err(status_error(status, &mut error));
        }
        Ok(VerifiedPackage {
            name: text(&package.name)?,
            epoch: text(&package.epoch)?,
            version: text(&package.version)?,
            release: text(&package.release)?,
            arch: text(&package.arch)?,
            vendor: text(&package.vendor)?,
            primary_fingerprint: text(&package.primary_fingerprint)?,
            signing_fingerprint: text(&package.signing_fingerprint)?,
        })
    }
    pub fn fixture() -> Result<Self, NativeError> {
        let mut raw = std::ptr::null_mut();
        let mut error = empty_error();
        // SAFETY: [Category 8 — FFI boundary UB] both out-pointers are live and
        // native initializes ownership only on successful return.
        let status = unsafe { dnfast_keyring_fixture_open(&mut raw, &mut error) };
        if status != 0 {
            return Err(status_error(status, &mut error));
        }
        NonNull::new(raw)
            .map(|raw| Self {
                raw,
                _thread_affine: PhantomData,
            })
            .ok_or_else(|| NativeError {
                status: 7,
                component: "rpm".into(),
                symbol: "rpmKeyringNew".into(),
                message: "null keyring".into(),
            })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedPackage {
    pub name: String,
    pub epoch: String,
    pub version: String,
    pub release: String,
    pub arch: String,
    pub vendor: String,
    pub primary_fingerprint: String,
    pub signing_fingerprint: String,
}

fn text<const N: usize>(value: &[std::ffi::c_char; N]) -> Result<String, NativeError> {
    // SAFETY: [Category 8 — FFI boundary UB] native guarantees NUL termination
    // within each fixed output array on successful return.
    unsafe { std::ffi::CStr::from_ptr(value.as_ptr()) }
        .to_str()
        .map(str::to_owned)
        .map_err(|error| NativeError {
            status: 7,
            component: "rpm".into(),
            symbol: "verified_package".into(),
            message: error.to_string(),
        })
}

impl Drop for Keyring {
    fn drop(&mut self) {
        // SAFETY: [Category 8 — FFI boundary UB] this owner frees its unique
        // native keyring exactly once after every borrowing context is dropped.
        unsafe { dnfast_keyring_free(self.raw.as_ptr()) }
    }
}
