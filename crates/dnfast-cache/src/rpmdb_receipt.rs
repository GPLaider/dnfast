use std::{
    fs::File,
    io::{Read, Write},
    os::fd::OwnedFd,
    path::{Path, PathBuf},
};

use rustix::fs::{
    AtFlags, IFlags, Mode, OFlags, fstat, fstatfs, fsync, ioctl_getflags, linkat, open, openat,
    renameat, unlinkat,
};
use sha2::{Digest, Sha256};

use crate::{CacheError, fs_safety::create_private_tree, model::io_error};

const RECEIPT_DIRECTORY: &str = "rpmdb-verify-v1";
const RECEIPT_VERSION: &str = "dnfast-rpmdb-verified-generation-v1";
const CURRENT_RECEIPT_VERSION: &str = "dnfast-rpmdb-current-generation-v1";
const CURRENT_RECEIPT_NAME: &str = "current.verified";
const MAX_RECEIPT_BYTES: u64 = 512;
const MAX_CURRENT_RECEIPT_BYTES: u64 = 16 * 1024;
const MAX_CURRENT_STATE_BYTES: usize = 4 * 1024;
const MAX_DATABASE_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const BTRFS_SUPER_MAGIC: u64 = 0x9123_683e;

#[derive(Debug)]
pub struct RpmDbReceiptCache {
    root: PathBuf,
    database: PathBuf,
    wal: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RpmDbVerifiedGeneration {
    binding: String,
    descriptor: String,
    receipt_name: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RpmDbReceiptCheck {
    Hit(RpmDbVerifiedGeneration),
    Miss {
        generation: RpmDbVerifiedGeneration,
        corrupted: bool,
    },
    Unsupported,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RpmDbCurrentReceipt {
    state: String,
    generation: RpmDbVerifiedGeneration,
}

impl RpmDbCurrentReceipt {
    pub fn state(&self) -> &str {
        &self.state
    }

    pub fn generation(&self) -> &RpmDbVerifiedGeneration {
        &self.generation
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RpmDbCurrentCheck {
    Hit(RpmDbCurrentReceipt),
    Miss { corrupted: bool },
    Unsupported,
}

impl RpmDbReceiptCache {
    pub fn new(
        root: impl Into<PathBuf>,
        database: impl Into<PathBuf>,
        wal: impl Into<PathBuf>,
    ) -> Self {
        Self {
            root: root.into(),
            database: database.into(),
            wal: wal.into(),
        }
    }

    pub fn check(&self, binding: &str) -> Result<RpmDbReceiptCheck, CacheError> {
        validate_digest(binding, "RPMDB verification binding")?;
        let Some(generation) = self.describe(binding)? else {
            return Ok(RpmDbReceiptCheck::Unsupported);
        };
        let path = self.root.join(RECEIPT_DIRECTORY);
        let Some(directory) = open_directory_if_present(&path)? else {
            return Ok(RpmDbReceiptCheck::Miss {
                generation,
                corrupted: false,
            });
        };
        match read_receipt(&directory, &generation.receipt_name) {
            Ok(Some(value)) if value == generation.descriptor => {
                Ok(RpmDbReceiptCheck::Hit(generation))
            }
            Ok(None) => Ok(RpmDbReceiptCheck::Miss {
                generation,
                corrupted: false,
            }),
            Ok(Some(_)) | Err(CacheError::Corrupt(_)) => Ok(RpmDbReceiptCheck::Miss {
                generation,
                corrupted: true,
            }),
            Err(error) => Err(error),
        }
    }

    /// Revalidates a generation that was already accepted by [`Self::check`].
    ///
    /// This is intentionally stricter than comparing an RPMDB cookie: the
    /// database must still be checksum-protected, its WAL must be quiescent,
    /// every measured file-generation field must match, and the protected
    /// receipt must still contain the exact descriptor.  Callers can use this
    /// between two adjacent phases without opening librpm a second time.
    pub fn is_current(&self, expected: &RpmDbVerifiedGeneration) -> Result<bool, CacheError> {
        Ok(matches!(
            self.check(&expected.binding)?,
            RpmDbReceiptCheck::Hit(ref current) if current == expected
        ))
    }

    pub fn publish(&self, expected: &RpmDbVerifiedGeneration) -> Result<(), CacheError> {
        let Some(current) = self.describe(&expected.binding)? else {
            return Err(CacheError::Corrupt(
                "RPMDB lost checksum protection after verification".into(),
            ));
        };
        if &current != expected {
            return Err(CacheError::Corrupt(
                "RPMDB changed while full verification was in progress".into(),
            ));
        }
        let path = self.root.join(RECEIPT_DIRECTORY);
        create_private_tree(&self.root, &path)?;
        let directory = open_directory(&path)?;
        publish_receipt(&directory, &current.receipt_name, &current.descriptor)
    }

    /// Opens the atomically published current-generation receipt without first
    /// opening librpm. The opaque state is accepted only when the protected
    /// RPMDB generation and its independently named verification receipt still
    /// match exactly.
    pub fn current(&self) -> Result<RpmDbCurrentCheck, CacheError> {
        let path = self.root.join(RECEIPT_DIRECTORY);
        let Some(directory) = open_directory_if_present(&path)? else {
            return Ok(RpmDbCurrentCheck::Miss { corrupted: false });
        };
        let value = match read_limited_receipt(
            &directory,
            CURRENT_RECEIPT_NAME,
            MAX_CURRENT_RECEIPT_BYTES,
            "RPMDB current-generation receipt",
        ) {
            Ok(Some(value)) => value,
            Ok(None) => return Ok(RpmDbCurrentCheck::Miss { corrupted: false }),
            Err(CacheError::Corrupt(_)) => {
                return Ok(RpmDbCurrentCheck::Miss { corrupted: true });
            }
            Err(error) => return Err(error),
        };
        let Some((binding, state, descriptor)) = parse_current_receipt(&value) else {
            return Ok(RpmDbCurrentCheck::Miss { corrupted: true });
        };
        let Some(generation) = self.describe(&binding)? else {
            return Ok(RpmDbCurrentCheck::Unsupported);
        };
        if generation.descriptor != descriptor {
            return Ok(RpmDbCurrentCheck::Miss { corrupted: false });
        }
        match read_receipt(&directory, &generation.receipt_name) {
            Ok(Some(value)) if value == generation.descriptor => {
                Ok(RpmDbCurrentCheck::Hit(RpmDbCurrentReceipt {
                    state,
                    generation,
                }))
            }
            Ok(None) => Ok(RpmDbCurrentCheck::Miss { corrupted: false }),
            Ok(Some(_)) | Err(CacheError::Corrupt(_)) => {
                Ok(RpmDbCurrentCheck::Miss { corrupted: true })
            }
            Err(error) => Err(error),
        }
    }

    /// Publishes a small opaque state record for the fully verified generation.
    /// The generation receipt is durable before the replaceable current pointer
    /// becomes visible, so interruption can only produce a conservative miss.
    pub fn publish_current(
        &self,
        expected: &RpmDbVerifiedGeneration,
        state: &str,
    ) -> Result<(), CacheError> {
        if state.is_empty() || state.len() > MAX_CURRENT_STATE_BYTES || state.contains('\0') {
            return Err(CacheError::Corrupt(
                "invalid RPMDB current-generation state".into(),
            ));
        }
        self.publish(expected)?;
        let Some(current) = self.describe(&expected.binding)? else {
            return Err(CacheError::Corrupt(
                "RPMDB lost checksum protection before current receipt publication".into(),
            ));
        };
        if &current != expected {
            return Err(CacheError::Corrupt(
                "RPMDB changed before current receipt publication".into(),
            ));
        }
        let value = format!(
            "{CURRENT_RECEIPT_VERSION}\nbinding={}\nstate={}\ndescriptor={}\n",
            current.binding,
            hex::encode(state.as_bytes()),
            hex::encode(current.descriptor.as_bytes()),
        );
        if value.len() as u64 > MAX_CURRENT_RECEIPT_BYTES {
            return Err(CacheError::Corrupt(
                "RPMDB current-generation receipt exceeds limit".into(),
            ));
        }
        let path = self.root.join(RECEIPT_DIRECTORY);
        create_private_tree(&self.root, &path)?;
        let directory = open_directory(&path)?;
        publish_limited_receipt(
            &directory,
            CURRENT_RECEIPT_NAME,
            &value,
            MAX_CURRENT_RECEIPT_BYTES,
            "RPMDB current-generation receipt",
        )
    }

    fn describe(&self, binding: &str) -> Result<Option<RpmDbVerifiedGeneration>, CacheError> {
        if !wal_is_quiescent(&self.wal)? {
            return Ok(None);
        }
        let database = File::from(
            open(
                &self.database,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(errno)?,
        );
        validate_database(&database)?;
        if !has_btrfs_checksums(&database)? {
            return Ok(None);
        }
        let before = fstat(&database).map_err(errno)?;
        let descriptor = format!(
            "{RECEIPT_VERSION} {binding} {} {} {} {} {} {} {}\n",
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime,
            before.st_mtime_nsec,
            before.st_ctime,
            before.st_ctime_nsec,
        );
        if descriptor.len() as u64 > MAX_RECEIPT_BYTES {
            return Err(CacheError::Corrupt(
                "RPMDB verification receipt exceeds limit".into(),
            ));
        }
        let after = fstat(&database).map_err(errno)?;
        if !same_generation(&before, &after) || !wal_is_quiescent(&self.wal)? {
            return Err(CacheError::Corrupt(
                "RPMDB changed while its generation was measured".into(),
            ));
        }
        let receipt_name = format!("{}.verified", hex::encode(Sha256::digest(&descriptor)));
        Ok(Some(RpmDbVerifiedGeneration {
            binding: binding.into(),
            descriptor,
            receipt_name,
        }))
    }
}

fn open_directory(path: &Path) -> Result<OwnedFd, CacheError> {
    let directory = open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(errno)?;
    validate_directory(&directory)?;
    Ok(directory)
}

fn open_directory_if_present(path: &Path) -> Result<Option<OwnedFd>, CacheError> {
    match open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(directory) => {
            validate_directory(&directory)?;
            Ok(Some(directory))
        }
        Err(rustix::io::Errno::NOENT) => Ok(None),
        Err(error) => Err(errno(error)),
    }
}

fn validate_directory(directory: &OwnedFd) -> Result<(), CacheError> {
    let metadata = fstat(directory).map_err(errno)?;
    if metadata.st_mode & 0o170000 != 0o040000
        || metadata.st_mode & 0o022 != 0
        || metadata.st_uid != rustix::process::geteuid().as_raw()
    {
        return Err(CacheError::Corrupt(
            "unsafe RPMDB verification receipt directory".into(),
        ));
    }
    Ok(())
}

fn validate_database(database: &File) -> Result<(), CacheError> {
    let metadata = fstat(database).map_err(errno)?;
    if metadata.st_mode & 0o170000 != 0o100000
        || metadata.st_mode & 0o022 != 0
        || metadata.st_uid != rustix::process::geteuid().as_raw()
        || metadata.st_nlink != 1
        || metadata.st_size <= 0
        || metadata.st_size as u64 > MAX_DATABASE_BYTES
    {
        return Err(CacheError::Corrupt("unsafe RPMDB database file".into()));
    }
    Ok(())
}

fn wal_is_quiescent(path: &Path) -> Result<bool, CacheError> {
    let wal = match open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(wal) => wal,
        Err(rustix::io::Errno::NOENT) => return Ok(true),
        Err(error) => return Err(errno(error)),
    };
    let metadata = fstat(&wal).map_err(errno)?;
    if metadata.st_mode & 0o170000 != 0o100000
        || metadata.st_mode & 0o022 != 0
        || metadata.st_uid != rustix::process::geteuid().as_raw()
        || metadata.st_nlink != 1
    {
        return Err(CacheError::Corrupt("unsafe RPMDB WAL file".into()));
    }
    Ok(metadata.st_size == 0)
}

fn has_btrfs_checksums(file: &File) -> Result<bool, CacheError> {
    let filesystem = fstatfs(file).map_err(errno)?;
    if filesystem.f_type as u64 != BTRFS_SUPER_MAGIC {
        return Ok(false);
    }
    let flags = ioctl_getflags(file).map_err(errno)?;
    Ok(!flags.contains(IFlags::NOCOW))
}

fn same_generation(before: &rustix::fs::Stat, after: &rustix::fs::Stat) -> bool {
    before.st_dev == after.st_dev
        && before.st_ino == after.st_ino
        && before.st_size == after.st_size
        && before.st_mtime == after.st_mtime
        && before.st_mtime_nsec == after.st_mtime_nsec
        && before.st_ctime == after.st_ctime
        && before.st_ctime_nsec == after.st_ctime_nsec
}

fn read_receipt(directory: &OwnedFd, name: &str) -> Result<Option<String>, CacheError> {
    read_limited_receipt(
        directory,
        name,
        MAX_RECEIPT_BYTES,
        "RPMDB verification receipt",
    )
}

fn read_limited_receipt(
    directory: &OwnedFd,
    name: &str,
    maximum: u64,
    role: &str,
) -> Result<Option<String>, CacheError> {
    let receipt = match openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(receipt) => receipt,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(error) => return Err(errno(error)),
    };
    let before = fstat(&receipt).map_err(errno)?;
    if before.st_mode & 0o170000 != 0o100000
        || before.st_mode & 0o022 != 0
        || before.st_uid != rustix::process::geteuid().as_raw()
        || before.st_nlink != 1
        || before.st_size <= 0
        || before.st_size as u64 > maximum
    {
        return Err(CacheError::Corrupt(format!("unsafe {role}")));
    }
    let mut file = File::from(receipt);
    let mut value = String::new();
    Read::by_ref(&mut file)
        .take(maximum + 1)
        .read_to_string(&mut value)
        .map_err(io_error)?;
    let after = fstat(&file).map_err(errno)?;
    if !same_generation(&before, &after)
        || value.len() as i64 != before.st_size
        || !value.ends_with('\n')
    {
        return Err(CacheError::Corrupt(format!("{role} changed while reading")));
    }
    Ok(Some(value))
}

fn parse_current_receipt(value: &str) -> Option<(String, String, String)> {
    let mut lines = value.lines();
    if lines.next()? != CURRENT_RECEIPT_VERSION {
        return None;
    }
    let binding = lines.next()?.strip_prefix("binding=")?.to_owned();
    validate_digest(&binding, "RPMDB verification binding").ok()?;
    let state = String::from_utf8(hex::decode(lines.next()?.strip_prefix("state=")?).ok()?).ok()?;
    if state.is_empty() || state.len() > MAX_CURRENT_STATE_BYTES || state.contains('\0') {
        return None;
    }
    let descriptor =
        String::from_utf8(hex::decode(lines.next()?.strip_prefix("descriptor=")?).ok()?).ok()?;
    if descriptor.len() as u64 > MAX_RECEIPT_BYTES
        || !descriptor.ends_with('\n')
        || lines.next().is_some()
    {
        return None;
    }
    Some((binding, state, descriptor))
}

fn publish_receipt(directory: &OwnedFd, name: &str, descriptor: &str) -> Result<(), CacheError> {
    publish_limited_receipt(
        directory,
        name,
        descriptor,
        MAX_RECEIPT_BYTES,
        "RPMDB verification receipt",
    )
}

fn publish_limited_receipt(
    directory: &OwnedFd,
    name: &str,
    descriptor: &str,
    maximum: u64,
    role: &str,
) -> Result<(), CacheError> {
    let mut temporary = File::from(
        openat(
            directory,
            ".",
            OFlags::TMPFILE | OFlags::RDWR | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .map_err(errno)?,
    );
    temporary
        .write_all(descriptor.as_bytes())
        .map_err(io_error)?;
    temporary.sync_all().map_err(io_error)?;
    match linkat(&temporary, "", directory, name, AtFlags::EMPTY_PATH) {
        Ok(()) => {}
        Err(rustix::io::Errno::EXIST) => match read_limited_receipt(directory, name, maximum, role)
        {
            Ok(Some(value)) if value == descriptor => return Ok(()),
            _ => {
                let repair = format!(".{name}.repair-{}", std::process::id());
                let _ = unlinkat(directory, repair.as_str(), AtFlags::empty());
                linkat(
                    &temporary,
                    "",
                    directory,
                    repair.as_str(),
                    AtFlags::EMPTY_PATH,
                )
                .map_err(errno)?;
                renameat(directory, repair.as_str(), directory, name).map_err(errno)?;
            }
        },
        Err(error) => return Err(errno(error)),
    }
    fsync(directory).map_err(errno)
}

fn validate_digest(value: &str, role: &str) -> Result<(), CacheError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(CacheError::Corrupt(format!("invalid {role} digest")));
    }
    Ok(())
}

fn errno(error: rustix::io::Errno) -> CacheError {
    CacheError::Io(std::io::Error::from_raw_os_error(error.raw_os_error()).to_string())
}

#[cfg(test)]
mod tests {
    use std::io::{Seek, SeekFrom};

    use super::*;

    fn binding() -> String {
        hex::encode(Sha256::digest(b"rpmdb binding"))
    }

    fn fixture() -> (tempfile::TempDir, RpmDbReceiptCache, PathBuf) {
        let root = tempfile::tempdir().expect("root");
        let database = root.path().join("rpmdb.sqlite");
        let wal = root.path().join("rpmdb.sqlite-wal");
        std::fs::write(&database, b"verified rpmdb bytes").expect("database");
        std::fs::write(&wal, []).expect("wal");
        let receipts = root.path().join("receipts");
        let cache = RpmDbReceiptCache::new(&receipts, &database, &wal);
        (root, cache, database)
    }

    #[test]
    fn receipt_round_trip_or_reports_unsupported_filesystem() {
        let (_root, cache, _database) = fixture();
        let generation = match cache.check(&binding()).expect("check") {
            RpmDbReceiptCheck::Miss { generation, .. } => generation,
            RpmDbReceiptCheck::Unsupported => return,
            RpmDbReceiptCheck::Hit(_) => panic!("receipt unexpectedly present"),
        };
        cache.publish(&generation).expect("publish");
        assert!(matches!(
            cache.check(&binding()).expect("recheck"),
            RpmDbReceiptCheck::Hit(_)
        ));
    }

    #[test]
    fn database_generation_change_never_reuses_receipt() {
        let (_root, cache, database) = fixture();
        let generation = match cache.check(&binding()).expect("check") {
            RpmDbReceiptCheck::Miss { generation, .. } => generation,
            RpmDbReceiptCheck::Unsupported => return,
            RpmDbReceiptCheck::Hit(_) => panic!("receipt unexpectedly present"),
        };
        cache.publish(&generation).expect("publish");
        let mut database = std::fs::OpenOptions::new()
            .write(true)
            .open(database)
            .expect("open database");
        database.seek(SeekFrom::Start(0)).expect("seek");
        database.write_all(b"changed").expect("modify");
        database.sync_all().expect("sync");
        assert!(!matches!(
            cache.check(&binding()).expect("recheck"),
            RpmDbReceiptCheck::Hit(_)
        ));
        assert!(!cache.is_current(&generation).expect("revalidate"));
    }

    #[test]
    fn accepted_generation_can_be_revalidated_without_librpm() {
        let (_root, cache, _database) = fixture();
        let generation = match cache.check(&binding()).expect("check") {
            RpmDbReceiptCheck::Miss { generation, .. } => generation,
            RpmDbReceiptCheck::Unsupported => return,
            RpmDbReceiptCheck::Hit(_) => panic!("receipt unexpectedly present"),
        };
        cache.publish(&generation).expect("publish");
        assert!(cache.is_current(&generation).expect("revalidate"));
    }

    #[test]
    fn current_receipt_round_trip_binds_opaque_state_to_generation() {
        let (_root, cache, _database) = fixture();
        let generation = match cache.check(&binding()).expect("check") {
            RpmDbReceiptCheck::Miss { generation, .. } => generation,
            RpmDbReceiptCheck::Unsupported => return,
            RpmDbReceiptCheck::Hit(_) => panic!("receipt unexpectedly present"),
        };
        cache
            .publish_current(&generation, "verified startup state")
            .expect("publish current");
        match cache.current().expect("open current") {
            RpmDbCurrentCheck::Hit(current) => {
                assert_eq!(current.state(), "verified startup state");
                assert_eq!(current.generation(), &generation);
            }
            other => panic!("unexpected current receipt: {other:?}"),
        }
    }

    #[test]
    fn changed_generation_never_accepts_current_state() {
        let (_root, cache, database) = fixture();
        let generation = match cache.check(&binding()).expect("check") {
            RpmDbReceiptCheck::Miss { generation, .. } => generation,
            RpmDbReceiptCheck::Unsupported => return,
            RpmDbReceiptCheck::Hit(_) => panic!("receipt unexpectedly present"),
        };
        cache
            .publish_current(&generation, "verified startup state")
            .expect("publish current");
        let mut database = std::fs::OpenOptions::new()
            .write(true)
            .open(database)
            .expect("open database");
        database.seek(SeekFrom::Start(0)).expect("seek");
        database.write_all(b"changed").expect("modify");
        database.sync_all().expect("sync");
        assert!(!matches!(
            cache.current().expect("current after change"),
            RpmDbCurrentCheck::Hit(_)
        ));
    }

    #[test]
    fn corrupt_receipt_is_repaired_only_after_publish() {
        let (_root, cache, _database) = fixture();
        let generation = match cache.check(&binding()).expect("check") {
            RpmDbReceiptCheck::Miss { generation, .. } => generation,
            RpmDbReceiptCheck::Unsupported => return,
            RpmDbReceiptCheck::Hit(_) => panic!("receipt unexpectedly present"),
        };
        cache.publish(&generation).expect("publish");
        let receipt = cache
            .root
            .join(RECEIPT_DIRECTORY)
            .join(&generation.receipt_name);
        std::fs::write(&receipt, b"corrupt\n").expect("corrupt receipt");
        assert!(matches!(
            cache.check(&binding()).expect("corrupt check"),
            RpmDbReceiptCheck::Miss {
                corrupted: true,
                ..
            }
        ));
        cache
            .publish(&generation)
            .expect("repair after verification");
        assert!(matches!(
            cache.check(&binding()).expect("recheck"),
            RpmDbReceiptCheck::Hit(_)
        ));
    }
}
