use std::{
    fs::File,
    io::{Read, Seek, Write},
    os::fd::OwnedFd,
    path::{Path, PathBuf},
};

use rustix::fs::{
    AtFlags, IFlags, Mode, OFlags, fstat, fstatfs, fsync, ioctl_getflags, linkat, open, openat,
    renameat, unlinkat,
};
use sha2::{Digest, Sha256};

use crate::{CacheError, fs_safety::create_private_tree, model::io_error};

const CACHE_DIRECTORY: &str = "solv-v1";
const MAX_SOLV_BYTES: u64 = 512 * 1024 * 1024;
const INTEGRITY_COOKIE_VERSION: &str = "dnfast-solv-integrity-v2";
const MAX_INTEGRITY_COOKIE_BYTES: u64 = 512;
const BTRFS_SUPER_MAGIC: u64 = 0x9123_683e;

#[derive(Debug)]
pub struct SolvCache {
    root: PathBuf,
}

pub struct CachedSolv {
    file: File,
    sha256: String,
    size: u64,
    verification: SolvVerification,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SolvVerification {
    FullSha256,
    FsVerity,
    BtrfsChecksum,
}

pub struct StagedSolv {
    directory: OwnedFd,
    file: File,
    binding: String,
}

impl SolvCache {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn open(&self, binding: &str) -> Result<Option<CachedSolv>, CacheError> {
        validate_digest(binding, "solv cache binding")?;
        let path = self.root.join(CACHE_DIRECTORY);
        match open_directory_if_present(&path)? {
            Some(directory) => open_cached(&directory, binding),
            None => Ok(None),
        }
    }

    pub fn stage(&self, binding: &str) -> Result<StagedSolv, CacheError> {
        validate_digest(binding, "solv cache binding")?;
        let path = self.root.join(CACHE_DIRECTORY);
        create_private_tree(&self.root, &path)?;
        let directory = open_directory(&path)?;
        let file = File::from(
            openat(
                &directory,
                ".",
                OFlags::TMPFILE | OFlags::RDWR | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o600),
            )
            .map_err(errno)?,
        );
        Ok(StagedSolv {
            directory,
            file,
            binding: binding.into(),
        })
    }
}

impl CachedSolv {
    pub fn file(&self) -> &File {
        &self.file
    }

    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    pub const fn size(&self) -> u64 {
        self.size
    }

    pub const fn verification(&self) -> SolvVerification {
        self.verification
    }
}

impl StagedSolv {
    pub fn file(&self) -> &File {
        &self.file
    }

    pub fn commit(mut self) -> Result<CachedSolv, CacheError> {
        // Hash the private inode first. Serialization has already dirtied all
        // of its pages, so this CPU pass can overlap kernel writeback instead
        // of blocking on a barrier and then rereading the same pages. Nothing
        // becomes reachable until the subsequent durability barrier succeeds.
        let (sha256, size) = verify_stream(&mut self.file, None)?;
        self.file.sync_all().map_err(io_error)?;
        let content_name = format!("{}-{sha256}.solv", self.binding);
        match linkat(
            &self.file,
            "",
            &self.directory,
            content_name.as_str(),
            AtFlags::EMPTY_PATH,
        ) {
            Ok(()) => {}
            Err(rustix::io::Errno::EXIST) => {
                if !content_matches(&self.directory, &content_name, &sha256, size)? {
                    replace_from_unnamed(&self.directory, &self.file, &content_name)?;
                }
            }
            Err(error) => return Err(errno(error)),
        }
        // Enabling fs-verity requires that no writable descriptor remains open.
        // The linked inode is durable and can now be reopened read-only below.
        drop(self.file);
        // A rebuild is also the atomic repair boundary for a damaged or stale
        // generation cookie. Removing only this derived receipt is safe: the
        // content is fully SHA-256 checked again before a new cookie appears.
        let cookie_name = format!("{}-{sha256}.integrity", self.binding);
        match unlinkat(&self.directory, cookie_name.as_str(), AtFlags::empty()) {
            Ok(()) | Err(rustix::io::Errno::NOENT) => {}
            Err(error) => return Err(errno(error)),
        }
        // The final directory fsync below makes the content link, integrity
        // cookie, and binding reference durable as one atomic cache batch.
        // Avoid a redundant directory barrier inside cookie publication.
        let existing = open_content_inner(
            &self.directory,
            &self.binding,
            &content_name,
            &sha256,
            false,
        )?;
        if existing.size != size {
            return Err(CacheError::Corrupt(
                "published solv cache size differs".into(),
            ));
        }
        let reference_name = format!("{}.ref", self.binding);
        let mut reference = File::from(
            openat(
                &self.directory,
                ".",
                OFlags::TMPFILE | OFlags::RDWR | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o600),
            )
            .map_err(errno)?,
        );
        reference
            .write_all(format!("{sha256}\n").as_bytes())
            .map_err(io_error)?;
        reference.sync_all().map_err(io_error)?;
        match linkat(
            &reference,
            "",
            &self.directory,
            reference_name.as_str(),
            AtFlags::EMPTY_PATH,
        ) {
            Ok(()) => {}
            Err(rustix::io::Errno::EXIST) => {
                match read_reference(&self.directory, &reference_name) {
                    Ok(bound) if bound == sha256 => {}
                    Ok(bound) => {
                        let bound_name = format!("{}-{bound}.solv", self.binding);
                        match open_content(&self.directory, &self.binding, &bound_name, &bound) {
                            // libsolv serialization may differ with otherwise
                            // irrelevant pool string numbering. A binding
                            // covers semantics, so the first still-valid
                            // content is the canonical concurrent winner.
                            Ok(existing) => return Ok(existing),
                            // A corrupt/missing referenced entry is derived
                            // state. Atomically point the binding at the fully
                            // verified staged replacement.
                            Err(CacheError::Corrupt(_)) => {
                                replace_from_unnamed(&self.directory, &reference, &reference_name)?
                            }
                            Err(error) => return Err(error),
                        }
                    }
                    Err(CacheError::Corrupt(_)) => {
                        replace_from_unnamed(&self.directory, &reference, &reference_name)?;
                    }
                    Err(error) => return Err(error),
                }
            }
            Err(error) => return Err(errno(error)),
        }
        fsync(&self.directory).map_err(errno)?;
        open_cached(&self.directory, &self.binding)?
            .ok_or_else(|| CacheError::Corrupt("committed solv cache disappeared".into()))
    }
}

fn content_matches(
    directory: &OwnedFd,
    name: &str,
    expected_sha256: &str,
    expected_size: u64,
) -> Result<bool, CacheError> {
    let descriptor = match openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(descriptor) => descriptor,
        Err(rustix::io::Errno::NOENT) => return Ok(false),
        Err(error) => return Err(errno(error)),
    };
    if validate_regular(&descriptor).is_err() {
        return Ok(false);
    }
    let mut file = File::from(descriptor);
    Ok(matches!(
        verify_stream(&mut file, Some(expected_sha256)),
        Ok((_, size)) if size == expected_size
    ))
}

fn replace_from_unnamed(
    directory: &OwnedFd,
    source: &File,
    target: &str,
) -> Result<(), CacheError> {
    let identity = fstat(source).map_err(errno)?;
    let repair = format!(
        ".{target}.repair-{}-{}",
        std::process::id(),
        identity.st_ino
    );
    let _ = unlinkat(directory, repair.as_str(), AtFlags::empty());
    linkat(source, "", directory, repair.as_str(), AtFlags::EMPTY_PATH).map_err(errno)?;
    if let Err(error) = renameat(directory, repair.as_str(), directory, target) {
        let _ = unlinkat(directory, repair.as_str(), AtFlags::empty());
        return Err(errno(error));
    }
    fsync(directory).map_err(errno)
}

fn open_directory(path: &Path) -> Result<OwnedFd, CacheError> {
    let fd = open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(errno)?;
    validate_directory(&fd)?;
    Ok(fd)
}

fn open_directory_if_present(path: &Path) -> Result<Option<OwnedFd>, CacheError> {
    let fd = match open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(error) => return Err(errno(error)),
    };
    validate_directory(&fd)?;
    Ok(Some(fd))
}

fn validate_directory(fd: &OwnedFd) -> Result<(), CacheError> {
    let metadata = fstat(fd).map_err(errno)?;
    if metadata.st_mode & 0o170000 != 0o040000
        || metadata.st_mode & 0o022 != 0
        || metadata.st_uid != rustix::process::geteuid().as_raw()
    {
        return Err(CacheError::Corrupt("unsafe solv cache directory".into()));
    }
    Ok(())
}

fn open_cached(directory: &OwnedFd, binding: &str) -> Result<Option<CachedSolv>, CacheError> {
    let reference_name = format!("{binding}.ref");
    let sha256 = match read_reference_if_present(directory, &reference_name)? {
        Some(value) => value,
        None => return Ok(None),
    };
    let content_name = format!("{binding}-{sha256}.solv");
    Ok(Some(open_content(
        directory,
        binding,
        &content_name,
        &sha256,
    )?))
}

fn open_content(
    directory: &OwnedFd,
    binding: &str,
    name: &str,
    expected_sha256: &str,
) -> Result<CachedSolv, CacheError> {
    open_content_inner(directory, binding, name, expected_sha256, true)
}

fn open_content_inner(
    directory: &OwnedFd,
    binding: &str,
    name: &str,
    expected_sha256: &str,
    sync_cookie_directory: bool,
) -> Result<CachedSolv, CacheError> {
    let fd = match openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT) => {
            return Err(CacheError::Corrupt(
                "referenced solv cache content disappeared".into(),
            ));
        }
        Err(error) => return Err(errno(error)),
    };
    validate_regular(&fd)?;
    let before = fstat(&fd).map_err(errno)?;
    let mut file = File::from(fd);
    let cookie_name = format!("{binding}-{expected_sha256}.integrity");
    let cookie = read_integrity_cookie_if_present(directory, &cookie_name)?;
    let (sha256, size, verification) = if let Some(cookie) = cookie {
        if cookie.binding != binding
            || cookie.sha256 != expected_sha256
            || cookie.size != before.st_size as u64
            || cookie.generation != FileGeneration::from_stat(&before)
        {
            return Err(CacheError::Corrupt(
                "solv cache integrity cookie differs from file generation".into(),
            ));
        }
        let verification = match cookie.protection {
            IntegrityProtection::FsVerity(expected) => {
                let measured = dnfast_native_sys::measure_fsverity(&file)
                    .map_err(io_error)?
                    .ok_or_else(|| {
                        CacheError::Corrupt("solv cache verity protection disappeared".into())
                    })?;
                if measured != expected {
                    return Err(CacheError::Corrupt(
                        "solv cache verity digest differs".into(),
                    ));
                }
                SolvVerification::FsVerity
            }
            IntegrityProtection::BtrfsChecksum => {
                if !has_btrfs_checksums(&file)? {
                    return Err(CacheError::Corrupt(
                        "solv cache Btrfs checksum protection disappeared".into(),
                    ));
                }
                SolvVerification::BtrfsChecksum
            }
        };
        file.rewind().map_err(io_error)?;
        (
            expected_sha256.to_owned(),
            before.st_size as u64,
            verification,
        )
    } else {
        let (sha256, size) = verify_stream(&mut file, Some(expected_sha256))?;
        let protection = if dnfast_native_sys::enable_fsverity(&file).map_err(io_error)? {
            Some(IntegrityProtection::FsVerity(
                dnfast_native_sys::measure_fsverity(&file)
                    .map_err(io_error)?
                    .ok_or_else(|| {
                        CacheError::Corrupt("enabled solv cache verity cannot be measured".into())
                    })?,
            ))
        } else if has_btrfs_checksums(&file)? {
            Some(IntegrityProtection::BtrfsChecksum)
        } else {
            None
        };
        let verification = if let Some(protection) = protection {
            let after_hash = fstat(&file).map_err(errno)?;
            if !same_file_generation(&before, &after_hash) {
                return Err(CacheError::Corrupt(
                    "solv cache changed before integrity cookie publication".into(),
                ));
            }
            publish_integrity_cookie(
                directory,
                &cookie_name,
                &IntegrityCookie {
                    binding: binding.to_owned(),
                    sha256: sha256.clone(),
                    size,
                    generation: FileGeneration::from_stat(&after_hash),
                    protection,
                },
                sync_cookie_directory,
            )?;
            match protection {
                IntegrityProtection::FsVerity(_) => SolvVerification::FsVerity,
                IntegrityProtection::BtrfsChecksum => SolvVerification::BtrfsChecksum,
            }
        } else {
            SolvVerification::FullSha256
        };
        (sha256, size, verification)
    };
    let after = fstat(&file).map_err(errno)?;
    if !same_file_generation(&before, &after) {
        return Err(CacheError::Corrupt(
            "solv cache changed while being verified".into(),
        ));
    }
    Ok(CachedSolv {
        file,
        sha256,
        size,
        verification,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileGeneration {
    device: u64,
    inode: u64,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
}

impl FileGeneration {
    fn from_stat(value: &rustix::fs::Stat) -> Self {
        Self {
            device: value.st_dev,
            inode: value.st_ino,
            mtime: value.st_mtime,
            mtime_nsec: value.st_mtime_nsec as i64,
            ctime: value.st_ctime,
            ctime_nsec: value.st_ctime_nsec as i64,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IntegrityProtection {
    FsVerity([u8; 32]),
    BtrfsChecksum,
}

struct IntegrityCookie {
    binding: String,
    sha256: String,
    size: u64,
    generation: FileGeneration,
    protection: IntegrityProtection,
}

fn publish_integrity_cookie(
    directory: &OwnedFd,
    name: &str,
    cookie: &IntegrityCookie,
    sync_directory: bool,
) -> Result<(), CacheError> {
    let (protection, digest) = match cookie.protection {
        IntegrityProtection::FsVerity(digest) => ("fsverity-sha256", hex::encode(digest)),
        IntegrityProtection::BtrfsChecksum => ("btrfs-checksum", "-".into()),
    };
    let value = format!(
        "{INTEGRITY_COOKIE_VERSION} {protection} {} {} {} {} {} {} {} {} {} {digest}\n",
        cookie.binding,
        cookie.sha256,
        cookie.size,
        cookie.generation.device,
        cookie.generation.inode,
        cookie.generation.mtime,
        cookie.generation.mtime_nsec,
        cookie.generation.ctime,
        cookie.generation.ctime_nsec,
    );
    if value.len() as u64 > MAX_INTEGRITY_COOKIE_BYTES {
        return Err(CacheError::Corrupt(
            "solv cache integrity cookie exceeds limit".into(),
        ));
    }
    let mut file = File::from(
        openat(
            directory,
            ".",
            OFlags::TMPFILE | OFlags::RDWR | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .map_err(errno)?,
    );
    file.write_all(value.as_bytes()).map_err(io_error)?;
    file.sync_all().map_err(io_error)?;
    match linkat(&file, "", directory, name, AtFlags::EMPTY_PATH) {
        Ok(()) => {}
        Err(rustix::io::Errno::EXIST) => {
            let existing = read_integrity_cookie(directory, name)?;
            if existing.binding != cookie.binding
                || existing.sha256 != cookie.sha256
                || existing.size != cookie.size
                || existing.generation != cookie.generation
                || existing.protection != cookie.protection
            {
                return Err(CacheError::Corrupt(
                    "solv cache integrity cookie is nondeterministic".into(),
                ));
            }
        }
        Err(error) => return Err(errno(error)),
    }
    if sync_directory {
        fsync(directory).map_err(errno)?;
    }
    Ok(())
}

fn read_integrity_cookie(directory: &OwnedFd, name: &str) -> Result<IntegrityCookie, CacheError> {
    read_integrity_cookie_if_present(directory, name)?
        .ok_or_else(|| CacheError::Corrupt("solv cache integrity cookie disappeared".into()))
}

fn read_integrity_cookie_if_present(
    directory: &OwnedFd,
    name: &str,
) -> Result<Option<IntegrityCookie>, CacheError> {
    let fd = match openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(error) => return Err(errno(error)),
    };
    validate_regular(&fd)?;
    let before = fstat(&fd).map_err(errno)?;
    if before.st_size as u64 > MAX_INTEGRITY_COOKIE_BYTES {
        return Err(CacheError::Corrupt(
            "solv cache integrity cookie exceeds limit".into(),
        ));
    }
    let mut file = File::from(fd);
    let mut value = String::new();
    Read::by_ref(&mut file)
        .take(MAX_INTEGRITY_COOKIE_BYTES + 1)
        .read_to_string(&mut value)
        .map_err(io_error)?;
    let after = fstat(&file).map_err(errno)?;
    if !same_file_generation(&before, &after) || value.len() as i64 != before.st_size {
        return Err(CacheError::Corrupt(
            "solv cache integrity cookie changed while reading".into(),
        ));
    }
    let mut fields = value.split_whitespace();
    if fields.next() != Some(INTEGRITY_COOKIE_VERSION) {
        return Err(CacheError::Corrupt(
            "solv cache integrity cookie version differs".into(),
        ));
    }
    let protection = fields
        .next()
        .ok_or_else(|| CacheError::Corrupt("solv cache protection is absent".into()))?;
    let binding = fields
        .next()
        .ok_or_else(|| CacheError::Corrupt("solv cache integrity binding is absent".into()))?;
    let sha256 = fields
        .next()
        .ok_or_else(|| CacheError::Corrupt("solv cache integrity content is absent".into()))?;
    validate_digest(binding, "solv cache integrity binding")?;
    validate_digest(sha256, "solv cache integrity content")?;
    let size = fields
        .next()
        .and_then(|field| field.parse::<u64>().ok())
        .filter(|size| *size > 0 && *size <= MAX_SOLV_BYTES)
        .ok_or_else(|| CacheError::Corrupt("solv cache integrity size is invalid".into()))?;
    let generation = FileGeneration {
        device: parse_cookie_field(&mut fields, "device")?,
        inode: parse_cookie_field(&mut fields, "inode")?,
        mtime: parse_cookie_field(&mut fields, "mtime")?,
        mtime_nsec: parse_cookie_field(&mut fields, "mtime_nsec")?,
        ctime: parse_cookie_field(&mut fields, "ctime")?,
        ctime_nsec: parse_cookie_field(&mut fields, "ctime_nsec")?,
    };
    let digest = fields
        .next()
        .ok_or_else(|| CacheError::Corrupt("solv cache protection digest is absent".into()))?;
    if fields.next().is_some() || !value.ends_with('\n') {
        return Err(CacheError::Corrupt(
            "solv cache integrity cookie has trailing data".into(),
        ));
    }
    let protection = match protection {
        "fsverity-sha256" => {
            validate_digest(digest, "solv cache verity digest")?;
            let bytes = hex::decode(digest)
                .map_err(|_| CacheError::Corrupt("solv cache verity digest is invalid".into()))?;
            IntegrityProtection::FsVerity(
                bytes.try_into().map_err(|_| {
                    CacheError::Corrupt("solv cache verity digest size differs".into())
                })?,
            )
        }
        "btrfs-checksum" if digest == "-" => IntegrityProtection::BtrfsChecksum,
        _ => {
            return Err(CacheError::Corrupt(
                "solv cache integrity protection is invalid".into(),
            ));
        }
    };
    Ok(Some(IntegrityCookie {
        binding: binding.to_owned(),
        sha256: sha256.to_owned(),
        size,
        generation,
        protection,
    }))
}

fn parse_cookie_field<T: std::str::FromStr>(
    fields: &mut std::str::SplitWhitespace<'_>,
    name: &str,
) -> Result<T, CacheError> {
    fields
        .next()
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| CacheError::Corrupt(format!("solv cache {name} is invalid")))
}

fn has_btrfs_checksums(file: &File) -> Result<bool, CacheError> {
    let filesystem = fstatfs(file).map_err(errno)?;
    if filesystem.f_type as u64 != BTRFS_SUPER_MAGIC {
        return Ok(false);
    }
    let flags = ioctl_getflags(file).map_err(errno)?;
    Ok(!flags.contains(IFlags::NOCOW))
}

fn same_file_generation(before: &rustix::fs::Stat, after: &rustix::fs::Stat) -> bool {
    before.st_dev == after.st_dev
        && before.st_ino == after.st_ino
        && before.st_size == after.st_size
        && before.st_mtime == after.st_mtime
        && before.st_mtime_nsec == after.st_mtime_nsec
        && before.st_ctime == after.st_ctime
        && before.st_ctime_nsec == after.st_ctime_nsec
}

fn read_reference(directory: &OwnedFd, name: &str) -> Result<String, CacheError> {
    read_reference_if_present(directory, name)?
        .ok_or_else(|| CacheError::Corrupt("solv cache reference disappeared".into()))
}

fn read_reference_if_present(
    directory: &OwnedFd,
    name: &str,
) -> Result<Option<String>, CacheError> {
    let fd = match openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(error) => return Err(errno(error)),
    };
    validate_regular(&fd)?;
    let before = fstat(&fd).map_err(errno)?;
    let mut file = File::from(fd);
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(66)
        .read_to_end(&mut bytes)
        .map_err(io_error)?;
    let after = fstat(&file).map_err(errno)?;
    if bytes.len() != 65
        || bytes[64] != b'\n'
        || before.st_dev != after.st_dev
        || before.st_ino != after.st_ino
        || before.st_size != after.st_size
    {
        return Err(CacheError::Corrupt(
            "solv cache reference is invalid".into(),
        ));
    }
    let value = std::str::from_utf8(&bytes[..64])
        .map_err(|_| CacheError::Corrupt("solv cache reference is not UTF-8".into()))?;
    validate_digest(value, "solv cache content")?;
    Ok(Some(value.into()))
}

fn validate_regular(fd: &OwnedFd) -> Result<(), CacheError> {
    let metadata = fstat(fd).map_err(errno)?;
    if metadata.st_mode & 0o170000 != 0o100000
        || metadata.st_mode & 0o022 != 0
        || metadata.st_uid != rustix::process::geteuid().as_raw()
        || metadata.st_nlink != 1
        || metadata.st_size <= 0
        || metadata.st_size as u64 > MAX_SOLV_BYTES
    {
        return Err(CacheError::Corrupt("unsafe solv cache file".into()));
    }
    Ok(())
}

fn verify_stream(
    file: &mut File,
    expected_sha256: Option<&str>,
) -> Result<(String, u64), CacheError> {
    file.rewind().map_err(io_error)?;
    let mut digest = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer).map_err(io_error)?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(count as u64)
            .ok_or_else(|| CacheError::Corrupt("solv cache size overflow".into()))?;
        if total > MAX_SOLV_BYTES {
            return Err(CacheError::Corrupt("solv cache exceeds limit".into()));
        }
        digest.update(&buffer[..count]);
    }
    if total == 0 {
        return Err(CacheError::Corrupt("solv cache is empty".into()));
    }
    let actual = hex::encode(digest.finalize());
    if expected_sha256.is_some_and(|expected| expected != actual) {
        return Err(CacheError::Corrupt("solv cache digest differs".into()));
    }
    file.rewind().map_err(io_error)?;
    Ok((actual, total))
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
    use std::io::Write;

    use sha2::{Digest, Sha256};

    use super::SolvCache;

    fn binding() -> String {
        hex::encode(Sha256::digest(b"binding"))
    }

    #[test]
    fn cache_round_trip_uses_fail_closed_verification() {
        let root = tempfile::tempdir().expect("cache root");
        let cache = SolvCache::new(root.path());
        let staged = cache.stage(&binding()).expect("stage");
        staged.file().write_all(b"solv payload").expect("write");
        let committed = staged.commit().expect("commit");
        assert_eq!(committed.size(), 12);
        assert_eq!(cache.open(&binding()).expect("open").unwrap().size(), 12);
    }

    #[test]
    fn absent_cache_is_a_clean_miss() {
        let root = tempfile::tempdir().expect("cache root");
        assert!(
            SolvCache::new(root.path())
                .open(&binding())
                .expect("cache miss")
                .is_none()
        );
    }

    #[test]
    fn cache_rejects_content_tampering() {
        let root = tempfile::tempdir().expect("cache root");
        let cache = SolvCache::new(root.path());
        let staged = cache.stage(&binding()).expect("stage");
        staged.file().write_all(b"solv payload").expect("write");
        let digest = staged.commit().expect("commit").sha256().to_owned();
        let path = root
            .path()
            .join("solv-v1")
            .join(format!("{}-{digest}.solv", binding()));
        std::fs::remove_file(&path).expect("remove immutable cache entry");
        std::fs::write(path, b"evil payload").expect("replace cache entry");
        assert!(cache.open(&binding()).is_err());
        let repaired = cache.stage(&binding()).expect("repair stage");
        repaired
            .file()
            .write_all(b"solv payload")
            .expect("repair write");
        repaired.commit().expect("atomic content repair");
        assert_eq!(cache.open(&binding()).unwrap().unwrap().size(), 12);
    }

    #[test]
    fn cache_rejects_integrity_cookie_tampering_when_supported() {
        let root = tempfile::tempdir().expect("cache root");
        let cache = SolvCache::new(root.path());
        let staged = cache.stage(&binding()).expect("stage");
        staged.file().write_all(b"solv payload").expect("write");
        let digest = staged.commit().expect("commit").sha256().to_owned();
        let path = root
            .path()
            .join("solv-v1")
            .join(format!("{}-{digest}.integrity", binding()));
        if path.exists() {
            std::fs::remove_file(&path).expect("remove integrity cookie");
            std::fs::write(&path, b"corrupt\n").expect("replace integrity cookie");
            assert!(cache.open(&binding()).is_err());
            let repaired = cache.stage(&binding()).expect("repair stage");
            repaired
                .file()
                .write_all(b"solv payload")
                .expect("repair write");
            repaired.commit().expect("atomic cookie repair");
            assert_eq!(cache.open(&binding()).unwrap().unwrap().size(), 12);
        }
    }

    #[test]
    fn concurrent_staging_keeps_the_first_valid_binding_content() {
        let root = tempfile::tempdir().expect("cache root");
        let cache = SolvCache::new(root.path());
        let first = cache.stage(&binding()).expect("first stage");
        let second = cache.stage(&binding()).expect("second stage");
        first
            .file()
            .write_all(b"same payload")
            .expect("first write");
        second
            .file()
            .write_all(b"same payload")
            .expect("second write");
        let first = first.commit().expect("first commit");
        let second = second.commit().expect("second commit");
        assert_eq!(first.sha256(), second.sha256());

        let conflicting = cache.stage(&binding()).expect("conflicting stage");
        conflicting
            .file()
            .write_all(b"different payload")
            .expect("conflicting write");
        let winner = conflicting.commit().expect("existing semantic winner");
        assert_eq!(winner.sha256(), first.sha256());
        assert_eq!(
            cache.open(&binding()).unwrap().unwrap().sha256(),
            first.sha256()
        );
    }

    #[test]
    fn corrupt_binding_can_be_atomically_repaired_with_different_serialization() {
        let root = tempfile::tempdir().expect("cache root");
        let cache = SolvCache::new(root.path());
        let first = cache.stage(&binding()).expect("first stage");
        first.file().write_all(b"first payload").expect("write");
        let first_sha256 = first.commit().expect("first commit").sha256().to_owned();
        let first_path = root
            .path()
            .join("solv-v1")
            .join(format!("{}-{first_sha256}.solv", binding()));
        std::fs::remove_file(&first_path).expect("remove first content");
        std::fs::write(&first_path, b"corrupt payload").expect("replace first content");
        assert!(cache.open(&binding()).is_err());

        let replacement = cache.stage(&binding()).expect("replacement stage");
        replacement
            .file()
            .write_all(b"second valid serialization")
            .expect("replacement write");
        let replacement = replacement.commit().expect("atomic replacement");
        assert_ne!(replacement.sha256(), first_sha256);
        assert_eq!(
            cache.open(&binding()).unwrap().unwrap().sha256(),
            replacement.sha256()
        );
    }
}
