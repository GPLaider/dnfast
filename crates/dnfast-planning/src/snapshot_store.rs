use std::{
    fs,
    io::Write,
    os::{
        fd::{AsFd, AsRawFd},
        unix::fs::PermissionsExt,
    },
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use sha2::Digest;

use crate::{PlanningError, PlanningRoots, PlanningSnapshot, fs::TrustedDirectory};

const CURRENT_POINTER: &str = "current";
const SNAPSHOT_FILE: &str = "snapshot.json";
const MAX_SNAPSHOT_BYTES: usize = 128 * 1024 * 1024;
const MAX_RETAINED_SNAPSHOTS: usize = 8;

pub(crate) fn open_snapshot(
    roots: &PlanningRoots,
    owner: u32,
) -> Result<PlanningSnapshot, PlanningError> {
    let planning = TrustedDirectory::open(roots.planning_root(), owner, false, 0)?;
    let digest = pointer_digest(&planning.read(CURRENT_POINTER, 65)?)?;
    let snapshots = planning.child("snapshots", false, 0)?;
    let snapshot = snapshots.child(&digest, false, 0)?;
    let bytes = snapshot.read(SNAPSHOT_FILE, MAX_SNAPSHOT_BYTES)?;
    let mut result = PlanningSnapshot::from_canonical_bytes(&bytes)?;
    if result.digest()? != digest {
        return Err(PlanningError::UnsafeSnapshot(
            "pointer digest differs from payload".into(),
        ));
    }
    result.attach_storage(roots.planning_root(), owner);
    Ok(result)
}

pub(crate) fn publish_blob(
    planning: &TrustedDirectory,
    digest: &str,
    bytes: &[u8],
) -> Result<(), PlanningError> {
    if !valid_digest(digest) || format!("{:x}", sha2::Sha256::digest(bytes)) != digest {
        return Err(PlanningError::UnsafeSnapshot(
            "planning blob digest differs from payload".into(),
        ));
    }
    let blobs = planning.child("blobs", true, 0o755)?;
    let sha256 = blobs.child("sha256", true, 0o755)?;
    if let Some(existing) = sha256.read_if_present(digest, bytes.len())? {
        if existing != bytes {
            return Err(PlanningError::UnsafeSnapshot(
                "immutable planning blob digest collision".into(),
            ));
        }
        return Ok(());
    }
    let temporary = format!(
        "/proc/self/fd/{}/.blob-{digest}-{}-{}",
        sha256.fd().as_fd().as_raw_fd(),
        std::process::id(),
        now_nanos()?
    );
    write_file(Path::new(&temporary), bytes)?;
    let target = format!(
        "/proc/self/fd/{}/{}",
        sha256.fd().as_fd().as_raw_fd(),
        digest
    );
    match fs::rename(&temporary, &target) {
        Ok(()) => sha256.sync(),
        Err(_error) if sha256.read_if_present(digest, bytes.len())?.is_some() => {
            fs::remove_file(&temporary).map_err(io)?;
            let existing = sha256.read(digest, bytes.len())?;
            if existing != bytes {
                return Err(PlanningError::UnsafeSnapshot(
                    "immutable planning blob digest collision".into(),
                ));
            }
            Ok(())
        }
        Err(error) => Err(io(error)),
    }
}

pub(crate) fn read_blob(
    planning_root: &Path,
    owner: u32,
    digest: &str,
    size: u64,
) -> Result<Vec<u8>, PlanningError> {
    if !valid_digest(digest) {
        return Err(PlanningError::UnsafeSnapshot(
            "invalid planning blob digest".into(),
        ));
    }
    let maximum = usize::try_from(size)
        .map_err(|error| PlanningError::UnsafeSnapshot(error.to_string()))?
        .checked_add(1)
        .ok_or_else(|| PlanningError::UnsafeSnapshot("planning blob size overflow".into()))?;
    let planning = TrustedDirectory::open(planning_root, owner, false, 0)?;
    let blobs = planning.child("blobs", false, 0)?;
    let sha256 = blobs.child("sha256", false, 0)?;
    sha256.read(digest, maximum)
}

pub(crate) fn current_digest(roots: &PlanningRoots, owner: u32) -> Result<String, PlanningError> {
    let planning = TrustedDirectory::open(roots.planning_root(), owner, false, 0)?;
    pointer_digest(&planning.read(CURRENT_POINTER, 65)?)
}

pub(crate) fn publish_snapshot(
    planning: &TrustedDirectory,
    snapshots: &TrustedDirectory,
    digest: &str,
    bytes: &[u8],
) -> Result<(), PlanningError> {
    if snapshot_exists(snapshots, digest)? {
        let existing = snapshots
            .child(digest, false, 0)?
            .read(SNAPSHOT_FILE, MAX_SNAPSHOT_BYTES)?;
        if existing != bytes {
            return Err(PlanningError::UnsafeSnapshot(
                "immutable snapshot digest collision".into(),
            ));
        }
    } else {
        let staging_name = format!(".staging-{digest}-{}-{}", std::process::id(), now_nanos()?);
        let staging_path = format!(
            "/proc/self/fd/{}/{}",
            snapshots.fd().as_fd().as_raw_fd(),
            staging_name
        );
        fs::create_dir(&staging_path).map_err(io)?;
        fs::set_permissions(&staging_path, fs::Permissions::from_mode(0o755)).map_err(io)?;
        write_file(&Path::new(&staging_path).join(SNAPSHOT_FILE), bytes)?;
        fs::File::open(&staging_path)
            .map_err(io)?
            .sync_all()
            .map_err(io)?;
        let target = format!(
            "/proc/self/fd/{}/{}",
            snapshots.fd().as_fd().as_raw_fd(),
            digest
        );
        match fs::rename(&staging_path, &target) {
            Ok(()) => snapshots.sync()?,
            Err(_error) if snapshot_exists(snapshots, digest)? => {
                fs::remove_dir_all(&staging_path).map_err(io)?
            }
            Err(error) => return Err(PlanningError::Io(error.to_string())),
        }
    }
    let temporary = format!(
        "/proc/self/fd/{}/.current-{}-{}",
        planning.fd().as_fd().as_raw_fd(),
        std::process::id(),
        now_nanos()?
    );
    write_file(Path::new(&temporary), format!("{digest}\n").as_bytes())?;
    fs::rename(
        &temporary,
        format!(
            "/proc/self/fd/{}/{}",
            planning.fd().as_fd().as_raw_fd(),
            CURRENT_POINTER
        ),
    )
    .map_err(io)?;
    planning.sync()
}

pub(crate) fn garbage_collect(
    snapshots: &TrustedDirectory,
    current: &str,
) -> Result<(), PlanningError> {
    snapshots.recheck()?;
    let directory = format!("/proc/self/fd/{}", snapshots.fd().as_fd().as_raw_fd());
    let mut entries = fs::read_dir(&directory)
        .map_err(io)?
        .map(|entry| entry.map_err(io))
        .collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| {
        std::cmp::Reverse(entry.metadata().and_then(|value| value.modified()).ok())
    });
    for entry in entries.into_iter().skip(MAX_RETAINED_SNAPSHOTS) {
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| PlanningError::UnsafeSnapshot("non-UTF-8 snapshot name".into()))?;
        if name == current || !valid_digest(&name) {
            continue;
        }
        let snapshot = snapshots.child(&name, false, 0)?;
        let _ = snapshot.read(SNAPSHOT_FILE, MAX_SNAPSHOT_BYTES)?;
        fs::remove_file(entry.path().join(SNAPSHOT_FILE)).map_err(io)?;
        fs::remove_dir(entry.path()).map_err(io)?;
    }
    snapshots.recheck()
}

fn snapshot_exists(snapshots: &TrustedDirectory, digest: &str) -> Result<bool, PlanningError> {
    if !valid_digest(digest) {
        return Err(PlanningError::UnsafeSnapshot(
            "invalid snapshot digest".into(),
        ));
    }
    Ok(snapshots.child_if_present(digest)?.is_some())
}

fn pointer_digest(pointer: &[u8]) -> Result<String, PlanningError> {
    if pointer.len() != 65
        || pointer[64] != b'\n'
        || !pointer[..64]
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(PlanningError::UnsafeSnapshot(
            "pointer is not a canonical digest".into(),
        ));
    }
    std::str::from_utf8(&pointer[..64])
        .map(str::to_owned)
        .map_err(|error| PlanningError::UnsafeSnapshot(error.to_string()))
}

fn write_file(path: &Path, bytes: &[u8]) -> Result<(), PlanningError> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    let mut file = options.open(path).map_err(io)?;
    file.write_all(bytes).map_err(io)?;
    file.sync_all().map_err(io)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o644)).map_err(io)
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn now_nanos() -> Result<u128, PlanningError> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| PlanningError::Io(error.to_string()))?
        .as_nanos())
}
fn io(error: std::io::Error) -> PlanningError {
    PlanningError::Io(error.to_string())
}
