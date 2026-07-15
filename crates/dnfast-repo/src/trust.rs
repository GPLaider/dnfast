use std::path::{Component, Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::{anchored_fs::{read_root_file, read_system_gpg_key}, MutationError};

const DOMAIN: &[u8] = b"dnfast-key-bundle-v1";
const MAX_KEY_FILES: usize = 256;
const MAX_KEY_BYTES: u64 = 1_048_576;
const SYSTEM_KEY_DIRECTORY: &str = "/etc/pki/rpm-gpg";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyBundle { pub paths: Vec<PathBuf>, pub digest: [u8; 32], pub certificates: Vec<Vec<u8>> }

#[cfg(test)]
mod system_key_tests {
    use super::*;
    use std::{fs, os::unix::fs::{symlink, MetadataExt, PermissionsExt}, time::{SystemTime, UNIX_EPOCH}};

    fn temporary_directory(label: &str) -> PathBuf {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH).expect("clock must be available").as_nanos();
        let path = PathBuf::from(std::env::var_os("HOME").expect("HOME must identify the test user's trusted directory"))
            .join(format!("dnfast-system-gpg-{label}-{}-{nonce}", std::process::id()));
        fs::create_dir(&path).expect("fixture directory must be created");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("fixture mode must be trusted");
        path
    }

    #[test]
    fn system_gpg_file_uri_and_root_owned_alias_are_accepted_without_losing_per_repo_binding() {
        // Given a Fedora-shaped file URI whose root-owned alias resolves to a regular key in the fixed system directory.
        let directory = temporary_directory("alias");
        let key = directory.join("fedora-primary");
        fs::write(&key, b"primary certificate").expect("key must be written");
        fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).expect("key mode must be trusted");
        let alias = directory.join("fedora-aarch64");
        symlink("fedora-primary", &alias).expect("relative system alias must be created");
        let owner = fs::metadata(&directory).expect("fixture metadata must exist").uid();

        // When the gpgkey URI is normalized and read through the bounded system-key resolver.
        let normalized = normalize_gpgkey_location(&format!("file://{}", alias.display())).expect("file URI must normalize");
        let bundle = key_bundle_digest_owned("fedora", &[normalized.clone()], Path::new("/etc/dnfast/keys"), owner, Some(&directory))
            .expect("root-owned system alias must resolve inside its trusted directory");

        // Then the original normalized path remains part of the per-repository v3 bundle framing.
        assert_eq!(bundle.paths, [normalized]);
        assert_eq!(bundle.certificates, [b"primary certificate".to_vec()]);
        fs::remove_dir_all(directory).expect("fixture must be removed");
    }

    #[test]
    fn system_gpg_rejects_url_outside_user_owned_and_escaping_symlink_before_trust_can_change() {
        // Given local roots, an out-of-directory file, and an alias that escapes the fixed system key directory.
        let directory = temporary_directory("reject");
        let key = directory.join("primary");
        fs::write(&key, b"primary").expect("key must be written");
        fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).expect("key mode must be trusted");
        let outside = directory.with_extension("outside");
        fs::write(&outside, b"outside").expect("outside fixture must be written");
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o644)).expect("outside mode must be trusted");
        let escaping = directory.join("escape");
        symlink("../dnfast-system-gpg-reject-outside", &escaping).expect("escaping alias must be created");
        let owner = fs::metadata(&directory).expect("fixture metadata must exist").uid();

        // When non-local URLs, direct outside paths, root-owner mismatches, or escaping aliases enter the key boundary.
        let url = normalize_gpgkey_location("https://untrusted.example.invalid/key");
        let direct_outside = key_bundle_digest_owned("fedora", &[outside.clone()], Path::new("/etc/dnfast/keys"), owner, Some(&directory));
        let user_owned = key_bundle_digest_owned("fedora", &[key], Path::new("/etc/dnfast/keys"), 0, Some(&directory));
        let escaping_alias = key_bundle_digest_owned("fedora", &[escaping], Path::new("/etc/dnfast/keys"), owner, Some(&directory));

        // Then none can supply a certificate or alter a repository trust bundle.
        assert!(url.is_err());
        assert!(direct_outside.is_err());
        assert!(user_owned.is_err());
        assert!(escaping_alias.is_err());
        fs::remove_dir_all(&directory).expect("fixture must be removed");
        fs::remove_file(outside).expect("outside fixture must be removed");
    }
}

pub fn key_bundle_digest(repo_id: &str, paths: &[PathBuf]) -> Result<KeyBundle, MutationError> {
    key_bundle_digest_owned(repo_id, paths, Path::new("/etc/dnfast/keys"), 0, Some(Path::new(SYSTEM_KEY_DIRECTORY)))
}

pub fn normalize_gpgkey_location(value: &str) -> Result<PathBuf, MutationError> {
    let label = Path::new("<gpgkey>");
    let path = if let Some(suffix) = value.strip_prefix("file:///") {
        if suffix.is_empty() || suffix.starts_with('/') { return Err(MutationError::new(label, 0, "gpgkey file URI is invalid")); }
        Path::new("/").join(suffix)
    } else if value.starts_with("file:") || value.contains("://") {
        return Err(MutationError::new(label, 0, "gpgkey is not a local file URI"));
    } else {
        PathBuf::from(value)
    };
    if !path.is_absolute() || path.components().any(|part| matches!(part, Component::ParentDir | Component::CurDir)) {
        return Err(MutationError::new(label, 0, "gpgkey is not an absolute local path"));
    }
    Ok(path)
}

pub fn validate_gpgkey_bundle_path(repository: &str, path: &str) -> Result<(), MutationError> {
    if !valid_id(repository) { return Err(MutationError::new(Path::new("<gpgkey>"), 0, "invalid repository id")); }
    validate_lexical_path(
        Path::new("<gpgkey>"),
        Path::new(path),
        &Path::new("/etc/dnfast/keys").join(repository),
        Some(Path::new(SYSTEM_KEY_DIRECTORY)),
    )?;
    Ok(())
}

fn key_bundle_digest_owned(repo_id: &str, paths: &[PathBuf], parent: &Path, owner: u32, system_directory: Option<&Path>) -> Result<KeyBundle, MutationError> {
    let label = Path::new("<gpgkey>");
    if !valid_id(repo_id) { return Err(MutationError::new(label, 0, "invalid repository id")); }
    if paths.len() > MAX_KEY_FILES { return Err(MutationError::new(label, 0, "gpgkey file limit exceeds 256")); }
    let root = parent.join(repo_id);
    let mut seen = std::collections::BTreeSet::new();
    let mut digest = Sha256::new();
    let mut certificates = Vec::with_capacity(paths.len());
    digest.update(DOMAIN);
    for path in paths {
        if !seen.insert(path) { return Err(MutationError::new(label, 0, "duplicate gpgkey path")); }
        let bytes = match validate_lexical_path(label, path, &root, system_directory)? {
            KeyLocation::Repository => read_root_file(path, MAX_KEY_BYTES, owner),
            KeyLocation::System(directory) => read_system_gpg_key(path, directory, MAX_KEY_BYTES, owner),
        }.map_err(|_| MutationError::new(path, 0, "untrusted or oversized gpgkey"))?;
        let encoded = path.to_str().ok_or_else(|| MutationError::new(label, 0, "gpgkey path is not UTF-8"))?.as_bytes();
        digest.update(u64::try_from(encoded.len()).map_err(|_| MutationError::new(label, 0, "gpgkey path too long"))?.to_be_bytes());
        digest.update(encoded);
        digest.update(u64::try_from(bytes.len()).map_err(|_| MutationError::new(label, 0, "gpgkey file too large"))?.to_be_bytes());
        digest.update(&bytes);
        certificates.push(bytes);
    }
    Ok(KeyBundle { paths: paths.to_vec(), digest: digest.finalize().into(), certificates })
}

enum KeyLocation<'a> {
    Repository,
    System(&'a Path),
}

fn validate_lexical_path<'a>(label: &Path, path: &Path, root: &Path, system_directory: Option<&'a Path>) -> Result<KeyLocation<'a>, MutationError> {
    if path.to_str().is_none() { return Err(MutationError::new(label, 0, "gpgkey path is not UTF-8")); }
    if !path.is_absolute() || path.components().any(|part| matches!(part, Component::ParentDir | Component::CurDir)) {
        return Err(MutationError::new(label, 0, "gpgkey path is not absolute and canonical"));
    }
    if path.starts_with(root) && path != root { return Ok(KeyLocation::Repository); }
    if let Some(directory) = system_directory
        && path.parent() == Some(directory)
        && path.file_name().is_some()
    {
        return Ok(KeyLocation::System(directory));
    }
    Err(MutationError::new(label, 0, "gpgkey path is outside trusted key directories"))
}

fn valid_id(id: &str) -> bool { !id.is_empty() && id.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte)) }

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::{MetadataExt, PermissionsExt}, time::{SystemTime, UNIX_EPOCH}};

    #[test]
    fn digest_bytes_order_size_and_count_boundaries() {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let parent = PathBuf::from(std::env::var_os("HOME").expect("HOME must identify the test user's trusted directory"))
            .join(format!("dnfast-key-test-{nonce}"));
        let root = parent.join("repo");
        fs::create_dir_all(&root).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let owner = fs::metadata(&root).unwrap().uid();
        let paths = (0..256).map(|index| {
            let path = root.join(format!("{index:03}.gpg"));
            fs::write(&path, if index == 0 { vec![b'x'; 1_048_576] } else { vec![index as u8] }).unwrap();
            path
        }).collect::<Vec<_>>();
        let bundle = key_bundle_digest_owned("repo", &paths, &parent, owner, None).unwrap();
        assert_ne!(bundle.digest, key_bundle_digest_owned("repo", &paths.iter().rev().cloned().collect::<Vec<_>>(), &parent, owner, None).unwrap().digest);
        assert!(key_bundle_digest_owned("repo", &[paths.clone(), vec![paths[0].clone()]].concat(), &parent, owner, None).is_err());
        fs::write(&paths[0], vec![b'x'; 1_048_577]).unwrap();
        assert!(key_bundle_digest_owned("repo", &paths, &parent, owner, None).is_err());
        fs::remove_dir_all(parent).unwrap();
    }
}
