use std::{
    collections::BTreeSet,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    process::Command,
};

use crate::{
    MutationError, MutationProfile, Variables, anchored_fs, key_bundle_digest, parse_main_config,
    parse_repo_profile, profile::expand_variables, trust::primary_certificate_fingerprints,
};

const MAIN_PATH: &str = "/etc/dnf/dnf.conf";
const MAX_CONFIG_FILES: usize = 256;
const TRUSTED_RPM_PATH: &str = "/usr/bin/rpm";

struct SystemVariables {
    releasever: String,
    basearch: String,
}

pub fn load_mutation_profile() -> Result<MutationProfile, MutationError> {
    load_mutation_profile_owned(Path::new(MAIN_PATH), 0, None)
}

pub fn load_system_mutation_profile() -> Result<MutationProfile, MutationError> {
    let variables = system_variables_from_rpm()?;
    load_mutation_profile_owned(Path::new(MAIN_PATH), 0, Some(variables))
}

pub fn load_mutation_profile_from(main_path: &Path) -> Result<MutationProfile, MutationError> {
    let owner = std::fs::symlink_metadata(main_path)
        .map_err(|_| MutationError::new(main_path, 0, "cannot inspect main configuration"))?
        .uid();
    load_mutation_profile_owned(main_path, owner, None)
}

fn load_mutation_profile_owned(
    main_path: &Path,
    owner: u32,
    system_variables: Option<SystemVariables>,
) -> Result<MutationProfile, MutationError> {
    let bind_system_certificate_fingerprints = system_variables.is_some();
    let main_text = read_root_file(main_path, owner)?;
    let main = parse_main_config(main_path, &main_text)?;
    let (variables, variable_count) = load_variable_sources(&main.varsdir, owner)?;
    let variables = match system_variables {
        Some(system) => variables.with_system_release_and_arch(system.releasever, system.basearch),
        None => variables,
    };
    let paths = repository_paths(&main.reposdir, variable_count + 1, owner)?;
    let mut output = MutationProfile {
        main: main.clone(),
        repositories: Vec::new(),
        variables: Variables::default(),
    };
    let mut ids = BTreeSet::new();
    for path in paths {
        let text = read_root_file(&path, owner)?;
        let parsed = parse_repo_profile(&path, &text, &main)?;
        for repo in parsed.repositories {
            if !ids.insert(repo.id.clone()) {
                return Err(MutationError::new(
                    &path,
                    0,
                    "duplicate repository id across files",
                ));
            }
            if ids.len() > 1024 {
                return Err(MutationError::new(
                    &path,
                    0,
                    "repository limit exceeds 1024",
                ));
            }
            output.repositories.push(repo);
        }
    }
    expand_variables(&mut output, variables)?;
    for repo in &mut output.repositories {
        if !repo.enabled {
            repo.key_bundle_digest = None;
            continue;
        }
        let key_paths = repo.gpgkey.iter().map(PathBuf::from).collect::<Vec<_>>();
        let bundle = key_bundle_digest(&repo.id, &key_paths)?;
        if bind_system_certificate_fingerprints && !bundle.certificates.is_empty() {
            let bundled = primary_certificate_fingerprints(&bundle.certificates)?;
            if repo.allowed_fingerprints.is_empty() {
                repo.allowed_fingerprints = bundled;
            } else {
                let available = bundled.into_iter().collect::<BTreeSet<_>>();
                if repo
                    .allowed_fingerprints
                    .iter()
                    .any(|fingerprint| !available.contains(&fingerprint.to_ascii_uppercase()))
                {
                    return Err(MutationError::new(
                        Path::new("<gpgkey>"),
                        0,
                        "allowed fingerprint is absent from the repository key bundle",
                    ));
                }
            }
        }
        repo.key_bundle_digest = Some(bundle.digest);
    }
    Ok(output)
}

fn system_variables_from_rpm() -> Result<SystemVariables, MutationError> {
    let releasever = trusted_rpm_evaluate("%{?fedora}")?;
    let basearch = trusted_rpm_evaluate("%{_arch}")?;
    system_variables_from_values(&releasever, &basearch)
}

fn trusted_rpm_evaluate(expression: &str) -> Result<String, MutationError> {
    let executable = Path::new(TRUSTED_RPM_PATH);
    anchored_fs::validate_root_executable(executable, 0)?;
    let output = Command::new(executable)
        .env_clear()
        .args(["--eval", expression])
        .output()
        .map_err(|_| {
            MutationError::new(executable, 0, "cannot evaluate trusted RPM system variable")
        })?;
    if !output.status.success() {
        return Err(MutationError::new(
            executable,
            0,
            "trusted RPM system variable evaluation failed",
        ));
    }
    String::from_utf8(output.stdout)
        .map(|value| value.trim_end_matches(['\n', '\r']).to_owned())
        .map_err(|_| {
            MutationError::new(
                executable,
                0,
                "trusted RPM system variable is not valid UTF-8",
            )
        })
}

fn system_variables_from_values(
    releasever: &str,
    basearch: &str,
) -> Result<SystemVariables, MutationError> {
    if releasever.is_empty()
        || releasever.len() > 32
        || !releasever.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(MutationError::new(
            Path::new("<system-rpm>"),
            0,
            "invalid Fedora releasever",
        ));
    }
    if !matches!(basearch, "aarch64" | "x86_64") {
        return Err(MutationError::new(
            Path::new("<system-rpm>"),
            0,
            "unsupported RPM base architecture",
        ));
    }
    Ok(SystemVariables {
        releasever: releasever.into(),
        basearch: basearch.into(),
    })
}

#[cfg(test)]
fn load_system_mutation_profile_from_with_values(
    main_path: &Path,
    releasever: &str,
    basearch: &str,
) -> Result<MutationProfile, MutationError> {
    let owner = std::fs::symlink_metadata(main_path)
        .map_err(|_| MutationError::new(main_path, 0, "cannot inspect main configuration"))?
        .uid();
    load_mutation_profile_owned(
        main_path,
        owner,
        Some(system_variables_from_values(releasever, basearch)?),
    )
}

fn repository_paths(
    directories: &[PathBuf],
    prior_count: usize,
    owner: u32,
) -> Result<Vec<PathBuf>, MutationError> {
    let mut paths = Vec::new();
    for directory in directories {
        if !directory.exists() {
            continue;
        }
        if let Err(error) = validate_root_metadata(directory, true, owner) {
            if owner != 0 {
                continue;
            }
            return Err(error);
        }
        for entry in std::fs::read_dir(directory)
            .map_err(|_| MutationError::new(directory, 0, "cannot read repository directory"))?
        {
            let path = entry
                .map_err(|_| MutationError::new(directory, 0, "cannot read repository entry"))?
                .path();
            let metadata = std::fs::symlink_metadata(&path)
                .map_err(|_| MutationError::new(&path, 0, "cannot inspect repository entry"))?;
            if path
                .extension()
                .is_some_and(|extension| extension == "repo")
                && metadata.is_file()
                && !metadata.file_type().is_symlink()
            {
                paths.push(path);
            }
        }
    }
    paths.sort_by(|left, right| {
        left.as_os_str()
            .as_encoded_bytes()
            .cmp(right.as_os_str().as_encoded_bytes())
    });
    if paths.len() + prior_count > MAX_CONFIG_FILES {
        return Err(MutationError::new(
            Path::new("<reposdir>"),
            0,
            "configuration file limit exceeds 256",
        ));
    }
    Ok(paths)
}

fn load_variable_sources(
    directories: &[PathBuf],
    owner: u32,
) -> Result<(Variables, usize), MutationError> {
    let mut count = 0;
    let mut pairs = Vec::new();
    for directory in directories {
        if !directory.exists() {
            continue;
        }
        if let Err(error) = validate_root_metadata(directory, true, owner) {
            if owner != 0 {
                continue;
            }
            return Err(error);
        }
        let mut paths = std::fs::read_dir(directory)
            .map_err(|_| MutationError::new(directory, 0, "cannot read variables directory"))?
            .map(|entry| {
                entry
                    .map(|value| value.path())
                    .map_err(|_| MutationError::new(directory, 0, "cannot read variable entry"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        paths.sort_by(|left, right| {
            left.as_os_str()
                .as_encoded_bytes()
                .cmp(right.as_os_str().as_encoded_bytes())
        });
        for path in paths {
            validate_root_metadata(&path, false, owner)?;
            let name = path
                .file_name()
                .and_then(|value| value.to_str())
                .ok_or_else(|| MutationError::new(&path, 0, "variable filename is not UTF-8"))?;
            if !name
                .bytes()
                .all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
            {
                return Err(MutationError::new(&path, 0, "invalid variable filename"));
            }
            pairs.push((
                name.to_owned(),
                read_root_file(&path, owner)?.trim().to_owned(),
            ));
            count += 1;
            if count + 1 > MAX_CONFIG_FILES {
                return Err(MutationError::new(
                    &path,
                    0,
                    "configuration file limit exceeds 256",
                ));
            }
        }
    }
    Ok((Variables::from_pairs(pairs), count))
}

fn validate_root_metadata(
    path: &Path,
    directory: bool,
    owner: u32,
) -> Result<std::fs::Metadata, MutationError> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| MutationError::new(path, 0, "cannot inspect root configuration source"))?;
    if metadata.file_type().is_symlink()
        || metadata.uid() != owner
        || metadata.mode() & 0o022 != 0
        || directory != metadata.is_dir()
    {
        return Err(MutationError::new(
            path,
            0,
            "untrusted root configuration source",
        ));
    }
    Ok(metadata)
}

fn read_root_file(path: &Path, owner: u32) -> Result<String, MutationError> {
    let bytes = anchored_fs::read_root_file(path, 1_048_576, owner)?;
    String::from_utf8(bytes)
        .map_err(|_| MutationError::new(path, 0, "configuration source is not valid UTF-8"))
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        path::{Path, PathBuf},
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::{load_system_mutation_profile_from_with_values, system_variables_from_values};

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock must be available")
                .as_nanos();
            let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!(
                ".dnfast-system-vars-{}-{nonce}",
                std::process::id()
            ));
            fs::create_dir(&root).expect("fixture root must be created");
            fs::set_permissions(&root, fs::Permissions::from_mode(0o755))
                .expect("fixture root mode must be set");
            Self(root)
        }

        fn directory(&self, name: &str) -> PathBuf {
            let path = self.0.join(name);
            fs::create_dir(&path).expect("fixture directory must be created");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755))
                .expect("fixture directory mode must be set");
            path
        }

        fn file(path: &Path, contents: &str) {
            fs::write(path, contents).expect("fixture file must be written");
            fs::set_permissions(path, fs::Permissions::from_mode(0o644))
                .expect("fixture file mode must be set");
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).expect("fixture must be removed");
        }
    }

    #[test]
    fn root_system_profile_expands_stock_fedora_metalink_from_rpm_values() {
        // Given stock Fedora metalink variables and malicious configured values for the special names.
        let fixture = Fixture::new();
        let repositories = fixture.directory("repos");
        let variables = fixture.directory("vars");
        Fixture::file(&variables.join("releasever"), "https://attacker.invalid");
        Fixture::file(&variables.join("basearch"), "evil");
        Fixture::file(
            &repositories.join("fedora.repo"),
            "[fedora]\ntype=rpm\nmetalink=https://mirrors.fedoraproject.org/metalink?repo=fedora-$releasever&arch=$basearch\n",
        );
        let main = fixture.0.join("dnf.conf");
        Fixture::file(
            &main,
            &format!(
                "[main]\nreposdir={}\nvarsdir={}\n",
                repositories.display(),
                variables.display()
            ),
        );

        // When root-system loading supplies RPM-derived Fedora values.
        let profile = load_system_mutation_profile_from_with_values(&main, "44", "aarch64")
            .expect("trusted RPM values must expand the stock Fedora metalink");

        // Then configured variable files cannot redirect the network source.
        assert_eq!(
            profile.repositories[0].metalink.as_deref(),
            Some("https://mirrors.fedoraproject.org/metalink?repo=fedora-44&arch=aarch64")
        );
        assert_eq!(
            profile
                .variables
                .expand("$releasever/$basearch/$arch")
                .expect("system values must remain available"),
            "44/aarch64/aarch64"
        );
    }

    #[test]
    fn root_system_profile_accepts_the_stock_fedora_system_gpgkey_alias() {
        // Given a stock Fedora file URI that expands to the architecture-specific system key alias.
        let fixture = Fixture::new();
        let repositories = fixture.directory("repos");
        let variables = fixture.directory("vars");
        Fixture::file(
            &repositories.join("fedora.repo"),
            "[fedora]\ntype=rpm\nbaseurl=https://download.example/fedora-$releasever/$basearch\ngpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-fedora-$releasever-$basearch\n",
        );
        let main = fixture.0.join("dnf.conf");
        Fixture::file(
            &main,
            &format!(
                "[main]\nreposdir={}\nvarsdir={}\n",
                repositories.display(),
                variables.display()
            ),
        );

        // When trusted RPM values expand the stock gpgkey before the refresh path is reachable.
        let profile = load_system_mutation_profile_from_with_values(&main, "44", "aarch64")
            .expect("Fedora system key alias must remain a valid per-repository trust source");

        // Then the file URI is normalized, its root-owned in-directory alias is retained, and its bundle is bound.
        assert_eq!(
            profile.repositories[0].gpgkey,
            ["/etc/pki/rpm-gpg/RPM-GPG-KEY-fedora-44-aarch64"]
        );
        assert!(profile.repositories[0].key_bundle_digest.is_some());
        assert_eq!(profile.repositories[0].allowed_fingerprints.len(), 1);
        assert!(
            profile.repositories[0].allowed_fingerprints[0]
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        );
    }

    #[test]
    fn disabled_third_party_remote_key_is_inert_until_repository_enablement() {
        let fixture = Fixture::new();
        let repositories = fixture.directory("repos");
        let variables = fixture.directory("vars");
        Fixture::file(
            &repositories.join("third-party.repo"),
            "[third:party]\nbaseurl=https://example.test/repo\nenabled=0\ngpgkey=https://example.test/key.gpg\n",
        );
        let main = fixture.0.join("dnf.conf");
        Fixture::file(
            &main,
            &format!(
                "[main]\nreposdir={}\nvarsdir={}\n",
                repositories.display(),
                variables.display()
            ),
        );
        let profile = load_system_mutation_profile_from_with_values(&main, "44", "aarch64")
            .expect("disabled third-party trust input must stay inert");
        assert!(!profile.repositories[0].enabled);
        assert_eq!(
            profile.repositories[0].gpgkey,
            ["https://example.test/key.gpg"]
        );
        assert!(profile.repositories[0].key_bundle_digest.is_none());
    }

    #[test]
    fn system_variable_values_reject_missing_and_malicious_rpm_output_before_profile_loading() {
        // Given missing, authority-shaped, and unsupported architecture RPM macro outputs.
        for (releasever, basearch) in [
            ("", "aarch64"),
            ("44\nhttps://attacker.invalid", "aarch64"),
            ("44", "evil"),
        ] {
            // When the root-system boundary parses the values before any repository profile exists.
            let result = system_variables_from_values(releasever, basearch);

            // Then it rejects the input without an opportunity to select a network source.
            assert!(
                result.is_err(),
                "must reject releasever={releasever:?}, basearch={basearch:?}"
            );
        }
    }

    #[test]
    fn root_system_profile_rejects_caller_home_variable_before_refresh_can_start() {
        // Given a stock-shaped root profile that tries to obtain an URL component from caller HOME.
        let fixture = Fixture::new();
        let repositories = fixture.directory("repos");
        let variables = fixture.directory("vars");
        Fixture::file(
            &repositories.join("fedora.repo"),
            "[fedora]\ntype=rpm\nmetalink=https://mirrors.fedoraproject.org/metalink?repo=fedora-$releasever&arch=$basearch&home=$HOME\n",
        );
        let main = fixture.0.join("dnf.conf");
        Fixture::file(
            &main,
            &format!(
                "[main]\nreposdir={}\nvarsdir={}\n",
                repositories.display(),
                variables.display()
            ),
        );

        // When the root-system profile is parsed before Refresher construction.
        let error = load_system_mutation_profile_from_with_values(&main, "44", "aarch64")
            .expect_err("caller HOME must not be a repository variable source");

        // Then URL expansion fails closed before any network-capable object is reachable.
        assert_eq!(
            error.to_string(),
            "<variables>:0: unresolved repository variable: HOME"
        );
    }
}
