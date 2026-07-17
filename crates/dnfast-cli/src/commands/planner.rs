use std::{
    collections::BTreeMap,
    fs,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use dnfast_core::{Action, Architecture, CanonicalDocument, Evra, TransactionIntent};
use dnfast_native::{NativeContext, Repository};
use dnfast_planning::{PlanningRepository, PlanningSnapshot};
use dnfast_solver::{CandidatePackage, CanonicalSolverPlan, NativeSolveOutput, PlanBuilder};

use super::AppFailure;

const PLAN_LIFETIME_SECONDS: u64 = 300;
type MaterializedPaths = (String, String, String);
type MaterializedRepository = (MaterializedPaths, Vec<dnfast_metadata::CompletePackage>);

pub(super) fn solve(
    intent: TransactionIntent,
    repository_ids: &[String],
) -> Result<CanonicalSolverPlan, AppFailure> {
    let snapshot = PlanningSnapshot::open_system().map_err(snapshot_failure)?;
    let integrity = snapshot
        .integrity_for_repositories(repository_ids)
        .map_err(snapshot_failure)?;
    let repositories = selected_repositories(&snapshot, &integrity)?;
    let module_catalog = snapshot
        .module_catalog(repository_ids)
        .map_err(snapshot_failure)?;
    let module_policies = module_catalog
        .artifact_policies(
            &snapshot.payload().module_state,
            snapshot.payload().policy.solver.base_arch(),
        )
        .map_err(snapshot_failure)?;
    let workspace = tempfile::tempdir().map_err(io_failure)?;
    let mut context = NativeContext::open(snapshot.payload().policy.solver.base_arch(), || false)
        .map_err(native_failure)?;
    context.add_installed_rpmdb("/").map_err(native_failure)?;
    let inventory = context
        .read_installed_inventory()
        .map_err(|error| AppFailure::new(1, error.to_string()))?;
    if inventory
        .canonical_sha256()
        .map_err(|error| AppFailure::new(1, error.to_string()))?
        != snapshot
            .payload()
            .inventory
            .canonical_sha256()
            .map_err(|error| AppFailure::new(1, error.to_string()))?
    {
        return Err(AppFailure::new(
            1,
            "root-published planning snapshot has stale RPMDB inventory",
        ));
    }
    let mut candidates = Vec::new();
    let mut metadata = Vec::new();
    for (index, repository) in repositories.iter().enumerate() {
        let (paths, solver_inputs) = materialize(&snapshot, workspace.path(), index, repository)?;
        context
            .add_repository(Repository {
                id: repository.id.clone(),
                repomd_path: paths.0,
                primary_path: paths.1,
                filelists_path: paths.2,
                priority: i32::try_from(repository.priority)
                    .map_err(|error| AppFailure::new(1, error.to_string()))?,
                cost: i32::try_from(repository.cost)
                    .map_err(|error| AppFailure::new(1, error.to_string()))?,
            })
            .map_err(native_failure)?;
        candidates.extend(candidates_for(
            repository,
            &solver_inputs,
            snapshot.payload().policy.solver.base_arch(),
            &module_policies,
        )?);
        metadata.extend(
            solver_inputs
                .iter()
                .cloned()
                .map(|package| (repository.id.clone(), package)),
        );
    }
    let module_excludes = module_policies
        .iter()
        .filter_map(|(artifact, excluded)| excluded.then_some(artifact.clone()))
        .collect::<Vec<_>>();
    context
        .set_module_excludes(&module_excludes)
        .map_err(native_failure)?;
    let names = intent
        .packages()
        .iter()
        .map(|package| package.as_str())
        .collect::<Vec<_>>();
    let solved = match intent.action() {
        Action::Install => context.solve_install_many(
            &names,
            snapshot.payload().policy.solver.install_weak_deps(),
            snapshot.payload().policy.solver.best(),
        ),
        Action::Upgrade => {
            context.solve_upgrade_many(&names, snapshot.payload().policy.solver.best())
        }
        Action::Remove => context.solve_erase_many(&names),
    }
    .map_err(native_failure)?;
    let metadata_refs = metadata
        .iter()
        .map(|(id, package)| (id.as_str(), package))
        .collect::<Vec<_>>();
    let transcript = NativeSolveOutput::from_native(
        solved,
        integrity.metadata_sha256().as_str().into(),
        &metadata_refs,
        &inventory,
    )
    .map_err(|error| AppFailure::new(1, error.to_string()))?;
    let satisfied_specs = transcript.satisfied_specs().to_vec();
    let resolved = transcript
        .into_resolved(&names, &candidates, &metadata_refs, &inventory)
        .map_err(|error| AppFailure::new(1, error.to_string()))?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| AppFailure::new(1, error.to_string()))?
        .as_secs();
    PlanBuilder {
        intent: &intent,
        snapshots: &integrity,
        inventory: &inventory,
        policy: &snapshot.payload().policy.solver,
        candidates: &candidates,
        expires_at_unix: now.saturating_add(PLAN_LIFETIME_SECONDS),
    }
    .build_with_satisfied(&resolved, &satisfied_specs)
    .map_err(|error| AppFailure::new(1, error.to_string()))
}

fn selected_repositories<'a>(
    snapshot: &'a PlanningSnapshot,
    integrity: &dnfast_core::PlanIntegrity,
) -> Result<Vec<&'a PlanningRepository>, AppFailure> {
    integrity
        .selected_repositories()
        .iter()
        .map(|binding| {
            snapshot
                .payload()
                .allowed_repositories
                .iter()
                .find(|repository| repository.id == binding.id())
                .ok_or_else(|| AppFailure::new(1, "root-published repository binding disappeared"))
        })
        .collect()
}

fn materialize(
    snapshot: &PlanningSnapshot,
    root: &Path,
    index: usize,
    repository: &PlanningRepository,
) -> Result<MaterializedRepository, AppFailure> {
    let metadata = snapshot
        .materialize_native_xml(repository)
        .map_err(snapshot_failure)?;
    write_materialized(root, index, metadata)
}

fn write_materialized(
    root: &Path,
    index: usize,
    metadata: dnfast_planning::NativeRepositoryXml,
) -> Result<MaterializedRepository, AppFailure> {
    let prefix = format!("repository-{index}");
    let repomd = write(root, &format!("{prefix}-repomd.xml"), metadata.repomd())?;
    let primary = write(root, &format!("{prefix}-primary.xml"), metadata.primary())?;
    let filelists = write(
        root,
        &format!("{prefix}-filelists.xml"),
        metadata.filelists(),
    )?;
    Ok((
        (display(&repomd)?, display(&primary)?, display(&filelists)?),
        metadata.solver_inputs().to_vec(),
    ))
}

#[cfg(test)]
fn materialize_inline(
    root: &Path,
    index: usize,
    repository: &PlanningRepository,
) -> Result<MaterializedRepository, AppFailure> {
    let metadata = repository
        .materialize_native_xml()
        .map_err(snapshot_failure)?;
    write_materialized(root, index, metadata)
}

fn write(root: &Path, name: &str, bytes: &[u8]) -> Result<std::path::PathBuf, AppFailure> {
    let path = root.join(name);
    fs::write(&path, bytes).map_err(io_failure)?;
    Ok(path)
}

fn candidates_for(
    repository: &PlanningRepository,
    solver_inputs: &[dnfast_metadata::CompletePackage],
    base_architecture: Architecture,
    module_policies: &BTreeMap<String, bool>,
) -> Result<Vec<CandidatePackage>, AppFailure> {
    let mut candidates = Vec::new();
    for item in solver_inputs {
        let Some(architecture) = candidate_architecture(&item.arch, base_architecture)? else {
            continue;
        };
        let epoch = item
            .epoch
            .parse()
            .map_err(|_| AppFailure::new(1, "root-published metadata has an invalid epoch"))?;
        let evra = Evra::new(
            epoch,
            item.version.clone(),
            item.release.clone(),
            architecture,
        );
        let identity = format!(
            "{}-{}:{}-{}.{}",
            item.name,
            evra.epoch(),
            evra.version(),
            evra.release(),
            evra.arch().as_rpm_arch(),
        );
        let module_excluded = module_policies.get(&identity).copied();
        candidates.push(CandidatePackage {
            name: item.name.clone(),
            evra,
            vendor: if item.vendor.is_empty() {
                "unknown".into()
            } else {
                item.vendor.clone()
            },
            repo_id: repository.id.clone(),
            priority: repository.priority,
            cost: repository.cost,
            package_size: item.package_size,
            installed_size: item.installed_size,
            checksum_sha256: item.checksum.clone(),
            location: item.location.clone(),
            excluded: module_excluded.unwrap_or(false),
            modular: module_excluded.is_some(),
        });
    }
    Ok(candidates)
}

fn candidate_architecture(
    value: &str,
    base: Architecture,
) -> Result<Option<Architecture>, AppFailure> {
    match value {
        "aarch64" => Ok(Some(Architecture::Aarch64)),
        "x86_64" => Ok(Some(Architecture::X86_64)),
        "noarch" => Ok(Some(Architecture::Noarch)),
        // Fedora's x86_64 repositories include i686 packages.  The canonical
        // policy currently has allow_multilib=false, so they are valid pool
        // input but cannot become executable plan candidates.
        "i686" if base == Architecture::X86_64 => Ok(None),
        _ => Err(AppFailure::new(
            1,
            "root-published metadata has an unsupported architecture",
        )),
    }
}

fn display(path: &Path) -> Result<String, AppFailure> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| AppFailure::new(1, "temporary metadata path is not UTF-8"))
}

fn snapshot_failure(error: dnfast_planning::PlanningError) -> AppFailure {
    AppFailure::new(1, error.to_string())
}
fn native_failure(error: dnfast_native::NativeError) -> AppFailure {
    AppFailure::new(1, error.to_string())
}
fn io_failure(error: std::io::Error) -> AppFailure {
    AppFailure::new(1, error.to_string())
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use dnfast_core::{RepoTrustPolicy, SigningSubkeyRule};
    use dnfast_planning::{PlanningBytes, PlanningKey, PlanningOrigin, PlanningRepository};
    use sha2::{Digest, Sha256};

    use super::{candidate_architecture, materialize_inline};

    #[test]
    fn x86_repository_i686_records_are_filtered_when_multilib_is_disabled() {
        assert_eq!(
            candidate_architecture("i686", dnfast_core::Architecture::X86_64).unwrap(),
            None
        );
        assert!(candidate_architecture("i686", dnfast_core::Architecture::Aarch64).is_err());
    }

    #[test]
    fn public_planner_materializes_zstd_metadata_as_xml_for_native_solver() {
        // Given: a root-published planning repository whose primary and filelists records are zstd.
        let repository = zstd_repository();
        let original = repository.clone();
        let workspace = tempfile::tempdir().expect("temporary materialization workspace");

        // When: the public planner creates the exact paths it passes to the native solver.
        let ((_, primary, filelists), solver_inputs) =
            materialize_inline(workspace.path(), 0, &repository).expect("planner materialization");

        // Then: both native-input paths contain parseable XML, not compressed snapshot bytes.
        let primary = fs::read(primary).expect("materialized primary");
        let filelists = fs::read(filelists).expect("materialized filelists");
        assert_eq!(repository, original);
        assert!(!primary.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]));
        assert!(!filelists.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]));
        assert_eq!(
            dnfast_metadata::parse_primary_records(primary.as_slice()).expect("native primary XML"),
            solver_inputs,
        );
        dnfast_metadata::parse_filelists(filelists.as_slice()).expect("native filelists XML");
    }

    #[test]
    fn public_planner_rejects_malformed_primary_before_writing_native_xml() {
        // Given: a snapshot repository whose primary bytes cannot satisfy its bound zstd record.
        let mut repository = zstd_repository();
        repository.primary = planning_bytes(b"not-zstd");
        let workspace = tempfile::tempdir().expect("temporary materialization workspace");

        // When: the public planner prepares native solver metadata.
        let result = materialize_inline(workspace.path(), 0, &repository);

        // Then: it names the primary role and writes no derived native inputs.
        let error = match result {
            Ok(_) => panic!("malformed primary must be rejected"),
            Err(error) => error,
        };
        assert!(
            error
                .message
                .starts_with("planning input is invalid: primary rpm-md materialization failed:")
        );
        assert!(
            fs::read_dir(workspace.path())
                .expect("workspace entries")
                .next()
                .is_none()
        );
    }

    fn zstd_repository() -> PlanningRepository {
        let metadata = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/rpm/generated-build10/repos/main/repodata");
        let repomd = fs::read(metadata.join("repomd.xml")).expect("repomd");
        let primary = fs::read(metadata.join("primary.xml.zst")).expect("primary");
        let filelists = fs::read(metadata.join("filelists.xml.zst")).expect("filelists");
        let records = dnfast_metadata::parse_repomd_records(&repomd).expect("repomd records");
        dnfast_metadata::parse_primary_records(
            dnfast_metadata::decode_record(primary.as_slice(), &records.primary)
                .expect("primary XML")
                .as_slice(),
        )
        .expect("primary records");
        dnfast_metadata::parse_filelists_record(filelists.as_slice(), &records.filelists)
            .expect("filelists records");
        let certificate = b"planner-key";
        let bundle_path = "/etc/pki/rpm-gpg/RPM-GPG-KEY-fedora-44-aarch64";
        let mut bundle = Sha256::new();
        bundle.update(b"dnfast-key-bundle-v1");
        for value in [bundle_path.as_bytes(), certificate.as_slice()] {
            bundle.update(
                u64::try_from(value.len())
                    .expect("fixture length")
                    .to_be_bytes(),
            );
            bundle.update(value);
        }
        let trust = RepoTrustPolicy::new(
            "main",
            format!("{:x}", bundle.finalize()),
            ["A".repeat(40)],
            SigningSubkeyRule::AuthorizedSubkeys,
            7,
        )
        .expect("trust");
        PlanningRepository {
            id: "main".into(),
            priority: 99,
            cost: 1000,
            generation_sha256: format!("{:x}", Sha256::digest(&repomd)),
            origin: PlanningOrigin {
                repomd_url: "https://mirror.example/fedora/repodata/repomd.xml".into(),
                sha256: format!(
                    "{:x}",
                    Sha256::digest(b"https://mirror.example/fedora/repodata/repomd.xml")
                ),
            },
            repomd: planning_bytes(&repomd),
            primary: planning_bytes(&primary),
            filelists: planning_bytes(&filelists),
            file_provides: None,
            group: None,
            modules: None,
            trust,
            keys: vec![PlanningKey {
                bundle_path: bundle_path.into(),
                certificate_base64: STANDARD.encode(certificate),
            }],
            repomd_authentication: dnfast_cache::RepomdAuthentication::TransportOnly,
        }
    }

    fn planning_bytes(bytes: &[u8]) -> PlanningBytes {
        PlanningBytes {
            sha256: format!("{:x}", Sha256::digest(bytes)),
            size: u64::try_from(bytes.len()).expect("fixture length"),
            base64: STANDARD.encode(bytes),
        }
    }
}
