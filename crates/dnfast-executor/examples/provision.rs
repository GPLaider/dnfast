use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use dnfast_core::{
    Action, Architecture, CanonicalDocument, Evra, RepoTrustPolicy, RepositoryBinding,
    Sha256Digest, SigningSubkeyRule, SolverPolicy, TransactionIntent,
};
use dnfast_metadata::{
    CompletePackage, decode_primary, decode_record, parse_primary_records, parse_repomd_records,
};
use dnfast_native::{NativeContext, Repository};
use dnfast_solver::{CandidatePackage, IntegritySnapshots, NativeSolveOutput, PlanBuilder};
use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Clone, Serialize)]
struct FileInput {
    name: String,
    sha256: String,
    size: u64,
}
#[derive(Clone, Serialize)]
struct OriginInput {
    repomd_url: String,
    sha256: String,
}
#[derive(Clone, Serialize)]
struct KeyInput {
    file: FileInput,
    bundle_path: String,
}
#[derive(Clone, Serialize)]
struct RepositoryTrustInput {
    policy: FileInput,
    sha256: String,
    keys: Vec<KeyInput>,
}
#[derive(Clone, Serialize)]
struct RepositoryInput {
    id: String,
    priority: i32,
    cost: i32,
    generation_sha256: String,
    origin: OriginInput,
    repomd: FileInput,
    primary: FileInput,
    filelists: FileInput,
    trust: RepositoryTrustInput,
}
#[derive(Serialize)]
struct ArtifactInput {
    file: FileInput,
    repo_id: String,
    generation_sha256: String,
    origin_sha256: String,
    trust_sha256: String,
    name: String,
    epoch: u32,
    version: String,
    release: String,
    arch: String,
    vendor: String,
}
#[derive(Serialize)]
struct Manifest {
    schema_version: u32,
    policy: FileInput,
    metadata_sha256: String,
    trust_sha256: String,
    repositories: Vec<RepositoryInput>,
    artifacts: Vec<ArtifactInput>,
}

#[derive(Clone)]
struct FixtureRepository {
    id: String,
    source: PathBuf,
    key_source: PathBuf,
    key_target: PathBuf,
    fingerprint: String,
    priority: i32,
}
struct MaterializedRepository {
    fixture: FixtureRepository,
    repomd: PathBuf,
    primary: PathBuf,
    filelists: PathBuf,
    packages: Vec<CompletePackage>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if rustix::process::geteuid().as_raw() != 0 {
        return Err("provision requires root".into());
    }
    let mut arguments = std::env::args().skip(1);
    let requested_action = arguments
        .next()
        .ok_or("usage: provision {install|upgrade|remove} [package]")?;
    let (
        action,
        fixture_wrong_candidate,
        fixture_vendor_mismatch,
        fixture_repo_binding,
        fixture_two_repo,
        fixture_wrong_key,
    ) = match requested_action.as_str() {
        "install" => (Action::Install, false, false, false, false, false),
        "upgrade" => (Action::Upgrade, false, false, false, false, false),
        "remove" => (Action::Remove, false, false, false, false, false),
        #[cfg(feature = "test-fixtures")]
        "wrong-install" => (Action::Install, true, false, false, false, false),
        #[cfg(feature = "test-fixtures")]
        "vendor-mismatch-install" => (Action::Install, false, true, false, false, false),
        #[cfg(feature = "test-fixtures")]
        "repo-binding-install" => (Action::Install, false, false, true, false, false),
        #[cfg(feature = "test-fixtures")]
        "two-repo-install" => (Action::Install, false, false, false, true, false),
        #[cfg(feature = "test-fixtures")]
        "wrong-key-two-repo-install" => (Action::Install, false, false, false, true, true),
        _ => return Err("unsupported action".into()),
    };
    let root = std::env::var("DNFAST_FIXTURE_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("fixtures/rpm/generated-build10"));
    let main_source = if fixture_two_repo {
        root.join("repos/two-repo-main")
    } else {
        root.join("repos/main")
    };
    let mut fixtures = vec![FixtureRepository {
        id: "main".into(),
        source: main_source,
        key_source: root.join("keys/allowed.asc"),
        key_target: PathBuf::from("/etc/dnfast/keys/main/allowed.asc"),
        fingerprint: fixture_primary_fingerprint(&root, "allowed")?,
        priority: 99,
    }];
    if fixture_repo_binding || fixture_two_repo {
        fixtures.push(FixtureRepository {
            id: "alternate".into(),
            source: root.join("repos/alternate"),
            key_source: if fixture_wrong_key {
                root.join("keys/allowed.asc")
            } else {
                root.join("keys/alternate.asc")
            },
            key_target: PathBuf::from("/etc/dnfast/keys/alternate/allowed.asc"),
            fingerprint: fixture_primary_fingerprint(&root, "alternate")?,
            priority: 1,
        });
    }
    for fixture in &fixtures {
        fs::create_dir_all(fixture.key_target.parent().ok_or("key parent")?)?;
        fs::copy(&fixture.key_source, &fixture.key_target)?;
        private(&fixture.key_target)?;
    }
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let expires_after = std::env::var("DNFAST_PROVISION_TTL_SECONDS")
        .ok()
        .map(|value| value.parse::<u64>())
        .transpose()?
        .unwrap_or(600);
    let policy = SolverPolicy::fedora44_aarch64(vec![], vec![]);
    let materialized_root = PathBuf::from("/var/lib/dnfast/provision");
    fs::create_dir_all(&materialized_root)?;
    private_dir(&materialized_root)?;
    let materialized = fixtures
        .iter()
        .map(|fixture| {
            materialize(
                fixture.clone(),
                &materialized_root,
                fixture_vendor_mismatch && fixture.id == "main",
            )
        })
        .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
    let mut native = NativeContext::open(Architecture::Aarch64, || false)?;
    native.add_installed_rpmdb("/")?;
    let inventory = native.read_installed_inventory()?;
    for repository in &materialized {
        native.add_repository(Repository {
            id: repository.fixture.id.clone(),
            repomd_path: repository.repomd.to_string_lossy().into_owned(),
            primary_path: repository.primary.to_string_lossy().into_owned(),
            filelists_path: repository.filelists.to_string_lossy().into_owned(),
            priority: repository.fixture.priority,
            cost: 1000,
        })?;
    }
    let name = arguments.next().unwrap_or_else(|| {
        if fixture_two_repo {
            "dnfast-app".into()
        } else if fixture_vendor_mismatch {
            "dnfast-vendor-switch".into()
        } else if action == Action::Upgrade || fixture_wrong_candidate {
            "dnfast-upgrade".into()
        } else {
            "dnfast-noarch".into()
        }
    });
    let result = match action {
        Action::Install => native.solve_install_many(
            &[&name],
            !fixture_two_repo && policy.install_weak_deps(),
            policy.best(),
        )?,
        Action::Upgrade => native.solve_upgrade_many(&[&name], policy.best())?,
        Action::Remove => native.solve_erase_many(&[&name])?,
    };
    let metadata = materialized
        .iter()
        .flat_map(|repository| {
            repository
                .packages
                .iter()
                .map(move |package| (repository.fixture.id.as_str(), package))
        })
        .collect::<Vec<_>>();
    let candidates = materialized
        .iter()
        .flat_map(|repository| {
            repository
                .packages
                .iter()
                .map(|package| candidate(package, &repository.fixture))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut repositories = materialized
        .iter()
        .map(|repository| repository_input(repository, now))
        .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
    repositories.sort_by(|left, right| left.id.cmp(&right.id));
    let metadata_sha256 = metadata_digest(&repositories)?;
    let trust_sha256 = trust_digest(&repositories)?;
    let native_output =
        NativeSolveOutput::from_native(result, metadata_sha256.clone(), &metadata, &inventory)?;
    let intent = TransactionIntent::from_package_names(action, &[&name])?;
    let snapshot = format!(
        "{:x}",
        Sha256::digest(b"dnfast-provision-fixture-planning-snapshot-v2")
    );
    let bindings = repositories
        .iter()
        .map(|repository| {
            RepositoryBinding::new(
                repository.id.clone(),
                Sha256Digest::parse(repository.generation_sha256.clone(), "generation_sha256")?,
                Sha256Digest::parse(repository.origin.sha256.clone(), "origin_sha256")?,
                Sha256Digest::parse(repository.trust.sha256.clone(), "trust_sha256")?,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let snapshots = IntegritySnapshots::new(
        [
            policy.canonical_sha256()?.as_str(),
            trust_sha256.as_str(),
            inventory.canonical_sha256()?.as_str(),
            metadata_sha256.as_str(),
            snapshot.as_str(),
        ],
        bindings,
    )?;
    let mut resolved = native_output.into_resolved(&[&name], &candidates, &metadata, &inventory)?;
    let planning_candidates = if fixture_wrong_candidate {
        let wrong = candidates
            .iter()
            .find(|candidate| candidate.name == name && candidate.evra.version() == "1.0")
            .ok_or("fixture candidate is absent")?
            .clone();
        let selected = resolved
            .iter_mut()
            .find(|item| item.name == name)
            .ok_or("fixture action is absent")?;
        selected.candidate = Some(wrong.clone());
        candidates
            .iter()
            .filter(|candidate| candidate.name != name || candidate.evra == wrong.evra)
            .cloned()
            .collect()
    } else {
        candidates.clone()
    };
    let plan = PlanBuilder {
        intent: &intent,
        snapshots: &snapshots,
        inventory: &inventory,
        policy: &policy,
        candidates: &planning_candidates,
        expires_at_unix: now.saturating_add(expires_after),
    }
    .build(&resolved)?;
    let input_root = PathBuf::from("/var/lib/dnfast/inputs").join(plan.digest()?.as_str());
    fs::create_dir_all(&input_root)?;
    private_dir(&input_root)?;
    let policy_file = write(&input_root, "policy.json", &policy.to_canonical_json()?)?;
    for repository in &repositories {
        let source = materialized
            .iter()
            .find(|item| item.fixture.id == repository.id)
            .ok_or("repository source is absent")?;
        copy(&input_root, &source.repomd, &repository.repomd.name)?;
        copy(&input_root, &source.primary, &repository.primary.name)?;
        copy(&input_root, &source.filelists, &repository.filelists.name)?;
        let trust = trust_for_id(
            &repository.id,
            Path::new(&repository.trust.keys[0].bundle_path),
            &source.fixture.fingerprint,
            now,
        )?;
        write(
            &input_root,
            &repository.trust.policy.name,
            &trust.to_canonical_json()?,
        )?;
        copy(
            &input_root,
            Path::new(&repository.trust.keys[0].bundle_path),
            &repository.trust.keys[0].file.name,
        )?;
    }
    let mut artifacts = plan
        .actions()
        .iter()
        .filter_map(|action| action.artifact.as_ref().map(|artifact| (action, artifact)))
        .map(|(planned, artifact)| {
            let planned_repository = planned
                .repo_id
                .as_deref()
                .ok_or("planned repository is absent")?;
            let binding_id = if fixture_repo_binding {
                "alternate"
            } else {
                planned_repository
            };
            let binding = repositories
                .iter()
                .find(|repository| repository.id == binding_id)
                .ok_or("artifact binding repository is absent")?;
            let source = materialized
                .iter()
                .find(|repository| repository.fixture.id == planned_repository)
                .ok_or("artifact source repository is absent")?;
            let file = copy(
                &input_root,
                &source.fixture.source.join(&artifact.location),
                &format!("artifact-{}", planned.name),
            )?;
            Ok(ArtifactInput {
                file,
                repo_id: binding.id.clone(),
                generation_sha256: binding.generation_sha256.clone(),
                origin_sha256: binding.origin.sha256.clone(),
                trust_sha256: binding.trust.sha256.clone(),
                name: planned.name.clone(),
                epoch: planned.target_evra.epoch(),
                version: planned.target_evra.version().into(),
                release: planned.target_evra.release().into(),
                arch: planned.target_evra.arch().as_rpm_arch().into(),
                vendor: planned.vendor.clone().ok_or("planned vendor is absent")?,
            })
        })
        .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
    artifacts.sort_by(|left, right| {
        (
            &left.repo_id,
            &left.name,
            left.epoch,
            &left.version,
            &left.release,
            &left.file.sha256,
        )
            .cmp(&(
                &right.repo_id,
                &right.name,
                right.epoch,
                &right.version,
                &right.release,
                &right.file.sha256,
            ))
    });
    let manifest = Manifest {
        schema_version: 3,
        policy: policy_file,
        metadata_sha256,
        trust_sha256,
        repositories,
        artifacts,
    };
    write(
        &input_root,
        "manifest.json",
        &serde_json::to_vec(&manifest)?,
    )?;
    let plan_path = PathBuf::from("/var/lib/dnfast/plans");
    fs::create_dir_all(&plan_path)?;
    private_dir(&plan_path)?;
    let output = plan_path.join(format!("{}.json", action.as_str()));
    fs::write(&output, plan.canonical_json()?)?;
    private(&output)?;
    println!("{}", output.display());
    Ok(())
}

fn materialize(
    fixture: FixtureRepository,
    root: &Path,
    mutate_vendor: bool,
) -> Result<MaterializedRepository, Box<dyn std::error::Error>> {
    let repomd = fixture.source.join("repodata/repomd.xml");
    let records = parse_repomd_records(&fs::read(&repomd)?)?;
    let directory = root.join(&fixture.id);
    fs::create_dir_all(&directory)?;
    private_dir(&directory)?;
    let primary = directory.join("primary.xml");
    let mut primary_bytes = decode_primary(
        &fs::read(fixture.source.join("repodata/primary.xml.zst"))?,
        &records.primary,
    )?;
    if mutate_vendor {
        let original = b"<rpm:vendor>Dnfast Vendor B</rpm:vendor>";
        let replacement = b"<rpm:vendor>Dnfast Metadata Lie</rpm:vendor>";
        let position = primary_bytes
            .windows(original.len())
            .position(|window| window == original)
            .ok_or("vendor fixture record is absent")?;
        primary_bytes.splice(
            position..position + original.len(),
            replacement.iter().copied(),
        );
    }
    fs::write(&primary, primary_bytes)?;
    private(&primary)?;
    let filelists = directory.join("filelists.xml");
    fs::write(
        &filelists,
        decode_record(
            &fs::read(fixture.source.join("repodata/filelists.xml.zst"))?,
            &records.filelists,
        )?,
    )?;
    private(&filelists)?;
    let primary_bytes = fs::read(&primary)?;
    let packages = parse_primary_records(primary_bytes.as_slice())?;
    Ok(MaterializedRepository {
        fixture,
        repomd,
        primary,
        filelists,
        packages,
    })
}

fn repository_input(
    repository: &MaterializedRepository,
    now: u64,
) -> Result<RepositoryInput, Box<dyn std::error::Error>> {
    let trust = trust_for_id(
        &repository.fixture.id,
        &repository.fixture.key_target,
        &repository.fixture.fingerprint,
        now,
    )?;
    let trust_bytes = trust.to_canonical_json()?;
    let repomd = descriptor(
        &repository.repomd,
        &format!("{}-repomd", repository.fixture.id),
    )?;
    let origin_url = format!(
        "https://{}.fixtures.invalid/repo/repodata/repomd.xml",
        repository.fixture.id
    );
    Ok(RepositoryInput {
        id: repository.fixture.id.clone(),
        priority: repository.fixture.priority,
        cost: 1000,
        generation_sha256: repomd.sha256.clone(),
        origin: OriginInput {
            sha256: format!("{:x}", Sha256::digest(origin_url.as_bytes())),
            repomd_url: origin_url,
        },
        repomd,
        primary: descriptor(
            &repository.primary,
            &format!("{}-primary", repository.fixture.id),
        )?,
        filelists: descriptor(
            &repository.filelists,
            &format!("{}-filelists", repository.fixture.id),
        )?,
        trust: RepositoryTrustInput {
            policy: descriptor_bytes(
                &format!("{}-trust.json", repository.fixture.id),
                &trust_bytes,
            )?,
            sha256: trust.canonical_sha256()?.as_str().into(),
            keys: vec![KeyInput {
                file: descriptor(
                    &repository.fixture.key_target,
                    &format!("{}-key", repository.fixture.id),
                )?,
                bundle_path: repository.fixture.key_target.to_string_lossy().into_owned(),
            }],
        },
    })
}

fn fixture_primary_fingerprint(
    root: &Path,
    label: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    fs::read_to_string(root.join("fingerprints.tsv"))?
        .lines()
        .skip(1)
        .find_map(|line| {
            let mut fields = line.split('\t');
            (fields.next() == Some(label) && fields.next() == Some("primary"))
                .then(|| fields.next().map(str::to_owned))
                .flatten()
        })
        .ok_or_else(|| format!("fixture primary fingerprint is absent: {label}").into())
}

fn trust_for_id(
    repository: &str,
    key: &Path,
    fingerprint: &str,
    now: u64,
) -> Result<RepoTrustPolicy, Box<dyn std::error::Error>> {
    let key_bytes = fs::read(key)?;
    let path = key.to_string_lossy();
    let mut bundle = Sha256::new();
    bundle.update(b"dnfast-key-bundle-v1");
    frame(&mut bundle, path.as_ref(), &key_bytes);
    Ok(RepoTrustPolicy::new(
        repository,
        format!("{:x}", bundle.finalize()),
        vec![fingerprint.into()],
        SigningSubkeyRule::AuthorizedSubkeys,
        now,
    )?)
}

fn candidate(
    item: &CompletePackage,
    repository: &FixtureRepository,
) -> Result<CandidatePackage, Box<dyn std::error::Error>> {
    Ok(CandidatePackage {
        name: item.name.clone(),
        evra: Evra::new(
            item.epoch.parse()?,
            item.version.clone(),
            item.release.clone(),
            match item.arch.as_str() {
                "aarch64" => Architecture::Aarch64,
                "x86_64" => Architecture::X86_64,
                "noarch" => Architecture::Noarch,
                _ => return Err("unsupported arch".into()),
            },
        ),
        vendor: if item.vendor.is_empty() {
            "unknown".into()
        } else {
            item.vendor.clone()
        },
        repo_id: repository.id.clone(),
        priority: u32::try_from(repository.priority)?,
        cost: 1000,
        package_size: item.package_size,
        installed_size: item.installed_size,
        checksum_sha256: item.checksum.clone(),
        location: item.location.clone(),
        excluded: false,
        modular: false,
    })
}
fn descriptor(path: &Path, name: &str) -> Result<FileInput, Box<dyn std::error::Error>> {
    descriptor_bytes(name, &fs::read(path)?)
}
fn descriptor_bytes(name: &str, bytes: &[u8]) -> Result<FileInput, Box<dyn std::error::Error>> {
    Ok(FileInput {
        name: name.into(),
        sha256: format!("{:x}", Sha256::digest(bytes)),
        size: bytes.len().try_into()?,
    })
}
fn copy(root: &Path, source: &Path, name: &str) -> Result<FileInput, Box<dyn std::error::Error>> {
    fs::copy(source, root.join(name))?;
    private(&root.join(name))?;
    descriptor(&root.join(name), name)
}
fn write(root: &Path, name: &str, bytes: &[u8]) -> Result<FileInput, Box<dyn std::error::Error>> {
    fs::write(root.join(name), bytes)?;
    private(&root.join(name))?;
    descriptor(&root.join(name), name)
}
fn frame(digest: &mut Sha256, path: &str, bytes: &[u8]) {
    digest.update((path.len() as u64).to_be_bytes());
    digest.update(path.as_bytes());
    digest.update((bytes.len() as u64).to_be_bytes());
    digest.update(bytes);
}
fn metadata_digest(repositories: &[RepositoryInput]) -> Result<String, Box<dyn std::error::Error>> {
    let mut digest = Sha256::new();
    digest.update(b"dnfast-root-metadata-v3");
    for repository in repositories {
        framed(&mut digest, &repository.id, repository.id.as_bytes())?;
        digest.update(repository.priority.to_be_bytes());
        digest.update(repository.cost.to_be_bytes());
        framed(
            &mut digest,
            &repository.generation_sha256,
            repository.generation_sha256.as_bytes(),
        )?;
        framed(
            &mut digest,
            &repository.origin.sha256,
            repository.origin.sha256.as_bytes(),
        )?;
        framed(
            &mut digest,
            &repository.trust.sha256,
            repository.trust.sha256.as_bytes(),
        )?;
        for file in [
            &repository.repomd,
            &repository.primary,
            &repository.filelists,
        ] {
            framed(&mut digest, &file.sha256, file.sha256.as_bytes())?;
            digest.update(file.size.to_be_bytes());
        }
    }
    Ok(format!("{:x}", digest.finalize()))
}
fn trust_digest(repositories: &[RepositoryInput]) -> Result<String, Box<dyn std::error::Error>> {
    let mut digest = Sha256::new();
    digest.update(b"dnfast-root-trust-v3");
    for repository in repositories {
        framed(&mut digest, &repository.id, repository.id.as_bytes())?;
        framed(
            &mut digest,
            &repository.trust.sha256,
            repository.trust.sha256.as_bytes(),
        )?;
    }
    Ok(format!("{:x}", digest.finalize()))
}
fn framed(digest: &mut Sha256, name: &str, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let name_len: u64 = name.len().try_into()?;
    let bytes_len: u64 = bytes.len().try_into()?;
    digest.update(name_len.to_be_bytes());
    digest.update(name.as_bytes());
    digest.update(bytes_len.to_be_bytes());
    digest.update(bytes);
    Ok(())
}
fn private(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}
fn private_dir(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}
