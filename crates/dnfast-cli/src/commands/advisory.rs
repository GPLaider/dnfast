use std::collections::{BTreeMap, BTreeSet};

use dnfast_core::{Architecture, Evra, InstalledPackage};
use dnfast_metadata::Advisory;
use dnfast_planning::{PlanningRepository, PlanningSnapshot};

use crate::{
    args::{AdvisoryQueryArgs, AdvisoryUpgradeArgs, MutationArgs, PlanAction},
    rendering::escaped_field,
    response::Response,
};

use super::{AppFailure, canonical_repository_ids, run_convenience};

struct CatalogEntry {
    repository: String,
    advisory: Advisory,
}

pub(super) fn list(arguments: AdvisoryQueryArgs) -> Result<Response, AppFailure> {
    validate_severity(arguments.severity.as_deref())?;
    let (snapshot, catalog) = catalog(arguments.repositories)?;
    let mut rendered = Vec::new();
    for entry in catalog.values() {
        if !matches_filter(
            &entry.advisory,
            arguments.security,
            arguments.severity.as_deref(),
        ) {
            continue;
        }
        let packages = applicable_packages(&snapshot, &entry.advisory)?;
        if packages.is_empty() && !arguments.all {
            continue;
        }
        rendered.push(format!(
            "{}:{}:{}:{}:packages=[{}]:title={}",
            escaped_field(&entry.advisory.id),
            escaped_field(&entry.advisory.kind),
            escaped_field(&entry.advisory.severity),
            escaped_field(&entry.repository),
            packages
                .iter()
                .map(|value| escaped_field(value))
                .collect::<Vec<_>>()
                .join(","),
            escaped_field(&entry.advisory.title),
        ));
    }
    Ok(Response::completed(
        "advisory",
        format!("advisories=[{}]", rendered.join(",")),
    ))
}

pub(super) fn info(
    repositories: Vec<String>,
    advisories: Vec<String>,
) -> Result<Response, AppFailure> {
    let (_, catalog) = catalog(repositories)?;
    let requested = validate_ids(advisories)?;
    let mut rendered = Vec::new();
    for id in requested {
        let entry = catalog.get(&id).ok_or_else(|| {
            AppFailure::with_error_code(
                1,
                "advisory_not_found",
                format!("advisory was not found in selected repositories: {id}"),
            )
        })?;
        let references = entry
            .advisory
            .references
            .iter()
            .map(|reference| {
                format!(
                    "{}:{}:{}",
                    escaped_field(&reference.kind),
                    escaped_field(&reference.id),
                    escaped_field(&reference.href)
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        let packages = entry
            .advisory
            .packages
            .iter()
            .filter(|package| supported_arch(&package.arch))
            .map(|package| {
                format!(
                    "{}-{}:{}-{}.{}",
                    escaped_field(&package.name),
                    package.epoch,
                    escaped_field(&package.version),
                    escaped_field(&package.release),
                    escaped_field(&package.arch)
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        rendered.push(format!(
            "id={};repository={};type={};status={};severity={};issued={};updated={};title={};summary={};description={};references=[{}];packages=[{}]",
            escaped_field(&entry.advisory.id),
            escaped_field(&entry.repository),
            escaped_field(&entry.advisory.kind),
            escaped_field(&entry.advisory.status),
            escaped_field(&entry.advisory.severity),
            escaped_field(&entry.advisory.issued),
            escaped_field(&entry.advisory.updated),
            escaped_field(&entry.advisory.title),
            escaped_field(&entry.advisory.summary),
            escaped_field(&entry.advisory.description),
            references,
            packages,
        ));
    }
    Ok(Response::completed(
        "advisory",
        format!("advisory_info=[{}]", rendered.join(";")),
    ))
}

pub(super) fn upgrade(arguments: AdvisoryUpgradeArgs) -> Result<Response, AppFailure> {
    if rustix::process::geteuid().as_raw() != 0 {
        return Err(AppFailure::new(1, "advisory upgrade requires root"));
    }
    validate_severity(arguments.severity.as_deref())?;
    let repositories = canonical_repository_ids(arguments.repositories)?;
    let (snapshot, catalog) = catalog(repositories.clone())?;
    let requested = validate_ids(arguments.advisories)?;
    let selected = if requested.is_empty() {
        catalog.values().collect::<Vec<_>>()
    } else {
        requested
            .iter()
            .map(|id| {
                catalog.get(id).ok_or_else(|| {
                    AppFailure::with_error_code(
                        1,
                        "advisory_not_found",
                        format!("advisory was not found in selected repositories: {id}"),
                    )
                })
            })
            .collect::<Result<Vec<_>, _>>()?
    };
    let mut packages = BTreeSet::new();
    for entry in selected {
        if matches_filter(
            &entry.advisory,
            arguments.security,
            arguments.severity.as_deref(),
        ) {
            packages.extend(applicable_packages(&snapshot, &entry.advisory)?);
        }
    }
    if packages.is_empty() {
        return Ok(Response::completed(
            "advisory",
            "no changes; no selected advisory applies to the current RPMDB",
        ));
    }
    run_convenience(
        PlanAction::Upgrade,
        MutationArgs {
            repositories,
            assumeyes: arguments.assumeyes,
            assumeno: arguments.assumeno,
            packages: packages.into_iter().collect(),
        },
    )
    .map(|response| response.with_command("advisory"))
}

fn catalog(
    repositories: Vec<String>,
) -> Result<(PlanningSnapshot, BTreeMap<String, CatalogEntry>), AppFailure> {
    let snapshot = PlanningSnapshot::open_system().map_err(snapshot_error)?;
    let repositories = selected(&snapshot, canonical_repository_ids(repositories)?)?;
    let mut catalog = BTreeMap::new();
    for repository in repositories {
        let Some(updateinfo) = snapshot.updateinfo(repository).map_err(snapshot_error)? else {
            continue;
        };
        for advisory in updateinfo.advisories {
            match catalog.get(&advisory.id) {
                None => {
                    catalog.insert(
                        advisory.id.clone(),
                        CatalogEntry {
                            repository: repository.id.clone(),
                            advisory,
                        },
                    );
                }
                Some(existing) if existing.advisory == advisory => {}
                Some(_) => {
                    return Err(AppFailure::with_error_code(
                        1,
                        "advisory_conflict",
                        format!(
                            "selected repositories publish conflicting advisory data: {}",
                            advisory.id
                        ),
                    ));
                }
            }
        }
    }
    Ok((snapshot, catalog))
}

fn applicable_packages(
    snapshot: &PlanningSnapshot,
    advisory: &Advisory,
) -> Result<BTreeSet<String>, AppFailure> {
    let mut packages = BTreeSet::new();
    for candidate in &advisory.packages {
        let Some(arch) = architecture(&candidate.arch) else {
            continue;
        };
        let epoch = u32::try_from(candidate.epoch).map_err(|_| {
            AppFailure::with_error_code(1, "invalid_updateinfo", "advisory epoch exceeds RPM range")
        })?;
        let candidate_evra = Evra::new(epoch, &candidate.version, &candidate.release, arch);
        if snapshot
            .payload()
            .inventory
            .packages()
            .iter()
            .any(|installed| applies_to(installed, &candidate.name, &candidate_evra))
        {
            packages.insert(candidate.name.clone());
        }
    }
    Ok(packages)
}

fn applies_to(installed: &InstalledPackage, name: &str, candidate: &Evra) -> bool {
    installed.name() == name
        && installed.evra().arch() == candidate.arch()
        && candidate.is_strictly_newer_than(installed.evra())
}

fn selected(
    snapshot: &PlanningSnapshot,
    repositories: Vec<String>,
) -> Result<Vec<&PlanningRepository>, AppFailure> {
    let ids = if repositories.is_empty() {
        snapshot
            .payload()
            .allowed_repositories
            .iter()
            .map(|repository| repository.id.clone())
            .collect::<Vec<_>>()
    } else {
        repositories
    };
    ids.into_iter()
        .map(|id| {
            snapshot
                .payload()
                .allowed_repositories
                .iter()
                .find(|repository| repository.id == id)
                .ok_or_else(|| {
                    AppFailure::with_error_code(
                        2,
                        "invalid_repository_selection",
                        format!("selected repository is not root-published and enabled: {id}"),
                    )
                })
        })
        .collect()
}

fn validate_ids(values: Vec<String>) -> Result<BTreeSet<String>, AppFailure> {
    let mut ids = BTreeSet::new();
    for value in values {
        if value.is_empty()
            || value.len() > 256
            || value
                .bytes()
                .any(|byte| !(byte.is_ascii_alphanumeric() || b"_.:-".contains(&byte)))
        {
            return Err(AppFailure::with_error_code(
                2,
                "invalid_arguments",
                "advisory identifiers contain invalid characters",
            ));
        }
        if !ids.insert(value) {
            return Err(AppFailure::with_error_code(
                2,
                "invalid_arguments",
                "advisory identifiers must be unique",
            ));
        }
    }
    Ok(ids)
}

fn validate_severity(severity: Option<&str>) -> Result<(), AppFailure> {
    if severity.is_some_and(|value| {
        value.is_empty()
            || value.len() > 64
            || value
                .bytes()
                .any(|byte| !(byte.is_ascii_alphanumeric() || byte == b'-'))
    }) {
        return Err(AppFailure::with_error_code(
            2,
            "invalid_arguments",
            "severity must contain only ASCII letters, digits, or dash",
        ));
    }
    Ok(())
}

fn matches_filter(advisory: &Advisory, security: bool, severity: Option<&str>) -> bool {
    (!security || advisory.kind.eq_ignore_ascii_case("security"))
        && severity.is_none_or(|value| advisory.severity.eq_ignore_ascii_case(value))
}

fn architecture(value: &str) -> Option<Architecture> {
    match value {
        "x86_64" => Some(Architecture::X86_64),
        "aarch64" => Some(Architecture::Aarch64),
        "noarch" => Some(Architecture::Noarch),
        _ => None,
    }
}

fn supported_arch(value: &str) -> bool {
    architecture(value).is_some()
}

fn snapshot_error(error: impl ToString) -> AppFailure {
    AppFailure::new(1, error.to_string())
}
