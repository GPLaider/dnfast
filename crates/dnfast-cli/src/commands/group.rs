use std::collections::{BTreeMap, BTreeSet};

use dnfast_metadata::{CompsEnvironment, CompsGroup, CompsPackage, CompsPackageType};
use dnfast_planning::{PlanningRepository, PlanningSnapshot};

use crate::{
    args::{GroupInstallArgs, ModuleMutationArgs, MutationArgs, PlanAction},
    rendering::escaped_field,
    response::Response,
};

use super::{AppFailure, canonical_repository_ids, run_convenience};

#[derive(Default)]
struct Catalog {
    groups: BTreeMap<String, CompsGroup>,
    environments: BTreeMap<String, CompsEnvironment>,
}

pub(super) fn list(repositories: Vec<String>) -> Result<Response, AppFailure> {
    let (_, catalog) = catalog(repositories)?;
    let groups = catalog
        .groups
        .values()
        .filter(|group| group.user_visible)
        .map(|group| {
            format!(
                "{}={}",
                escaped_field(&group.id),
                escaped_field(&group.name)
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let environments = catalog
        .environments
        .values()
        .map(|environment| {
            format!(
                "{}={}",
                escaped_field(&environment.id),
                escaped_field(&environment.name)
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    Ok(Response::completed(
        "group",
        format!("groups=[{groups}]; environments=[{environments}]"),
    ))
}

pub(super) fn info(repositories: Vec<String>, id: &str) -> Result<Response, AppFailure> {
    validate_id(id, "group id")?;
    let (_, catalog) = catalog(repositories)?;
    if let Some(group) = catalog.groups.get(id) {
        let packages = group
            .packages
            .iter()
            .map(|package| {
                let kind = match package.kind {
                    CompsPackageType::Mandatory => "mandatory",
                    CompsPackageType::Default => "default",
                    CompsPackageType::Optional => "optional",
                    CompsPackageType::Conditional => "conditional",
                };
                match &package.condition {
                    Some(condition) => format!(
                        "{}:{kind}:requires={}",
                        escaped_field(&package.name),
                        escaped_field(condition)
                    ),
                    None => format!("{}:{kind}", escaped_field(&package.name)),
                }
            })
            .collect::<Vec<_>>()
            .join(",");
        return Ok(Response::completed(
            "group",
            format!(
                "group={}; name={}; description={}; default={}; user_visible={}; packages=[{}]",
                escaped_field(&group.id),
                escaped_field(&group.name),
                escaped_field(&group.description),
                group.default,
                group.user_visible,
                packages
            ),
        ));
    }
    if let Some(environment) = catalog.environments.get(id) {
        return Ok(Response::completed(
            "group",
            format!(
                "environment={}; name={}; description={}; groups=[{}]; optional_groups=[{}]",
                escaped_field(&environment.id),
                escaped_field(&environment.name),
                escaped_field(&environment.description),
                environment.groups.join(","),
                environment.optional_groups.join(",")
            ),
        ));
    }
    Err(not_found("group or environment", id))
}

pub(super) fn install(arguments: GroupInstallArgs) -> Result<Response, AppFailure> {
    if rustix::process::geteuid().as_raw() != 0 {
        return Err(AppFailure::new(1, "group install requires root"));
    }
    let repositories = canonical_repository_ids(arguments.repositories)?;
    let (snapshot, catalog) = catalog(repositories.clone())?;
    let mut requested_groups = BTreeSet::new();
    for id in &arguments.groups {
        validate_id(id, "group or environment id")?;
        if !requested_groups.insert(id.clone()) {
            return Err(AppFailure::with_error_code(
                2,
                "invalid_arguments",
                "group or environment identifiers must be unique",
            ));
        }
    }
    let mut selected_groups = BTreeSet::new();
    for id in requested_groups {
        if catalog.groups.contains_key(&id) {
            selected_groups.insert(id);
        } else if let Some(environment) = catalog.environments.get(&id) {
            selected_groups.extend(environment.groups.iter().cloned());
            if arguments.with_optional {
                selected_groups.extend(environment.optional_groups.iter().cloned());
            }
        } else {
            return Err(not_found("group or environment", &id));
        }
    }
    let mut packages = BTreeSet::new();
    let mut conditional = Vec::new();
    for id in selected_groups {
        let group = catalog
            .groups
            .get(&id)
            .ok_or_else(|| not_found("environment member group", &id))?;
        for package in &group.packages {
            match package.kind {
                CompsPackageType::Mandatory | CompsPackageType::Default => {
                    packages.insert(package.name.clone());
                }
                CompsPackageType::Optional if arguments.with_optional => {
                    packages.insert(package.name.clone());
                }
                CompsPackageType::Conditional => conditional.push(package.clone()),
                CompsPackageType::Optional => {}
            }
        }
    }
    let installed = snapshot
        .payload()
        .inventory
        .packages()
        .iter()
        .map(|package| package.name())
        .collect::<BTreeSet<_>>();
    loop {
        let before = packages.len();
        for package in &conditional {
            if package.condition.as_deref().is_some_and(|condition| {
                installed.contains(condition) || packages.contains(condition)
            }) {
                packages.insert(package.name.clone());
            }
        }
        if packages.len() == before {
            break;
        }
    }
    if packages.is_empty() {
        return Err(AppFailure::new(
            1,
            "selected group set has no installable mandatory/default packages",
        ));
    }
    run_convenience(
        PlanAction::Install,
        MutationArgs {
            repositories,
            assumeyes: arguments.assumeyes,
            assumeno: arguments.assumeno,
            packages: packages.into_iter().collect(),
        },
    )
}

pub(super) fn module_list(repositories: Vec<String>) -> Result<Response, AppFailure> {
    let snapshot = PlanningSnapshot::open_system().map_err(snapshot_error)?;
    let repositories = selected(&snapshot, canonical_repository_ids(repositories)?)?;
    for repository in repositories {
        if snapshot
            .module_metadata(repository)
            .map_err(snapshot_error)?
            .is_some()
        {
            return Err(AppFailure::new(
                1,
                "module metadata is present but this build cannot safely interpret modulemd",
            ));
        }
    }
    Ok(Response::completed("module", "modules=[]"))
}

pub(super) fn module_info(repositories: Vec<String>, spec: &str) -> Result<Response, AppFailure> {
    validate_id(spec, "module spec")?;
    module_absent(repositories, spec)
}

pub(super) fn module_mutation(
    operation: &str,
    arguments: ModuleMutationArgs,
) -> Result<Response, AppFailure> {
    if rustix::process::geteuid().as_raw() != 0 {
        return Err(AppFailure::new(
            1,
            format!("module {operation} requires root"),
        ));
    }
    let repositories = canonical_repository_ids(arguments.repositories)?;
    for spec in &arguments.specs {
        validate_id(spec, "module spec")?;
    }
    let spec = arguments.specs.join(",");
    module_absent(repositories, &spec)
}

fn module_absent(repositories: Vec<String>, spec: &str) -> Result<Response, AppFailure> {
    let snapshot = PlanningSnapshot::open_system().map_err(snapshot_error)?;
    for repository in selected(&snapshot, repositories)? {
        if snapshot
            .module_metadata(repository)
            .map_err(snapshot_error)?
            .is_some()
        {
            return Err(AppFailure::new(
                1,
                "module metadata is present but this build cannot safely interpret modulemd",
            ));
        }
    }
    Err(not_found("module", spec))
}

fn catalog(repositories: Vec<String>) -> Result<(PlanningSnapshot, Catalog), AppFailure> {
    let snapshot = PlanningSnapshot::open_system().map_err(snapshot_error)?;
    let repositories = selected(&snapshot, canonical_repository_ids(repositories)?)?;
    let mut catalog = Catalog::default();
    for repository in repositories {
        let Some(comps) = snapshot.comps(repository).map_err(snapshot_error)? else {
            continue;
        };
        for group in comps.groups {
            merge_group(&mut catalog.groups, group)?;
        }
        for environment in comps.environments {
            merge_environment(&mut catalog.environments, environment)?;
        }
    }
    Ok((snapshot, catalog))
}

fn merge_group(
    groups: &mut BTreeMap<String, CompsGroup>,
    incoming: CompsGroup,
) -> Result<(), AppFailure> {
    let Some(current) = groups.get_mut(&incoming.id) else {
        groups.insert(incoming.id.clone(), incoming);
        return Ok(());
    };
    let mut packages = current
        .packages
        .iter()
        .cloned()
        .map(|package| (package.name.clone(), package))
        .collect::<BTreeMap<_, _>>();
    for package in incoming.packages {
        match packages.get(&package.name) {
            None => {
                packages.insert(package.name.clone(), package);
            }
            Some(existing) if existing == &package => {}
            Some(existing) => {
                let selected = stronger(existing, &package);
                packages.insert(selected.name.clone(), selected);
            }
        }
    }
    current.packages = packages.into_values().collect();
    current.default |= incoming.default;
    current.user_visible |= incoming.user_visible;
    Ok(())
}

fn stronger(left: &CompsPackage, right: &CompsPackage) -> CompsPackage {
    let rank = |kind| match kind {
        CompsPackageType::Mandatory => 0,
        CompsPackageType::Default => 1,
        CompsPackageType::Conditional => 2,
        CompsPackageType::Optional => 3,
    };
    if rank(left.kind) <= rank(right.kind) {
        left.clone()
    } else {
        right.clone()
    }
}

fn merge_environment(
    environments: &mut BTreeMap<String, CompsEnvironment>,
    incoming: CompsEnvironment,
) -> Result<(), AppFailure> {
    let Some(current) = environments.get_mut(&incoming.id) else {
        environments.insert(incoming.id.clone(), incoming);
        return Ok(());
    };
    current.groups.extend(incoming.groups);
    current.optional_groups.extend(incoming.optional_groups);
    current.groups.sort();
    current.groups.dedup();
    current.optional_groups.sort();
    current.optional_groups.dedup();
    current
        .optional_groups
        .retain(|id| current.groups.binary_search(id).is_err());
    Ok(())
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
                        "selected repository is not root-published and enabled",
                    )
                })
        })
        .collect()
}

fn validate_id(value: &str, kind: &str) -> Result<(), AppFailure> {
    if value.is_empty()
        || value.starts_with('-')
        || value.chars().any(char::is_control)
        || value.chars().any(char::is_whitespace)
    {
        return Err(AppFailure::with_error_code(
            2,
            "invalid_arguments",
            format!("{kind} is invalid"),
        ));
    }
    Ok(())
}

fn not_found(kind: &str, value: &str) -> AppFailure {
    AppFailure::with_error_code(1, "not_found", format!("{kind} not found: {value}"))
}

fn snapshot_error(error: dnfast_planning::PlanningError) -> AppFailure {
    AppFailure::new(1, error.to_string())
}
