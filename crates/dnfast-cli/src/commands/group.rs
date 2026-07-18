use std::collections::{BTreeMap, BTreeSet};

use dnfast_metadata::{CompsEnvironment, CompsGroup, CompsPackage, CompsPackageType};
use dnfast_planning::{
    ModuleMutation, ModuleState, PlanningRepository, PlanningSnapshot, RootPlanningPublisher,
};

use crate::{
    args::{GroupInstallArgs, ModuleInstallArgs, ModuleMutationArgs, MutationArgs, PlanAction},
    rendering::escaped_field,
    response::Response,
};

use super::{AppFailure, canonical_repository_ids, run_convenience, run_convenience_with_plan};

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
    let selected = selected_group_package_map(
        &snapshot,
        &catalog,
        &arguments.groups,
        arguments.with_optional,
    )?;
    let packages = selected
        .values()
        .flatten()
        .cloned()
        .collect::<BTreeSet<_>>();
    if packages.is_empty() {
        return Err(AppFailure::new(
            1,
            "selected group set has no installable mandatory/default packages",
        ));
    }
    let installed = snapshot
        .payload()
        .inventory
        .packages()
        .iter()
        .map(|package| package.name())
        .collect::<BTreeSet<_>>();
    let records = selected
        .into_iter()
        .map(|(id, packages)| dnfast_state::GroupRecord {
            id,
            owned_packages: packages.into_iter().collect(),
        })
        .collect::<Vec<_>>();
    let introduced_packages = packages
        .iter()
        .filter(|package| !installed.contains(package.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    let store = dnfast_state::GroupStateStore::open_system()
        .map_err(|error| AppFailure::new(1, error.to_string()))?;
    run_convenience_with_plan(
        PlanAction::Install,
        MutationArgs {
            repositories,
            assumeyes: arguments.assumeyes,
            assumeno: arguments.assumeno,
            packages: packages.into_iter().collect(),
        },
        move |plan| match plan {
            Some(plan) => store
                .record_pending_install(
                    plan.digest()
                        .map_err(|error| AppFailure::new(1, error.to_string()))?
                        .as_str(),
                    &records,
                    &introduced_packages,
                )
                .map_err(|error| AppFailure::new(1, error.to_string())),
            None => store
                .apply_install_now(&records, &introduced_packages)
                .map_err(|error| AppFailure::new(1, error.to_string())),
        },
    )
}

pub(super) fn remove(arguments: GroupInstallArgs) -> Result<Response, AppFailure> {
    if rustix::process::geteuid().as_raw() != 0 {
        return Err(AppFailure::new(1, "group remove requires root"));
    }
    let repositories = canonical_repository_ids(arguments.repositories)?;
    let (snapshot, catalog) = catalog(repositories.clone())?;
    let installed = snapshot
        .payload()
        .inventory
        .packages()
        .iter()
        .map(|package| package.name())
        .collect::<BTreeSet<_>>();
    let selected = selected_group_package_map(
        &snapshot,
        &catalog,
        &arguments.groups,
        arguments.with_optional,
    )?;
    let group_ids = selected.into_keys().collect::<Vec<_>>();
    let store = dnfast_state::GroupStateStore::open_system()
        .map_err(|error| AppFailure::new(1, error.to_string()))?;
    let packages = store
        .packages_to_remove(&group_ids)
        .map_err(|error| AppFailure::new(1, error.to_string()))?
        .into_iter()
        .filter(|package| installed.contains(package.as_str()))
        .collect::<Vec<_>>();
    if packages.is_empty() {
        store
            .apply_remove_now(&group_ids)
            .map_err(|error| AppFailure::new(1, error.to_string()))?;
        return Ok(Response::completed(
            "group",
            "no changes; selected group packages are already absent",
        ));
    }
    run_convenience_with_plan(
        PlanAction::Remove,
        MutationArgs {
            repositories,
            assumeyes: arguments.assumeyes,
            assumeno: arguments.assumeno,
            packages,
        },
        move |plan| match plan {
            Some(plan) => store
                .record_pending_remove(
                    plan.digest()
                        .map_err(|error| AppFailure::new(1, error.to_string()))?
                        .as_str(),
                    &group_ids,
                )
                .map_err(|error| AppFailure::new(1, error.to_string())),
            None => store
                .apply_remove_now(&group_ids)
                .map_err(|error| AppFailure::new(1, error.to_string())),
        },
    )
}

fn selected_group_package_map(
    snapshot: &PlanningSnapshot,
    catalog: &Catalog,
    requested: &[String],
    with_optional: bool,
) -> Result<BTreeMap<String, BTreeSet<String>>, AppFailure> {
    let mut requested_groups = BTreeSet::new();
    for id in requested {
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
            if with_optional {
                selected_groups.extend(environment.optional_groups.iter().cloned());
            }
        } else {
            return Err(not_found("group or environment", &id));
        }
    }
    let mut packages = BTreeMap::<String, BTreeSet<String>>::new();
    let mut conditional = BTreeMap::<String, Vec<CompsPackage>>::new();
    for id in selected_groups {
        let group = catalog
            .groups
            .get(&id)
            .ok_or_else(|| not_found("environment member group", &id))?;
        let selected = packages.entry(id.clone()).or_default();
        for package in &group.packages {
            match package.kind {
                CompsPackageType::Mandatory | CompsPackageType::Default => {
                    selected.insert(package.name.clone());
                }
                CompsPackageType::Optional if with_optional => {
                    selected.insert(package.name.clone());
                }
                CompsPackageType::Conditional => conditional
                    .entry(id.clone())
                    .or_default()
                    .push(package.clone()),
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
        let available = packages
            .values()
            .flatten()
            .cloned()
            .chain(installed.iter().map(|value| (*value).to_owned()))
            .collect::<BTreeSet<_>>();
        let before = packages.values().map(BTreeSet::len).sum::<usize>();
        for (id, conditionals) in &conditional {
            for package in conditionals {
                if package
                    .condition
                    .as_deref()
                    .is_some_and(|condition| available.contains(condition))
                {
                    packages
                        .get_mut(id)
                        .expect("selected group has a package set")
                        .insert(package.name.clone());
                }
            }
        }
        if packages.values().map(BTreeSet::len).sum::<usize>() == before {
            break;
        }
    }
    Ok(packages)
}

pub(super) fn module_list(repositories: Vec<String>) -> Result<Response, AppFailure> {
    let snapshot = PlanningSnapshot::open_system().map_err(snapshot_error)?;
    let repository_ids = canonical_repository_ids(repositories)?;
    let catalog = snapshot
        .module_catalog(&repository_ids)
        .map_err(snapshot_error)?;
    let mut modules = Vec::new();
    for module in catalog.modules() {
        let active = catalog.active_stream(&snapshot.payload().module_state, &module.name);
        let explicit = snapshot
            .payload()
            .module_state
            .entries
            .iter()
            .find(|entry| entry.name == module.name);
        for stream in module.streams.values() {
            let status = if explicit.is_some_and(|entry| entry.disabled) {
                "disabled"
            } else if active == Some(stream.name.as_str()) && explicit.is_some() {
                "enabled"
            } else if active == Some(stream.name.as_str()) {
                "default"
            } else {
                "inactive"
            };
            modules.push(format!(
                "{}:{}:{}:{}",
                escaped_field(&module.name),
                escaped_field(&stream.name),
                status,
                escaped_field(&stream.summary)
            ));
        }
    }
    Ok(Response::completed(
        "module",
        format!("modules=[{}]", modules.join(",")),
    ))
}

pub(super) fn module_info(repositories: Vec<String>, spec: &str) -> Result<Response, AppFailure> {
    validate_id(spec, "module spec")?;
    let snapshot = PlanningSnapshot::open_system().map_err(snapshot_error)?;
    let repository_ids = canonical_repository_ids(repositories)?;
    let catalog = snapshot
        .module_catalog(&repository_ids)
        .map_err(snapshot_error)?;
    let (name, requested_stream) = module_spec(spec)?;
    let module = catalog
        .module(name)
        .ok_or_else(|| not_found("module", name))?;
    let active = catalog.active_stream(&snapshot.payload().module_state, name);
    let streams = match requested_stream {
        Some(stream) => vec![
            module
                .streams
                .get(stream)
                .ok_or_else(|| not_found("module stream", spec))?,
        ],
        None => module.streams.values().collect(),
    };
    let rendered = streams
        .into_iter()
        .map(|stream| {
            let profiles = stream
                .profiles
                .iter()
                .map(|profile| {
                    format!(
                        "{}=[{}]",
                        escaped_field(&profile.name),
                        profile
                            .rpms
                            .iter()
                            .map(|rpm| escaped_field(rpm))
                            .collect::<Vec<_>>()
                            .join(",")
                    )
                })
                .collect::<Vec<_>>()
                .join(",");
            format!(
                "{}:{}:active={}:summary={}:description={}:profiles=[{}]:artifacts={}",
                escaped_field(name),
                escaped_field(&stream.name),
                active == Some(stream.name.as_str()),
                escaped_field(&stream.summary),
                escaped_field(&stream.description),
                profiles,
                stream.artifacts.len()
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    Ok(Response::completed(
        "module",
        format!("streams=[{rendered}]"),
    ))
}

pub(super) fn module_install(arguments: ModuleInstallArgs) -> Result<Response, AppFailure> {
    if rustix::process::geteuid().as_raw() != 0 {
        return Err(AppFailure::new(1, "module install requires root"));
    }
    let repositories = canonical_repository_ids(arguments.repositories)?;
    let snapshot = PlanningSnapshot::open_system().map_err(snapshot_error)?;
    let catalog = snapshot
        .module_catalog(&repositories)
        .map_err(snapshot_error)?;
    let mut unique = BTreeSet::new();
    let mut packages = BTreeSet::new();
    for spec in &arguments.specs {
        validate_id(spec, "module profile spec")?;
        if !unique.insert(spec.clone()) {
            return Err(AppFailure::with_error_code(
                2,
                "invalid_arguments",
                "module profile specs must be unique",
            ));
        }
        let (module_stream_spec, profile_name) = module_profile_spec(spec)?;
        let (name, requested_stream) = module_spec(module_stream_spec)?;
        let module = catalog
            .module(name)
            .ok_or_else(|| not_found("module", name))?;
        let active = catalog
            .active_stream(&snapshot.payload().module_state, name)
            .ok_or_else(|| AppFailure::new(1, format!("module has no active stream: {name}")))?;
        if requested_stream.is_some_and(|stream| stream != active) {
            return Err(AppFailure::with_error_code(
                1,
                "module_stream_inactive",
                format!(
                    "module stream is not active: {name}:{}; enable it before profile install",
                    requested_stream.expect("checked stream")
                ),
            ));
        }
        let stream = module
            .streams
            .get(active)
            .ok_or_else(|| not_found("active module stream", active))?;
        let profile = stream
            .profiles
            .iter()
            .find(|profile| profile.name == profile_name)
            .ok_or_else(|| not_found("module profile", spec))?;
        packages.extend(profile.rpms.iter().cloned());
    }
    if packages.is_empty() {
        return Ok(Response::completed(
            "module",
            "no changes; selected module profiles contain no packages",
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

fn module_profile_spec(spec: &str) -> Result<(&str, &str), AppFailure> {
    let mut parts = spec.split('/');
    let module = parts.next().unwrap_or_default();
    let profile = parts.next().unwrap_or_default();
    if parts.next().is_some() || module.is_empty() || profile.is_empty() {
        return Err(AppFailure::with_error_code(
            2,
            "invalid_arguments",
            "module profile spec must be NAME[:STREAM]/PROFILE",
        ));
    }
    Ok((module, profile))
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
    let operation_kind = match operation {
        "enable" => ModuleMutation::Enable,
        "reset" => ModuleMutation::Reset,
        "disable" => ModuleMutation::Disable,
        _ => return Err(AppFailure::new(1, "unsupported module mutation")),
    };
    let snapshot = PlanningSnapshot::open_system().map_err(snapshot_error)?;
    let selected_catalog = snapshot
        .module_catalog(&repositories)
        .map_err(snapshot_error)?;
    for spec in &arguments.specs {
        let (name, _) = module_spec(spec)?;
        if selected_catalog.module(name).is_none() {
            return Err(not_found("module in selected repositories", name));
        }
    }
    if operation_kind == ModuleMutation::Enable {
        // Validate the entire requested stream/dependency closure against the
        // explicitly selected repositories before publishing global state.
        // This prevents `--repo` from authorizing a stream that is only
        // present in some other enabled repository.
        selected_catalog
            .mutate(&ModuleState::default(), operation_kind, &arguments.specs)
            .map_err(snapshot_error)?;
    }
    let catalog = snapshot.module_catalog(&[]).map_err(snapshot_error)?;
    let state = catalog
        .mutate(
            &snapshot.payload().module_state,
            operation_kind,
            &arguments.specs,
        )
        .map_err(snapshot_error)?;
    let source = snapshot.digest().map_err(snapshot_error)?;
    let published = RootPlanningPublisher::system()
        .map_err(snapshot_error)?
        .publish_module_state_onto_current(&source, state)
        .map_err(snapshot_error)?;
    Ok(Response::completed(
        "module",
        format!(
            "operation={operation}; modules=[{}]; planning_snapshot={published}",
            arguments
                .specs
                .iter()
                .map(|spec| escaped_field(spec))
                .collect::<Vec<_>>()
                .join(",")
        ),
    ))
}

fn module_spec(spec: &str) -> Result<(&str, Option<&str>), AppFailure> {
    let mut parts = spec.split(':');
    let name = parts.next().unwrap_or_default();
    let stream = parts.next();
    if parts.next().is_some() || name.is_empty() || stream.is_some_and(str::is_empty) {
        return Err(AppFailure::with_error_code(
            2,
            "invalid_arguments",
            "module spec must be NAME or NAME:STREAM",
        ));
    }
    Ok((name, stream))
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
