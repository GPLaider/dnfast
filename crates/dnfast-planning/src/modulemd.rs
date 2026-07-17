use std::collections::{BTreeMap, BTreeSet, VecDeque};

use dnfast_core::Architecture;
use serde::{Deserialize, Serialize};

use crate::{PlanningError, PlanningSnapshot};

const MAX_MODULES: usize = 16_384;
const MAX_STREAMS: usize = 131_072;
const MAX_ARTIFACTS: usize = 2_000_000;

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleState {
    pub entries: Vec<ModuleStateEntry>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleStateEntry {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream: Option<String>,
    pub disabled: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModuleMutation {
    Enable,
    Reset,
    Disable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModuleCatalog {
    modules: BTreeMap<String, Module>,
    artifact_owners: BTreeMap<String, (String, String)>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Module {
    pub name: String,
    pub default_stream: Option<String>,
    pub streams: BTreeMap<String, ModuleStream>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModuleStream {
    pub name: String,
    pub summary: String,
    pub description: String,
    pub profiles: Vec<ModuleProfile>,
    pub artifacts: Vec<String>,
    dependencies: Vec<ModuleDependencies>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModuleProfile {
    pub name: String,
    pub description: String,
    pub rpms: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct RawCatalog {
    modules: Vec<RawModule>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct RawModule {
    name: String,
    default_stream: Option<String>,
    streams: Vec<RawStream>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct RawStream {
    name: String,
    stream: String,
    version: u64,
    context: String,
    arch: String,
    summary: Option<String>,
    description: Option<String>,
    profiles: Vec<RawProfile>,
    dependencies: Vec<ModuleDependencies>,
    artifacts: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct RawProfile {
    name: String,
    description: Option<String>,
    rpms: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Ord, PartialOrd)]
#[serde(deny_unknown_fields)]
struct ModuleDependencies {
    requires: Vec<ModuleRequirement>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Ord, PartialOrd)]
#[serde(deny_unknown_fields)]
struct ModuleRequirement {
    module: String,
    streams: Vec<String>,
}

#[derive(Clone, Debug)]
struct LogicalStream {
    latest_version: u64,
    summary: String,
    description: String,
    profiles: Vec<ModuleProfile>,
    artifacts: BTreeSet<String>,
    dependencies: Vec<ModuleDependencies>,
}

impl ModuleState {
    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub(crate) fn validate(&self) -> Result<(), PlanningError> {
        if self
            .entries
            .windows(2)
            .any(|pair| pair[0].name >= pair[1].name)
        {
            return Err(input("module state is not canonical"));
        }
        for entry in &self.entries {
            identifier(&entry.name, "module state name")?;
            if let Some(stream) = &entry.stream {
                identifier(stream, "module state stream")?;
            }
            if entry.disabled == entry.stream.is_some() {
                return Err(input("module state entry has an invalid mode"));
            }
        }
        Ok(())
    }

    fn map(&self) -> BTreeMap<String, ModuleStateEntry> {
        self.entries
            .iter()
            .cloned()
            .map(|entry| (entry.name.clone(), entry))
            .collect()
    }
}

impl ModuleCatalog {
    pub fn modules(&self) -> impl Iterator<Item = &Module> {
        self.modules.values()
    }

    pub fn module(&self, name: &str) -> Option<&Module> {
        self.modules.get(name)
    }

    pub fn active_stream<'a>(&'a self, state: &'a ModuleState, name: &str) -> Option<&'a str> {
        match state.entries.iter().find(|entry| entry.name == name) {
            Some(entry) if entry.disabled => None,
            Some(entry) => entry.stream.as_deref(),
            None => self
                .modules
                .get(name)
                .and_then(|module| module.default_stream.as_deref()),
        }
    }

    pub fn mutate(
        &self,
        current: &ModuleState,
        operation: ModuleMutation,
        specs: &[String],
    ) -> Result<ModuleState, PlanningError> {
        current.validate()?;
        if specs.is_empty() {
            return Err(input("module mutation requires at least one specification"));
        }
        let mut entries = current.map();
        let mut requested = BTreeSet::new();
        for spec in specs {
            let (name, requested_stream) = parse_spec(spec)?;
            if !requested.insert(name.to_owned()) {
                return Err(input("module mutation specifications are duplicate"));
            }
            let module = self
                .modules
                .get(name)
                .ok_or_else(|| input(format!("module not found: {name}")))?;
            if let Some(stream) = requested_stream {
                if !module.streams.contains_key(stream) {
                    return Err(input(format!("module stream not found: {name}:{stream}")));
                }
            }
            match operation {
                ModuleMutation::Enable => {
                    let stream = requested_stream
                        .or(module.default_stream.as_deref())
                        .ok_or_else(|| {
                            input(format!("module stream must be specified: {name}:STREAM"))
                        })?;
                    entries.insert(
                        name.to_owned(),
                        ModuleStateEntry {
                            name: name.to_owned(),
                            stream: Some(stream.to_owned()),
                            disabled: false,
                        },
                    );
                }
                ModuleMutation::Reset => {
                    entries.remove(name);
                }
                ModuleMutation::Disable => {
                    entries.insert(
                        name.to_owned(),
                        ModuleStateEntry {
                            name: name.to_owned(),
                            stream: None,
                            disabled: true,
                        },
                    );
                }
            }
        }
        if operation == ModuleMutation::Enable {
            self.complete_dependencies(&mut entries, &requested)?;
        }
        let state = ModuleState {
            entries: entries.into_values().collect(),
        };
        self.validate_state(&state)?;
        Ok(state)
    }

    pub fn validate_state(&self, state: &ModuleState) -> Result<(), PlanningError> {
        state.validate()?;
        for entry in &state.entries {
            let module = self
                .modules
                .get(&entry.name)
                .ok_or_else(|| input(format!("enabled module disappeared: {}", entry.name)))?;
            if let Some(stream) = &entry.stream {
                if !module.streams.contains_key(stream) {
                    return Err(input(format!(
                        "enabled module stream disappeared: {}:{}",
                        entry.name, stream
                    )));
                }
            }
        }
        for module in self.modules.values() {
            let Some(stream_name) = self.active_stream(state, &module.name) else {
                continue;
            };
            let stream = module
                .streams
                .get(stream_name)
                .ok_or_else(|| input("active module stream is absent"))?;
            if !self.dependencies_satisfied(state, &stream.dependencies)? {
                return Err(input(format!(
                    "module dependencies are not satisfied: {}:{}",
                    module.name, stream_name
                )));
            }
        }
        Ok(())
    }

    pub fn excluded_artifacts(
        &self,
        state: &ModuleState,
        architecture: Architecture,
    ) -> Result<Vec<String>, PlanningError> {
        Ok(self
            .artifact_policies(state, architecture)?
            .into_iter()
            .filter_map(|(artifact, excluded)| excluded.then_some(artifact))
            .collect())
    }

    /// Returns the checksum-bound modular RPM identity set.  The value is
    /// `true` only for artifacts excluded by the current stream state.
    pub fn artifact_policies(
        &self,
        state: &ModuleState,
        architecture: Architecture,
    ) -> Result<BTreeMap<String, bool>, PlanningError> {
        self.validate_state(state)?;
        let mut policies = BTreeMap::new();
        for module in self.modules.values() {
            let active = self.active_stream(state, &module.name);
            for (stream_name, stream) in &module.streams {
                let excluded = active != Some(stream_name.as_str());
                for artifact in &stream.artifacts {
                    if artifact_matches_architecture(artifact, architecture)? {
                        policies.insert(artifact.clone(), excluded);
                    }
                }
            }
        }
        Ok(policies)
    }

    pub fn artifact_owner(&self, nevra: &str) -> Option<(&str, &str)> {
        self.artifact_owners
            .get(nevra)
            .map(|(module, stream)| (module.as_str(), stream.as_str()))
    }

    fn complete_dependencies(
        &self,
        entries: &mut BTreeMap<String, ModuleStateEntry>,
        roots: &BTreeSet<String>,
    ) -> Result<(), PlanningError> {
        let mut queue = VecDeque::from_iter(roots.iter().cloned());
        let mut visited = BTreeSet::new();
        while let Some(name) = queue.pop_front() {
            if !visited.insert(name.clone()) {
                continue;
            }
            let module = self
                .modules
                .get(&name)
                .ok_or_else(|| input("module disappeared"))?;
            let stream_name = match entries.get(&name) {
                Some(entry) if entry.disabled => {
                    return Err(input(format!("enabled module is disabled: {name}")));
                }
                Some(entry) => entry.stream.as_deref(),
                None => module.default_stream.as_deref(),
            }
            .ok_or_else(|| input(format!("module has no active stream: {name}")))?;
            let stream = module
                .streams
                .get(stream_name)
                .ok_or_else(|| input("module stream disappeared"))?;
            if stream.dependencies.is_empty() {
                continue;
            }
            let alternative = stream
                .dependencies
                .iter()
                .find(|alternative| self.alternative_can_resolve(entries, alternative))
                .ok_or_else(|| input(format!("module dependency conflict: {name}:{stream_name}")))?
                .clone();
            for requirement in alternative.requires {
                let selected = self.select_requirement(entries, &requirement)?;
                if let Some(existing) = entries.get(&requirement.module) {
                    if existing.disabled || existing.stream.as_deref() != Some(&selected) {
                        return Err(input(format!(
                            "module dependency conflicts with explicit state: {}",
                            requirement.module
                        )));
                    }
                } else {
                    entries.insert(
                        requirement.module.clone(),
                        ModuleStateEntry {
                            name: requirement.module.clone(),
                            stream: Some(selected),
                            disabled: false,
                        },
                    );
                }
                queue.push_back(requirement.module);
            }
        }
        Ok(())
    }

    fn alternative_can_resolve(
        &self,
        entries: &BTreeMap<String, ModuleStateEntry>,
        alternative: &ModuleDependencies,
    ) -> bool {
        alternative
            .requires
            .iter()
            .all(|requirement| self.select_requirement(entries, requirement).is_ok())
    }

    fn select_requirement(
        &self,
        entries: &BTreeMap<String, ModuleStateEntry>,
        requirement: &ModuleRequirement,
    ) -> Result<String, PlanningError> {
        let module = self
            .modules
            .get(&requirement.module)
            .ok_or_else(|| input(format!("required module not found: {}", requirement.module)))?;
        let allowed = requirement
            .streams
            .iter()
            .filter(|stream| !stream.starts_with('-'))
            .filter(|stream| module.streams.contains_key(*stream))
            .cloned()
            .collect::<BTreeSet<_>>();
        if allowed.is_empty()
            || requirement
                .streams
                .iter()
                .any(|stream| stream.starts_with('-'))
        {
            return Err(input(
                "negative or empty module dependency streams are unsupported",
            ));
        }
        if let Some(entry) = entries.get(&requirement.module) {
            return entry
                .stream
                .as_ref()
                .filter(|stream| !entry.disabled && allowed.contains(*stream))
                .cloned()
                .ok_or_else(|| input("explicit module state conflicts with a dependency"));
        }
        if let Some(default) = module
            .default_stream
            .as_ref()
            .filter(|stream| allowed.contains(*stream))
        {
            return Ok(default.clone());
        }
        if allowed.len() == 1 {
            return Ok(allowed.into_iter().next().expect("one allowed stream"));
        }
        Err(input("module dependency stream is ambiguous"))
    }

    fn dependencies_satisfied(
        &self,
        state: &ModuleState,
        alternatives: &[ModuleDependencies],
    ) -> Result<bool, PlanningError> {
        if alternatives.is_empty() {
            return Ok(true);
        }
        Ok(alternatives.iter().any(|alternative| {
            alternative.requires.iter().all(|requirement| {
                let Some(active) = self.active_stream(state, &requirement.module) else {
                    return false;
                };
                !requirement
                    .streams
                    .iter()
                    .any(|stream| stream.starts_with('-'))
                    && requirement.streams.iter().any(|allowed| allowed == active)
            })
        }))
    }
}

impl PlanningSnapshot {
    pub fn module_catalog(
        &self,
        selected_repository_ids: &[String],
    ) -> Result<ModuleCatalog, PlanningError> {
        let repositories = self.selected_repositories(selected_repository_ids)?;
        let mut raw = Vec::new();
        for repository in repositories {
            if repository.modules.is_none() {
                continue;
            }
            let bytes = self.module_metadata(repository)?.ok_or_else(|| {
                input("module descriptor disappeared during verified materialization")
            })?;
            let json = dnfast_native::parse_modulemd_json(&bytes)
                .map_err(|error| input(error.to_string()))?;
            let parsed: RawCatalog = serde_json::from_str(&json)
                .map_err(|error| input(format!("invalid native module catalog: {error}")))?;
            raw.extend(parsed.modules);
        }
        catalog_from_raw(raw, self.payload().policy.solver.base_arch())
    }

    pub fn module_excludes(
        &self,
        selected_repository_ids: &[String],
    ) -> Result<Vec<String>, PlanningError> {
        self.module_catalog(selected_repository_ids)?
            .excluded_artifacts(
                &self.payload().module_state,
                self.payload().policy.solver.base_arch(),
            )
    }
}

fn catalog_from_raw(
    raw_modules: Vec<RawModule>,
    architecture: Architecture,
) -> Result<ModuleCatalog, PlanningError> {
    if raw_modules.len() > MAX_MODULES {
        return Err(input("module catalog exceeds module limit"));
    }
    let mut modules: BTreeMap<String, (Option<String>, BTreeMap<String, LogicalStream>)> =
        BTreeMap::new();
    let mut stream_count = 0_usize;
    let mut artifact_count = 0_usize;
    for raw_module in raw_modules {
        identifier(&raw_module.name, "module name")?;
        if let Some(default) = &raw_module.default_stream {
            identifier(default, "module default stream")?;
        }
        let module = modules
            .entry(raw_module.name.clone())
            .or_insert_with(|| (raw_module.default_stream.clone(), BTreeMap::new()));
        match (&module.0, &raw_module.default_stream) {
            (Some(left), Some(right)) if left != right => {
                return Err(input(format!(
                    "repository module defaults conflict: {}",
                    raw_module.name
                )));
            }
            (None, Some(default)) => module.0 = Some(default.clone()),
            _ => {}
        }
        for mut raw in raw_module.streams {
            if raw.name != raw_module.name {
                return Err(input("module stream name differs from its module"));
            }
            identifier(&raw.stream, "module stream")?;
            identifier(&raw.context, "module context")?;
            identifier(&raw.arch, "module architecture")?;
            if !matches_arch(&raw.arch, architecture) {
                continue;
            }
            stream_count += 1;
            if stream_count > MAX_STREAMS {
                return Err(input("module catalog exceeds stream limit"));
            }
            normalize_strings(&mut raw.artifacts, "module artifact")?;
            artifact_count = artifact_count
                .checked_add(raw.artifacts.len())
                .ok_or_else(|| input("module artifact count overflow"))?;
            if artifact_count > MAX_ARTIFACTS {
                return Err(input("module catalog exceeds artifact limit"));
            }
            normalize_dependencies(&mut raw.dependencies)?;
            let profiles = normalize_profiles(raw.profiles)?;
            let summary = raw.summary.unwrap_or_default();
            let description = raw.description.unwrap_or_default();
            let incoming = LogicalStream {
                latest_version: raw.version,
                summary,
                description,
                profiles,
                artifacts: raw.artifacts.into_iter().collect(),
                dependencies: raw.dependencies,
            };
            match module.1.get_mut(&raw.stream) {
                None => {
                    module.1.insert(raw.stream, incoming);
                }
                Some(existing) => {
                    if existing.dependencies != incoming.dependencies
                        || existing.profiles != incoming.profiles
                    {
                        return Err(input(format!(
                            "module stream contexts have incompatible policy: {}:{}",
                            raw_module.name, raw.stream
                        )));
                    }
                    existing.artifacts.extend(incoming.artifacts);
                    if incoming.latest_version > existing.latest_version {
                        existing.latest_version = incoming.latest_version;
                        existing.summary = incoming.summary;
                        existing.description = incoming.description;
                    }
                }
            }
        }
    }
    let mut artifact_owners = BTreeMap::new();
    let mut result = BTreeMap::new();
    for (name, (default_stream, streams)) in modules {
        if let Some(default) = &default_stream {
            if !streams.contains_key(default) {
                return Err(input(format!(
                    "module default stream is absent: {name}:{default}"
                )));
            }
        }
        let mut final_streams = BTreeMap::new();
        for (stream_name, stream) in streams {
            let artifacts = stream.artifacts.into_iter().collect::<Vec<_>>();
            for artifact in &artifacts {
                if let Some((owner_module, owner_stream)) =
                    artifact_owners.insert(artifact.clone(), (name.clone(), stream_name.clone()))
                {
                    if owner_module != name || owner_stream != stream_name {
                        return Err(input(format!(
                            "module artifact belongs to multiple streams: {artifact}"
                        )));
                    }
                }
            }
            final_streams.insert(
                stream_name.clone(),
                ModuleStream {
                    name: stream_name,
                    summary: stream.summary,
                    description: stream.description,
                    profiles: stream.profiles,
                    artifacts,
                    dependencies: stream.dependencies,
                },
            );
        }
        result.insert(
            name.clone(),
            Module {
                name,
                default_stream,
                streams: final_streams,
            },
        );
    }
    let catalog = ModuleCatalog {
        modules: result,
        artifact_owners,
    };
    Ok(catalog)
}

fn normalize_profiles(raw: Vec<RawProfile>) -> Result<Vec<ModuleProfile>, PlanningError> {
    let mut profiles = raw
        .into_iter()
        .map(|mut profile| {
            identifier(&profile.name, "module profile")?;
            normalize_strings(&mut profile.rpms, "module profile RPM")?;
            Ok(ModuleProfile {
                name: profile.name,
                description: profile.description.unwrap_or_default(),
                rpms: profile.rpms,
            })
        })
        .collect::<Result<Vec<_>, PlanningError>>()?;
    profiles.sort_by(|left, right| left.name.cmp(&right.name));
    if profiles.windows(2).any(|pair| pair[0].name == pair[1].name) {
        return Err(input("module profiles are duplicate"));
    }
    Ok(profiles)
}

fn normalize_dependencies(values: &mut Vec<ModuleDependencies>) -> Result<(), PlanningError> {
    for alternative in values.iter_mut() {
        for requirement in &mut alternative.requires {
            identifier(&requirement.module, "required module")?;
            normalize_strings(&mut requirement.streams, "required module stream")?;
        }
        alternative
            .requires
            .sort_by(|left, right| left.module.cmp(&right.module));
        if alternative
            .requires
            .windows(2)
            .any(|pair| pair[0].module == pair[1].module)
        {
            return Err(input("module dependency requirements are duplicate"));
        }
    }
    values.sort();
    values.dedup();
    Ok(())
}

fn normalize_strings(values: &mut [String], kind: &str) -> Result<(), PlanningError> {
    for value in values.iter() {
        identifier(value.trim_start_matches('-'), kind)?;
    }
    values.sort();
    if values.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(input(format!("{kind} values are duplicate")));
    }
    Ok(())
}

fn parse_spec(spec: &str) -> Result<(&str, Option<&str>), PlanningError> {
    let mut parts = spec.split(':');
    let name = parts.next().unwrap_or_default();
    let stream = parts.next();
    if parts.next().is_some() {
        return Err(input("module spec must be NAME or NAME:STREAM"));
    }
    identifier(name, "module spec name")?;
    if let Some(stream) = stream {
        identifier(stream, "module spec stream")?;
    }
    Ok((name, stream))
}

fn identifier(value: &str, kind: &str) -> Result<(), PlanningError> {
    if value.is_empty()
        || value.len() > 4096
        || value.starts_with('-')
        || value.chars().any(char::is_control)
        || value.chars().any(char::is_whitespace)
    {
        return Err(input(format!("{kind} is invalid")));
    }
    Ok(())
}

fn matches_arch(value: &str, architecture: Architecture) -> bool {
    value == architecture.as_rpm_arch() || value == "noarch"
}

fn artifact_matches_architecture(
    value: &str,
    architecture: Architecture,
) -> Result<bool, PlanningError> {
    let (_, arch) = value
        .rsplit_once('.')
        .ok_or_else(|| input(format!("module artifact lacks architecture: {value}")))?;
    Ok(matches_arch(arch, architecture))
}

fn input(message: impl Into<String>) -> PlanningError {
    PlanningError::Input(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn catalog() -> ModuleCatalog {
        catalog_from_raw(
            vec![RawModule {
                name: "demo".into(),
                default_stream: Some("stable".into()),
                streams: vec![
                    RawStream {
                        name: "demo".into(),
                        stream: "stable".into(),
                        version: 1,
                        context: "c1".into(),
                        arch: "x86_64".into(),
                        summary: Some("stable".into()),
                        description: None,
                        profiles: Vec::new(),
                        dependencies: Vec::new(),
                        artifacts: vec!["demo-0:1-1.x86_64".into()],
                    },
                    RawStream {
                        name: "demo".into(),
                        stream: "next".into(),
                        version: 2,
                        context: "c2".into(),
                        arch: "x86_64".into(),
                        summary: Some("next".into()),
                        description: None,
                        profiles: Vec::new(),
                        dependencies: Vec::new(),
                        artifacts: vec!["demo-0:2-1.x86_64".into()],
                    },
                ],
            }],
            Architecture::X86_64,
        )
        .unwrap()
    }

    #[test]
    fn enable_reset_and_disable_are_canonical() {
        let catalog = catalog();
        let enabled = catalog
            .mutate(
                &ModuleState::default(),
                ModuleMutation::Enable,
                &["demo:next".into()],
            )
            .unwrap();
        assert_eq!(catalog.active_stream(&enabled, "demo"), Some("next"));
        assert_eq!(
            catalog
                .excluded_artifacts(&enabled, Architecture::X86_64)
                .unwrap(),
            ["demo-0:1-1.x86_64"]
        );
        let reset = catalog
            .mutate(&enabled, ModuleMutation::Reset, &["demo".into()])
            .unwrap();
        assert_eq!(catalog.active_stream(&reset, "demo"), Some("stable"));
        let disabled = catalog
            .mutate(&reset, ModuleMutation::Disable, &["demo".into()])
            .unwrap();
        assert_eq!(catalog.active_stream(&disabled, "demo"), None);
    }

    #[test]
    fn artifact_policy_marks_only_inactive_streams_excluded() {
        let catalog = catalog();
        let defaults = catalog
            .artifact_policies(&ModuleState::default(), Architecture::X86_64)
            .unwrap();
        assert_eq!(defaults.get("demo-0:1-1.x86_64"), Some(&false));
        assert_eq!(defaults.get("demo-0:2-1.x86_64"), Some(&true));

        let next = catalog
            .mutate(
                &ModuleState::default(),
                ModuleMutation::Enable,
                &["demo:next".into()],
            )
            .unwrap();
        let switched = catalog
            .artifact_policies(&next, Architecture::X86_64)
            .unwrap();
        assert_eq!(switched.get("demo-0:1-1.x86_64"), Some(&true));
        assert_eq!(switched.get("demo-0:2-1.x86_64"), Some(&false));
    }

    #[test]
    fn artifact_collision_fails_closed() {
        let mut raw = vec![RawModule {
            name: "one".into(),
            default_stream: None,
            streams: Vec::new(),
        }];
        raw[0].streams = ["a", "b"]
            .into_iter()
            .map(|stream| RawStream {
                name: "one".into(),
                stream: stream.into(),
                version: 1,
                context: stream.into(),
                arch: "x86_64".into(),
                summary: None,
                description: None,
                profiles: Vec::new(),
                dependencies: Vec::new(),
                artifacts: vec!["shared-0:1-1.x86_64".into()],
            })
            .collect();
        assert!(catalog_from_raw(raw, Architecture::X86_64).is_err());
    }
}
