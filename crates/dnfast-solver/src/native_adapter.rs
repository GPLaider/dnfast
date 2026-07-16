use std::collections::{BTreeMap, BTreeSet, HashMap};

use serde::{Deserialize, Serialize};

use crate::{
    CandidatePackage, DependencyEdge, DependencyKind, PlanError, ResolvedAction, ResolvedOperation,
};
use dnfast_core::PackageSpec;

type ResolvedIdentity = (
    ResolvedOperation,
    String,
    Option<u64>,
    Option<String>,
    Option<String>,
);

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeAction {
    pub kind: String,
    pub repository: String,
    pub nevra: String,
    pub old_nevra: Option<String>,
    pub installed_instance: Option<u64>,
    pub installed_header_sha256: Option<String>,
    pub requested_spec: Option<PackageSpec>,
    pub requested_relation: bool,
    pub provenance: Option<crate::ActionProvenance>,
    pub transaction_counterpart_nevra: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeDecision {
    pub requiring_nevra: String,
    pub requiring_repo: String,
    pub requirement: dnfast_metadata::Relation,
    pub kind: DependencyKind,
    pub provider_nevra: String,
    pub provider_repo: String,
    pub provider_installed: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeSolveOutput {
    pub source_transcript_sha256: String,
    pub actions: Vec<NativeAction>,
    pub decisions: Vec<NativeDecision>,
    #[serde(default)]
    pub satisfied_specs: Vec<PackageSpec>,
}

impl NativeSolveOutput {
    pub fn from_native(
        result: dnfast_native::SolveResult,
        source_transcript_sha256: String,
        metadata: &[(&str, &dnfast_metadata::CompletePackage)],
        inventory: &dnfast_core::InstalledInventory,
    ) -> Result<Self, PlanError> {
        if result.actions.len() != result.repositories.len()
            || result.actions.len() != result.kinds.len()
            || result.actions.len() != result.obsoletes.len()
            || result.actions.len() != result.requested_specs.len()
            || result.actions.len() != result.requested_relation_kinds.len()
        {
            return Err(PlanError::Invalid("native action columns differ"));
        }
        let mut identities = BTreeMap::new();
        for (nevra, repo) in result.actions.iter().zip(&result.repositories) {
            if identities.insert(nevra.clone(), repo.clone()).is_some() {
                return Err(PlanError::DuplicateAction(nevra.clone()));
            }
        }
        let mut metadata_index = HashMap::<&str, HashMap<String, _>>::new();
        for (repository, package) in metadata {
            metadata_index
                .entry(*repository)
                .or_default()
                .insert(complete_nevra(package), *package);
        }
        let raw = result
            .actions
            .into_iter()
            .zip(result.repositories)
            .zip(result.kinds)
            .zip(result.obsoletes)
            .zip(result.requested_specs)
            .zip(result.requested_relation_kinds)
            .map(
                |(
                    ((((nevra, repository), kind), transaction_counterpart_nevra), requested_spec),
                    requested_relation,
                )| {
                    Ok(NativeAction {
                        kind,
                        repository,
                        nevra,
                        old_nevra: None,
                        installed_instance: None,
                        installed_header_sha256: None,
                        requested_spec: requested_spec
                            .map(PackageSpec::parse)
                            .transpose()
                            .map_err(|_| {
                                PlanError::Invalid("native requested selector is invalid")
                            })?,
                        requested_relation,
                        provenance: None,
                        transaction_counterpart_nevra,
                    })
                },
            )
            .collect::<Result<Vec<_>, PlanError>>()?;
        let actions = pair_actions(raw, inventory)?;
        let decisions = result
            .decisions
            .into_iter()
            .map(|item| {
                let requiring_repo = identities
                    .get(&item.requiring)
                    .cloned()
                    .ok_or_else(|| PlanError::MissingParent(item.requiring.clone()))?;
                let provider_repo = if item.provider_installed {
                    "@System".into()
                } else {
                    identities
                        .get(&item.provider)
                        .cloned()
                        .ok_or_else(|| PlanError::Unresolved(item.provider.clone()))?
                };
                let package = metadata_index
                    .get(requiring_repo.as_str())
                    .and_then(|packages| packages.get(item.requiring.as_str()))
                    .copied()
                    .ok_or(PlanError::Invalid(
                        "native requiring identity absent from rpm-md",
                    ))?;
                let kind = if item.weak {
                    DependencyKind::Weak
                } else {
                    DependencyKind::Strong
                };
                let provider_package = (!item.provider_installed)
                    .then(|| {
                        metadata_index
                            .get(provider_repo.as_str())
                            .and_then(|packages| packages.get(item.provider.as_str()))
                            .copied()
                            .ok_or(PlanError::Invalid(
                                "native provider identity absent from rpm-md",
                            ))
                    })
                    .transpose()?;
                let requirement =
                    decision_requirement(package, provider_package, item.weak, &item.relation)?;
                Ok(NativeDecision {
                    requiring_nevra: item.requiring,
                    requiring_repo,
                    requirement,
                    kind,
                    provider_nevra: item.provider,
                    provider_repo,
                    provider_installed: item.provider_installed,
                })
            })
            .collect::<Result<Vec<_>, PlanError>>()?;
        let satisfied_specs = result
            .satisfied_specs
            .into_iter()
            .map(PackageSpec::parse)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| PlanError::Invalid("native satisfied selector is invalid"))?;
        Ok(Self {
            source_transcript_sha256,
            actions,
            decisions,
            satisfied_specs,
        })
    }

    pub fn satisfied_specs(&self) -> &[PackageSpec] {
        &self.satisfied_specs
    }

    pub fn into_resolved(
        self,
        requested: &[&str],
        candidates: &[CandidatePackage],
        metadata: &[(&str, &dnfast_metadata::CompletePackage)],
        inventory: &dnfast_core::InstalledInventory,
    ) -> Result<Vec<ResolvedAction>, PlanError> {
        if self.source_transcript_sha256.len() != 64
            || !self
                .source_transcript_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(PlanError::Invalid("invalid native transcript digest"));
        }
        let expected_specs = requested
            .iter()
            .map(|value| {
                PackageSpec::parse(*value)
                    .map(|item| item.as_str().to_owned())
                    .map_err(|_| PlanError::Invalid("requested selector is invalid"))
            })
            .collect::<Result<BTreeSet<_>, _>>()?;
        if expected_specs.len() != requested.len() {
            return Err(PlanError::Invalid("requested selector is duplicated"));
        }
        let action_ids = self
            .actions
            .iter()
            .map(|item| (item.nevra.as_str(), item.repository.as_str()))
            .collect::<BTreeSet<_>>();
        if action_ids.len() != self.actions.len() {
            return Err(PlanError::DuplicateAction("native identity".into()));
        }
        let mut assigned_specs = BTreeSet::new();
        for action in &self.actions {
            if action.requested_relation && action.requested_spec.is_none() {
                return Err(PlanError::Invalid("native relation selector is missing"));
            }
            if let Some(spec) = &action.requested_spec {
                if !expected_specs.contains(spec.as_str()) {
                    return Err(PlanError::Invalid(
                        "native selector is not in requested intent",
                    ));
                }
                if !assigned_specs.insert(spec.as_str()) {
                    return Err(PlanError::Invalid(
                        "native selector provenance is duplicated",
                    ));
                }
            }
        }
        let mut satisfied_specs = BTreeSet::new();
        for spec in &self.satisfied_specs {
            if !expected_specs.contains(spec.as_str()) {
                return Err(PlanError::Invalid(
                    "native satisfied selector is not in requested intent",
                ));
            }
            if assigned_specs.contains(spec.as_str()) || !satisfied_specs.insert(spec.as_str()) {
                return Err(PlanError::Invalid(
                    "native selector provenance is duplicated",
                ));
            }
        }
        if assigned_specs.len() + satisfied_specs.len() != expected_specs.len() {
            return Err(PlanError::Invalid("native selector provenance is missing"));
        }
        self.validate_decisions(&action_ids, metadata, inventory)?;
        let mut candidate_index = HashMap::<&str, HashMap<String, _>>::new();
        for candidate in candidates {
            candidate_index
                .entry(candidate.repo_id.as_str())
                .or_default()
                .insert(full_nevra(candidate), candidate);
        }
        self.actions
            .into_iter()
            .map(|action| {
                let candidate = candidate_index
                    .get(action.repository.as_str())
                    .and_then(|packages| packages.get(action.nevra.as_str()))
                    .copied()
                    .cloned();
                let (operation, name, instance, header, vendor) =
                    action_identity(&action, candidate.as_ref(), inventory)?;
                let edges = self
                    .decisions
                    .iter()
                    .filter(|decision| {
                        !decision.provider_installed
                            && decision.provider_nevra == action.nevra
                            && decision.provider_repo == action.repository
                            && (decision.requiring_nevra != decision.provider_nevra
                                || decision.requiring_repo != decision.provider_repo)
                    })
                    .map(|decision| {
                        Ok(DependencyEdge {
                            parent: nevra_name(&decision.requiring_nevra)?,
                            kind: decision.kind,
                        })
                    })
                    .collect::<Result<Vec<_>, PlanError>>()?;
                let requested_spec = action.requested_spec;
                let requested = requested_spec.is_some()
                    || (expected_specs.is_empty() && operation == ResolvedOperation::Upgrade);
                Ok(ResolvedAction {
                    operation,
                    requested,
                    requested_spec,
                    requested_relation: action.requested_relation,
                    name,
                    candidate,
                    installed_instance: instance,
                    installed_header_sha256: header,
                    installed_vendor: vendor,
                    dependency_edges: edges,
                    required_by_remaining: vec![],
                    unresolved_dependencies: vec![],
                    provenance: action.provenance,
                    introduced_by_requested: false,
                    solver_rule: "libsolv typed causal decision".into(),
                })
            })
            .collect()
    }

    fn validate_decisions(
        &self,
        actions: &BTreeSet<(&str, &str)>,
        metadata: &[(&str, &dnfast_metadata::CompletePackage)],
        inventory: &dnfast_core::InstalledInventory,
    ) -> Result<(), PlanError> {
        let mut metadata_index = HashMap::<&str, HashMap<String, _>>::new();
        for (repository, package) in metadata {
            metadata_index
                .entry(*repository)
                .or_default()
                .insert(complete_nevra(package), *package);
        }
        for decision in &self.decisions {
            if !actions.contains(&(
                decision.requiring_nevra.as_str(),
                decision.requiring_repo.as_str(),
            )) {
                return Err(PlanError::MissingParent(decision.requiring_nevra.clone()));
            }
            if !decision.provider_installed
                && !actions.contains(&(
                    decision.provider_nevra.as_str(),
                    decision.provider_repo.as_str(),
                ))
            {
                return Err(PlanError::Unresolved(decision.requiring_nevra.clone()));
            }
            if decision.provider_installed {
                if decision.provider_repo != "@System" {
                    return Err(PlanError::Invalid("installed provider repository differs"));
                }
                unique_installed(&decision.provider_nevra, inventory)?;
            } else if decision.provider_repo == "@System" {
                return Err(PlanError::Invalid("action provider marked as system"));
            }
            let requiring = metadata_index
                .get(decision.requiring_repo.as_str())
                .and_then(|packages| packages.get(decision.requiring_nevra.as_str()))
                .copied()
                .ok_or(PlanError::Invalid(
                    "native requiring identity absent from rpm-md",
                ))?;
            let provider = (!decision.provider_installed)
                .then(|| {
                    metadata_index
                        .get(decision.provider_repo.as_str())
                        .and_then(|packages| packages.get(decision.provider_nevra.as_str()))
                        .copied()
                        .ok_or(PlanError::Invalid(
                            "native provider identity absent from rpm-md",
                        ))
                })
                .transpose()?;
            let weak = decision.kind == DependencyKind::Weak;
            if decision_requirement(
                requiring,
                provider,
                weak,
                &relation_text(&decision.requirement),
            )? != decision.requirement
            {
                return Err(PlanError::Invalid(
                    "native decision relation differs from rpm-md",
                ));
            }
        }
        Ok(())
    }
}

fn decision_requirement(
    requiring: &dnfast_metadata::CompletePackage,
    provider: Option<&dnfast_metadata::CompletePackage>,
    weak: bool,
    relation: &str,
) -> Result<dnfast_metadata::Relation, PlanError> {
    let direct = if weak {
        &requiring.recommends
    } else {
        &requiring.requires
    };
    let mut direct_matches = direct.iter().filter(|item| relation_text(item) == relation);
    if let Some(found) = direct_matches.next() {
        if direct_matches.next().is_some() {
            return Err(PlanError::Invalid("native relation is ambiguous in rpm-md"));
        }
        return Ok(found.clone());
    }
    if weak {
        if let Some(provider) = provider {
            let mut reverse_matches = provider
                .supplements
                .iter()
                .chain(&provider.enhances)
                .filter(|item| relation_text(item) == relation);
            if let Some(found) = reverse_matches.next() {
                if reverse_matches.next().is_some() {
                    return Err(PlanError::Invalid(
                        "native reverse relation is ambiguous in rpm-md",
                    ));
                }
                return Ok(found.clone());
            }
        }
    }
    Err(PlanError::Invalid("native relation absent from rpm-md"))
}

fn action_identity(
    action: &NativeAction,
    candidate: Option<&CandidatePackage>,
    inventory: &dnfast_core::InstalledInventory,
) -> Result<ResolvedIdentity, PlanError> {
    match action.kind.as_str() {
        "install" | "obsoletes" => {
            let value =
                candidate.ok_or(PlanError::Invalid("native install missing exact candidate"))?;
            Ok((
                ResolvedOperation::Install,
                value.name.clone(),
                None,
                None,
                None,
            ))
        }
        "upgrade" => {
            let value =
                candidate.ok_or(PlanError::Invalid("native upgrade missing exact candidate"))?;
            let old = exact_installed(action, inventory)?;
            Ok((
                ResolvedOperation::Upgrade,
                value.name.clone(),
                Some(old.db_instance()),
                Some(old.immutable_header_sha256().as_str().into()),
                Some(old.vendor().into()),
            ))
        }
        "erase" | "obsoleted" => {
            let old = exact_installed(action, inventory)?;
            Ok((
                ResolvedOperation::Remove,
                old.name().into(),
                Some(old.db_instance()),
                Some(old.immutable_header_sha256().as_str().into()),
                Some(old.vendor().into()),
            ))
        }
        _ => Err(PlanError::ConflictingAction(action.nevra.clone())),
    }
}

fn exact_installed<'a>(
    action: &NativeAction,
    inventory: &'a dnfast_core::InstalledInventory,
) -> Result<&'a dnfast_core::InstalledPackage, PlanError> {
    let nevra = action.old_nevra.as_deref().unwrap_or(&action.nevra);
    let instance = action
        .installed_instance
        .ok_or(PlanError::Invalid("native old action missing instance"))?;
    let header = action
        .installed_header_sha256
        .as_deref()
        .ok_or(PlanError::Invalid("native old action missing header"))?;
    inventory
        .erase_target(instance, header)
        .map_err(|_| PlanError::InstalledMissing(nevra.into()))
        .and_then(|item| {
            if installed_nevra(item) == nevra {
                Ok(item)
            } else {
                Err(PlanError::InstalledMissing(nevra.into()))
            }
        })
}

fn pair_actions(
    mut raw: Vec<NativeAction>,
    inventory: &dnfast_core::InstalledInventory,
) -> Result<Vec<NativeAction>, PlanError> {
    for action in raw.iter_mut().filter(|item| item.repository == "@System") {
        let installed = unique_installed(&action.nevra, inventory)?;
        action.old_nevra = Some(action.nevra.clone());
        action.installed_instance = Some(installed.db_instance());
        action.installed_header_sha256 = Some(installed.immutable_header_sha256().as_str().into());
    }
    let mut paired = BTreeSet::new();
    for index in 0..raw.len() {
        let old_kind = match raw[index].kind.as_str() {
            "upgrade" => Some("upgraded"),
            "obsoletes" => Some("obsoleted"),
            _ => None,
        };
        let Some(old_kind) = old_kind else { continue };
        let name = nevra_name(&raw[index].nevra)?;
        let new_nevra = raw[index].nevra.clone();
        let matches = raw
            .iter()
            .enumerate()
            .filter(|(_, item)| {
                item.kind == old_kind
                    && item.repository == "@System"
                    && (item.transaction_counterpart_nevra.as_deref() == Some(new_nevra.as_str())
                        || raw[index].transaction_counterpart_nevra.as_deref()
                            == Some(item.nevra.as_str()))
            })
            .filter(|(_, item)| {
                old_kind == "obsoleted" || nevra_name(&item.nevra).as_deref() == Ok(name.as_str())
            })
            .map(|(position, _)| position)
            .collect::<Vec<_>>();
        if matches.is_empty() {
            return Err(PlanError::InstalledMissing(name));
        }
        if old_kind == "upgraded" && matches.len() != 1 {
            return Err(PlanError::AmbiguousInstalled(name));
        }
        let parent = format!("{}:{}", raw[index].repository, raw[index].nevra);
        for old in matches {
            if !paired.insert(old) {
                return Err(PlanError::AmbiguousInstalled(raw[old].nevra.clone()));
            }
            if old_kind == "obsoleted" {
                raw[old].kind = "erase".into();
                raw[old].provenance = Some(crate::ActionProvenance::ObsoletedBy {
                    parent_action_identity: parent.clone(),
                });
            } else {
                let old_nevra = raw[old].nevra.clone();
                let instance = raw[old].installed_instance;
                let header = raw[old].installed_header_sha256.clone();
                raw[index].old_nevra = Some(old_nevra);
                raw[index].installed_instance = instance;
                raw[index].installed_header_sha256 = header;
            }
        }
    }
    if raw.iter().enumerate().any(|(index, item)| {
        matches!(item.kind.as_str(), "upgraded" | "obsoleted") && !paired.contains(&index)
    }) {
        return Err(PlanError::Invalid("unpaired native old action"));
    }
    Ok(raw
        .into_iter()
        .filter(|item| item.kind != "upgraded")
        .collect())
}

fn unique_installed<'a>(
    nevra: &str,
    inventory: &'a dnfast_core::InstalledInventory,
) -> Result<&'a dnfast_core::InstalledPackage, PlanError> {
    let matches = inventory
        .packages()
        .iter()
        .filter(|item| installed_nevra(item) == nevra)
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [] => Err(PlanError::InstalledMissing(nevra.into())),
        [item] => Ok(*item),
        _ => Err(PlanError::AmbiguousInstalled(nevra.into())),
    }
}

fn full_nevra(item: &CandidatePackage) -> String {
    format!(
        "{}-{}:{}-{}.{}",
        item.name,
        item.evra.epoch(),
        item.evra.version(),
        item.evra.release(),
        arch(item.evra.arch())
    )
}
fn installed_nevra(item: &dnfast_core::InstalledPackage) -> String {
    format!(
        "{}-{}:{}-{}.{}",
        item.name(),
        item.evra().epoch(),
        item.evra().version(),
        item.evra().release(),
        arch(item.evra().arch())
    )
}
fn complete_nevra(item: &dnfast_metadata::CompletePackage) -> String {
    format!(
        "{}-{}:{}-{}.{}",
        item.name, item.epoch, item.version, item.release, item.arch
    )
}
fn relation_text(item: &dnfast_metadata::Relation) -> String {
    let Some(flags) = item.flags else {
        return item.name.clone();
    };
    let operator = match flags {
        dnfast_metadata::RelationFlags::Equal => "=",
        dnfast_metadata::RelationFlags::Less => "<",
        dnfast_metadata::RelationFlags::LessEqual => "<=",
        dnfast_metadata::RelationFlags::Greater => ">",
        dnfast_metadata::RelationFlags::GreaterEqual => ">=",
    };
    let epoch = item
        .epoch
        .as_deref()
        .filter(|value| *value != "0")
        .map(|value| format!("{value}:"))
        .unwrap_or_default();
    let release = item
        .release
        .as_deref()
        .map(|value| format!("-{value}"))
        .unwrap_or_default();
    format!(
        "{} {operator} {epoch}{}{release}",
        item.name,
        item.version.as_deref().unwrap_or_default()
    )
}
fn arch(value: dnfast_core::Architecture) -> &'static str {
    value.as_rpm_arch()
}
fn nevra_name(value: &str) -> Result<String, PlanError> {
    value
        .rsplit_once('-')
        .and_then(|(left, _)| left.rsplit_once('-').map(|(name, _)| name.to_owned()))
        .ok_or(PlanError::Invalid("invalid native full NEVRA"))
}

#[cfg(test)]
mod tests {
    use super::arch;

    #[test]
    fn x86_64_native_solver_architecture_is_not_aarch64() {
        assert_eq!(arch(dnfast_core::Architecture::X86_64), "x86_64");
    }
}
