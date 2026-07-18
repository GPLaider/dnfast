use std::collections::{BTreeMap, BTreeSet};

use dnfast_core::Action;

use crate::{CandidatePackage, PlanError, ResolvedAction, ResolvedOperation};

pub(crate) fn validate_inputs(
    builder: &crate::PlanBuilder<'_>,
    actions: &[ResolvedAction],
    satisfied_specs: &[dnfast_core::PackageSpec],
) -> Result<(), PlanError> {
    if actions.is_empty() {
        return Err(PlanError::NoChanges);
    }
    if actions.len() > dnfast_core::MAX_PLAN_ACTIONS {
        return Err(PlanError::Invalid("action limit exceeded"));
    }
    validate_repository_selection(builder)?;
    validate_candidates(builder.candidates)?;
    let bytes = actions
        .iter()
        .filter_map(|item| item.candidate.as_ref())
        .try_fold(0_u64, |total, item| {
            total
                .checked_add(item.package_size)
                .ok_or(PlanError::Invalid("artifact size overflow"))
        })?;
    if bytes > crate::MAX_PLAN_ARTIFACT_BYTES {
        return Err(PlanError::Invalid("artifact size limit exceeded"));
    }
    let requested = builder
        .intent
        .packages()
        .iter()
        .map(|item| item.as_str())
        .collect::<BTreeSet<_>>();
    let names = actions
        .iter()
        .map(|item| item.name.as_str())
        .collect::<BTreeSet<_>>();
    if names.len() != actions.len() {
        return Err(PlanError::DuplicateAction("name".into()));
    }
    let mut covered = BTreeMap::<&str, usize>::new();
    for spec in satisfied_specs {
        if !requested.contains(spec.as_str()) {
            return Err(PlanError::Invalid(
                "satisfied selector is not in requested intent",
            ));
        }
        *covered.entry(spec.as_str()).or_default() += 1;
    }
    let mut identities = BTreeSet::new();
    for action in actions {
        if action.name.is_empty() || !action.unresolved_dependencies.is_empty() {
            return Err(PlanError::Unresolved(action.name.clone()));
        }
        let identity = (
            action.operation,
            action.name.as_str(),
            action.installed_instance,
            action
                .candidate
                .as_ref()
                .map(|item| (&item.evra, item.repo_id.as_str())),
        );
        if !identities.insert(identity) {
            return Err(PlanError::DuplicateAction(action.name.clone()));
        }
        let all_replacement_root = action.requested
            && action.requested_spec.is_none()
            && matches!(
                builder.intent.action(),
                Action::Upgrade | Action::DistroSync
            )
            && requested.is_empty()
            && matches!(
                action.operation,
                ResolvedOperation::Upgrade
                    | ResolvedOperation::Downgrade
                    | ResolvedOperation::Reinstall
            );
        if action.requested != action.requested_spec.is_some() && !all_replacement_root {
            return Err(PlanError::Invalid("requested action provenance differs"));
        }
        if action.requested_relation && !action.requested {
            return Err(PlanError::Invalid("relation selector is not requested"));
        }
        if action.requested {
            match action.requested_spec.as_ref() {
                Some(spec) => {
                    if !requested.contains(spec.as_str()) {
                        return Err(PlanError::UnrelatedAction(action.name.clone()));
                    }
                    *covered.entry(spec.as_str()).or_default() += 1;
                }
                None if matches!(
                    builder.intent.action(),
                    Action::Upgrade | Action::DistroSync
                ) && requested.is_empty() => {}
                None => {
                    return Err(PlanError::Invalid(
                        "requested action lacks selector provenance",
                    ));
                }
            }
        }
        for edge in &action.dependency_edges {
            if edge.parent == action.name {
                return Err(PlanError::DependencyCycle);
            }
            if !names.contains(edge.parent.as_str()) {
                return Err(PlanError::MissingParent(edge.parent.clone()));
            }
        }
        if let Some(crate::ActionProvenance::ObsoletedBy {
            parent_action_identity,
        }) = &action.provenance
        {
            if action.operation != ResolvedOperation::Remove
                || !actions.iter().any(|parent| {
                    action_identity(parent).as_deref() == Some(parent_action_identity)
                })
            {
                return Err(PlanError::MissingParent(parent_action_identity.clone()));
            }
        }
        validate_kind(builder.intent.action(), action)?;
    }
    if requested
        .iter()
        .any(|name| covered.get(name).copied() != Some(1))
        || covered.values().any(|count| *count != 1)
    {
        return Err(PlanError::IntentCoverage);
    }
    validate_reachable(actions)?;
    Ok(())
}

fn validate_repository_selection(builder: &crate::PlanBuilder<'_>) -> Result<(), PlanError> {
    for candidate in builder.candidates {
        if !builder
            .snapshots
            .selected_repositories()
            .iter()
            .any(|repository| repository.id() == candidate.repo_id)
        {
            return Err(PlanError::RepositoryNotSelected(candidate.repo_id.clone()));
        }
    }
    Ok(())
}

fn validate_reachable(actions: &[ResolvedAction]) -> Result<(), PlanError> {
    let mut reachable = actions
        .iter()
        .filter(|item| item.requested)
        .map(|item| item.name.as_str())
        .collect::<BTreeSet<_>>();
    loop {
        let before = reachable.len();
        for item in actions {
            let obsolete_parent =
                item.provenance
                    .as_ref()
                    .is_some_and(|provenance| match provenance {
                        crate::ActionProvenance::ObsoletedBy {
                            parent_action_identity,
                        } => actions.iter().any(|parent| {
                            reachable.contains(parent.name.as_str())
                                && action_identity(parent).as_deref()
                                    == Some(parent_action_identity)
                        }),
                    });
            if obsolete_parent
                || item
                    .dependency_edges
                    .iter()
                    .any(|edge| reachable.contains(edge.parent.as_str()))
            {
                reachable.insert(&item.name);
            }
        }
        if reachable.len() == before {
            break;
        }
    }
    if reachable.len() == actions.len() {
        Ok(())
    } else {
        Err(PlanError::DisconnectedGraph)
    }
}

fn validate_kind(intent: Action, action: &ResolvedAction) -> Result<(), PlanError> {
    let obsoletion_side_effect = action.provenance.is_some()
        && action.operation == ResolvedOperation::Remove
        && intent != Action::Remove;
    // An upgrade may legitimately add a new package (for example a renamed
    // library or a newly introduced dependency).  Accept it only when the
    // native causal graph ties it to another selected action; reachability
    // validation below then proves the chain reaches an explicit/all-package
    // upgrade root.  A bare unrelated install therefore remains fail-closed.
    let dependency_install = matches!(intent, Action::Upgrade | Action::DistroSync)
        && action.operation == ResolvedOperation::Install
        && !action.requested
        && action.requested_spec.is_none()
        && !action.dependency_edges.is_empty();
    let valid = obsoletion_side_effect
        || dependency_install
        || match intent {
            Action::Install => matches!(
                action.operation,
                ResolvedOperation::Install | ResolvedOperation::Upgrade
            ),
            Action::Remove => {
                matches!(action.operation, ResolvedOperation::Remove) && action.provenance.is_none()
            }
            Action::Upgrade => matches!(action.operation, ResolvedOperation::Upgrade),
            Action::Downgrade => matches!(action.operation, ResolvedOperation::Downgrade),
            Action::Reinstall => matches!(action.operation, ResolvedOperation::Reinstall),
            Action::DistroSync => matches!(
                action.operation,
                ResolvedOperation::Upgrade
                    | ResolvedOperation::Downgrade
                    | ResolvedOperation::Reinstall
            ),
            Action::Autoremove => {
                matches!(action.operation, ResolvedOperation::Remove) && action.provenance.is_none()
            }
        };
    if valid {
        Ok(())
    } else {
        Err(PlanError::ConflictingAction(action.name.clone()))
    }
}

fn validate_candidates(candidates: &[CandidatePackage]) -> Result<(), PlanError> {
    let mut exact = BTreeSet::new();
    let mut policy = BTreeMap::new();
    for item in candidates {
        let exact_key = (
            &item.name,
            &item.evra,
            &item.repo_id,
            item.priority,
            item.cost,
            &item.vendor,
            &item.checksum_sha256,
            &item.location,
        );
        if !exact.insert(exact_key) {
            return Err(PlanError::DuplicateCandidate(item.name.clone()));
        }
        let key = (
            &item.name,
            &item.evra,
            &item.repo_id,
            item.priority,
            item.cost,
        );
        let identity = (
            &item.vendor,
            &item.checksum_sha256,
            &item.location,
            item.package_size,
            item.installed_size,
        );
        if policy
            .insert(key, identity)
            .is_some_and(|previous| previous != identity)
        {
            return Err(PlanError::AmbiguousCandidate(item.name.clone()));
        }
    }
    Ok(())
}

pub(crate) fn execution_order(
    resolved: &[ResolvedAction],
    actions: Vec<crate::ExplainedAction>,
) -> Result<Vec<crate::ExplainedAction>, PlanError> {
    let mut remaining = actions
        .into_iter()
        .map(|item| (item.name.clone(), item))
        .collect::<BTreeMap<_, _>>();
    if remaining.len() != resolved.len() {
        return Err(PlanError::DuplicateAction("name".into()));
    }
    let remove = resolved
        .first()
        .is_some_and(|item| item.operation == ResolvedOperation::Remove);
    let mut edges = BTreeSet::new();
    for item in resolved {
        for dependency in &item.dependency_edges {
            if !remaining.contains_key(&dependency.parent) {
                return Err(PlanError::MissingParent(dependency.parent.clone()));
            }
            edges.insert(if remove {
                (dependency.parent.clone(), item.name.clone())
            } else {
                (item.name.clone(), dependency.parent.clone())
            });
        }
        if let Some(crate::ActionProvenance::ObsoletedBy {
            parent_action_identity,
        }) = &item.provenance
        {
            let parent = resolved
                .iter()
                .find(|candidate| {
                    action_identity(candidate).as_deref() == Some(parent_action_identity)
                })
                .ok_or_else(|| PlanError::MissingParent(parent_action_identity.clone()))?;
            edges.insert((parent.name.clone(), item.name.clone()));
        }
    }
    let mut outgoing = BTreeMap::<String, BTreeSet<String>>::new();
    let mut incoming = BTreeMap::<String, BTreeSet<String>>::new();
    let mut indegree = remaining
        .keys()
        .cloned()
        .map(|name| (name, 0_usize))
        .collect::<BTreeMap<_, _>>();
    for (from, to) in edges {
        if outgoing.entry(from.clone()).or_default().insert(to.clone()) {
            incoming.entry(to.clone()).or_default().insert(from);
            *indegree.get_mut(&to).ok_or(PlanError::MissingParent(to))? += 1;
        }
    }
    let mut active = remaining.keys().cloned().collect::<BTreeSet<_>>();
    let mut ready = indegree
        .iter()
        .filter(|(_, count)| **count == 0)
        .map(|(name, _)| name.clone())
        .collect::<BTreeSet<_>>();
    let mut ordered = Vec::with_capacity(remaining.len());
    while !active.is_empty() {
        let next = if let Some(name) = ready.pop_first() {
            name
        } else {
            // Real RPM graphs contain mutually requiring packages.  The RPM
            // transaction performs its own authoritative rpmtsOrder pass, so
            // break only a proven cycle here to obtain stable plan bytes while
            // preserving every acyclic dependency ordering constraint.
            cycle_member(&active, &incoming).ok_or(PlanError::DependencyCycle)?
        };
        if !active.remove(&next) {
            return Err(PlanError::DependencyCycle);
        }
        ordered.push(remaining.remove(&next).ok_or(PlanError::DependencyCycle)?);
        if let Some(targets) = outgoing.get(&next) {
            for target in targets.iter().filter(|target| active.contains(*target)) {
                let count = indegree
                    .get_mut(target)
                    .ok_or_else(|| PlanError::MissingParent(target.clone()))?;
                *count = count.checked_sub(1).ok_or(PlanError::DependencyCycle)?;
                if *count == 0 {
                    ready.insert(target.clone());
                }
            }
        }
    }
    Ok(ordered)
}

fn cycle_member(
    active: &BTreeSet<String>,
    incoming: &BTreeMap<String, BTreeSet<String>>,
) -> Option<String> {
    let mut current = active.first()?.clone();
    let mut seen = BTreeSet::new();
    loop {
        if !seen.insert(current.clone()) {
            return Some(current);
        }
        current = incoming
            .get(&current)?
            .iter()
            .find(|parent| active.contains(*parent))?
            .clone();
    }
}

fn action_identity(action: &ResolvedAction) -> Option<String> {
    action.candidate.as_ref().map(|candidate| {
        format!(
            "{}:{}-{}:{}-{}.{}",
            candidate.repo_id,
            candidate.name,
            candidate.evra.epoch(),
            candidate.evra.version(),
            candidate.evra.release(),
            candidate.evra.arch().as_rpm_arch()
        )
    })
}

#[cfg(test)]
mod tests {
    use super::validate_kind;
    use crate::{DependencyEdge, DependencyKind, ResolvedAction, ResolvedOperation};
    use dnfast_core::Action;

    fn install(dependency_edges: Vec<DependencyEdge>) -> ResolvedAction {
        ResolvedAction {
            operation: ResolvedOperation::Install,
            name: "replacement-library".into(),
            requested: false,
            requested_spec: None,
            requested_relation: false,
            candidate: None,
            installed_instance: None,
            installed_header_sha256: None,
            installed_vendor: None,
            dependency_edges,
            provenance: None,
            required_by_remaining: vec![],
            unresolved_dependencies: vec![],
            introduced_by_requested: false,
            solver_rule: "test".into(),
        }
    }

    #[test]
    fn upgrade_accepts_only_causally_attached_install_side_effects() {
        let causal = install(vec![DependencyEdge {
            parent: "upgraded-parent".into(),
            kind: DependencyKind::Strong,
        }]);
        assert!(validate_kind(Action::Upgrade, &causal).is_ok());
        assert!(validate_kind(Action::DistroSync, &causal).is_ok());
        assert!(validate_kind(Action::Upgrade, &install(vec![])).is_err());
    }
}
