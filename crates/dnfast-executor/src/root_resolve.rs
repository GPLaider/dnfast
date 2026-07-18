use dnfast_core::{Action, CanonicalDocument};
use dnfast_solver::{CanonicalSolverPlan, NativeSolveOutput, PlanBuilder, ReSolveContract};

use crate::staged_inputs::apply_module_artifact_policy;
use crate::{ExecutorError, StagedInputs};

pub fn require_equal(
    proposed: &CanonicalSolverPlan,
    staged: &StagedInputs,
    root: &str,
) -> Result<dnfast_core::InstalledInventory, ExecutorError> {
    let proposal = proposed.proposal();
    let selected = proposal
        .selected_repositories()
        .iter()
        .map(|repository| repository.id().to_owned())
        .collect::<Vec<_>>();
    let snapshot = dnfast_planning::PlanningSnapshot::open_system()
        .map_err(|error| ExecutorError::Plan(error.to_string()))?;
    let current = snapshot
        .integrity_for_repositories(&selected)
        .map_err(|error| ExecutorError::Plan(error.to_string()))?;
    if proposal.integrity() != current {
        return Err(ExecutorError::Plan(
            "root planning snapshot or repository binding mismatch".into(),
        ));
    }
    let mut context =
        dnfast_native::NativeContext::open(staged.policy.base_arch(), || false).map_err(native)?;
    context.add_installed_rpmdb(root).map_err(native)?;
    let inventory = context
        .read_installed_inventory()
        .map_err(|error| ExecutorError::Plan(error.to_string()))?;
    if inventory
        .canonical_sha256()
        .map_err(|error| ExecutorError::Plan(error.to_string()))?
        .as_str()
        != proposal.inventory_sha256().as_str()
    {
        return Err(ExecutorError::Plan("root inventory digest mismatch".into()));
    }
    for repository in &staged.repositories {
        context
            .add_repository(repository.repository.clone())
            .map_err(native)?;
    }
    let module_policies = snapshot
        .module_catalog(&selected)
        .and_then(|catalog| {
            catalog.artifact_policies(&snapshot.payload().module_state, staged.policy.base_arch())
        })
        .map_err(|error| ExecutorError::Plan(error.to_string()))?;
    let module_excludes = module_policies
        .iter()
        .filter_map(|(artifact, excluded)| excluded.then_some(artifact.clone()))
        .collect::<Vec<_>>();
    context
        .set_module_excludes(&module_excludes)
        .map_err(native)?;
    let intent = proposal.intent();
    let names = intent
        .packages()
        .iter()
        .map(|package| package.as_str())
        .collect::<Vec<_>>();
    let result = match intent.action() {
        Action::Install => context.solve_install_many(
            &names,
            staged.policy.install_weak_deps(),
            staged.policy.best(),
        ),
        Action::Upgrade => context.solve_upgrade_many(&names, staged.policy.best()),
        Action::Downgrade => context.solve_downgrade_many(&names),
        Action::Reinstall => context.solve_reinstall_many(&names),
        Action::DistroSync => context.solve_distro_sync_many(&names, staged.policy.best()),
        Action::Remove => context.solve_erase_many(&names),
        Action::Autoremove => context.solve_autoremove_many(&names),
    }
    .map_err(native)?;
    let metadata = staged
        .metadata
        .iter()
        .map(|(repository, package)| (repository.as_str(), package))
        .collect::<Vec<_>>();
    let transcript = NativeSolveOutput::from_native(
        result,
        proposal.metadata_sha256().as_str().into(),
        &metadata,
        &inventory,
    )
    .map_err(|error| ExecutorError::Plan(error.to_string()))?;
    let satisfied_specs = transcript.satisfied_specs().to_vec();
    let mut candidates = staged.candidates.clone();
    apply_module_artifact_policy(&mut candidates, &module_policies);
    let resolved = transcript
        .into_resolved(&names, &candidates, &metadata, &inventory)
        .map_err(|error| ExecutorError::Plan(error.to_string()))?;
    let snapshots = proposal.integrity();
    let root_plan = PlanBuilder {
        intent,
        snapshots: &snapshots,
        inventory: &inventory,
        policy: &staged.policy,
        candidates: &candidates,
        expires_at_unix: proposal.expires_at_unix(),
    }
    .build_with_satisfied(&resolved, &satisfied_specs)
    .map_err(|error| ExecutorError::Plan(error.to_string()))?;
    ReSolveContract::require_equal(proposed, &root_plan)
        .map_err(|error| ExecutorError::Plan(error.to_string()))?;
    Ok(inventory)
}

fn native(error: dnfast_native::NativeError) -> ExecutorError {
    ExecutorError::Plan(error.to_string())
}
