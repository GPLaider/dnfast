use dnfast_core::{CanonicalDocument, InstalledInventory};
use dnfast_native::NativeContext;
use dnfast_planning::{PlanningRepository, PlanningSnapshot};
use dnfast_solver::CanonicalSolverPlan;

use super::{PreparationError, domain, native, snapshot_error};

pub(super) fn current_snapshot(
    proposal: &CanonicalSolverPlan,
) -> Result<PlanningSnapshot, PreparationError> {
    let snapshot = PlanningSnapshot::open_system().map_err(snapshot_error)?;
    snapshot.revalidate_system_state().map_err(snapshot_error)?;
    let selected = selected_ids(proposal);
    if snapshot
        .integrity_for_repositories(&selected)
        .map_err(snapshot_error)?
        != proposal.proposal().integrity()
    {
        return Err(PreparationError::SnapshotMismatch);
    }
    Ok(snapshot)
}

pub(super) fn revalidate_snapshot_and_inventory(
    proposal: &CanonicalSolverPlan,
) -> Result<(), PreparationError> {
    let snapshot = current_snapshot(proposal)?;
    let inventory = current_inventory(snapshot.payload().policy.solver.base_arch())?;
    if inventory.canonical_sha256().map_err(domain)?.as_str()
        == proposal.proposal().inventory_sha256().as_str()
    {
        Ok(())
    } else {
        Err(PreparationError::RpmdbChanged)
    }
}

pub(super) fn selected_ids(proposal: &CanonicalSolverPlan) -> Vec<String> {
    proposal
        .proposal()
        .selected_repositories()
        .iter()
        .map(|binding| binding.id().to_owned())
        .collect()
}

pub(super) fn selected_repositories<'a>(
    snapshot: &'a PlanningSnapshot,
    proposal: &CanonicalSolverPlan,
) -> Result<Vec<&'a PlanningRepository>, PreparationError> {
    let mut selected = proposal
        .proposal()
        .selected_repositories()
        .iter()
        .map(|binding| {
            snapshot
                .payload()
                .allowed_repositories
                .iter()
                .find(|repository| repository.id == binding.id())
                .ok_or_else(|| PreparationError::Snapshot("selected repository is absent".into()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    selected.sort_by(|left, right| left.id.cmp(&right.id));
    if selected.windows(2).any(|pair| pair[0].id == pair[1].id) {
        return Err(PreparationError::Snapshot(
            "duplicate selected repository".into(),
        ));
    }
    Ok(selected)
}

fn current_inventory(
    architecture: dnfast_core::Architecture,
) -> Result<InstalledInventory, PreparationError> {
    let mut context = NativeContext::open(architecture, || false).map_err(native)?;
    context.add_installed_rpmdb("/").map_err(native)?;
    context
        .read_installed_inventory()
        .map_err(|error| PreparationError::Native(error.to_string()))
}
