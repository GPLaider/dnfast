use std::rc::Rc;

use dnfast_solver::CanonicalSolverPlan;

use crate::{ExecutorError, MountRoot, StagedInputs};

pub fn run(plan: &CanonicalSolverPlan, staged: &mut StagedInputs, inventory: &dnfast_core::InstalledInventory, journal: Rc<dnfast_state::TransactionJournal>, root: &str, mount_root: &MountRoot) -> Result<(), ExecutorError> {
    let isolated_keyrings = staged.repositories.iter().map(|repository| {
        dnfast_native::KeyringInstalled::from_verified_staged_bundle(&repository.trust, &repository.repository.id, &repository.keys)
            .map(|keyring| (&repository.repository.id, keyring)).map_err(native)
    }).collect::<Result<Vec<_>, ExecutorError>>()?;
    let mut verified = Vec::new();
    for action in plan.actions().iter().filter(|action| matches!(action.operation.as_str(), "install" | "upgrade")) {
        let repository_id = action.repo_id.as_deref().ok_or_else(|| ExecutorError::Inputs("planned artifact has no repository".into()))?;
        let position = staged.artifacts.iter().position(|artifact| artifact.repo_id == repository_id && artifact.expected.name == action.name
            && artifact.expected.epoch == u64::from(action.target_evra.epoch()) && artifact.expected.version == action.target_evra.version()
            && artifact.expected.release == action.target_evra.release()).ok_or_else(|| ExecutorError::Inputs("staged artifact for planned action is absent".into()))?;
        let artifact = &staged.artifacts[position];
        let repository = staged.repositories.iter().find(|repository| repository.repository.id == artifact.repo_id)
            .ok_or_else(|| ExecutorError::Inputs("staged artifact repository is absent".into()))?;
        if artifact.generation_sha256 != repository.generation_sha256 || artifact.origin_sha256 != repository.origin_sha256
            || artifact.trust_sha256 != repository.trust_sha256 {
            return Err(ExecutorError::Inputs("staged artifact repository binding differs".into()));
        }
        let keyring = isolated_keyrings.iter().find(|(id, _)| *id == &artifact.repo_id)
            .map(|(_, keyring)| keyring).ok_or_else(|| ExecutorError::Inputs("isolated repository keyring is absent".into()))?;
        let cached = dnfast_cache::CachedArtifact::from_verified_root_file(artifact.file.try_clone().map_err(io)?, &artifact.sha256, artifact.size).map_err(cache)?;
        let verified_artifact = keyring.verify_artifact(&cached, &artifact.expected, repository.trust.signing_subkey_rule()).map_err(native_trust)?;
        verified.push((position, cached, verified_artifact, action.operation == "upgrade"));
    }
    let bundles = staged.repositories.iter().map(|repository| (&repository.trust, repository.repository.id.as_str(), repository.keys.as_slice())).collect::<Vec<_>>();
    let keyring = dnfast_native::KeyringInstalled::from_verified_staged_bundles(&bundles).map_err(native)?;
    let mut executor = dnfast_native::ExecutorInventory::begin_at_root(staged.policy.base_arch(), keyring, inventory, root).map_err(inventory_error)?;
    executor.bind_journal(journal).map_err(inventory_error)?;
    for action in plan.actions() {
        match action.operation.as_str() {
            "remove" => {
                let instance = action.installed_instance.ok_or_else(|| ExecutorError::Plan("remove action lacks installed instance".into()))?;
                let header = action.installed_header_sha256.as_deref().ok_or_else(|| ExecutorError::Plan("remove action lacks installed header".into()))?;
                let installed = inventory.erase_target(instance, header).map_err(|error| ExecutorError::Plan(error.to_string()))?;
                executor.add_erase(installed).map_err(inventory_error)?;
            }
            "install" | "upgrade" => {
                let (position, cached, verified_artifact, upgrade) = verified.iter().find(|(position, _, _, _)| staged.artifacts[*position].expected.name == action.name)
                    .ok_or_else(|| ExecutorError::Plan("verified artifact is absent".into()))?;
                let _ = position;
                executor.add_install(cached, verified_artifact, *upgrade).map_err(inventory_error)?;
            }
            _ => return Err(ExecutorError::Plan("unknown planned operation".into())),
        }
    }
    executor.prepare_checked_transaction().map_err(|error| phase("prepare", error))?;
    executor.test_checked_transaction().map_err(|error| phase("test", error))?;
    mount_root.verify_unchanged()?;
    if let Err(error) = executor.run_checked_transaction() { return stateful_or_preflight(&mut executor, mount_root, "run", error); }
    if let Err(error) = executor.verify_transaction_db() { return stateful_or_preflight(&mut executor, mount_root, "verify-db", error); }
    if let Err(error) = executor.reconcile() { return stateful_or_preflight(&mut executor, mount_root, "reconcile", error); }
    mount_root.verify_unchanged().map_err(|error| ExecutorError::MountStateful(error.to_string()))?;
    Ok(())
}

fn stateful_or_preflight(executor: &mut dnfast_native::ExecutorInventory, mount_root: &MountRoot,
    phase_name: &str, error: dnfast_native::InventoryError) -> Result<(), ExecutorError> {
    if executor.transaction_counts().real_run == 0 { return Err(phase(phase_name, error)); }
    let reconciliation = executor.reconcile_after_failure();
    let mount = mount_root.verify_unchanged();
    let details = [format!("original={error}"), format!("reconciliation={}", reconciliation.as_ref().map(|_| "completed").unwrap_or("failed")),
        format!("mount={}", mount.as_ref().map(|_| "unchanged").unwrap_or("changed"))].join("; ");
    Err(ExecutorError::Plan(format!("executor-phase={phase_name}: transaction may be stateful; {details}")))
}

fn io(error: std::io::Error) -> ExecutorError { ExecutorError::Inputs(error.to_string()) }
fn cache(error: dnfast_cache::ArtifactError) -> ExecutorError { ExecutorError::Inputs(error.to_string()) }
fn native(error: dnfast_native::TrustError) -> ExecutorError { ExecutorError::Inputs(error.to_string()) }
fn native_trust(error: dnfast_native::TrustError) -> ExecutorError { ExecutorError::Inputs(error.to_string()) }
fn inventory_error(error: dnfast_native::InventoryError) -> ExecutorError {
    match error {
        dnfast_native::InventoryError::TransactionPreflight { problems } => ExecutorError::Plan(format!("checked RPM transaction preflight failed: {}", problems.iter().map(dnfast_native::TransactionProblem::as_str).collect::<Vec<_>>().join("; "))),
        dnfast_native::InventoryError::PotentiallyStateful { problems, journal_error } => ExecutorError::Plan(format!("real RPM transaction failed: {}{}", problems.iter().map(dnfast_native::TransactionProblem::as_str).collect::<Vec<_>>().join("; "), journal_error.map(|value| format!("; journal: {value}")).unwrap_or_default())),
        other => ExecutorError::Plan(other.to_string()),
    }
}
fn phase(name: &str, error: dnfast_native::InventoryError) -> ExecutorError { ExecutorError::Plan(format!("executor-phase={name}: {}", inventory_error(error))) }
