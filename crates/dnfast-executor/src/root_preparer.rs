#[cfg(test)]
use std::os::fd::OwnedFd;

use dnfast_cache::{ArtifactTransport, HttpArtifactTransport};
use dnfast_core::{Action, CanonicalDocument};
use dnfast_native::{NativeContext, Repository};
use dnfast_planning::PlanningSnapshot;
use dnfast_solver::{CanonicalSolverPlan, NativeSolveOutput, PlanBuilder, ReSolveContract};
use rustix::process::geteuid;
use thiserror::Error;

use crate::{
    ExecutorError, InheritedPlan, RootInputs,
    input_model::InputManifest,
    staged_inputs::{apply_module_artifact_policy, parse_candidates},
};

mod prepared_generation;
mod root_state;
#[cfg(test)]
mod tests;

use prepared_generation::{InputDraft, metadata_digest_v5, trust_digest};
use root_state::{
    current_snapshot, revalidate_snapshot_and_inventory, selected_ids, selected_repositories,
};

/// A root-only result whose inputs have been atomically published for one exact plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedInputs {
    digest: String,
}

impl PreparedInputs {
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// Re-opens every root-owned boundary immediately before the caller passes the plan on FD 3.
    ///
    /// This deliberately does not replace the executor's final lock-held RPMDB check.
    pub fn revalidate_before_fd3(
        &self,
        proposal: &CanonicalSolverPlan,
    ) -> Result<(), PreparationError> {
        require_root()?;
        let digest = proposal.digest().map_err(solver)?;
        if digest.as_str() != self.digest {
            return Err(PreparationError::DifferentPlan);
        }
        revalidate_snapshot_and_inventory(proposal)?;
        RootInputs::open(proposal).map_err(inputs)?;
        Ok(())
    }

    #[cfg(test)]
    fn revalidate_before_fd3_under(
        &self,
        proposal: &CanonicalSolverPlan,
        parent: &OwnedFd,
    ) -> Result<(), PreparationError> {
        let digest = proposal.digest().map_err(solver)?;
        if digest.as_str() != self.digest {
            return Err(PreparationError::DifferentPlan);
        }
        RootInputs::open_under_for_test(parent, proposal).map_err(inputs)?;
        Ok(())
    }
}

/// Root-only producer for the strict v3 executor input generation.
pub struct RootInputPreparer;

impl RootInputPreparer {
    /// Removes only old, unlocked, root-private input generations. Active
    /// preparers and executors retain shared directory locks and are skipped.
    pub fn garbage_collect_system() -> Result<usize, PreparationError> {
        require_root()?;
        prepared_generation::garbage_collect_system()
    }

    /// Downloads through the bounded system artifact cache and publishes only an exactly re-solved plan.
    pub fn prepare_system(
        proposal: &CanonicalSolverPlan,
    ) -> Result<PreparedInputs, PreparationError> {
        let transport = HttpArtifactTransport::new();
        Self::prepare_with_transport(proposal, &transport)
    }

    /// Stages a plan produced in this process by the root-published planner.
    ///
    /// The fixed executor still independently re-solves and performs its final
    /// lock-held RPMDB equality check before any write.  This path only avoids
    /// repeating the same unlocked solve once more while staging trusted inputs.
    pub fn prepare_locally_solved_system(
        proposal: &CanonicalSolverPlan,
    ) -> Result<PreparedInputs, PreparationError> {
        let transport = HttpArtifactTransport::new();
        Self::prepare_with_transport_mode(proposal, &transport, false)
    }

    /// Publishes inputs for a solve-token held by the resident root daemon.
    ///
    /// The token's RPMDB cookie is checked under the final librpm write lock,
    /// so this path revalidates the root-owned snapshot but deliberately does
    /// not perform another unlocked RPMDB walk or solve.
    pub fn prepare_token_bound_system(
        proposal: &CanonicalSolverPlan,
    ) -> Result<PreparedInputs, PreparationError> {
        require_root()?;
        let transport = HttpArtifactTransport::new();
        let digest = proposal.digest().map_err(solver)?;
        let snapshot = current_snapshot(proposal)?;
        let mut draft = InputDraft::create()?;
        prepare_into_draft(proposal, &snapshot, &mut draft, &transport, false)?;
        current_snapshot(proposal)?;
        draft.publish(digest.as_str(), proposal)
    }

    pub fn prepare_inherited(
        inherited: &InheritedPlan,
        now_unix: u64,
        transport: &dyn ArtifactTransport,
    ) -> Result<PreparedInputs, PreparationError> {
        let proposal = CanonicalSolverPlan::from_canonical_json(inherited.bytes(), now_unix)
            .map_err(solver)?;
        Self::prepare_with_transport(&proposal, transport)
    }

    /// Same system-only preparation boundary with an injected transport for embedders and tests.
    /// The snapshot, cache, RPMDB and published input root remain fixed system paths.
    pub fn prepare_with_transport(
        proposal: &CanonicalSolverPlan,
        transport: &dyn ArtifactTransport,
    ) -> Result<PreparedInputs, PreparationError> {
        Self::prepare_with_transport_mode(proposal, transport, true)
    }

    fn prepare_with_transport_mode(
        proposal: &CanonicalSolverPlan,
        transport: &dyn ArtifactTransport,
        re_solve: bool,
    ) -> Result<PreparedInputs, PreparationError> {
        require_root()?;
        let digest = proposal.digest().map_err(solver)?;
        let snapshot = current_snapshot(proposal)?;
        let mut draft = InputDraft::create()?;

        match prepare_into_draft(proposal, &snapshot, &mut draft, transport, re_solve) {
            Ok(()) => {
                revalidate_snapshot_and_inventory(proposal)?;
                draft.publish(digest.as_str(), proposal)
            }
            Err(error) => Err(error),
        }
    }
}

fn prepare_into_draft(
    proposal: &CanonicalSolverPlan,
    snapshot: &PlanningSnapshot,
    draft: &mut InputDraft,
    transport: &dyn ArtifactTransport,
    re_solve: bool,
) -> Result<(), PreparationError> {
    let selected_ids = selected_ids(proposal);
    let integrity = snapshot
        .integrity_for_repositories(&selected_ids)
        .map_err(snapshot_error)?;
    if integrity != proposal.proposal().integrity() {
        return Err(PreparationError::SnapshotMismatch);
    }

    let policy = &snapshot.payload().policy.solver;
    let mut context = if re_solve {
        let mut context = NativeContext::open(policy.base_arch(), || false).map_err(native)?;
        context.add_installed_rpmdb("/").map_err(native)?;
        let inventory = context
            .read_installed_inventory()
            .map_err(|error| PreparationError::Native(error.to_string()))?;
        if inventory.canonical_sha256().map_err(domain)?.as_str()
            != proposal.proposal().inventory_sha256().as_str()
        {
            return Err(PreparationError::RpmdbChanged);
        }
        Some((context, inventory))
    } else {
        None
    };

    let repositories = selected_repositories(snapshot, proposal)?;
    let mut materialized_repositories = Vec::with_capacity(repositories.len());
    let mut repository_inputs = Vec::with_capacity(repositories.len());
    let mut candidates = Vec::new();
    let mut metadata = Vec::new();
    for (index, repository) in repositories.iter().enumerate() {
        if let Some((context, _)) = &mut context {
            let materialized = draft.write_repository(snapshot, repository, index)?;
            // A locally solved proposal was already built from this exact
            // immutable snapshot.  Only the independent re-solve path needs
            // another full candidate/relation copy here; the fixed executor
            // will parse the published raw metadata at its own boundary.
            let mut repomd = draft.open(&materialized.input.repomd)?;
            let mut primary = draft.open(&materialized.input.primary)?;
            let parsed = parse_candidates(
                &materialized.input,
                &mut repomd,
                &mut primary,
                policy.base_arch(),
            )
            .map_err(inputs)?;
            candidates.extend(parsed.0);
            metadata.extend(parsed.1);
            context
                .add_repository(Repository {
                    id: materialized.input.id.clone(),
                    repomd_path: draft.absolute_path(&materialized.input.repomd.name),
                    primary_path: draft.absolute_path(&materialized.native_primary.name),
                    filelists_path: draft.absolute_path(&materialized.native_filelists.name),
                    priority: materialized.input.priority,
                    cost: materialized.input.cost,
                })
                .map_err(native)?;
            repository_inputs.push(materialized.input.clone());
            materialized_repositories.push(materialized);
        } else {
            // The local fallback has already solved and revalidated this exact
            // immutable snapshot.  Publish only the digest-bound raw payloads
            // consumed by the fixed executor instead of inflating duplicate
            // native XML that would immediately be discarded.
            repository_inputs.push(draft.write_repository_raw(snapshot, repository, index)?);
        }
    }

    let module_catalog = snapshot
        .module_catalog(&selected_ids)
        .map_err(snapshot_error)?;
    let module_policies = module_catalog
        .artifact_policies(&snapshot.payload().module_state, policy.base_arch())
        .map_err(snapshot_error)?;
    apply_module_artifact_policy(&mut candidates, &module_policies);

    draft.discard_native_metadata(&materialized_repositories)?;
    if let Some((mut context, inventory)) = context {
        let module_excludes = module_policies
            .iter()
            .filter_map(|(artifact, excluded)| excluded.then_some(artifact.clone()))
            .collect::<Vec<_>>();
        context
            .set_module_excludes(&module_excludes)
            .map_err(native)?;
        let names = proposal
            .proposal()
            .intent()
            .packages()
            .iter()
            .map(|package| package.as_str())
            .collect::<Vec<_>>();
        let solved = match proposal.proposal().intent().action() {
            Action::Install => {
                context.solve_install_many(&names, policy.install_weak_deps(), policy.best())
            }
            Action::Upgrade => context.solve_upgrade_many(&names, policy.best()),
            Action::Downgrade => context.solve_downgrade_many(&names),
            Action::Reinstall => context.solve_reinstall_many(&names),
            Action::DistroSync => context.solve_distro_sync_many(&names, policy.best()),
            Action::Remove => context.solve_erase_many(&names),
            Action::Autoremove => context.solve_autoremove_many(&names),
        }
        .map_err(native)?;
        let metadata_refs = metadata
            .iter()
            .map(|(id, package)| (id.as_str(), package))
            .collect::<Vec<_>>();
        let transcript = NativeSolveOutput::from_native(
            solved,
            proposal.proposal().metadata_sha256().as_str().into(),
            &metadata_refs,
            &inventory,
        )
        .map_err(solver)?;
        let satisfied_specs = transcript.satisfied_specs().to_vec();
        let resolved = transcript
            .into_resolved(&names, &candidates, &metadata_refs, &inventory)
            .map_err(solver)?;
        let root_plan = PlanBuilder {
            intent: proposal.proposal().intent(),
            snapshots: &integrity,
            inventory: &inventory,
            policy,
            candidates: &candidates,
            expires_at_unix: proposal.proposal().expires_at_unix(),
        }
        .build_with_satisfied(&resolved, &satisfied_specs)
        .map_err(solver)?;
        ReSolveContract::require_equal(proposal, &root_plan)
            .map_err(|_| PreparationError::ReSolveMismatch)?;
    }

    let artifacts = draft.fetch_artifacts(proposal, &repository_inputs, transport)?;
    let policy_file =
        draft.write_bytes("policy.json", &policy.to_canonical_json().map_err(domain)?)?;
    let manifest = InputManifest {
        schema_version: 5,
        policy: policy_file,
        metadata_sha256: metadata_digest_v5(&repository_inputs)?,
        trust_sha256: trust_digest(&repository_inputs)?,
        repositories: repository_inputs,
        artifacts,
    };
    draft.write_manifest(&manifest)?;
    Ok(())
}

#[derive(Debug, Error)]
pub enum PreparationError {
    #[error("root input preparation requires EUID 0")]
    NotRoot,
    #[error("root planning snapshot is stale or differs from the proposal")]
    SnapshotMismatch,
    #[error("root RPMDB differs from the proposal inventory")]
    RpmdbChanged,
    #[error("root native re-solve differs from the canonical proposal")]
    ReSolveMismatch,
    #[error("prepared input belongs to a different proposal")]
    DifferentPlan,
    #[error("root planning snapshot failed validation: {0}")]
    Snapshot(String),
    #[error("root native preparation failed: {0}")]
    Native(String),
    #[error("artifact preparation failed: {0}")]
    Artifact(String),
    #[error("root input publication failed: {0}")]
    Publish(String),
    #[error("root input validation failed: {0}")]
    Inputs(String),
    #[error("canonical domain operation failed: {0}")]
    Domain(String),
    #[error("canonical solver operation failed: {0}")]
    Solver(String),
}

fn require_root() -> Result<(), PreparationError> {
    require_root_uid(geteuid().as_raw())
}

const fn require_root_uid(uid: u32) -> Result<(), PreparationError> {
    if uid == 0 {
        Ok(())
    } else {
        Err(PreparationError::NotRoot)
    }
}

pub(super) fn domain(error: dnfast_core::DomainError) -> PreparationError {
    PreparationError::Domain(error.to_string())
}
pub(super) fn inputs(error: ExecutorError) -> PreparationError {
    PreparationError::Inputs(error.to_string())
}
pub(super) fn native(error: dnfast_native::NativeError) -> PreparationError {
    PreparationError::Native(error.to_string())
}
pub(super) fn snapshot_error(error: dnfast_planning::PlanningError) -> PreparationError {
    PreparationError::Snapshot(error.to_string())
}
fn solver(error: dnfast_solver::PlanError) -> PreparationError {
    PreparationError::Solver(error.to_string())
}
