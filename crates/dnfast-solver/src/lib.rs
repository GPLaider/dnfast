#![forbid(unsafe_code)]

mod model;
mod native_adapter;
mod plan;
mod preflight;
mod validation;

pub use model::{
    ActionProvenance, ArtifactRecord, CandidatePackage, DependencyEdge, DependencyKind,
    ExplainedAction, IntegritySnapshots, NativePackageEvidence, PlanProtection, RequestedRelation,
    ResolvedAction, ResolvedOperation,
};
pub use native_adapter::{NativeAction, NativeDecision, NativeSolveOutput};
pub use plan::{CanonicalSolverPlan, PlanBuilder, PlanDigest, ReSolveContract};
pub use validation::PlanError;

pub const MAX_PLAN_ARTIFACT_BYTES: u64 = 16 * 1024 * 1024 * 1024 * 1024;
