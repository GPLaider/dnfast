use thiserror::Error;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum PlanError {
    #[error("solver produced no changes")]
    NoChanges,
    #[error("transaction intent is not covered exactly once")]
    IntentCoverage,
    #[error("unrelated requested action: {0}")]
    UnrelatedAction(String),
    #[error("conflicting action kind: {0}")]
    ConflictingAction(String),
    #[error("duplicate action identity: {0}")]
    DuplicateAction(String),
    #[error("unresolved dependency set for: {0}")]
    Unresolved(String),
    #[error("duplicate candidate: {0}")]
    DuplicateCandidate(String),
    #[error("ambiguous candidate identity: {0}")]
    AmbiguousCandidate(String),
    #[error("dependency ordering cycle")]
    DependencyCycle,
    #[error("dependency parent does not exist: {0}")]
    MissingParent(String),
    #[error("dependency graph contains a disconnected component")]
    DisconnectedGraph,
    #[error("invalid plan input: {0}")]
    Invalid(&'static str),
    #[error("excluded package: {0}")]
    Excluded(String),
    #[error("unsupported modular package: {0}")]
    Modular(String),
    #[error("solver selected a non-preferred candidate: {0}")]
    NonPreferred(String),
    #[error("candidate repository is not selected in the planning snapshot: {0}")]
    RepositoryNotSelected(String),
    #[error("installed package was not found: {0}")]
    InstalledMissing(String),
    #[error("installed package identity is ambiguous: {0}")]
    AmbiguousInstalled(String),
    #[error("unsafe action: {0}")]
    Unsafe(String),
    #[error("canonical document failed: {0}")]
    Canonical(String),
    #[error("root re-solve action bytes differ")]
    ReSolveMismatch,
}
