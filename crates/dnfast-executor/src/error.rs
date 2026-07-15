use thiserror::Error;

#[derive(Debug, Error)]
pub enum ExecutorError {
    #[error("dnfast executor requires EUID 0")]
    NotRoot,
    #[error("executor argument contract is invalid")]
    Arguments,
    #[error("plan path is not an absolute UTF-8 path")]
    PlanPath,
    #[error("plan path contains an unsafe component")]
    UnsafeComponent,
    #[error("plan descriptor is not a secure regular file")]
    UnsafePlan,
    #[error("plan exceeds the 16 MiB limit")]
    PlanTooLarge,
    #[error("plan descriptor could not be read: {0}")]
    Read(String),
    #[error("root-owned staging could not be prepared: {0}")]
    Staging(String),
    #[error("proposal is not a current canonical solver plan: {0}")]
    Plan(String),
    #[error("transaction execution is not yet available")]
    Unavailable,
    #[error("private root mount could not be prepared: {0}")]
    Mount(String),
    #[error("root mount changed after reconciliation; transaction may be stateful: {0}")]
    MountStateful(String),
    #[error("root-owned transaction inputs are invalid: {0}")]
    Inputs(String),
}
