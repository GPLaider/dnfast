use thiserror::Error;

#[derive(Debug, Error)]
pub enum PlanningError {
    #[error("dnfast planning publication requires EUID 0")]
    NotRoot,
    #[error("planning root is unsafe: {0}")]
    UnsafeRoot(String),
    #[error("planning snapshot is unsafe: {0}")]
    UnsafeSnapshot(String),
    #[error("planning input is invalid: {0}")]
    Input(String),
    #[error("planning cache is invalid: {0}")]
    Cache(String),
    #[error("planning publication failed: {0}")]
    Io(String),
}
