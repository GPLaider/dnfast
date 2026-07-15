#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("journal I/O failure: {0}")]
    Io(String),
    #[error("unsafe journal path: {0}")]
    UnsafePath(String),
    #[error("journal record is corrupt: {0}")]
    Corrupt(String),
    #[error("illegal journal transition: {0}")]
    Transition(String),
    #[error("journal limit exceeded: {0}")]
    Limit(&'static str),
    #[error("transaction journal is busy")]
    Busy,
}

pub(crate) fn io(error: std::io::Error) -> StateError { StateError::Io(error.to_string()) }
pub(crate) fn errno(error: rustix::io::Errno) -> StateError { StateError::Io(error.to_string()) }
