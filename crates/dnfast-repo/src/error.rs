use std::{error::Error, fmt, io, path::PathBuf};

#[derive(Debug)]
pub enum RepoError {
    Parse {
        path: PathBuf,
        line: usize,
        message: String,
    },
    UnresolvedVariable(String),
    MalformedVariable(String),
    Io {
        path: PathBuf,
        source: io::Error,
    },
    InvalidUtf8 {
        path: PathBuf,
    },
}

impl fmt::Display for RepoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse {
                path,
                line,
                message,
            } => write!(formatter, "{}:{line}: {message}", path.display()),
            Self::UnresolvedVariable(variable) => {
                write!(formatter, "unresolved repository variable: {variable}")
            }
            Self::MalformedVariable(value) => {
                write!(formatter, "malformed repository variable in: {value}")
            }
            Self::Io { path, source } => write!(formatter, "{}: {source}", path.display()),
            Self::InvalidUtf8 { path } => write!(
                formatter,
                "{}: repository file is not valid UTF-8",
                path.display()
            ),
        }
    }
}

impl Error for RepoError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Parse { .. }
            | Self::UnresolvedVariable(_)
            | Self::MalformedVariable(_)
            | Self::InvalidUtf8 { .. } => None,
        }
    }
}

pub(crate) fn parse_error(
    path: &std::path::Path,
    line: usize,
    message: impl Into<String>,
) -> RepoError {
    RepoError::Parse {
        path: path.to_owned(),
        line,
        message: message.into(),
    }
}
