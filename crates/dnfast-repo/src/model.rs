use std::path::PathBuf;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceKind {
    BaseUrl,
    Metalink,
    Mirrorlist,
}

impl SourceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BaseUrl => "baseurl",
            Self::Metalink => "metalink",
            Self::Mirrorlist => "mirrorlist",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Repository {
    pub id: String,
    pub enabled: bool,
    pub baseurls: Vec<String>,
    pub metalink: Option<String>,
    pub mirrorlist: Option<String>,
    pub origin: PathBuf,
}

impl Repository {
    pub fn sources(&self) -> impl Iterator<Item = (SourceKind, &str)> {
        self.baseurls
            .iter()
            .map(|source| (SourceKind::BaseUrl, source.as_str()))
            .chain(
                self.metalink
                    .iter()
                    .map(|source| (SourceKind::Metalink, source.as_str())),
            )
            .chain(
                self.mirrorlist
                    .iter()
                    .map(|source| (SourceKind::Mirrorlist, source.as_str())),
            )
    }

    pub fn selected_source(&self) -> Option<(SourceKind, &str)> {
        self.sources().next()
    }
}
