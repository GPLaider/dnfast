use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InputManifest {
    pub(crate) schema_version: u32,
    pub(crate) policy: InputFile,
    pub(crate) metadata_sha256: String,
    pub(crate) trust_sha256: String,
    pub(crate) repositories: Vec<InputRepository>,
    pub(crate) artifacts: Vec<InputArtifact>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InputRepository {
    pub(crate) id: String,
    pub(crate) priority: i32,
    pub(crate) cost: i32,
    pub(crate) generation_sha256: String,
    pub(crate) origin: InputOrigin,
    pub(crate) repomd: InputFile,
    pub(crate) primary: InputFile,
    pub(crate) filelists: InputFile,
    pub(crate) trust: InputRepositoryTrust,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InputOrigin {
    pub(crate) repomd_url: String,
    pub(crate) sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InputRepositoryTrust {
    pub(crate) policy: InputFile,
    pub(crate) sha256: String,
    pub(crate) keys: Vec<InputKey>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InputFile { pub(crate) name: String, pub(crate) sha256: String, pub(crate) size: u64 }

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InputKey { pub(crate) file: InputFile, pub(crate) bundle_path: String }

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InputArtifact {
    pub(crate) file: InputFile,
    pub(crate) repo_id: String,
    pub(crate) generation_sha256: String,
    pub(crate) origin_sha256: String,
    pub(crate) trust_sha256: String,
    pub(crate) name: String,
    pub(crate) epoch: u32,
    pub(crate) version: String,
    pub(crate) release: String,
    pub(crate) arch: String,
    pub(crate) vendor: String,
}
