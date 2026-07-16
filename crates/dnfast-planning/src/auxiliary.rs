use crate::{PlanningBytes, PlanningError, PlanningRepository, PlanningSnapshot};

const MAX_COMPS_OPEN_BYTES: u64 = 128 * 1024 * 1024;
const MAX_MODULES_OPEN_BYTES: u64 = 512 * 1024 * 1024;

impl PlanningSnapshot {
    pub fn comps(
        &self,
        repository: &PlanningRepository,
    ) -> Result<Option<dnfast_metadata::Comps>, PlanningError> {
        let bytes = auxiliary(self, repository, AuxiliaryKind::Group, MAX_COMPS_OPEN_BYTES)?;
        bytes
            .map(|bytes| dnfast_metadata::parse_comps(&bytes).map_err(metadata))
            .transpose()
    }

    pub fn module_metadata(
        &self,
        repository: &PlanningRepository,
    ) -> Result<Option<Vec<u8>>, PlanningError> {
        auxiliary(
            self,
            repository,
            AuxiliaryKind::Modules,
            MAX_MODULES_OPEN_BYTES,
        )
    }
}

#[derive(Clone, Copy)]
enum AuxiliaryKind {
    Group,
    Modules,
}

fn auxiliary(
    snapshot: &PlanningSnapshot,
    repository: &PlanningRepository,
    kind: AuxiliaryKind,
    maximum_open_bytes: u64,
) -> Result<Option<Vec<u8>>, PlanningError> {
    let repomd = repository
        .repomd
        .decode_verified(snapshot.storage())
        .map_err(|error| role(kind, error))?;
    let records = dnfast_metadata::parse_repomd_records(&repomd).map_err(metadata)?;
    let (record, descriptor): (
        Option<&dnfast_metadata::AuxiliaryRecord>,
        Option<&PlanningBytes>,
    ) = match kind {
        AuxiliaryKind::Group => (records.group.as_ref(), repository.group.as_ref()),
        AuxiliaryKind::Modules => (records.modules.as_ref(), repository.modules.as_ref()),
    };
    match (record, descriptor) {
        (None, None) => Ok(None),
        (Some(record), Some(descriptor))
            if record.checksum == descriptor.sha256 && record.size == descriptor.size =>
        {
            let payload = descriptor
                .decode_verified(snapshot.storage())
                .map_err(|error| role(kind, error))?;
            dnfast_metadata::decode_auxiliary(&payload, record, maximum_open_bytes)
                .map(Some)
                .map_err(metadata)
        }
        _ => Err(PlanningError::Input(format!(
            "{} descriptor differs from checksum-bound repomd",
            label(kind)
        ))),
    }
}

fn label(kind: AuxiliaryKind) -> &'static str {
    match kind {
        AuxiliaryKind::Group => "group metadata",
        AuxiliaryKind::Modules => "module metadata",
    }
}

fn role(kind: AuxiliaryKind, error: PlanningError) -> PlanningError {
    PlanningError::Input(format!("{} materialization failed: {error}", label(kind)))
}

fn metadata(error: dnfast_metadata::MetadataError) -> PlanningError {
    PlanningError::Input(error.to_string())
}
