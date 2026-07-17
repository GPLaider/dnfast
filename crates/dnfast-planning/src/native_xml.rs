use crate::{PlanningError, PlanningRepository, PlanningSnapshot};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeRepositoryXml {
    repomd: Vec<u8>,
    primary_payload: Vec<u8>,
    filelists_payload: Vec<u8>,
    primary: Vec<u8>,
    filelists: Vec<u8>,
    solver_inputs: Vec<dnfast_metadata::CompletePackage>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeRepositoryPrimary {
    repomd: Vec<u8>,
    primary: Vec<u8>,
}

impl NativeRepositoryPrimary {
    pub fn repomd(&self) -> &[u8] {
        &self.repomd
    }

    pub fn primary(&self) -> &[u8] {
        &self.primary
    }
}

impl NativeRepositoryXml {
    pub fn repomd(&self) -> &[u8] {
        &self.repomd
    }
    pub fn primary(&self) -> &[u8] {
        &self.primary
    }
    pub fn primary_payload(&self) -> &[u8] {
        &self.primary_payload
    }
    pub fn filelists(&self) -> &[u8] {
        &self.filelists
    }
    pub fn filelists_payload(&self) -> &[u8] {
        &self.filelists_payload
    }
    pub fn solver_inputs(&self) -> &[dnfast_metadata::CompletePackage] {
        &self.solver_inputs
    }
}

impl PlanningRepository {
    /// Materializes legacy inline metadata. New external-payload snapshots must
    /// use `PlanningSnapshot::materialize_native_xml` so their trusted storage
    /// root remains bound to the root-published snapshot.
    pub fn materialize_native_xml(&self) -> Result<NativeRepositoryXml, PlanningError> {
        materialize(self, None, true)
    }
}

impl PlanningSnapshot {
    pub fn materialize_native_xml(
        &self,
        repository: &PlanningRepository,
    ) -> Result<NativeRepositoryXml, PlanningError> {
        materialize(repository, self.storage(), true)
    }

    pub fn materialize_native_primary(
        &self,
        repository: &PlanningRepository,
    ) -> Result<NativeRepositoryXml, PlanningError> {
        materialize(repository, self.storage(), false)
    }

    pub fn materialize_native_primary_unparsed(
        &self,
        repository: &PlanningRepository,
    ) -> Result<NativeRepositoryPrimary, PlanningError> {
        let repomd = repository
            .repomd
            .decode_verified(self.storage())
            .map_err(|error| materialization_error("repomd", error))?;
        let records = dnfast_metadata::parse_repomd_records(&repomd)
            .map_err(|error| materialization_error("repomd", error))?;
        let primary_payload = repository
            .primary
            .decode_verified(self.storage())
            .map_err(|error| materialization_error("primary", error))?;
        let primary = dnfast_metadata::decode_record(&primary_payload, &records.primary)
            .map_err(|error| materialization_error("primary", error))?;
        Ok(NativeRepositoryPrimary { repomd, primary })
    }
}

fn materialize(
    repository: &PlanningRepository,
    storage: Option<(&std::path::Path, u32)>,
    include_filelists: bool,
) -> Result<NativeRepositoryXml, PlanningError> {
    let repomd = repository
        .repomd
        .decode_verified(storage)
        .map_err(|error| materialization_error("repomd", error))?;
    let records = dnfast_metadata::parse_repomd_records(&repomd)
        .map_err(|error| materialization_error("repomd", error))?;
    let primary_payload = repository
        .primary
        .decode_verified(storage)
        .map_err(|error| materialization_error("primary", error))?;
    let primary = dnfast_metadata::decode_record(&primary_payload, &records.primary)
        .map_err(|error| materialization_error("primary", error))?;
    let parsed_primary = dnfast_metadata::parse_primary_records(primary.as_slice())
        .map_err(|error| materialization_error("primary", error))?;
    let (filelists_payload, filelists) = if include_filelists {
        let filelists_payload = repository
            .filelists
            .decode_verified(storage)
            .map_err(|error| materialization_error("filelists", error))?;
        let filelists = dnfast_metadata::decode_record(&filelists_payload, &records.filelists)
            .map_err(|error| materialization_error("filelists", error))?;
        dnfast_metadata::validate_filelists_xml(filelists.as_slice(), &parsed_primary)
            .map_err(|error| materialization_error("filelists", error))?;
        (filelists_payload, filelists)
    } else {
        (Vec::new(), Vec::new())
    };
    Ok(NativeRepositoryXml {
        repomd,
        primary_payload,
        filelists_payload,
        primary,
        filelists,
        solver_inputs: parsed_primary,
    })
}

fn materialization_error(role: &'static str, error: impl std::fmt::Display) -> PlanningError {
    PlanningError::Input(format!("{role} rpm-md materialization failed: {error}"))
}
