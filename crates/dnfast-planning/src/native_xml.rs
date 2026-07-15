use crate::{PlanningError, PlanningRepository};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeRepositoryXml {
    repomd: Vec<u8>,
    primary: Vec<u8>,
    filelists: Vec<u8>,
}

impl NativeRepositoryXml {
    pub fn repomd(&self) -> &[u8] { &self.repomd }
    pub fn primary(&self) -> &[u8] { &self.primary }
    pub fn filelists(&self) -> &[u8] { &self.filelists }
}

impl PlanningRepository {
    pub fn materialize_native_xml(&self) -> Result<NativeRepositoryXml, PlanningError> {
        let repomd = self.repomd.decode_verified().map_err(|error| materialization_error("repomd", error))?;
        let records = dnfast_metadata::parse_repomd_records(&repomd).map_err(|error| materialization_error("repomd", error))?;
        let primary = self.primary.decode_verified().map_err(|error| materialization_error("primary", error))?;
        let primary = dnfast_metadata::decode_record(&primary, &records.primary).map_err(|error| materialization_error("primary", error))?;
        let parsed_primary = dnfast_metadata::parse_primary_records(primary.as_slice()).map_err(|error| materialization_error("primary", error))?;
        if parsed_primary != self.solver_inputs {
            return Err(PlanningError::Input("solver inputs differ from primary metadata".into()));
        }
        let filelists = self.filelists.decode_verified().map_err(|error| materialization_error("filelists", error))?;
        let filelists = dnfast_metadata::decode_record(&filelists, &records.filelists).map_err(|error| materialization_error("filelists", error))?;
        let parsed_filelists = dnfast_metadata::parse_filelists(filelists.as_slice()).map_err(|error| materialization_error("filelists", error))?;
        if parsed_filelists != self.filelist_inputs {
            return Err(PlanningError::Input("filelist inputs differ from filelists metadata".into()));
        }
        dnfast_metadata::validate_filelists_generation(&self.solver_inputs, &self.filelist_inputs)
            .map_err(|error| materialization_error("filelists", error))?;
        Ok(NativeRepositoryXml { repomd, primary, filelists })
    }
}

fn materialization_error(role: &'static str, error: impl std::fmt::Display) -> PlanningError {
    PlanningError::Input(format!("{role} rpm-md materialization failed: {error}"))
}
