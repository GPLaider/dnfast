#![forbid(unsafe_code)]

mod compression;
mod comps;
mod error;
mod filelists;
mod limits;
mod primary;
mod relations;
mod repomd;
mod search;
mod updateinfo;
mod xml;

pub use compression::{
    copy_filelists_record_verified, copy_primary_record_verified, decode_auxiliary, decode_primary,
    decode_record, parse_filelists_record, validate_filelists_record,
    validate_filelists_record_identities, validate_primary_record, verify_compressed,
    visit_filelists_record_identities,
};
pub use comps::{Comps, CompsEnvironment, CompsGroup, CompsPackage, CompsPackageType, parse_comps};
pub use error::MetadataError;
pub use filelists::{
    FileListPackage, parse_filelists, publish_validated, validate_filelists_generation,
    validate_filelists_identities, validate_filelists_xml, validate_filelists_xml_identities,
};
pub use limits::*;
pub use primary::{
    CompletePackage, MAX_PACKAGES, Package, PrimaryPackageIdentity, ValidatedPrimary,
    parse_primary, parse_primary_records, parse_primary_validated,
};
pub use relations::{MAX_RELATIONS, MAX_RELATIONS_PER_PACKAGE, Relation, RelationFlags};
pub use repomd::{
    AuxiliaryRecord, MAX_PRIMARY_COMPRESSED_BYTES, MAX_PRIMARY_OPEN_BYTES, MetadataRecord,
    PrimaryRecord, RepomdRecords, parse_repomd, parse_repomd_records,
};
pub use search::search;
pub use updateinfo::{Advisory, AdvisoryPackage, AdvisoryReference, UpdateInfo, parse_updateinfo};
