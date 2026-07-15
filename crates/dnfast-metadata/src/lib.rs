#![forbid(unsafe_code)]

mod compression;
mod error;
mod filelists;
mod limits;
mod primary;
mod relations;
mod repomd;
mod search;
mod xml;

pub use compression::{decode_primary, decode_record, parse_filelists_record, verify_compressed};
pub use error::MetadataError;
pub use filelists::{
    FileListPackage, parse_filelists, publish_validated, validate_filelists_generation,
};
pub use limits::*;
pub use primary::{CompletePackage, MAX_PACKAGES, Package, parse_primary, parse_primary_records};
pub use relations::{MAX_RELATIONS, MAX_RELATIONS_PER_PACKAGE, Relation, RelationFlags};
pub use repomd::{
    MAX_PRIMARY_COMPRESSED_BYTES, MAX_PRIMARY_OPEN_BYTES, MetadataRecord, PrimaryRecord,
    RepomdRecords, parse_repomd, parse_repomd_records,
};
pub use search::search;
