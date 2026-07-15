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
pub use filelists::{parse_filelists, publish_validated, validate_filelists_generation, FileListPackage};
pub use limits::*;
pub use primary::{parse_primary, parse_primary_records, CompletePackage, Package, MAX_PACKAGES};
pub use relations::{Relation, RelationFlags, MAX_RELATIONS, MAX_RELATIONS_PER_PACKAGE};
pub use repomd::{parse_repomd, parse_repomd_records, MetadataRecord, PrimaryRecord, RepomdRecords, MAX_PRIMARY_COMPRESSED_BYTES, MAX_PRIMARY_OPEN_BYTES};
pub use search::search;
