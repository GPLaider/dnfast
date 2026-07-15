#![forbid(unsafe_code)]

mod error;
mod anchored_fs;
mod loader;
mod main_config;
mod model;
mod parser;
mod profile;
mod refresh_policy;
mod source_loader;
mod trust;
mod variables;

#[cfg(test)]
mod tests;

pub use error::RepoError;
pub use loader::load_repository_dirs;
pub use main_config::{parse_main_config, MainConfig, MutationError};
pub use model::{Repository, SourceKind};
pub use parser::parse_repository_file;
pub use profile::{apply_setopts, parse_before_network, parse_repo_profile, MetadataExpire, MutationProfile, RepoConfig};
pub use refresh_policy::{load_refresh_policy, RefreshPolicy};
pub use source_loader::{load_mutation_profile, load_mutation_profile_from, load_system_mutation_profile};
pub use trust::{key_bundle_digest, normalize_gpgkey_location, validate_gpgkey_bundle_path, KeyBundle};
pub use variables::Variables;
