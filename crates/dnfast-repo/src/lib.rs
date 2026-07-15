#![forbid(unsafe_code)]

mod anchored_fs;
mod error;
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
pub use main_config::{MainConfig, MutationError, parse_main_config};
pub use model::{Repository, SourceKind};
pub use parser::parse_repository_file;
pub use profile::{
    MetadataExpire, MutationProfile, RepoConfig, apply_setopts, parse_before_network,
    parse_repo_profile,
};
pub use refresh_policy::{RefreshPolicy, load_refresh_policy};
pub use source_loader::{
    load_mutation_profile, load_mutation_profile_from, load_system_mutation_profile,
};
pub use trust::{
    KeyBundle, key_bundle_digest, normalize_gpgkey_location, validate_gpgkey_bundle_path,
};
pub use variables::Variables;
