use std::error::Error;
use std::fmt;
use std::marker::PhantomData;
use std::rc::Rc;

mod inventory;
pub use inventory::{
    ExecutionState, ExecutorInventory, InventoryError, InventoryReader, KeyringInstalled,
};
mod checked_transaction;
mod transaction;
mod trust;
pub use transaction::{
    TransactionCounts, TransactionFailureClass, TransactionProblem, TransactionProblemError,
};
pub use trust::{ExpectedPackage, TrustError, VerifiedArtifact, VerifiedStagedKey};

#[cfg(feature = "test-fixtures")]
pub fn fixture_reset_inventory_counts() {
    dnfast_native_sys::fixture_reset_inventory_counts();
}

#[cfg(feature = "test-fixtures")]
pub fn fixture_inventory_counts() -> (u64, u64) {
    dnfast_native_sys::fixture_inventory_counts()
}

/// A thread-affine native solver/RPM context.
///
/// ```compile_fail
/// fn require_send<T: Send>() {}
/// require_send::<dnfast_native::NativeContext>();
/// ```
///
/// ```compile_fail
/// fn require_sync<T: Sync>() {}
/// require_sync::<dnfast_native::NativeContext>();
/// ```
pub struct NativeContext {
    inner: dnfast_native_sys::Context,
    _thread_affine: PhantomData<Rc<()>>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Repository {
    pub id: String,
    pub repomd_path: String,
    pub primary_path: String,
    pub filelists_path: String,
    pub priority: i32,
    pub cost: i32,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SolveResult {
    pub actions: Vec<String>,
    pub repositories: Vec<String>,
    pub kinds: Vec<String>,
    pub obsoletes: Vec<Option<String>>,
    pub requested_specs: Vec<Option<String>>,
    pub requested_relation_kinds: Vec<bool>,
    pub problems: Vec<String>,
    pub decisions: Vec<SolveDecision>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SolveDecision {
    pub requiring: String,
    pub provider: String,
    pub relation: String,
    pub weak: bool,
    pub provider_installed: bool,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct NativeLimits {
    pub max_packages: u32,
    pub max_relations_per_package: u32,
    pub max_metadata_bytes: u64,
}

#[derive(Debug, Eq, PartialEq)]
pub enum NativeError {
    UnsupportedArchitecture(dnfast_core::Architecture),
    UnsupportedAbi { component: String, symbol: String },
    Interrupted,
    CallbackFailed,
    NativeFailure { status: i32, message: String },
    PermissionDenied,
    LockTimeout,
}

impl NativeContext {
    pub fn open(
        architecture: dnfast_core::Architecture,
        interrupt: impl FnMut() -> bool + 'static,
    ) -> Result<Self, NativeError> {
        dnfast_native_sys::Context::open(pool_architecture(architecture)?, interrupt)
            .map(|inner| Self {
                inner,
                _thread_affine: PhantomData,
            })
            .map_err(NativeError::from)
    }

    pub fn open_with_limits(
        architecture: dnfast_core::Architecture,
        interrupt: impl FnMut() -> bool + 'static,
        limits: NativeLimits,
    ) -> Result<Self, NativeError> {
        dnfast_native_sys::Context::open_with_limits(
            pool_architecture(architecture)?,
            interrupt,
            dnfast_native_sys::Limits {
                max_packages: limits.max_packages,
                max_relations_per_package: limits.max_relations_per_package,
                max_metadata_bytes: limits.max_metadata_bytes,
            },
        )
        .map(|inner| Self {
            inner,
            _thread_affine: PhantomData,
        })
        .map_err(NativeError::from)
    }

    pub fn check_interruption(&mut self) -> Result<bool, NativeError> {
        self.inner.check().map_err(NativeError::from)
    }

    pub fn pool_architecture(&self) -> Result<dnfast_core::Architecture, NativeError> {
        match self.inner.pool_architecture().map_err(NativeError::from)? {
            dnfast_native_sys::PoolArchitecture::Aarch64 => Ok(dnfast_core::Architecture::Aarch64),
            dnfast_native_sys::PoolArchitecture::X86_64 => Ok(dnfast_core::Architecture::X86_64),
        }
    }

    pub fn add_repository(&mut self, repository: Repository) -> Result<(), NativeError> {
        self.inner
            .add_repo(&dnfast_native_sys::RepoInput {
                id: repository.id,
                repomd_path: repository.repomd_path,
                primary_path: repository.primary_path,
                filelists_path: repository.filelists_path,
                priority: repository.priority,
                cost: repository.cost,
            })
            .map_err(NativeError::from)
    }

    pub fn add_installed_rpmdb(&mut self, root: &str) -> Result<(), NativeError> {
        self.inner.add_rpmdb(root).map_err(NativeError::from)
    }

    pub fn read_installed_inventory(
        &mut self,
    ) -> Result<dnfast_core::InstalledInventory, InventoryError> {
        inventory::read_from_context(&mut self.inner)
    }

    pub fn add_installed_repository(&mut self, repository: Repository) -> Result<(), NativeError> {
        self.inner
            .add_installed_repo(&dnfast_native_sys::RepoInput {
                id: repository.id,
                repomd_path: repository.repomd_path,
                primary_path: repository.primary_path,
                filelists_path: repository.filelists_path,
                priority: repository.priority,
                cost: repository.cost,
            })
            .map_err(NativeError::from)
    }

    pub fn solve_install(
        &mut self,
        name: &str,
        weak: bool,
        best: bool,
    ) -> Result<SolveResult, NativeError> {
        self.solve_install_many(&[name], weak, best)
    }

    pub fn solve_install_many(
        &mut self,
        names: &[&str],
        weak: bool,
        best: bool,
    ) -> Result<SolveResult, NativeError> {
        self.solve_operation(
            names,
            weak,
            best,
            dnfast_native_sys::SolveOperation::Install,
        )
    }

    pub fn solve_erase_many(&mut self, names: &[&str]) -> Result<SolveResult, NativeError> {
        self.solve_operation(
            names,
            false,
            false,
            dnfast_native_sys::SolveOperation::Erase,
        )
    }

    pub fn solve_upgrade_many(
        &mut self,
        names: &[&str],
        best: bool,
    ) -> Result<SolveResult, NativeError> {
        self.solve_operation(
            names,
            false,
            best,
            dnfast_native_sys::SolveOperation::Upgrade,
        )
    }

    fn solve_operation(
        &mut self,
        names: &[&str],
        weak: bool,
        best: bool,
        operation: dnfast_native_sys::SolveOperation,
    ) -> Result<SolveResult, NativeError> {
        self.inner
            .solve_with_operation(names, weak, best, operation)
            .map(|result| SolveResult {
                actions: result.actions,
                repositories: result.repositories,
                kinds: result.kinds,
                obsoletes: result.obsoletes,
                requested_specs: result.requested_specs,
                requested_relation_kinds: result.requested_relation_kinds,
                problems: result.problems,
                decisions: result
                    .decisions
                    .into_iter()
                    .map(|item| SolveDecision {
                        requiring: item.requiring,
                        provider: item.provider,
                        relation: item.relation,
                        weak: item.weak,
                        provider_installed: item.provider_installed,
                    })
                    .collect(),
            })
            .map_err(NativeError::from)
    }
}

pub(crate) fn pool_architecture(
    architecture: dnfast_core::Architecture,
) -> Result<dnfast_native_sys::PoolArchitecture, NativeError> {
    match architecture {
        dnfast_core::Architecture::Aarch64 => Ok(dnfast_native_sys::PoolArchitecture::Aarch64),
        dnfast_core::Architecture::X86_64 => Ok(dnfast_native_sys::PoolArchitecture::X86_64),
        dnfast_core::Architecture::Noarch => {
            Err(NativeError::UnsupportedArchitecture(architecture))
        }
    }
}

impl From<dnfast_native_sys::NativeError> for NativeError {
    fn from(error: dnfast_native_sys::NativeError) -> Self {
        match error.status {
            2 => Self::UnsupportedAbi {
                component: error.component,
                symbol: error.symbol,
            },
            4 => Self::CallbackFailed,
            5 => Self::Interrupted,
            8 => Self::PermissionDenied,
            9 => Self::LockTimeout,
            status => Self::NativeFailure {
                status,
                message: error.message,
            },
        }
    }
}

impl fmt::Display for NativeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedArchitecture(architecture) => write!(
                formatter,
                "unsupported native pool architecture: {architecture:?}"
            ),
            Self::UnsupportedAbi { component, symbol } => {
                write!(formatter, "unsupported native ABI: {component}:{symbol}")
            }
            Self::Interrupted => formatter.write_str("native operation interrupted"),
            Self::CallbackFailed => formatter.write_str("native callback failed"),
            Self::NativeFailure { status, message } => {
                write!(formatter, "native failure {status}: {message}")
            }
            Self::PermissionDenied => {
                formatter.write_str("root execution required for RPM write context")
            }
            Self::LockTimeout => formatter.write_str("RPM write lock deadline exceeded"),
        }
    }
}

impl Error for NativeError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x86_64_public_context_selects_x86_64_native_pool() {
        let context = NativeContext::open(dnfast_core::Architecture::X86_64, || false).unwrap();
        assert_eq!(
            context.pool_architecture().unwrap(),
            dnfast_core::Architecture::X86_64
        );
    }

    #[test]
    fn noarch_cannot_be_used_as_a_native_pool_architecture() {
        assert!(matches!(
            NativeContext::open(dnfast_core::Architecture::Noarch, || false),
            Err(NativeError::UnsupportedArchitecture(
                dnfast_core::Architecture::Noarch
            ))
        ));
    }
}
