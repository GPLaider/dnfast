use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};
use dnfast_core::Action;

use crate::response::JsonOutput;

#[derive(Debug, Parser)]
#[command(
    name = "dnfast",
    version,
    about = "Fast, accurate Fedora RPM tooling",
    long_about = "dnfast refreshes and searches RPM metadata, resolves transactions directly with libsolv, verifies RPMs, and applies approved plans directly with librpm through a fixed root executor. It does not invoke DNF or DNF5."
)]
pub(crate) struct Cli {
    #[arg(
        long,
        global = true,
        help = "Explicitly request the dnfast.cli.v1 JSON response"
    )]
    json: bool,
    #[command(subcommand)]
    pub(crate) command: Option<Commands>,
}

impl Cli {
    pub(crate) const fn json_output(&self) -> JsonOutput {
        if self.json {
            JsonOutput::RequestedV1
        } else {
            JsonOutput::NativeV1
        }
    }
}

#[derive(Debug, Subcommand)]
pub(crate) enum Commands {
    #[command(about = "Solve package intent and write a reviewable plan without changing packages")]
    Plan {
        #[arg(value_enum)]
        action: PlanAction,
        #[arg(long, value_name = "ABSOLUTE_FILE")]
        output: PathBuf,
        #[arg(long = "repo", visible_alias = "enable-repo", value_name = "ID")]
        repositories: Vec<String>,
        packages: Vec<String>,
    },
    #[command(about = "Run one approved plan through the fixed root executor")]
    Apply {
        #[arg(value_name = "ABSOLUTE_PLAN")]
        plan: PathBuf,
        #[arg(long, conflicts_with = "assumeno")]
        assumeyes: bool,
        #[arg(long, conflicts_with = "assumeyes")]
        assumeno: bool,
    },
    #[command(about = "Plan and apply an install through the fixed root executor")]
    Install(MutationArgs),
    #[command(about = "Plan and apply a removal through the fixed root executor")]
    Remove(MutationArgs),
    #[command(about = "Plan and apply an upgrade through the fixed root executor")]
    Upgrade(MutationArgs),
    #[command(about = "Plan and apply an explicit package downgrade")]
    Downgrade(MutationArgs),
    #[command(about = "Reinstall the exact installed EVRA from a verified repository")]
    Reinstall(MutationArgs),
    #[command(about = "Synchronize installed packages to verified repository versions")]
    DistroSync(MutationArgs),
    #[command(about = "Remove only dependency-reason packages proven unneeded")]
    Autoremove(MutationArgs),
    #[command(about = "Inspect or pre-warm the resident transaction daemon")]
    Daemon {
        #[command(subcommand)]
        command: DaemonCommand,
    },
    #[command(about = "Inspect configured repositories without network access")]
    Repo {
        #[command(subcommand)]
        command: RepoCommand,
    },
    #[command(about = "Inspect the durable dnfast transaction journal")]
    History {
        #[command(subcommand)]
        command: HistoryCommand,
    },
    #[command(about = "Report runtime capabilities and optionally clean stale private inputs")]
    Doctor {
        #[arg(
            long,
            help = "Remove only old, unlocked root-private input generations"
        )]
        cleanup_stale_inputs: bool,
    },
    #[command(about = "Search verified cached repository metadata without network access")]
    Search {
        #[arg(long = "repo", value_name = "ID")]
        repositories: Vec<String>,
        #[arg(long, value_name = "DIR")]
        cache_dir: Option<PathBuf>,
        query: String,
    },
    #[command(about = "Inspect comps groups/environments or install their package set")]
    Group {
        #[command(subcommand)]
        command: GroupCommand,
    },
    #[command(about = "Inspect, install, or remove comps environments")]
    Environment {
        #[command(subcommand)]
        command: GroupCommand,
    },
    #[command(about = "Inspect or change modular repository state")]
    Module {
        #[command(subcommand)]
        command: ModuleCommand,
    },
    #[command(about = "Inspect or apply checksum-bound Fedora advisories")]
    Advisory {
        #[command(subcommand)]
        command: AdvisoryCommand,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum AdvisoryCommand {
    #[command(about = "List advisories applicable to the current RPMDB")]
    List(AdvisoryQueryArgs),
    #[command(about = "Show full details for one or more advisory identifiers")]
    Info {
        #[arg(long = "repo", visible_alias = "enable-repo", value_name = "ID")]
        repositories: Vec<String>,
        #[arg(required = true)]
        advisories: Vec<String>,
    },
    #[command(about = "Upgrade packages covered by applicable advisories")]
    Upgrade(AdvisoryUpgradeArgs),
}

#[derive(Debug, clap::Args)]
pub(crate) struct AdvisoryQueryArgs {
    #[arg(long = "repo", visible_alias = "enable-repo", value_name = "ID")]
    pub(crate) repositories: Vec<String>,
    #[arg(
        long,
        help = "Include advisories that are not applicable to installed packages"
    )]
    pub(crate) all: bool,
    #[arg(long, help = "Select only security advisories")]
    pub(crate) security: bool,
    #[arg(long, value_name = "SEVERITY")]
    pub(crate) severity: Option<String>,
}

#[derive(Debug, clap::Args)]
pub(crate) struct AdvisoryUpgradeArgs {
    #[arg(long = "repo", visible_alias = "enable-repo", value_name = "ID")]
    pub(crate) repositories: Vec<String>,
    #[arg(long, conflicts_with = "assumeno")]
    pub(crate) assumeyes: bool,
    #[arg(long, conflicts_with = "assumeyes")]
    pub(crate) assumeno: bool,
    #[arg(long, help = "Select only security advisories")]
    pub(crate) security: bool,
    #[arg(long, value_name = "SEVERITY")]
    pub(crate) severity: Option<String>,
    #[arg(value_name = "ADVISORY")]
    pub(crate) advisories: Vec<String>,
}

#[derive(Debug, Subcommand)]
pub(crate) enum GroupCommand {
    #[command(about = "List checksum-bound groups and environments")]
    List {
        #[arg(long = "repo", visible_alias = "enable-repo", value_name = "ID")]
        repositories: Vec<String>,
    },
    #[command(about = "Show one checksum-bound group or environment")]
    Info {
        #[arg(long = "repo", visible_alias = "enable-repo", value_name = "ID")]
        repositories: Vec<String>,
        id: String,
    },
    #[command(about = "Install mandatory/default packages from groups or environments")]
    Install(GroupInstallArgs),
    #[command(about = "Remove installed packages selected by groups or environments")]
    Remove(GroupInstallArgs),
}

#[derive(Debug, clap::Args)]
pub(crate) struct GroupInstallArgs {
    #[arg(long = "repo", visible_alias = "enable-repo", value_name = "ID")]
    pub(crate) repositories: Vec<String>,
    #[arg(long, conflicts_with = "assumeno")]
    pub(crate) assumeyes: bool,
    #[arg(long, conflicts_with = "assumeyes")]
    pub(crate) assumeno: bool,
    #[arg(
        long,
        help = "Also install optional group packages and optional environment groups"
    )]
    pub(crate) with_optional: bool,
    #[arg(required = true)]
    pub(crate) groups: Vec<String>,
}

#[derive(Debug, Subcommand)]
pub(crate) enum ModuleCommand {
    #[command(about = "List module streams in root-published repository metadata")]
    List {
        #[arg(long = "repo", visible_alias = "enable-repo", value_name = "ID")]
        repositories: Vec<String>,
    },
    #[command(about = "Show one module stream")]
    Info {
        #[arg(long = "repo", visible_alias = "enable-repo", value_name = "ID")]
        repositories: Vec<String>,
        spec: String,
    },
    #[command(about = "Install a profile from an active module stream")]
    Install(ModuleInstallArgs),
    #[command(about = "Enable a module stream")]
    Enable(ModuleMutationArgs),
    #[command(about = "Reset module stream state")]
    Reset(ModuleMutationArgs),
    #[command(about = "Disable a module stream")]
    Disable(ModuleMutationArgs),
}

#[derive(Debug, clap::Args)]
pub(crate) struct ModuleInstallArgs {
    #[arg(long = "repo", visible_alias = "enable-repo", value_name = "ID")]
    pub(crate) repositories: Vec<String>,
    #[arg(long, conflicts_with = "assumeno")]
    pub(crate) assumeyes: bool,
    #[arg(long, conflicts_with = "assumeyes")]
    pub(crate) assumeno: bool,
    #[arg(value_name = "NAME[:STREAM]/PROFILE", required = true)]
    pub(crate) specs: Vec<String>,
}

#[derive(Debug, clap::Args)]
pub(crate) struct ModuleMutationArgs {
    #[arg(long = "repo", visible_alias = "enable-repo", value_name = "ID")]
    pub(crate) repositories: Vec<String>,
    #[arg(required = true)]
    pub(crate) specs: Vec<String>,
}

#[derive(Debug, Subcommand)]
pub(crate) enum HistoryCommand {
    #[command(about = "List recent transactions and their terminal state")]
    List {
        #[arg(long, default_value_t = 20, value_parser = clap::value_parser!(u16).range(1..=1000))]
        limit: u16,
        #[arg(long, value_enum, default_value_t = HistorySource::Dnfast)]
        source: HistorySource,
    },
    #[command(about = "Show the verified journal sequence for one transaction")]
    Info { transaction_id: String },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub(crate) enum HistorySource {
    Dnfast,
    Dnf5,
    All,
}

#[derive(Debug, Subcommand)]
pub(crate) enum DaemonCommand {
    #[command(about = "Check whether the root-only resident daemon is available")]
    Status,
    #[command(about = "Preload the libsolv pool for an exact repository selection")]
    Warm {
        #[arg(long = "repo", visible_alias = "enable-repo", value_name = "ID")]
        repositories: Vec<String>,
    },
}

#[derive(Debug, clap::Args)]
pub(crate) struct MutationArgs {
    #[arg(long = "repo", visible_alias = "enable-repo", value_name = "ID")]
    pub(crate) repositories: Vec<String>,
    #[arg(long, conflicts_with = "assumeno")]
    pub(crate) assumeyes: bool,
    #[arg(long, conflicts_with = "assumeyes")]
    pub(crate) assumeno: bool,
    pub(crate) packages: Vec<String>,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub(crate) enum PlanAction {
    Install,
    Upgrade,
    Remove,
    Downgrade,
    Reinstall,
    DistroSync,
    Autoremove,
}

impl From<PlanAction> for Action {
    fn from(action: PlanAction) -> Self {
        match action {
            PlanAction::Install => Self::Install,
            PlanAction::Upgrade => Self::Upgrade,
            PlanAction::Remove => Self::Remove,
            PlanAction::Downgrade => Self::Downgrade,
            PlanAction::Reinstall => Self::Reinstall,
            PlanAction::DistroSync => Self::DistroSync,
            PlanAction::Autoremove => Self::Autoremove,
        }
    }
}

#[derive(Debug, Subcommand)]
pub(crate) enum RepoCommand {
    #[command(about = "List repositories and selected source URLs")]
    List {
        #[arg(
            long = "repo-dir",
            value_name = "DIR",
            help = "Read only this repository directory; repeat to add directories"
        )]
        repo_dirs: Vec<PathBuf>,
        #[arg(long, help = "Override Fedora release version for URL expansion")]
        releasever: Option<String>,
        #[arg(long, help = "Override RPM base architecture for URL expansion")]
        basearch: Option<String>,
    },
    #[command(about = "Refresh verified metadata into the immutable cache")]
    Refresh {
        #[arg(long = "repo", visible_alias = "enable-repo", value_name = "ID")]
        repositories: Vec<String>,
    },
    #[command(about = "Refresh only when trusted metadata_expire policy says the cache is stale")]
    Makecache {
        #[arg(long = "repo", visible_alias = "enable-repo", value_name = "ID")]
        repositories: Vec<String>,
    },
}
