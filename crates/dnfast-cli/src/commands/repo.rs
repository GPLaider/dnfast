use std::{
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use dnfast_cache::{Cache, CacheError};
use dnfast_planning::{RootPlanningPublisher, SYSTEM_CACHE_PATH};
use dnfast_refresh::{HttpTransport, MetadataTrust, RefreshOutcome, Refresher, Source};
use dnfast_repo::{
    MutationProfile, RepoConfig, key_bundle_digest, load_repository_dirs,
    load_system_mutation_profile,
};

use crate::{
    commands::AppFailure,
    environment::{repository_variables, system_repo_dirs},
    rendering::escaped_field,
};

pub(super) fn refresh(requested: Vec<String>) -> Result<String, AppFailure> {
    require_root()?;
    let publisher = RootPlanningPublisher::system().map_err(planning_failure)?;
    publisher
        .prepare_system_cache_for_verified_refresh()
        .map_err(planning_failure)?;
    let profile =
        load_system_mutation_profile().map_err(|error| AppFailure::new(1, error.to_string()))?;
    let cache = Cache::new(SYSTEM_CACHE_PATH);
    // A planning snapshot is deliberately bound to every enabled repository,
    // even when --repo narrows which repositories the caller wants refreshed.
    // On first use there is no safe old generation to retain for unselected
    // repositories, so bootstrap those missing/corrupt pointers in the same
    // transaction instead of downloading the requested subset and failing at
    // publication time.
    let requested = expand_bootstrap_selection(&profile, requested, |repository| {
        match cache.open_current_generation_identity(repository) {
            Ok(_) => Ok(true),
            Err(
                CacheError::MissingSnapshot(_)
                | CacheError::CacheUpgradeRequired
                | CacheError::Corrupt(_),
            ) => Ok(false),
            Err(CacheError::Io(error)) => Err(error),
        }
    })?;
    let refresher = Refresher::new(HttpTransport::new(), &cache);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| AppFailure::new(1, error.to_string()))?
        .as_secs();
    let report = refresh_profile(
        &profile,
        requested,
        |repository, source| {
            let metadata_trust = metadata_trust(repository, now)?;
            refresher
                .refresh_with_metadata_trust(&repository.id, source, metadata_trust.as_ref())
                .map_err(|error| error.to_string())
        },
        |published_at_unix, refreshed_generations| {
            publisher
                .publish_after_verified_refresh(published_at_unix, refreshed_generations)
                .map_err(|error| error.to_string())
        },
        now,
    )?;
    Ok(format!(
        "refreshed repositories: {}; planning_snapshot={}",
        report.refreshed.join(", "),
        report.planning_snapshot,
    ))
}

fn expand_bootstrap_selection<Probe>(
    profile: &MutationProfile,
    mut requested: Vec<String>,
    has_generation: Probe,
) -> Result<Vec<String>, AppFailure>
where
    Probe: Fn(&str) -> Result<bool, String>,
{
    requested.sort();
    requested.dedup();
    for id in &requested {
        if !profile
            .repositories
            .iter()
            .any(|repository| repository.enabled && repository.id == *id)
        {
            return Err(AppFailure::new(1, format!("unknown repository: {id}")));
        }
    }
    if requested.is_empty() {
        return Ok(requested);
    }
    for repository in profile
        .repositories
        .iter()
        .filter(|repository| repository.enabled)
    {
        if !requested.contains(&repository.id)
            && !has_generation(&repository.id).map_err(|error| {
                AppFailure::new(
                    1,
                    format!("cannot inspect repository {} cache: {error}", repository.id),
                )
            })?
        {
            requested.push(repository.id.clone());
        }
    }
    requested.sort();
    Ok(requested)
}

pub(super) fn makecache(requested: Vec<String>) -> Result<String, AppFailure> {
    require_root_for("repo makecache")?;
    let publisher = RootPlanningPublisher::system().map_err(planning_failure)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| AppFailure::new(1, error.to_string()))?
        .as_secs();
    if publisher
        .current_metadata_is_fresh(&requested, now)
        .unwrap_or(false)
    {
        let digest =
            dnfast_planning::PlanningSnapshot::current_system_digest().map_err(planning_failure)?;
        return Ok(format!(
            "metadata cache is fresh; planning_snapshot={digest}"
        ));
    }
    refresh(requested)
}

#[derive(Debug, Eq, PartialEq)]
struct RefreshReport {
    refreshed: Vec<String>,
    planning_snapshot: String,
}

fn refresh_profile<Refresh, Publish>(
    profile: &MutationProfile,
    mut requested: Vec<String>,
    refresh_source: Refresh,
    publish_snapshot: Publish,
    published_at_unix: u64,
) -> Result<RefreshReport, AppFailure>
where
    Refresh: Fn(&RepoConfig, Source) -> Result<RefreshOutcome, String> + Sync,
    Publish: FnOnce(u64, &[(String, String)]) -> Result<String, String>,
{
    requested.sort();
    requested.dedup();
    for id in &requested {
        if !profile
            .repositories
            .iter()
            .any(|repository| repository.id == *id && repository.enabled)
        {
            return Err(AppFailure::new(1, format!("unknown repository: {id}")));
        }
    }
    let mut selected = profile
        .repositories
        .iter()
        .filter(|repository| repository.enabled)
        .filter(|repository| requested.is_empty() || requested.contains(&repository.id))
        .collect::<Vec<_>>();
    selected.sort_by(|left, right| left.id.cmp(&right.id));
    if selected.is_empty() {
        return Err(AppFailure::new(1, "no enabled repositories selected"));
    }
    let results = std::thread::scope(|scope| {
        selected
            .into_iter()
            .map(|repository| {
                let refresh_source = &refresh_source;
                scope.spawn(move || {
                    let mut outcome = None;
                    let mut last_error = None;
                    for source in sources(repository) {
                        match refresh_source(repository, source) {
                            Ok(value) => {
                                outcome = Some(value);
                                break;
                            }
                            Err(error) => last_error = Some(error),
                        }
                    }
                    outcome
                        .map(|outcome| {
                            (
                                escaped_field(&repository.id),
                                repository.id.clone(),
                                outcome.digest,
                            )
                        })
                        .ok_or_else(|| {
                            format!(
                                "{}: {}",
                                repository.id,
                                last_error
                                    .unwrap_or_else(|| "repository has no usable source".into())
                            )
                        })
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|worker| {
                worker
                    .join()
                    .map_err(|_| "repository refresh worker panicked".to_owned())?
            })
            .collect::<Result<Vec<_>, String>>()
    })
    .map_err(|error| AppFailure::new(1, error))?;
    let mut refreshed = Vec::with_capacity(results.len());
    let mut refreshed_generations = Vec::with_capacity(results.len());
    for (label, repository, digest) in results {
        refreshed.push(label);
        refreshed_generations.push((repository, digest));
    }
    let planning_snapshot = publish_snapshot(published_at_unix, &refreshed_generations)
        .map_err(|error| AppFailure::new(1, error))?;
    Ok(RefreshReport {
        refreshed,
        planning_snapshot,
    })
}

fn metadata_trust(
    repository: &RepoConfig,
    valid_at_unix: u64,
) -> Result<Option<MetadataTrust>, String> {
    if !repository.repo_gpgcheck {
        return Ok(None);
    }
    let paths = repository
        .gpgkey
        .iter()
        .map(PathBuf::from)
        .collect::<Vec<_>>();
    let bundle = key_bundle_digest(&repository.id, &paths).map_err(|error| error.to_string())?;
    if repository.key_bundle_digest != Some(bundle.digest) {
        return Err("repository key bundle changed after profile validation".into());
    }
    MetadataTrust::new(
        bundle.certificates,
        repository.allowed_fingerprints.clone(),
        hex::encode(bundle.digest),
        valid_at_unix,
    )
    .map(Some)
    .map_err(|error| error.to_string())
}

fn sources(repository: &RepoConfig) -> Vec<Source> {
    repository
        .baseurl
        .iter()
        .cloned()
        .map(Source::BaseUrl)
        .chain(repository.metalink.iter().cloned().map(Source::Metalink))
        .chain(
            repository
                .mirrorlist
                .iter()
                .cloned()
                .map(Source::Mirrorlist),
        )
        .collect()
}

fn require_root() -> Result<(), AppFailure> {
    require_root_for("repo refresh")
}

fn require_root_for(command: &str) -> Result<(), AppFailure> {
    if rustix::process::geteuid().as_raw() == 0 {
        Ok(())
    } else {
        Err(AppFailure::new(1, format!("{command} requires root")))
    }
}

fn planning_failure(error: dnfast_planning::PlanningError) -> AppFailure {
    AppFailure::new(1, error.to_string())
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

    use dnfast_refresh::RefreshOutcome;
    use dnfast_repo::{MainConfig, MetadataExpire, MutationProfile, RepoConfig, Variables};

    use super::{expand_bootstrap_selection, refresh_profile};

    #[test]
    fn explicit_first_refresh_bootstraps_missing_enabled_repositories() {
        let profile = MutationProfile {
            main: MainConfig::default(),
            repositories: vec![repository("first"), repository("second")],
            variables: Variables::default(),
        };
        let selected =
            expand_bootstrap_selection(&profile, vec!["first".into()], |id| Ok(id == "first"))
                .expect("selection");
        assert_eq!(selected, ["first", "second"]);

        let selected = expand_bootstrap_selection(&profile, vec!["first".into()], |_| Ok(true))
            .expect("selection");
        assert_eq!(selected, ["first"]);
    }

    #[test]
    fn refresh_publishes_the_snapshot_after_every_selected_repository_verifies() {
        let profile = MutationProfile {
            main: MainConfig::default(),
            repositories: vec![repository("first"), repository("second")],
            variables: Variables::default(),
        };
        let refreshed = AtomicUsize::new(0);
        let published_after = AtomicUsize::new(0);
        let published_at = AtomicU64::new(0);

        let report = refresh_profile(
            &profile,
            Vec::new(),
            |_, _| {
                refreshed.fetch_add(1, Ordering::SeqCst);
                Ok(RefreshOutcome {
                    digest: "verified-generation".into(),
                    packages: 1,
                })
            },
            |timestamp, _| {
                published_after.store(refreshed.load(Ordering::SeqCst), Ordering::SeqCst);
                published_at.store(timestamp, Ordering::SeqCst);
                Ok("published-snapshot".into())
            },
            42,
        )
        .expect("the fake verified refresh and publisher must succeed");

        assert_eq!(report.refreshed, ["first", "second"]);
        assert_eq!(report.planning_snapshot, "published-snapshot");
        assert_eq!(published_after.load(Ordering::SeqCst), 2);
        assert_eq!(published_at.load(Ordering::SeqCst), 42);
    }

    #[test]
    fn implicit_skip_if_unavailable_failure_does_not_publish() {
        let mut skipped = repository("skip");
        skipped.skip_if_unavailable = true;
        let profile = MutationProfile {
            main: MainConfig::default(),
            repositories: vec![skipped],
            variables: Variables::default(),
        };
        let publisher_calls = AtomicUsize::new(0);

        let result = refresh_profile(
            &profile,
            Vec::new(),
            |_, _| Err("unavailable".into()),
            |_, _| {
                publisher_calls.fetch_add(1, Ordering::SeqCst);
                Ok("published-snapshot".into())
            },
            42,
        );

        assert_eq!(publisher_calls.load(Ordering::SeqCst), 0);
        let error = result.expect_err("a selected refresh failure must reject publication");
        assert_eq!(error.code, 1);
        assert_eq!(error.message, "skip: unavailable");
    }

    #[test]
    fn explicit_skip_if_unavailable_failure_does_not_publish() {
        let mut skipped = repository("skip");
        skipped.skip_if_unavailable = true;
        let profile = MutationProfile {
            main: MainConfig::default(),
            repositories: vec![skipped],
            variables: Variables::default(),
        };
        let publisher_calls = AtomicUsize::new(0);

        let result = refresh_profile(
            &profile,
            vec!["skip".into()],
            |_, _| Err("unavailable".into()),
            |_, _| {
                publisher_calls.fetch_add(1, Ordering::SeqCst);
                Ok("published-snapshot".into())
            },
            42,
        );

        assert!(result.is_err());
        assert_eq!(publisher_calls.load(Ordering::SeqCst), 0);
    }

    fn repository(id: &str) -> RepoConfig {
        RepoConfig {
            id: id.into(),
            name: None,
            enabled: true,
            baseurl: vec![format!("https://{id}.example.invalid/repository")],
            metalink: None,
            mirrorlist: None,
            priority: 99,
            cost: 1_000,
            skip_if_unavailable: false,
            metadata_expire: MetadataExpire::AfterSeconds(172_800),
            proxy: None,
            sslverify: true,
            gpgcheck: true,
            pkg_gpgcheck: true,
            repo_gpgcheck: false,
            excludepkgs: Vec::new(),
            includepkgs: Vec::new(),
            gpgkey: Vec::new(),
            allowed_fingerprints: Vec::new(),
            key_bundle_digest: None,
        }
    }
}

pub(super) fn list(
    mut repo_dirs: Vec<PathBuf>,
    releasever: Option<String>,
    basearch: Option<String>,
) -> Result<String, AppFailure> {
    if repo_dirs.is_empty() {
        repo_dirs = system_repo_dirs();
    }
    let variables = repository_variables(releasever, basearch)?;
    let repositories =
        load_repository_dirs(&repo_dirs).map_err(|error| AppFailure::new(1, error.to_string()))?;
    if repositories.is_empty() {
        return Err(AppFailure::new(1, "no repository definitions found"));
    }

    let mut listed = Vec::new();
    for repository in repositories {
        let _expanded_sources = repository
            .sources()
            .map(|(kind, source)| {
                variables
                    .expand(source)
                    .map(|source| (kind, source))
                    .map_err(|error| {
                        AppFailure::new(1, format!("{}: {error}", repository.origin.display()))
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        listed.push(format!(
            "{}={}",
            escaped_field(&repository.id),
            if repository.enabled {
                "enabled"
            } else {
                "disabled"
            },
        ));
    }
    Ok(format!("configured repositories: {}", listed.join(", ")))
}
