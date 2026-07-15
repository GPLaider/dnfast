use std::path::Path;

use dnfast_repo::{
    MainConfig, MetadataExpire, apply_setopts, parse_before_network, parse_main_config,
    parse_repo_profile,
};

#[test]
fn defaults_match_frozen_fedora_profile_when_main_is_empty() {
    // Given an empty main section.
    // When it is parsed for mutation.
    let config = parse_main_config(Path::new("dnf.conf"), "[main]\n").unwrap();
    // Then every frozen default is present.
    assert_eq!(config, MainConfig::default());
    assert_eq!(config.installonly_limit, 3);
    assert!(config.install_weak_deps);
    assert!(!config.best);
    assert_eq!(
        config.reposdir,
        ["/etc/yum.repos.d", "/etc/dnf/repos.d"].map(std::path::PathBuf::from)
    );
    assert_eq!(
        config.varsdir,
        ["/etc/dnf/vars", "/etc/yum/vars"].map(std::path::PathBuf::from)
    );
    assert!(config.excludepkgs.is_empty() && config.includepkgs.is_empty());
    assert_eq!(
        config.protected_packages,
        ["dnfast", "dnf", "dnf5", "rpm", "glibc", "systemd"]
    );
    assert_eq!(
        config.installonlypkgs,
        [
            "kernel",
            "kernel-core",
            "kernel-modules",
            "kernel-modules-core",
            "kernel-modules-extra"
        ]
    );
}

#[test]
fn supported_values_and_list_reset_follow_layer_order() {
    // Given main values and a repository section.
    let main = parse_main_config(
        Path::new("dnf.conf"),
        "[main]\nbest=true\nexcludepkgs=a b\n",
    )
    .unwrap();
    let profile = parse_repo_profile(Path::new("fedora.repo"), "[fedora]\nbaseurl=https://example.test\nexcludepkgs=c\ngpgkey=/etc/dnfast/keys/fedora/a.gpg\ndnfast_allowed_fingerprints=0123456789ABCDEF0123456789ABCDEF01234567\n", &main).unwrap();
    // When ordered CLI overrides reset then append.
    let result = apply_setopts(
        profile,
        &[
            "main.excludepkgs=".into(),
            "repo.fedora.excludepkgs=z".into(),
        ],
    )
    .unwrap();
    // Then scalar precedence and list semantics are deterministic.
    assert!(result.main.best);
    assert_eq!(result.main.excludepkgs, Vec::<String>::new());
    assert_eq!(result.repositories[0].excludepkgs, ["a", "b", "c", "z"]);
}

#[test]
fn stock_fedora_rpm_repository_type_is_accepted_without_adding_a_source() {
    // Given a stock Fedora repository declaration from Fedora 44.
    let input = "[fedora]\nname=Fedora $releasever - $basearch\ntype=rpm\nmetalink=https://mirrors.fedoraproject.org/metalink?repo=fedora-$releasever&arch=$basearch\nenabled=true\n";
    // When the strict mutation parser reads it.
    let profile =
        parse_repo_profile(Path::new("fedora.repo"), input, &MainConfig::default()).unwrap();
    // Then rpm is accepted and the configured metalink remains the sole source authority.
    let repository = &profile.repositories[0];
    assert!(repository.baseurl.is_empty());
    assert_eq!(
        repository.metalink.as_deref(),
        Some("https://mirrors.fedoraproject.org/metalink?repo=fedora-$releasever&arch=$basearch")
    );
    assert!(repository.mirrorlist.is_none());
}

#[test]
fn stock_fedora_countme_is_accepted_as_inert_metadata() {
    // Given Fedora 44's stock countme declaration and a fixed metalink authority.
    let input = "[fedora]\nmetalink=https://mirrors.fedoraproject.org/metalink?repo=fedora-44&arch=aarch64\ncountme=1\n";
    // When the strict mutation parser reads the repository.
    let profile =
        parse_repo_profile(Path::new("fedora.repo"), input, &MainConfig::default()).unwrap();
    // Then countme is accepted without adding, rewriting, or selecting a source.
    let repository = &profile.repositories[0];
    assert!(repository.baseurl.is_empty());
    assert_eq!(
        repository.metalink.as_deref(),
        Some("https://mirrors.fedoraproject.org/metalink?repo=fedora-44&arch=aarch64")
    );
    assert!(repository.mirrorlist.is_none());
}

#[test]
fn countme_only_accepts_stock_binary_values_before_network() {
    // Given the alternate stock-disabled value and invalid authority-shaped values.
    let disabled = "[fedora]\nbaseurl=https://example.test/fedora\ncountme=0\n";
    let disabled_profile =
        parse_repo_profile(Path::new("fedora.repo"), disabled, &MainConfig::default()).unwrap();
    assert_eq!(
        disabled_profile.repositories[0].baseurl,
        ["https://example.test/fedora"]
    );
    for value in [
        "2",
        "true",
        "false",
        "yes",
        "https://untrusted.example.invalid",
        "1\\0authority",
    ] {
        let input = format!("[fedora]\nbaseurl=https://example.test/fedora\ncountme={value}\n");
        let mut network_calls = 0;
        // When the parse-before-network boundary reads the invalid setting.
        let result = parse_before_network(
            Path::new("fedora.repo"),
            &input,
            &MainConfig::default(),
            |_| network_calls += 1,
        );
        // Then no telemetry URL or other network authority is reached.
        assert!(result.is_err(), "must reject {value:?}");
        assert_eq!(network_calls, 0, "must not reach the network for {value:?}");
    }
}

#[test]
fn countme_setopt_is_strict_and_inert() {
    // Given a repository with a configured baseurl.
    let profile = parse_repo_profile(
        Path::new("fedora.repo"),
        "[fedora]\nbaseurl=https://example.test/fedora\n",
        &MainConfig::default(),
    )
    .unwrap();
    // When the supported stock value is applied through the CLI setopt boundary.
    let changed = apply_setopts(profile.clone(), &["repo.fedora.countme=1".to_owned()]).unwrap();
    // Then it does not mutate the stored planning/source configuration.
    assert_eq!(changed, profile);
    // And non-stock values remain rejected at that same boundary.
    let error = apply_setopts(
        profile,
        &["repo.fedora.countme=https://untrusted.example.invalid".to_owned()],
    )
    .unwrap_err();
    assert_eq!(error.to_string(), "<command-line>:1: invalid countme");
}

#[test]
fn stock_fedora_metadata_expire_duration_units_are_converted_to_seconds() {
    // Given the Fedora 44 repository durations used by the fedora and updates repos.
    let fedora = "[fedora]\ntype=rpm\nmetalink=https://mirrors.fedoraproject.org/metalink?repo=fedora-44&arch=aarch64\nmetadata_expire=7d\n";
    let updates = "[updates]\ntype=rpm\nmetalink=https://mirrors.fedoraproject.org/metalink?repo=updates-released-f44&arch=aarch64\nmetadata_expire=6h\n";
    let rawhide = "[rawhide]\ntype=rpm\nmetalink=https://mirrors.fedoraproject.org/metalink?repo=rawhide&arch=aarch64\nmetadata_expire=14d\n";
    // When the strict mutation parser reads the stock duration syntax.
    let fedora_profile =
        parse_repo_profile(Path::new("fedora.repo"), fedora, &MainConfig::default()).unwrap();
    let updates_profile = parse_repo_profile(
        Path::new("fedora-updates.repo"),
        updates,
        &MainConfig::default(),
    )
    .unwrap();
    let rawhide_profile = parse_repo_profile(
        Path::new("fedora-rawhide.repo"),
        rawhide,
        &MainConfig::default(),
    )
    .unwrap();
    // Then durations are represented as their exact number of seconds.
    assert_eq!(
        fedora_profile.repositories[0].metadata_expire,
        MetadataExpire::AfterSeconds(604_800)
    );
    assert_eq!(
        updates_profile.repositories[0].metadata_expire,
        MetadataExpire::AfterSeconds(21_600)
    );
    assert_eq!(
        rawhide_profile.repositories[0].metadata_expire,
        MetadataExpire::AfterSeconds(1_209_600)
    );
}

#[test]
fn metadata_expire_accepts_libdnf_hex_integers_with_optional_units() {
    // Given OptionSeconds-compatible hexadecimal values, including an uppercase digit and unit.
    let seconds = "[fedora]\nbaseurl=https://example.test/fedora\nmetadata_expire=0xF\n";
    let hours = "[fedora]\nbaseurl=https://example.test/fedora\nmetadata_expire=0xFh\n";
    let uppercase = "[fedora]\nbaseurl=https://example.test/fedora\nmetadata_expire=0XfH\n";
    // When the strict mutation parser reads each value.
    let seconds_profile =
        parse_repo_profile(Path::new("fedora.repo"), seconds, &MainConfig::default()).unwrap();
    let hours_profile =
        parse_repo_profile(Path::new("fedora.repo"), hours, &MainConfig::default()).unwrap();
    let uppercase_profile =
        parse_repo_profile(Path::new("fedora.repo"), uppercase, &MainConfig::default()).unwrap();
    // Then each value has the exact typed seconds value and cannot alter source authority.
    assert_eq!(
        seconds_profile.repositories[0].metadata_expire,
        MetadataExpire::AfterSeconds(15)
    );
    assert_eq!(
        hours_profile.repositories[0].metadata_expire,
        MetadataExpire::AfterSeconds(54_000)
    );
    assert_eq!(
        uppercase_profile.repositories[0].metadata_expire,
        MetadataExpire::AfterSeconds(54_000)
    );
}

#[test]
fn metadata_expire_uses_the_same_duration_parser_for_cli_overrides() {
    // Given an enabled repository with the compiled metadata-expiry default.
    let profile = parse_repo_profile(
        Path::new("fedora.repo"),
        "[fedora]\nbaseurl=https://example.test/fedora\n",
        &MainConfig::default(),
    )
    .unwrap();
    // When DNF-compatible duration syntax reaches the ordered setopt boundary.
    let profile = apply_setopts(profile, &["repo.fedora.metadata_expire=1.5h".to_owned()]).unwrap();
    // Then the override preserves its exact integer-second value.
    assert_eq!(
        profile.repositories[0].metadata_expire,
        MetadataExpire::AfterSeconds(5_400)
    );
}

#[test]
fn metadata_expire_uses_the_same_hex_duration_parser_for_cli_overrides() {
    // Given an enabled repository with the compiled metadata-expiry default.
    let profile = parse_repo_profile(
        Path::new("fedora.repo"),
        "[fedora]\nbaseurl=https://example.test/fedora\n",
        &MainConfig::default(),
    )
    .unwrap();
    // When a hexadecimal duration reaches the ordered setopt boundary.
    let profile = apply_setopts(profile, &["repo.fedora.metadata_expire=0xFh".to_owned()]).unwrap();
    // Then its exact integer-second value is preserved.
    assert_eq!(
        profile.repositories[0].metadata_expire,
        MetadataExpire::AfterSeconds(54_000)
    );
}

#[test]
fn metadata_expire_preserves_decimal_fractional_second_semantics() {
    // Given decimal durations whose sub-second component needs integer-second flooring.
    let input = "[fedora]\nbaseurl=https://example.test/fedora\nmetadata_expire=0.5\n";
    // When the strict mutation parser reads the repository and a unit-bearing override.
    let profile =
        parse_repo_profile(Path::new("fedora.repo"), input, &MainConfig::default()).unwrap();
    assert_eq!(
        profile.repositories[0].metadata_expire,
        MetadataExpire::AfterSeconds(0)
    );
    let profile = apply_setopts(profile, &["repo.fedora.metadata_expire=0.5h".to_owned()]).unwrap();
    // Then the unqualified sub-second duration floors while the hour conversion remains exact.
    assert_eq!(
        profile.repositories[0].metadata_expire,
        MetadataExpire::AfterSeconds(1_800)
    );
}

#[test]
fn metadata_expire_rejects_non_duration_and_overflow_before_network() {
    // Given malformed, authority-shaped, control-byte, and overflowing duration values.
    for value in [
        "1w",
        "1h1m",
        "https://untrusted.example.invalid",
        "18446744073709551615d",
        "6h\0authority",
        "1e3",
        "0x",
        "0xG",
        "0xF.1",
        "0x1p2",
        "0xFh1",
        "0xFh://untrusted.example.invalid",
        "0x10000000000000000",
        "0x1000000000000000h",
    ] {
        let input =
            format!("[fedora]\nbaseurl=https://example.test/fedora\nmetadata_expire={value}\n");
        let mut network_calls = 0;
        // When the mutation profile is parsed at the network boundary.
        let result = parse_before_network(
            Path::new("fedora.repo"),
            &input,
            &MainConfig::default(),
            |_| network_calls += 1,
        );
        // Then the input is rejected without granting network authority.
        assert!(result.is_err(), "must reject {value:?}");
        assert_eq!(network_calls, 0, "must not reach the network for {value:?}");
    }
}

#[test]
fn metadata_expire_distinguishes_malformed_hex_from_hex_overflow() {
    // Given one syntactically malformed hexadecimal value and one overflowing hexadecimal value.
    let malformed = "[fedora]\nbaseurl=https://example.test/fedora\nmetadata_expire=0x\n";
    let overflow =
        "[fedora]\nbaseurl=https://example.test/fedora\nmetadata_expire=0x10000000000000000\n";
    // When the strict mutation parser reads each value.
    let malformed_error =
        parse_repo_profile(Path::new("fedora.repo"), malformed, &MainConfig::default())
            .unwrap_err();
    let overflow_error =
        parse_repo_profile(Path::new("fedora.repo"), overflow, &MainConfig::default()).unwrap_err();
    // Then malformed syntax and arithmetic overflow keep distinct diagnostics.
    assert_eq!(
        malformed_error.to_string(),
        "fedora.repo:3: invalid metadata_expire"
    );
    assert_eq!(
        overflow_error.to_string(),
        "fedora.repo:3: metadata_expire exceeds u64 seconds"
    );
}

#[test]
fn metadata_expire_models_dnf_never_without_colliding_with_seconds() {
    // Given the two DNF spellings for metadata that never expires.
    for value in ["-1", "never"] {
        let input =
            format!("[fedora]\nbaseurl=https://example.test/fedora\nmetadata_expire={value}\n");
        // When the strict mutation parser reads the repository.
        let profile =
            parse_repo_profile(Path::new("fedora.repo"), &input, &MainConfig::default()).unwrap();
        // Then the no-expiry state is typed rather than encoded as a numeric sentinel.
        assert_eq!(
            profile.repositories[0].metadata_expire,
            MetadataExpire::Never
        );
    }
}

#[test]
fn documented_rpm_md_type_aliases_are_accepted_without_changing_sources() {
    // Given each locally documented DNF rpm-md type alias and a fixed source.
    for alias in ["rpm", "rpm-md", "repomd", "rpmmd", "yum", "YUM"] {
        let input = format!("[fedora]\ntype={alias}\nbaseurl=https://example.test/fedora\n");
        // When the strict mutation parser reads it.
        let profile =
            parse_repo_profile(Path::new("fedora.repo"), &input, &MainConfig::default()).unwrap();
        // Then the alias is inert metadata-format syntax, not a source override.
        assert_eq!(
            profile.repositories[0].baseurl,
            ["https://example.test/fedora"]
        );
        assert!(profile.repositories[0].metalink.is_none());
        assert!(profile.repositories[0].mirrorlist.is_none());
    }
}

#[test]
fn repository_type_rejects_non_rpm_md_values_without_accepting_new_sources() {
    // Given unsupported repository metadata types and no source declaration.
    for value in ["deb", "RPM", "rpm-MD", "Yum"] {
        let input = format!("[foreign]\ntype={value}\n");
        // When the strict mutation parser reads it.
        let error = parse_repo_profile(Path::new("foreign.repo"), &input, &MainConfig::default())
            .unwrap_err();
        // Then the typed configuration boundary rejects each non-documented spelling.
        assert_eq!(
            error.to_string(),
            "foreign.repo:2: unsupported repository type"
        );
    }
}

#[test]
fn repository_type_cannot_grant_url_authority() {
    // Given a type value shaped like an attacker-controlled URL.
    let input = "[foreign]\ntype=https://untrusted.example.invalid/repository\n";
    let mut network_calls = 0;
    // When the parse-before-network boundary reads it.
    let error = parse_before_network(
        Path::new("foreign.repo"),
        input,
        &MainConfig::default(),
        |_| network_calls += 1,
    )
    .unwrap_err();
    // Then the metadata-type boundary rejects it before a network source can receive authority.
    assert_eq!(
        error.to_string(),
        "foreign.repo:2: unsupported repository type"
    );
    assert_eq!(network_calls, 0);
}

#[test]
fn forbidden_and_unknown_settings_fail_closed_without_leaking_values() {
    // Given unsafe and unknown settings.
    for input in [
        "[main]\npluginconfpath=/secret/token\n",
        "[main]\nunknown=value\n",
    ] {
        // When parsed, then mutation config rejects them.
        let error = parse_main_config(Path::new("dnf.conf"), input)
            .unwrap_err()
            .to_string();
        assert!(error.contains("unsupported mutation key"));
        assert!(!error.contains("/secret/token"));
    }
    let main = MainConfig::default();
    for line in ["sslverify=false", "proxy_username=alice"] {
        let input = format!("[fedora]\nbaseurl=https://example.test\n{line}\n");
        let error = parse_repo_profile(Path::new("fedora.repo"), &input, &main)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("rejected mutation setting")
                || error.contains("unsupported mutation key")
        );
        assert!(!error.contains("alice"));
    }
}

#[test]
fn duplicate_keys_ids_and_numeric_boundaries_are_enforced() {
    // Given duplicate and out-of-range values, when parsed, then they fail.
    assert!(parse_main_config(Path::new("x"), "[main]\nbest=true\nbest=false\n").is_err());
    assert!(parse_main_config(Path::new("x"), "[main]\ninstallonly_limit=1\n").is_err());
    assert!(parse_main_config(Path::new("x"), "[main]\ninstallonly_limit=2\n").is_ok());
    let main = MainConfig::default();
    assert!(parse_repo_profile(Path::new("x"), "[a]\nbaseurl=x\n[a]\nbaseurl=y\n", &main).is_err());
    assert!(parse_repo_profile(Path::new("x"), "[a]\nbaseurl=x\npriority=65536\n", &main).is_err());
    assert!(parse_repo_profile(Path::new("x"), "[a]\nbaseurl=x\npriority=65535\n", &main).is_ok());
}

#[test]
fn parser_resource_limits_reject_boundary_plus_one() {
    // Given a maximum line, when parsed, then it succeeds.
    let value = "x".repeat(65_536 - "name=".len());
    let input = format!("[a]\nbaseurl=x\nname={value}\n");
    assert!(parse_repo_profile(Path::new("x"), &input, &MainConfig::default()).is_ok());
    // Given one byte beyond maximum, then it fails.
    let input = format!("[a]\nbaseurl=x\nname={value}x\n");
    assert!(parse_repo_profile(Path::new("x"), &input, &MainConfig::default()).is_err());
}

#[test]
fn setopt_supports_every_frozen_main_key_and_repo_trust_reset() {
    // Given a minimal repository and every main key override.
    let profile = parse_repo_profile(Path::new("x"), "[a]\nbaseurl=x\ngpgkey=one\ndnfast_allowed_fingerprints=0123456789ABCDEF0123456789ABCDEF01234567\n", &MainConfig::default()).unwrap();
    let options = [
        "main.reposdir=",
        "main.varsdir=/safe",
        "main.install_weak_deps=false",
        "main.best=true",
        "main.excludepkgs=x",
        "main.includepkgs=y",
        "main.protected_packages=",
        "main.installonlypkgs=custom",
        "main.installonly_limit=0",
        "repo.a.gpgkey=",
        "repo.a.dnfast_allowed_fingerprints=",
    ]
    .map(str::to_owned);
    // When the ordered overrides are applied.
    let result = apply_setopts(profile, &options).unwrap();
    // Then all main keys and trust-list clears use the same precedence rules.
    assert!(result.main.reposdir.is_empty());
    assert_eq!(
        result.main.varsdir,
        [
            std::path::PathBuf::from("/etc/dnf/vars"),
            "/etc/yum/vars".into(),
            "/safe".into()
        ]
    );
    assert!(!result.main.install_weak_deps);
    assert!(result.main.best);
    assert_eq!(result.main.installonly_limit, 0);
    assert!(result.repositories[0].gpgkey.is_empty());
    assert!(result.repositories[0].allowed_fingerprints.is_empty());
}

#[test]
fn repo_trust_defaults_are_explicit_and_credentials_fail_before_network() {
    // Given a valid repository, when parsed, then trust defaults are explicit.
    let result =
        parse_repo_profile(Path::new("x"), "[a]\nbaseurl=x\n", &MainConfig::default()).unwrap();
    let repo = &result.repositories[0];
    assert!(repo.sslverify && repo.gpgcheck && repo.pkg_gpgcheck && !repo.repo_gpgcheck);
    assert!(repo.enabled);
    assert_eq!(
        (repo.priority, repo.cost, repo.metadata_expire),
        (99, 1000, MetadataExpire::AfterSeconds(172_800))
    );
    assert!(!repo.skip_if_unavailable);
    assert!(
        repo.name.is_none()
            && repo.metalink.is_none()
            && repo.mirrorlist.is_none()
            && repo.proxy.is_none()
    );
    assert_eq!(repo.baseurl, ["x"]);
    assert!(repo.excludepkgs.is_empty() && repo.includepkgs.is_empty());
    assert!(repo.gpgkey.is_empty() && repo.allowed_fingerprints.is_empty());
    let source_empty = parse_repo_profile(
        Path::new("x"),
        "[a]\nenabled=false\n",
        &MainConfig::default(),
    )
    .unwrap();
    let source_empty = &source_empty.repositories[0];
    assert!(
        source_empty.baseurl.is_empty()
            && source_empty.metalink.is_none()
            && source_empty.mirrorlist.is_none()
    );
    // Given credential-bearing and disabled-check settings, when parsed before networking, then no call occurs.
    for setting in [
        "proxy=alice:secret@host",
        "proxy=https://alice:secret@host",
        "gpgcheck=false",
        "pkg_gpgcheck=false",
        "sslverify=false",
        "module_hotfixes=true",
    ] {
        let input = format!("[a]\nbaseurl=x\n{setting}\n");
        let mut calls = 0;
        assert!(
            parse_before_network(Path::new("x"), &input, &MainConfig::default(), |_| calls +=
                1)
            .is_err()
        );
        assert_eq!(calls, 0);
    }
}

#[test]
fn repomd_openpgp_check_is_explicitly_supported() {
    let profile = parse_repo_profile(
        Path::new("x"),
        "[a]\nbaseurl=x\nrepo_gpgcheck=true\n",
        &MainConfig::default(),
    )
    .unwrap();
    assert!(profile.repositories[0].repo_gpgcheck);
}

#[test]
fn repository_and_numeric_limits_accept_boundary_and_reject_plus_one() {
    // Given numeric boundaries, when parsed, then maximum values are accepted.
    let valid =
        "[a]\nbaseurl=x\ncost=4294967295\nmetadata_expire=18446744073709551615\npriority=65535\n";
    assert!(parse_repo_profile(Path::new("x"), valid, &MainConfig::default()).is_ok());
    // Given boundary plus one, then each value is rejected.
    for setting in [
        "cost=4294967296",
        "metadata_expire=18446744073709551616",
        "priority=65536",
    ] {
        assert!(
            parse_repo_profile(
                Path::new("x"),
                &format!("[a]\nbaseurl=x\n{setting}\n"),
                &MainConfig::default()
            )
            .is_err()
        );
    }
    let repositories = (0..1024)
        .map(|index| format!("[r{index}]\nbaseurl=x\n"))
        .collect::<String>();
    assert!(parse_repo_profile(Path::new("x"), &repositories, &MainConfig::default()).is_ok());
    let plus_one = format!("{repositories}[overflow]\nbaseurl=x\n");
    assert!(parse_repo_profile(Path::new("x"), &plus_one, &MainConfig::default()).is_err());
}

#[test]
fn every_repo_key_parses_defaults_repo_values_and_cli_precedence() {
    // Given every supported repository key, when parsed, then each typed value is observable.
    let input = "[a]\nname=Alpha\ntype=rpm-md\nenabled=true\nbaseurl=https://one\nmetalink=https://meta\nmirrorlist=https://mirror\npriority=7\ncost=8\nskip_if_unavailable=true\nmetadata_expire=9\nsslverify=true\nproxy=http://proxy\nexcludepkgs=repo-exclude\nincludepkgs=repo-include\ngpgcheck=true\npkg_gpgcheck=true\nrepo_gpgcheck=false\ngpgkey=\ndnfast_allowed_fingerprints=\n";
    let main = parse_main_config(
        Path::new("main"),
        "[main]\nexcludepkgs=main-exclude\nincludepkgs=main-include\n",
    )
    .unwrap();
    let profile = parse_repo_profile(Path::new("repo"), input, &main).unwrap();
    let repo = &profile.repositories[0];
    assert_eq!(repo.name.as_deref(), Some("Alpha"));
    assert!(
        repo.enabled
            && repo.skip_if_unavailable
            && repo.sslverify
            && repo.gpgcheck
            && repo.pkg_gpgcheck
            && !repo.repo_gpgcheck
    );
    assert_eq!(
        (repo.priority, repo.cost, repo.metadata_expire),
        (7, 8, MetadataExpire::AfterSeconds(9))
    );
    assert_eq!(repo.excludepkgs, ["main-exclude", "repo-exclude"]);
    assert_eq!(repo.includepkgs, ["main-include", "repo-include"]);
    // When repeated CLI scalar and list overrides are applied, then last scalar and reset order wins.
    let options = [
        "repo.a.name=CLI",
        "repo.a.type=rpm-md",
        "repo.a.enabled=false",
        "repo.a.baseurl=",
        "repo.a.metalink=",
        "repo.a.mirrorlist=",
        "repo.a.priority=10",
        "repo.a.cost=11",
        "repo.a.skip_if_unavailable=false",
        "repo.a.metadata_expire=12",
        "repo.a.sslverify=true",
        "repo.a.proxy=_none_",
        "repo.a.excludepkgs=",
        "repo.a.excludepkgs=cli",
        "repo.a.includepkgs=",
        "repo.a.gpgcheck=true",
        "repo.a.pkg_gpgcheck=true",
        "repo.a.repo_gpgcheck=false",
        "repo.a.gpgkey=",
        "repo.a.dnfast_allowed_fingerprints=",
    ]
    .map(str::to_owned);
    let changed = apply_setopts(profile, &options).unwrap();
    let repo = &changed.repositories[0];
    assert_eq!(repo.name.as_deref(), Some("CLI"));
    assert!(!repo.enabled && !repo.skip_if_unavailable);
    assert!(
        repo.baseurl.is_empty()
            && repo.metalink.is_none()
            && repo.mirrorlist.is_none()
            && repo.proxy.is_none()
    );
    assert_eq!(
        (repo.priority, repo.cost, repo.metadata_expire),
        (10, 11, MetadataExpire::AfterSeconds(12))
    );
    assert_eq!(repo.excludepkgs, ["cli"]);
    assert!(
        repo.includepkgs.is_empty()
            && repo.gpgkey.is_empty()
            && repo.allowed_fingerprints.is_empty()
    );
}
