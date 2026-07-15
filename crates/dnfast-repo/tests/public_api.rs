use std::{
    error::Error,
    fs, io,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use dnfast_repo::{
    RepoError, Repository, SourceKind, Variables, load_refresh_policy, load_repository_dirs,
    parse_repository_file,
};

struct TemporaryDirectory(PathBuf);

impl TemporaryDirectory {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("dnfast-repo-{}-{nonce}", std::process::id()));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}

#[test]
fn refresh_policy_rejects_insecure_transport_settings_before_use() {
    let directory = TemporaryDirectory::new();
    let path = directory.0.join("policy.repo");
    fs::write(
        &path,
        "[fedora]\nbaseurl=https://example\nsslverify=false\n",
    )
    .unwrap();
    let repository = parse_repository_file(&path, &fs::read_to_string(&path).unwrap())
        .unwrap()
        .remove(0);
    assert!(load_refresh_policy(&repository).is_err());
    fs::write(
        &path,
        "[fedora]\nbaseurl=https://example\nproxy=http://proxy\n",
    )
    .unwrap();
    assert!(load_refresh_policy(&repository).is_err());
}

#[test]
fn refresh_policy_accepts_skip_only_with_mandatory_tls() {
    let directory = TemporaryDirectory::new();
    let path = directory.0.join("policy.repo");
    fs::write(&path, "[fedora]\nbaseurl=https://example\nsslverify=true\nskip_if_unavailable=true\nproxy=_none_\n").unwrap();
    let repository = parse_repository_file(&path, &fs::read_to_string(&path).unwrap())
        .unwrap()
        .remove(0);
    assert!(
        load_refresh_policy(&repository)
            .unwrap()
            .skip_if_unavailable
    );
}

impl Drop for TemporaryDirectory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn public_model_reports_sources_in_priority_order() {
    let repository = Repository {
        id: "fedora".into(),
        enabled: true,
        baseurls: vec!["https://base.example".into()],
        metalink: Some("https://meta.example".into()),
        mirrorlist: Some("https://mirror.example".into()),
        origin: PathBuf::from("fedora.repo"),
    };

    let sources = repository.sources().collect::<Vec<_>>();

    assert_eq!(sources[0], (SourceKind::BaseUrl, "https://base.example"));
    assert_eq!(sources[1].0.as_str(), "metalink");
    assert_eq!(sources[2].0.as_str(), "mirrorlist");
    assert_eq!(repository.selected_source(), sources.first().copied());
}

#[test]
fn parser_preserves_sources_booleans_and_ignored_keys() {
    let repositories = parse_repository_file(
        Path::new("fedora.repo"),
        "[fedora]\nenabled=YES\nhidden=value\nbaseurl=https://one.example https://two.example\n\n[testing]\nenabled=Off\nmetalink=https://meta.example\n",
    )
    .unwrap();

    assert_eq!(repositories.len(), 2);
    assert_eq!(repositories[0].baseurls.len(), 2);
    assert!(!repositories[1].enabled);
    assert_eq!(
        repositories[1].selected_source().unwrap().0,
        SourceKind::Metalink
    );
}

#[test]
fn parser_reports_each_malformed_input_class() {
    let cases = [
        ("key=value", "broken.repo:1: key outside repository section"),
        ("[broken", "broken.repo:1: malformed repository section"),
        ("[]", "broken.repo:1: repository id cannot be empty"),
        ("[x]\nnot-a-pair", "broken.repo:2: expected key=value"),
        (
            "[x]\nbaseurl=https://example\nenabled=perhaps",
            "broken.repo:3: invalid boolean for enabled: perhaps",
        ),
        (
            "[x]\nenabled=1",
            "broken.repo:1: enabled repository has no source",
        ),
        (
            "[x]\nbaseurl=https://one\n[x]\nbaseurl=https://two",
            "broken.repo:3: duplicate repository id: x",
        ),
    ];

    for (input, expected) in cases {
        let error = parse_repository_file(Path::new("broken.repo"), input).unwrap_err();
        assert_eq!(error.to_string(), expected);
    }
}

#[test]
fn variables_preserve_literal_and_malformed_behavior() {
    let variables = Variables::from_pairs([
        ("releasever".into(), "44".into()),
        ("basearch".into(), "aarch64".into()),
    ]);

    assert_eq!(
        variables
            .expand("https://example/$releasever/${basearch}/$$cache/$9/$")
            .unwrap(),
        "https://example/44/aarch64/$cache/$9/$"
    );
    assert!(matches!(
        variables.expand("${}"),
        Err(RepoError::MalformedVariable(value)) if value == "${}"
    ));
    assert!(matches!(
        variables.expand("${unterminated"),
        Err(RepoError::MalformedVariable(value)) if value == "${unterminated"
    ));
    assert!(matches!(
        variables.expand("$hidden"),
        Err(RepoError::UnresolvedVariable(value)) if value == "hidden"
    ));
}

#[test]
fn public_error_variants_preserve_display_and_sources() {
    let parse = RepoError::Parse {
        path: "x.repo".into(),
        line: 7,
        message: "bad".into(),
    };
    let io = RepoError::Io {
        path: "x.repo".into(),
        source: io::Error::new(io::ErrorKind::PermissionDenied, "denied"),
    };
    let utf8 = RepoError::InvalidUtf8 {
        path: "x.repo".into(),
    };

    assert_eq!(parse.to_string(), "x.repo:7: bad");
    assert!(parse.source().is_none());
    assert_eq!(io.to_string(), "x.repo: denied");
    assert!(io.source().is_some());
    assert_eq!(
        utf8.to_string(),
        "x.repo: repository file is not valid UTF-8"
    );
}

#[test]
fn loader_sorts_files_and_rejects_duplicate_ids_across_files() {
    let directory = TemporaryDirectory::new();
    fs::write(directory.0.join("b.repo"), "[b]\nbaseurl=https://b\n").unwrap();
    fs::write(directory.0.join("a.repo"), "[a]\nbaseurl=https://a\n").unwrap();

    let repositories = load_repository_dirs(std::slice::from_ref(&directory.0)).unwrap();
    assert_eq!(
        repositories
            .iter()
            .map(|repo| repo.id.as_str())
            .collect::<Vec<_>>(),
        ["a", "b"]
    );

    fs::write(directory.0.join("b.repo"), "[a]\nbaseurl=https://b\n").unwrap();
    let error = load_repository_dirs(std::slice::from_ref(&directory.0)).unwrap_err();
    assert!(error.to_string().contains("duplicate repository id a"));
}

#[test]
fn loader_reports_invalid_utf8_and_ignores_missing_directories() {
    let directory = TemporaryDirectory::new();
    fs::write(directory.0.join("bad.repo"), [0xff]).unwrap();

    let error = load_repository_dirs(std::slice::from_ref(&directory.0)).unwrap_err();
    assert!(matches!(error, RepoError::InvalidUtf8 { .. }));

    let missing = directory.0.join("missing");
    assert!(load_repository_dirs(&[missing]).unwrap().is_empty());
}

#[cfg(unix)]
#[test]
fn loader_ignores_symlinked_files_roots_and_ancestors() {
    use std::os::unix::fs::symlink;

    let parent = TemporaryDirectory::new();
    let real = parent.0.join("real");
    let nested = real.join("nested");
    fs::create_dir_all(&nested).unwrap();
    fs::write(nested.join("real.repo"), "[real]\nbaseurl=https://real\n").unwrap();
    symlink(nested.join("real.repo"), nested.join("linked.repo")).unwrap();

    let direct = load_repository_dirs(std::slice::from_ref(&nested)).unwrap();
    assert_eq!(direct.len(), 1);

    let linked = parent.0.join("linked");
    symlink(&real, &linked).unwrap();
    assert!(
        load_repository_dirs(std::slice::from_ref(&linked))
            .unwrap()
            .is_empty()
    );
    assert!(
        load_repository_dirs(&[linked.join("nested")])
            .unwrap()
            .is_empty()
    );
}
