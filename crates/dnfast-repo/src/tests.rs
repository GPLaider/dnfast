use super::*;
use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

fn temporary_directory() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("dnfast-repo-{}-{nonce}", std::process::id()));
    fs::create_dir(&path).unwrap();
    path
}

#[test]
fn parses_sources_and_case_insensitive_booleans() {
    let repositories = parse_repository_file(
        Path::new("fedora.repo"),
        "[fedora]\nenabled = YES\nbaseurl = https://one.example/repo https://two.example/repo\n\n[testing]\nenabled=Off\nmetalink=https://mirrors.example/metalink\n",
    )
    .unwrap();

    assert_eq!(repositories.len(), 2);
    assert_eq!(repositories[0].id, "fedora");
    assert!(repositories[0].enabled);
    assert_eq!(repositories[0].baseurls.len(), 2);
    assert!(!repositories[1].enabled);
    assert_eq!(repositories[1].selected_source().unwrap().0, SourceKind::Metalink);
}

#[test]
fn rejects_malformed_boolean_with_provenance() {
    let error = parse_repository_file(
        Path::new("broken.repo"),
        "[broken]\nbaseurl=https://example.test/repo\nenabled=perhaps\n",
    )
    .unwrap_err();
    assert_eq!(
        error.to_string(),
        "broken.repo:3: invalid boolean for enabled: perhaps"
    );
}

#[test]
fn enabled_repository_requires_source() {
    let error =
        parse_repository_file(Path::new("empty.repo"), "[empty]\nenabled=1\n").unwrap_err();
    assert_eq!(
        error.to_string(),
        "empty.repo:1: enabled repository has no source"
    );
}

#[test]
fn expands_known_variables_and_literal_dollar() {
    let variables = Variables::from_pairs([
        ("releasever".into(), "44".into()),
        ("basearch".into(), "aarch64".into()),
    ]);
    assert_eq!(
        variables
            .expand("https://example/$releasever/${basearch}/$$cache")
            .unwrap(),
        "https://example/44/aarch64/$cache"
    );
    assert_eq!(
        variables.expand("$unknown").unwrap_err().to_string(),
        "unresolved repository variable: unknown"
    );
}

#[cfg(unix)]
#[test]
fn loader_ignores_symlinks_and_non_repo_files() {
    use std::os::unix::fs::symlink;

    let directory = temporary_directory();
    fs::write(
        directory.join("real.repo"),
        "[real]\nbaseurl=https://example.test/repo\n",
    )
    .unwrap();
    fs::write(
        directory.join("notes.txt"),
        "[notes]\nbaseurl=https://bad.test\n",
    )
    .unwrap();
    symlink(directory.join("real.repo"), directory.join("linked.repo")).unwrap();

    let repositories = load_repository_dirs(std::slice::from_ref(&directory)).unwrap();
    assert_eq!(repositories.len(), 1);
    assert_eq!(repositories[0].id, "real");
    fs::remove_dir_all(directory).unwrap();
}

#[cfg(unix)]
#[test]
fn loader_does_not_follow_symlinked_root_directory() {
    use std::os::unix::fs::symlink;

    let parent = temporary_directory();
    let real = parent.join("real");
    fs::create_dir(&real).unwrap();
    fs::write(
        real.join("linked.repo"),
        "[linked]\nbaseurl=https://example.test/repo\n",
    )
    .unwrap();
    let linked = parent.join("linked");
    symlink(&real, &linked).unwrap();

    let repositories = load_repository_dirs(&[linked]).unwrap();
    fs::remove_dir_all(parent).unwrap();
    assert!(repositories.is_empty());
}

#[cfg(unix)]
#[test]
fn loader_does_not_follow_symlinked_ancestor_directory() {
    use std::os::unix::fs::symlink;

    let parent = temporary_directory();
    let real = parent.join("real");
    let nested = real.join("nested");
    fs::create_dir_all(&nested).unwrap();
    fs::write(
        nested.join("linked.repo"),
        "[linked]\nbaseurl=https://example.test/repo\n",
    )
    .unwrap();
    let linked = parent.join("linked");
    symlink(&real, &linked).unwrap();
    let repositories = load_repository_dirs(&[linked.join("nested")]).unwrap();
    assert!(repositories.is_empty());
    fs::remove_dir_all(parent).unwrap();
}
