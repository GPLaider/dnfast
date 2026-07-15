use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use dnfast_repo::{key_bundle_digest, load_mutation_profile_from, parse_main_config};
use sha2::{Digest, Sha256};

struct Fixture(PathBuf);

impl Fixture {
    fn new(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = PathBuf::from(
            std::env::var_os("HOME").expect("HOME must identify the test user's trusted directory"),
        )
        .join(format!("dnfast-t3-{label}-{}-{nonce}", std::process::id()));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        Self(path)
    }

    fn directory(&self, name: &str) -> PathBuf {
        let path = self.0.join(name);
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    fn file(path: &Path, bytes: impl AsRef<[u8]>) {
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o644)).unwrap();
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn explicit_main_list_resets_exclude_stock_repository_and_variable_directories() {
    // Given reset-and-replacement list entries for the public matrix.
    let input = "[main]\nreposdir=\nreposdir=/etc/dnfast-public-repos\nvarsdir=\nvarsdir=/etc/dnfast-public-vars\n";

    // When the trusted main configuration is parsed.
    let main = parse_main_config(Path::new("matrix.conf"), input)
        .expect("list-valued reset followed by replacement must be accepted");

    // Then the selected configuration has no stock source directories.
    assert_eq!(main.reposdir, [PathBuf::from("/etc/dnfast-public-repos")]);
    assert_eq!(main.varsdir, [PathBuf::from("/etc/dnfast-public-vars")]);
    assert!(
        parse_main_config(Path::new("matrix.conf"), "[main]\nbest=true\nbest=false\n").is_err()
    );
}

#[test]
fn loader_reads_sorted_sources_expands_vars_and_rejects_cross_file_duplicates() {
    // Given root-owned main, variable, and bytewise-unsorted repository sources.
    let fixture = Fixture::new("loader");
    let repos = fixture.directory("repos");
    let vars = fixture.directory("vars");
    Fixture::file(&vars.join("releasever"), "44\n");
    Fixture::file(
        &repos.join("b.repo"),
        "[b]\nbaseurl=https://b/$releasever\n",
    );
    Fixture::file(
        &repos.join("a.repo"),
        "[a]\nbaseurl=https://a/$releasever\n",
    );
    let main = fixture.0.join("dnf.conf");
    Fixture::file(
        &main,
        format!(
            "[main]\nreposdir={}\nvarsdir={}\n",
            repos.display(),
            vars.display()
        ),
    );
    // When the mutation source loader runs.
    let profile = load_mutation_profile_from(&main).unwrap();
    // Then file order and variable expansion are observable.
    assert_eq!(
        profile
            .repositories
            .iter()
            .map(|repo| repo.id.as_str())
            .collect::<Vec<_>>(),
        ["a", "b"]
    );
    assert_eq!(profile.repositories[0].baseurl, ["https://a/44"]);
    Fixture::file(&repos.join("b.repo"), "[a]\nbaseurl=x\n");
    assert!(
        load_mutation_profile_from(&main)
            .unwrap_err()
            .to_string()
            .contains("duplicate repository id across files")
    );
}

#[test]
fn loader_rejects_writable_and_symlinked_sources_and_cleans_up() {
    // Given a trusted fixture with an untrusted repository source.
    let fixture = Fixture::new("modes");
    let repos = fixture.directory("repos");
    let vars = fixture.directory("vars");
    let main = fixture.0.join("dnf.conf");
    Fixture::file(
        &main,
        format!(
            "[main]\nreposdir={}\nvarsdir={}\n",
            repos.display(),
            vars.display()
        ),
    );
    let target = repos.join("target");
    Fixture::file(&target, "[x]\nbaseurl=x\n");
    symlink(&target, repos.join("linked.repo")).unwrap();
    // When loaded, then symlinks are ignored and writable main files are rejected.
    assert!(
        load_mutation_profile_from(&main)
            .unwrap()
            .repositories
            .is_empty()
    );
    fs::set_permissions(&main, fs::Permissions::from_mode(0o666)).unwrap();
    assert!(load_mutation_profile_from(&main).is_err());
}

#[test]
fn key_bundle_digest_binds_domain_paths_lengths_contents_and_order() {
    // Given two root-owned key files beneath the exact repository key root.
    let repo = format!("dnfast-test-{}", std::process::id());
    let root = PathBuf::from("/etc/dnfast/keys").join(&repo);
    if fs::create_dir_all(&root).is_err() {
        assert!(key_bundle_digest(&repo, &[]).is_ok());
        return;
    }
    fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
    let first = root.join("a.gpg");
    let second = root.join("b.gpg");
    Fixture::file(&first, b"one");
    Fixture::file(&second, b"two");
    // When the bundle is digested, then the specified byte framing matches exactly and order matters.
    let paths = [first.clone(), second.clone()];
    let bundle = key_bundle_digest(&repo, &paths).unwrap();
    let mut expected = Sha256::new();
    expected.update(b"dnfast-key-bundle-v1");
    for (path, bytes) in [(&first, b"one".as_slice()), (&second, b"two".as_slice())] {
        expected.update((path.to_str().unwrap().len() as u64).to_be_bytes());
        expected.update(path.to_str().unwrap().as_bytes());
        expected.update((bytes.len() as u64).to_be_bytes());
        expected.update(bytes);
    }
    assert_eq!(bundle.digest.as_slice(), expected.finalize().as_slice());
    assert_ne!(
        bundle.digest,
        key_bundle_digest(&repo, &[second, first]).unwrap().digest
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn exact_config_byte_and_line_boundaries_accept_then_reject_plus_one() {
    // Given exactly 4096 lines and exactly one MiB, when parsed, then boundaries pass and plus one fails.
    let mut lines = vec!["#".to_owned(); 4095];
    let fixed = "[main]\n".len() + lines.iter().map(|line| line.len() + 1).sum::<usize>();
    let mut remaining = 1_048_576 - fixed;
    for line in &mut lines {
        let add = remaining.min(255);
        line.push_str(&"x".repeat(add));
        remaining -= add;
    }
    let input = format!("[main]\n{}\n", lines.join("\n"));
    assert_eq!(input.len(), 1_048_576);
    assert!(parse_main_config(Path::new("x"), &input).is_ok());
    assert!(parse_main_config(Path::new("x"), &(input.clone() + "x")).is_err());
    assert!(parse_main_config(Path::new("x"), &(input + "\n")).is_err());
}

#[test]
fn aggregate_config_file_limit_accepts_256_and_rejects_257() {
    // Given one main file and 255 repository files, when loaded, then the exact boundary succeeds.
    let fixture = Fixture::new("file-limit");
    let repos = fixture.directory("repos");
    let vars = fixture.directory("vars");
    let main = fixture.0.join("dnf.conf");
    Fixture::file(
        &main,
        format!(
            "[main]\nreposdir={}\nvarsdir={}\n",
            repos.display(),
            vars.display()
        ),
    );
    for index in 0..255 {
        Fixture::file(
            &repos.join(format!("{index:03}.repo")),
            format!("[r{index}]\nbaseurl=x\n"),
        );
    }
    assert_eq!(
        load_mutation_profile_from(&main)
            .unwrap()
            .repositories
            .len(),
        255
    );
    // Given one additional file, then the aggregate limit rejects it.
    Fixture::file(&repos.join("overflow.repo"), "[overflow]\nbaseurl=x\n");
    assert!(load_mutation_profile_from(&main).is_err());
}
