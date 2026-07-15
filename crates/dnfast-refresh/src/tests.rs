use std::{collections::HashMap, sync::Mutex};

use dnfast_cache::Cache;
use sha2::{Digest, Sha256};

use crate::{
    RefreshError, Refresher, Source, Transport,
    metalink::parse_metalink,
};

pub(crate) struct FakeTransport {
    responses: Mutex<HashMap<String, Vec<u8>>>,
}

impl FakeTransport {
    pub(crate) fn new(responses: impl IntoIterator<Item = (String, Vec<u8>)>) -> Self {
        Self {
            responses: Mutex::new(responses.into_iter().collect()),
        }
    }
}

impl Transport for FakeTransport {
    fn get(&self, url: &str, maximum_bytes: u64) -> Result<Vec<u8>, RefreshError> {
        let bytes = self
            .responses
            .lock()
            .unwrap()
            .get(url)
            .cloned()
            .ok_or_else(|| RefreshError::Transport(format!("missing fake response: {url}")))?;
        if bytes.len() as u64 > maximum_bytes {
            return Err(RefreshError::Transport("response exceeds limit".into()));
        }
        Ok(bytes)
    }
}

pub(crate) fn metadata_fixture() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let package_id = "a".repeat(64);
    let primary = format!(r#"<metadata xmlns="http://linux.duke.edu/metadata/common" xmlns:rpm="http://linux.duke.edu/metadata/rpm" packages="1"><package type="rpm"><name>ripgrep</name><arch>aarch64</arch><version epoch="0" ver="14.1.1" rel="1.fc44"/><checksum type="sha256" pkgid="YES">{package_id}</checksum><summary>Fast search</summary><location href="packages/ripgrep.rpm"/><format><rpm:provides/><rpm:requires/></format></package></metadata>"#).into_bytes();
    let compressed = zstd::stream::encode_all(primary.as_slice(), 1).unwrap();
    let filelists = format!(r#"<filelists xmlns="http://linux.duke.edu/metadata/filelists" packages="1"><package pkgid="{package_id}" name="ripgrep" arch="aarch64"><version epoch="0" ver="14.1.1" rel="1.fc44"/><file>/usr/bin/rg</file></package></filelists>"#).into_bytes();
    let compressed_filelists = zstd::stream::encode_all(filelists.as_slice(), 1).unwrap();
    let checksum = hex::encode(Sha256::digest(&compressed));
    let open_checksum = hex::encode(Sha256::digest(&primary));
    let filelists_checksum = hex::encode(Sha256::digest(&compressed_filelists));
    let filelists_open_checksum = hex::encode(Sha256::digest(&filelists));
    let repomd = format!(
        r#"<repomd xmlns="http://linux.duke.edu/metadata/repo"><data type="primary"><checksum type="sha256">{checksum}</checksum><open-checksum type="sha256">{open_checksum}</open-checksum><location href="repodata/primary.xml.zst"/><size>{}</size><open-size>{}</open-size></data><data type="filelists"><checksum type="sha256">{filelists_checksum}</checksum><open-checksum type="sha256">{filelists_open_checksum}</open-checksum><location href="repodata/filelists.xml.zst"/><size>{}</size><open-size>{}</open-size></data></repomd>"#,
        compressed.len(),
        primary.len(),
        compressed_filelists.len(),
        filelists.len()
    )
    .into_bytes();
    (repomd, compressed, compressed_filelists)
}

pub(crate) fn metalink_fixture(repomd: &[u8]) -> Vec<u8> {
    let repomd_hash = hex::encode(Sha256::digest(repomd));
    format!(
        r#"<metalink xmlns="http://www.metalinker.org/"><files><file name="repomd.xml"><verification><hash type="sha256">{repomd_hash}</hash></verification><size>{}</size><resources><url preference="100">https://bad.example/repodata/repomd.xml</url><url preference="90">https://good.example/repodata/repomd.xml</url></resources></file></files></metalink>"#,
        repomd.len()
    )
    .into_bytes()
}

#[test]
fn refreshes_verified_baseurl_into_cache() {
    let directory = tempfile::tempdir().unwrap();
    let cache = Cache::new(directory.path());
    let (repomd, primary, filelists) = metadata_fixture();
    let base = "https://mirror.example/fedora";
    let transport = FakeTransport::new([
        (format!("{base}/repodata/repomd.xml"), repomd),
        (format!("{base}/repodata/primary.xml.zst"), primary),
        (format!("{base}/repodata/filelists.xml.zst"), filelists),
    ]);
    let outcome = Refresher::new(transport, &cache)
        .refresh("fedora", Source::BaseUrl(base.into()))
        .unwrap();
    assert_eq!(outcome.packages, 1);
    assert_eq!(outcome.digest, hex::encode(Sha256::digest(&metadata_fixture().0)));
    assert_eq!(cache.load("fedora").unwrap().packages[0].name, "ripgrep");
}

#[test]
fn metalink_falls_back_after_corrupt_mirror() {
    let directory = tempfile::tempdir().unwrap();
    let cache = Cache::new(directory.path());
    let (repomd, primary, filelists) = metadata_fixture();
    let metalink = metalink_fixture(&repomd);
    let mut corrupt = repomd.clone();
    corrupt[0] ^= 1;
    let transport = FakeTransport::new([
        ("https://meta.example/list".into(), metalink),
        ("https://bad.example/repodata/repomd.xml".into(), corrupt),
        ("https://good.example/repodata/repomd.xml".into(), repomd),
        ("https://good.example/repodata/primary.xml.zst".into(), primary),
        ("https://good.example/repodata/filelists.xml.zst".into(), filelists),
    ]);
    let outcome = Refresher::new(transport, &cache)
        .refresh("fedora", Source::Metalink("https://meta.example/list".into()))
        .unwrap();
    assert_eq!(outcome.packages, 1);
}

#[test]
fn rejects_non_https_source() {
    let directory = tempfile::tempdir().unwrap();
    let cache = Cache::new(directory.path());
    let error = Refresher::new(FakeTransport::new([]), &cache)
        .refresh("fedora", Source::BaseUrl("http://mirror.example/fedora".into()))
        .unwrap_err();
    assert!(matches!(error, RefreshError::Policy(_)));
}

#[test]
fn failed_refresh_preserves_current_snapshot() {
    let directory = tempfile::tempdir().unwrap();
    let cache = Cache::new(directory.path());
    let (old_repomd, old_primary, _) = metadata_fixture();
    let old_digest = cache.publish("fedora", &old_repomd, &old_primary).unwrap().digest;
    let pointer = directory.path().join("repos").join(hex::encode(Sha256::digest(b"fedora"))).join("current");
    let current_before = std::fs::read(&pointer).unwrap();
    let (repomd, _, _) = metadata_fixture();
    let base = "https://mirror.example/fedora";
    let transport = FakeTransport::new([
        (format!("{base}/repodata/repomd.xml"), repomd),
        (format!("{base}/repodata/primary.xml.zst"), b"corrupt".to_vec()),
    ]);
    assert!(Refresher::new(transport, &cache)
        .refresh("fedora", Source::BaseUrl(base.into()))
        .is_err());
    let snapshot = cache.load("fedora").unwrap();
    assert_eq!(snapshot.digest, old_digest);
    assert_eq!(snapshot.packages[0].name, "ripgrep");
    assert_eq!(std::fs::read(pointer).unwrap(), current_before);
}

#[test]
fn metalink_retries_complete_generation_after_primary_failure() {
    let directory = tempfile::tempdir().unwrap();
    let cache = Cache::new(directory.path());
    let (repomd, primary, filelists) = metadata_fixture();
    let transport = FakeTransport::new([
        ("https://meta.example/list".into(), metalink_fixture(&repomd)),
        ("https://bad.example/repodata/repomd.xml".into(), repomd.clone()),
        ("https://bad.example/repodata/primary.xml.zst".into(), b"corrupt".to_vec()),
        ("https://good.example/repodata/repomd.xml".into(), repomd),
        ("https://good.example/repodata/primary.xml.zst".into(), primary),
        ("https://good.example/repodata/filelists.xml.zst".into(), filelists),
    ]);
    let outcome = Refresher::new(transport, &cache)
        .refresh("fedora", Source::Metalink("https://meta.example/list".into()))
        .unwrap();
    assert_eq!(outcome.packages, 1);
}

#[test]
fn mirrorlist_preserves_document_order_and_publishes_complete_metadata() {
    let directory = tempfile::tempdir().unwrap();
    let cache = Cache::new(directory.path());
    let (repomd, primary, filelists) = metadata_fixture();
    let transport = FakeTransport::new([
        ("https://list.example/mirrors".into(), b"# mirrors\nhttps://mirror.example/fedora\n".to_vec()),
        ("https://mirror.example/fedora/repodata/repomd.xml".into(), repomd),
        ("https://mirror.example/fedora/repodata/primary.xml.zst".into(), primary),
        ("https://mirror.example/fedora/repodata/filelists.xml.zst".into(), filelists),
    ]);

    let outcome = Refresher::new(transport, &cache)
        .refresh("fedora", Source::Mirrorlist("https://list.example/mirrors".into()))
        .unwrap();

    assert_eq!(outcome.packages, 1);
    let snapshot = cache.open_by_digest(&outcome.digest).unwrap();
    assert_eq!(snapshot.filelists.len(), 1);
    assert_eq!(snapshot.source_origin.as_ref().map(dnfast_cache::SelectedOrigin::repomd_url), Some("https://mirror.example/fedora/repodata/repomd.xml"));
}

#[test]
fn source_origin_rejects_query_and_fragment() {
    let directory = tempfile::tempdir().unwrap();
    let cache = Cache::new(directory.path());
    for source in [
        "https://mirror.example/fedora?token=secret",
        "https://mirror.example/fedora#fragment",
    ] {
        assert!(matches!(
            Refresher::new(FakeTransport::new([]), &cache).refresh("fedora", Source::BaseUrl(source.into())),
            Err(RefreshError::Policy(_))
        ));
    }
}

#[test]
fn mirrorlist_accepts_exact_entry_cap_and_rejects_plus_one() {
    let exact = (0..32).map(|index| format!("https://m{index}.example/repo\n")).collect::<String>();
    assert_eq!(super::mirrorlist::parse(exact.as_bytes()).unwrap().len(), 32);
    let plus_one = format!("{exact}https://overflow.example/repo\n");
    assert!(super::mirrorlist::parse(plus_one.as_bytes()).is_err());
}

#[test]
fn metalink_accepts_exact_resource_cap_and_rejects_plus_one() {
    let resources = |count| (0..count).map(|index| format!("<url>https://m{index}.example/repodata/repomd.xml</url>")).collect::<String>();
    let document = |count| format!("<metalink xmlns=\"http://www.metalinker.org/\"><file name=\"repomd.xml\"><hash type=\"sha256\">{}</hash><size>1</size>{}</file></metalink>", "a".repeat(64), resources(count));
    assert_eq!(parse_metalink(document(32).as_bytes()).unwrap().resources.len(), 32);
    assert!(parse_metalink(document(33).as_bytes()).is_err());
}

#[test]
fn mirrorlist_accepts_exact_byte_cap_and_rejects_plus_one() {
    let prefix = b"https://mirror.example/repo\n";
    let mut exact = vec![b'#'; super::metalink::MAX_METALINK_BYTES as usize];
    exact[..prefix.len()].copy_from_slice(prefix);
    assert_eq!(super::mirrorlist::parse(&exact).unwrap().len(), 1);
    exact.push(b'#');
    assert!(super::mirrorlist::parse(&exact).is_err());
}

#[test]
fn wrong_filelists_restarts_generation_and_publishes_once() {
    let directory = tempfile::tempdir().unwrap();
    let cache = Cache::new(directory.path());
    let (repomd, primary, filelists) = metadata_fixture();
    let transport = FakeTransport::new([
        ("https://meta.example/list".into(), metalink_fixture(&repomd)),
        ("https://bad.example/repodata/repomd.xml".into(), repomd.clone()),
        ("https://bad.example/repodata/primary.xml.zst".into(), primary.clone()),
        ("https://bad.example/repodata/filelists.xml.zst".into(), b"wrong-generation".to_vec()),
        ("https://good.example/repodata/repomd.xml".into(), repomd),
        ("https://good.example/repodata/primary.xml.zst".into(), primary),
        ("https://good.example/repodata/filelists.xml.zst".into(), filelists),
    ]);
    let outcome = Refresher::new(transport, &cache)
        .refresh("fedora", Source::Metalink("https://meta.example/list".into())).unwrap();
    let objects = std::fs::read_dir(directory.path().join("objects/sha256")).unwrap().count();
    assert_eq!(objects, 1);
    assert_eq!(cache.load("fedora").unwrap().digest, outcome.digest);
}

#[test]
fn missing_filelists_preserves_pointer_and_publishes_nothing() {
    let directory = tempfile::tempdir().unwrap();
    let cache = Cache::new(directory.path());
    let (repomd, primary, _) = metadata_fixture();
    let base = "https://missing.example/fedora";
    let transport = FakeTransport::new([
        (format!("{base}/repodata/repomd.xml"), repomd),
        (format!("{base}/repodata/primary.xml.zst"), primary),
    ]);
    let result = Refresher::new(transport, &cache).refresh("fedora", Source::BaseUrl(base.into()));
    assert!(result.is_err());
    assert!(!directory.path().join("objects/sha256").exists());
}


#[test]
fn rejects_metalink_namespace_declaration_not_bound_to_root() {
    let xml = br#"<evil:metalink xmlns:evil="urn:evil" xmlns:unused="http://www.metalinker.org/"><file name="repomd.xml"/></evil:metalink>"#;
    assert!(matches!(parse_metalink(xml), Err(RefreshError::Metalink(_))));
}
