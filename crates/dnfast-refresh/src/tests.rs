use std::{
    collections::HashMap,
    sync::{Condvar, Mutex},
    time::Duration,
};

use dnfast_cache::Cache;
use sha2::{Digest, Sha256};

use crate::{MetadataTrust, RefreshError, Refresher, Source, Transport, metalink::parse_metalink};

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

struct ConcurrentMetadataTransport {
    responses: HashMap<String, Vec<u8>>,
    arrived_metadata: Mutex<usize>,
    both_arrived: Condvar,
}

impl Transport for ConcurrentMetadataTransport {
    fn get(&self, url: &str, maximum_bytes: u64) -> Result<Vec<u8>, RefreshError> {
        let metadata = url.ends_with("primary.xml.zst") || url.ends_with("filelists.xml.zst");
        if metadata {
            let mut arrived = self.arrived_metadata.lock().unwrap();
            *arrived += 1;
            if *arrived == 2 {
                self.both_arrived.notify_all();
            } else {
                let (observed, timeout) = self
                    .both_arrived
                    .wait_timeout_while(arrived, Duration::from_secs(5), |count| *count < 2)
                    .unwrap();
                arrived = observed;
                if timeout.timed_out() && *arrived < 2 {
                    return Err(RefreshError::Transport(
                        "primary and filelists were fetched sequentially".into(),
                    ));
                }
            }
        }
        let result = self
            .responses
            .get(url)
            .cloned()
            .ok_or_else(|| RefreshError::Transport(format!("missing fake response: {url}")));
        let bytes = result?;
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
    assert_eq!(
        outcome.digest,
        hex::encode(Sha256::digest(&metadata_fixture().0))
    );
    assert_eq!(cache.load("fedora").unwrap().packages[0].name, "ripgrep");
}

#[test]
fn unchanged_fresh_repomd_reuses_only_a_rehashed_complete_generation() {
    let directory = tempfile::tempdir().unwrap();
    let cache = Cache::new(directory.path());
    let (repomd, primary, filelists) = metadata_fixture();
    let base = "https://reuse.example/fedora";
    Refresher::new(
        FakeTransport::new([
            (format!("{base}/repodata/repomd.xml"), repomd.clone()),
            (format!("{base}/repodata/primary.xml.zst"), primary),
            (format!("{base}/repodata/filelists.xml.zst"), filelists),
        ]),
        &cache,
    )
    .refresh("fedora", Source::BaseUrl(base.into()))
    .expect("initial complete refresh");

    // Only the freshly fetched repomd is available. A second metadata download
    // would fail this transport, so success proves content-addressed reuse.
    let reused = Refresher::new(
        FakeTransport::new([(format!("{base}/repodata/repomd.xml"), repomd.clone())]),
        &cache,
    )
    .refresh("fedora", Source::BaseUrl(base.into()))
    .expect("unchanged verified generation reuse");
    assert_eq!(reused.digest, hex::encode(Sha256::digest(&repomd)));
    assert_eq!(reused.packages, 1);

    // Semantically equivalent but byte-distinct repomd is a new generation and
    // must not use the old cache capability without downloading its records.
    let mut changed = repomd.clone();
    changed.extend_from_slice(b"\n");
    let rejected = Refresher::new(
        FakeTransport::new([(format!("{base}/repodata/repomd.xml"), changed)]),
        &cache,
    )
    .refresh("fedora", Source::BaseUrl(base.into()));
    assert!(rejected.is_err());
    assert_eq!(
        cache
            .open_current_verified_complete_generation("fedora")
            .unwrap()
            .digest(),
        reused.digest
    );
}

#[test]
fn primary_and_filelists_downloads_overlap_without_weakening_validation() {
    let directory = tempfile::tempdir().unwrap();
    let cache = Cache::new(directory.path());
    let (repomd, primary, filelists) = metadata_fixture();
    let base = "https://parallel.example/fedora";
    let transport = ConcurrentMetadataTransport {
        responses: [
            (format!("{base}/repodata/repomd.xml"), repomd),
            (format!("{base}/repodata/primary.xml.zst"), primary),
            (format!("{base}/repodata/filelists.xml.zst"), filelists),
        ]
        .into_iter()
        .collect(),
        arrived_metadata: Mutex::new(0),
        both_arrived: Condvar::new(),
    };
    let outcome = Refresher::new(transport, &cache)
        .refresh("fedora", Source::BaseUrl(base.into()))
        .expect("parallel verified refresh");
    assert_eq!(outcome.packages, 1);
}

#[test]
fn metalink_single_connection_policy_uses_one_mirror_sequentially() {
    let directory = tempfile::tempdir().unwrap();
    let cache = Cache::new(directory.path());
    let (repomd, primary, filelists) = metadata_fixture();
    let repomd_hash = hex::encode(Sha256::digest(&repomd));
    let metalink = format!(
        r#"<metalink xmlns="http://www.metalinker.org/"><files><file name="repomd.xml"><verification><hash type="sha256">{repomd_hash}</hash></verification><size>{}</size><resources maxconnections="1"><url preference="100">https://one.example/repo/repodata/repomd.xml</url><url preference="90">https://two.example/repo/repodata/repomd.xml</url></resources></file></files></metalink>"#,
        repomd.len()
    )
    .into_bytes();
    let transport = FakeTransport::new([
        ("https://meta.example/list".into(), metalink),
        (
            "https://one.example/repo/repodata/repomd.xml".into(),
            repomd,
        ),
        (
            "https://one.example/repo/repodata/primary.xml.zst".into(),
            primary,
        ),
        (
            "https://one.example/repo/repodata/filelists.xml.zst".into(),
            filelists,
        ),
    ]);
    let outcome = Refresher::new(transport, &cache)
        .refresh(
            "fedora",
            Source::Metalink("https://meta.example/list".into()),
        )
        .expect("single-connection mirror is used sequentially");
    assert_eq!(outcome.packages, 1);
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
        (
            "https://good.example/repodata/primary.xml.zst".into(),
            primary,
        ),
        (
            "https://good.example/repodata/filelists.xml.zst".into(),
            filelists,
        ),
    ]);
    let outcome = Refresher::new(transport, &cache)
        .refresh(
            "fedora",
            Source::Metalink("https://meta.example/list".into()),
        )
        .unwrap();
    assert_eq!(outcome.packages, 1);
}

#[test]
fn metalink_accepts_bounded_declared_repomd_alternate() {
    let directory = tempfile::tempdir().unwrap();
    let cache = Cache::new(directory.path());
    let (repomd, primary, filelists) = metadata_fixture();
    let future = b"not-yet-mirrored-repomd";
    let future_hash = hex::encode(Sha256::digest(future));
    let alternate_hash = hex::encode(Sha256::digest(&repomd));
    let metalink = format!(
        r#"<metalink xmlns="http://www.metalinker.org/" xmlns:mm0="http://fedorahosted.org/mirrormanager"><files><file name="repomd.xml"><size>{}</size><verification><hash type="sha256">{future_hash}</hash></verification><mm0:alternates><mm0:alternate><size>{}</size><verification><hash type="sha256">{alternate_hash}</hash></verification></mm0:alternate></mm0:alternates><resources><url preference="100">https://good.example/repodata/repomd.xml</url></resources></file></files></metalink>"#,
        future.len(),
        repomd.len(),
    )
    .into_bytes();
    let transport = FakeTransport::new([
        ("https://meta.example/list".into(), metalink),
        ("https://good.example/repodata/repomd.xml".into(), repomd),
        (
            "https://good.example/repodata/primary.xml.zst".into(),
            primary,
        ),
        (
            "https://good.example/repodata/filelists.xml.zst".into(),
            filelists,
        ),
    ]);
    let outcome = Refresher::new(transport, &cache)
        .refresh(
            "updates",
            Source::Metalink("https://meta.example/list".into()),
        )
        .expect("declared alternate is still checksum and size bound");
    assert_eq!(outcome.packages, 1);
}

#[test]
fn rejects_non_https_source() {
    let directory = tempfile::tempdir().unwrap();
    let cache = Cache::new(directory.path());
    let error = Refresher::new(FakeTransport::new([]), &cache)
        .refresh(
            "fedora",
            Source::BaseUrl("http://mirror.example/fedora".into()),
        )
        .unwrap_err();
    assert!(matches!(error, RefreshError::Policy(_)));
}

#[test]
fn fedora_metalink_endpoint_allows_query_but_mirror_resources_do_not() {
    let directory = tempfile::tempdir().unwrap();
    let cache = Cache::new(directory.path());
    let endpoint = "https://mirrors.fedoraproject.org/metalink?repo=fedora-44&arch=x86_64";
    let error = Refresher::new(
        FakeTransport::new([(endpoint.into(), b"not-a-metalink".to_vec())]),
        &cache,
    )
    .refresh("fedora", Source::Metalink(endpoint.into()))
    .expect_err("the endpoint reaches parsing instead of URL-policy rejection");
    assert!(matches!(error, RefreshError::Metalink(_)));
    assert!(super::url_policy::validate_https("https://mirror.example/repo?token=x").is_err());
}

#[test]
fn origin_only_baseurl_accepts_the_equivalent_optional_root_slash() {
    assert!(super::url_policy::validate_https("https://localhost:18443").is_ok());
    assert!(super::url_policy::validate_https("https://localhost:18443/").is_ok());
    assert!(super::url_policy::validate_https("https://localhost:18443?token=x").is_err());
}

#[test]
fn failed_refresh_preserves_current_snapshot() {
    let directory = tempfile::tempdir().unwrap();
    let cache = Cache::new(directory.path());
    let (old_repomd, old_primary, _) = metadata_fixture();
    let old_digest = cache
        .publish("fedora", &old_repomd, &old_primary)
        .unwrap()
        .digest;
    let pointer = directory
        .path()
        .join("repos")
        .join(hex::encode(Sha256::digest(b"fedora")))
        .join("current");
    let current_before = std::fs::read(&pointer).unwrap();
    let (repomd, _, _) = metadata_fixture();
    let base = "https://mirror.example/fedora";
    let transport = FakeTransport::new([
        (format!("{base}/repodata/repomd.xml"), repomd),
        (
            format!("{base}/repodata/primary.xml.zst"),
            b"corrupt".to_vec(),
        ),
    ]);
    assert!(
        Refresher::new(transport, &cache)
            .refresh("fedora", Source::BaseUrl(base.into()))
            .is_err()
    );
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
        (
            "https://meta.example/list".into(),
            metalink_fixture(&repomd),
        ),
        (
            "https://bad.example/repodata/repomd.xml".into(),
            repomd.clone(),
        ),
        (
            "https://bad.example/repodata/primary.xml.zst".into(),
            b"corrupt".to_vec(),
        ),
        ("https://good.example/repodata/repomd.xml".into(), repomd),
        (
            "https://good.example/repodata/primary.xml.zst".into(),
            primary,
        ),
        (
            "https://good.example/repodata/filelists.xml.zst".into(),
            filelists,
        ),
    ]);
    let outcome = Refresher::new(transport, &cache)
        .refresh(
            "fedora",
            Source::Metalink("https://meta.example/list".into()),
        )
        .unwrap();
    assert_eq!(outcome.packages, 1);
}

#[test]
fn mirrorlist_preserves_document_order_and_publishes_complete_metadata() {
    let directory = tempfile::tempdir().unwrap();
    let cache = Cache::new(directory.path());
    let (repomd, primary, filelists) = metadata_fixture();
    let transport = FakeTransport::new([
        (
            "https://list.example/mirrors".into(),
            b"# mirrors\nhttps://mirror.example/fedora\n".to_vec(),
        ),
        (
            "https://mirror.example/fedora/repodata/repomd.xml".into(),
            repomd,
        ),
        (
            "https://mirror.example/fedora/repodata/primary.xml.zst".into(),
            primary,
        ),
        (
            "https://mirror.example/fedora/repodata/filelists.xml.zst".into(),
            filelists,
        ),
    ]);

    let outcome = Refresher::new(transport, &cache)
        .refresh(
            "fedora",
            Source::Mirrorlist("https://list.example/mirrors".into()),
        )
        .unwrap();

    assert_eq!(outcome.packages, 1);
    let snapshot = cache.open_by_digest(&outcome.digest).unwrap();
    assert_eq!(snapshot.filelists.len(), 1);
    assert_eq!(
        snapshot
            .source_origin
            .as_ref()
            .map(dnfast_cache::SelectedOrigin::repomd_url),
        Some("https://mirror.example/fedora/repodata/repomd.xml")
    );
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
            Refresher::new(FakeTransport::new([]), &cache)
                .refresh("fedora", Source::BaseUrl(source.into())),
            Err(RefreshError::Policy(_))
        ));
    }
}

#[test]
fn mirrorlist_accepts_exact_entry_cap_and_rejects_plus_one() {
    let exact = (0..32)
        .map(|index| format!("https://m{index}.example/repo\n"))
        .collect::<String>();
    assert_eq!(
        super::mirrorlist::parse(exact.as_bytes()).unwrap().len(),
        32
    );
    let plus_one = format!("{exact}https://overflow.example/repo\n");
    assert!(super::mirrorlist::parse(plus_one.as_bytes()).is_err());
}

#[test]
fn metalink_accepts_exact_resource_cap_and_rejects_plus_one() {
    let resources = |count| {
        (0..count)
            .map(|index| format!("<url>https://m{index}.example/repodata/repomd.xml</url>"))
            .collect::<String>()
    };
    let document = |count| {
        format!(
            "<metalink xmlns=\"http://www.metalinker.org/\"><file name=\"repomd.xml\"><hash type=\"sha256\">{}</hash><size>1</size>{}</file></metalink>",
            "a".repeat(64),
            resources(count)
        )
    };
    assert_eq!(
        parse_metalink(document(32).as_bytes())
            .unwrap()
            .resources
            .len(),
        32
    );
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
        (
            "https://meta.example/list".into(),
            metalink_fixture(&repomd),
        ),
        (
            "https://bad.example/repodata/repomd.xml".into(),
            repomd.clone(),
        ),
        (
            "https://bad.example/repodata/primary.xml.zst".into(),
            primary.clone(),
        ),
        (
            "https://bad.example/repodata/filelists.xml.zst".into(),
            b"wrong-generation".to_vec(),
        ),
        ("https://good.example/repodata/repomd.xml".into(), repomd),
        (
            "https://good.example/repodata/primary.xml.zst".into(),
            primary,
        ),
        (
            "https://good.example/repodata/filelists.xml.zst".into(),
            filelists,
        ),
    ]);
    let outcome = Refresher::new(transport, &cache)
        .refresh(
            "fedora",
            Source::Metalink("https://meta.example/list".into()),
        )
        .unwrap();
    let objects = std::fs::read_dir(directory.path().join("objects/sha256"))
        .unwrap()
        .count();
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
fn openpgp_authenticated_refresh_binds_signer_evidence_and_rejects_missing_signature() {
    let directory = tempfile::tempdir().unwrap();
    let cache = Cache::new(directory.path());
    let (repomd, primary, filelists) = metadata_fixture();
    let (certificate, fingerprint, signature, now) = super::openpgp::signed_fixture(&repomd);
    let trust =
        MetadataTrust::new([certificate], [fingerprint.clone()], "a".repeat(64), now).unwrap();
    let base = "https://signed.example/fedora";
    cache
        .publish_complete_with_origin(
            "fedora",
            &repomd,
            &primary,
            &filelists,
            Some(&format!("{base}/repodata/repomd.xml")),
        )
        .unwrap();
    let transport = FakeTransport::new([
        (format!("{base}/repodata/repomd.xml"), repomd.clone()),
        (format!("{base}/repodata/repomd.xml.asc"), signature),
        (format!("{base}/repodata/primary.xml.zst"), primary),
        (format!("{base}/repodata/filelists.xml.zst"), filelists),
    ]);

    let outcome = Refresher::new(transport, &cache)
        .refresh_with_metadata_trust("fedora", Source::BaseUrl(base.into()), Some(&trust))
        .unwrap();
    let generation = cache
        .open_current_verified_complete_generation("fedora")
        .unwrap();

    assert_eq!(generation.digest(), outcome.digest);
    assert!(
        matches!(generation.repomd_authentication(), dnfast_cache::RepomdAuthentication::OpenPgp {
        primary_fingerprint, ..
    } if primary_fingerprint == &fingerprint)
    );
    let missing = Refresher::new(
        FakeTransport::new([(format!("{base}/repodata/repomd.xml"), repomd)]),
        &Cache::new(tempfile::tempdir().unwrap().keep()),
    )
    .refresh_with_metadata_trust("fedora", Source::BaseUrl(base.into()), Some(&trust));
    assert!(missing.is_err());
}

#[test]
fn rejects_metalink_namespace_declaration_not_bound_to_root() {
    let xml = br#"<evil:metalink xmlns:evil="urn:evil" xmlns:unused="http://www.metalinker.org/"><file name="repomd.xml"/></evil:metalink>"#;
    assert!(matches!(
        parse_metalink(xml),
        Err(RefreshError::Metalink(_))
    ));
}
