use dnfast_cache::Cache;
use sha2::{Digest, Sha256};

use crate::{Refresher, Source, tests::{FakeTransport, metadata_fixture, metalink_fixture}};

#[test]
fn every_source_kind_publishes_identical_repomd_digest() {
    let (repomd, primary, filelists) = metadata_fixture();
    let expected = hex::encode(Sha256::digest(&repomd));
    let direct_dir = tempfile::tempdir().unwrap();
    let direct_cache = Cache::new(direct_dir.path());
    let base = "https://direct.example/repo";
    let direct = FakeTransport::new([
        (format!("{base}/repodata/repomd.xml"), repomd.clone()),
        (format!("{base}/repodata/primary.xml.zst"), primary.clone()),
        (format!("{base}/repodata/filelists.xml.zst"), filelists.clone()),
    ]);
    let direct = Refresher::new(direct, &direct_cache).refresh("repo", Source::BaseUrl(base.into())).unwrap().digest;
    let metalink_dir = tempfile::tempdir().unwrap();
    let metalink_cache = Cache::new(metalink_dir.path());
    let metalink = FakeTransport::new([
        ("https://meta.example/list".into(), metalink_fixture(&repomd)),
        ("https://bad.example/repodata/repomd.xml".into(), repomd.clone()),
        ("https://bad.example/repodata/primary.xml.zst".into(), primary.clone()),
        ("https://bad.example/repodata/filelists.xml.zst".into(), filelists.clone()),
    ]);
    let metalink = Refresher::new(metalink, &metalink_cache).refresh("repo", Source::Metalink("https://meta.example/list".into())).unwrap().digest;
    let mirror_dir = tempfile::tempdir().unwrap();
    let mirror_cache = Cache::new(mirror_dir.path());
    let mirror = FakeTransport::new([
        ("https://list.example/mirrors".into(), b"https://mirror.example/repo\n".to_vec()),
        ("https://mirror.example/repo/repodata/repomd.xml".into(), repomd),
        ("https://mirror.example/repo/repodata/primary.xml.zst".into(), primary),
        ("https://mirror.example/repo/repodata/filelists.xml.zst".into(), filelists),
    ]);
    let mirror = Refresher::new(mirror, &mirror_cache).refresh("repo", Source::Mirrorlist("https://list.example/mirrors".into())).unwrap().digest;
    assert_eq!([direct, metalink, mirror], [expected.clone(), expected.clone(), expected]);
}
