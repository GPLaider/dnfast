use std::error::Error;

use dnfast_metadata::{
    decode_primary, parse_primary, parse_repomd, search, verify_compressed, MetadataError, Package,
    PrimaryRecord, MAX_PACKAGES, MAX_PRIMARY_COMPRESSED_BYTES, MAX_PRIMARY_OPEN_BYTES,
};
use sha2::{Digest, Sha256};
use serde::{de::DeserializeOwned, Serialize};

const CHECKSUM: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn record(bytes: &[u8], href: &str) -> PrimaryRecord {
    PrimaryRecord {
        href: href.into(),
        checksum: hex::encode(Sha256::digest(bytes)),
        size: bytes.len() as u64,
        open_checksum: hex::encode(Sha256::digest(bytes)),
        open_size: bytes.len() as u64,
    }
}

#[test]
fn public_types_and_constants_remain_consumer_usable() {
    let package = Package { name: "pkg".into(), arch: "x86_64".into(), epoch: "0".into(), version: "1".into(), release: "2".into(), summary: "tool".into() };
    fn assert_serde<T: Serialize + DeserializeOwned>() {}
    assert_serde::<Package>();
    assert_eq!(package.nevra(), "pkg-0:1-2.x86_64");
    assert_eq!((MAX_PRIMARY_COMPRESSED_BYTES, MAX_PRIMARY_OPEN_BYTES, MAX_PACKAGES), (536_870_912, 1_073_741_824, 2_000_000));
    let cloned = record(b"x", "repodata/p.xml").clone();
    assert_eq!(cloned, record(b"x", "repodata/p.xml"));
}

#[test]
fn repomd_parser_preserves_fields_and_error_observables() {
    let xml = format!(r#"<repomd xmlns="http://linux.duke.edu/metadata/repo"><data type="primary"><checksum type="sha256">{CHECKSUM}</checksum><open-checksum type="sha256">{CHECKSUM}</open-checksum><location href="repodata/primary.xml"/><size>1</size><open-size>2</open-size></data></repomd>"#);
    let parsed = parse_repomd(xml.as_bytes()).expect("valid repomd");
    assert_eq!(parsed, PrimaryRecord { href: "repodata/primary.xml".into(), checksum: CHECKSUM.into(), size: 1, open_checksum: CHECKSUM.into(), open_size: 2 });
    assert_eq!(parse_repomd(b"<wrong/>"), Err(MetadataError::Xml("element outside repomd root".into())));
    assert_eq!(parse_repomd(xml.replace("repodata/primary.xml", "../x").as_bytes()), Err(MetadataError::UnsafeLocation("../x".into())));
    assert_eq!(parse_repomd(xml.replace("<size>1</size>", "<size>x</size>").as_bytes()), Err(MetadataError::InvalidNumber("x".into())));
    assert_eq!(parse_repomd(xml.replace(CHECKSUM, "bad").as_bytes()), Err(MetadataError::UnsupportedChecksum("bad".into())));
    assert_eq!(parse_repomd(b"<repomd xmlns=\"http://linux.duke.edu/metadata/repo\"></repomd>"), Err(MetadataError::MissingPrimary));
}

#[test]
fn primary_parser_and_search_preserve_order_and_borrowing() {
    let xml = br#"<metadata xmlns="http://linux.duke.edu/metadata/common" packages="2"><package type="rpm"><name>Alpha</name><arch>x86_64</arch><version ver="1" rel="1"/><summary>needle</summary></package><package type="rpm"><name>alpha-tools</name><arch>noarch</arch><version epoch="2" ver="3" rel="4"/><summary>other</summary></package></metadata>"#;
    let packages = parse_primary(xml.as_slice()).expect("valid primary");
    assert_eq!(packages[0].epoch, "0");
    assert_eq!(search(&packages, " ALPHA "), vec![&packages[0], &packages[1]]);
    assert_eq!(search(&packages, "needle"), vec![&packages[0]]);
    assert!(search(&packages, "  ").is_empty());
    assert_eq!(parse_primary(b"<metadata xmlns=\"http://linux.duke.edu/metadata/common\" packages=\"1\"></metadata>".as_slice()), Err(MetadataError::Xml("primary package count mismatch: declared 1, parsed 0".into())));
}

#[test]
fn compression_functions_preserve_success_and_failure_precedence() {
    let bytes = b"<metadata/>";
    let good = record(bytes, "repodata/primary.xml");
    assert_eq!(verify_compressed(bytes, &good), Ok(()));
    assert_eq!(decode_primary(bytes, &good), Ok(bytes.to_vec()));
    let mut wrong_size = good.clone(); wrong_size.size = 4;
    assert_eq!(decode_primary(bytes, &wrong_size), Err(MetadataError::SizeMismatch { expected: 4, actual: bytes.len() as u64 }));
    let mut wrong_hash = good.clone(); wrong_hash.checksum = CHECKSUM.into();
    assert_eq!(verify_compressed(bytes, &wrong_hash), Err(MetadataError::ChecksumMismatch));
    let suffix_mismatch = record(bytes, "repodata/primary.bz2");
    assert_eq!(decode_primary(bytes, &suffix_mismatch), Ok(bytes.to_vec()));
    let malformed = b"plain";
    assert!(matches!(decode_primary(malformed, &record(malformed, "repodata/primary.xml")), Err(MetadataError::Xml(_))));
}

#[test]
fn every_error_variant_retains_debug_based_display_and_error_trait() {
    let errors = [
        MetadataError::Xml("x".into()), MetadataError::MissingPrimary,
        MetadataError::InvalidNumber("x".into()), MetadataError::UnsafeLocation("x".into()),
        MetadataError::UnsupportedChecksum("x".into()), MetadataError::ChecksumMismatch,
        MetadataError::SizeMismatch { expected: 1, actual: 2 },
        MetadataError::UnsupportedCompression("x".into()), MetadataError::Io("x".into()),
    ];
    for error in errors {
        let as_error: &dyn Error = &error;
        assert_eq!(as_error.to_string(), format!("metadata error: {error:?}"));
        assert!(as_error.source().is_none());
    }
}
