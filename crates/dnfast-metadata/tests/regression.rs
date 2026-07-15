use std::io::{Cursor, Write};

use dnfast_metadata::{
    MAX_PRIMARY_COMPRESSED_BYTES, MAX_PRIMARY_OPEN_BYTES, MetadataError, PrimaryRecord,
    decode_primary, decode_record, parse_filelists_record, parse_primary, parse_repomd, search,
    verify_compressed,
};
use flate2::{Compression, write::GzEncoder};
use sha2::{Digest, Sha256};

const REPOMD: &str = r#"<?xml version="1.0"?>
<repomd xmlns="http://linux.duke.edu/metadata/repo">
  <data type="filelists"><location href="repodata/files.xml.zst"/></data>
  <data type="primary">
    <checksum type="sha256">aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa</checksum>
    <open-checksum type="sha256">bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb</open-checksum>
    <location href="repodata/primary.xml.zst"/><size>123</size><open-size>456</open-size>
  </data>
</repomd>"#;

const PRIMARY: &str = r#"<?xml version="1.0"?>
<metadata xmlns="http://linux.duke.edu/metadata/common" packages="2">
  <package type="rpm"><name>ripgrep</name><arch>aarch64</arch><version epoch="0" ver="14.1.1" rel="1.fc44"/><summary>Fast search tool</summary></package>
  <package type="rpm"><name>ripgrep-all</name><arch>noarch</arch><version epoch="0" ver="0.10.9" rel="2.fc44"/><summary>Search PDFs</summary></package>
</metadata>"#;

const FILELISTS: &str = r#"<?xml version="1.0"?>
<filelists xmlns="http://linux.duke.edu/metadata/filelists" packages="1">
  <package pkgid="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" name="ripgrep" arch="aarch64">
    <version epoch="0" ver="14.1.1" rel="1.fc44"/>
    <file>/usr/bin/rg</file>
  </package>
</filelists>"#;

fn compressed_record(href: &str, compressed: &[u8], open: &[u8]) -> PrimaryRecord {
    PrimaryRecord {
        href: href.into(),
        checksum: hex::encode(Sha256::digest(compressed)),
        size: compressed.len() as u64,
        open_checksum: hex::encode(Sha256::digest(open)),
        open_size: open.len() as u64,
    }
}

#[test]
fn parses_primary_record_from_repomd() {
    let record = parse_repomd(REPOMD.as_bytes()).expect("valid repomd");
    assert_eq!(
        (record.href.as_str(), record.size, record.open_size),
        ("repodata/primary.xml.zst", 123, 456)
    );
    assert_eq!(record.checksum.len(), 64);
}

#[test]
fn parses_packages_and_ranks_search_deterministically() {
    let packages = parse_primary(PRIMARY.as_bytes()).expect("valid primary");
    assert_eq!(packages[0].nevra(), "ripgrep-0:14.1.1-1.fc44.aarch64");
    assert_eq!(
        search(&packages, "ripgrep")
            .iter()
            .map(|package| package.name.as_str())
            .collect::<Vec<_>>(),
        ["ripgrep", "ripgrep-all"]
    );
    assert!(search(&packages, "missing").is_empty());
}

#[test]
fn primary_requires_common_root_and_exact_package_count() {
    let wrong_root = PRIMARY.replace("metadata/common", "metadata/other");
    assert_eq!(
        parse_primary(wrong_root.as_bytes()),
        Err(MetadataError::Xml(
            "unexpected primary root or namespace".into()
        ))
    );
    let wrong_count = PRIMARY.replace("packages=\"2\"", "packages=\"3\"");
    assert_eq!(
        parse_primary(wrong_count.as_bytes()),
        Err(MetadataError::Xml(
            "primary package count mismatch: declared 3, parsed 2".into()
        ))
    );
}

#[test]
fn rejects_invalid_open_checksum_syntax() {
    let xml = REPOMD.replace(
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "not-a-sha256",
    );
    assert_eq!(
        parse_repomd(xml.as_bytes()),
        Err(MetadataError::UnsupportedChecksum("not-a-sha256".into()))
    );
}

#[test]
fn rejects_repomd_from_wrong_namespace() {
    let xml = REPOMD.replace("metadata/repo", "metadata/common");
    assert_eq!(
        parse_repomd(xml.as_bytes()),
        Err(MetadataError::Xml(
            "unexpected repomd root or namespace".into()
        ))
    );
}

#[test]
fn rejects_unsafe_primary_location() {
    let xml = REPOMD.replace("repodata/primary.xml.zst", "../escape.xml.zst");
    assert_eq!(
        parse_repomd(xml.as_bytes()),
        Err(MetadataError::UnsafeLocation("../escape.xml.zst".into()))
    );
}

#[test]
fn verifies_compressed_size_and_sha256() {
    let bytes = b"verified metadata";
    let record = compressed_record("repodata/primary.xml", bytes, bytes);
    assert_eq!(verify_compressed(bytes, &record), Ok(()));
    assert_eq!(
        verify_compressed(b"corrupt metadata", &record),
        Err(MetadataError::SizeMismatch {
            expected: bytes.len() as u64,
            actual: 16
        })
    );
}

#[test]
fn rejects_namespace_declaration_not_bound_to_repomd() {
    let xml = REPOMD.replace("xmlns=", "xmlns:repo=");
    assert_eq!(
        parse_repomd(xml.as_bytes()),
        Err(MetadataError::Xml(
            "unexpected repomd root or namespace".into()
        ))
    );
}

#[test]
fn rejects_metadata_sizes_above_policy_caps() {
    let too_large = REPOMD.replace(
        "<size>123</size>",
        &format!("<size>{}</size>", MAX_PRIMARY_COMPRESSED_BYTES + 1),
    );
    assert_eq!(
        parse_repomd(too_large.as_bytes()),
        Err(MetadataError::SizeMismatch {
            expected: MAX_PRIMARY_COMPRESSED_BYTES,
            actual: MAX_PRIMARY_COMPRESSED_BYTES + 1
        })
    );
    let too_open = REPOMD.replace(
        "<open-size>456</open-size>",
        &format!("<open-size>{}</open-size>", MAX_PRIMARY_OPEN_BYTES + 1),
    );
    assert_eq!(
        parse_repomd(too_open.as_bytes()),
        Err(MetadataError::SizeMismatch {
            expected: MAX_PRIMARY_OPEN_BYTES,
            actual: MAX_PRIMARY_OPEN_BYTES + 1
        })
    );
}

#[test]
fn rejects_wrong_namespace_on_empty_version_and_non_rpm_package() {
    let namespace = PRIMARY.replace("<version epoch=", "<version xmlns=\"urn:wrong\" epoch=");
    assert_eq!(
        parse_primary(namespace.as_bytes()),
        Err(MetadataError::Xml("unexpected primary namespace".into()))
    );
    let package_type = PRIMARY.replacen("type=\"rpm\"", "type=\"deb\"", 1);
    assert_eq!(
        parse_primary(package_type.as_bytes()),
        Err(MetadataError::Xml("primary package type is not rpm".into()))
    );
}

#[test]
fn rejects_decompressed_output_above_declared_size() {
    let compressed = zstd::stream::encode_all(b"four".as_slice(), 1).expect("zstd encode");
    let mut record = compressed_record("repodata/primary.xml.zst", &compressed, b"four");
    record.open_size = 3;
    assert_eq!(
        decode_primary(&compressed, &record),
        Err(MetadataError::SizeMismatch {
            expected: 3,
            actual: 4
        })
    );
}

#[test]
fn requires_open_integrity_fields() {
    let no_checksum = REPOMD.replace(
        &format!(
            "<open-checksum type=\"sha256\">{}</open-checksum>",
            "b".repeat(64)
        ),
        "",
    );
    assert_eq!(
        parse_repomd(no_checksum.as_bytes()),
        Err(MetadataError::MissingPrimary)
    );
    let no_size = REPOMD.replace("<open-size>456</open-size>", "");
    assert_eq!(
        parse_repomd(no_size.as_bytes()),
        Err(MetadataError::MissingPrimary)
    );
}

#[test]
fn requires_complete_single_xml_documents() {
    assert_eq!(
        parse_repomd(b"<repomd xmlns=\"http://linux.duke.edu/metadata/repo\">"),
        Err(MetadataError::Xml("incomplete repomd root".into()))
    );
    let trailing = format!("{PRIMARY}<extra/>");
    assert_eq!(
        parse_primary(trailing.as_bytes()),
        Err(MetadataError::Xml("element outside primary root".into()))
    );
}

#[test]
fn decodes_gzip_and_zstd_with_open_integrity() {
    let open = PRIMARY.as_bytes();
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(open).expect("gzip write");
    let gzip = encoder.finish().expect("gzip finish");
    let zstd = zstd::stream::encode_all(open, 1).expect("zstd encode");
    assert_eq!(
        decode_primary(
            &gzip,
            &compressed_record("repodata/primary.xml.gz", &gzip, open)
        )
        .expect("gzip decode"),
        open
    );
    assert_eq!(
        decode_primary(
            &zstd,
            &compressed_record("repodata/primary.xml.zst", &zstd, open)
        )
        .expect("zstd decode"),
        open
    );
}

#[test]
fn record_decoder_uses_content_magic_not_href_suffix() {
    // Given: the same valid primary XML represented as plain, gzip, and zstd bytes.
    let open = PRIMARY.as_bytes();
    let mut gzip_encoder = GzEncoder::new(Vec::new(), Compression::default());
    gzip_encoder.write_all(open).expect("gzip write");
    let gzip = gzip_encoder.finish().expect("gzip finish");
    let zstd = zstd::stream::encode_all(open, 1).expect("zstd encode");

    // When: each payload is bound to locations whose suffixes deliberately name every other codec.
    let cases = [
        (open, "repodata/primary.xml.zst"),
        (open, "repodata/primary.xml.gz"),
        (&gzip, "repodata/primary.xml.zst"),
        (&gzip, "repodata/primary.xml"),
        (&zstd, "repodata/primary.xml.gz"),
        (&zstd, "repodata/primary.xml"),
    ];

    // Then: bytes, not a location spelling, choose the decoder.
    for (bytes, href) in cases {
        assert_eq!(
            decode_record(bytes, &compressed_record(href, bytes, open)).expect("decode by content"),
            open
        );
    }
}

#[test]
fn filelists_stream_uses_content_magic_not_href_suffix() {
    // Given: valid filelists XML compressed as zstd and bound to a plain-XML location.
    let open = FILELISTS.as_bytes();
    let zstd = zstd::stream::encode_all(open, 1).expect("zstd encode");
    let record = compressed_record("repodata/filelists.xml", &zstd, open);

    // When: the streaming parser reads the record.
    let packages = parse_filelists_record(Cursor::new(zstd), &record).expect("decode by content");

    // Then: zstd magic, not the .xml suffix, selected the decompressor.
    assert_eq!(packages.len(), 1);
}
