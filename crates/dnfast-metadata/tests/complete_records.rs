use std::{
    cell::Cell,
    fs::File,
    io::{self, BufReader, Read},
    path::PathBuf,
    rc::Rc,
};

use dnfast_metadata::{
    MAX_FILELISTS_COMPRESSED_BYTES, MAX_FILELISTS_OPEN_BYTES, MAX_PRIMARY_COMPRESSED_BYTES,
    MAX_PRIMARY_OPEN_BYTES, MAX_RELATIONS_PER_PACKAGE, MAX_TOTAL_OPEN_BYTES, checked_total_open,
};
use dnfast_metadata::{
    RelationFlags, copy_filelists_record_verified, copy_primary_record_verified, decode_record,
    parse_filelists, parse_filelists_record, parse_primary_records, parse_repomd_records,
    publish_validated, validate_filelists_generation, validate_filelists_record,
};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/rpm/generated-build10/repos/main/repodata")
        .join(name)
}

#[test]
fn complete_records_when_parsing_todo2a_corpus() {
    // Given: the corrected Todo 2A build10 repository.
    let repomd = std::fs::read(fixture("repomd.xml")).expect("fixture repomd");
    // When: both mandatory records and primary packages are parsed.
    let records = parse_repomd_records(&repomd).expect("complete repomd");
    let primary = std::fs::read(fixture(
        records.primary.href.rsplit('/').next().expect("name"),
    ))
    .expect("primary");
    let opened = decode_record(&primary, &records.primary).expect("verified primary");
    let packages = parse_primary_records(opened.as_slice()).expect("primary records");
    // Then: solver and artifact fields survive the boundary.
    let app = packages
        .iter()
        .find(|package| package.name == "dnfast-app")
        .expect("app");
    assert_eq!(app.location, "dnfast-app-1.0-1.noarch.rpm");
    assert_eq!(app.source_rpm, "dnfast-relations-1.0-1.src.rpm");
    assert!(
        app.requires.iter().any(
            |item| item.name == "dnfast-dep" && item.flags == Some(RelationFlags::GreaterEqual)
        )
    );
    let weak = packages
        .iter()
        .find(|package| package.name == "dnfast-weak-app")
        .expect("weak");
    assert_eq!(weak.recommends[0].name, "dnfast-dep");
    assert_eq!(weak.suggests[0].name, "dnfast-file-provider");
    assert_eq!(weak.supplements[0].name, "dnfast-app");
    assert_eq!(weak.enhances[0].name, "dnfast-rich");
}

#[test]
fn verified_primary_copy_streams_the_exact_open_record_and_rejects_tamper() {
    let records = parse_repomd_records(&std::fs::read(fixture("repomd.xml")).expect("repomd"))
        .expect("records");
    let primary = std::fs::read(fixture("primary.xml.zst")).expect("primary");
    let expected = decode_record(&primary, &records.primary).expect("opened primary");
    let mut streamed = Vec::new();
    assert_eq!(
        copy_primary_record_verified(primary.as_slice(), &records.primary, &mut streamed)
            .expect("verified streaming copy"),
        expected.len() as u64
    );
    assert_eq!(streamed, expected);

    let mut corrupted = primary;
    let midpoint = corrupted.len() / 2;
    corrupted[midpoint] ^= 1;
    assert!(
        copy_primary_record_verified(corrupted.as_slice(), &records.primary, Vec::new()).is_err()
    );
}

#[test]
fn verified_filelists_copy_streams_the_exact_open_record_and_rejects_tamper() {
    let records = parse_repomd_records(&std::fs::read(fixture("repomd.xml")).expect("repomd"))
        .expect("records");
    let filelists = std::fs::read(fixture("filelists.xml.zst")).expect("filelists");
    let expected = decode_record(&filelists, &records.filelists).expect("opened filelists");
    let mut streamed = Vec::new();
    assert_eq!(
        copy_filelists_record_verified(filelists.as_slice(), &records.filelists, &mut streamed)
            .expect("verified streaming copy"),
        expected.len() as u64
    );
    assert_eq!(streamed, expected);

    let mut corrupted = filelists;
    let midpoint = corrupted.len() / 2;
    corrupted[midpoint] ^= 1;
    assert!(
        copy_filelists_record_verified(corrupted.as_slice(), &records.filelists, Vec::new(),)
            .is_err()
    );
}

#[test]
fn filelists_stream_when_parsing_todo2a_corpus() {
    // Given: a verified filelists stream from the corrected corpus.
    let repomd = std::fs::read(fixture("repomd.xml")).expect("fixture repomd");
    let records = parse_repomd_records(&repomd).expect("complete repomd");
    let compressed = std::fs::read(fixture(
        records.filelists.href.rsplit('/').next().expect("name"),
    ))
    .expect("filelists");
    // When: filelists is consumed from a reader.
    let files = parse_filelists_record(compressed.as_slice(), &records.filelists)
        .expect("filelists records");
    // Then: package identity and paths are retained.
    let config = files
        .iter()
        .find(|package| package.name == "dnfast-config")
        .expect("config");
    assert_eq!(config.files, ["/etc/dnfast/fixture.conf"]);
    assert_eq!(files.len(), 25);
    validate_filelists_generation(
        &parse_primary_records(
            decode_record(
                &std::fs::read(fixture("primary.xml.zst")).expect("primary"),
                &records.primary,
            )
            .expect("opened primary")
            .as_slice(),
        )
        .expect("primary"),
        &files,
    )
    .expect("same generation");
    let primary = parse_primary_records(
        decode_record(
            &std::fs::read(fixture("primary.xml.zst")).expect("primary"),
            &records.primary,
        )
        .expect("opened primary")
        .as_slice(),
    )
    .expect("primary");
    validate_filelists_record(compressed.as_slice(), &records.filelists, &primary)
        .expect("streaming identity validation without retaining paths");
    drop(File::open(fixture("filelists.xml.zst")).expect("fixture remains available"));
}

#[test]
fn mutation_records_fail_when_filelists_is_missing_or_duplicated() {
    // Given: repomd with a missing or duplicate mandatory record.
    let xml = std::fs::read_to_string(fixture("repomd.xml")).expect("fixture repomd");
    let missing = xml.replace("type=\"filelists\"", "type=\"other-filelists\"");
    // When/Then: no mutation record set is published.
    assert!(parse_repomd_records(missing.as_bytes()).is_err());
    let data = xml
        .split("  <data type=\"filelists\">")
        .nth(1)
        .expect("filelists");
    let block = format!(
        "  <data type=\"filelists\">{}",
        data.split("  </data>").next().expect("block")
    );
    let duplicate = xml.replace("</repomd>", &format!("{block}  </data>\n</repomd>"));
    assert!(parse_repomd_records(duplicate.as_bytes()).is_err());
}

#[test]
fn generation_join_fails_when_filelists_is_swapped() {
    // Given: build9 primary records and build10 filelists records.
    let build9 = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/rpm/generated-build9/repos/main/repodata");
    let repomd9 = std::fs::read(build9.join("repomd.xml")).expect("build9 repomd");
    let records9 = parse_repomd_records(&repomd9).expect("build9 records");
    let primary = parse_primary_records(
        decode_record(
            &std::fs::read(build9.join("primary.xml.zst")).expect("build9 primary"),
            &records9.primary,
        )
        .expect("opened build9 primary")
        .as_slice(),
    )
    .expect("build9 primary");
    let records10 =
        parse_repomd_records(&std::fs::read(fixture("repomd.xml")).expect("build10 repomd"))
            .expect("build10 records");
    let filelists = parse_filelists(BufReader::new(
        decode_record(
            &std::fs::read(fixture("filelists.xml.zst")).expect("build10 filelists"),
            &records10.filelists,
        )
        .expect("opened build10 filelists")
        .as_slice(),
    ))
    .expect("build10 filelists");
    // When/Then: the generation join rejects publication.
    let publications = Cell::new(0);
    assert!(
        publish_validated(&primary, &filelists, || publications
            .set(publications.get() + 1))
        .is_err()
    );
    assert_eq!(publications.get(), 0);
}

#[test]
fn cross_group_relation_limit_rejects_plus_one() {
    // Given: one package with exactly half-cap provides and half-cap-plus-one requires.
    let provides = "<rpm:entry name=\"p\"/>".repeat(MAX_RELATIONS_PER_PACKAGE / 2);
    let requires = "<rpm:entry name=\"r\"/>".repeat(MAX_RELATIONS_PER_PACKAGE / 2 + 1);
    let xml = format!(
        "<metadata xmlns=\"http://linux.duke.edu/metadata/common\" xmlns:rpm=\"http://linux.duke.edu/metadata/rpm\" packages=\"1\"><package type=\"rpm\"><name>x</name><arch>noarch</arch><version epoch=\"0\" ver=\"1\" rel=\"1\"/><checksum type=\"sha256\" pkgid=\"YES\">{}</checksum><location href=\"x.rpm\"/><format><rpm:provides>{provides}</rpm:provides><rpm:requires>{requires}</rpm:requires></format></package></metadata>",
        "a".repeat(64)
    );
    // When/Then: the aggregate per-package cap rejects the cross-group bypass.
    assert!(matches!(
        parse_primary_records(xml.as_bytes()),
        Err(dnfast_metadata::MetadataError::LimitExceeded {
            kind: "relations per package",
            maximum: 16_384,
            actual: 16_385
        })
    ));
}

#[test]
fn escaped_entities_are_reassembled_before_file_path_validation() {
    let primary = format!(
        "<metadata xmlns=\"http://linux.duke.edu/metadata/common\" xmlns:rpm=\"http://linux.duke.edu/metadata/rpm\" packages=\"1\"><package type=\"rpm\"><name>x</name><arch>noarch</arch><version epoch=\"0\" ver=\"1\" rel=\"1\"/><checksum type=\"sha256\" pkgid=\"YES\">{}</checksum><summary>A &amp; B</summary><location href=\"x.rpm\"/><format><file>/usr/share/a&amp;b&lt;\\.html</file></format></package></metadata>",
        "a".repeat(64)
    );
    let primary = parse_primary_records(primary.as_bytes()).expect("escaped primary");
    assert_eq!(primary[0].summary, "A & B");
    assert_eq!(primary[0].files, ["/usr/share/a&b<\\.html"]);

    let filelists = format!(
        "<filelists xmlns=\"http://linux.duke.edu/metadata/filelists\" packages=\"1\"><package pkgid=\"{}\" name=\"x\" arch=\"noarch\"><version epoch=\"0\" ver=\"1\" rel=\"1\"/><file>/usr/share/a&amp;b&lt;\\.html</file></package></filelists>",
        "a".repeat(64)
    );
    let filelists = parse_filelists(filelists.as_bytes()).expect("escaped filelists");
    assert_eq!(filelists[0].files, ["/usr/share/a&b<\\.html"]);
}

#[test]
fn namespace_location_and_duplicate_identity_exploits_reject() {
    // Given: malicious prefix and unsafe package location mutations.
    let records = parse_repomd_records(&std::fs::read(fixture("repomd.xml")).expect("repomd"))
        .expect("records");
    let opened = decode_record(
        &std::fs::read(fixture("primary.xml.zst")).expect("primary"),
        &records.primary,
    )
    .expect("opened");
    let evil = String::from_utf8(opened.clone())
        .expect("utf8")
        .replace("rpm:entry", "evil:entry");
    let evil_uri = String::from_utf8(opened.clone())
        .expect("utf8")
        .replace("http://linux.duke.edu/metadata/rpm", "urn:evil");
    let nested_rebind = String::from_utf8(opened.clone()).expect("utf8").replacen(
        "<rpm:provides>",
        "<rpm:provides xmlns:rpm=\"urn:evil\">",
        1,
    );
    let unsafe_location = String::from_utf8(opened.clone()).expect("utf8").replacen(
        "dnfast-app-1.0-1.noarch.rpm",
        "../escape.rpm",
        1,
    );
    // When/Then: both parser boundary exploits fail closed.
    assert!(parse_primary_records(evil.as_bytes()).is_err());
    assert!(parse_primary_records(evil_uri.as_bytes()).is_err());
    assert!(parse_primary_records(nested_rebind.as_bytes()).is_err());
    assert!(parse_primary_records(unsafe_location.as_bytes()).is_err());
    let mut primary = parse_primary_records(opened.as_slice()).expect("primary records");
    primary[1].checksum = primary[0].checksum.clone();
    let files = parse_filelists_record(
        std::fs::File::open(fixture("filelists.xml.zst")).expect("filelists"),
        &records.filelists,
    )
    .expect("files");
    assert!(validate_filelists_generation(&primary, &files).is_err());
}

#[test]
fn nested_default_namespace_rebinding_rejects_for_repomd_and_filelists() {
    // Given: valid documents with an attacker rebinding the active default namespace in nested scope.
    let repomd = std::fs::read_to_string(fixture("repomd.xml")).expect("repomd");
    let rebound_repomd = repomd.replacen(
        "<data type=\"primary\">",
        "<data xmlns=\"urn:evil\" type=\"primary\">",
        1,
    );
    let records = parse_repomd_records(repomd.as_bytes()).expect("records");
    let opened = decode_record(
        &std::fs::read(fixture("filelists.xml.zst")).expect("filelists"),
        &records.filelists,
    )
    .expect("opened");
    let rebound_filelists = String::from_utf8(opened).expect("utf8").replacen(
        "<package ",
        "<package xmlns=\"urn:evil\" ",
        1,
    );
    // When/Then: namespace-scope resolution rejects both nested rebindings.
    assert!(parse_repomd_records(rebound_repomd.as_bytes()).is_err());
    assert!(parse_filelists(BufReader::new(rebound_filelists.as_bytes())).is_err());
}

struct ChunkedReader {
    inner: File,
    largest: Rc<Cell<usize>>,
}

impl Read for ChunkedReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.largest.set(self.largest.get().max(buffer.len()));
        let length = buffer.len().min(7);
        self.inner.read(&mut buffer[..length])
    }
}

struct CountingReader {
    bytes: Vec<u8>,
    offset: usize,
    read: Rc<Cell<usize>>,
}

impl Read for CountingReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let remaining = &self.bytes[self.offset..];
        let count = remaining.len().min(buffer.len());
        buffer[..count].copy_from_slice(&remaining[..count]);
        self.offset += count;
        self.read.set(self.offset);
        Ok(count)
    }
}

#[test]
fn compressed_stream_never_reads_beyond_declared_plus_one() {
    // Given: valid compressed filelists followed by one MiB of attacker-controlled trailing bytes.
    let records = parse_repomd_records(&std::fs::read(fixture("repomd.xml")).expect("repomd"))
        .expect("records");
    let mut bytes = std::fs::read(fixture("filelists.xml.zst")).expect("filelists");
    bytes.resize(bytes.len() + 1024 * 1024, 0x41);
    let read = Rc::new(Cell::new(0));
    // When: the streaming decoder consumes the adversarial input.
    let result = parse_filelists_record(
        CountingReader {
            bytes,
            offset: 0,
            read: Rc::clone(&read),
        },
        &records.filelists,
    );
    // Then: it fails integrity without allowing decoder buffering beyond size plus one.
    assert!(result.is_err());
    assert!(read.get() <= records.filelists.size as usize + 1);
}

#[test]
fn filelists_decode_is_incremental_when_reader_is_chunked() {
    // Given: a reader that returns at most seven compressed bytes per call.
    let records = parse_repomd_records(&std::fs::read(fixture("repomd.xml")).expect("repomd"))
        .expect("records");
    let largest = Rc::new(Cell::new(0));
    let reader = ChunkedReader {
        inner: File::open(fixture("filelists.xml.zst")).expect("filelists"),
        largest: Rc::clone(&largest),
    };
    // When: verified decompression feeds the streaming XML parser directly.
    let files = parse_filelists_record(reader, &records.filelists).expect("streamed files");
    // Then: all records parse without a full opened-document allocation.
    assert_eq!(files.len(), 25);
    assert!(largest.get() <= 131_075);
}

#[test]
fn numeric_metadata_caps_accept_boundary_and_reject_plus_one() {
    // Given: the real repomd document with filelists sizes replaced at policy edges.
    let xml = std::fs::read_to_string(fixture("repomd.xml")).expect("repomd");
    let boundary = xml
        .replace(
            "<size>1497</size>",
            &format!("<size>{MAX_FILELISTS_COMPRESSED_BYTES}</size>"),
        )
        .replace(
            "<open-size>6561</open-size>",
            &format!("<open-size>{MAX_FILELISTS_OPEN_BYTES}</open-size>"),
        );
    // When/Then: exact limits parse, while each +1 and arithmetic overflow reject.
    assert!(parse_repomd_records(boundary.as_bytes()).is_ok());
    assert!(
        parse_repomd_records(
            boundary
                .replace(
                    &MAX_FILELISTS_COMPRESSED_BYTES.to_string(),
                    &(MAX_FILELISTS_COMPRESSED_BYTES + 1).to_string()
                )
                .as_bytes()
        )
        .is_err()
    );
    assert!(
        parse_repomd_records(
            boundary
                .replace(
                    &MAX_FILELISTS_OPEN_BYTES.to_string(),
                    &(MAX_FILELISTS_OPEN_BYTES + 1).to_string()
                )
                .as_bytes()
        )
        .is_err()
    );
    let primary_boundary = xml
        .replace(
            "<size>2979</size>",
            &format!("<size>{MAX_PRIMARY_COMPRESSED_BYTES}</size>"),
        )
        .replace(
            "<open-size>25482</open-size>",
            &format!("<open-size>{MAX_PRIMARY_OPEN_BYTES}</open-size>"),
        );
    assert!(parse_repomd_records(primary_boundary.as_bytes()).is_ok());
    assert!(
        parse_repomd_records(
            primary_boundary
                .replace(
                    &MAX_PRIMARY_COMPRESSED_BYTES.to_string(),
                    &(MAX_PRIMARY_COMPRESSED_BYTES + 1).to_string()
                )
                .as_bytes()
        )
        .is_err()
    );
    assert!(
        parse_repomd_records(
            primary_boundary
                .replace(
                    &MAX_PRIMARY_OPEN_BYTES.to_string(),
                    &(MAX_PRIMARY_OPEN_BYTES + 1).to_string()
                )
                .as_bytes()
        )
        .is_err()
    );
    assert_eq!(
        checked_total_open([MAX_TOTAL_OPEN_BYTES]),
        Ok(MAX_TOTAL_OPEN_BYTES)
    );
    assert!(checked_total_open([MAX_TOTAL_OPEN_BYTES, 1]).is_err());
    assert!(checked_total_open([u64::MAX, 1]).is_err());
}
