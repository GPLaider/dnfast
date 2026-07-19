use std::{
    cell::RefCell,
    io::{self, BufRead, BufReader, Read, Write},
    rc::Rc,
};

use flate2::read::GzDecoder;
use quick_xml::{Reader, events::Event};
use sha2::{Digest, Sha256};

use crate::{
    CompletePackage, FileListPackage, MAX_FILELISTS_COMPRESSED_BYTES, MAX_FILELISTS_OPEN_BYTES,
    PrimaryPackageIdentity, ValidatedPrimary, parse_filelists, parse_primary_validated,
    validate_filelists_xml, validate_filelists_xml_identities,
};
use crate::{MAX_PRIMARY_OPEN_BYTES, MetadataError, MetadataRecord, PrimaryRecord};

pub fn decode_auxiliary(
    bytes: &[u8],
    record: &crate::AuxiliaryRecord,
    maximum_open_bytes: u64,
) -> Result<Vec<u8>, MetadataError> {
    if bytes.len() as u64 != record.size {
        return Err(MetadataError::SizeMismatch {
            expected: record.size,
            actual: bytes.len() as u64,
        });
    }
    if hex::encode(Sha256::digest(bytes)) != record.checksum {
        return Err(MetadataError::ChecksumMismatch);
    }
    let read_limit = maximum_open_bytes
        .checked_add(1)
        .ok_or_else(|| MetadataError::InvalidNumber(maximum_open_bytes.to_string()))?;
    let mut output = Vec::new();
    match encoding(bytes) {
        MetadataEncoding::Zstd => {
            zstd::stream::read::Decoder::new(bytes)
                .map_err(|error| MetadataError::Io(error.to_string()))?
                .take(read_limit)
                .read_to_end(&mut output)
                .map_err(|error| MetadataError::Io(error.to_string()))?;
        }
        MetadataEncoding::Gzip => {
            GzDecoder::new(bytes)
                .take(read_limit)
                .read_to_end(&mut output)
                .map_err(|error| MetadataError::Io(error.to_string()))?;
        }
        MetadataEncoding::Xml => output.extend_from_slice(bytes),
    }
    if output.len() as u64 > maximum_open_bytes {
        return Err(MetadataError::LimitExceeded {
            kind: "opened auxiliary metadata",
            maximum: maximum_open_bytes,
            actual: output.len() as u64,
        });
    }
    Ok(output)
}

pub fn verify_compressed(bytes: &[u8], record: &PrimaryRecord) -> Result<(), MetadataError> {
    if bytes.len() as u64 != record.size {
        return Err(MetadataError::SizeMismatch {
            expected: record.size,
            actual: bytes.len() as u64,
        });
    }
    if hex::encode(Sha256::digest(bytes)) != record.checksum {
        return Err(MetadataError::ChecksumMismatch);
    }
    Ok(())
}

pub fn decode_primary(bytes: &[u8], record: &PrimaryRecord) -> Result<Vec<u8>, MetadataError> {
    decode_bounded(bytes, record, MAX_PRIMARY_OPEN_BYTES)
}

pub fn decode_record(bytes: &[u8], record: &MetadataRecord) -> Result<Vec<u8>, MetadataError> {
    decode_bounded(bytes, record, crate::MAX_FILELISTS_OPEN_BYTES)
}

/// Streams an integrity-verified primary record into a bounded sink without
/// retaining its expanded XML in memory. The caller must still parse the
/// resulting XML before treating its contents as metadata evidence.
pub fn copy_primary_record_verified(
    input: impl Read,
    record: &MetadataRecord,
    output: impl Write,
) -> Result<u64, MetadataError> {
    copy_record_verified(
        input,
        record,
        crate::MAX_PRIMARY_COMPRESSED_BYTES,
        crate::MAX_PRIMARY_OPEN_BYTES,
        output,
    )
}

/// Streams an integrity-verified filelists record into a bounded sink without
/// retaining its expanded XML in memory.  Both the compressed and opened
/// checksums from repomd are verified before EOF is reported to the caller.
pub fn copy_filelists_record_verified(
    input: impl Read,
    record: &MetadataRecord,
    output: impl Write,
) -> Result<u64, MetadataError> {
    copy_record_verified(
        input,
        record,
        crate::MAX_FILELISTS_COMPRESSED_BYTES,
        crate::MAX_FILELISTS_OPEN_BYTES,
        output,
    )
}

fn copy_record_verified(
    input: impl Read,
    record: &MetadataRecord,
    max_compressed: u64,
    max_open: u64,
    mut output: impl Write,
) -> Result<u64, MetadataError> {
    let mut verified = verified_metadata_reader(input, record, max_compressed, max_open)?;
    io::copy(&mut verified, &mut output).map_err(|error| MetadataError::Io(error.to_string()))
}

fn decode_bounded(
    bytes: &[u8],
    record: &MetadataRecord,
    maximum: u64,
) -> Result<Vec<u8>, MetadataError> {
    verify_compressed(bytes, record)?;
    let expected_limit = record.open_size;
    if expected_limit > maximum {
        return Err(MetadataError::SizeMismatch {
            expected: maximum,
            actual: expected_limit,
        });
    }
    let read_limit = expected_limit
        .checked_add(1)
        .ok_or_else(|| MetadataError::InvalidNumber(expected_limit.to_string()))?;
    let mut output = Vec::new();
    match encoding(bytes) {
        MetadataEncoding::Zstd => {
            zstd::stream::read::Decoder::new(bytes)
                .map_err(|error| MetadataError::Io(error.to_string()))?
                .take(read_limit)
                .read_to_end(&mut output)
                .map_err(|error| MetadataError::Io(error.to_string()))?;
        }
        MetadataEncoding::Gzip => {
            GzDecoder::new(bytes)
                .take(read_limit)
                .read_to_end(&mut output)
                .map_err(|error| MetadataError::Io(error.to_string()))?;
        }
        MetadataEncoding::Xml => output.extend_from_slice(bytes),
    }
    if output.len() as u64 != expected_limit {
        return Err(MetadataError::SizeMismatch {
            expected: expected_limit,
            actual: output.len() as u64,
        });
    }
    if hex::encode(Sha256::digest(&output)) != record.open_checksum {
        return Err(MetadataError::ChecksumMismatch);
    }
    validate_xml(&output)?;
    Ok(output)
}

pub fn parse_filelists_record<R: Read>(
    input: R,
    record: &MetadataRecord,
) -> Result<Vec<FileListPackage>, MetadataError> {
    parse_filelists(verified_filelists_reader(input, record)?)
}

pub fn validate_filelists_record<R: Read>(
    input: R,
    record: &MetadataRecord,
    primary: &[CompletePackage],
) -> Result<(), MetadataError> {
    validate_filelists_xml(verified_filelists_reader(input, record)?, primary)
}

pub fn validate_primary_record<R: Read>(
    input: R,
    record: &MetadataRecord,
) -> Result<ValidatedPrimary, MetadataError> {
    parse_primary_validated(verified_metadata_reader(
        input,
        record,
        crate::MAX_PRIMARY_COMPRESSED_BYTES,
        crate::MAX_PRIMARY_OPEN_BYTES,
    )?)
}

pub fn validate_filelists_record_identities<R: Read>(
    input: R,
    record: &MetadataRecord,
    primary: &[PrimaryPackageIdentity],
) -> Result<(), MetadataError> {
    validate_filelists_xml_identities(verified_filelists_reader(input, record)?, primary)
}

pub fn visit_filelists_record_identities<R: Read>(
    input: R,
    record: &MetadataRecord,
    primary: &[PrimaryPackageIdentity],
    mut visitor: impl FnMut(&str, &str) -> Result<(), MetadataError>,
) -> Result<(), MetadataError> {
    crate::filelists::visit_filelists_xml_identities(
        verified_filelists_reader(input, record)?,
        primary,
        &mut visitor,
    )
}

pub fn scan_validated_filelists_record_path<R: Read>(
    input: R,
    record: &MetadataRecord,
    target: &str,
) -> Result<Vec<String>, MetadataError> {
    crate::filelists::scan_validated_filelists_xml_path(
        verified_filelists_reader(input, record)?,
        target,
    )
}

/// Scans filelists bytes whose complete opened XML was already validated when
/// a root-owned immutable capability was published. The compressed SHA-256
/// and both exact sizes are revalidated while streaming; only the redundant
/// hash of the multi-gigabyte opened stream is omitted.
pub fn scan_prevalidated_filelists_record_path(
    input: impl Read,
    record: &MetadataRecord,
    target: &str,
) -> Result<Vec<String>, MetadataError> {
    if record.size > MAX_FILELISTS_COMPRESSED_BYTES {
        return Err(MetadataError::SizeMismatch {
            expected: MAX_FILELISTS_COMPRESSED_BYTES,
            actual: record.size,
        });
    }
    if record.open_size > MAX_FILELISTS_OPEN_BYTES {
        return Err(MetadataError::SizeMismatch {
            expected: MAX_FILELISTS_OPEN_BYTES,
            actual: record.open_size,
        });
    }
    let compressed = Rc::new(RefCell::new(StreamDigest::default()));
    let hashed = DigestReader {
        inner: input.take(
            record
                .size
                .checked_add(1)
                .ok_or(MetadataError::LimitExceeded {
                    kind: "compressed metadata",
                    maximum: record.size,
                    actual: u64::MAX,
                })?,
        ),
        state: Rc::clone(&compressed),
    };
    let mut buffered = BufReader::new(hashed);
    let format = buffered
        .fill_buf()
        .map_err(|error| MetadataError::Io(error.to_string()))
        .map(encoding)?;
    let decoded: Box<dyn Read + '_> = match format {
        MetadataEncoding::Zstd => Box::new(
            zstd::stream::read::Decoder::new(buffered)
                .map_err(|error| MetadataError::Io(error.to_string()))?,
        ),
        MetadataEncoding::Gzip => Box::new(GzDecoder::new(buffered)),
        MetadataEncoding::Xml => Box::new(buffered),
    };
    crate::filelists::scan_validated_filelists_xml_path(
        BufReader::new(CapabilityVerifier {
            inner: decoded,
            opened: 0,
            compressed,
            record,
            checked: false,
        }),
        target,
    )
}

fn verified_filelists_reader<'a, R: Read + 'a>(
    input: R,
    record: &'a MetadataRecord,
) -> Result<BufReader<OpenVerifier<'a>>, MetadataError> {
    verified_metadata_reader(
        input,
        record,
        MAX_FILELISTS_COMPRESSED_BYTES,
        MAX_FILELISTS_OPEN_BYTES,
    )
}

fn verified_metadata_reader<'a, R: Read + 'a>(
    input: R,
    record: &'a MetadataRecord,
    max_compressed: u64,
    max_open: u64,
) -> Result<BufReader<OpenVerifier<'a>>, MetadataError> {
    if record.size > max_compressed {
        return Err(MetadataError::SizeMismatch {
            expected: max_compressed,
            actual: record.size,
        });
    }
    if record.open_size > max_open {
        return Err(MetadataError::SizeMismatch {
            expected: max_open,
            actual: record.open_size,
        });
    }
    let compressed = Rc::new(RefCell::new(StreamDigest::default()));
    let read_limit = record
        .size
        .checked_add(1)
        .ok_or(MetadataError::LimitExceeded {
            kind: "compressed metadata",
            maximum: record.size,
            actual: u64::MAX,
        })?;
    let hashed = DigestReader {
        inner: input.take(read_limit),
        state: Rc::clone(&compressed),
    };
    let mut buffered = BufReader::new(hashed);
    let encoding = buffered
        .fill_buf()
        .map_err(|error| MetadataError::Io(error.to_string()))
        .map(encoding)?;
    let decoded: Box<dyn Read> = match encoding {
        MetadataEncoding::Zstd => Box::new(
            zstd::stream::read::Decoder::new(buffered)
                .map_err(|error| MetadataError::Io(error.to_string()))?,
        ),
        MetadataEncoding::Gzip => Box::new(GzDecoder::new(buffered)),
        MetadataEncoding::Xml => Box::new(buffered),
    };
    let verified = OpenVerifier {
        inner: decoded,
        opened: StreamDigest::default(),
        compressed,
        record,
        checked: false,
    };
    Ok(BufReader::new(verified))
}

#[derive(Clone, Copy)]
enum MetadataEncoding {
    Zstd,
    Gzip,
    Xml,
}

fn encoding(bytes: &[u8]) -> MetadataEncoding {
    if bytes.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        MetadataEncoding::Zstd
    } else if bytes.starts_with(&[0x1f, 0x8b]) {
        MetadataEncoding::Gzip
    } else {
        MetadataEncoding::Xml
    }
}

fn validate_xml(bytes: &[u8]) -> Result<(), MetadataError> {
    let mut reader = Reader::from_reader(bytes);
    reader.config_mut().check_end_names = true;
    let mut buffer = Vec::new();
    let mut declaration_seen = false;
    let mut roots = 0_u8;
    let mut depth = 0_u64;
    loop {
        match reader.read_event_into(&mut buffer) {
            Ok(Event::Start(_)) => {
                if roots != 0 && depth == 0 {
                    return Err(MetadataError::Xml("multiple XML roots".into()));
                }
                roots = 1;
                depth = depth
                    .checked_add(1)
                    .ok_or_else(|| MetadataError::Xml("XML nesting overflow".into()))?;
            }
            Ok(Event::Empty(_)) => {
                if depth == 0 {
                    if roots != 0 {
                        return Err(MetadataError::Xml("multiple XML roots".into()));
                    }
                    roots = 1;
                }
            }
            Ok(Event::End(_)) => {
                depth = depth
                    .checked_sub(1)
                    .ok_or_else(|| MetadataError::Xml("XML end without start".into()))?;
            }
            Ok(Event::Decl(_)) => {
                if declaration_seen || roots != 0 {
                    return Err(MetadataError::Xml("misplaced XML declaration".into()));
                }
                declaration_seen = true;
            }
            Ok(Event::DocType(_)) => {
                return Err(MetadataError::Xml(
                    "doctype is not allowed in metadata XML".into(),
                ));
            }
            Ok(Event::Text(text)) if roots == 0 || depth == 0 => {
                if !crate::xml::decode_text(&text)?.trim().is_empty() {
                    return Err(MetadataError::Xml("text outside XML root".into()));
                }
            }
            Ok(Event::CData(_)) if roots == 0 || depth == 0 => {
                return Err(MetadataError::Xml("CDATA outside XML root".into()));
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(error) => return Err(MetadataError::Xml(error.to_string())),
        }
        buffer.clear();
    }
    if roots == 1 && depth == 0 {
        Ok(())
    } else {
        Err(MetadataError::Xml("incomplete XML document".into()))
    }
}

#[derive(Default)]
struct StreamDigest {
    hasher: Sha256,
    bytes: u64,
}

struct DigestReader<R> {
    inner: R,
    state: Rc<RefCell<StreamDigest>>,
}

impl<R: Read> Read for DigestReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let count = self.inner.read(buffer)?;
        let mut state = self.state.borrow_mut();
        state.bytes = state
            .bytes
            .checked_add(count as u64)
            .ok_or_else(|| io::Error::other("compressed size overflow"))?;
        state.hasher.update(&buffer[..count]);
        Ok(count)
    }
}

struct OpenVerifier<'a> {
    inner: Box<dyn Read + 'a>,
    opened: StreamDigest,
    compressed: Rc<RefCell<StreamDigest>>,
    record: &'a MetadataRecord,
    checked: bool,
}

struct CapabilityVerifier<'a, R> {
    inner: R,
    opened: u64,
    compressed: Rc<RefCell<StreamDigest>>,
    record: &'a MetadataRecord,
    checked: bool,
}

impl<R: Read> Read for CapabilityVerifier<'_, R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let count = self.inner.read(buffer)?;
        self.opened = self
            .opened
            .checked_add(count as u64)
            .ok_or_else(|| io::Error::other("open size overflow"))?;
        if self.opened > self.record.open_size {
            return Err(io::Error::other("opened metadata exceeds declared size"));
        }
        if count == 0 && !self.checked {
            self.checked = true;
            let compressed = self.compressed.borrow();
            if compressed.bytes != self.record.size
                || hex::encode(compressed.hasher.clone().finalize()) != self.record.checksum
                || self.opened != self.record.open_size
            {
                return Err(io::Error::other("metadata capability integrity mismatch"));
            }
        }
        Ok(count)
    }
}

impl Read for OpenVerifier<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let count = self.inner.read(buffer)?;
        self.opened.bytes = self
            .opened
            .bytes
            .checked_add(count as u64)
            .ok_or_else(|| io::Error::other("open size overflow"))?;
        if self.opened.bytes > self.record.open_size {
            return Err(io::Error::other("opened metadata exceeds declared size"));
        }
        self.opened.hasher.update(&buffer[..count]);
        if count == 0 && !self.checked {
            self.checked = true;
            let compressed = self.compressed.borrow();
            if compressed.bytes != self.record.size
                || hex::encode(compressed.hasher.clone().finalize()) != self.record.checksum
                || self.opened.bytes != self.record.open_size
                || hex::encode(self.opened.hasher.clone().finalize()) != self.record.open_checksum
            {
                return Err(io::Error::other("metadata stream integrity mismatch"));
            }
        }
        Ok(count)
    }
}
