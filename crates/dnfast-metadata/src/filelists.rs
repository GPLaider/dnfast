use std::{
    collections::{HashMap, HashSet},
    io::BufRead,
};

use quick_xml::{
    events::{BytesStart, BytesText, Event},
    reader::Reader,
};
use serde::{Deserialize, Serialize};

use crate::{CompletePackage, PrimaryPackageIdentity};
use crate::{
    MAX_FILE_PATHS, MAX_FILES_PER_PACKAGE, MAX_PACKAGES, MAX_XML_TEXT_BYTES, MetadataError,
    limits::{checked_increment, checked_limit},
    xml::{attribute_streaming, decode_reference, decode_text, parse_number},
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FileListPackage {
    pub package_id: String,
    pub name: String,
    pub arch: String,
    pub epoch: String,
    pub version: String,
    pub release: String,
    pub files: Vec<String>,
}

pub fn validate_filelists_generation(
    primary: &[CompletePackage],
    filelists: &[FileListPackage],
) -> Result<(), MetadataError> {
    if primary.len() != filelists.len() {
        return Err(MetadataError::Xml(
            "primary/filelists package count mismatch".into(),
        ));
    }
    let primary_by_id = primary
        .iter()
        .map(|package| (package.checksum.as_str(), package))
        .collect::<HashMap<_, _>>();
    if primary_by_id.len() != primary.len() {
        return Err(MetadataError::Xml(
            "duplicate primary package checksum".into(),
        ));
    }
    let mut seen = HashSet::with_capacity(filelists.len());
    for files in filelists {
        if !seen.insert(files.package_id.as_str()) {
            return Err(MetadataError::Xml("duplicate filelists package id".into()));
        }
        let package = primary_by_id
            .get(files.package_id.as_str())
            .ok_or_else(|| MetadataError::Xml("mixed primary/filelists generation".into()))?;
        if package.name != files.name
            || package.arch != files.arch
            || package.epoch != files.epoch
            || package.version != files.version
            || package.release != files.release
        {
            return Err(MetadataError::Xml(
                "primary/filelists identity mismatch".into(),
            ));
        }
    }
    Ok(())
}

pub fn validate_filelists_identities(
    primary: &[PrimaryPackageIdentity],
    filelists: &[FileListPackage],
) -> Result<(), MetadataError> {
    if primary.len() != filelists.len() {
        return Err(MetadataError::Xml(
            "primary/filelists package count mismatch".into(),
        ));
    }
    let primary_by_id = primary
        .iter()
        .map(|package| (package.checksum.as_str(), package))
        .collect::<HashMap<_, _>>();
    if primary_by_id.len() != primary.len() {
        return Err(MetadataError::Xml(
            "duplicate primary package checksum".into(),
        ));
    }
    let mut seen = HashSet::with_capacity(filelists.len());
    for files in filelists {
        if !seen.insert(files.package_id.as_str()) {
            return Err(MetadataError::Xml("duplicate filelists package id".into()));
        }
        let package = primary_by_id
            .get(files.package_id.as_str())
            .ok_or_else(|| MetadataError::Xml("mixed primary/filelists generation".into()))?;
        if package.name != files.name
            || package.arch != files.arch
            || package.epoch != files.epoch
            || package.version != files.version
            || package.release != files.release
        {
            return Err(MetadataError::Xml(
                "primary/filelists identity mismatch".into(),
            ));
        }
    }
    Ok(())
}

pub fn publish_validated<T>(
    primary: &[CompletePackage],
    filelists: &[FileListPackage],
    publish: impl FnOnce() -> T,
) -> Result<T, MetadataError> {
    validate_filelists_generation(primary, filelists)?;
    Ok(publish())
}

#[derive(Default)]
struct Builder {
    package_id: String,
    name: String,
    arch: String,
    epoch: String,
    version: String,
    release: String,
    files: Vec<String>,
    file_count: u64,
}

type FileVisitor<'a> = dyn FnMut(&str, &str) -> Result<(), MetadataError> + 'a;

#[derive(Default)]
struct State<'a> {
    current: Option<Builder>,
    file_text: Option<String>,
    spare_file_text: String,
    packages: Vec<FileListPackage>,
    declared: Option<u64>,
    root_seen: bool,
    root_closed: bool,
    declaration_seen: bool,
    paths: u64,
    retain_files: bool,
    visitor: Option<&'a mut FileVisitor<'a>>,
}

pub fn parse_filelists<R: BufRead>(input: R) -> Result<Vec<FileListPackage>, MetadataError> {
    parse_filelists_with_mode(input, true, None)
}

pub fn validate_filelists_xml<R: BufRead>(
    input: R,
    primary: &[CompletePackage],
) -> Result<(), MetadataError> {
    let filelists = parse_filelists_with_mode(input, false, None)?;
    validate_filelists_generation(primary, &filelists)
}

pub fn validate_filelists_xml_identities<R: BufRead>(
    input: R,
    primary: &[PrimaryPackageIdentity],
) -> Result<(), MetadataError> {
    let filelists = parse_filelists_with_mode(input, false, None)?;
    validate_filelists_identities(primary, &filelists)
}

pub(crate) fn visit_filelists_xml_identities<R: BufRead>(
    input: R,
    primary: &[PrimaryPackageIdentity],
    visitor: &mut dyn FnMut(&str, &str) -> Result<(), MetadataError>,
) -> Result<(), MetadataError> {
    let filelists = parse_filelists_with_mode(input, false, Some(visitor))?;
    validate_filelists_identities(primary, &filelists)
}

/// Scans a filelists document that has already passed the complete structural
/// and primary-identity validation gate. The caller still supplies a reader
/// that verifies the compressed and opened repomd checksums through EOF; this
/// tokenizer only avoids rebuilding the full XML event graph for one exact
/// path lookup.
pub(crate) fn scan_validated_filelists_xml_path<R: BufRead>(
    mut input: R,
    target: &str,
) -> Result<Vec<String>, MetadataError> {
    let mut scanner = ValidatedPathScanner::new(target);
    let mut buffer = [0_u8; 256 * 1024];
    loop {
        let count = input
            .read(&mut buffer)
            .map_err(|error| MetadataError::Io(error.to_string()))?;
        if count == 0 {
            break;
        }
        scanner.push(&buffer[..count])?;
    }
    scanner.finish()
}

struct ValidatedPathScanner<'a> {
    target: &'a str,
    tag: Vec<u8>,
    file: Vec<u8>,
    file_length: usize,
    file_matches: bool,
    file_complex: bool,
    package_id: Option<String>,
    providers: Vec<String>,
    file_active: bool,
    state: LexicalState,
    quote: Option<u8>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum LexicalState {
    Text,
    Tag,
    Comment,
    ProcessingInstruction,
}

impl<'a> ValidatedPathScanner<'a> {
    fn new(target: &'a str) -> Self {
        Self {
            target,
            tag: Vec::with_capacity(256),
            file: Vec::with_capacity(256),
            file_length: 0,
            file_matches: true,
            file_complex: false,
            package_id: None,
            providers: Vec::new(),
            file_active: false,
            state: LexicalState::Text,
            quote: None,
        }
    }

    fn push(&mut self, bytes: &[u8]) -> Result<(), MetadataError> {
        let mut offset = 0;
        while offset < bytes.len() {
            if self.state == LexicalState::Text {
                let remaining = &bytes[offset..];
                let text_length = memchr::memchr(b'<', remaining).unwrap_or(remaining.len());
                if self.file_active && text_length != 0 {
                    self.push_file_bytes(&remaining[..text_length])?;
                }
                offset += text_length;
                if offset == bytes.len() {
                    break;
                }
                self.tag.clear();
                self.quote = None;
                self.state = LexicalState::Tag;
                offset += 1;
                // Regular file entries dominate Fedora filelists. Consume
                // their two validated common tags as slices instead of
                // growing and comparing a Vec byte by byte. A tag split at a
                // reader boundary safely falls back to the lexical machine.
                let tag = &bytes[offset..];
                if tag.starts_with(b"file>") {
                    self.begin_file();
                    self.state = LexicalState::Text;
                    offset += b"file>".len();
                } else if tag.starts_with(b"/file>") {
                    self.end_file()?;
                    self.state = LexicalState::Text;
                    offset += b"/file>".len();
                }
                continue;
            }
            let byte = bytes[offset];
            offset += 1;
            match self.state {
                LexicalState::Text => unreachable!("text is handled in bulk"),
                LexicalState::Tag => {
                    self.tag.push(byte);
                    if self.tag == b"!--" {
                        self.state = LexicalState::Comment;
                    } else if self.tag == b"?" {
                        self.state = LexicalState::ProcessingInstruction;
                    } else if let Some(quote) = self.quote {
                        if byte == quote {
                            self.quote = None;
                        }
                    } else if matches!(byte, b'\'' | b'"') {
                        self.quote = Some(byte);
                    } else if byte == b'>' {
                        self.finish_tag()?;
                        self.state = LexicalState::Text;
                    }
                }
                LexicalState::Comment => {
                    self.tag.push(byte);
                    if self.tag.ends_with(b"-->") {
                        self.state = LexicalState::Text;
                    }
                }
                LexicalState::ProcessingInstruction => {
                    self.tag.push(byte);
                    if self.tag.ends_with(b"?>") {
                        self.state = LexicalState::Text;
                    }
                }
            }
        }
        Ok(())
    }

    fn push_file_bytes(&mut self, bytes: &[u8]) -> Result<(), MetadataError> {
        let previous_length = self.file_length;
        self.file_length = self
            .file_length
            .checked_add(bytes.len())
            .ok_or_else(|| MetadataError::Xml("file path length overflow".into()))?;
        checked_limit(
            self.file_length as u64,
            MAX_XML_TEXT_BYTES as u64,
            "XML text",
        )?;
        if self.file_complex {
            self.file.extend_from_slice(bytes);
        } else if !self.file_matches {
            return Ok(());
        } else if let Some(ampersand) = memchr::memchr(b'&', bytes) {
            let prefix_end = previous_length + ampersand;
            self.file_matches &= self.target.as_bytes().get(previous_length..prefix_end)
                == Some(&bytes[..ampersand]);
            if !self.file_matches || prefix_end > self.target.len() {
                return Ok(());
            }
            self.file_complex = true;
            self.file
                .extend_from_slice(&self.target.as_bytes()[..prefix_end]);
            self.file.extend_from_slice(&bytes[ampersand..]);
        } else {
            self.file_matches = self
                .target
                .as_bytes()
                .get(previous_length..self.file_length)
                == Some(bytes);
        }
        Ok(())
    }

    fn finish_tag(&mut self) -> Result<(), MetadataError> {
        let tag = self.tag.strip_suffix(b">").unwrap_or(&self.tag);
        if tag_name(tag, b"package") {
            self.package_id = Some(required_raw_attribute(tag, b"pkgid")?);
        } else if tag
            .strip_prefix(b"/")
            .is_some_and(|tag| tag_name(tag, b"package"))
        {
            self.package_id = None;
        } else if tag_name(tag, b"file") {
            self.begin_file();
        } else if tag
            .strip_prefix(b"/")
            .is_some_and(|tag| tag_name(tag, b"file"))
        {
            self.end_file()?;
        }
        Ok(())
    }

    fn begin_file(&mut self) {
        self.file.clear();
        self.file_length = 0;
        self.file_matches = true;
        self.file_complex = false;
        self.file_active = true;
    }

    fn end_file(&mut self) -> Result<(), MetadataError> {
        if !self.file_active {
            return Ok(());
        }
        let matched = if self.file_complex {
            let raw = std::str::from_utf8(&self.file)
                .map_err(|error| MetadataError::Xml(error.to_string()))?;
            quick_xml::escape::unescape(raw)
                .map_err(|error| MetadataError::Xml(error.to_string()))?
                == self.target
        } else {
            self.file_matches && self.file_length == self.target.len()
        };
        if matched {
            let package_id = self
                .package_id
                .as_ref()
                .ok_or_else(|| MetadataError::Xml("file outside filelists package".into()))?;
            self.providers.push(package_id.clone());
        }
        self.file_active = false;
        Ok(())
    }

    fn finish(mut self) -> Result<Vec<String>, MetadataError> {
        if self.state != LexicalState::Text || self.file_active || self.package_id.is_some() {
            return Err(MetadataError::Xml(
                "validated filelists scan ended inside an element".into(),
            ));
        }
        self.providers.sort();
        self.providers.dedup();
        Ok(self.providers)
    }
}

fn tag_name(tag: &[u8], expected: &[u8]) -> bool {
    tag.starts_with(expected)
        && tag
            .get(expected.len())
            .is_none_or(|byte| byte.is_ascii_whitespace() || *byte == b'/' || *byte == b'>')
}

fn required_raw_attribute(tag: &[u8], expected: &[u8]) -> Result<String, MetadataError> {
    let mut offset = tag
        .iter()
        .position(u8::is_ascii_whitespace)
        .ok_or_else(|| MetadataError::Xml("package attributes are absent".into()))?;
    while offset < tag.len() {
        while tag
            .get(offset)
            .is_some_and(|byte| byte.is_ascii_whitespace())
        {
            offset += 1;
        }
        let name_start = offset;
        while tag
            .get(offset)
            .is_some_and(|byte| !byte.is_ascii_whitespace() && *byte != b'=')
        {
            offset += 1;
        }
        let name = &tag[name_start..offset];
        while tag
            .get(offset)
            .is_some_and(|byte| byte.is_ascii_whitespace())
        {
            offset += 1;
        }
        if tag.get(offset) != Some(&b'=') {
            return Err(MetadataError::Xml("invalid package attribute".into()));
        }
        offset += 1;
        while tag
            .get(offset)
            .is_some_and(|byte| byte.is_ascii_whitespace())
        {
            offset += 1;
        }
        let quote = *tag
            .get(offset)
            .filter(|byte| matches!(byte, b'\'' | b'"'))
            .ok_or_else(|| MetadataError::Xml("unquoted package attribute".into()))?;
        offset += 1;
        let value_start = offset;
        while tag.get(offset).is_some_and(|byte| *byte != quote) {
            offset += 1;
        }
        let raw = tag
            .get(value_start..offset)
            .ok_or_else(|| MetadataError::Xml("incomplete package attribute".into()))?;
        offset += 1;
        if name == expected {
            let raw =
                std::str::from_utf8(raw).map_err(|error| MetadataError::Xml(error.to_string()))?;
            return quick_xml::escape::unescape(raw)
                .map(|value| value.into_owned())
                .map_err(|error| MetadataError::Xml(error.to_string()));
        }
    }
    Err(MetadataError::Xml("missing required attribute".into()))
}

fn parse_filelists_with_mode<'a, R: BufRead>(
    input: R,
    retain_files: bool,
    visitor: Option<&'a mut FileVisitor<'a>>,
) -> Result<Vec<FileListPackage>, MetadataError> {
    let mut reader = Reader::from_reader(input);
    // Preserve text around entity-reference events until the complete path is
    // reassembled and validated.
    reader.config_mut().trim_text(false);
    reader.config_mut().check_end_names = true;
    let mut buffer = Vec::new();
    let mut state = State {
        retain_files,
        visitor,
        ..State::default()
    };
    loop {
        match reader.read_event_into(&mut buffer) {
            Ok(Event::Start(event)) => state.start(reader.decoder(), &event)?,
            Ok(Event::Empty(event)) => state.empty(reader.decoder(), &event)?,
            Ok(Event::Text(event)) if state.file_text.is_some() => {
                state.append_file_event(&event)?
            }
            Ok(Event::GeneralRef(event)) if state.file_text.is_some() => {
                state.append_file_text(&decode_reference(&event)?)?
            }
            Ok(Event::Text(event)) if !state.root_seen || state.root_closed => {
                if !decode_text(&event)?.trim().is_empty() {
                    return Err(MetadataError::Xml("text outside filelists root".into()));
                }
            }
            Ok(Event::End(event)) => state.end(event.name().as_ref())?,
            Ok(Event::Decl(_)) if !state.root_seen && !state.declaration_seen => {
                state.declaration_seen = true
            }
            Ok(Event::Decl(_) | Event::DocType(_)) => {
                return Err(MetadataError::Xml(
                    "misplaced XML declaration or doctype".into(),
                ));
            }
            Ok(Event::Comment(_) | Event::PI(_)) => {}
            Ok(Event::Eof) => break,
            Ok(_) if !state.root_seen || state.root_closed => {
                return Err(MetadataError::Xml("content outside filelists root".into()));
            }
            Err(error) => return Err(MetadataError::Xml(error.to_string())),
            _ => {}
        }
        buffer.clear();
    }
    state.finish()
}

impl State<'_> {
    fn start(
        &mut self,
        decoder: quick_xml::encoding::Decoder,
        event: &BytesStart<'_>,
    ) -> Result<(), MetadataError> {
        if self.root_closed {
            return Err(MetadataError::Xml("content after filelists root".into()));
        }
        if !self.root_seen {
            if event.name().as_ref() != b"filelists"
                || namespace(decoder, event)?.as_deref()
                    != Some("http://linux.duke.edu/metadata/filelists")
            {
                return Err(MetadataError::Xml(
                    "unexpected filelists root or namespace".into(),
                ));
            }
            let declared = parse_number(&required(decoder, event, b"packages")?)?;
            checked_limit(declared, MAX_PACKAGES, "packages")?;
            self.declared = Some(declared);
            self.root_seen = true;
            return Ok(());
        }
        reject_nested_namespace_declarations(event)?;
        reject_prefix(event.name().as_ref())?;
        match event.name().as_ref() {
            b"package" => {
                if self.current.is_some() {
                    return Err(MetadataError::Xml("nested filelists package".into()));
                }
                self.current = Some(Builder {
                    package_id: required(decoder, event, b"pkgid")?,
                    name: required(decoder, event, b"name")?,
                    arch: required(decoder, event, b"arch")?,
                    ..Builder::default()
                });
            }
            b"file" if self.current.is_some() => {
                if self.file_text.is_some() {
                    return Err(MetadataError::Xml("nested filelists file".into()));
                }
                self.file_text = Some(std::mem::take(&mut self.spare_file_text));
            }
            _ => {}
        }
        Ok(())
    }

    fn empty(
        &mut self,
        decoder: quick_xml::encoding::Decoder,
        event: &BytesStart<'_>,
    ) -> Result<(), MetadataError> {
        if !self.root_seen || self.root_closed {
            return Err(MetadataError::Xml("element outside filelists root".into()));
        }
        reject_nested_namespace_declarations(event)?;
        reject_prefix(event.name().as_ref())?;
        if event.name().as_ref() == b"version" {
            let package = self
                .current
                .as_mut()
                .ok_or_else(|| MetadataError::Xml("version outside filelists package".into()))?;
            package.epoch =
                attribute_streaming(decoder, event, b"epoch")?.unwrap_or_else(|| "0".into());
            package.version = required(decoder, event, b"ver")?;
            package.release = required(decoder, event, b"rel")?;
        }
        Ok(())
    }

    fn append_file_text(&mut self, value: &str) -> Result<(), MetadataError> {
        let file = self
            .file_text
            .as_mut()
            .ok_or_else(|| MetadataError::Xml("file text outside file".into()))?;
        file.push_str(value);
        checked_limit(file.len() as u64, MAX_XML_TEXT_BYTES as u64, "XML text")?;
        Ok(())
    }

    fn append_file_event(&mut self, event: &BytesText<'_>) -> Result<(), MetadataError> {
        let decoded = event
            .decode()
            .map_err(|error| MetadataError::Xml(error.to_string()))?;
        let unescaped = quick_xml::escape::unescape(&decoded)
            .map_err(|error| MetadataError::Xml(error.to_string()))?;
        self.append_file_text(&unescaped)
    }

    fn finish_file(&mut self) -> Result<(), MetadataError> {
        let mut value = self
            .file_text
            .take()
            .ok_or_else(|| MetadataError::Xml("file end without start".into()))?;
        if !safe_file_path(&value) {
            return Err(MetadataError::UnsafeLocation(value));
        }
        let package = self
            .current
            .as_mut()
            .ok_or_else(|| MetadataError::Xml("file outside filelists package".into()))?;
        package.file_count = checked_increment(
            package.file_count,
            MAX_FILES_PER_PACKAGE as u64,
            "files per package",
        )?;
        self.paths = checked_increment(self.paths, MAX_FILE_PATHS, "file paths")?;
        if let Some(visitor) = self.visitor.as_mut() {
            visitor(&package.package_id, &value)?;
        }
        if self.retain_files {
            package.files.push(value);
        } else {
            value.clear();
            self.spare_file_text = value;
        }
        Ok(())
    }

    fn end(&mut self, name: &[u8]) -> Result<(), MetadataError> {
        if !self.root_seen || self.root_closed {
            return Err(MetadataError::Xml(
                "end element outside filelists root".into(),
            ));
        }
        if name == b"file" {
            self.finish_file()?;
        } else if name == b"package" {
            if self.file_text.is_some() {
                return Err(MetadataError::Xml("unclosed filelists file".into()));
            }
            let package = self
                .current
                .take()
                .ok_or_else(|| MetadataError::Xml("package end without start".into()))?;
            if package.version.is_empty() || package.release.is_empty() {
                return Err(MetadataError::Xml(
                    "filelists package missing version".into(),
                ));
            }
            self.packages.push(FileListPackage {
                package_id: package.package_id,
                name: package.name,
                arch: package.arch,
                epoch: package.epoch,
                version: package.version,
                release: package.release,
                files: package.files,
            });
        } else if name == b"filelists" {
            if self.current.is_some() {
                return Err(MetadataError::Xml("unclosed filelists package".into()));
            }
            self.root_closed = true;
        }
        Ok(())
    }

    fn finish(self) -> Result<Vec<FileListPackage>, MetadataError> {
        if !self.root_seen || !self.root_closed {
            return Err(MetadataError::Xml("incomplete filelists root".into()));
        }
        let declared = self
            .declared
            .ok_or_else(|| MetadataError::Xml("missing filelists package count".into()))?;
        if self.packages.len() as u64 != declared {
            return Err(MetadataError::Xml(format!(
                "filelists package count mismatch: declared {declared}, parsed {}",
                self.packages.len()
            )));
        }
        Ok(self.packages)
    }
}

fn safe_file_path(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.first() != Some(&b'/') {
        return false;
    }
    let mut segment_length = 0_usize;
    let mut segment_is_dots = true;
    for &byte in &bytes[1..] {
        if byte < b' ' || byte == 0x7f {
            return false;
        }
        if byte == b'/' {
            if segment_length == 0 || (segment_is_dots && matches!(segment_length, 1 | 2)) {
                return false;
            }
            segment_length = 0;
            segment_is_dots = true;
        } else {
            segment_length += 1;
            segment_is_dots &= byte == b'.';
        }
    }
    !(segment_is_dots && matches!(segment_length, 1 | 2))
        && (value.is_ascii() || !value.chars().any(char::is_control))
}

fn namespace(
    decoder: quick_xml::encoding::Decoder,
    event: &BytesStart<'_>,
) -> Result<Option<String>, MetadataError> {
    attribute_streaming(decoder, event, b"xmlns")
}
fn required(
    decoder: quick_xml::encoding::Decoder,
    event: &BytesStart<'_>,
    name: &[u8],
) -> Result<String, MetadataError> {
    attribute_streaming(decoder, event, name)?
        .ok_or_else(|| MetadataError::Xml("missing required attribute".into()))
}
fn reject_prefix(name: &[u8]) -> Result<(), MetadataError> {
    if name.contains(&b':') {
        return Err(MetadataError::Xml(
            "unexpected filelists namespace prefix".into(),
        ));
    }
    Ok(())
}
fn reject_nested_namespace_declarations(event: &BytesStart<'_>) -> Result<(), MetadataError> {
    for attribute in event.attributes() {
        let attribute = attribute.map_err(|error| MetadataError::Xml(error.to_string()))?;
        let name = attribute.key.as_ref();
        if name == b"xmlns" || name.starts_with(b"xmlns:") {
            return Err(MetadataError::Xml(
                "nested filelists namespace declaration".into(),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::safe_file_path;

    #[test]
    fn file_path_validation_rejects_traversal_repetition_and_unicode_controls() {
        assert!(safe_file_path("/usr/share/한글/파일"));
        assert!(safe_file_path("/"));
        assert!(safe_file_path("/usr/share/"));
        for unsafe_path in [
            "relative/path",
            "/usr//share",
            "/usr/./share",
            "/usr/../share",
            "/usr/share/\u{009f}hidden",
            "/usr/share/\nfile",
        ] {
            assert!(!safe_file_path(unsafe_path), "accepted {unsafe_path:?}");
        }
    }
}
