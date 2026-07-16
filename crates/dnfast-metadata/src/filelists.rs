use std::{
    collections::{HashMap, HashSet},
    io::BufRead,
};

use quick_xml::{
    events::{BytesStart, Event},
    name::ResolveResult,
    reader::NsReader,
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

fn parse_filelists_with_mode<'a, R: BufRead>(
    input: R,
    retain_files: bool,
    visitor: Option<&'a mut FileVisitor<'a>>,
) -> Result<Vec<FileListPackage>, MetadataError> {
    let mut reader = NsReader::from_reader(input);
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
        match reader.read_resolved_event_into(&mut buffer) {
            Ok((namespace, Event::Start(event))) => {
                validate_resolved(&namespace)?;
                state.start(reader.decoder(), &event)?;
            }
            Ok((namespace, Event::Empty(event))) => {
                validate_resolved(&namespace)?;
                state.empty(reader.decoder(), &event)?;
            }
            Ok((_, Event::Text(event))) if state.file_text.is_some() => {
                state.append_file_text(&decode_text(&event)?)?
            }
            Ok((_, Event::GeneralRef(event))) if state.file_text.is_some() => {
                state.append_file_text(&decode_reference(&event)?)?
            }
            Ok((_, Event::Text(event))) if !state.root_seen || state.root_closed => {
                if !decode_text(&event)?.trim().is_empty() {
                    return Err(MetadataError::Xml("text outside filelists root".into()));
                }
            }
            Ok((_, Event::End(event))) => state.end(event.name().as_ref())?,
            Ok((_, Event::Decl(_))) if !state.root_seen && !state.declaration_seen => {
                state.declaration_seen = true
            }
            Ok((_, Event::Decl(_) | Event::DocType(_))) => {
                return Err(MetadataError::Xml(
                    "misplaced XML declaration or doctype".into(),
                ));
            }
            Ok((_, Event::Comment(_) | Event::PI(_))) => {}
            Ok((_, Event::Eof)) => break,
            Ok((_, _)) if !state.root_seen || state.root_closed => {
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
        self.check_namespace(decoder, event)?;
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
            b"file"
                if self.current.is_some() && self.file_text.replace(String::new()).is_some() =>
            {
                return Err(MetadataError::Xml("nested filelists file".into()));
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
        self.check_namespace(decoder, event)?;
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

    fn finish_file(&mut self) -> Result<(), MetadataError> {
        let value = self
            .file_text
            .take()
            .ok_or_else(|| MetadataError::Xml("file end without start".into()))?;
        if !value.starts_with('/')
            || value.contains("//")
            || value.chars().any(char::is_control)
            || value.split('/').any(|part| part == "." || part == "..")
        {
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

    fn check_namespace(
        &self,
        decoder: quick_xml::encoding::Decoder,
        event: &BytesStart<'_>,
    ) -> Result<(), MetadataError> {
        if namespace(decoder, event)?
            .is_some_and(|value| value != "http://linux.duke.edu/metadata/filelists")
        {
            return Err(MetadataError::Xml("unexpected filelists namespace".into()));
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
fn validate_resolved(namespace: &ResolveResult<'_>) -> Result<(), MetadataError> {
    match namespace {
        ResolveResult::Bound(actual)
            if actual.as_ref() == b"http://linux.duke.edu/metadata/filelists" =>
        {
            Ok(())
        }
        _ => Err(MetadataError::Xml(
            "unexpected filelists resolved namespace".into(),
        )),
    }
}
