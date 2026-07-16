use std::io::Read;

use quick_xml::{
    events::{BytesStart, Event},
    name::ResolveResult,
    reader::NsReader,
};
use serde::{Deserialize, Serialize};

use crate::{
    MAX_FILE_PATHS, MAX_FILES_PER_PACKAGE, MAX_XML_TEXT_BYTES, MetadataError,
    limits::{checked_increment, checked_limit},
    relations::{MAX_RELATIONS, MAX_RELATIONS_PER_PACKAGE, Relation, parse_relation},
    xml::{attribute_streaming, decode_reference, decode_text, parse_number},
};

pub const MAX_PACKAGES: u64 = 2_000_000;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CompletePackage {
    pub name: String,
    pub arch: String,
    pub epoch: String,
    pub version: String,
    pub release: String,
    pub summary: String,
    pub checksum: String,
    pub location: String,
    pub description: String,
    pub vendor: String,
    pub build_host: String,
    pub source_rpm: String,
    pub package_size: u64,
    pub installed_size: u64,
    pub archive_size: u64,
    pub build_time: u64,
    pub provides: Vec<Relation>,
    pub requires: Vec<Relation>,
    pub recommends: Vec<Relation>,
    pub suggests: Vec<Relation>,
    pub supplements: Vec<Relation>,
    pub enhances: Vec<Relation>,
    pub conflicts: Vec<Relation>,
    pub obsoletes: Vec<Relation>,
    pub files: Vec<String>,
}

impl CompletePackage {
    pub fn nevra(&self) -> String {
        format!(
            "{}-{}:{}-{}.{}",
            self.name, self.epoch, self.version, self.release, self.arch
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Package {
    pub name: String,
    pub arch: String,
    pub epoch: String,
    pub version: String,
    pub release: String,
    pub summary: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrimaryPackageIdentity {
    pub checksum: String,
    pub name: String,
    pub arch: String,
    pub epoch: String,
    pub version: String,
    pub release: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedPrimary {
    pub packages: Vec<Package>,
    pub identities: Vec<PrimaryPackageIdentity>,
}

impl Package {
    pub fn nevra(&self) -> String {
        format!(
            "{}-{}:{}-{}.{}",
            self.name, self.epoch, self.version, self.release, self.arch
        )
    }
}

#[derive(Default)]
struct Builder {
    name: String,
    arch: String,
    epoch: String,
    version: String,
    release: String,
    summary: String,
    checksum: String,
    location: String,
    description: String,
    vendor: String,
    build_host: String,
    source_rpm: String,
    package_size: u64,
    installed_size: u64,
    archive_size: u64,
    build_time: u64,
    relation_count: usize,
    provides: Vec<Relation>,
    requires: Vec<Relation>,
    recommends: Vec<Relation>,
    suggests: Vec<Relation>,
    supplements: Vec<Relation>,
    enhances: Vec<Relation>,
    conflicts: Vec<Relation>,
    obsoletes: Vec<Relation>,
    files: Vec<String>,
}

#[derive(Default)]
struct State {
    current: Option<Builder>,
    field: Option<Vec<u8>>,
    relation_group: Option<Vec<u8>>,
    packages: Vec<CompletePackage>,
    search_packages: Vec<Package>,
    identities: Vec<PrimaryPackageIdentity>,
    retain_complete: bool,
    parsed_packages: u64,
    root_seen: bool,
    root_closed: bool,
    rpm_namespace: bool,
    declared: Option<u64>,
    declaration_seen: bool,
    relations: u64,
    paths: u64,
}

pub fn parse_primary<R: Read>(input: R) -> Result<Vec<Package>, MetadataError> {
    parse_primary_validated(input).map(|validated| validated.packages)
}

pub fn parse_primary_records<R: Read>(input: R) -> Result<Vec<CompletePackage>, MetadataError> {
    let records = parse_complete(input)?;
    if records
        .iter()
        .any(|record| record.location.is_empty() || record.checksum.is_empty())
    {
        return Err(MetadataError::Xml(
            "package missing complete record fields".into(),
        ));
    }
    Ok(records)
}

fn parse_complete<R: Read>(input: R) -> Result<Vec<CompletePackage>, MetadataError> {
    let state = parse_with_mode(input, true)?;
    Ok(state.packages)
}

pub fn parse_primary_validated<R: Read>(input: R) -> Result<ValidatedPrimary, MetadataError> {
    let state = parse_with_mode(input, false)?;
    Ok(ValidatedPrimary {
        packages: state.search_packages,
        identities: state.identities,
    })
}

fn parse_with_mode<R: Read>(input: R, retain_complete: bool) -> Result<State, MetadataError> {
    let mut reader = NsReader::from_reader(std::io::BufReader::new(input));
    // Text and entity references are separate events.  Trimming each event
    // independently would turn `A &amp; B` into `A&B`.
    reader.config_mut().trim_text(false);
    reader.config_mut().check_end_names = true;
    let mut buffer = Vec::new();
    let mut state = State {
        retain_complete,
        ..State::default()
    };
    loop {
        match reader.read_resolved_event_into(&mut buffer) {
            Ok((namespace, Event::Start(event))) => {
                let valid = resolved_is_valid(&namespace, event.name().as_ref());
                state.start(reader.decoder(), &event)?;
                if !valid {
                    return Err(MetadataError::Xml(
                        "unexpected primary resolved namespace".into(),
                    ));
                }
            }
            Ok((namespace, Event::Empty(event))) => {
                let valid = resolved_is_valid(&namespace, event.name().as_ref());
                state.empty(reader.decoder(), &event)?;
                if !valid {
                    return Err(MetadataError::Xml(
                        "unexpected primary resolved namespace".into(),
                    ));
                }
            }
            Ok((_, Event::Text(event))) if !state.root_seen || state.root_closed => {
                if !decode_text(&event)?.trim().is_empty() {
                    return Err(MetadataError::Xml("text outside primary root".into()));
                }
            }
            Ok((_, Event::Text(event))) => state.text(&event)?,
            Ok((_, Event::GeneralRef(event))) if state.field.is_some() => {
                state.append_field(&decode_reference(&event)?)?
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
                return Err(MetadataError::Xml("content outside primary root".into()));
            }
            Err(error) => return Err(MetadataError::Xml(error.to_string())),
            _ => {}
        }
        buffer.clear();
    }
    state.finish()?;
    Ok(state)
}

impl State {
    fn start(
        &mut self,
        decoder: quick_xml::encoding::Decoder,
        event: &BytesStart<'_>,
    ) -> Result<(), MetadataError> {
        if self.root_closed {
            return Err(MetadataError::Xml("content after primary root".into()));
        }
        if !self.root_seen {
            if event.name().as_ref() != b"metadata"
                || namespace(decoder, event)?.as_deref()
                    != Some("http://linux.duke.edu/metadata/common")
            {
                return Err(MetadataError::Xml(
                    "unexpected primary root or namespace".into(),
                ));
            }
            let count = parse_number(
                &attribute_streaming(decoder, event, b"packages")?
                    .ok_or_else(|| MetadataError::Xml("missing primary package count".into()))?,
            )?;
            checked_limit(count, MAX_PACKAGES, "packages")?;
            let rpm = attribute_streaming(decoder, event, b"xmlns:rpm")?;
            if rpm
                .as_deref()
                .is_some_and(|value| value != "http://linux.duke.edu/metadata/rpm")
            {
                return Err(MetadataError::Xml("unexpected rpm namespace".into()));
            }
            self.rpm_namespace = rpm.is_some();
            self.declared = Some(count);
            self.root_seen = true;
            return Ok(());
        }
        self.check_namespace(decoder, event)?;
        validate_prefix(event.name().as_ref(), self.rpm_namespace)?;
        match local_name(event.name().as_ref()) {
            b"package" => {
                if self.current.is_some() {
                    return Err(MetadataError::Xml("nested primary package".into()));
                }
                if attribute_streaming(decoder, event, b"type")?.as_deref() != Some("rpm") {
                    return Err(MetadataError::Xml("primary package type is not rpm".into()));
                }
                self.current = Some(Builder::default());
            }
            b"checksum" if self.current.is_some() => {
                if attribute_streaming(decoder, event, b"type")?.as_deref() != Some("sha256")
                    || attribute_streaming(decoder, event, b"pkgid")?.as_deref() != Some("YES")
                {
                    return Err(MetadataError::UnsupportedChecksum(
                        "primary package checksum declaration".into(),
                    ));
                }
                self.field = Some(b"checksum".to_vec());
            }
            name @ (b"name" | b"arch" | b"summary" | b"description" | b"vendor" | b"buildhost"
            | b"sourcerpm" | b"file")
                if self.current.is_some() =>
            {
                if name == b"file" {
                    let package = self.current.as_mut().expect("checked above");
                    checked_increment(
                        package.files.len() as u64,
                        MAX_FILES_PER_PACKAGE as u64,
                        "files per package",
                    )?;
                    self.paths = checked_increment(self.paths, MAX_FILE_PATHS, "file paths")?;
                    package.files.push(String::new());
                }
                self.field = Some(name.to_vec())
            }
            name @ (b"provides" | b"requires" | b"recommends" | b"suggests" | b"supplements"
            | b"enhances" | b"conflicts" | b"obsoletes")
                if self.current.is_some() =>
            {
                self.relation_group = Some(name.to_vec())
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
            return Err(MetadataError::Xml("element outside primary root".into()));
        }
        self.check_namespace(decoder, event)?;
        validate_prefix(event.name().as_ref(), self.rpm_namespace)?;
        let Some(package) = self.current.as_mut() else {
            return Ok(());
        };
        match local_name(event.name().as_ref()) {
            b"version" => fill_version(decoder, event, package)?,
            b"location" => package.location = required_attr(decoder, event, b"href")?,
            b"time" => package.build_time = optional_number(decoder, event, b"build")?,
            b"size" => {
                package.package_size = optional_number(decoder, event, b"package")?;
                package.installed_size = optional_number(decoder, event, b"installed")?;
                package.archive_size = optional_number(decoder, event, b"archive")?;
            }
            b"entry" if self.relation_group.is_some() => {
                let relation = parse_relation(decoder, event)?;
                self.relations = checked_increment(self.relations, MAX_RELATIONS, "relations")?;
                package.relation_count = checked_increment(
                    package.relation_count as u64,
                    MAX_RELATIONS_PER_PACKAGE as u64,
                    "relations per package",
                )? as usize;
                push_relation(package, self.relation_group.as_deref(), relation)?;
            }
            _ => {}
        }
        Ok(())
    }

    fn text(&mut self, event: &quick_xml::events::BytesText<'_>) -> Result<(), MetadataError> {
        let value = decode_text(event)?;
        self.append_field(&value)
    }

    fn append_field(&mut self, value: &str) -> Result<(), MetadataError> {
        if let Some(package) = self.current.as_mut() {
            let target = match self.field.as_deref() {
                Some(b"name") => Some(&mut package.name),
                Some(b"arch") => Some(&mut package.arch),
                Some(b"summary") => Some(&mut package.summary),
                Some(b"description") => Some(&mut package.description),
                Some(b"checksum") => Some(&mut package.checksum),
                Some(b"vendor") => Some(&mut package.vendor),
                Some(b"buildhost") => Some(&mut package.build_host),
                Some(b"sourcerpm") => Some(&mut package.source_rpm),
                Some(b"file") => package.files.last_mut(),
                _ => None,
            };
            if let Some(target) = target {
                target.push_str(value);
                checked_limit(target.len() as u64, MAX_XML_TEXT_BYTES as u64, "XML text")?;
            }
        }
        Ok(())
    }

    fn end(&mut self, name: &[u8]) -> Result<(), MetadataError> {
        if !self.root_seen || self.root_closed {
            return Err(MetadataError::Xml(
                "end element outside primary root".into(),
            ));
        }
        if name == b"package" {
            let package = self
                .current
                .take()
                .ok_or_else(|| MetadataError::Xml("package end without start".into()))?;
            self.push(package)?;
        } else if name == b"metadata" {
            if self.current.is_some() {
                return Err(MetadataError::Xml("unclosed primary package".into()));
            }
            self.root_closed = true;
        }
        let local = local_name(name);
        if local == b"file" {
            let path = self
                .current
                .as_ref()
                .and_then(|package| package.files.last())
                .ok_or_else(|| MetadataError::Xml("file end without start".into()))?;
            validate_file_path(path)?;
        }
        if self.relation_group.as_deref() == Some(local) {
            self.relation_group = None;
        }
        if self.field.as_deref() == Some(local) {
            self.field = None;
        }
        Ok(())
    }

    fn push(&mut self, builder: Builder) -> Result<(), MetadataError> {
        if builder.name.is_empty()
            || builder.arch.is_empty()
            || builder.version.is_empty()
            || builder.release.is_empty()
        {
            return Err(MetadataError::Xml("package missing required fields".into()));
        }
        if !builder.location.is_empty() {
            validate_package_location(&builder.location)?;
        }
        if !builder.checksum.is_empty()
            && (builder.checksum.len() != 64
                || !builder
                    .checksum
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit()))
        {
            return Err(MetadataError::UnsupportedChecksum(builder.checksum));
        }
        let epoch = if builder.epoch.is_empty() {
            "0".into()
        } else {
            builder.epoch
        };
        if self.retain_complete {
            self.packages.push(CompletePackage {
                name: builder.name,
                arch: builder.arch,
                epoch,
                version: builder.version,
                release: builder.release,
                summary: builder.summary,
                checksum: builder.checksum,
                location: builder.location,
                description: builder.description,
                vendor: builder.vendor,
                build_host: builder.build_host,
                source_rpm: builder.source_rpm,
                package_size: builder.package_size,
                installed_size: builder.installed_size,
                archive_size: builder.archive_size,
                build_time: builder.build_time,
                provides: builder.provides,
                requires: builder.requires,
                recommends: builder.recommends,
                suggests: builder.suggests,
                supplements: builder.supplements,
                enhances: builder.enhances,
                conflicts: builder.conflicts,
                obsoletes: builder.obsoletes,
                files: builder.files,
            });
        } else {
            self.identities.push(PrimaryPackageIdentity {
                checksum: builder.checksum,
                name: builder.name.clone(),
                arch: builder.arch.clone(),
                epoch: epoch.clone(),
                version: builder.version.clone(),
                release: builder.release.clone(),
            });
            self.search_packages.push(Package {
                name: builder.name,
                arch: builder.arch,
                epoch,
                version: builder.version,
                release: builder.release,
                summary: builder.summary,
            });
        }
        self.parsed_packages = checked_increment(self.parsed_packages, MAX_PACKAGES, "packages")?;
        if self.parsed_packages > MAX_PACKAGES {
            return Err(MetadataError::SizeMismatch {
                expected: MAX_PACKAGES,
                actual: self.parsed_packages,
            });
        }
        Ok(())
    }

    fn check_namespace(
        &self,
        decoder: quick_xml::encoding::Decoder,
        event: &BytesStart<'_>,
    ) -> Result<(), MetadataError> {
        if namespace(decoder, event)?.is_some_and(|value| {
            value != "http://linux.duke.edu/metadata/common"
                && value != "http://linux.duke.edu/metadata/rpm"
        }) {
            return Err(MetadataError::Xml("unexpected primary namespace".into()));
        }
        Ok(())
    }
    fn finish(&self) -> Result<(), MetadataError> {
        if !self.root_seen || !self.root_closed {
            return Err(MetadataError::Xml("incomplete primary root".into()));
        }
        let declared = self
            .declared
            .ok_or_else(|| MetadataError::Xml("missing primary package count".into()))?;
        if self.parsed_packages != declared {
            return Err(MetadataError::Xml(format!(
                "primary package count mismatch: declared {declared}, parsed {}",
                self.parsed_packages
            )));
        }
        Ok(())
    }
}

fn push_relation(
    package: &mut Builder,
    group: Option<&[u8]>,
    relation: Relation,
) -> Result<(), MetadataError> {
    let target = match group {
        Some(b"provides") => &mut package.provides,
        Some(b"requires") => &mut package.requires,
        Some(b"recommends") => &mut package.recommends,
        Some(b"suggests") => &mut package.suggests,
        Some(b"supplements") => &mut package.supplements,
        Some(b"enhances") => &mut package.enhances,
        Some(b"conflicts") => &mut package.conflicts,
        Some(b"obsoletes") => &mut package.obsoletes,
        _ => return Err(MetadataError::Xml("relation outside group".into())),
    };
    target.push(relation);
    Ok(())
}
fn namespace(
    decoder: quick_xml::encoding::Decoder,
    event: &BytesStart<'_>,
) -> Result<Option<String>, MetadataError> {
    attribute_streaming(decoder, event, b"xmlns")
}
fn required_attr(
    decoder: quick_xml::encoding::Decoder,
    event: &BytesStart<'_>,
    name: &[u8],
) -> Result<String, MetadataError> {
    attribute_streaming(decoder, event, name)?
        .ok_or_else(|| MetadataError::Xml("missing required attribute".into()))
}
fn optional_number(
    decoder: quick_xml::encoding::Decoder,
    event: &BytesStart<'_>,
    name: &[u8],
) -> Result<u64, MetadataError> {
    attribute_streaming(decoder, event, name)?.map_or(Ok(0), |value| parse_number(&value))
}
fn fill_version(
    decoder: quick_xml::encoding::Decoder,
    event: &BytesStart<'_>,
    package: &mut Builder,
) -> Result<(), MetadataError> {
    package.epoch = attribute_streaming(decoder, event, b"epoch")?.unwrap_or_else(|| "0".into());
    package.version = required_attr(decoder, event, b"ver")?;
    package.release = required_attr(decoder, event, b"rel")?;
    Ok(())
}
fn local_name(name: &[u8]) -> &[u8] {
    name.rsplit(|byte| *byte == b':').next().unwrap_or(name)
}
fn validate_prefix(name: &[u8], rpm_namespace: bool) -> Result<(), MetadataError> {
    if let Some(position) = name.iter().position(|byte| *byte == b':') {
        if &name[..position] != b"rpm" || !rpm_namespace {
            return Err(MetadataError::Xml(
                "unexpected primary namespace prefix".into(),
            ));
        }
    }
    Ok(())
}
fn validate_package_location(href: &str) -> Result<(), MetadataError> {
    if href.is_empty()
        || href.starts_with('/')
        || href.contains("//")
        || href.contains('\\')
        || href.contains('?')
        || href.contains('#')
        || href.contains('%')
        || href.chars().any(char::is_control)
        || href
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
        || href.contains("://")
    {
        return Err(MetadataError::UnsafeLocation(href.into()));
    }
    Ok(())
}
fn validate_file_path(path: &str) -> Result<(), MetadataError> {
    if !path.starts_with('/')
        || path.contains("//")
        || path.chars().any(char::is_control)
        || path.split('/').any(|part| part == "." || part == "..")
    {
        return Err(MetadataError::UnsafeLocation(path.into()));
    }
    Ok(())
}
fn resolved_is_valid(namespace: &ResolveResult<'_>, name: &[u8]) -> bool {
    let expected = if name.contains(&b':') {
        b"http://linux.duke.edu/metadata/rpm".as_slice()
    } else {
        b"http://linux.duke.edu/metadata/common".as_slice()
    };
    matches!(namespace, ResolveResult::Bound(actual) if actual.as_ref() == expected)
}
