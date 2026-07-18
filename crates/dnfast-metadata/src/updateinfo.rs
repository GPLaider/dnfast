use quick_xml::{Reader, events::Event};

use crate::{MetadataError, xml::decode_reference};

const MAX_ADVISORIES: usize = 250_000;
const MAX_PACKAGES: usize = 4_000_000;
const MAX_PACKAGES_PER_ADVISORY: usize = 100_000;
const MAX_REFERENCES_PER_ADVISORY: usize = 100_000;
const MAX_TEXT_BYTES: usize = 4 * 1024 * 1024;
const MAX_DEPTH: usize = 64;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpdateInfo {
    pub advisories: Vec<Advisory>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Advisory {
    pub id: String,
    pub title: String,
    pub kind: String,
    pub status: String,
    pub severity: String,
    pub issued: String,
    pub updated: String,
    pub summary: String,
    pub description: String,
    pub references: Vec<AdvisoryReference>,
    pub packages: Vec<AdvisoryPackage>,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct AdvisoryReference {
    pub id: String,
    pub kind: String,
    pub href: String,
    pub title: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct AdvisoryPackage {
    pub name: String,
    pub epoch: u64,
    pub version: String,
    pub release: String,
    pub arch: String,
    pub filename: String,
}

#[derive(Default)]
struct AdvisoryBuilder {
    id: String,
    title: String,
    kind: String,
    status: String,
    severity: String,
    issued: String,
    updated: String,
    summary: String,
    description: String,
    references: Vec<AdvisoryReference>,
    packages: Vec<AdvisoryPackage>,
}

struct PackageBuilder {
    name: String,
    epoch: u64,
    version: String,
    release: String,
    arch: String,
    filename: String,
}

#[derive(Clone, Copy)]
enum TextTarget {
    Id,
    Title,
    Severity,
    Summary,
    Description,
    Filename,
}

struct TextValue {
    target: TextTarget,
    value: String,
}

pub fn parse_updateinfo(input: &[u8]) -> Result<UpdateInfo, MetadataError> {
    let mut reader = Reader::from_reader(input);
    reader.config_mut().trim_text(false);
    reader.config_mut().check_end_names = true;
    let mut stack = Vec::<Vec<u8>>::new();
    let mut advisories = Vec::new();
    let mut advisory: Option<AdvisoryBuilder> = None;
    let mut package: Option<PackageBuilder> = None;
    let mut text: Option<TextValue> = None;
    let mut declaration_seen = false;
    let mut root_closed = false;

    loop {
        match reader.read_event() {
            Ok(Event::Start(event)) => {
                if root_closed || stack.len() >= MAX_DEPTH {
                    return xml("content after updateinfo root or excessive XML depth");
                }
                let name = event.name().as_ref().to_vec();
                reject_prefixed(&name)?;
                let parent = stack.last().map(Vec::as_slice);
                if stack.is_empty() {
                    if name != b"updates" {
                        return xml("unexpected updateinfo root");
                    }
                    if event.attributes().next().is_some() {
                        return xml("unexpected updateinfo root attribute");
                    }
                } else if parent == Some(b"updates") && name == b"update" {
                    if advisory.is_some() {
                        return xml("nested updateinfo advisory");
                    }
                    advisory = Some(start_advisory(&reader, &event)?);
                } else if name == b"package" && advisory.is_some() {
                    if package.is_some() {
                        return xml("nested updateinfo package");
                    }
                    package = Some(start_package(&reader, &event)?);
                }
                text = target(parent, &name, advisory.is_some(), package.is_some()).map(|target| {
                    TextValue {
                        target,
                        value: String::new(),
                    }
                });
                stack.push(name);
            }
            Ok(Event::Empty(event)) => {
                if stack.is_empty() || root_closed {
                    return xml("empty element outside updateinfo root");
                }
                reject_prefixed(event.name().as_ref())?;
                match event.name().as_ref() {
                    b"issued" => set_date(
                        &reader,
                        &event,
                        &mut required_advisory(&mut advisory)?.issued,
                        "issued",
                    )?,
                    b"updated" => set_date(
                        &reader,
                        &event,
                        &mut required_advisory(&mut advisory)?.updated,
                        "updated",
                    )?,
                    b"reference" => {
                        push_reference(&reader, &event, required_advisory(&mut advisory)?)?
                    }
                    b"references" | b"pkglist" => {}
                    _ => {}
                }
            }
            Ok(Event::Text(event)) => {
                if let Some(value) = text.as_mut() {
                    append(&mut value.value, &event.decode().map_err(xml_error)?)?;
                } else if stack.is_empty() || root_closed {
                    let decoded = event.decode().map_err(xml_error)?;
                    if !decoded.trim().is_empty() {
                        return xml("text outside updateinfo root");
                    }
                }
            }
            Ok(Event::GeneralRef(event)) => {
                let value = text.as_mut().ok_or_else(|| {
                    MetadataError::Xml("entity reference outside updateinfo text".into())
                })?;
                append(&mut value.value, &decode_reference(&event)?)?;
            }
            Ok(Event::CData(event)) => {
                let value = text
                    .as_mut()
                    .ok_or_else(|| MetadataError::Xml("CDATA outside updateinfo text".into()))?;
                append(&mut value.value, &event.decode().map_err(xml_error)?)?;
            }
            Ok(Event::End(event)) => {
                let expected = stack
                    .pop()
                    .ok_or_else(|| MetadataError::Xml("updateinfo end without start".into()))?;
                if expected.as_slice() != event.name().as_ref() {
                    return xml("mismatched updateinfo element");
                }
                if let Some(value) = text.take() {
                    finish_text(value, &mut advisory, &mut package)?;
                }
                match expected.as_slice() {
                    b"package" => {
                        let finished = finish_package(package.take().ok_or_else(|| {
                            MetadataError::Xml("package end without package".into())
                        })?)?;
                        let advisory = required_advisory(&mut advisory)?;
                        advisory.packages.push(finished);
                        checked_len(
                            advisory.packages.len(),
                            MAX_PACKAGES_PER_ADVISORY,
                            "packages per advisory",
                        )?;
                    }
                    b"update" => {
                        if package.is_some() {
                            return xml("advisory ended inside package");
                        }
                        advisories.push(finish_advisory(advisory.take().ok_or_else(|| {
                            MetadataError::Xml("advisory end without advisory".into())
                        })?)?);
                        checked_len(advisories.len(), MAX_ADVISORIES, "advisories")?;
                    }
                    b"updates" => root_closed = true,
                    _ => {}
                }
            }
            Ok(Event::Decl(_)) if stack.is_empty() && !declaration_seen && !root_closed => {
                declaration_seen = true;
            }
            Ok(Event::Decl(_) | Event::DocType(_)) => {
                return xml("misplaced XML declaration or updateinfo doctype");
            }
            Ok(Event::Comment(_) | Event::PI(_)) => {}
            Ok(Event::Eof) => break,
            Err(error) => return Err(MetadataError::Xml(error.to_string())),
        }
    }
    if !root_closed || !stack.is_empty() || advisory.is_some() || package.is_some() {
        return xml("incomplete updateinfo document");
    }
    let package_count = advisories.iter().try_fold(0_usize, |total, item| {
        total
            .checked_add(item.packages.len())
            .ok_or(MetadataError::LimitExceeded {
                kind: "updateinfo packages",
                maximum: MAX_PACKAGES as u64,
                actual: u64::MAX,
            })
    })?;
    checked_len(package_count, MAX_PACKAGES, "updateinfo packages")?;
    advisories.sort_by(|left, right| left.id.cmp(&right.id));
    if advisories.windows(2).any(|pair| pair[0].id == pair[1].id) {
        return xml("duplicate advisory id");
    }
    Ok(UpdateInfo { advisories })
}

fn start_advisory(
    reader: &Reader<&[u8]>,
    event: &quick_xml::events::BytesStart<'_>,
) -> Result<AdvisoryBuilder, MetadataError> {
    let kind = required_attribute(reader, event, b"type", "advisory type")?;
    let status = required_attribute(reader, event, b"status", "advisory status")?;
    validate_token(&kind, "advisory type")?;
    validate_token(&status, "advisory status")?;
    Ok(AdvisoryBuilder {
        kind,
        status,
        ..AdvisoryBuilder::default()
    })
}

fn start_package(
    reader: &Reader<&[u8]>,
    event: &quick_xml::events::BytesStart<'_>,
) -> Result<PackageBuilder, MetadataError> {
    let name = required_attribute(reader, event, b"name", "package name")?;
    let epoch = required_attribute(reader, event, b"epoch", "package epoch")?
        .parse::<u64>()
        .map_err(|_| MetadataError::Xml("invalid package epoch".into()))?;
    let version = required_attribute(reader, event, b"version", "package version")?;
    let release = required_attribute(reader, event, b"release", "package release")?;
    let arch = required_attribute(reader, event, b"arch", "package architecture")?;
    for (value, label) in [
        (&name, "package name"),
        (&version, "package version"),
        (&release, "package release"),
        (&arch, "package architecture"),
    ] {
        validate_token(value, label)?;
    }
    Ok(PackageBuilder {
        name,
        epoch,
        version,
        release,
        arch,
        filename: String::new(),
    })
}

fn target(
    parent: Option<&[u8]>,
    name: &[u8],
    in_advisory: bool,
    in_package: bool,
) -> Option<TextTarget> {
    if in_package && parent == Some(b"package") && name == b"filename" {
        return Some(TextTarget::Filename);
    }
    if !in_advisory {
        return None;
    }
    match (parent, name) {
        (Some(b"update"), b"id") => Some(TextTarget::Id),
        (Some(b"update"), b"title") => Some(TextTarget::Title),
        (Some(b"update"), b"severity") => Some(TextTarget::Severity),
        (Some(b"update"), b"summary") => Some(TextTarget::Summary),
        (Some(b"update"), b"description") => Some(TextTarget::Description),
        _ => None,
    }
}

fn finish_text(
    text: TextValue,
    advisory: &mut Option<AdvisoryBuilder>,
    package: &mut Option<PackageBuilder>,
) -> Result<(), MetadataError> {
    let value = text.value.trim().to_owned();
    match text.target {
        TextTarget::Filename => set_once(
            &mut package
                .as_mut()
                .ok_or_else(|| MetadataError::Xml("filename outside package".into()))?
                .filename,
            value,
            "package filename",
            true,
        ),
        target => {
            let advisory = required_advisory(advisory)?;
            let (slot, label, token) = match target {
                TextTarget::Id => (&mut advisory.id, "advisory id", true),
                TextTarget::Title => (&mut advisory.title, "advisory title", false),
                TextTarget::Severity => (&mut advisory.severity, "advisory severity", true),
                TextTarget::Summary => (&mut advisory.summary, "advisory summary", false),
                TextTarget::Description => {
                    (&mut advisory.description, "advisory description", false)
                }
                TextTarget::Filename => unreachable!(),
            };
            set_once(slot, value, label, token)
        }
    }
}

fn set_date(
    reader: &Reader<&[u8]>,
    event: &quick_xml::events::BytesStart<'_>,
    slot: &mut String,
    label: &'static str,
) -> Result<(), MetadataError> {
    let value = required_attribute(reader, event, b"date", label)?;
    set_once(slot, value, label, false)
}

fn push_reference(
    reader: &Reader<&[u8]>,
    event: &quick_xml::events::BytesStart<'_>,
    advisory: &mut AdvisoryBuilder,
) -> Result<(), MetadataError> {
    let reference = AdvisoryReference {
        id: required_attribute(reader, event, b"id", "reference id")?,
        kind: required_attribute(reader, event, b"type", "reference type")?,
        href: required_attribute(reader, event, b"href", "reference href")?,
        title: optional_attribute(reader, event, b"title")?.unwrap_or_default(),
    };
    validate_token(&reference.id, "reference id")?;
    validate_token(&reference.kind, "reference type")?;
    validate_text(&reference.href, "reference href")?;
    if !reference.title.is_empty() {
        validate_text(&reference.title, "reference title")?;
    }
    advisory.references.push(reference);
    checked_len(
        advisory.references.len(),
        MAX_REFERENCES_PER_ADVISORY,
        "references per advisory",
    )
}

fn finish_package(builder: PackageBuilder) -> Result<AdvisoryPackage, MetadataError> {
    validate_token(&builder.filename, "package filename")?;
    if builder.filename.contains('/') || builder.filename.contains("..") {
        return xml("unsafe package filename");
    }
    Ok(AdvisoryPackage {
        name: builder.name,
        epoch: builder.epoch,
        version: builder.version,
        release: builder.release,
        arch: builder.arch,
        filename: builder.filename,
    })
}

fn finish_advisory(mut builder: AdvisoryBuilder) -> Result<Advisory, MetadataError> {
    validate_token(&builder.id, "advisory id")?;
    validate_text(&builder.title, "advisory title")?;
    if builder.severity.is_empty() {
        builder.severity = "None".into();
    }
    validate_token(&builder.severity, "advisory severity")?;
    builder.references.sort();
    builder.packages.sort();
    builder.references.dedup();
    builder.packages.dedup();
    if builder.packages.is_empty() {
        return xml("advisory contains no packages");
    }
    Ok(Advisory {
        id: builder.id,
        title: builder.title,
        kind: builder.kind,
        status: builder.status,
        severity: builder.severity,
        issued: builder.issued,
        updated: builder.updated,
        summary: builder.summary,
        description: builder.description,
        references: builder.references,
        packages: builder.packages,
    })
}

fn optional_attribute(
    reader: &Reader<&[u8]>,
    event: &quick_xml::events::BytesStart<'_>,
    name: &[u8],
) -> Result<Option<String>, MetadataError> {
    for attribute in event.attributes() {
        let attribute = attribute.map_err(xml_error)?;
        if attribute.key.as_ref() == name {
            return attribute
                .decoded_and_normalized_value(quick_xml::XmlVersion::Implicit1_0, reader.decoder())
                .map(|value| Some(value.into_owned()))
                .map_err(xml_error);
        }
    }
    Ok(None)
}

fn required_attribute(
    reader: &Reader<&[u8]>,
    event: &quick_xml::events::BytesStart<'_>,
    name: &[u8],
    label: &'static str,
) -> Result<String, MetadataError> {
    optional_attribute(reader, event, name)?
        .ok_or_else(|| MetadataError::Xml(format!("missing required {label}")))
}

fn required_advisory(
    advisory: &mut Option<AdvisoryBuilder>,
) -> Result<&mut AdvisoryBuilder, MetadataError> {
    advisory
        .as_mut()
        .ok_or_else(|| MetadataError::Xml("advisory field outside advisory".into()))
}

fn set_once(
    target: &mut String,
    value: String,
    label: &'static str,
    token: bool,
) -> Result<(), MetadataError> {
    if !target.is_empty() {
        return xml(&format!("duplicate {label}"));
    }
    if token {
        validate_token(&value, label)?;
    } else {
        validate_text(&value, label)?;
    }
    *target = value;
    Ok(())
}

fn append(target: &mut String, value: &str) -> Result<(), MetadataError> {
    target
        .try_reserve(value.len())
        .map_err(|error| MetadataError::Io(error.to_string()))?;
    target.push_str(value);
    checked_len(target.len(), MAX_TEXT_BYTES, "updateinfo XML text")
}

fn validate_token(value: &str, label: &'static str) -> Result<(), MetadataError> {
    validate_text(value, label)?;
    if value.chars().any(char::is_whitespace) {
        return xml(&format!("invalid {label}"));
    }
    Ok(())
}

fn validate_text(value: &str, label: &'static str) -> Result<(), MetadataError> {
    if value.is_empty()
        || value
            .chars()
            .any(|value| value.is_control() && value != '\n' && value != '\t')
    {
        return xml(&format!("invalid {label}"));
    }
    Ok(())
}

fn checked_len(actual: usize, maximum: usize, kind: &'static str) -> Result<(), MetadataError> {
    if actual > maximum {
        return Err(MetadataError::LimitExceeded {
            kind,
            maximum: maximum as u64,
            actual: actual as u64,
        });
    }
    Ok(())
}

fn reject_prefixed(name: &[u8]) -> Result<(), MetadataError> {
    if name.contains(&b':') {
        return xml("unexpected updateinfo namespace prefix");
    }
    Ok(())
}

fn xml<T>(message: &str) -> Result<T, MetadataError> {
    Err(MetadataError::Xml(message.into()))
}

fn xml_error(error: impl ToString) -> MetadataError {
    MetadataError::Xml(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &[u8] = br#"<?xml version="1.0"?><updates><update status="stable" type="security" version="2.0"><id>FEDORA-2026-deadbeef00</id><title>demo-2-1.fc44</title><issued date="2026-07-01 00:00:00"/><updated date="2026-07-02 00:00:00"/><severity>Important</severity><summary>demo update</summary><description>fixes an issue</description><references><reference href="https://example.invalid/1" id="CVE-2026-1" type="cve" title="issue"/></references><pkglist><collection short="F44"><name>Fedora 44</name><package name="demo" epoch="0" version="2" release="1.fc44" arch="x86_64"><filename>demo-2-1.fc44.x86_64.rpm</filename></package></collection></pkglist></update></updates>"#;

    #[test]
    fn parses_and_canonicalizes_updateinfo() {
        let parsed = parse_updateinfo(VALID).expect("valid updateinfo");
        assert_eq!(parsed.advisories.len(), 1);
        assert_eq!(parsed.advisories[0].kind, "security");
        assert_eq!(parsed.advisories[0].packages[0].name, "demo");
    }

    #[test]
    fn rejects_doctype_duplicate_id_and_unsafe_filename() {
        assert!(parse_updateinfo(b"<!DOCTYPE updates><updates></updates>").is_err());
        let duplicated = [
            b"<updates>".as_slice(),
            &VALID[VALID.iter().position(|byte| *byte == b'<').unwrap()..][38..VALID.len() - 10],
            &VALID[VALID.iter().position(|byte| *byte == b'<').unwrap()..][38..VALID.len() - 10],
            b"</updates>",
        ]
        .concat();
        assert!(parse_updateinfo(&duplicated).is_err());
        let unsafe_name = String::from_utf8(VALID.to_vec())
            .expect("UTF-8")
            .replace("demo-2-1.fc44.x86_64.rpm", "../demo.rpm");
        assert!(parse_updateinfo(unsafe_name.as_bytes()).is_err());
    }
}
