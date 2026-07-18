use quick_xml::{events::Event, name::ResolveResult, reader::NsReader};

use crate::{
    MetadataError,
    limits::{MAX_FILELISTS_COMPRESSED_BYTES, MAX_FILELISTS_OPEN_BYTES, checked_total_open},
    xml::{attribute, decode_text, default_namespace, parse_number},
};

pub const MAX_PRIMARY_COMPRESSED_BYTES: u64 = 512 * 1024 * 1024;
pub const MAX_PRIMARY_OPEN_BYTES: u64 = 1024 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetadataRecord {
    pub href: String,
    pub checksum: String,
    pub size: u64,
    pub open_checksum: String,
    pub open_size: u64,
}

pub type PrimaryRecord = MetadataRecord;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuxiliaryRecord {
    pub href: String,
    pub checksum: String,
    pub size: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepomdRecords {
    pub primary: MetadataRecord,
    pub filelists: MetadataRecord,
    pub group: Option<AuxiliaryRecord>,
    pub modules: Option<AuxiliaryRecord>,
    pub updateinfo: Option<AuxiliaryRecord>,
}

pub fn parse_repomd(input: &[u8]) -> Result<PrimaryRecord, MetadataError> {
    parse_document(input, false)?
        .primary
        .ok_or(MetadataError::MissingPrimary)
}

pub fn parse_repomd_records(input: &[u8]) -> Result<RepomdRecords, MetadataError> {
    let parsed = parse_document(input, true)?;
    let primary = parsed.primary.ok_or(MetadataError::MissingPrimary)?;
    let filelists = parsed.filelists.ok_or(MetadataError::MissingFilelists)?;
    checked_total_open([primary.open_size, filelists.open_size])?;
    Ok(RepomdRecords {
        primary,
        filelists,
        group: parsed.group,
        modules: parsed.modules,
        updateinfo: parsed.updateinfo,
    })
}

#[derive(Default)]
struct Document {
    primary: Option<MetadataRecord>,
    filelists: Option<MetadataRecord>,
    group: Option<AuxiliaryRecord>,
    modules: Option<AuxiliaryRecord>,
    updateinfo: Option<AuxiliaryRecord>,
    root_seen: bool,
    root_closed: bool,
    declaration_seen: bool,
}

#[derive(Default)]
struct Builder {
    kind: Option<String>,
    field: Option<Vec<u8>>,
    href: Option<String>,
    checksum: Option<String>,
    size: Option<u64>,
    open_checksum: Option<String>,
    open_size: Option<u64>,
}

fn parse_document(input: &[u8], require_filelists: bool) -> Result<Document, MetadataError> {
    let mut reader = NsReader::from_reader(input);
    reader.config_mut().trim_text(true);
    reader.config_mut().check_end_names = true;
    let mut document = Document::default();
    let mut current = Builder::default();
    loop {
        match reader.read_resolved_event() {
            Ok((namespace, Event::Start(event))) if !document.root_seen => {
                let valid = resolved_is_valid(&namespace);
                if event.name().as_ref() != b"repomd"
                    || default_namespace(&reader, &event)?.as_deref()
                        != Some("http://linux.duke.edu/metadata/repo")
                {
                    return Err(MetadataError::Xml(
                        "unexpected repomd root or namespace".into(),
                    ));
                }
                if !valid {
                    return Err(MetadataError::Xml(
                        "unexpected repomd resolved namespace".into(),
                    ));
                }
                document.root_seen = true;
            }
            Ok((_, Event::Start(_))) if document.root_closed => {
                return Err(MetadataError::Xml("element outside repomd root".into()));
            }
            Ok((namespace, Event::Start(event))) => {
                let valid = resolved_is_valid(&namespace);
                start(&reader, &event, &document, &mut current)?;
                if !valid {
                    return Err(MetadataError::Xml(
                        "unexpected repomd resolved namespace".into(),
                    ));
                }
            }
            Ok((_, Event::Empty(_))) if !document.root_seen || document.root_closed => {
                return Err(MetadataError::Xml("element outside repomd root".into()));
            }
            Ok((namespace, Event::Empty(event))) => {
                let valid = resolved_is_valid(&namespace);
                empty(&reader, &event, &document, &mut current)?;
                if !valid {
                    return Err(MetadataError::Xml(
                        "unexpected repomd resolved namespace".into(),
                    ));
                }
            }
            Ok((_, Event::Text(event))) if current.kind.is_some() => text(&event, &mut current)?,
            Ok((_, Event::Text(event)))
                if !decode_text(&event)?.trim().is_empty()
                    && (!document.root_seen || document.root_closed) =>
            {
                return Err(MetadataError::Xml("text outside repomd root".into()));
            }
            Ok((_, Event::End(event))) if event.name().as_ref() == b"data" => finish_record(
                &mut document,
                std::mem::take(&mut current),
                require_filelists,
            )?,
            Ok((_, Event::End(event))) if event.name().as_ref() == b"repomd" => {
                document.root_closed = true
            }
            Ok((_, Event::End(_))) if !document.root_seen || document.root_closed => {
                return Err(MetadataError::Xml("end element outside repomd root".into()));
            }
            Ok((_, Event::End(_))) => current.field = None,
            Ok((_, Event::Decl(_))) if !document.root_seen && !document.declaration_seen => {
                document.declaration_seen = true
            }
            Ok((_, Event::Decl(_) | Event::DocType(_))) => {
                return Err(MetadataError::Xml(
                    "misplaced XML declaration or doctype".into(),
                ));
            }
            Ok((_, Event::Comment(_) | Event::PI(_))) => {}
            Ok((_, Event::Eof)) => break,
            Ok((_, _)) if !document.root_seen || document.root_closed => {
                return Err(MetadataError::Xml("content outside repomd root".into()));
            }
            Err(error) => return Err(MetadataError::Xml(error.to_string())),
            _ => {}
        }
    }
    if !document.root_seen || !document.root_closed {
        return Err(MetadataError::Xml("incomplete repomd root".into()));
    }
    if document.primary.is_none() {
        return Err(MetadataError::MissingPrimary);
    }
    if require_filelists && document.filelists.is_none() {
        return Err(MetadataError::MissingFilelists);
    }
    Ok(document)
}

fn start(
    reader: &NsReader<&[u8]>,
    event: &quick_xml::events::BytesStart<'_>,
    document: &Document,
    builder: &mut Builder,
) -> Result<(), MetadataError> {
    namespace(reader, event, document)?;
    if event.name().as_ref() == b"data" {
        builder.kind = attribute(reader, event, b"type")?;
    } else if builder.kind.is_some() {
        match event.name().as_ref() {
            b"checksum" | b"open-checksum" => {
                let kind = attribute(reader, event, b"type")?.unwrap_or_default();
                if kind != "sha256" {
                    return Err(MetadataError::UnsupportedChecksum(kind));
                }
                builder.field = Some(event.name().as_ref().to_vec());
            }
            b"size" | b"open-size" => builder.field = Some(event.name().as_ref().to_vec()),
            _ => {}
        }
    }
    Ok(())
}

fn empty(
    reader: &NsReader<&[u8]>,
    event: &quick_xml::events::BytesStart<'_>,
    document: &Document,
    builder: &mut Builder,
) -> Result<(), MetadataError> {
    namespace(reader, event, document)?;
    if builder.kind.is_some() && event.name().as_ref() == b"location" {
        builder.href = attribute(reader, event, b"href")?;
    }
    Ok(())
}

fn namespace(
    reader: &NsReader<&[u8]>,
    event: &quick_xml::events::BytesStart<'_>,
    document: &Document,
) -> Result<(), MetadataError> {
    if !document.root_seen || document.root_closed {
        return Err(MetadataError::Xml("element outside repomd root".into()));
    }
    if event.name().as_ref().contains(&b':') {
        return Err(MetadataError::Xml(
            "unexpected repomd namespace prefix".into(),
        ));
    }
    if default_namespace(reader, event)?
        .is_some_and(|value| value != "http://linux.duke.edu/metadata/repo")
    {
        return Err(MetadataError::Xml("unexpected repomd namespace".into()));
    }
    Ok(())
}

fn text(
    event: &quick_xml::events::BytesText<'_>,
    builder: &mut Builder,
) -> Result<(), MetadataError> {
    let value = decode_text(event)?;
    match builder.field.as_deref() {
        Some(b"checksum") => builder.checksum = Some(value),
        Some(b"open-checksum") => builder.open_checksum = Some(value),
        Some(b"size") => builder.size = Some(parse_number(&value)?),
        Some(b"open-size") => builder.open_size = Some(parse_number(&value)?),
        _ => {}
    }
    Ok(())
}

fn finish_record(
    document: &mut Document,
    builder: Builder,
    collect_filelists: bool,
) -> Result<(), MetadataError> {
    let Some(kind) = builder.kind.clone() else {
        return Ok(());
    };
    if kind == "filelists" && !collect_filelists {
        return Ok(());
    }
    if matches!(kind.as_str(), "group" | "modules" | "updateinfo") {
        if !collect_filelists {
            return Ok(());
        }
        let record = build_auxiliary(builder, 512 * 1024 * 1024)?;
        let slot = match kind.as_str() {
            "group" => &mut document.group,
            "modules" => &mut document.modules,
            "updateinfo" => &mut document.updateinfo,
            _ => unreachable!(),
        };
        if slot.replace(record).is_some() {
            return Err(MetadataError::DuplicateRecord(kind));
        }
        return Ok(());
    }
    let limits = match kind.as_str() {
        "primary" => Some((MAX_PRIMARY_COMPRESSED_BYTES, MAX_PRIMARY_OPEN_BYTES)),
        "filelists" => Some((MAX_FILELISTS_COMPRESSED_BYTES, MAX_FILELISTS_OPEN_BYTES)),
        _ => None,
    };
    let Some((compressed_limit, open_limit)) = limits else {
        return Ok(());
    };
    let record = build(builder, compressed_limit, open_limit)?;
    let slot = if kind == "primary" {
        &mut document.primary
    } else {
        &mut document.filelists
    };
    if slot.replace(record).is_some() {
        return Err(MetadataError::DuplicateRecord(kind));
    }
    Ok(())
}

fn build_auxiliary(
    builder: Builder,
    compressed_limit: u64,
) -> Result<AuxiliaryRecord, MetadataError> {
    let href = builder.href.ok_or(MetadataError::MissingPrimary)?;
    validate_location(&href)?;
    let checksum = valid_checksum(builder.checksum.ok_or(MetadataError::MissingPrimary)?)?;
    let size = bounded(
        builder.size.ok_or(MetadataError::MissingPrimary)?,
        compressed_limit,
    )?;
    if size == 0 {
        return Err(MetadataError::SizeMismatch {
            expected: 1,
            actual: 0,
        });
    }
    Ok(AuxiliaryRecord {
        href,
        checksum,
        size,
    })
}

fn build(
    builder: Builder,
    compressed_limit: u64,
    open_limit: u64,
) -> Result<MetadataRecord, MetadataError> {
    let href = builder.href.ok_or(MetadataError::MissingPrimary)?;
    validate_location(&href)?;
    let checksum = valid_checksum(builder.checksum.ok_or(MetadataError::MissingPrimary)?)?;
    let open_checksum =
        valid_checksum(builder.open_checksum.ok_or(MetadataError::MissingPrimary)?)?;
    let size = bounded(
        builder.size.ok_or(MetadataError::MissingPrimary)?,
        compressed_limit,
    )?;
    let open_size = bounded(
        builder.open_size.ok_or(MetadataError::MissingPrimary)?,
        open_limit,
    )?;
    Ok(MetadataRecord {
        href,
        checksum,
        size,
        open_checksum,
        open_size,
    })
}

fn valid_checksum(value: String) -> Result<String, MetadataError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(MetadataError::UnsupportedChecksum(value));
    }
    Ok(value.to_ascii_lowercase())
}
fn bounded(value: u64, maximum: u64) -> Result<u64, MetadataError> {
    if value > maximum {
        return Err(MetadataError::SizeMismatch {
            expected: maximum,
            actual: value,
        });
    }
    Ok(value)
}
fn validate_location(href: &str) -> Result<(), MetadataError> {
    let lowered = href.to_ascii_lowercase();
    if href.is_empty()
        || !href.starts_with("repodata/")
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
        || lowered.contains("://")
    {
        return Err(MetadataError::UnsafeLocation(href.to_owned()));
    }
    Ok(())
}
fn resolved_is_valid(namespace: &ResolveResult<'_>) -> bool {
    matches!(namespace, ResolveResult::Bound(actual) if actual.as_ref() == b"http://linux.duke.edu/metadata/repo")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(kind: &str, checksum: char, href: &str, size: u64, opened: bool) -> String {
        let open = if opened {
            format!(
                "<open-checksum type=\"sha256\">{}</open-checksum><open-size>{size}</open-size>",
                checksum.to_string().repeat(64)
            )
        } else {
            String::new()
        };
        format!(
            "<data type=\"{kind}\"><checksum type=\"sha256\">{}</checksum>{open}<location href=\"{href}\"/><size>{size}</size></data>",
            checksum.to_string().repeat(64)
        )
    }

    fn document(extra: &str) -> Vec<u8> {
        format!(
            "<repomd xmlns=\"http://linux.duke.edu/metadata/repo\">{}{}{extra}</repomd>",
            record("primary", 'a', "repodata/primary.xml.zst", 10, true),
            record("filelists", 'b', "repodata/filelists.xml.zst", 20, true),
        )
        .into_bytes()
    }

    #[test]
    fn optional_auxiliary_records_are_exact_checksum_bound_records() {
        let extra = format!(
            "{}{}{}{}",
            record("group", 'c', "repodata/comps.xml.zst", 30, false),
            record("group_zck", 'd', "repodata/comps.xml.zck", 40, false),
            record("modules", 'e', "repodata/modules.yaml.zst", 50, false),
            record("updateinfo", 'f', "repodata/updateinfo.xml.zst", 60, false),
        );
        let parsed = parse_repomd_records(&document(&extra)).expect("optional records");
        assert_eq!(parsed.group.expect("group").checksum, "c".repeat(64));
        assert_eq!(parsed.modules.expect("modules").size, 50);
        assert_eq!(parsed.updateinfo.expect("updateinfo").size, 60);
    }

    #[test]
    fn optional_records_reject_duplicates_unsafe_locations_and_zero_sizes() {
        let group = record("group", 'c', "repodata/comps.xml.zst", 30, false);
        assert!(parse_repomd_records(&document(&format!("{group}{group}"))).is_err());
        assert!(
            parse_repomd_records(&document(&record(
                "group",
                'c',
                "../comps.xml.zst",
                30,
                false
            )))
            .is_err()
        );
        assert!(
            parse_repomd_records(&document(&record(
                "modules",
                'e',
                "repodata/modules.yaml.zst",
                0,
                false
            )))
            .is_err()
        );
        let updateinfo = record("updateinfo", 'f', "repodata/updateinfo.xml.zst", 60, false);
        assert!(parse_repomd_records(&document(&format!("{updateinfo}{updateinfo}"))).is_err());
    }
}
