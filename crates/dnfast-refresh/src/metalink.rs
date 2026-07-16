use quick_xml::{Reader, events::Event};
use sha2::Digest;

use crate::{RefreshError, url_policy::validate_https};

pub(crate) const MAX_METALINK_BYTES: u64 = 2 * 1024 * 1024;
pub(crate) const MAX_REPOMD_BYTES: u64 = 16 * 1024 * 1024;
const MAX_METALINK_RESOURCES: usize = 32;
const MAX_METALINK_ALTERNATES: usize = 16;

pub(crate) struct Metalink {
    pub(crate) versions: Vec<RepomdVersion>,
    pub(crate) max_connections: Option<u32>,
    pub(crate) resources: Vec<Resource>,
}

pub(crate) struct RepomdVersion {
    pub(crate) size: u64,
    pub(crate) sha256: String,
}

impl Metalink {
    pub(crate) fn accepts(&self, bytes: &[u8]) -> bool {
        let digest = hex::encode(sha2::Sha256::digest(bytes));
        self.versions
            .iter()
            .any(|version| bytes.len() as u64 == version.size && digest == version.sha256)
    }
}

pub(crate) struct Resource {
    preference: u32,
    order: usize,
    pub(crate) url: String,
}

pub(crate) fn parse_metalink(input: &[u8]) -> Result<Metalink, RefreshError> {
    let mut reader = Reader::from_reader(input);
    reader.config_mut().trim_text(true);
    reader.config_mut().check_end_names = true;
    let mut root_valid = false;
    let mut in_repomd = false;
    let mut field = None::<Vec<u8>>;
    let mut hash_type_valid = false;
    let mut size = None;
    let mut sha256 = None;
    let mut alternate_size = None;
    let mut alternate_sha256 = None;
    let mut alternate_versions = Vec::new();
    let mut in_alternate = false;
    let mut resources = Vec::new();
    let mut max_connections = None;
    let mut pending_preference = None;
    let mut root_seen = false;

    loop {
        match reader.read_event() {
            Ok(Event::Start(event)) => {
                if !root_seen {
                    root_valid = event.name().as_ref() == b"metalink"
                        && default_namespace(&reader, &event)?.as_deref()
                            == Some("http://www.metalinker.org/");
                    if !root_valid {
                        return Err(RefreshError::Metalink(
                            "unexpected Metalink root or namespace".into(),
                        ));
                    }
                    root_seen = true;
                    continue;
                }
                if default_namespace(&reader, &event)?
                    .is_some_and(|namespace| namespace != "http://www.metalinker.org/")
                {
                    return Err(RefreshError::Metalink(
                        "unexpected Metalink namespace".into(),
                    ));
                }
                match event.local_name().as_ref() {
                    b"file" => {
                        in_repomd = xml_attribute(&reader, &event, b"name")?.as_deref()
                            == Some("repomd.xml");
                    }
                    b"hash" if in_repomd => {
                        hash_type_valid =
                            xml_attribute(&reader, &event, b"type")?.as_deref() == Some("sha256");
                        field = Some(b"hash".to_vec());
                    }
                    b"size" if in_repomd => field = Some(b"size".to_vec()),
                    b"url" if in_repomd => {
                        pending_preference = xml_attribute(&reader, &event, b"preference")?
                            .and_then(|value| value.parse::<u32>().ok())
                            .filter(|value| (1..=100).contains(value));
                        field = Some(b"url".to_vec());
                    }
                    b"resources" if in_repomd => {
                        max_connections = xml_attribute(&reader, &event, b"maxconnections")?
                            .and_then(|value| value.parse::<u32>().ok())
                            .filter(|value| *value > 0);
                    }
                    b"alternate" if in_repomd => {
                        if in_alternate {
                            return Err(RefreshError::Metalink("nested repomd alternate".into()));
                        }
                        in_alternate = true;
                        alternate_size = None;
                        alternate_sha256 = None;
                    }
                    _ => {}
                }
            }
            Ok(Event::Text(event)) if in_repomd => {
                let value = event
                    .decode()
                    .map_err(|error| RefreshError::Metalink(error.to_string()))?;
                let value = quick_xml::escape::unescape(&value)
                    .map_err(|error| RefreshError::Metalink(error.to_string()))?
                    .into_owned();
                match field.as_deref() {
                    Some(b"hash") if hash_type_valid && in_alternate => {
                        alternate_sha256 = Some(value.to_ascii_lowercase())
                    }
                    Some(b"hash") if hash_type_valid => sha256 = Some(value.to_ascii_lowercase()),
                    Some(b"size") if in_alternate => alternate_size = value.parse::<u64>().ok(),
                    Some(b"size") => size = value.parse::<u64>().ok(),
                    Some(b"url") if validate_https(&value).is_ok() => resources.push(Resource {
                        preference: pending_preference.unwrap_or(1),
                        order: resources.len(),
                        url: value,
                    }),
                    _ => {}
                }
            }
            Ok(Event::End(event)) => {
                let local = event.local_name();
                if local.as_ref() == b"alternate" && in_alternate {
                    if alternate_versions.len() == MAX_METALINK_ALTERNATES {
                        return Err(RefreshError::Metalink("too many repomd alternates".into()));
                    }
                    alternate_versions.push(validated_version(
                        alternate_size.take(),
                        alternate_sha256.take(),
                    )?);
                    in_alternate = false;
                }
                if local.as_ref() == b"file" && in_repomd {
                    in_repomd = false;
                }
                field = None;
                pending_preference = None;
            }
            Ok(Event::Eof) => break,
            Err(error) => return Err(RefreshError::Metalink(error.to_string())),
            _ => {}
        }
    }
    if !root_valid {
        return Err(RefreshError::Metalink(
            "unexpected Metalink namespace".into(),
        ));
    }
    let mut versions = vec![validated_version(size, sha256)?];
    for version in alternate_versions {
        if !versions
            .iter()
            .any(|existing| existing.size == version.size && existing.sha256 == version.sha256)
        {
            versions.push(version);
        }
    }
    if resources.is_empty() {
        return Err(RefreshError::Metalink("no HTTPS repomd resources".into()));
    }
    if resources.len() > MAX_METALINK_RESOURCES {
        return Err(RefreshError::Metalink("too many Metalink resources".into()));
    }
    resources.sort_by(|left, right| {
        right
            .preference
            .cmp(&left.preference)
            .then_with(|| left.order.cmp(&right.order))
    });
    Ok(Metalink {
        versions,
        max_connections,
        resources,
    })
}

fn validated_version(
    size: Option<u64>,
    sha256: Option<String>,
) -> Result<RepomdVersion, RefreshError> {
    let size = size.ok_or_else(|| RefreshError::Metalink("missing repomd size".into()))?;
    if size > MAX_REPOMD_BYTES {
        return Err(RefreshError::Metalink("repomd exceeds policy limit".into()));
    }
    let sha256 = sha256.ok_or_else(|| RefreshError::Metalink("missing repomd sha256".into()))?;
    if sha256.len() != 64 || !sha256.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(RefreshError::Metalink("invalid repomd sha256".into()));
    }
    Ok(RepomdVersion { size, sha256 })
}

fn default_namespace(
    reader: &Reader<&[u8]>,
    event: &quick_xml::events::BytesStart<'_>,
) -> Result<Option<String>, RefreshError> {
    for attribute in event.attributes() {
        let attribute = attribute.map_err(|error| RefreshError::Metalink(error.to_string()))?;
        if attribute.key.as_ref() == b"xmlns" {
            return attribute
                .decoded_and_normalized_value(quick_xml::XmlVersion::Implicit1_0, reader.decoder())
                .map(|value| Some(value.into_owned()))
                .map_err(|error| RefreshError::Metalink(error.to_string()));
        }
    }
    Ok(None)
}

fn xml_attribute(
    reader: &Reader<&[u8]>,
    event: &quick_xml::events::BytesStart<'_>,
    key: &[u8],
) -> Result<Option<String>, RefreshError> {
    for attribute in event.attributes() {
        let attribute = attribute.map_err(|error| RefreshError::Metalink(error.to_string()))?;
        if attribute.key.as_ref() == key {
            return attribute
                .decoded_and_normalized_value(quick_xml::XmlVersion::Implicit1_0, reader.decoder())
                .map(|value| Some(value.into_owned()))
                .map_err(|error| RefreshError::Metalink(error.to_string()));
        }
    }
    Ok(None)
}
