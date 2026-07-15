use quick_xml::{Reader, events::Event};

use crate::{RefreshError, url_policy::validate_https};

pub(crate) const MAX_METALINK_BYTES: u64 = 2 * 1024 * 1024;
pub(crate) const MAX_REPOMD_BYTES: u64 = 16 * 1024 * 1024;
const MAX_METALINK_RESOURCES: usize = 32;

pub(crate) struct Metalink {
    pub(crate) size: u64,
    pub(crate) sha256: String,
    pub(crate) resources: Vec<Resource>,
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
    let mut resources = Vec::new();
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
                match event.name().as_ref() {
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
                    Some(b"hash") if hash_type_valid => sha256 = Some(value.to_ascii_lowercase()),
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
                if event.local_name().as_ref() == b"file" && in_repomd {
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
    let size = size.ok_or_else(|| RefreshError::Metalink("missing repomd size".into()))?;
    if size > MAX_REPOMD_BYTES {
        return Err(RefreshError::Metalink("repomd exceeds policy limit".into()));
    }
    let sha256 = sha256.ok_or_else(|| RefreshError::Metalink("missing repomd sha256".into()))?;
    if sha256.len() != 64 || !sha256.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(RefreshError::Metalink("invalid repomd sha256".into()));
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
        size,
        sha256,
        resources,
    })
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
