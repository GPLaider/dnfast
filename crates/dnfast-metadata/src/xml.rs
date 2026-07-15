use quick_xml::{
    Reader,
    encoding::Decoder,
    events::{BytesStart, BytesText},
};

use crate::MetadataError;

pub(crate) fn default_namespace(
    reader: &Reader<&[u8]>,
    event: &BytesStart<'_>,
) -> Result<Option<String>, MetadataError> {
    for attribute in event.attributes() {
        let attribute = attribute.map_err(|error| MetadataError::Xml(error.to_string()))?;
        if attribute.key.as_ref() == b"xmlns" {
            return attribute
                .decoded_and_normalized_value(quick_xml::XmlVersion::Implicit1_0, reader.decoder())
                .map(|value| Some(value.into_owned()))
                .map_err(|error| MetadataError::Xml(error.to_string()));
        }
    }
    Ok(None)
}

pub(crate) fn attribute(
    reader: &Reader<&[u8]>,
    event: &BytesStart<'_>,
    key: &[u8],
) -> Result<Option<String>, MetadataError> {
    attribute_streaming(reader.decoder(), event, key)
}

pub(crate) fn attribute_streaming(
    decoder: Decoder,
    event: &BytesStart<'_>,
    key: &[u8],
) -> Result<Option<String>, MetadataError> {
    for attribute in event.attributes() {
        let attribute = attribute.map_err(|error| MetadataError::Xml(error.to_string()))?;
        if attribute.key.as_ref() == key {
            return attribute
                .decoded_and_normalized_value(quick_xml::XmlVersion::Implicit1_0, decoder)
                .map(|value| Some(value.into_owned()))
                .map_err(|error| MetadataError::Xml(error.to_string()));
        }
    }
    Ok(None)
}

pub(crate) fn decode_text(event: &BytesText<'_>) -> Result<String, MetadataError> {
    let decoded = event
        .decode()
        .map_err(|error| MetadataError::Xml(error.to_string()))?;
    quick_xml::escape::unescape(&decoded)
        .map(|value| value.into_owned())
        .map_err(|error| MetadataError::Xml(error.to_string()))
}

pub(crate) fn parse_number(value: &str) -> Result<u64, MetadataError> {
    value
        .parse()
        .map_err(|_| MetadataError::InvalidNumber(value.to_owned()))
}
