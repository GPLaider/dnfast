use quick_xml::events::BytesStart;
use serde::{Deserialize, Serialize};

use crate::{xml::attribute_streaming, MetadataError};

pub const MAX_RELATIONS: u64 = 20_000_000;
pub const MAX_RELATIONS_PER_PACKAGE: usize = 4_096;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum RelationFlags { Equal, Less, LessEqual, Greater, GreaterEqual }

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Relation {
    pub name: String,
    pub flags: Option<RelationFlags>,
    pub epoch: Option<String>,
    pub version: Option<String>,
    pub release: Option<String>,
    pub pre: bool,
}

pub(crate) fn parse_relation(
    decoder: quick_xml::encoding::Decoder,
    event: &BytesStart<'_>,
) -> Result<Relation, MetadataError> {
    let name = attribute_streaming(decoder, event, b"name")?
        .ok_or_else(|| MetadataError::Xml("relation missing name".into()))?;
    let flags = match attribute_streaming(decoder, event, b"flags")?.as_deref() {
        None => None,
        Some("EQ") => Some(RelationFlags::Equal),
        Some("LT") => Some(RelationFlags::Less),
        Some("LE") => Some(RelationFlags::LessEqual),
        Some("GT") => Some(RelationFlags::Greater),
        Some("GE") => Some(RelationFlags::GreaterEqual),
        Some(value) => return Err(MetadataError::Xml(format!("unsupported relation flags: {value}"))),
    };
    Ok(Relation {
        name,
        flags,
        epoch: attribute_streaming(decoder, event, b"epoch")?,
        version: attribute_streaming(decoder, event, b"ver")?,
        release: attribute_streaming(decoder, event, b"rel")?,
        pre: attribute_streaming(decoder, event, b"pre")?.as_deref() == Some("1"),
    })
}
