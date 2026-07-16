use std::collections::BTreeSet;

use quick_xml::{Reader, events::Event};

use crate::{MetadataError, xml::decode_reference};

const MAX_COMPS_GROUPS: usize = 100_000;
const MAX_COMPS_ENVIRONMENTS: usize = 10_000;
const MAX_COMPS_PACKAGES: usize = 2_000_000;
const MAX_COMPS_PACKAGES_PER_GROUP: usize = 100_000;
const MAX_COMPS_GROUPS_PER_ENVIRONMENT: usize = 100_000;
const MAX_COMPS_TEXT_BYTES: usize = 1024 * 1024;
const MAX_COMPS_DEPTH: usize = 64;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Comps {
    pub groups: Vec<CompsGroup>,
    pub environments: Vec<CompsEnvironment>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompsGroup {
    pub id: String,
    pub name: String,
    pub description: String,
    pub default: bool,
    pub user_visible: bool,
    pub packages: Vec<CompsPackage>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompsEnvironment {
    pub id: String,
    pub name: String,
    pub description: String,
    pub groups: Vec<String>,
    pub optional_groups: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct CompsPackage {
    pub name: String,
    pub kind: CompsPackageType,
    pub condition: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum CompsPackageType {
    Mandatory,
    Default,
    Optional,
    Conditional,
}

#[derive(Default)]
struct GroupBuilder {
    id: String,
    name: String,
    description: String,
    default: Option<bool>,
    user_visible: Option<bool>,
    packages: Vec<CompsPackage>,
}

#[derive(Default)]
struct EnvironmentBuilder {
    id: String,
    name: String,
    description: String,
    groups: Vec<String>,
    optional_groups: Vec<String>,
}

enum TextTarget {
    GroupId,
    GroupName,
    GroupDescription,
    GroupDefault,
    GroupVisible,
    Package(CompsPackageType, Option<String>),
    EnvironmentId,
    EnvironmentName,
    EnvironmentDescription,
    EnvironmentGroup(bool),
}

struct TextValue {
    target: TextTarget,
    value: String,
}

pub fn parse_comps(input: &[u8]) -> Result<Comps, MetadataError> {
    let mut reader = Reader::from_reader(input);
    reader.config_mut().trim_text(false);
    reader.config_mut().check_end_names = true;
    let mut stack = Vec::<Vec<u8>>::new();
    let mut groups = Vec::new();
    let mut environments = Vec::new();
    let mut group = None;
    let mut environment = None;
    let mut text = None;
    let mut declaration_seen = false;
    let mut doctype_seen = false;
    let mut root_closed = false;

    loop {
        match reader.read_event() {
            Ok(Event::Start(event)) => {
                if root_closed || stack.len() >= MAX_COMPS_DEPTH {
                    return xml("content after comps root or excessive XML depth");
                }
                let name = event.name().as_ref().to_vec();
                reject_prefixed(&name)?;
                if stack.is_empty() {
                    if name != b"comps" {
                        return xml("unexpected comps root");
                    }
                } else if stack.len() == 1 && name == b"group" {
                    if group.replace(GroupBuilder::default()).is_some() {
                        return xml("nested comps group");
                    }
                } else if stack.len() == 1
                    && name == b"environment"
                    && environment.replace(EnvironmentBuilder::default()).is_some()
                {
                    return xml("nested comps environment");
                }
                let parent = stack.last().map(Vec::as_slice);
                text = text_target(
                    &reader,
                    &event,
                    parent,
                    group.is_some(),
                    environment.is_some(),
                )?
                .map(|target| TextValue {
                    target,
                    value: String::new(),
                });
                stack.push(name);
            }
            Ok(Event::Empty(event)) => {
                if stack.is_empty() || root_closed {
                    return xml("empty element outside comps root");
                }
                reject_prefixed(event.name().as_ref())?;
            }
            Ok(Event::Text(event)) => {
                if let Some(value) = text.as_mut() {
                    append(&mut value.value, &event.decode().map_err(xml_error)?)?;
                } else if stack.is_empty() || root_closed {
                    let decoded = event.decode().map_err(xml_error)?;
                    if !decoded.trim().is_empty() {
                        return xml("text outside comps root");
                    }
                }
            }
            Ok(Event::GeneralRef(event)) => {
                let value = text.as_mut().ok_or_else(|| {
                    MetadataError::Xml("entity reference outside comps text".into())
                })?;
                append(&mut value.value, &decode_reference(&event)?)?;
            }
            Ok(Event::CData(event)) => {
                let value = text
                    .as_mut()
                    .ok_or_else(|| MetadataError::Xml("CDATA outside comps text".into()))?;
                append(&mut value.value, &event.decode().map_err(xml_error)?)?;
            }
            Ok(Event::End(event)) => {
                let expected = stack
                    .pop()
                    .ok_or_else(|| MetadataError::Xml("comps end without start".into()))?;
                if expected.as_slice() != event.name().as_ref() {
                    return xml("mismatched comps element");
                }
                if let Some(value) = text.take() {
                    finish_text(value, group.as_mut(), environment.as_mut())?;
                }
                if expected == b"group" {
                    let finished =
                        finish_group(group.take().ok_or_else(|| {
                            MetadataError::Xml("group end without group".into())
                        })?)?;
                    groups.push(finished);
                    checked_len(groups.len(), MAX_COMPS_GROUPS, "comps groups")?;
                } else if expected == b"environment" {
                    let finished = finish_environment(environment.take().ok_or_else(|| {
                        MetadataError::Xml("environment end without environment".into())
                    })?)?;
                    environments.push(finished);
                    checked_len(
                        environments.len(),
                        MAX_COMPS_ENVIRONMENTS,
                        "comps environments",
                    )?;
                } else if expected == b"comps" {
                    root_closed = true;
                }
            }
            Ok(Event::Decl(_)) if stack.is_empty() && !declaration_seen && !root_closed => {
                declaration_seen = true;
            }
            Ok(Event::DocType(event)) if stack.is_empty() && !doctype_seen && !root_closed => {
                let value = event.decode().map_err(xml_error)?;
                let normalized = value
                    .replace('"', "'")
                    .split_whitespace()
                    .collect::<Vec<_>>()
                    .join(" ");
                if normalized != "comps PUBLIC '-//Red Hat, Inc.//DTD Comps info//EN' 'comps.dtd'" {
                    return xml("unrecognized comps doctype");
                }
                doctype_seen = true;
            }
            Ok(Event::Decl(_) | Event::DocType(_)) => {
                return xml("misplaced XML declaration or comps doctype");
            }
            Ok(Event::Comment(_) | Event::PI(_)) => {}
            Ok(Event::Eof) => break,
            Err(error) => return Err(MetadataError::Xml(error.to_string())),
        }
    }
    if !root_closed || !stack.is_empty() || group.is_some() || environment.is_some() {
        return xml("incomplete comps document");
    }
    let package_count = groups.iter().try_fold(0_usize, |total, item| {
        total
            .checked_add(item.packages.len())
            .ok_or(MetadataError::LimitExceeded {
                kind: "comps packages",
                maximum: MAX_COMPS_PACKAGES as u64,
                actual: u64::MAX,
            })
    })?;
    checked_len(package_count, MAX_COMPS_PACKAGES, "comps packages")?;
    groups.sort_by(|left, right| left.id.cmp(&right.id));
    environments.sort_by(|left, right| left.id.cmp(&right.id));
    reject_duplicate_ids(groups.iter().map(|item| item.id.as_str()), "comps group")?;
    reject_duplicate_ids(
        environments.iter().map(|item| item.id.as_str()),
        "comps environment",
    )?;
    Ok(Comps {
        groups,
        environments,
    })
}

fn text_target(
    reader: &Reader<&[u8]>,
    event: &quick_xml::events::BytesStart<'_>,
    parent: Option<&[u8]>,
    in_group: bool,
    in_environment: bool,
) -> Result<Option<TextTarget>, MetadataError> {
    let event_name = event.name();
    let name = event_name.as_ref();
    let translated = event
        .attributes()
        .map(|item| item.map_err(xml_error))
        .collect::<Result<Vec<_>, _>>()?
        .iter()
        .any(|attribute| attribute.key.as_ref() == b"xml:lang");
    let target = if in_group {
        match (parent, name) {
            (Some(b"group"), b"id") => Some(TextTarget::GroupId),
            (Some(b"group"), b"name") if !translated => Some(TextTarget::GroupName),
            (Some(b"group"), b"description") if !translated => Some(TextTarget::GroupDescription),
            (Some(b"group"), b"default") => Some(TextTarget::GroupDefault),
            (Some(b"group"), b"uservisible") => Some(TextTarget::GroupVisible),
            (Some(b"packagelist"), b"packagereq") => {
                let kind = required_attribute(reader, event, b"type")?;
                let kind = match kind.as_str() {
                    "mandatory" => CompsPackageType::Mandatory,
                    "default" => CompsPackageType::Default,
                    "optional" => CompsPackageType::Optional,
                    "conditional" => CompsPackageType::Conditional,
                    _ => return xml("unsupported comps package type"),
                };
                let condition = optional_attribute(reader, event, b"requires")?;
                if kind == CompsPackageType::Conditional && condition.is_none() {
                    return xml("conditional comps package has no requires attribute");
                }
                if kind != CompsPackageType::Conditional && condition.is_some() {
                    return xml("non-conditional comps package has a requires attribute");
                }
                Some(TextTarget::Package(kind, condition))
            }
            _ => None,
        }
    } else if in_environment {
        match (parent, name) {
            (Some(b"environment"), b"id") => Some(TextTarget::EnvironmentId),
            (Some(b"environment"), b"name") if !translated => Some(TextTarget::EnvironmentName),
            (Some(b"environment"), b"description") if !translated => {
                Some(TextTarget::EnvironmentDescription)
            }
            (Some(b"grouplist"), b"groupid") => Some(TextTarget::EnvironmentGroup(false)),
            (Some(b"optionlist"), b"groupid") => Some(TextTarget::EnvironmentGroup(true)),
            _ => None,
        }
    } else {
        None
    };
    Ok(target)
}

fn finish_text(
    text: TextValue,
    group: Option<&mut GroupBuilder>,
    environment: Option<&mut EnvironmentBuilder>,
) -> Result<(), MetadataError> {
    let value = text.value.trim().to_owned();
    match text.target {
        TextTarget::GroupId => set_once(&mut required_group(group)?.id, value, "group id"),
        TextTarget::GroupName => set_once(&mut required_group(group)?.name, value, "group name"),
        TextTarget::GroupDescription => set_once(
            &mut required_group(group)?.description,
            value,
            "group description",
        ),
        TextTarget::GroupDefault => {
            set_bool(&mut required_group(group)?.default, &value, "group default")
        }
        TextTarget::GroupVisible => set_bool(
            &mut required_group(group)?.user_visible,
            &value,
            "group uservisible",
        ),
        TextTarget::Package(kind, condition) => {
            validate_identifier(&value, "package name")?;
            if let Some(condition) = &condition {
                validate_identifier(condition, "conditional package requirement")?;
            }
            let group = required_group(group)?;
            group.packages.push(CompsPackage {
                name: value,
                kind,
                condition,
            });
            checked_len(
                group.packages.len(),
                MAX_COMPS_PACKAGES_PER_GROUP,
                "packages per comps group",
            )
        }
        TextTarget::EnvironmentId => set_once(
            &mut required_environment(environment)?.id,
            value,
            "environment id",
        ),
        TextTarget::EnvironmentName => set_once(
            &mut required_environment(environment)?.name,
            value,
            "environment name",
        ),
        TextTarget::EnvironmentDescription => set_once(
            &mut required_environment(environment)?.description,
            value,
            "environment description",
        ),
        TextTarget::EnvironmentGroup(optional) => {
            validate_identifier(&value, "environment group id")?;
            let environment = required_environment(environment)?;
            let list = if optional {
                &mut environment.optional_groups
            } else {
                &mut environment.groups
            };
            list.push(value);
            checked_len(
                list.len(),
                MAX_COMPS_GROUPS_PER_ENVIRONMENT,
                "groups per comps environment",
            )
        }
    }
}

fn finish_group(builder: GroupBuilder) -> Result<CompsGroup, MetadataError> {
    validate_identifier(&builder.id, "group id")?;
    validate_text(&builder.name, "group name")?;
    let mut packages = builder.packages;
    packages.sort_by(|left, right| {
        left.kind
            .cmp(&right.kind)
            .then_with(|| left.name.cmp(&right.name))
            .then_with(|| left.condition.cmp(&right.condition))
    });
    let mut names = BTreeSet::new();
    if packages
        .iter()
        .any(|item| !names.insert(item.name.as_str()))
    {
        return xml("duplicate package in comps group");
    }
    Ok(CompsGroup {
        id: builder.id,
        name: builder.name,
        description: builder.description,
        default: builder.default.unwrap_or(false),
        user_visible: builder.user_visible.unwrap_or(true),
        packages,
    })
}

fn finish_environment(builder: EnvironmentBuilder) -> Result<CompsEnvironment, MetadataError> {
    validate_identifier(&builder.id, "environment id")?;
    validate_text(&builder.name, "environment name")?;
    let mut groups = builder.groups;
    let mut optional_groups = builder.optional_groups;
    groups.sort();
    optional_groups.sort();
    if groups.windows(2).any(|pair| pair[0] == pair[1])
        || optional_groups.windows(2).any(|pair| pair[0] == pair[1])
        || groups
            .iter()
            .any(|id| optional_groups.binary_search(id).is_ok())
    {
        return xml("duplicate group in comps environment");
    }
    Ok(CompsEnvironment {
        id: builder.id,
        name: builder.name,
        description: builder.description,
        groups,
        optional_groups,
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
) -> Result<String, MetadataError> {
    optional_attribute(reader, event, name)?
        .ok_or_else(|| MetadataError::Xml("missing required comps attribute".into()))
}

fn required_group(value: Option<&mut GroupBuilder>) -> Result<&mut GroupBuilder, MetadataError> {
    value.ok_or_else(|| MetadataError::Xml("group field outside group".into()))
}

fn required_environment(
    value: Option<&mut EnvironmentBuilder>,
) -> Result<&mut EnvironmentBuilder, MetadataError> {
    value.ok_or_else(|| MetadataError::Xml("environment field outside environment".into()))
}

fn append(target: &mut String, value: &str) -> Result<(), MetadataError> {
    target
        .try_reserve(value.len())
        .map_err(|error| MetadataError::Io(error.to_string()))?;
    target.push_str(value);
    checked_len(target.len(), MAX_COMPS_TEXT_BYTES, "comps XML text")
}

fn set_once(target: &mut String, value: String, kind: &'static str) -> Result<(), MetadataError> {
    if !target.is_empty() {
        return xml(&format!("duplicate {kind}"));
    }
    validate_text(&value, kind)?;
    *target = value;
    Ok(())
}

fn set_bool(
    target: &mut Option<bool>,
    value: &str,
    kind: &'static str,
) -> Result<(), MetadataError> {
    if target.is_some() {
        return xml(&format!("duplicate {kind}"));
    }
    *target = Some(match value {
        "true" => true,
        "false" => false,
        _ => return xml(&format!("invalid {kind}")),
    });
    Ok(())
}

fn validate_identifier(value: &str, kind: &'static str) -> Result<(), MetadataError> {
    validate_text(value, kind)?;
    if value.chars().any(char::is_whitespace) {
        return xml(&format!("invalid {kind}"));
    }
    Ok(())
}

fn validate_text(value: &str, kind: &'static str) -> Result<(), MetadataError> {
    if value.is_empty() || value.chars().any(char::is_control) {
        return xml(&format!("invalid {kind}"));
    }
    Ok(())
}

fn reject_prefixed(name: &[u8]) -> Result<(), MetadataError> {
    if name.contains(&b':') {
        return xml("unexpected comps namespace prefix");
    }
    Ok(())
}

fn reject_duplicate_ids<'a>(
    values: impl IntoIterator<Item = &'a str>,
    kind: &'static str,
) -> Result<(), MetadataError> {
    let mut previous = None;
    for value in values {
        if previous == Some(value) {
            return xml(&format!("duplicate {kind} id"));
        }
        previous = Some(value);
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

fn xml<T>(message: &str) -> Result<T, MetadataError> {
    Err(MetadataError::Xml(message.into()))
}

fn xml_error(error: impl std::fmt::Display) -> MetadataError {
    MetadataError::Xml(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"<?xml version="1.0"?>
<!DOCTYPE comps PUBLIC '-//Red Hat, Inc.//DTD Comps info//EN' 'comps.dtd'>
<comps>
  <group><id>tools</id><name>Tools</name><name xml:lang="ko">도구</name>
    <description>A &amp; B</description><default>true</default><uservisible>true</uservisible>
    <packagelist>
      <packagereq type="optional">extra</packagereq>
      <packagereq type="conditional" requires="base">addon</packagereq>
      <packagereq type="mandatory">base</packagereq>
      <packagereq type="default">normal</packagereq>
    </packagelist></group>
  <environment><id>workstation</id><name>Workstation</name><description>Desktop</description>
    <grouplist><groupid>tools</groupid></grouplist>
    <optionlist><groupid>extras</groupid></optionlist></environment>
</comps>"#;

    #[test]
    fn parses_canonical_groups_environments_and_package_types() {
        let parsed = parse_comps(SAMPLE.as_bytes()).expect("valid comps");
        assert_eq!(parsed.groups[0].id, "tools");
        assert_eq!(parsed.groups[0].name, "Tools");
        assert_eq!(parsed.groups[0].description, "A & B");
        assert_eq!(parsed.groups[0].packages[0].name, "base");
        assert_eq!(
            parsed.groups[0].packages[0].kind,
            CompsPackageType::Mandatory
        );
        assert_eq!(parsed.environments[0].groups, ["tools"]);
        assert_eq!(parsed.environments[0].optional_groups, ["extras"]);
    }

    #[test]
    fn rejects_custom_doctype_entities_duplicates_and_invalid_conditionals() {
        assert!(parse_comps(SAMPLE.replace("comps.dtd", "evil.dtd").as_bytes()).is_err());
        assert!(parse_comps(SAMPLE.replace("A &amp; B", "A &evil; B").as_bytes()).is_err());
        assert!(
            parse_comps(
                SAMPLE
                    .replace("<id>tools</id>", "<id>tools</id><id>x</id>")
                    .as_bytes()
            )
            .is_err()
        );
        assert!(parse_comps(SAMPLE.replace(" requires=\"base\"", "").as_bytes()).is_err());
    }
}
