use std::collections::BTreeMap;

use crate::RepoError;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Variables(BTreeMap<String, String>);

impl Variables {
    pub fn from_pairs(pairs: impl IntoIterator<Item = (String, String)>) -> Self {
        Self(pairs.into_iter().collect())
    }

    pub(crate) fn with_system_release_and_arch(mut self, releasever: String, basearch: String) -> Self {
        self.0.insert("releasever".into(), releasever);
        self.0.insert("basearch".into(), basearch.clone());
        self.0.insert("arch".into(), basearch);
        self
    }

    pub fn expand(&self, input: &str) -> Result<String, RepoError> {
        let mut output = String::with_capacity(input.len());
        let mut characters = input.char_indices().peekable();
        while let Some((_, character)) = characters.next() {
            if character != '$' {
                output.push(character);
                continue;
            }
            let Some(&(next_index, next)) = characters.peek() else {
                output.push('$');
                break;
            };
            if next == '$' {
                characters.next();
                output.push('$');
                continue;
            }

            let name = if next == '{' {
                characters.next();
                let name_start = next_index + next.len_utf8();
                let mut name_end = None;
                for (index, current) in characters.by_ref() {
                    if current == '}' {
                        name_end = Some(index);
                        break;
                    }
                }
                let Some(name_end) = name_end else {
                    return Err(RepoError::MalformedVariable(input.to_owned()));
                };
                &input[name_start..name_end]
            } else if next == '_' || next.is_ascii_alphabetic() {
                let name_start = next_index;
                let mut name_end = input.len();
                while let Some(&(index, current)) = characters.peek() {
                    if current == '_' || current.is_ascii_alphanumeric() {
                        characters.next();
                    } else {
                        name_end = index;
                        break;
                    }
                }
                &input[name_start..name_end]
            } else {
                output.push('$');
                continue;
            };
            if name.is_empty() {
                return Err(RepoError::MalformedVariable(input.to_owned()));
            }
            let Some(value) = self.0.get(name) else {
                return Err(RepoError::UnresolvedVariable(name.to_owned()));
            };
            output.push_str(value);
        }
        Ok(output)
    }
}
