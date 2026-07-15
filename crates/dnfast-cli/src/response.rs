use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

pub(crate) const CLI_SCHEMA: &str = "dnfast.cli.v1";

#[derive(Clone, Copy, Debug)]
pub(crate) enum JsonOutput {
    NativeV1,
    RequestedV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Status {
    Planned,
    Applied,
    Aborted,
    Failed,
    Unsupported,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Action {
    pub(crate) kind: String,
    pub(crate) name: String,
    pub(crate) epoch: String,
    pub(crate) version: String,
    pub(crate) release: String,
    pub(crate) arch: String,
    pub(crate) repo_id: Option<String>,
    pub(crate) reason: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Error {
    pub(crate) code: String,
    pub(crate) message: String,
    pub(crate) context: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Response {
    pub(crate) schema: String,
    pub(crate) command: String,
    pub(crate) status: Status,
    pub(crate) exit_code: u8,
    pub(crate) message: Option<String>,
    pub(crate) plan_digest: Option<String>,
    pub(crate) plan_path: Option<String>,
    pub(crate) transaction_id: Option<String>,
    pub(crate) actions: Vec<Action>,
    pub(crate) errors: Vec<Error>,
}

impl Response {
    pub(crate) fn from_daemon(outcome: dnfast_executor::DaemonOutcome) -> Self {
        let status = match outcome.status {
            dnfast_executor::DaemonStatus::Applied => Status::Applied,
            dnfast_executor::DaemonStatus::Aborted => Status::Aborted,
        };
        Self {
            schema: CLI_SCHEMA.into(),
            command: outcome.command,
            status,
            exit_code: 0,
            message: None,
            plan_digest: Some(outcome.plan_digest),
            plan_path: None,
            transaction_id: outcome.transaction_id,
            actions: outcome
                .actions
                .into_iter()
                .map(|action| Action {
                    kind: action.kind,
                    name: action.name,
                    epoch: action.epoch,
                    version: action.version,
                    release: action.release,
                    arch: action.arch,
                    repo_id: action.repo_id,
                    reason: action.reason,
                })
                .collect(),
            errors: Vec::new(),
        }
    }

    pub(crate) fn failed(
        command: &str,
        exit_code: u8,
        code: &str,
        message: impl Into<String>,
    ) -> Self {
        let message = message.into();
        Self {
            schema: CLI_SCHEMA.into(),
            command: command.into(),
            status: Status::Failed,
            exit_code,
            message: Some(message.clone()),
            plan_digest: None,
            plan_path: None,
            transaction_id: None,
            actions: Vec::new(),
            errors: vec![Error {
                code: code.into(),
                message,
                context: BTreeMap::new(),
            }],
        }
    }

    pub(crate) fn planned(
        command: &str,
        plan_digest: String,
        plan_path: String,
        actions: Vec<Action>,
    ) -> Self {
        Self {
            schema: CLI_SCHEMA.into(),
            command: command.into(),
            status: Status::Planned,
            exit_code: 0,
            message: None,
            plan_digest: Some(plan_digest),
            plan_path: Some(plan_path),
            transaction_id: None,
            actions,
            errors: Vec::new(),
        }
    }

    pub(crate) fn completed(command: &str, message: impl Into<String>) -> Self {
        Self {
            schema: CLI_SCHEMA.into(),
            command: command.into(),
            status: Status::Planned,
            exit_code: 0,
            message: Some(message.into()),
            plan_digest: None,
            plan_path: None,
            transaction_id: None,
            actions: Vec::new(),
            errors: Vec::new(),
        }
    }

    pub(crate) fn unsupported(command: &str) -> Self {
        let message = format!("unsupported command: {command}");
        Self {
            schema: CLI_SCHEMA.into(),
            command: command.into(),
            status: Status::Unsupported,
            exit_code: 2,
            message: Some(message.clone()),
            plan_digest: None,
            plan_path: None,
            transaction_id: None,
            actions: Vec::new(),
            errors: vec![Error {
                code: "unsupported_command".into(),
                message,
                context: BTreeMap::from([("command".into(), command.into())]),
            }],
        }
    }

    pub(crate) fn json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

pub(crate) fn emit(response: &Response, output: JsonOutput) -> Result<(), serde_json::Error> {
    let encoded = match output {
        JsonOutput::NativeV1 | JsonOutput::RequestedV1 => response.json()?,
    };
    println!("{encoded}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{CLI_SCHEMA, Response, Status};

    #[test]
    fn unsupported_response_has_the_frozen_v1_shape() {
        // Given a frozen unsupported command name.
        let response = Response::unsupported("group");
        // When the response crosses the JSON boundary.
        let encoded = response.json().unwrap();
        // Then all v1 fields are present in the specified order and consumers parse it.
        assert_eq!(
            encoded,
            r#"{"schema":"dnfast.cli.v1","command":"group","status":"unsupported","exit_code":2,"message":"unsupported command: group","plan_digest":null,"plan_path":null,"transaction_id":null,"actions":[],"errors":[{"code":"unsupported_command","message":"unsupported command: group","context":{"command":"group"}}]}"#
        );
        let decoded: Response = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded.schema, CLI_SCHEMA);
        assert_eq!(decoded.status, Status::Unsupported);
    }

    #[test]
    fn consumer_rejects_unknown_and_duplicate_response_fields() {
        // Given invalid consumer input at the schema boundary.
        let unknown = r#"{"schema":"dnfast.cli.v1","command":"group","status":"unsupported","exit_code":2,"message":null,"plan_digest":null,"plan_path":null,"transaction_id":null,"actions":[],"errors":[],"extra":true}"#;
        let duplicate = r#"{"schema":"dnfast.cli.v1","schema":"dnfast.cli.v1","command":"group","status":"unsupported","exit_code":2,"message":null,"plan_digest":null,"plan_path":null,"transaction_id":null,"actions":[],"errors":[]}"#;
        // When a strict response consumer parses it.
        let unknown_result = serde_json::from_str::<Response>(unknown);
        let duplicate_result = serde_json::from_str::<Response>(duplicate);
        // Then neither ambiguous document is accepted.
        assert!(unknown_result.is_err());
        assert!(duplicate_result.is_err());
    }
}
