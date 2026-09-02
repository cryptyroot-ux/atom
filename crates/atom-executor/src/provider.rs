//! HTTP model-provider cognition backend.
//!
//! A real provider is consulted **asynchronously outside the daemon loop**
//! (once per mission, before the runtime starts). Its response is cached as an
//! ordered plan of [`ProviderProposal`]s, and a synchronous [`CachedProvider`]
//! replays that plan during the runtime loop. Reducer/commit/effect state stays
//! deterministic with respect to the cached plan; the provider only proposes
//! and never mutates authoritative state or executes an external effect.
//!
//! The upstream wire contract is the OpenAI-compatible chat-completions shape:
//! `POST {base_url}/v1/chat/completions` with body
//! `{ "model", "messages": [system, user] }` and `Authorization: Bearer {key}`.
//! The assistant content is expected to be a JSON array of SCREAMING_SNAKE_CASE
//! mission commands, e.g. `["COMPILE","PREPARE","START","EXECUTE","VERIFY"]`.

use std::collections::VecDeque;

use atom_mission::MissionCommand;
use atom_provider::{Provider, ProviderProposal, ProviderRequest};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Configuration for connecting the executor to a model gateway.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProviderConfig {
    /// Whether the HTTP provider replaces the native cognition backend.
    pub enabled: bool,
    /// Base URL of the OpenAI-compatible gateway, e.g. `https://…`.
    pub base_url: String,
    /// Model identifier to ask for a plan.
    pub model: String,
    /// Gateway bearer token. Never hardcoded; fed from the environment.
    pub api_key: String,
}

/// Why the HTTP provider could not hand the runtime a plan.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProviderError {
    /// The HTTP call could not be completed.
    #[error("provider HTTP request failed: {0}")]
    Request(String),
    /// The gateway answered without a success status.
    #[error("provider returned non-success status {status}")]
    NonSuccess { status: u16 },
    /// The gateway body was not the expected shape.
    #[error("provider response malformed: {0}")]
    Malformed(String),
    /// The gateway returned no usable commands.
    #[error("provider returned an empty plan")]
    EmptyPlan,
}

/// The ordered, cached plan the runtime will replay during one mission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderPlan {
    mission_id: String,
    proposals: VecDeque<ProviderProposal>,
}

impl ProviderPlan {
    /// The mission this plan belongs to.
    #[must_use]
    pub fn mission_id(&self) -> &str {
        &self.mission_id
    }

    /// The ordered proposal cache.
    #[must_use]
    pub fn proposals(&self) -> &VecDeque<ProviderProposal> {
        &self.proposals
    }
}

/// Synchronous provider that replays an already-fetched [`ProviderPlan`].
///
/// This is the bridge between the async HTTP call (happened before the loop)
/// and the synchronous `Cognition::decide` inside the runtime loop. Each
/// `invoke` consumes the next cached proposal; an exhausted plan yields a safe
/// [`ProviderProposal::hold_terminal`].
#[derive(Clone, Debug)]
pub struct CachedProvider {
    plan: ProviderPlan,
}

impl CachedProvider {
    /// Wraps a cached plan for synchronous replay.
    #[must_use]
    pub fn new(plan: ProviderPlan) -> Self {
        Self { plan }
    }
}

impl Provider for CachedProvider {
    fn invoke(&mut self, request: ProviderRequest<'_>) -> ProviderProposal {
        if self.plan.mission_id != request.perception.mission_id {
            return ProviderProposal::hold_terminal();
        }
        self.plan.proposals.pop_front().unwrap_or_else(ProviderProposal::hold_terminal)
    }
}

/// The OpenAI-compatible request body we send to the gateway.
#[derive(Debug, Serialize)]
struct ChatRequest<'a> {
    model: &'a str,
    messages: Vec<ChatMessage>,
}

#[derive(Debug, Serialize)]
struct ChatMessage {
    role: &'static str,
    content: String,
}

/// The parseable part of the gateway response.
#[derive(Debug, Deserialize)]
struct ChatResponse {
    choices: Vec<ChatChoice>,
}

#[derive(Debug, Deserialize)]
struct ChatChoice {
    message: ChatMessageOut,
}

#[derive(Debug, Deserialize)]
struct ChatMessageOut {
    #[serde(default)]
    content: String,
}

/// Async HTTP client that fetches a mission plan from the gateway.
#[derive(Clone, Debug)]
pub struct HttpProposalClient {
    http: reqwest::Client,
    config: ProviderConfig,
}

impl HttpProposalClient {
    /// Creates a client for the given gateway configuration.
    #[must_use]
    pub fn new(config: ProviderConfig) -> Self {
        Self {
            http: reqwest::Client::new(),
            config,
        }
    }

    /// The wrapped gateway configuration.
    #[must_use]
    pub fn config(&self) -> &ProviderConfig {
        &self.config
    }

    /// Fetches and parses the ordered plan for `mission_id`.
    ///
    /// The user message states the mission identity and current lifecycle phase
    /// and asks for the next command sequence as a SCREAMING_SNAKE_CASE JSON
    /// array. This is advisory input to the model; the runtime still validates
    /// every command against its own state machine.
    pub async fn propose(
        &self,
        mission_id: &str,
        phase: &str,
    ) -> Result<ProviderPlan, ProviderError> {
        if !self.config.enabled {
            return Err(ProviderError::EmptyPlan);
        }

        let system = "You are the cognition backend of a sovereign mission \
            runtime. Propose mission commands only. Answer with a compact JSON \
            array of SCREAMING_SNAKE_CASE commands (COMPILE, PREPARE, START, \
            EXECUTE, VERIFY) that would drive the mission to a terminal state. \
            Never output commentary.";
        let user = format!("mission id: {mission_id}\ncurrent phase: {phase}\nplan:");

        let url = format!("{}/v1/chat/completions", self.config.base_url.trim_end_matches('/'));
        let body = ChatRequest {
            model: &self.config.model,
            messages: vec![
                ChatMessage {
                    role: "system",
                    content: system.to_owned(),
                },
                ChatMessage {
                    role: "user",
                    content: user,
                },
            ],
        };

        let response = self
            .http
            .post(&url)
            .bearer_auth(&self.config.api_key)
            .json(&body)
            .send()
            .await
            .map_err(|e| ProviderError::Request(e.to_string()))?;

        if !response.status().is_success() {
            return Err(ProviderError::NonSuccess {
                status: response.status().as_u16(),
            });
        }

        let chat: ChatResponse = response
            .json()
            .await
            .map_err(|e| ProviderError::Malformed(e.to_string()))?;

        let content = chat
            .choices
            .first()
            .map(|choice| choice.message.content.as_str())
            .unwrap_or("");

        let commands: Vec<MissionCommand> = serde_json::from_str(content)
            .map_err(|e| ProviderError::Malformed(e.to_string()))?;

        if commands.is_empty() {
            return Err(ProviderError::EmptyPlan);
        }

        Ok(ProviderPlan {
            mission_id: mission_id.to_owned(),
            proposals: commands
                .into_iter()
                .map(ProviderProposal::activity)
                .collect(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use atom_runtime::Perception;
    use chrono::{TimeZone, Utc};

    fn parse_phase(name: &'static str) -> atom_mission::MissionPhase {
        match name {
            "CREATED" => atom_mission::MissionPhase::Created,
            "COMPILED" => atom_mission::MissionPhase::Compiled,
            "READY" => atom_mission::MissionPhase::Ready,
            "RUNNING" => atom_mission::MissionPhase::Running,
            "VERIFYING" => atom_mission::MissionPhase::Verifying,
            "TERMINAL" => atom_mission::MissionPhase::Terminal,
            other => panic!("unknown phase {other}"),
        }
    }

    fn perception_at(mission_id: &str, phase: &'static str) -> Perception {
        Perception {
            mission_id: mission_id.to_owned(),
            observed_at: fixed_time(),
            mission_state: atom_mission::MissionState {
                phase: parse_phase(phase),
                condition: atom_mission::MissionCondition::Normal,
                outcome: None,
                reason: None,
            },
            pending_effect: None,
        }
    }

    fn fixed_time() -> chrono::DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 9, 2, 0, 0, 0)
            .single()
            .expect("fixed test time")
    }

    #[test]
    fn cached_provider_replays_plan_in_order() {
        let plan = ProviderPlan {
            mission_id: "m1".to_owned(),
            proposals: vec![
                ProviderProposal::activity(MissionCommand::Compile),
                ProviderProposal::activity(MissionCommand::Prepare),
            ]
            .into(),
        };
        let mut provider = CachedProvider::new(plan);
        let mut request = perception_at("m1", "CREATED");
        assert_eq!(
            provider.invoke(ProviderRequest::new(&request, 1)),
            ProviderProposal::activity(MissionCommand::Compile)
        );
        request.mission_state.phase = parse_phase("COMPILED");
        assert_eq!(
            provider.invoke(ProviderRequest::new(&request, 2)),
            ProviderProposal::activity(MissionCommand::Prepare)
        );
        assert_eq!(
            provider.invoke(ProviderRequest::new(&request, 3)),
            ProviderProposal::hold_terminal()
        );
    }

    #[test]
    fn cached_provider_never_proposes_for_other_mission() {
        let plan = ProviderPlan {
            mission_id: "mine".to_owned(),
            proposals: vec![ProviderProposal::activity(MissionCommand::Start)].into(),
        };
        let mut provider = CachedProvider::new(plan);
        let request = perception_at("other", "CREATED");
        assert_eq!(
            provider.invoke(ProviderRequest::new(&request, 1)),
            ProviderProposal::hold_terminal()
        );
    }

    #[test]
    fn plan_parses_from_snake_case_command_array() {
        let commands: Vec<MissionCommand> =
            serde_json::from_str(r#"["COMPILE","START"]"#).expect("parses");
        assert_eq!(commands, vec![MissionCommand::Compile, MissionCommand::Start]);
    }
}