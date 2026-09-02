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

use std::{collections::VecDeque, time::Duration};

use atom_mission::{
    try_reduce, ActivityResultEvent, MissionCommand, MissionCondition, MissionEvent, MissionPhase,
    MissionState,
};
use atom_provider::{Provider, ProviderProposal, ProviderRequest};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Configuration for connecting the executor to a model gateway.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
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
    /// Total timeout for one HTTP request, in milliseconds.
    pub timeout_ms: u64,
    /// Number of retries after the initial request for transient failures.
    pub max_retries: u32,
    /// Initial retry delay, doubled for each subsequent attempt.
    pub backoff_ms: u64,
    /// Maximum number of lifecycle commands accepted in one provider plan.
    pub max_plan_steps: usize,
    /// Maximum response body accepted from the gateway, in bytes.
    pub max_response_bytes: usize,
}

impl ProviderConfig {
    /// Validates operator-supplied provider settings before any network call.
    pub fn validate(&self) -> Result<(), ProviderError> {
        if !self.enabled {
            return Ok(());
        }
        if self.base_url.trim().is_empty() {
            return Err(ProviderError::Config(
                "base_url must not be blank".to_owned(),
            ));
        }
        if self.model.trim().is_empty() {
            return Err(ProviderError::Config("model must not be blank".to_owned()));
        }
        if self.timeout_ms == 0 {
            return Err(ProviderError::Config(
                "timeout_ms must be greater than zero".to_owned(),
            ));
        }
        if self.max_retries > 8 {
            return Err(ProviderError::Config(
                "max_retries must be at most 8".to_owned(),
            ));
        }
        if self.backoff_ms > 60_000 {
            return Err(ProviderError::Config(
                "backoff_ms must be at most 60000".to_owned(),
            ));
        }
        if self.max_plan_steps == 0 || self.max_plan_steps > 64 {
            return Err(ProviderError::Config(
                "max_plan_steps must be between 1 and 64".to_owned(),
            ));
        }
        if self.max_response_bytes == 0 || self.max_response_bytes > 1_048_576 {
            return Err(ProviderError::Config(
                "max_response_bytes must be between 1 and 1048576".to_owned(),
            ));
        }
        Ok(())
    }
}

impl Default for ProviderConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            base_url: String::new(),
            model: String::new(),
            api_key: String::new(),
            timeout_ms: 30_000,
            max_retries: 2,
            backoff_ms: 250,
            max_plan_steps: 8,
            max_response_bytes: 64 * 1024,
        }
    }
}

/// Why the HTTP provider could not hand the runtime a plan.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProviderError {
    /// The provider configuration is unsafe or incomplete.
    #[error("invalid provider configuration: {0}")]
    Config(String),
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
        self.plan
            .proposals
            .pop_front()
            .unwrap_or_else(ProviderProposal::hold_terminal)
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
    pub fn new(config: ProviderConfig) -> Result<Self, ProviderError> {
        config.validate()?;
        let timeout = Duration::from_millis(config.timeout_ms);
        let http = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|error| ProviderError::Config(format!("building HTTP client: {error}")))?;
        Ok(Self { http, config })
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

        let url = format!(
            "{}/v1/chat/completions",
            self.config.base_url.trim_end_matches('/')
        );
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

        let response = self.send_with_retry(&url, &body).await?;

        if !response.status().is_success() {
            return Err(ProviderError::NonSuccess {
                status: response.status().as_u16(),
            });
        }

        if response
            .content_length()
            .is_some_and(|length| length > self.config.max_response_bytes as u64)
        {
            return Err(ProviderError::Malformed(format!(
                "response exceeds {} bytes",
                self.config.max_response_bytes
            )));
        }
        let bytes = response
            .bytes()
            .await
            .map_err(|e| ProviderError::Malformed(e.to_string()))?;
        if bytes.len() > self.config.max_response_bytes {
            return Err(ProviderError::Malformed(format!(
                "response exceeds {} bytes",
                self.config.max_response_bytes
            )));
        }
        let chat: ChatResponse =
            serde_json::from_slice(&bytes).map_err(|e| ProviderError::Malformed(e.to_string()))?;

        let content = chat
            .choices
            .first()
            .map(|choice| choice.message.content.as_str())
            .unwrap_or("");

        let commands = validate_plan(content, phase, self.config.max_plan_steps)?;

        Ok(ProviderPlan {
            mission_id: mission_id.to_owned(),
            proposals: commands
                .into_iter()
                .map(ProviderProposal::activity)
                .collect(),
        })
    }

    async fn send_with_retry(
        &self,
        url: &str,
        body: &ChatRequest<'_>,
    ) -> Result<reqwest::Response, ProviderError> {
        for attempt in 0..=self.config.max_retries {
            let mut request = self.http.post(url);
            if !self.config.api_key.is_empty() {
                request = request.bearer_auth(&self.config.api_key);
            }
            match request.json(body).send().await {
                Ok(response)
                    if !retryable_status(response.status())
                        || attempt == self.config.max_retries =>
                {
                    return Ok(response);
                }
                Ok(_response) => sleep_backoff(&self.config, attempt).await,
                Err(error) if attempt == self.config.max_retries => {
                    return Err(ProviderError::Request(error.to_string()));
                }
                Err(_error) => sleep_backoff(&self.config, attempt).await,
            }
        }
        unreachable!("retry loop always returns on its final attempt")
    }
}

fn retryable_status(status: reqwest::StatusCode) -> bool {
    matches!(status.as_u16(), 408 | 425 | 429 | 500 | 502 | 503 | 504)
}

async fn sleep_backoff(config: &ProviderConfig, attempt: u32) {
    let shift = attempt.min(6);
    let multiplier = 1_u64 << shift;
    let delay_ms = config.backoff_ms.saturating_mul(multiplier).min(60_000);
    if delay_ms > 0 {
        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
    }
}

fn validate_plan(
    content: &str,
    phase: &str,
    max_plan_steps: usize,
) -> Result<Vec<MissionCommand>, ProviderError> {
    let commands: Vec<MissionCommand> = serde_json::from_str(content)
        .map_err(|e| ProviderError::Malformed(format!("commands must be a JSON array: {e}")))?;
    if commands.is_empty() {
        return Err(ProviderError::EmptyPlan);
    }
    if commands.len() > max_plan_steps {
        return Err(ProviderError::Malformed(format!(
            "plan contains {} commands; maximum is {max_plan_steps}",
            commands.len()
        )));
    }

    let mut state = MissionState::new(parse_phase(phase)?, MissionCondition::Normal, None, None)
        .map_err(|error| ProviderError::Malformed(error.to_string()))?;
    for (index, command) in commands.iter().copied().enumerate() {
        command.validate(&state).map_err(|error| {
            ProviderError::Malformed(format!("command {index} ({command:?}) is invalid: {error}"))
        })?;
        let event = MissionEvent::from(ActivityResultEvent::succeeded(command.activity().kind));
        state = try_reduce(&state, &event).map_err(|error| {
            ProviderError::Malformed(format!("command {index} rejected: {error}"))
        })?;
    }
    if state.phase != MissionPhase::Terminal {
        return Err(ProviderError::Malformed(
            "plan must reach TERMINAL with a complete lifecycle".to_owned(),
        ));
    }
    Ok(commands)
}

fn parse_phase(phase: &str) -> Result<MissionPhase, ProviderError> {
    match phase {
        "CREATED" => Ok(MissionPhase::Created),
        "COMPILED" => Ok(MissionPhase::Compiled),
        "READY" => Ok(MissionPhase::Ready),
        "RUNNING" => Ok(MissionPhase::Running),
        "VERIFYING" => Ok(MissionPhase::Verifying),
        other => Err(ProviderError::Malformed(format!(
            "unsupported starting phase {other:?}"
        ))),
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
        assert_eq!(
            commands,
            vec![MissionCommand::Compile, MissionCommand::Start]
        );
    }

    #[test]
    fn enabled_provider_rejects_unsafe_limits() {
        let mut config = ProviderConfig {
            enabled: true,
            base_url: "http://gateway".to_owned(),
            model: "model".to_owned(),
            ..ProviderConfig::default()
        };
        config.timeout_ms = 0;
        assert!(matches!(
            config.validate(),
            Err(ProviderError::Config(detail)) if detail.contains("timeout_ms")
        ));

        config.timeout_ms = 1_000;
        config.max_plan_steps = 65;
        assert!(config.validate().is_err());
    }
}
