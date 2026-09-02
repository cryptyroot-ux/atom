//! Provider-backed conversational endpoint used by the interactive CLI.
#![forbid(unsafe_code)]

use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::app::{AppState, ChatConfig};
use crate::error::ApiError;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChatBody {
    pub messages: Vec<ChatMessage>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
}

#[derive(Debug, Serialize)]
pub struct ChatReply {
    pub content: String,
    pub model: String,
}

#[derive(Debug, Serialize)]
struct WireRequest<'a> {
    model: &'a str,
    messages: &'a [ChatMessage],
}

#[derive(Debug, Deserialize)]
struct WireResponse {
    choices: Vec<WireChoice>,
}

#[derive(Debug, Deserialize)]
struct WireChoice {
    message: ChatMessage,
}

pub async fn chat(
    State(state): State<AppState>,
    Json(body): Json<ChatBody>,
) -> Result<Json<ChatReply>, ApiError> {
    if body.messages.is_empty() || body.messages.len() > 64 {
        return Err(ApiError::bad_request(
            "/chat",
            "messages must contain between 1 and 64 entries",
        ));
    }
    if body
        .messages
        .iter()
        .any(|message| message.content.is_empty() || message.content.len() > 32_768)
    {
        return Err(ApiError::bad_request(
            "/chat",
            "message content must be between 1 and 32768 bytes",
        ));
    }
    if body
        .messages
        .iter()
        .any(|message| !matches!(message.role.as_str(), "system" | "user" | "assistant"))
    {
        return Err(ApiError::bad_request(
            "/chat",
            "message role must be system, user, or assistant",
        ));
    }
    let config = state.chat.ok_or_else(|| {
        ApiError::service_unavailable(
            "/chat",
            "no model provider is configured; run `sudo atom setup`",
        )
    })?;
    let url = format!(
        "{}/v1/chat/completions",
        config.base_url.trim_end_matches('/')
    );
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(config.timeout_ms))
        .build()
        .map_err(|error| ApiError::service_unavailable("/chat", error.to_string()))?;
    let response = client
        .post(url)
        .bearer_auth(&config.api_key)
        .json(&WireRequest {
            model: &config.model,
            messages: &body.messages,
        })
        .send()
        .await
        .map_err(|error| ApiError::service_unavailable("/chat", error.to_string()))?;
    if !response.status().is_success() {
        return Err(ApiError::service_unavailable(
            "/chat",
            format!("provider returned HTTP {}", response.status()),
        ));
    }
    if response
        .content_length()
        .is_some_and(|size| size > config.max_response_bytes as u64)
    {
        return Err(ApiError::service_unavailable(
            "/chat",
            "provider response too large",
        ));
    }
    let bytes = response
        .bytes()
        .await
        .map_err(|error| ApiError::service_unavailable("/chat", error.to_string()))?;
    if bytes.len() > config.max_response_bytes {
        return Err(ApiError::service_unavailable(
            "/chat",
            "provider response too large",
        ));
    }
    let parsed: WireResponse = serde_json::from_slice(&bytes)
        .map_err(|error| ApiError::service_unavailable("/chat", error.to_string()))?;
    let content = parsed
        .choices
        .first()
        .map(|choice| choice.message.content.trim().to_owned())
        .filter(|content| !content.is_empty())
        .ok_or_else(|| ApiError::service_unavailable("/chat", "provider returned no message"))?;
    Ok(Json(ChatReply {
        content,
        model: config.model.clone(),
    }))
}

pub type SharedChatConfig = Arc<ChatConfig>;
