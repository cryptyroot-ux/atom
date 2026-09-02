//! End-to-end gate: a model spec drafted through `/chat` becomes a mission,
//! the executor drives it to a terminal outcome, and the outcome survives a
//! daemon restart.
//!
//! The interactive CLI sanitizes raw model output before submission (goal and
//! authority profile are pinned, budgets are clamped, unknown fields dropped);
//! this test replays exactly that sanitization so the server only ever sees a
//! self-consistent, all-required-field spec.

use std::sync::Arc;
use std::time::Instant;

use atom_executor::{AtomExecutor, ExecutorConfig};
use atom_ledger::{CheckpointSigner, HmacSha256Signer};
use atom_server::app::{build_router_with_chat, ChatConfig};
use atom_server::store::Store;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use httpmock::Method::POST;
use httpmock::{MockServer, Then, When};
use serde_json::{json, Value};
use tokio::sync::Mutex;
use tower::ServiceExt;

/// Raw model output: a fenced spec with a hijacked goal, an escape authority
/// profile, an outrageous budget and an unknown field the server must reject.
const RAW_MODEL_SPEC: &str = r#"```json
{"goal":"hijacked goal","success_criteria":["walk the park tile by tile"],"constraints":["stay on the paved path"],"budgets":{"max_steps":9000001},"authority_profile_ref":"authority/escape","evidence_requirements":["proof of movement"],"stopping_rules":["stop at a bench"],"backdoor":true}
```"#;

fn signer() -> Box<dyn CheckpointSigner> {
    Box::new(HmacSha256Signer::new("e2e-gate", b"e2e-gate-signing-key"))
}

/// Replays the interactive CLI sanitization on a `/chat` spec.
fn sanitize_spec(raw: &Value, goal: &str) -> Value {
    assert!(
        raw["backdoor"].as_bool() == Some(true),
        "mock must show the raw field"
    );
    let mut spec = raw.clone();
    spec["goal"] = json!(goal);
    spec["authority_profile_ref"] = json!("authority/read-only");
    let max_steps = spec["budgets"]["max_steps"].as_u64().unwrap_or(8);
    spec["budgets"]["max_steps"] = json!(max_steps.clamp(1, 256));
    spec.as_object_mut().unwrap().remove("backdoor");
    spec
}

async fn post_json(app: Router, uri: &str, payload: Value) -> (StatusCode, Value) {
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("content-type", "application/json")
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, body)
}

async fn get_json(app: Router, uri: &str) -> (StatusCode, Value) {
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(uri)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, body)
}

fn mission_by_id<'a>(store: &'a Store, id: &str) -> &'a Value {
    store
        .missions()
        .iter()
        .find(|m| m["mission_id"] == id)
        .unwrap_or_else(|| panic!("mission {id} must be durable"))
}

#[tokio::test]
async fn chat_spec_mission_terminal_and_restart_persistent() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("gate.db");
    let store = Arc::new(Mutex::new(Store::open(&db_path, signer()).unwrap()));

    // Mock the OpenAI-compatible chat-completions endpoint the daemon calls.
    let server = MockServer::start();
    let chat_endpoint = server.mock(|when: When, then: Then| {
        when.method(POST).path("/v1/chat/completions");
        then.status(200).json_body(json!({
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": RAW_MODEL_SPEC
                }
            }]
        }));
    });

    let app = build_router_with_chat(
        "0.0.0-gate-test",
        0,
        Instant::now(),
        store.clone(),
        Some(ChatConfig {
            base_url: server.base_url(),
            model: "test-model".to_owned(),
            api_key: "test-key".to_owned(),
            timeout_ms: 5000,
            max_response_bytes: 1 << 20,
        }),
    );

    // 1. /chat hands back the model draft and records exactly one provider call.
    let (chat_status, chat_reply) = post_json(
        app.clone(),
        "/chat",
        json!({ "messages": [{ "role": "user", "content": "demo goal" }] }),
    )
    .await;
    assert_eq!(chat_status, StatusCode::OK);
    assert_eq!(chat_reply["model"], "test-model");
    let raw_content = chat_reply["content"].as_str().unwrap();
    let trimmed = raw_content.trim();
    let de_fenced = trimmed
        .strip_prefix("```json")
        .or_else(|| trimmed.strip_prefix("```"))
        .unwrap_or(trimmed)
        .trim()
        .strip_suffix("```")
        .map(str::trim)
        .unwrap_or(trimmed);
    let raw_spec: Value = serde_json::from_str(de_fenced).unwrap();
    chat_endpoint.assert_hits(1);

    // 2. The sanitized (all-required-field) spec creates a real mission.
    let spec = sanitize_spec(&raw_spec, "demo goal");
    let (create_status, created) = post_json(app.clone(), "/missions", spec).await;
    assert_eq!(create_status, StatusCode::CREATED, "body: {created}");
    let mission_id = created["mission_id"].as_str().unwrap().to_owned();
    assert_eq!(created["goal"], "demo goal");
    let (get_status, fetched) = get_json(app.clone(), &format!("/missions/{mission_id}")).await;
    assert_eq!(get_status, StatusCode::OK);
    assert_eq!(fetched["phase"], "READY");
    assert_eq!(fetched["goal"], "demo goal");

    // 3. The native executor drives the mission to a terminal success.
    let executor = AtomExecutor::new(store.clone(), ExecutorConfig::default());
    let result = executor.drive_once(&mission_id).await.unwrap();
    assert_eq!(result.phase, "TERMINAL");
    assert_eq!(result.outcome, Some("SUCCEEDED"));

    // 4. Daemon restart: reopening the same sqlite file restores the outcome.
    drop(app);
    let reopened = Store::open(&db_path, signer()).unwrap();
    let restored = mission_by_id(&reopened, &mission_id);
    assert_eq!(restored["phase"], "TERMINAL");
    assert_eq!(restored["outcome"], "SUCCEEDED");
    assert_eq!(restored["goal"], "demo goal");
}
