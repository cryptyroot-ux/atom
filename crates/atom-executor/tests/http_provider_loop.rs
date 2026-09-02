//! End-to-end coverage for the HTTP provider loop:
//!
//! - A configured provider is consulted **once** per mission, before the
//!   runtime loop, and its plan is replayed synchronously.
//! - A provider failure seals the mission honestly as `UNSATISFIABLE` —
//!   never a fabricated success.

use std::sync::Arc;

use atom_executor::{
    AtomExecutor, ExecutorConfig, HttpProposalClient, ProviderConfig, ProviderError,
};
use atom_ledger::HmacSha256Signer;
use atom_server::store::Store;
use httpmock::Method::POST;
use httpmock::{MockServer, Then, When};
use serde_json::{json, Value};
use tokio::sync::Mutex;

const MISSION_ID: &str = "m-provider-http";

fn mission(id: &str) -> Value {
    json!({
        "mission_id": id,
        "state": "CREATED",
        "phase": "READY",
        "condition": "NORMAL",
        "outcome": null,
        "goal": "drive a provider-routed mission",
        "updated_at": "now"
    })
}

fn in_memory_store() -> Arc<Mutex<Store>> {
    let signer: Box<dyn atom_ledger::CheckpointSigner> = Box::new(HmacSha256Signer::new(
        "e2e-provider",
        b"e2e-provider-signing-key",
    ));
    Arc::new(Mutex::new(Store::open_in_memory(signer).unwrap()))
}

/// Mocks the OpenAI-compatible chat-completions endpoint.
fn successful_chat() -> Value {
    json!({
        "choices": [{
            "message": {
                "role": "assistant",
                "content": r#"["COMPILE","PREPARE","START","EXECUTE","VERIFY"]"#
            }
        }]
    })
}

fn provider_config(base_url: String) -> ProviderConfig {
    ProviderConfig {
        enabled: true,
        base_url,
        model: "test-model".to_owned(),
        api_key: "test-key".to_owned(),
        backoff_ms: 0,
        ..ProviderConfig::default()
    }
}

#[tokio::test]
async fn provider_plan_drives_mission_to_terminal_once() {
    let server = MockServer::start();
    let endpoint = server.mock(|when: When, then: Then| {
        when.method(POST).path("/v1/chat/completions");
        then.status(200).json_body(successful_chat());
    });

    let store = in_memory_store();
    {
        let mut s = store.lock().await;
        s.append_mission_created(&mission(MISSION_ID)).unwrap();
    }

    let config = ExecutorConfig {
        provider: provider_config(server.base_url()),
        ..ExecutorConfig::default()
    };
    let executor = AtomExecutor::new(store.clone(), config);

    let result = executor.drive_once(MISSION_ID).await.unwrap();

    // The provider callback ran exactly once, before the runtime loop.
    endpoint.assert_hits(1);
    assert_eq!(result.phase, "TERMINAL");
    assert_eq!(result.outcome, Some("SUCCEEDED"));
    assert_eq!(result.reason, None);

    // The durable store reflects a terminal outcome, not a fabrication.
    let s = store.lock().await;
    let m = s
        .missions()
        .iter()
        .find(|m| m["mission_id"] == MISSION_ID)
        .unwrap();
    assert_eq!(m["phase"], "TERMINAL");
    assert_eq!(m["outcome"], "SUCCEEDED");
}

#[tokio::test]
async fn provider_failure_seals_mission_unsatisfiable() {
    let server = MockServer::start();
    let failing = server.mock(|when: When, then: Then| {
        when.method(POST).path("/v1/chat/completions");
        then.status(500)
            .json_body(json!({ "error": "gateway down" }));
    });

    let store = in_memory_store();
    {
        let mut s = store.lock().await;
        s.append_mission_created(&mission(MISSION_ID)).unwrap();
    }

    let config = ExecutorConfig {
        provider: provider_config(server.base_url()),
        ..ExecutorConfig::default()
    };
    let executor = AtomExecutor::new(store.clone(), config);

    let result = executor.drive_once(MISSION_ID).await.unwrap();

    // Initial request plus the two configured retries.
    failing.assert_hits(3);
    // Honest failure: no fabricated terminal outcome, reason explains why.
    assert_eq!(result.phase, "VERIFYING");
    assert_eq!(result.outcome, None);
    assert!(result
        .reason
        .as_deref()
        .unwrap_or_default()
        .contains("non-success status 500"));

    // The durable store records the honest unsatisfiable seal.
    let s = store.lock().await;
    let m = s
        .missions()
        .iter()
        .find(|m| m["mission_id"] == MISSION_ID)
        .unwrap();
    assert_eq!(m["phase"], "TERMINAL");
    assert_eq!(m["outcome"], "UNSATISFIABLE");
}

#[tokio::test]
async fn non_retryable_gateway_status_is_attempted_once() {
    let server = MockServer::start();
    let denied = server.mock(|when: When, then: Then| {
        when.method(POST).path("/v1/chat/completions");
        then.status(400)
            .json_body(json!({ "error": "invalid model" }));
    });

    let client = HttpProposalClient::new(provider_config(server.base_url())).unwrap();
    let error = client
        .propose("mission", "CREATED")
        .await
        .expect_err("400 must be surfaced without retry");

    denied.assert_hits(1);
    assert_eq!(error, ProviderError::NonSuccess { status: 400 });
}

#[tokio::test]
async fn invalid_command_sequence_is_rejected_before_runtime() {
    let server = MockServer::start();
    server.mock(|when: When, then: Then| {
        when.method(POST).path("/v1/chat/completions");
        then.status(200).json_body(json!({
            "choices": [{
                "message": {"content": r#"["VERIFY"]"#}
            }]
        }));
    });

    let client = HttpProposalClient::new(provider_config(server.base_url())).unwrap();
    let error = client
        .propose("mission", "CREATED")
        .await
        .expect_err("VERIFY is not legal from CREATED");

    assert!(matches!(error, ProviderError::Malformed(detail) if detail.contains("command 0")));
}

#[tokio::test]
async fn oversized_plan_is_rejected() {
    let server = MockServer::start();
    server.mock(|when: When, then: Then| {
        when.method(POST).path("/v1/chat/completions");
        then.status(200).json_body(json!({
            "choices": [{
                "message": {"content": r#"["COMPILE","PREPARE","START","EXECUTE","VERIFY"]"#}
            }]
        }));
    });

    let mut config = provider_config(server.base_url());
    config.max_plan_steps = 4;
    let client = HttpProposalClient::new(config).unwrap();
    let error = client
        .propose("mission", "CREATED")
        .await
        .expect_err("plan over the configured bound must be rejected");

    assert!(matches!(error, ProviderError::Malformed(detail) if detail.contains("maximum is 4")));
}
