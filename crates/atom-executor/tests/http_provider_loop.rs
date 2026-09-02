//! End-to-end coverage for the HTTP provider loop:
//!
//! - A configured provider is consulted **once** per mission, before the
//!   runtime loop, and its plan is replayed synchronously.
//! - A provider failure seals the mission honestly as `UNSATISFIABLE` —
//!   never a fabricated success.

use std::sync::Arc;

use atom_executor::{AtomExecutor, ExecutorConfig, ProviderConfig};
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
    let signer: Box<dyn atom_ledger::CheckpointSigner> =
        Box::new(HmacSha256Signer::new("e2e-provider", b"e2e-provider-signing-key"));
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
        provider: ProviderConfig {
            enabled: true,
            base_url: server.base_url(),
            model: "test-model".to_owned(),
            api_key: "test-key".to_owned(),
        },
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
        then.status(500).json_body(json!({ "error": "gateway down" }));
    });

    let store = in_memory_store();
    {
        let mut s = store.lock().await;
        s.append_mission_created(&mission(MISSION_ID)).unwrap();
    }

    let config = ExecutorConfig {
        provider: ProviderConfig {
            enabled: true,
            base_url: server.base_url(),
            model: "test-model".to_owned(),
            api_key: "test-key".to_owned(),
        },
        ..ExecutorConfig::default()
    };
    let executor = AtomExecutor::new(store.clone(), config);

    let result = executor.drive_once(MISSION_ID).await.unwrap();

    failing.assert_hits(1);
    // Honest failure: no fabricated terminal outcome, reason explains why.
    assert_eq!(result.phase, "VERIFYING");
    assert_eq!(result.outcome, None);
    assert!(result.reason.as_deref().unwrap_or_default().contains("non-success status 500"));

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