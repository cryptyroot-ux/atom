//! ATOM-VT-001 server-persistence subcase: a daemon restart rebuilds its HTTP
//! projections from the authoritative ledger instead of treating in-memory
//! vectors as state. Runtime execution recovery has a stricter, separate gate.

use std::sync::Arc;

use atom_ledger::HmacSha256Signer;
use atom_server::app::build_router;
use atom_server::store::Store;
use axum::body::Body;
use axum::http::Request;
use http_body_util::BodyExt;
use rusqlite::{params, Connection};
use tempfile::tempdir;
use tokio::sync::Mutex;
use tower::ServiceExt;

fn signer() -> Box<dyn atom_ledger::CheckpointSigner> {
    Box::new(HmacSha256Signer::new(
        "daemon-recovery-test",
        b"daemon-recovery-test-signing-key",
    ))
}

fn complete_contract(goal: &str) -> serde_json::Value {
    serde_json::json!({
        "goal": goal,
        "success_criteria": ["mission remains readable after restart"],
        "constraints": [],
        "budgets": { "max_steps": 4 },
        "authority_profile_ref": "authority/test-read-only",
        "evidence_requirements": [],
        "stopping_rules": []
    })
}

#[test]
fn restart_rebuilds_every_server_projection_from_sqlite_ledger() {
    let directory = tempdir().expect("temporary state directory");
    let path = directory.path().join("atom.sqlite");

    {
        let mut store = Store::open(&path, signer()).expect("open persistent store");
        store
            .append_mission_created(&serde_json::json!({
                "mission_id": "mission-restart",
                "state": "CREATED",
                "goal": "survive a daemon restart"
            }))
            .expect("persist created mission");
        store
            .update_mission(
                "mission-restart",
                &serde_json::json!({
                    "mission_id": "mission-restart",
                    "state": "CANCELLED",
                    "goal": "survive a daemon restart"
                }),
            )
            .expect("persist mission update");
        store
            .append_effect(&serde_json::json!({
                "effect_id": "effect-restart",
                "mission_id": "mission-restart",
                "state": "AUTHORIZATION_PENDING"
            }))
            .expect("persist effect");
        store
            .add_grant(&serde_json::json!({
                "grant_id": "grant-restart",
                "subject_id": "operator"
            }))
            .expect("persist grant");
        store
            .add_observation(&serde_json::json!({
                "observation_id": "observation-restart",
                "claim_id": "claim-restart"
            }))
            .expect("persist observation");
        store
            .add_secret_handle(&serde_json::json!({
                "handle_id": "handle-restart",
                "name": "provider-credential"
            }))
            .expect("persist secret handle");
    }

    let restored = Store::open(&path, signer()).expect("restart rebuilds store");

    assert_eq!(restored.missions().len(), 1);
    assert_eq!(restored.missions()[0]["mission_id"], "mission-restart");
    assert_eq!(restored.missions()[0]["state"], "CANCELLED");
    assert_eq!(restored.effects().len(), 1);
    assert_eq!(restored.effects()[0]["effect_id"], "effect-restart");
    assert_eq!(restored.grants().len(), 1);
    assert_eq!(restored.grants()[0]["grant_id"], "grant-restart");
    assert_eq!(restored.observations().len(), 1);
    assert_eq!(
        restored.observations()[0]["observation_id"],
        "observation-restart"
    );
    assert_eq!(restored.secret_handles().len(), 1);
    assert_eq!(restored.secret_handles()[0]["handle_id"], "handle-restart");
}

#[test]
fn restart_refuses_a_tampered_server_ledger() {
    let directory = tempdir().expect("temporary state directory");
    let path = directory.path().join("atom.sqlite");

    {
        let mut store = Store::open(&path, signer()).expect("open persistent store");
        store
            .append_mission_created(&serde_json::json!({
                "mission_id": "mission-tamper",
                "state": "CREATED",
                "goal": "the original durable mission"
            }))
            .expect("persist mission");
    }

    // Simulate an attacker or storage fault bypassing the append-only trigger.
    // The stored payload digest is deliberately left untouched, so startup must
    // fail ledger verification before it can rebuild an HTTP projection.
    let connection = Connection::open(&path).expect("open SQLite database for tamper test");
    connection
        .execute_batch("DROP TRIGGER ledger_event_no_update")
        .expect("disable append-only guard for tamper test");
    connection
        .execute(
            "UPDATE ledger_event SET payload = ?1 WHERE stream_id = ?2 AND seq = 1",
            params![
                br#"{\"event\":\"created\",\"mission\":{\"mission_id\":\"mission-tamper\",\"state\":\"CREATED\",\"goal\":\"tampered\"}}"#,
                "mission",
            ],
        )
        .expect("tamper stored payload");
    drop(connection);

    let error = Store::open(&path, signer())
        .err()
        .expect("tampered ledger must prevent daemon startup");
    assert!(
        format!("{error:#}").contains("invalid ledger stream"),
        "unexpected startup failure: {error:#}"
    );
}

async fn body_json(response: axum::response::Response) -> serde_json::Value {
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("response body")
        .to_bytes();
    serde_json::from_slice(&bytes).expect("JSON response")
}

#[tokio::test]
async fn restart_keeps_mission_visible_through_the_http_api() {
    let directory = tempdir().expect("temporary state directory");
    let path = directory.path().join("atom.sqlite");

    let created = {
        let store = Store::open(&path, signer()).expect("open persistent store");
        let app = build_router(
            "test",
            1,
            std::time::Instant::now(),
            Arc::new(Mutex::new(store)),
        );
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/missions")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        complete_contract("survive HTTP daemon restart").to_string(),
                    ))
                    .expect("request"),
            )
            .await
            .expect("router response");
        assert_eq!(response.status(), axum::http::StatusCode::CREATED);
        body_json(response).await
    };
    let mission_id = created["mission_id"]
        .as_str()
        .expect("created mission id")
        .to_owned();

    let restarted_store = Store::open(&path, signer()).expect("restart rebuilds store");
    assert_eq!(restarted_store.missions().len(), 1);
    assert_eq!(
        restarted_store.missions()[0]["spec"]["authority_profile_ref"],
        "authority/test-read-only"
    );
    assert_eq!(
        restarted_store.missions()[0]["spec"]["success_criteria"][0],
        "mission remains readable after restart"
    );
    let restarted_app = build_router(
        "test",
        1,
        std::time::Instant::now(),
        Arc::new(Mutex::new(restarted_store)),
    );
    let response = restarted_app
        .oneshot(
            Request::builder()
                .uri(format!("/missions/{mission_id}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("router response");

    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let restored = body_json(response).await;
    assert_eq!(restored["mission_id"], mission_id);
    assert_eq!(restored["goal"], "survive HTTP daemon restart");
    assert_eq!(restored["state"], "CREATED");
}
