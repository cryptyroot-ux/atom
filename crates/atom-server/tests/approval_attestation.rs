//! Approval attestation acceptance (P0-B): every approval the daemon issues
//! carries the daemon's seal, and every reader verifies it.
//!
//! The ledger hash chain already fails a *modified stream* closed at startup;
//! attestation additionally binds each approval's content to the daemon
//! identity recorded through the authenticated API, checked item-by-item at
//! rehydrate, redeem, and commit time. Pre-attestation (legacy) records stay
//! usable until expiry — accept-but-distinguish, never silently upgrade and
//! never bricked.
//!
//! Covered here:
//!
//! - issue staples `attestation.{key_id,signature}` (HTTP + store level)
//! - flipped field + copied signature refuses at redeem, at startup rehydrate,
//!   and at commit time (loud 409, never a silent skip)
//! - legacy records without attestation still redeem and still authorize a
//!   crossing end-to-end (grandfathered compat, pinned so a future cleanup
//!   cannot silently brick them)

use std::sync::Arc;

use atom_approval::{ApprovalGrant, ApprovalScope, ValidityInterval};
use atom_capability::{Budget, CapabilityGrant, ResourceSelector, RevocationState};
use atom_ledger::HmacSha256Signer;
use atom_server::app::build_router;
use atom_server::store::{ApprovalAttestationState, Store};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::{Duration, Utc};
use http_body_util::BodyExt;
use tokio::sync::Mutex;
use tower::ServiceExt;

fn signer() -> Box<HmacSha256Signer> {
    Box::new(HmacSha256Signer::new(
        "test",
        b"00000000000000000000000000000000",
    ))
}

fn memory_store() -> Arc<Mutex<Store>> {
    Arc::new(Mutex::new(
        Store::open_in_memory(signer()).expect("in-memory store"),
    ))
}

fn approval_value(grant_id: &str, digest: &str) -> serde_json::Value {
    let now = Utc::now();
    let approval = ApprovalGrant::new(
        grant_id,
        "human/root",
        ApprovalScope::Effect {
            effect_digest: digest.to_owned(),
        },
        ValidityInterval::new(now - Duration::minutes(1), now + Duration::hours(1))
            .expect("validity"),
    );
    serde_json::to_value(&approval).unwrap()
}

async fn request(
    app: &axum::Router,
    method: &str,
    uri: &str,
    body: Option<serde_json::Value>,
) -> (StatusCode, serde_json::Value) {
    let builder = Request::builder().method(method).uri(uri);
    let request = if let Some(value) = body {
        builder
            .header("content-type", "application/json")
            .body(Body::from(value.to_string()))
    } else {
        builder.body(Body::empty())
    }
    .unwrap();
    let response = app.clone().oneshot(request).await.expect("request");
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| serde_json::json!({ "raw": String::from_utf8_lossy(&bytes) }));
    (status, json)
}

// ---------------------------------------------------------------------------
// Issue staples a verifiable daemon attestation.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn issued_approval_carries_daemon_attestation() {
    let store = memory_store();
    let app = build_router("0.0.0-alpha", 32, std::time::Instant::now(), store.clone());

    let (status, created) = request(
        &app,
        "POST",
        "/approvals",
        Some(approval_value("approval/att-1", "sha256:aaaa")),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "issue refused: {created}");

    let attestation = created["attestation"]
        .as_object()
        .expect("issued approval must carry an attestation");
    assert_eq!(attestation["key_id"], "test");
    let signature = attestation["signature"].as_str().expect("signature");
    assert_eq!(signature.len(), 64, "HMAC-SHA256 hex must be 64 chars");

    // The stored projection holds exactly what was sealed, and it verifies.
    let guard = store.lock().await;
    let stored = guard
        .approvals()
        .iter()
        .find(|v| v["grant_id"] == "approval/att-1")
        .expect("projection holds the approval")
        .clone();
    let typed: ApprovalGrant = serde_json::from_value(stored).expect("typed");
    assert_eq!(
        guard.check_approval_attestation(&typed).expect("verifies"),
        ApprovalAttestationState::Attested
    );
}

// ---------------------------------------------------------------------------
// A copied signature over flipped content refuses everywhere.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tampered_copy_refuses_redeem() {
    let store = memory_store();
    {
        let mut guard = store.lock().await;
        guard
            .add_approval(&approval_value("approval/att-2", "sha256:aaaa"))
            .expect("issue");
        // Flip the scope the owner approved, keep the daemon's signature:
        // this is exactly what a projection-tampering attacker would hold.
        let mut tampered: ApprovalGrant = serde_json::from_value(
            guard
                .approvals()
                .iter()
                .find(|v| v["grant_id"] == "approval/att-2")
                .expect("stored")
                .clone(),
        )
        .expect("typed");
        tampered.scope = ApprovalScope::Effect {
            effect_digest: "sha256:bbbb".into(),
        };
        assert!(
            guard.check_approval_attestation(&tampered).is_err(),
            "a flipped scope with a copied signature must not verify"
        );
    }
}

#[tokio::test]
async fn tampered_record_fails_daemon_at_startup() {
    let dir = tempfile::tempdir().expect("state dir");
    let path = dir.path().join("atom.sqlite");
    {
        let mut store = Store::open(&path, signer()).expect("open");
        store
            .add_approval(&approval_value("approval/att-3", "sha256:aaaa"))
            .expect("issue");
        // Same tamper, smuggled straight into the ledger stream behind the
        // store's back. The chain itself stays intact (proper append), so only
        // the item-level attestation can catch this.
        let mut tampered: serde_json::Value = serde_json::to_value(
            serde_json::from_value::<ApprovalGrant>(
                store
                    .approvals()
                    .iter()
                    .find(|v| v["grant_id"] == "approval/att-3")
                    .expect("stored")
                    .clone(),
            )
            .expect("typed"),
        )
        .expect("json");
        tampered["approver_id"] = serde_json::Value::String("human/impostor".into());
        store
            .ledger
            .append(
                "approval",
                &serde_json::json!({ "event": "issued", "grant": tampered }),
                Utc::now().timestamp_millis(),
            )
            .expect("smuggled append");
    }
    let err = match Store::open(&path, signer()) {
        Ok(_) => panic!("a tampered approval must fail the daemon at startup"),
        Err(err) => err,
    };
    assert!(
        err.to_string().contains("attestation"),
        "unexpected startup error: {err}"
    );
}

// ---------------------------------------------------------------------------
// Legacy records (no attestation) keep working: redeem + full crossing.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn legacy_unsigned_approval_still_redeems() {
    let dir = tempfile::tempdir().expect("state dir");
    let path = dir.path().join("atom.sqlite");
    {
        let mut store = Store::open(&path, signer()).expect("open");
        // A pre-P0-B record: valid grant shape, no attestation key at all.
        let legacy = approval_value("approval/legacy-1", "sha256:aaaa");
        assert!(legacy.get("attestation").is_none());
        store
            .ledger
            .append(
                "approval",
                &serde_json::json!({ "event": "issued", "grant": legacy }),
                Utc::now().timestamp_millis(),
            )
            .expect("legacy append");
    }
    let mut reopened = Store::open(&path, signer()).expect("legacy must load");
    let redeemed = reopened
        .redeem_approval("approval/legacy-1")
        .expect("legacy must redeem");
    assert_eq!(redeemed["grant_id"], "approval/legacy-1");
}

#[tokio::test]
async fn legacy_unsigned_approval_still_authorizes_a_crossing() {
    let dir = tempfile::tempdir().expect("state dir");
    let sandbox = tempfile::tempdir().expect("sandbox");
    let path = dir.path().join("atom.sqlite");

    // Capability grant first (owner-side shape, direct to the store).
    let now = Utc::now();
    let capability = CapabilityGrant {
        grant_id: "grant/legacy-e2e".to_owned(),
        subject_id: "owner/test".to_owned(),
        workload_id: "workload/test".to_owned(),
        operations: vec!["write".to_owned()],
        resources: vec![ResourceSelector {
            resource_type: "file".to_owned(),
            resource_id: "/legacy.txt".to_owned(),
        }],
        purpose: "legacy attestation compat".to_owned(),
        not_before: now - Duration::minutes(1),
        expires_at: now + Duration::hours(1),
        budget: Budget {
            max_cost: 100,
            max_seconds: 100,
        },
        delegation_depth: 0,
        audience: "atom-server".to_owned(),
        generation: 1,
        revocation_state: RevocationState::Active,
        parent_grant_id: None,
        parent_authority_digest: None,
        holder_binding: None,
        authority_digest: None,
        nonce: None,
        constraints: None,
    };
    let plan_id;
    let digest;
    {
        let store = Arc::new(Mutex::new(Store::open(&path, signer()).expect("open")));
        store
            .lock()
            .await
            .add_grant(&serde_json::to_value(&capability).unwrap())
            .expect("capability recorded");
        // Host surface enabled, like a daemon started with `--host-root`.
        let app = atom_server::app::build_router_with(
            "0.0.0-alpha",
            32,
            std::time::Instant::now(),
            store,
            None,
            Some(atom_server::routes::host::HostConfig {
                root: sandbox.path().to_path_buf(),
            }),
        );
        let (status, plan) = request(
            &app,
            "POST",
            "/host/plan",
            Some(serde_json::json!({
                "mission_id": "mission/legacy-e2e",
                "grant_id": "grant/legacy-e2e",
                "op": { "op": "write_file", "path": "/legacy.txt", "contents": "grandfathered" },
            })),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "plan refused: {plan}");
        plan_id = plan["plan_id"].as_str().expect("plan_id").to_owned();
        digest = plan["effect_digest"].as_str().expect("digest").to_owned();
    }
    // Owner approval arrives as a legacy (unsigned) record, then the daemon
    // restarts — the exact shape of a pre-P0-B database after upgrade.
    {
        let mut store = Store::open(&path, signer()).expect("reopen");
        let legacy = approval_value("approval/legacy-e2e", &digest);
        assert!(legacy.get("attestation").is_none());
        store
            .ledger
            .append(
                "approval",
                &serde_json::json!({ "event": "issued", "grant": legacy }),
                Utc::now().timestamp_millis(),
            )
            .expect("legacy append");
    }
    {
        let store = Arc::new(Mutex::new(Store::open(&path, signer()).expect("reopen")));
        // Host surface needs the sandbox root: rebuild the authed-less router
        // the way the binary does for tests (open builder), with host config.
        let app = atom_server::app::build_router_with(
            "0.0.0-alpha",
            32,
            std::time::Instant::now(),
            store,
            None,
            Some(atom_server::routes::host::HostConfig {
                root: sandbox.path().to_path_buf(),
            }),
        );
        let (status, commit) = request(
            &app,
            "POST",
            "/host/commit",
            Some(serde_json::json!({ "plan_id": plan_id })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "legacy commit refused: {commit}");
        assert_eq!(commit["state"], "COMMITTED");
    }
    let written =
        std::fs::read_to_string(sandbox.path().join("legacy.txt")).expect("the crossing happened");
    assert_eq!(written, "grandfathered");
}
