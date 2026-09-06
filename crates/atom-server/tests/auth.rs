//! Transport-auth acceptance (P0-A): the daemon must refuse anonymous callers
//! while keeping liveness probes public and keeping auth separate from
//! authority.
//!
//! Background: `POST /approvals` once accepted any caller with a self-declared
//! `approver_id` (verified live 2026-09-05: `HTTP 201` for
//! `approver_id: "anonymous/attacker"`). These tests pin the closed door:
//!
//! - no credentials → 401 (not 201, not 400)
//! - wrong token → 401
//! - wrong scheme → 401, no panic
//! - `/health` + `/ready` → 200 without credentials
//! - valid token + no approval → authority still refuses (auth ≠ authority)

use std::sync::Arc;

use atom_approval::{ApprovalGrant, ApprovalScope, ValidityInterval};
use atom_capability::{Budget, CapabilityGrant, ResourceSelector, RevocationState};
use atom_ledger::HmacSha256Signer;
use atom_server::app::{build_router, build_router_with_auth};
use atom_server::auth::ApiToken;
use atom_server::routes::host::HostConfig;
use atom_server::store::Store;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::{Duration, Utc};
use http_body_util::BodyExt;
use tokio::sync::Mutex;
use tower::ServiceExt;

const TOKEN: &[u8] = b"test-token-0123456789abcdef";
const WRONG: &str = "Bearer wrong-token-0123456789abcdef";

fn signer() -> Box<HmacSha256Signer> {
    Box::new(HmacSha256Signer::new(
        "test",
        b"00000000000000000000000000000000",
    ))
}

fn token() -> ApiToken {
    ApiToken::new(TOKEN.to_vec()).expect("test token meets minimum length")
}

/// A router with transport auth enforced, mirroring production `atom serve`.
fn guarded() -> axum::Router {
    let store = Arc::new(Mutex::new(
        Store::open_in_memory(signer()).expect("in-memory store"),
    ));
    build_router_with_auth(
        "0.0.0-alpha",
        32,
        std::time::Instant::now(),
        store,
        None,
        None,
        Some(token()),
    )
}

/// A router with host mutation enabled AND auth enforced, for the
/// auth-is-not-authority test.
fn guarded_host() -> (axum::Router, Arc<Mutex<Store>>, tempfile::TempDir) {
    let root = tempfile::tempdir().expect("sandbox root");
    let store = Arc::new(Mutex::new(
        Store::open_in_memory(signer()).expect("in-memory store"),
    ));
    let app = build_router_with_auth(
        "0.0.0-alpha",
        32,
        std::time::Instant::now(),
        store.clone(),
        None,
        Some(HostConfig {
            root: root.path().to_path_buf(),
        }),
        Some(token()),
    );
    (app, store, root)
}

struct Responded {
    status: StatusCode,
    json: serde_json::Value,
    www_authenticate: Option<String>,
}

async fn request(
    app: &axum::Router,
    method: &str,
    uri: &str,
    auth: Option<&str>,
    body: Option<serde_json::Value>,
) -> Responded {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(scheme) = auth {
        builder = builder.header("authorization", scheme);
    }
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
    let www_authenticate = response
        .headers()
        .get("www-authenticate")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| serde_json::json!({ "raw": String::from_utf8_lossy(&bytes) }));
    Responded {
        status,
        json,
        www_authenticate,
    }
}

fn approval_body(grant_id: &str) -> serde_json::Value {
    let now = Utc::now();
    let approval = ApprovalGrant::new(
        grant_id,
        "human/root",
        ApprovalScope::Effect {
            effect_digest: "sha256:0".to_owned(),
        },
        ValidityInterval::new(now - Duration::minutes(1), now + Duration::hours(1))
            .expect("validity"),
    );
    serde_json::to_value(&approval).unwrap()
}

// ---------------------------------------------------------------------------
// Liveness stays public.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn health_and_ready_stay_public_without_credentials() {
    let app = guarded();
    let health = request(&app, "GET", "/health", None, None).await;
    assert_eq!(health.status, StatusCode::OK, "body: {}", health.json);
    assert_eq!(health.json["status"], "healthy");

    let ready = request(&app, "GET", "/ready", None, None).await;
    assert_eq!(ready.status, StatusCode::OK, "body: {}", ready.json);
}

// ---------------------------------------------------------------------------
// Anonymous and wrong callers are refused with 401, not routed, not served.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn missing_credentials_are_refused_with_401() {
    let app = guarded();
    let denied = request(&app, "POST", "/approvals", None, Some(approval_body("a/1"))).await;
    assert_eq!(
        denied.status,
        StatusCode::UNAUTHORIZED,
        "body: {}",
        denied.json
    );
    assert_eq!(denied.json["status"], 401);
    assert_eq!(denied.json["title"], "Unauthorized");

    let denied = request(&app, "GET", "/missions", None, None).await;
    assert_eq!(
        denied.status,
        StatusCode::UNAUTHORIZED,
        "body: {}",
        denied.json
    );
}

#[tokio::test]
async fn wrong_token_is_refused_with_401() {
    let app = guarded();
    let denied = request(
        &app,
        "POST",
        "/approvals",
        Some(WRONG),
        Some(approval_body("a/2")),
    )
    .await;
    assert_eq!(
        denied.status,
        StatusCode::UNAUTHORIZED,
        "body: {}",
        denied.json
    );
    assert_eq!(denied.json["title"], "Unauthorized");
}

#[tokio::test]
async fn wrong_scheme_is_refused_without_panic() {
    let app = guarded();
    for scheme in ["Token abcdef0123456789", "Basic dXNlcjpwYXNz", "Bearer "] {
        let denied = request(&app, "GET", "/missions", Some(scheme), None).await;
        assert_eq!(
            denied.status,
            StatusCode::UNAUTHORIZED,
            "scheme `{scheme}` was not refused: {}",
            denied.json
        );
    }
}

#[tokio::test]
async fn refusal_carries_a_bearer_challenge() {
    let app = guarded();
    let denied = request(&app, "GET", "/missions", None, None).await;
    assert_eq!(denied.status, StatusCode::UNAUTHORIZED);
    let challenge = denied.www_authenticate.expect("WWW-Authenticate header");
    assert!(
        challenge.starts_with("Bearer"),
        "unexpected challenge: {challenge}"
    );
}

// ---------------------------------------------------------------------------
// A valid token opens transport — and nothing else.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn valid_token_reaches_handlers() {
    let app = guarded();
    let bearer = format!("Bearer {}", String::from_utf8_lossy(TOKEN));
    let listed = request(&app, "GET", "/missions", Some(&bearer), None).await;
    assert_eq!(listed.status, StatusCode::OK, "body: {}", listed.json);
}

#[tokio::test]
async fn auth_is_not_authority_commit_without_approval_still_refuses() {
    let (app, store, _root) = guarded_host();
    let bearer = format!("Bearer {}", String::from_utf8_lossy(TOKEN));

    // Install a capability grant directly in the store (owner-side, offline —
    // the same path `atom grant issue` takes, never HTTP).
    let now = Utc::now();
    let grant = CapabilityGrant {
        grant_id: "grant/auth-e2e".to_owned(),
        subject_id: "owner/test".to_owned(),
        workload_id: "workload/test".to_owned(),
        operations: vec!["write".to_owned()],
        resources: vec![ResourceSelector {
            resource_type: "file".to_owned(),
            resource_id: "/proof.txt".to_owned(),
        }],
        purpose: "auth-is-not-authority test".to_owned(),
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
    store
        .lock()
        .await
        .add_grant(&serde_json::to_value(&grant).unwrap())
        .expect("grant recorded");

    // Planning passes the transport gate with the valid token.
    let planned = request(
        &app,
        "POST",
        "/host/plan",
        Some(&bearer),
        Some(serde_json::json!({
            "mission_id": "mission/auth-e2e",
            "grant_id": "grant/auth-e2e",
            "op": { "op": "write_file", "path": "/proof.txt", "contents": "must not appear" },
        })),
    )
    .await;
    assert_eq!(
        planned.status,
        StatusCode::CREATED,
        "plan refused: {}",
        planned.json
    );
    let plan_id = planned.json["plan_id"]
        .as_str()
        .expect("plan_id")
        .to_owned();

    // Committing with a valid token but NO approval must fail at the authority
    // gate — 400 (no usable approval), never 401 (transport passed) and never
    // 200 (auth must not mint authority).
    let commit = request(
        &app,
        "POST",
        "/host/commit",
        Some(&bearer),
        Some(serde_json::json!({ "plan_id": plan_id })),
    )
    .await;
    assert_eq!(
        commit.status,
        StatusCode::BAD_REQUEST,
        "expected the authority gate to refuse, got: {}",
        commit.json
    );
    assert!(
        !std::path::Path::new("/proof.txt").exists(),
        "auth bypassed the authority gate"
    );
}

// ---------------------------------------------------------------------------
// The open builder stays open — explicitly, for tests and `--no-auth` only.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn open_builder_serves_without_credentials() {
    let store = Arc::new(Mutex::new(
        Store::open_in_memory(signer()).expect("in-memory store"),
    ));
    let app = build_router("0.0.0-alpha", 32, std::time::Instant::now(), store);
    let listed = request(&app, "GET", "/missions", None, None).await;
    assert_eq!(
        listed.status,
        StatusCode::OK,
        "the test-only open builder must stay open: {}",
        listed.json
    );
}
