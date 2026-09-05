//! End-to-end proof that the governed host-mutation surface actually changes the
//! host — and refuses to when any part of the gate is missing.
//!
//! These tests exist because "the spine compiles" is not the same claim as "the
//! spine commits". Each one asserts on the real filesystem after the request,
//! not on a response body alone.
//!
//! The path under test: `POST /host/plan` → owner approval → `POST /host/commit`
//! → `PrivilegeBroker::admit` → `SandboxedHostExecutor` → real `fs::write`.

use std::sync::Arc;

use atom_approval::{ApprovalGrant, ApprovalScope, ValidityInterval};
use atom_capability::{Budget, CapabilityGrant, ResourceSelector, RevocationState};
use atom_ledger::HmacSha256Signer;
use atom_server::app::{build_router, build_router_with};
use atom_server::routes::host::HostConfig;
use atom_server::store::Store;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::{Duration, Utc};
use http_body_util::BodyExt;
use tokio::sync::Mutex;
use tower::ServiceExt;

/// The sandbox root plus a router wired to it.
struct Harness {
    app: axum::Router,
    store: Arc<Mutex<Store>>,
    root: tempfile::TempDir,
}

fn signer() -> Box<HmacSha256Signer> {
    Box::new(HmacSha256Signer::new(
        "test",
        b"00000000000000000000000000000000",
    ))
}

impl Harness {
    /// A daemon with the host surface enabled over a fresh sandbox.
    fn enabled() -> Self {
        let root = tempfile::tempdir().expect("sandbox root");
        let store = Arc::new(Mutex::new(
            Store::open_in_memory(signer()).expect("in-memory store"),
        ));
        let app = build_router_with(
            "0.0.0-alpha",
            32,
            std::time::Instant::now(),
            store.clone(),
            None,
            Some(HostConfig {
                root: root.path().to_path_buf(),
            }),
        );
        Self { app, store, root }
    }

    /// A daemon with no `--host-root`: the surface must refuse everything.
    fn disabled() -> axum::Router {
        let store = Arc::new(Mutex::new(
            Store::open_in_memory(signer()).expect("in-memory store"),
        ));
        build_router("0.0.0-alpha", 32, std::time::Instant::now(), store)
    }

    async fn post(&self, uri: &str, body: serde_json::Value) -> (StatusCode, serde_json::Value) {
        let response = self
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(uri)
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .expect("request");
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let json = serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| serde_json::json!({ "raw": String::from_utf8_lossy(&bytes) }));
        (status, json)
    }

    async fn get(&self, uri: &str) -> (StatusCode, serde_json::Value) {
        let response = self
            .app
            .clone()
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .expect("request");
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let json = serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| serde_json::json!({ "raw": String::from_utf8_lossy(&bytes) }));
        (status, json)
    }

    /// Installs a capability grant covering `write` on `resource_id`.
    async fn grant_write(&self, grant_id: &str, resource_id: &str) {
        let now = Utc::now();
        let grant = CapabilityGrant {
            grant_id: grant_id.to_owned(),
            subject_id: "owner/test".to_owned(),
            workload_id: "workload/test".to_owned(),
            operations: vec!["write".to_owned()],
            resources: vec![ResourceSelector {
                resource_type: "file".to_owned(),
                resource_id: resource_id.to_owned(),
            }],
            purpose: "end-to-end host mutation test".to_owned(),
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
        let mut store = self.store.lock().await;
        store
            .add_grant(&serde_json::to_value(&grant).unwrap())
            .expect("grant recorded");
    }

    /// Installs an owner approval for exactly `effect_digest`.
    async fn approve(&self, grant_id: &str, effect_digest: &str) {
        let now = Utc::now();
        let approval = ApprovalGrant::new(
            grant_id,
            "human/root",
            ApprovalScope::Effect {
                effect_digest: effect_digest.to_owned(),
            },
            ValidityInterval::new(now - Duration::minutes(1), now + Duration::hours(1))
                .expect("validity"),
        );
        let mut value = serde_json::to_value(&approval).unwrap();
        value["redeemed"] = serde_json::Value::Bool(false);
        let mut store = self.store.lock().await;
        store.add_approval(&value).expect("approval recorded");
    }

    /// The bytes actually on disk at `relative`, if the file exists.
    fn on_disk(&self, relative: &str) -> Option<String> {
        std::fs::read_to_string(self.root.path().join(relative.trim_start_matches('/'))).ok()
    }
}

fn write_op(path: &str, contents: &str) -> serde_json::Value {
    serde_json::json!({ "op": "write_file", "path": path, "contents": contents })
}

fn plan_body(grant_id: &str, op: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "mission_id": "mission/host-e2e",
        "grant_id": grant_id,
        "op": op,
    })
}

// ---------------------------------------------------------------------------
// The happy path: a real file appears, through the full gate.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn approved_plan_commits_a_real_host_write() {
    let h = Harness::enabled();
    h.grant_write("grant/write-hello", "/hello.txt").await;

    let (status, plan) = h
        .post(
            "/host/plan",
            plan_body(
                "grant/write-hello",
                write_op("/hello.txt", "governed world"),
            ),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "plan rejected: {plan}");
    assert_eq!(plan["state"], "PLANNED");
    assert_eq!(plan["operation"], "write");
    assert_eq!(plan["planned_witness"]["kind"], "absent");

    // Planning alone must not have touched the host.
    assert!(
        h.on_disk("/hello.txt").is_none(),
        "planning wrote to the host before any approval existed"
    );

    let digest = plan["effect_digest"].as_str().expect("digest").to_owned();
    h.approve("approval/hello", &digest).await;

    let plan_id = plan["plan_id"].as_str().unwrap().to_owned();
    let (status, commit) = h
        .post("/host/commit", serde_json::json!({ "plan_id": plan_id }))
        .await;
    assert_eq!(status, StatusCode::OK, "commit refused: {commit}");
    assert_eq!(commit["state"], "COMMITTED");
    assert_eq!(commit["approval_id"], "approval/hello");
    assert_eq!(commit["effect_digest"], digest);

    // The actual proof: the host changed.
    assert_eq!(
        h.on_disk("/hello.txt").as_deref(),
        Some("governed world"),
        "the file was not written through the privilege boundary"
    );

    // And the crossing left an audit trail with a burned nonce.
    let (_, plans) = h.get("/host/plans").await;
    assert_eq!(plans["burned_nonces"], 1);
    let (_, evidence) = h.get("/evidence").await;
    let observations = evidence["observations"].as_array().expect("observations");
    let entry = observations
        .iter()
        .find(|o| o["observation_id"] == commit["observation_id"])
        .expect("the commit sealed an observation");
    assert_eq!(entry["taint"], "HOST_MUTATION_COMMITTED");
    assert_eq!(entry["tool"], "write_file");
}

// ---------------------------------------------------------------------------
// Deny-by-default: every missing piece of the gate refuses, host untouched.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn host_surface_is_disabled_without_a_sandbox_root() {
    let app = Harness::disabled();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/host/plan")
                .header("content-type", "application/json")
                .body(Body::from(
                    plan_body("grant/x", write_op("/x.txt", "y")).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "a daemon with no --host-root must refuse to plan host mutations"
    );
}

#[tokio::test]
async fn plan_without_a_capability_grant_is_refused() {
    let h = Harness::enabled();
    let (status, body) = h
        .post(
            "/host/plan",
            plan_body("grant/does-not-exist", write_op("/nope.txt", "x")),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        body["detail"]
            .as_str()
            .unwrap_or_default()
            .contains("deny-by-default"),
        "expected a deny-by-default refusal, got {body}"
    );
    assert!(h.on_disk("/nope.txt").is_none());
}

#[tokio::test]
async fn plan_outside_the_grants_resources_is_refused() {
    let h = Harness::enabled();
    h.grant_write("grant/narrow", "/allowed.txt").await;
    let (status, body) = h
        .post(
            "/host/plan",
            plan_body("grant/narrow", write_op("/elsewhere.txt", "x")),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(h.on_disk("/elsewhere.txt").is_none());
}

#[tokio::test]
async fn plan_with_an_operation_the_grant_does_not_allow_is_refused() {
    let h = Harness::enabled();
    // The grant allows `write`; `remove_file` needs `delete`.
    h.grant_write("grant/write-only", "/target.txt").await;
    let (status, body) = h
        .post(
            "/host/plan",
            plan_body(
                "grant/write-only",
                serde_json::json!({ "op": "remove_file", "path": "/target.txt" }),
            ),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        body["detail"]
            .as_str()
            .unwrap_or_default()
            .contains("does not allow `delete`"),
        "expected an operation refusal, got {body}"
    );
}

#[tokio::test]
async fn commit_without_an_approval_never_reaches_the_host() {
    let h = Harness::enabled();
    h.grant_write("grant/unapproved", "/unapproved.txt").await;
    let (_, plan) = h
        .post(
            "/host/plan",
            plan_body("grant/unapproved", write_op("/unapproved.txt", "x")),
        )
        .await;
    let plan_id = plan["plan_id"].as_str().unwrap().to_owned();

    let (status, body) = h
        .post("/host/commit", serde_json::json!({ "plan_id": plan_id }))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        h.on_disk("/unapproved.txt").is_none(),
        "an unapproved commit wrote to the host"
    );
    let (_, plans) = h.get("/host/plans").await;
    assert_eq!(
        plans["burned_nonces"], 0,
        "no permit should have been spent"
    );
}

#[tokio::test]
async fn an_approval_for_a_different_digest_does_not_authorise_this_plan() {
    let h = Harness::enabled();
    h.grant_write("grant/mismatch", "/mismatch.txt").await;
    let (_, plan) = h
        .post(
            "/host/plan",
            plan_body("grant/mismatch", write_op("/mismatch.txt", "x")),
        )
        .await;
    // Approve *something else*, with the right shape but the wrong digest.
    h.approve("approval/wrong", "effect/deadbeef").await;

    let plan_id = plan["plan_id"].as_str().unwrap().to_owned();
    let (status, body) = h
        .post("/host/commit", serde_json::json!({ "plan_id": plan_id }))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(h.on_disk("/mismatch.txt").is_none());
}

#[tokio::test]
async fn witness_drift_between_plan_and_commit_refuses_the_crossing() {
    let h = Harness::enabled();
    h.grant_write("grant/drift", "/drift.txt").await;
    let (_, plan) = h
        .post(
            "/host/plan",
            plan_body("grant/drift", write_op("/drift.txt", "planned")),
        )
        .await;
    let digest = plan["effect_digest"].as_str().unwrap().to_owned();
    h.approve("approval/drift", &digest).await;

    // Somebody else creates the file after planning observed it absent.
    std::fs::write(h.root.path().join("drift.txt"), "someone else was here").unwrap();

    let plan_id = plan["plan_id"].as_str().unwrap().to_owned();
    let (status, body) = h
        .post("/host/commit", serde_json::json!({ "plan_id": plan_id }))
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(
        h.on_disk("/drift.txt").as_deref(),
        Some("someone else was here"),
        "the drifted file was overwritten anyway"
    );

    let (_, plans) = h.get("/host/plans").await;
    assert_eq!(plans["burned_nonces"], 0);
    let recorded = plans["plans"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["plan_id"] == plan_id)
        .expect("plan recorded");
    assert_eq!(recorded["state"], "REFUSED");
}

#[tokio::test]
async fn a_committed_plan_cannot_be_committed_twice() {
    let h = Harness::enabled();
    h.grant_write("grant/once", "/once.txt").await;
    let (_, plan) = h
        .post(
            "/host/plan",
            plan_body("grant/once", write_op("/once.txt", "first")),
        )
        .await;
    let digest = plan["effect_digest"].as_str().unwrap().to_owned();
    h.approve("approval/once", &digest).await;
    let plan_id = plan["plan_id"].as_str().unwrap().to_owned();

    let (first, _) = h
        .post("/host/commit", serde_json::json!({ "plan_id": &plan_id }))
        .await;
    assert_eq!(first, StatusCode::OK);

    let (second, body) = h
        .post("/host/commit", serde_json::json!({ "plan_id": &plan_id }))
        .await;
    assert_eq!(
        second,
        StatusCode::CONFLICT,
        "a spent plan must not be re-committable: {body}"
    );

    let (_, plans) = h.get("/host/plans").await;
    assert_eq!(plans["burned_nonces"], 1, "exactly one permit was spent");
}

#[tokio::test]
async fn an_identical_replanned_effect_cannot_reuse_a_spent_approval() {
    let h = Harness::enabled();
    h.grant_write("grant/replay", "/replay.txt").await;

    let body = plan_body("grant/replay", write_op("/replay.txt", "once only"));
    let (_, first_plan) = h.post("/host/plan", body.clone()).await;
    let digest = first_plan["effect_digest"].as_str().unwrap().to_owned();
    h.approve("approval/replay", &digest).await;

    let first_id = first_plan["plan_id"].as_str().unwrap().to_owned();
    let (status, _) = h
        .post("/host/commit", serde_json::json!({ "plan_id": first_id }))
        .await;
    assert_eq!(status, StatusCode::OK);

    // The same material planned again yields the same digest — but the owner's
    // decision was already spent, so it must not carry a second crossing.
    let (_, second_plan) = h.post("/host/plan", body).await;
    assert_eq!(
        second_plan["effect_digest"], digest,
        "identical material must be content-addressed identically"
    );
    let second_id = second_plan["plan_id"].as_str().unwrap().to_owned();
    let (status, refusal) = h
        .post("/host/commit", serde_json::json!({ "plan_id": second_id }))
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a spent approval authorised a second crossing: {refusal}"
    );

    let (_, plans) = h.get("/host/plans").await;
    assert_eq!(plans["burned_nonces"], 1);
}

#[tokio::test]
async fn a_path_escaping_the_sandbox_is_refused_by_the_executor() {
    let h = Harness::enabled();
    h.grant_write("grant/escape", "/../escape.txt").await;
    let (status, plan) = h
        .post(
            "/host/plan",
            plan_body("grant/escape", write_op("/../escape.txt", "outside")),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{plan}");
    let digest = plan["effect_digest"].as_str().unwrap().to_owned();
    h.approve("approval/escape", &digest).await;

    let plan_id = plan["plan_id"].as_str().unwrap().to_owned();
    let (status, body) = h
        .post("/host/commit", serde_json::json!({ "plan_id": plan_id }))
        .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "the sandbox admitted a `..` escape: {body}"
    );
    assert!(
        !h.root.path().parent().unwrap().join("escape.txt").exists(),
        "a write escaped the sandbox root"
    );
}

#[tokio::test]
async fn network_configuration_is_refused_even_when_fully_approved() {
    let h = Harness::enabled();
    let now = Utc::now();
    // A grant that does allow `configure` on the interface.
    let grant = CapabilityGrant {
        grant_id: "grant/net".to_owned(),
        subject_id: "owner/test".to_owned(),
        workload_id: "workload/test".to_owned(),
        operations: vec!["configure".to_owned()],
        resources: vec![ResourceSelector {
            resource_type: "network".to_owned(),
            resource_id: "eth0".to_owned(),
        }],
        purpose: "prove the sandbox refuses network authority".to_owned(),
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
    {
        let mut store = h.store.lock().await;
        store
            .add_grant(&serde_json::to_value(&grant).unwrap())
            .unwrap();
    }

    let (status, plan) = h
        .post(
            "/host/plan",
            plan_body(
                "grant/net",
                serde_json::json!({
                    "op": "configure_network",
                    "interface": "eth0",
                    "allow_cidr": "10.0.0.0/8"
                }),
            ),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{plan}");
    let digest = plan["effect_digest"].as_str().unwrap().to_owned();
    h.approve("approval/net", &digest).await;

    let plan_id = plan["plan_id"].as_str().unwrap().to_owned();
    let (status, body) = h
        .post("/host/commit", serde_json::json!({ "plan_id": plan_id }))
        .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "the filesystem sandbox must refuse network authority: {body}"
    );
}

#[tokio::test]
async fn a_malformed_op_is_refused_before_anything_is_recorded() {
    let h = Harness::enabled();
    h.grant_write("grant/relative", "relative.txt").await;
    let (status, body) = h
        .post(
            "/host/plan",
            plan_body("grant/relative", write_op("relative.txt", "x")),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let (_, plans) = h.get("/host/plans").await;
    assert!(
        plans["plans"].as_array().unwrap().is_empty(),
        "a malformed op was recorded as a plan"
    );
}

// ---------------------------------------------------------------------------
// Durability: the one-shot guarantee must survive a restart.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn burned_nonces_are_rebuilt_from_the_ledger_after_a_restart() {
    let dir = tempfile::tempdir().expect("state dir");
    let db = dir.path().join("state.db");
    let sandbox = tempfile::tempdir().expect("sandbox");

    // First life: commit one mutation.
    let digest = {
        let store = Arc::new(Mutex::new(
            Store::open(&db, signer()).expect("open state db"),
        ));
        let h = Harness {
            app: build_router_with(
                "0.0.0-alpha",
                32,
                std::time::Instant::now(),
                store.clone(),
                None,
                Some(HostConfig {
                    root: sandbox.path().to_path_buf(),
                }),
            ),
            store,
            root: tempfile::tempdir().expect("unused"),
        };
        h.grant_write("grant/restart", "/restart.txt").await;
        let (_, plan) = h
            .post(
                "/host/plan",
                plan_body("grant/restart", write_op("/restart.txt", "before restart")),
            )
            .await;
        let digest = plan["effect_digest"].as_str().unwrap().to_owned();
        h.approve("approval/restart", &digest).await;
        let plan_id = plan["plan_id"].as_str().unwrap().to_owned();
        let (status, body) = h
            .post("/host/commit", serde_json::json!({ "plan_id": plan_id }))
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        digest
    };

    assert_eq!(
        std::fs::read_to_string(sandbox.path().join("restart.txt")).unwrap(),
        "before restart"
    );

    // Second life: a fresh Store over the same ledger must remember the burn and
    // the spent approval.
    let store = Arc::new(Mutex::new(
        Store::open(&db, signer()).expect("reopen state db"),
    ));
    let h = Harness {
        app: build_router_with(
            "0.0.0-alpha",
            32,
            std::time::Instant::now(),
            store.clone(),
            None,
            Some(HostConfig {
                root: sandbox.path().to_path_buf(),
            }),
        ),
        store,
        root: tempfile::tempdir().expect("unused"),
    };

    let (_, plans) = h.get("/host/plans").await;
    assert_eq!(
        plans["burned_nonces"], 1,
        "the nonce burn did not survive the restart"
    );

    // The same effect, replanned after the restart, still cannot reuse the
    // approval that was spent in the previous life.
    let (_, replan) = h
        .post(
            "/host/plan",
            plan_body("grant/restart", write_op("/restart.txt", "before restart")),
        )
        .await;
    assert_eq!(replan["effect_digest"], digest);
    let plan_id = replan["plan_id"].as_str().unwrap().to_owned();
    let (status, body) = h
        .post("/host/commit", serde_json::json!({ "plan_id": plan_id }))
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a restart reopened a spent approval: {body}"
    );
}
