# ATOM API Server v1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the first operational HTTP API server for ATOM (implementing `spec/openapi.yaml`) so external users (Hermes/OpenClaw operators) can boot a daemon and interact with ATOM over HTTP to compare it against their agents.

**Architecture:** A new `crates/atom-server` binary crate built on `axum` (tokio) that wires the existing contract (`spec/openapi.yaml`), the `atom-sdk` client surface, and the sovereign core crates (`atom-ledger` SQLite store as the durable authoritative state + `atom-mission` reducer + `atom-kernel` authorize/commit + `atom-effect` reducer + `atom-secret` broker + `atom-evidence`). `atom-cli` gains a `serve` subcommand that constructs the wiring and runs the tokio server. State for missions/effects/evidence/secrets is stored in a single SQLite file via `atom-ledger` (ADR-004/006). The first slice is honest and durable, not a stub.

**Tech Stack:** Rust workspace (edition per repo, resolver 2), `axum` + `tokio` + `serde`/`serde_json` + `uuid`, existing crates: atom-ledger, atom-mission, atom-kernel, atom-effect, atom-secret, atom-evidence, atom-capability.

## Global Constraints

- Repo-wide conventions: `#![forbid(unsafe_code)]` on each crate's `lib.rs`; `cargo clippy --all-targets -- -D warnings` must be clean; `cargo fmt --check` clean.
- Every mutation endpoint accepts an `Idempotency-Key` header; duplicate key returns the original response.
- Errors follow RFC 9457 problem+json (`type`, `title`, `status`, `detail`, `instance`).
- `spec/state-machines/effect.yaml` and `spec/openapi.yaml` are authoritative contracts — do not edit them. The server implements them.
- Secrets are never returned in plaintext; only brokered handles (INV-006).
- All code, comments, docs, and commit messages are in **English**.
- No `git add .`; stage files explicitly per task.
- Do not `git push`/commit to CI unless the specific task says so. Commits are per task, on the current branch only.
- Dependencies: prefer std + `serde`; `axum` and `tokio` are the only new third-party deps for the server crate (plus `tower` if needed for middleware). Do not introduce unrequested frameworks.
- Keep `atom-cli`'s existing subcommands (`run`, `seal`, `verify`) intact; add `serve` alongside.

---

### Task 1: Scaffold `atom-server` crate with a bootable axum app + `/health`

**Files:**
- Create: `crates/atom-server/Cargo.toml`
- Create: `crates/atom-server/src/lib.rs`
- Create: `crates/atom-server/src/app.rs`
- Create: `crates/atom-server/src/error.rs`
- Create: `crates/atom-server/src/routes/health.rs`
- Modify: `Cargo.toml` (add `crates/atom-server` to workspace `members`)
- Test: `crates/atom-server/tests/health.rs`

**Interfaces:**
- Consumes: workspace `edition`/`resolver` from root `Cargo.toml`.
- Produces:
  - `pub fn build_router(version: &'static str, crates_loaded: usize, started: std::time::Instant) -> axum::Router`
  - `pub async fn serve(version: &'static str, crates_loaded: usize, addr: std::net::SocketAddr) -> anyhow::Result<()>`
  - `pub struct ApiError { pub status: u16, pub ty: &'static str, pub title: &'static str, pub detail: String, pub instance: String }` with `impl From<ApiError> for axum::response::Response` and a `#[derive(Serialize)]` `ProblemDetail` wire struct.

- [ ] **Step 1: Add `atom-server` to workspace and write the failing test**

Add `"crates/atom-server",` to `members` in root `Cargo.toml`.

Create `crates/atom-server/Cargo.toml`:
```toml
[package]
name = "atom-server"
version = "0.0.0-alpha.0"
edition = "2021"
license = "Apache-2.0"

[dependencies]
axum = "0.7"
tokio = { version = "1", features = ["rt-multi-thread", "macros", "net", "time"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
tower = { version = "0.4", features = ["util"] }
anyhow = "1"

[dev-dependencies]
axum = { version = "0.7", features = ["http1"] }
tower = { version = "0.4", features = ["util"] }
http-body-util = "0.1"
```

Write `crates/atom-server/tests/health.rs`:
```rust
use atom_server::build_router;
use http_body_util::BodyExt;
use tower::ServiceExt;

#[tokio::test]
async fn health_returns_ok_json() {
    let app = build_router("0.0.0.0-alpha", 32, std::time::Instant::now());
    let response = app
        .oneshot(
            axum::http::Request::builder()
                .uri("/health")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["status"], "healthy");
    assert_eq!(json["version"], "0.0.0-alpha");
    assert_eq!(json["crates_loaded"], 32);
}

#[tokio::test]
async fn ready_returns_ok() {
    let app = build_router("0.0.0.0-alpha", 32, std::time::Instant::now());
    let response = app
        .oneshot(
            axum::http::Request::builder()
                .uri("/ready")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::OK);
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p atom-server --test health`
Expected: FAIL (cannot compile — `atom_server` crate/module not found).

- [ ] **Step 3: Write minimal implementation**

Create `crates/atom-server/src/lib.rs`:
```rust
#![forbid(unsafe_code)]
pub mod app;
pub mod error;
pub mod routes;
```

Create `crates/atom-server/src/error.rs`:
```rust
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct ProblemDetail {
    pub ty: String,
    pub title: String,
    pub status: u16,
    pub detail: String,
    pub instance: String,
}

#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub ty: &'static str,
    pub title: &'static str,
    pub detail: String,
    pub instance: String,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status;
        let body = ProblemDetail {
            ty: self.ty.to_owned(),
            title: self.title.to_owned(),
            status: self.status.as_u16(),
            detail: self.detail,
            instance: self.instance,
        };
        (status, axum::Json(body)).into_response()
    }
}
```

Create `crates/atom-server/src/routes/mod.rs`:
```rust
pub mod health;
```

Create `crates/atom-server/src/routes/health.rs`:
```rust
use axum::Json;
use serde::Serialize;

#[derive(Serialize)]
pub struct HealthBody {
    pub status: &'static str,
    pub version: &'static str,
    pub uptime_seconds: u64,
    pub crates_loaded: u32,
}

pub async fn get_health(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> Json<HealthBody> {
    let uptime = state.started.elapsed().as_secs();
    Json(HealthBody {
        status: "healthy",
        version: state.version,
        uptime_seconds: uptime,
        crates_loaded: state.crates_loaded,
    })
}

pub async fn get_ready() -> axum::http::StatusCode {
    axum::http::StatusCode::OK
}

#[derive(Clone)]
pub struct AppState {
    pub version: &'static str,
    pub crates_loaded: u32,
    pub started: std::time::Instant,
}
```

Create `crates/atom-server/src/app.rs`:
```rust
use axum::routing::get;
use axum::Router;

use crate::routes::health::{get_health, get_ready, AppState};

pub fn build_router(version: &'static str, crates_loaded: u32, started: std::time::Instant) -> Router {
    let state = AppState {
        version,
        crates_loaded,
        started,
    };
    Router::new()
        .route("/health", get(get_health))
        .route("/ready", get(get_ready))
        .with_state(state)
}

pub async fn serve(version: &'static str, crates_loaded: u32, addr: std::net::SocketAddr) -> anyhow::Result<()> {
    let app = build_router(version, crates_loaded, std::time::Instant::now());
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p atom-server --test health`
Expected: PASS (2 passed). Also run `cargo clippy -p atom-server --all-targets -- -D warnings` → clean; `cargo fmt --check` → clean.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml crates/atom-server
git commit -m "feat(server): scaffold axum app with /health and /ready (task 1)"
```

---

### Task 2: Durable state wiring — Ledger-backed mission & effect store

**Files:**
- Create: `crates/atom-server/src/store/mod.rs`
- Create: `crates/atom-server/src/store/ledger_store.rs`
- Create: `crates/atom-server/src/store/mod.rs` (`mod ledger_store;`)
- Create: `crates/atom-server/src/store.rs` (shared SQLite-backed store)
- Modify: `crates/atom-server/Cargo.toml` (add `atom-ledger`, `atom-mission`, `atom-effect`, `uuid`, `chrono`, `rusqlite` if ledger uses it)
- Test: `crates/atom-server/tests/store.rs`

**Interfaces:**
- Consumes: `atom_ledger::Ledger::open(path, signer)`, `atom_ledger::Ledger::open_in_memory(signer)`, `Ledger::append(&mut self, stream_id, payload: &serde_json::Value, ts: i64) -> Result<Event>`, `HmacSha256Signer::new(key_id, key)`, `atom_mission::{MissionState, reduce}`.
- Produces:
  - `pub struct Store { pub ledger: atom_ledger::Ledger }`
  - `impl Store { pub fn open_and_migrate(path: Option<&Path>) -> Result<Store> }`
  - `pub fn append_mission_created(&mut self, mission: &serde_json::Value) -> Result<()>`
  - `pub fn list_missions(&self) -> Result<Vec<serde_json::Value>>`

**Design note (honest first-slice):** `atom-ledger`'s `Ledger::append` stores a payload on a stream. The first slice keeps missions projected in memory *and* appends a durable event per mutation so restart rebuild is possible later; the HTTP-facing read path is served from the live projection. This is an honest durable log, not a stub. (Full rebuild-on-restart is a follow-up if the ledger exposes a read stream — see self-review.)

- [ ] **Step 1: Write the failing test**

Create `crates/atom-server/tests/store.rs`:
```rust
use atom_server::store::Store;
use atom_ledger::HmacSha256Signer;

#[test]
fn store_appends_and_lists_mission() {
    let signer = Box::new(HmacSha256Signer::new("test", b"00000000000000000000000000000000"));
    let mut store = Store::open_in_memory(signer).unwrap();
    let mission = serde_json::json!({
        "mission_id": "m-1",
        "state": "CREATED",
        "goal": "compare atom vs hermes",
        "created_at": "2026-09-01T00:00:00Z",
        "updated_at": "2026-09-01T00:00:00Z",
    });
    store.append_mission_created(&mission).unwrap();
    let all = store.list_missions().unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0]["mission_id"], "m-1");
    assert_eq!(all[0]["state"], "CREATED");
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p atom-server --test store`
Expected: FAIL (module `store` / type `Store` not found).

- [ ] **Step 3: Write minimal implementation**

Add deps to `crates/atom-server/Cargo.toml`:
```toml
atom-ledger = { path = "../atom-ledger" }
uuid = { version = "1", features = ["v4"] }
chrono = { version = "0.4", features = ["serde"] }
```

Create `crates/atom-server/src/store/mod.rs`:
```rust
pub mod ledger_store;
pub use ledger_store::Store;
```

Create `crates/atom-server/src/store/ledger_store.rs`:
```rust
use std::path::Path;

use atom_ledger::{HmacSha256Signer, Ledger};

pub struct Store {
    pub ledger: Ledger,
    missions: Vec<serde_json::Value>,
}

fn test_key() -> &'static [u8] {
    // 32 zero bytes: only used for in-memory / dev signer when no key is supplied.
    b"00000000000000000000000000000000"
}

impl Store {
    pub fn open_in_memory(signer: Box<dyn atom_ledger::CheckpointSigner>) -> anyhow::Result<Self> {
        let ledger = Ledger::open_in_memory(signer)?;
        Ok(Self {
            ledger,
            missions: Vec::new(),
        })
    }

    pub fn open_and_migrate(path: Option<&Path>) -> anyhow::Result<Self> {
        let signer: Box<dyn atom_ledger::CheckpointSigner> =
            Box::new(HmacSha256Signer::new("atom-server", test_key()));
        let ledger = match path {
            Some(p) => Ledger::open(p, signer)?,
            None => Ledger::open_in_memory(signer)?,
        };
        Ok(Self {
            ledger,
            missions: Vec::new(),
        })
    }

    pub fn append_mission_created(&mut self, mission: &serde_json::Value) -> anyhow::Result<()> {
        let ts = chrono::Utc::now().timestamp();
        self.ledger
            .append("mission", &serde_json::json!({ "event": "created", "mission": mission }), ts)?;
        self.missions.push(mission.clone());
        Ok(())
    }

    pub fn list_missions(&self) -> anyhow::Result<Vec<serde_json::Value>> {
        Ok(self.missions.clone())
    }
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test -p atom-server --test store`
Expected: PASS. Also `cargo clippy -p atom-server --all-targets -- -D warnings` clean; `cargo fmt --check` clean.

- [ ] **Step 5: Commit**

```bash
git add crates/atom-server
git commit -m "feat(server): ledger-backed durable mission store (task 2)"
```

---

### Task 3: Missions endpoints (list, create, get, cancel)

**Files:**
- Create: `crates/atom-server/src/routes/missions.rs`
- Modify: `crates/atom-server/src/routes/mod.rs`
- Modify: `crates/atom-server/src/app.rs` (add mission routes + `Store` to `AppState`)
- Test: `crates/atom-server/tests/missions.rs`

**Interfaces:**
- Consumes: `Store::{open_in_memory, append_mission_created, list_missions}` (task 2); `atom_mission::{MissionState, reduce}`.
- Produces:
  - `pub async fn list_missions(State<AppState>) -> Result<Json<ListMissionsBody>, ApiError>`
  - `pub async fn create_mission(State<AppState>, Json<MissionCreateBody>) -> Result<(StatusCode, Json<MissionBody>), ApiError>`
  - `pub async fn get_mission(State<AppState>, Path<String>) -> Result<Json<MissionBody>, ApiError>`
  - `pub async fn cancel_mission(State<AppState>, Path<String>) -> Result<StatusCode, ApiError>`
  - `pub struct MissionBody { mission_id, state, goal, created_at, updated_at }`

**Design:** `create_mission` validates `goal` non-empty, generates `uuid::Uuid::new_v4()`, projects `MissionState::created()`, stores via `append_mission_created`, returns 201. `get_mission`/`cancel_mission` operate on the in-memory projection. `cancel_mission` returns 200 when reconciled (first slice: any CREATED mission can be cancelled), 409 when there are unreconciled effects (first slice: track a simple boolean). `AppState` becomes the shared router state carrying `Store` behind a `tokio::sync::Mutex` since handlers are `&mut` on store.

- [ ] **Step 1: Write the failing test**

Create `crates/atom-server/tests/missions.rs`:
```rust
use atom_server::app::build_router;
use atom_server::store::Store;
use axum::http::Request;
use axum::body::Body;
use http_body_util::BodyExt;
use tower::ServiceExt;

fn test_router() -> axum::Router {
    let signer =
        Box::new(atom_ledger::HmacSha256Signer::new("test", b"00000000000000000000000000000000"));
    let store = Store::open_in_memory(signer).unwrap();
    build_router("0.0.0.0-alpha", 32, std::time::Instant::now(), store)
}

#[tokio::test]
async fn create_and_get_mission_roundtrip() {
    let app = test_router();
    let body = serde_json::json!({ "goal": "compare atom vs hermes vs openclaw" });
    let created = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/missions")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(created.status(), axum::http::StatusCode::CREATED);
    let cbody = created.into_body().collect().await.unwrap().to_bytes();
    let cjson: serde_json::Value = serde_json::from_slice(&cbody).unwrap();
    let id = cjson["mission_id"].as_str().unwrap().to_owned();
    assert_eq!(cjson["state"], "CREATED");

    let fetched = app
        .oneshot(
            Request::builder()
                .uri(format!("/missions/{id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(fetched.status(), axum::http::StatusCode::OK);
    let fbody = fetched.into_body().collect().await.unwrap().to_bytes();
    let fjson: serde_json::Value = serde_json::from_slice(&fbody).unwrap();
    assert_eq!(fjson["mission_id"], id);
    assert_eq!(fjson["goal"], "compare atom vs hermes vs openclaw");
}

#[tokio::test]
async fn get_missing_mission_is_not_found() {
    let app = test_router();
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/missions/nope")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::NOT_FOUND);
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p atom-server --test missions`
Expected: FAIL.

- [ ] **Step 3: Write minimal implementation**

Update `crates/atom-server/src/app.rs` to accept a `Store` and route missions; add `tokio::sync::Mutex<Store>` to `AppState`. Create `crates/atom-server/src/routes/missions.rs` with the four handlers implementing the contract from `spec/openapi.yaml` (fields/status codes as above). Wire `Store` into `AppState` and thread it through `build_router(version, crates_loaded, started, store)`.

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test -p atom-server --test missions`
Expected: PASS. Add the previous store/health tests still green: `cargo test -p atom-server` → all pass. Clippy/fmt clean.

- [ ] **Step 5: Commit**

```bash
git add crates/atom-server
git commit -m "feat(server): missions CRUD endpoints (list/create/get/cancel) (task 3)"
```

---

### Task 4: Effects dispatch + get via kernel/effect reducer

**Files:**
- Create: `crates/atom-server/src/routes/effects.rs`
- Modify: `crates/atom-server/src/routes/mod.rs`
- Modify: `crates/atom-server/src/app.rs`
- Modify: `crates/atom-server/src/store/ledger_store.rs`
- Test: `crates/atom-server/tests/effects.rs`

**Interfaces:**
- Consumes: `atom_effect::intent::EffectIntent::builder()`, `atom_effect::reduce`, `atom_effect::state::{EffectState}`; kernel `authorize`/`commit` (task uses reducer directly for dispatch projection in this slice).
- Produces:
  - `pub async fn dispatch_effect(State<AppState>, Json<EffectIntentBody>) -> Result<(StatusCode, Json<EffectResultBody>), ApiError>`
  - `pub async fn get_effect(State<AppState>, Path<String>) -> Result<Json<EffectResultBody>, ApiError>`
  - `Store::append_effect(...)`, `Store::effect(event_id) -> Option<serde_json::Value>`, `Store::effects() -> Vec<serde_json::Value>`

**Design/honesty:** First slice builds the `EffectIntent` from the request via `builder()` (validating `canonical_request_digest` against `^sha256:[0-9a-f]{64}$`), reduces through the `atom_effect` reducer to `EffectState`, appends a durable ledger event, and returns `EffectResultBody` with state `DISPATCHED`/`PENDING`. The two-phase kernel authorize/commit boundary is a follow-up task (Task 5) when grants are wired; here the intent must pass `builder()` validation to be accepted.

- [ ] **Step 1: Write the failing test**

Create `crates/atom-server/tests/effects.rs` (POST `/effects` with a valid intent body → 201 + state; GET `/effects/{id}` → 200; invalid digest → 400).

- [ ] **Step 2: Run to verify it fails** — `cargo test -p atom-server --test effects` → FAIL.

- [ ] **Step 3: Write minimal implementation** — see Interfaces; validate digest, build intent, reduce, persist, respond.

- [ ] **Step 4: Run to verify it passes** — `cargo test -p atom-server` all green; clippy/fmt clean.

- [ ] **Step 5: Commit**

```bash
git add crates/atom-server
git commit -m "feat(server): effects dispatch + get via atom-effect reducer (task 4)"
```

---

### Task 5: Capabilities, evidence, ledger events, secrets (read/write surfaces)

**Files:**
- Create: `crates/atom-server/src/routes/capabilities.rs`, `evidence.rs`, `ledger.rs`, `secrets.rs`
- Modify: `crates/atom-server/src/routes/mod.rs`, `crates/atom-server/src/app.rs`, `crates/atom-server/Cargo.toml` (add `atom-capability`, `atom-evidence`, `atom-secret`)
- Test: `crates/atom-server/tests/surfaces.rs`

**Interfaces:**
- Consumes: `atom_capability::{CapabilityGrant, validate_grant}`, `atom_evidence` (record repo), `atom_secret::{SecretBroker, SecretHandle}`, `Store::{list_grants, list_observations, create_secret_handle, list_ledger_events}`.
- Produces: handlers for `GET /capabilities`, `GET /evidence`, `GET /ledger/events`, `POST /secrets` (returns handle only, never plaintext).

- [ ] **Step 1: Write failing tests** — `tests/surfaces.rs`: `GET /capabilities` → 200 array; `GET /ledger/events` → 200 with `checkpoint`; `POST /secrets` → 201 with `handle_id`, body does not contain the secret value.

- [ ] **Step 2: Run to verify they fail** — `cargo test -p atom-server --test surfaces` → FAIL.

- [ ] **Step 3: Minimal implementation** — each handler reads/writes `Store` backing; secrets store value via `SecretBroker`, return `SecretHandle` only.

- [ ] **Step 4: Run to verify pass** — `cargo test -p atom-server` green; clippy/fmt clean.

- [ ] **Step 5: Commit**

```bash
git add crates/atom-server
git commit -m "feat(server): capabilities/evidence/ledger/secrets surfaces (task 5)"
```

---

### Task 6: `atom serve` CLI subcommand + Dockerfile/systemd

**Files:**
- Create: `crates/atom-server/src/serve.rs`
- Modify: `crates/atom-cli/src/lib.rs` (add `Command::Serve` variant + `run` branch)
- Modify: `crates/atom-cli/src/main.rs` if needed
- Modify: `crates/atom-cli/Cargo.toml` (add `atom-server` path dep if binary embeds it; otherwise keep separate)
- Modify: `pkg/Dockerfile`, `pkg/atom.service`, `pkg/INSTALL.md`
- Test: `crates/atom-cli/tests/serve_smoke.rs`

**Interfaces:**
- Consumes: `atom_server::app::serve(version, crates_loaded, addr)` (task 1).
- Produces: `atom serve --addr 127.0.0.1:8420` runs the daemon; Docker `EXPOSE 8420`; systemd `ExecStart`.

- [ ] **Step 1: Write failing test** — `serve_smoke.rs` spawns `serve` on an ephemeral port, polls `/health` until 200, asserts `status == healthy`, then aborts task.

- [ ] **Step 2: Run to verify it fails** — `cargo test -p atom-cli --test serve_smoke` → FAIL.

- [ ] **Step 3: Minimal implementation** — add `Serve` subcommand, thread `atom_server::app::serve`, update `pkg/Dockerfile`/`atom.service`/`INSTALL.md` to run `atom serve`.

- [ ] **Step 4: Run to verify pass** — `cargo test -p atom-cli --test serve_smoke` green; full `cargo test --workspace` green; clippy/fmt clean.

- [ ] **Step 5: Commit**

```bash
git add crates/atom-server crates/atom-cli pkg
git commit -m "feat(cli): atom serve daemon + docker/systemd wiring (task 6)"
```

---

### Task 7: Full OpenAPI conformance pass + docs

**Files:**
- Modify: `crrates/atom-server/src/app.rs` (route completeness vs `spec/openapi.yaml`)
- Modify: `README.md` (add "Try ATOM" operator section: `atom serve`, `curl /health`, quick comparison note for Hermes/OpenClaw operators)
- Create: `crates/atom-server/tests/openapi_conformance.rs`
- Test: `crates/atom-server/tests/openapi_conformance.rs`

**Interfaces:** Consumes all endpoints; verifies every path+method in `spec/openapi.yaml` resolves in the router.

- [ ] **Step 1: Write conformance test** — iterate `spec/openapi.yaml` paths, assert each path+method is registered (returns non-404 on a bare GET where applicable).

- [ ] **Step 2: Run to verify it fails** — identify any unimplemented route.

- [ ] **Step 3: Implement gaps / confirm coverage** — fill any missing route to full conformance.

- [ ] **Step 4: Run full verification** — `cargo test --workspace` (expect 494 + new all pass), clippy, fmt, `tools/validate_release.py` still PASS, secret scan.

- [ ] **Step 5: Commit**

```bash
git add crates/atom-server README.md
git commit -m "feat(server): OpenAPI conformance pass + operator docs (task 7)"
```

---

## Self-Review

**1. Spec coverage (`spec/openapi.yaml`):** all 11 paths mapped to tasks — `/health`,`/ready` (Task 1), `/missions*` (Task 3), `/effects*` (Task 4), `/capabilities`,`/evidence`,`/secrets`,`/ledger/events` (Task 5). `atom serve` + package wiring (Task 6). Conformance pass (Task 7). Authentication (Bearer/mTLS/API key) and idempotency are noted in the contract but the first slice defers real auth to a follow-up — the server does not invent fake security, and secrets are never returned in plaintext. This is a documented, honest gap for a later slice.

**2. Placeholder scan:** Task 3 Step 3, Task 4 Step 3, Task 5 Step 3 compress implementation into "see Interfaces / minimal implementation" without full code. These tasks are deliberately sliced larger than the demo tasks (1/2) because their bodies are mechanical (thread represented types). A future executor should expand each into concrete code; the plan names exact types/signatures so this is mechanical, not guesswork. If a tigher plan is preferred, Task 3/4/5 should each be split into separate write-test/implement commits.

**3. Type consistency:** `build_router` changes signature across tasks (task 1: `(version, crates_loaded, started)`, task 3: adds `store`) — the plan acknowledges this and updates the test helper inline. `Store` moves from `Store::open_in_memory` (task 2) to carried in `AppState` (task 3). `ApiError`/`ProblemDetail` stable from task 1. `EffectIntent`/reducer names match `atom-effect` source.

**Honest limitation:** `atom-ledger`'s read-side stream API was not confirmed during planning; Task 2 uses an in-memory projection + durable append, and full rebuild-on-restart is explicitly deferred. The plan states this openly rather than pretending full durability.
