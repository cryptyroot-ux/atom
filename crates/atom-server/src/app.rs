use std::sync::Arc;
use std::time::Instant;

use axum::routing::get;
use axum::Router;
use tokio::sync::Mutex;

use crate::auth::{require_bearer, ApiToken};
use crate::routes::approvals::{
    issue as issue_approval, list as list_approvals, redeem as redeem_approval,
};
use crate::routes::capabilities::list_capabilities;
use crate::routes::chat::chat;
use crate::routes::effects::{dispatch_effect, get_effect};
use crate::routes::evidence::list_evidence;
use crate::routes::health::{get_health, get_ready};
use crate::routes::host::{
    commit as commit_host_op, list as list_host_plans, plan as plan_host_op, HostConfig,
};
use crate::routes::ledger::list_ledger_events;
use crate::routes::missions::{cancel_mission, create_mission, get_mission, list_missions};
use crate::routes::secrets::create_secret_handle;
use crate::routes::tools::read_only;
use crate::store::Store;

/// Router state shared by all handlers.
#[derive(Clone)]
pub struct AppState {
    pub version: &'static str,
    pub crates_loaded: u32,
    pub started: Instant,
    pub store: Arc<Mutex<Store>>,
    pub chat: Option<Arc<ChatConfig>>,
    /// Host-mutation configuration. `None` disables `/host/*` entirely, which
    /// is the default: a daemon with no sandbox root can change nothing.
    pub host: Option<Arc<HostConfig>>,
    /// Bearer-token transport auth. `None` leaves the router open: the test
    /// builders below and explicit `--no-auth` development use only.
    /// Production `atom serve` refuses to start unauthenticated, so an open
    /// router can never be a silent misconfiguration.
    pub auth: Option<Arc<ApiToken>>,
}

/// Redacted provider settings needed by `/chat`. The API key stays in daemon
/// memory and is never serialized or included in diagnostics.
#[derive(Clone)]
pub struct ChatConfig {
    pub base_url: String,
    pub model: String,
    pub api_key: String,
    pub timeout_ms: u64,
    pub max_response_bytes: usize,
}

pub fn build_router(
    version: &'static str,
    crates_loaded: u32,
    started: Instant,
    store: Arc<Mutex<Store>>,
) -> Router {
    build_router_with_chat(version, crates_loaded, started, store, None)
}

pub fn build_router_with_chat(
    version: &'static str,
    crates_loaded: u32,
    started: Instant,
    store: Arc<Mutex<Store>>,
    chat_config: Option<ChatConfig>,
) -> Router {
    build_router_with(version, crates_loaded, started, store, chat_config, None)
}

/// Builds the full router, including the host-mutation surface when a sandbox
/// root is configured.
///
/// `host_config: None` is the safe default: `/host/plan` and `/host/commit` then
/// refuse every request, so a misconfigured daemon cannot change the host.
///
/// The router is built **without** transport auth: test and loopback-development
/// use only. Production code must use [`build_router_with_auth`].
pub fn build_router_with(
    version: &'static str,
    crates_loaded: u32,
    started: Instant,
    store: Arc<Mutex<Store>>,
    chat_config: Option<ChatConfig>,
    host_config: Option<HostConfig>,
) -> Router {
    build_router_with_auth(
        version,
        crates_loaded,
        started,
        store,
        chat_config,
        host_config,
        None,
    )
}

/// Builds the full router with an explicit transport-auth choice.
///
/// `auth: None` leaves every route open (tests and explicit `--no-auth` only).
/// `auth: Some(token)` requires `Authorization: Bearer <token>` on every route
/// except `/health` and `/ready`, which stay public for unauthenticated
/// diagnostics. Auth is transport only: it never substitutes for capability
/// grants or approvals further down the stack.
pub fn build_router_with_auth(
    version: &'static str,
    crates_loaded: u32,
    started: Instant,
    store: Arc<Mutex<Store>>,
    chat_config: Option<ChatConfig>,
    host_config: Option<HostConfig>,
    auth: Option<ApiToken>,
) -> Router {
    let state = AppState {
        version,
        crates_loaded,
        started,
        store,
        chat: chat_config.map(Arc::new),
        host: host_config.map(Arc::new),
        auth: auth.map(Arc::new),
    };
    // Public surface: read-only liveness only, safe without credentials.
    let public = Router::new()
        .route("/health", get(get_health))
        .route("/ready", get(get_ready));
    // Everything else requires the bearer token when one is configured.
    let protected = Router::new()
        .route("/chat", axum::routing::post(chat))
        .route("/missions", get(list_missions).post(create_mission))
        .route("/missions/{mission_id}", get(get_mission))
        .route(
            "/missions/{mission_id}/cancel",
            axum::routing::post(cancel_mission),
        )
        .route("/effects", axum::routing::post(dispatch_effect))
        .route("/effects/{effect_id}", get(get_effect))
        .route("/capabilities", get(list_capabilities))
        .route("/evidence", get(list_evidence))
        .route("/ledger/events", get(list_ledger_events))
        .route("/secrets", axum::routing::post(create_secret_handle))
        .route("/tools/read-only", axum::routing::post(read_only))
        .route("/host/plans", get(list_host_plans))
        .route("/host/plan", axum::routing::post(plan_host_op))
        .route("/host/commit", axum::routing::post(commit_host_op))
        .route("/approvals", get(list_approvals).post(issue_approval))
        .route(
            "/approvals/{grant_id}/redeem",
            axum::routing::post(redeem_approval),
        )
        // The bearer check runs before any protected handler. `state` is
        // cloned into the middleware here and again by `with_state` below;
        // both clones share the same `Arc` allocations.
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            require_bearer,
        ));
    public.merge(protected).with_state(state)
}

pub async fn serve(
    version: &'static str,
    crates_loaded: u32,
    addr: std::net::SocketAddr,
    store: Arc<Mutex<Store>>,
) -> anyhow::Result<()> {
    serve_with_chat(version, crates_loaded, addr, store, None).await
}

/// Serves the API with an explicit host-mutation configuration.
///
/// Kept signature-stable for the smoke test: serves **without** transport auth,
/// loopback development only. Production `atom serve` uses [`serve_with`] with
/// an explicit auth choice.
pub async fn serve_with_chat(
    version: &'static str,
    crates_loaded: u32,
    addr: std::net::SocketAddr,
    store: Arc<Mutex<Store>>,
    chat_config: Option<ChatConfig>,
) -> anyhow::Result<()> {
    serve_with(version, crates_loaded, addr, store, chat_config, None, None).await
}

/// Serves the API with explicit host-mutation and transport-auth choices.
///
/// `auth: None` serves open (the CLI only allows this under explicit
/// `--no-auth`); `Some(token)` enforces the bearer check on every route except
/// `/health` and `/ready`.
pub async fn serve_with(
    version: &'static str,
    crates_loaded: u32,
    addr: std::net::SocketAddr,
    store: Arc<Mutex<Store>>,
    chat_config: Option<ChatConfig>,
    host_config: Option<HostConfig>,
    auth: Option<ApiToken>,
) -> anyhow::Result<()> {
    let app = build_router_with_auth(
        version,
        crates_loaded,
        std::time::Instant::now(),
        store,
        chat_config,
        host_config,
        auth,
    );
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
