use std::sync::Arc;
use std::time::Instant;

use axum::routing::get;
use axum::Router;
use tokio::sync::Mutex;

use crate::routes::approvals::{
    issue as issue_approval, list as list_approvals, redeem as redeem_approval,
};
use crate::routes::capabilities::list_capabilities;
use crate::routes::chat::chat;
use crate::routes::effects::{dispatch_effect, get_effect};
use crate::routes::evidence::list_evidence;
use crate::routes::health::{get_health, get_ready};
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
    let state = AppState {
        version,
        crates_loaded,
        started,
        store,
        chat: chat_config.map(Arc::new),
    };
    Router::new()
        .route("/health", get(get_health))
        .route("/ready", get(get_ready))
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
        .route("/approvals", get(list_approvals).post(issue_approval))
        .route(
            "/approvals/{grant_id}/redeem",
            axum::routing::post(redeem_approval),
        )
        .with_state(state)
}

pub async fn serve(
    version: &'static str,
    crates_loaded: u32,
    addr: std::net::SocketAddr,
    store: Arc<Mutex<Store>>,
) -> anyhow::Result<()> {
    serve_with_chat(version, crates_loaded, addr, store, None).await
}

pub async fn serve_with_chat(
    version: &'static str,
    crates_loaded: u32,
    addr: std::net::SocketAddr,
    store: Arc<Mutex<Store>>,
    chat_config: Option<ChatConfig>,
) -> anyhow::Result<()> {
    let app = build_router_with_chat(
        version,
        crates_loaded,
        std::time::Instant::now(),
        store,
        chat_config,
    );
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
