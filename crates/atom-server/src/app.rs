use std::sync::Arc;
use std::time::Instant;

use axum::routing::get;
use axum::Router;
use tokio::sync::Mutex;

use crate::routes::capabilities::list_capabilities;
use crate::routes::effects::{dispatch_effect, get_effect};
use crate::routes::evidence::list_evidence;
use crate::routes::health::{get_health, get_ready};
use crate::routes::ledger::list_ledger_events;
use crate::routes::missions::{cancel_mission, create_mission, get_mission, list_missions};
use crate::routes::secrets::create_secret_handle;
use crate::store::Store;

/// Router state shared by all handlers.
#[derive(Clone)]
pub struct AppState {
    pub version: &'static str,
    pub crates_loaded: u32,
    pub started: Instant,
    pub store: Arc<Mutex<Store>>,
}

pub fn build_router(
    version: &'static str,
    crates_loaded: u32,
    started: Instant,
    store: Arc<Mutex<Store>>,
) -> Router {
    let state = AppState {
        version,
        crates_loaded,
        started,
        store,
    };
    Router::new()
        .route("/health", get(get_health))
        .route("/ready", get(get_ready))
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
        .with_state(state)
}

pub async fn serve(
    version: &'static str,
    crates_loaded: u32,
    addr: std::net::SocketAddr,
    store: Arc<Mutex<Store>>,
) -> anyhow::Result<()> {
    let app = build_router(version, crates_loaded, std::time::Instant::now(), store);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
