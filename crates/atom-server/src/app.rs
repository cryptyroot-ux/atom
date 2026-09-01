use std::sync::Arc;
use std::time::Instant;

use axum::routing::get;
use axum::Router;
use tokio::sync::Mutex;

use crate::routes::health::{get_health, get_ready};
use crate::routes::missions::{cancel_mission, create_mission, get_mission, list_missions};
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
    store: Store,
) -> Router {
    let state = AppState {
        version,
        crates_loaded,
        started,
        store: Arc::new(Mutex::new(store)),
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
        .with_state(state)
}

pub async fn serve(
    version: &'static str,
    crates_loaded: u32,
    addr: std::net::SocketAddr,
    store: Store,
) -> anyhow::Result<()> {
    let app = build_router(version, crates_loaded, std::time::Instant::now(), store);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
