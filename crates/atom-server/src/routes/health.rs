use axum::Json;
use serde::Serialize;

use crate::app::AppState;

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
