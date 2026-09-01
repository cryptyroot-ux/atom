use axum::extract::{Query, State};
use axum::Json;
use serde::Deserialize;

use crate::app::AppState;
use crate::error::ApiError;

#[derive(Deserialize)]
pub struct CapabilitiesQuery {
    pub subject_id: Option<String>,
    pub active_only: Option<bool>,
}

pub async fn list_capabilities(
    State(app_state): State<AppState>,
    Query(_query): Query<CapabilitiesQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let store = app_state.store.lock().await;
    let grants: Vec<serde_json::Value> = store.grants().to_vec();
    Ok(Json(serde_json::json!({ "grants": grants })))
}
