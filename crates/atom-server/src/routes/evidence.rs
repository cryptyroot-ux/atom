use axum::extract::{Query, State};
use axum::Json;
use serde::Deserialize;

use crate::app::AppState;
use crate::error::ApiError;

#[derive(Deserialize)]
pub struct EvidenceQuery {
    pub claim_id: Option<String>,
    pub taint: Option<String>,
}

pub async fn list_evidence(
    State(app_state): State<AppState>,
    Query(_query): Query<EvidenceQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let store = app_state.store.lock().await;
    let observations: Vec<serde_json::Value> = store.observations().to_vec();
    Ok(Json(serde_json::json!({ "observations": observations })))
}
