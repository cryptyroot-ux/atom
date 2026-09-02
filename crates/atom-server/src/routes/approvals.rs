use crate::{app::AppState, error::ApiError};
use atom_approval::ApprovalGrant;
use axum::{extract::State, http::StatusCode, Json};

pub async fn list(State(state): State<AppState>) -> Result<Json<serde_json::Value>, ApiError> {
    let store = state.store.lock().await;
    Ok(Json(serde_json::json!({"approvals": store.approvals()})))
}

pub async fn issue(
    State(state): State<AppState>,
    Json(grant): Json<ApprovalGrant>,
) -> Result<(StatusCode, Json<ApprovalGrant>), ApiError> {
    let value = serde_json::to_value(&grant)
        .map_err(|e| ApiError::bad_request("/approvals", e.to_string()))?;
    let mut store = state.store.lock().await;
    store
        .add_approval(&value)
        .map_err(|e| ApiError::bad_request("/approvals", e.to_string()))?;
    Ok((StatusCode::CREATED, Json(grant)))
}
