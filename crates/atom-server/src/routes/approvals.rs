use crate::{app::AppState, error::ApiError};
use atom_approval::ApprovalGrant;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};

pub async fn list(State(state): State<AppState>) -> Result<Json<serde_json::Value>, ApiError> {
    let store = state.store.lock().await;
    Ok(Json(serde_json::json!({"approvals": store.approvals()})))
}

pub async fn issue(
    State(state): State<AppState>,
    Json(grant): Json<ApprovalGrant>,
) -> Result<(StatusCode, Json<ApprovalGrant>), ApiError> {
    let mut value = serde_json::to_value(&grant)
        .map_err(|e| ApiError::bad_request("/approvals", e.to_string()))?;
    value["redeemed"] = serde_json::Value::Bool(false);
    let mut store = state.store.lock().await;
    store
        .add_approval(&value)
        .map_err(|e| ApiError::bad_request("/approvals", e.to_string()))?;
    Ok((StatusCode::CREATED, Json(grant)))
}

pub async fn redeem(
    State(state): State<AppState>,
    Path(grant_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let mut store = state.store.lock().await;
    let grant = store
        .redeem_approval(&grant_id)
        .map_err(|e| ApiError::conflict(format!("/approvals/{grant_id}/redeem"), e.to_string()))?;
    Ok(Json(
        serde_json::json!({"grant_id": grant_id, "redeemed": true, "grant": grant}),
    ))
}
