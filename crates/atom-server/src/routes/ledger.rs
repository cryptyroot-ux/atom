use axum::extract::{Query, State};
use axum::Json;
use serde::Deserialize;

use crate::app::AppState;
use crate::error::ApiError;

#[derive(Deserialize)]
pub struct LedgerQuery {
    pub since_checkpoint: Option<u64>,
    pub limit: Option<usize>,
}

pub async fn list_ledger_events(
    State(app_state): State<AppState>,
    Query(query): Query<LedgerQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let store = app_state.store.lock().await;
    let (mut events, checkpoint) = store
        .list_ledger_events(query.since_checkpoint)
        .map_err(|e| ApiError::bad_request("/ledger/events", format!("scan failed: {e}")))?;
    if let Some(limit) = query.limit {
        events.truncate(limit);
    }
    Ok(Json(
        serde_json::json!({ "events": events, "checkpoint": checkpoint }),
    ))
}
