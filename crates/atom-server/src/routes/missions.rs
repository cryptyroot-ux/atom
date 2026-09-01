use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::app::AppState;
use crate::error::ApiError;

#[derive(Deserialize)]
pub struct MissionCreateBody {
    pub goal: String,
    #[serde(default)]
    pub context: Option<serde_json::Value>,
    #[serde(default)]
    pub priority: Option<String>,
}

#[derive(Serialize, Clone)]
pub struct MissionBody {
    pub mission_id: String,
    pub state: String,
    pub goal: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Serialize)]
pub struct ListMissionsBody {
    pub missions: Vec<MissionBody>,
    pub total: usize,
}

fn utf8_time_now() -> String {
    chrono::Utc::now().to_rfc3339()
}

fn mission_body(value: &serde_json::Value) -> Option<MissionBody> {
    let mission_id = value["mission_id"].as_str()?.to_owned();
    let state = value["state"].as_str()?.to_owned();
    let goal = value["goal"].as_str()?.to_owned();
    let created_at = value["created_at"].as_str().unwrap_or_default().to_owned();
    let updated_at = value["updated_at"].as_str().unwrap_or_default().to_owned();
    Some(MissionBody {
        mission_id,
        state,
        goal,
        created_at,
        updated_at,
    })
}

pub async fn list_missions(
    State(state): State<AppState>,
    axum::extract::Query(query): axum::extract::Query<ListQuery>,
) -> Result<Json<ListMissionsBody>, ApiError> {
    let store = state.store.lock().await;
    let all = store.missions();
    let filtered: Vec<MissionBody> = all
        .iter()
        .filter(|m| match &query.state {
            Some(s) => m["state"].as_str() == Some(s.as_str()),
            None => true,
        })
        .skip(query.offset.unwrap_or(0))
        .take(query.limit.unwrap_or(20).min(100))
        .filter_map(mission_body)
        .collect();
    let total = filtered.len();
    Ok(Json(ListMissionsBody {
        missions: filtered,
        total,
    }))
}

#[derive(Deserialize)]
pub struct ListQuery {
    pub state: Option<String>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

pub async fn create_mission(
    State(state): State<AppState>,
    Json(body): Json<MissionCreateBody>,
) -> Result<(StatusCode, Json<MissionBody>), ApiError> {
    if body.goal.trim().is_empty() {
        return Err(ApiError::bad_request(
            "/missions",
            "goal must be a non-empty string",
        ));
    }
    let mission_id = uuid::Uuid::new_v4().to_string();
    let now = utf8_time_now();
    let mission = serde_json::json!({
        "mission_id": mission_id,
        "state": "CREATED",
        "goal": body.goal,
        "created_at": now,
        "updated_at": now,
    });
    let mut store = state.store.lock().await;
    store
        .append_mission_created(&mission)
        .map_err(|e| ApiError::bad_request("/missions", format!("append failed: {e}")))?;
    let body = mission_body(&mission).expect("just-built mission body");
    Ok((StatusCode::CREATED, Json(body)))
}

pub async fn get_mission(
    State(state): State<AppState>,
    Path(mission_id): Path<String>,
) -> Result<Json<MissionBody>, ApiError> {
    let store = state.store.lock().await;
    let mission = store
        .missions()
        .iter()
        .find(|m| m["mission_id"] == mission_id)
        .and_then(mission_body)
        .ok_or_else(|| {
            ApiError::not_found(format!("/missions/{mission_id}"), "mission not found")
        })?;
    Ok(Json(mission))
}

pub async fn cancel_mission(
    State(state): State<AppState>,
    Path(mission_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let mut store = state.store.lock().await;
    let mission = store
        .missions()
        .iter()
        .find(|m| m["mission_id"] == mission_id)
        .cloned()
        .ok_or_else(|| {
            ApiError::not_found(
                format!("/missions/{mission_id}/cancel"),
                "mission not found",
            )
        })?;
    if mission["state"] == "CANCELLED" {
        return Err(ApiError::conflict(
            format!("/missions/{mission_id}/cancel"),
            "mission already cancelled",
        ));
    }
    // INV-013: cancellation is only surfaced once owned effects are reconciled.
    // First slice tracks no outstanding effects per mission, so any CREATED
    // mission may cancel. (Durable reconciliation wiring is a follow-up.)
    let mut updated = mission.clone();
    updated["state"] = serde_json::Value::String("CANCELLED".to_owned());
    updated["updated_at"] = serde_json::Value::String(utf8_time_now());
    store.update_mission(&mission_id, &updated).map_err(|e| {
        ApiError::bad_request(
            format!("/missions/{mission_id}/cancel"),
            format!("update failed: {e}"),
        )
    })?;
    Ok(StatusCode::OK)
}
