use std::collections::BTreeMap;

use atom_mission::MissionSpec;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::app::AppState;
use crate::error::ApiError;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MissionCreateBody {
    pub goal: Option<String>,
    pub success_criteria: Option<Vec<String>>,
    pub constraints: Option<Vec<String>>,
    pub budgets: Option<BTreeMap<String, u64>>,
    pub authority_profile_ref: Option<String>,
    pub evidence_requirements: Option<Vec<String>>,
    pub stopping_rules: Option<Vec<String>>,
    #[serde(default)]
    pub context: Option<serde_json::Value>,
    #[serde(default)]
    pub priority: Option<String>,
}

impl MissionCreateBody {
    /// Converts the wire request into the canonical durable objective. Every
    /// field is explicitly required at the HTTP boundary, including fields the
    /// domain model permits to be an empty *declared* list.
    fn into_parts(
        self,
    ) -> Result<(MissionSpec, Option<serde_json::Value>, Option<String>), ApiError> {
        let goal = required(self.goal, "goal")?;
        let success_criteria = required(self.success_criteria, "success_criteria")?;
        let constraints = required(self.constraints, "constraints")?;
        let budgets = required(self.budgets, "budgets")?;
        let authority_profile_ref = required(self.authority_profile_ref, "authority_profile_ref")?;
        let evidence_requirements = required(self.evidence_requirements, "evidence_requirements")?;
        let stopping_rules = required(self.stopping_rules, "stopping_rules")?;
        let spec = MissionSpec::new(
            goal,
            success_criteria,
            constraints,
            budgets,
            authority_profile_ref,
            evidence_requirements,
            stopping_rules,
        )
        .map_err(|error| ApiError::bad_request("/missions", error.to_string()))?;
        Ok((spec, self.context, self.priority))
    }
}

fn required<T>(value: Option<T>, field: &str) -> Result<T, ApiError> {
    value.ok_or_else(|| {
        ApiError::bad_request(
            "/missions",
            format!("mission contract is missing required field `{field}`"),
        )
    })
}

#[derive(Serialize, Clone)]
pub struct MissionBody {
    pub mission_id: String,
    pub state: String,
    pub goal: String,
    pub created_at: String,
    pub updated_at: String,
    /// Durable execution phase (CREATED … TERMINAL), additive to `state`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase: Option<String>,
    /// Mission condition (NORMAL | …), additive to `state`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub condition: Option<String>,
    /// Terminal outcome (SUCCEEDED | FAILED | CANCELLED | …) or null.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<String>,
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
    let phase = value["phase"].as_str().map(String::from);
    let condition = value["condition"].as_str().map(String::from);
    let outcome = value["outcome"].as_str().map(String::from);
    Some(MissionBody {
        mission_id,
        state,
        goal,
        created_at,
        updated_at,
        phase,
        condition,
        outcome,
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
    let (spec, context, priority) = body.into_parts()?;
    let mission_id = uuid::Uuid::new_v4().to_string();
    let now = utf8_time_now();
    let mission = serde_json::json!({
        "mission_id": mission_id,
        "state": "CREATED",
        "phase": "READY",
        "condition": "NORMAL",
        "outcome": null,
        "goal": spec.goal,
        "spec": spec,
        "context": context,
        "priority": priority,
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
    updated["phase"] = serde_json::Value::String("TERMINAL".to_owned());
    updated["condition"] = serde_json::Value::String("NORMAL".to_owned());
    updated["outcome"] = serde_json::Value::String("CANCELLED".to_owned());
    updated["updated_at"] = serde_json::Value::String(utf8_time_now());
    store.update_mission(&mission_id, &updated).map_err(|e| {
        ApiError::bad_request(
            format!("/missions/{mission_id}/cancel"),
            format!("update failed: {e}"),
        )
    })?;
    Ok(StatusCode::OK)
}
