//! Local read-only tool boundary. Consequential tools remain unavailable.
use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::{app::AppState, error::ApiError};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolRequest {
    pub tool: String,
    pub path: String,
    #[serde(default)]
    pub needle: Option<String>,
}

#[derive(Serialize)]
pub struct ToolResponse {
    pub tool: String,
    pub path: String,
    pub result: serde_json::Value,
    pub observation_id: String,
}

pub async fn read_only(
    State(state): State<AppState>,
    Json(request): Json<ToolRequest>,
) -> Result<(StatusCode, Json<ToolResponse>), ApiError> {
    let root = Path::new("/var/lib/atom").canonicalize().map_err(|e| {
        ApiError::bad_request("/tools/read-only", format!("tool root unavailable: {e}"))
    })?;
    let candidate = PathBuf::from(&request.path)
        .canonicalize()
        .map_err(|_| ApiError::bad_request("/tools/read-only", "path does not exist"))?;
    if !candidate.starts_with(&root) {
        return Err(ApiError::bad_request(
            "/tools/read-only",
            "path is outside capability root",
        ));
    }
    let result = match request.tool.as_str() {
        "list_directory" => {
            if !candidate.is_dir() {
                return Err(ApiError::bad_request(
                    "/tools/read-only",
                    "target is not a directory",
                ));
            }
            let mut entries: Vec<String> = std::fs::read_dir(&candidate)
                .map_err(io_err)?
                .map(|e| {
                    e.map(|v| v.file_name().to_string_lossy().into_owned())
                        .map_err(io_err)
                })
                .collect::<Result<_, _>>()?;
            entries.sort();
            if entries.len() > 128 {
                return Err(ApiError::bad_request(
                    "/tools/read-only",
                    "entry budget exceeded",
                ));
            }
            serde_json::json!(entries)
        }
        "read_file" | "search_text" => {
            let metadata = std::fs::metadata(&candidate).map_err(io_err)?;
            if metadata.len() > 64 * 1024 {
                return Err(ApiError::bad_request(
                    "/tools/read-only",
                    "byte budget exceeded",
                ));
            }
            let content = std::fs::read_to_string(&candidate).map_err(io_err)?;
            if request.tool == "search_text" {
                let needle = request
                    .needle
                    .as_deref()
                    .filter(|s| !s.is_empty())
                    .ok_or_else(|| {
                        ApiError::bad_request("/tools/read-only", "needle is required")
                    })?;
                serde_json::json!(content
                    .lines()
                    .filter(|line| line.contains(needle))
                    .take(128)
                    .collect::<Vec<_>>())
            } else {
                serde_json::json!(content)
            }
        }
        other => {
            return Err(ApiError::bad_request(
                "/tools/read-only",
                format!("tool `{other}` is not allowed"),
            ))
        }
    };
    let observation_id = uuid::Uuid::new_v4().to_string();
    let observation = serde_json::json!({
        "observation_id": observation_id,
        "tool": request.tool,
        "path": candidate,
        "result": result,
        "taint": "LOCAL_READ_ONLY"
    });
    let mut store = state.store.lock().await;
    store.add_observation(&observation).map_err(|e| {
        ApiError::bad_request("/tools/read-only", format!("evidence append failed: {e}"))
    })?;
    Ok((
        StatusCode::OK,
        Json(ToolResponse {
            tool: observation["tool"].as_str().unwrap_or_default().into(),
            path: observation["path"].as_str().unwrap_or_default().into(),
            result: observation["result"].clone(),
            observation_id,
        }),
    ))
}

fn io_err(error: std::io::Error) -> ApiError {
    ApiError::bad_request("/tools/read-only", error.to_string())
}
