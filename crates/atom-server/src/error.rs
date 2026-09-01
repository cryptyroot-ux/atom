use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;

/// RFC 9457 problem+json wire body.
#[derive(Debug, Clone, Serialize)]
pub struct ProblemDetail {
    pub ty: String,
    pub title: String,
    pub status: u16,
    pub detail: String,
    pub instance: String,
}

/// Application error mapped to an RFC 9457 response.
#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub ty: &'static str,
    pub title: &'static str,
    pub detail: String,
    pub instance: String,
}

impl ApiError {
    pub fn not_found(instance: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            ty: "https://atom.dev/errors/not-found",
            title: "Resource Not Found",
            detail: detail.into(),
            instance: instance.into(),
        }
    }

    pub fn bad_request(instance: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            ty: "https://atom.dev/errors/bad-request",
            title: "Bad Request",
            detail: detail.into(),
            instance: instance.into(),
        }
    }

    pub fn conflict(instance: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            ty: "https://atom.dev/errors/conflict",
            title: "Conflict",
            detail: detail.into(),
            instance: instance.into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status;
        let body = ProblemDetail {
            ty: self.ty.to_owned(),
            title: self.title.to_owned(),
            status: self.status.as_u16(),
            detail: self.detail,
            instance: self.instance,
        };
        (status, axum::Json(body)).into_response()
    }
}
