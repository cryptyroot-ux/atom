//! SDK error types — transport + API + serialization.

use thiserror::Error;

/// Result alias for SDK operations.
pub type SdkResult<T> = std::result::Result<T, SdkError>;

/// What went wrong when driving the ATOM /v1 API.
#[derive(Debug, Error)]
pub enum SdkError {
    /// The request could not be serialized into the wire shape.
    #[error("serialize request: {0}")]
    Serialize(#[from] serde_json::Error),

    /// The response was not parseable as the expected wire type.
    #[error("deserialize response: {0}")]
    Deserialize(String),

    /// The HTTP transport itself failed (connection, timeout, DNS).
    #[error("transport: {0}")]
    Transport(String),

    /// The server returned a structured error (non-2xx).
    #[error("api status {status}: {message}")]
    Api {
        /// HTTP status code.
        status: u16,
        /// Human-readable error message from the server.
        message: String,
    },

    /// A builder was used with an invalid configuration.
    #[error("invalid client config: {0}")]
    InvalidConfig(String),
}
