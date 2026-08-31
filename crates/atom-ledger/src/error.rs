//! Ledger error type.
//!
//! Every variant is reachable: nothing here is speculative. Integrity problems found by
//! `verify_stream` are *not* errors — they are [`crate::Finding`]s in a report, because a
//! tampered store still answers questions correctly, it just answers them provably wrong.

/// Convenience alias used across the crate's public API.
pub type Result<T> = std::result::Result<T, Error>;

/// Something that stopped the ledger from doing its job.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The SQLite store rejected an operation (including append-only trigger aborts).
    #[error("ledger store: {0}")]
    Store(#[from] rusqlite::Error),

    /// A stored payload is no longer valid JSON, so it cannot be handed back as a value.
    /// The hash chain reports the same damage as a
    /// [`Finding::PayloadDigestMismatch`](crate::Finding::PayloadDigestMismatch).
    #[error("stored payload is not valid JSON: {0}")]
    Json(#[from] serde_json::Error),

    /// A number cannot be encoded under RFC 8785, which defines numbers as IEEE 754
    /// doubles. Refusing is deliberate: silently rounding would let two implementations
    /// derive different identities for the same event (ADR-020).
    #[error("number {value} is not representable under RFC 8785 (max safe integer is 2^53)")]
    UnrepresentableNumber { value: String },

    /// A stored row does not have the shape the schema promises.
    #[error("malformed ledger row: {detail}")]
    MalformedRow { detail: String },

    /// A hash was not 32 bytes, or not valid lowercase hex.
    #[error("invalid hash: {detail}")]
    InvalidHash { detail: String },

    /// A checkpoint was requested for a stream that holds no events; there is no head to
    /// seal (ATOM-LED-001).
    #[error("stream `{stream_id}` is empty: there is no head to seal")]
    EmptyStream { stream_id: String },

    /// The current head is already sealed. Checkpoints are append-only like events, so
    /// re-sealing the same head would mean rewriting history.
    #[error("stream `{stream_id}` is already sealed at seq {seq}")]
    AlreadySealed { stream_id: String, seq: u64 },
}
