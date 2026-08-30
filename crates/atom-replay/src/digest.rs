//! Length-prefixed SHA-256 component hashing, matching `atom-effect`'s scheme.
//!
//! Concatenation is never ambiguous: every component is prefixed by its byte
//! length, so `("ab", "c")` and `("a", "bc")` hash differently. Replay digests
//! are built the same way as effect digests so a replayed trajectory can be
//! compared against the effect kernel's own output without re-encoding.

use sha2::{Digest, Sha256};

/// Feeds `value` into `hasher`, prefixed by its length in bytes.
pub(crate) fn component(hasher: &mut Sha256, value: &str) {
    let length =
        u64::try_from(value.len()).expect("string lengths fit in u64 on supported targets");
    hasher.update(length.to_be_bytes());
    hasher.update(value.as_bytes());
}

/// The crate-wide digest encoding: `sha256:` followed by 64 lowercase hex.
pub(crate) fn finish(hasher: Sha256) -> String {
    format!("sha256:{:x}", hasher.finalize())
}
