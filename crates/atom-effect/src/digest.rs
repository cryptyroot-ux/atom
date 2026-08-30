//! Length-prefixed SHA-256 component hashing.
//!
//! Every digest in this crate is built from `digest_component` calls so that
//! concatenation can never be ambiguous: `("ab", "c")` and `("a", "bc")` hash
//! differently.

use sha2::{Digest, Sha256};

/// Feeds `value` into `hasher`, prefixed by its length in bytes.
pub(crate) fn digest_component(hasher: &mut Sha256, value: &str) {
    let length =
        u64::try_from(value.len()).expect("string lengths fit in u64 on supported targets");
    hasher.update(length.to_be_bytes());
    hasher.update(value.as_bytes());
}

/// Feeds `value` into `hasher`, distinguishing absence from an empty string.
pub(crate) fn digest_optional(hasher: &mut Sha256, value: Option<&str>) {
    match value {
        Some(value) => {
            digest_component(hasher, "some");
            digest_component(hasher, value);
        }
        None => digest_component(hasher, "none"),
    }
}

/// The crate-wide digest encoding: `sha256:` followed by 64 lowercase hex.
pub(crate) fn finish(hasher: Sha256) -> String {
    format!("sha256:{:x}", hasher.finalize())
}
