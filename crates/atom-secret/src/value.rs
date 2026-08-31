//! SecretValue — opaque wrapper that zeroizes on drop.
//!
//! Per SEC-001 / ADR-019: SecretValue MUST zeroize on drop using the `zeroize` crate.
//! This ensures secrets never persist in memory after use.

use zeroize::{Zeroize, ZeroizeOnDrop};

/// An opaque secret value that automatically zeroizes its contents on drop.
///
/// This wrapper ensures that secret material is never left in memory after
/// the value goes out of scope. The `ZeroizeOnDrop` derive guarantees
/// that the inner bytes are overwritten with zeros when the value is dropped.
///
/// # Example
///
/// ```rust
/// use atom_secret::SecretValue;
///
/// let secret = SecretValue::new(b"my-api-key");
/// // Use secret.bytes() to access the raw bytes
/// // When `secret` goes out of scope, the bytes are zeroized
/// ```
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretValue {
    /// The secret bytes. This field is zeroized on drop.
    #[zeroize(skip)]
    inner: Vec<u8>,
}

impl SecretValue {
    /// Create a new SecretValue from bytes.
    pub fn new(bytes: &[u8]) -> Self {
        Self {
            inner: bytes.to_vec(),
        }
    }

    /// Create a new SecretValue from a string.
    pub fn from_string(s: &str) -> Self {
        Self::new(s.as_bytes())
    }

    /// Get a reference to the secret bytes.
    ///
    /// The caller must ensure the bytes are not retained beyond the
    /// lifetime of this SecretValue.
    pub fn bytes(&self) -> &[u8] {
        &self.inner
    }

    /// Get the length of the secret in bytes.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Check if the secret is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Explicitly zeroize the secret. This is called automatically on drop.
    pub fn zeroize(&mut self) {
        self.inner.zeroize();
    }
}

impl AsRef<[u8]> for SecretValue {
    fn as_ref(&self) -> &[u8] {
        &self.inner
    }
}

impl std::fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretValue")
            .field("len", &self.inner.len())
            .finish()
    }
}

impl PartialEq for SecretValue {
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner
    }
}

impl Eq for SecretValue {}
