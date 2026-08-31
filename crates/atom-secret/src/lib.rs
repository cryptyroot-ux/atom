//! atom-secret: SecretHandle broker (audience/principal/mission/capability/target/operation/expiry/redemptions/generation).
//!
//! Normative sources (`spec/`, precedence 1):
//!
//! * **SEC-001** — Secrets MUST be delivered by SecretHandle with audience, principal,
//!   mission, capability, target, operation, expiry, redemptions and generation constraints.
//! * **INV-006** — Secrets are brokered handles, not ambient model or worker environment state.
//! * **ADR-019** — SecretHandle is scoped; secrets are never ambient.
//!
//! ```
//! use atom_secret::{SecretBroker, SecretHandle, SecretValue, SecretVault};
//! use chrono::{Utc, Duration};
//!
//! let broker = SecretBroker::new();
//! let handle = SecretHandle::builder()
//!     .audience("aud")
//!     .principal_id("p1")
//!     .target("api.example.com")
//!     .operation("read")
//!     .expiry(Utc::now() + Duration::hours(1))
//!     .max_redemptions(1)
//!     .generation(0)
//!     .build();
//! broker.plant(handle.clone(), SecretValue::new(b"my-secret"));
//! let secret = broker.redeem(&handle).unwrap();
//! // secret.zeroize_on_drop() happens automatically
//! ```

#![forbid(unsafe_code)]

pub mod broker;
pub mod handle;
pub mod value;
pub mod vault;

pub use broker::SecretBroker;
pub use handle::SecretHandle;
pub use value::SecretValue;
pub use vault::{SecretVault, SecretVaultError};

/// Placeholder marker so the crate compiles under the G0 spec-freeze skeleton.
pub const CRATE_STAGE: &str = "G0-skeleton";
