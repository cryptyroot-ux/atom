//! # atom-agent-profile
//!
//! Governed Agent Self types: AgentIdentityProfile, SoulProfile, AgentSelfRevision,
//! EffectiveSelfView. Enforces constitutional clauses from ATOM-SELF-001..028.
//!
//! ## Constitutional Constraints
//! - Persona Non-Authority: SOUL.md, IDENTITY.md MUST NOT create/replace authority
//! - Identity Domain Separation: Display identity != security identity
//! - Governed Self-Modification: Agent MAY propose, MUST NOT approve own change
//! - Constitutional Enforcement: Via typed API, not LLM prompt compliance
//! - Identity Continuity: Tenant/owner/agent isolation

pub mod profile;
pub mod revision;
pub mod types;
pub mod view;
pub mod workspace;

pub use profile::*;
pub use revision::*;
pub use types::*;
pub use view::*;
pub use workspace::*;
