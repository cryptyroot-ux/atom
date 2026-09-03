use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::types::{content_digest, AgentProfileError, Result};

/// EffectiveSelfView — derived, short-lived view for a session/mission.
///
/// Constitutional constraint (ATOM-SELF-008):
/// - NOT root-of-truth
/// - NOT operations/resources/budget authority
/// - MUST carry derivation digest, source digests, generation, scope, expiry
/// - MUST be regenerated at session/mission boundary
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectiveSelfView {
    pub derivation_digest: String,
    pub source_digests: Vec<String>,
    pub generation: u64,
    pub scope: String,
    pub expiry: DateTime<Utc>,
    pub constitution_digest: String,
    pub identity_profile_id: String,
    pub soul_profile_id: String,
}

impl EffectiveSelfView {
    /// Create a new effective self view.
    pub fn new(
        constitution_digest: String,
        identity_profile_id: String,
        soul_profile_id: String,
        scope: String,
        ttl_seconds: i64,
    ) -> Self {
        let now = Utc::now();
        let source_digests = vec![
            constitution_digest.clone(),
            identity_profile_id.clone(),
            soul_profile_id.clone(),
        ];
        let derivation = format!("{:?}{}{:?}", now, scope, source_digests);
        Self {
            derivation_digest: content_digest(derivation.as_bytes()),
            source_digests,
            generation: 0,
            scope,
            expiry: now + chrono::Duration::seconds(ttl_seconds),
            constitution_digest,
            identity_profile_id,
            soul_profile_id,
        }
    }

    /// Check if the view is expired.
    pub fn is_expired(&self) -> bool {
        Utc::now() >= self.expiry
    }

    /// Verify the view is valid for use.
    pub fn verify(&self) -> Result<()> {
        if self.is_expired() {
            return Err(AgentProfileError::InvalidInput(
                "EffectiveSelfView expired".to_string(),
            ));
        }
        Ok(())
    }
}
