use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::types::{content_digest, AgentProfileError, Result, RevisionState};

/// AgentIdentityProfile — presentation identity, NOT security principal.
///
/// Constitutional constraint (ATOM-SELF-001): MUST NOT create/replace authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentIdentityProfile {
    pub profile_id: String,
    pub agent_id: String,
    pub owner_principal_id: String,
    pub display_name: String,
    pub role: String,
    pub archetype: Option<String>,
    pub avatar_ref: Option<String>,
    pub signature_symbol: Option<String>,
    pub languages: Vec<String>,
    pub generation: u64,
    pub state: RevisionState,
    pub constitution_digest: String,
    pub content_digest: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub authorized_by: String,
}

impl AgentIdentityProfile {
    /// Create a new identity profile in DRAFT state.
    pub fn new(
        agent_id: String,
        owner_principal_id: String,
        display_name: String,
        role: String,
        constitution_digest: String,
    ) -> Self {
        let now = Utc::now();
        Self {
            profile_id: uuid::Uuid::new_v4().to_string(),
            agent_id,
            owner_principal_id: owner_principal_id.clone(),
            display_name,
            role,
            archetype: None,
            avatar_ref: None,
            signature_symbol: None,
            languages: vec!["en".to_string()],
            generation: 0,
            state: RevisionState::Draft,
            constitution_digest,
            content_digest: String::new(),
            created_at: now,
            updated_at: now,
            authorized_by: owner_principal_id,
        }
    }

    /// Verify content digest matches.
    pub fn verify_digest(&self, content: &[u8]) -> Result<()> {
        let expected = content_digest(content);
        if self.content_digest != expected {
            return Err(AgentProfileError::DigestMismatch {
                expected: self.content_digest.clone(),
                found: expected,
            });
        }
        Ok(())
    }

    /// Verify constitution digest matches.
    pub fn verify_constitution(&self, constitution_digest: &str) -> Result<()> {
        if self.constitution_digest != constitution_digest {
            return Err(AgentProfileError::DigestMismatch {
                expected: self.constitution_digest.clone(),
                found: constitution_digest.to_string(),
            });
        }
        Ok(())
    }
}

/// SoulProfile — shapes cognition style, NOT authority.
///
/// Constitutional constraint (ATOM-SELF-001): MUST NOT contain operations/resources/budget.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SoulProfile {
    pub soul_id: String,
    pub agent_id: String,
    pub values: Vec<String>,
    pub voice: String,
    pub tone: String,
    pub epistemic_stance: String,
    pub uncertainty_policy: String,
    pub disagreement_policy: String,
    pub autonomy_posture: String,
    pub interaction_boundaries: Vec<String>,
    pub forbidden_behaviors: Vec<String>,
    pub change_policy: String,
    pub generation: u64,
    pub state: RevisionState,
    pub content_digest: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub authorized_by: String,
}

impl SoulProfile {
    /// Create a new soul profile in DRAFT state.
    pub fn new(agent_id: String, owner_principal_id: String) -> Self {
        let now = Utc::now();
        Self {
            soul_id: uuid::Uuid::new_v4().to_string(),
            agent_id,
            values: Vec::new(),
            voice: "neutral".to_string(),
            tone: "professional".to_string(),
            epistemic_stance: "careful".to_string(),
            uncertainty_policy: "acknowledge".to_string(),
            disagreement_policy: "respectful".to_string(),
            autonomy_posture: "propose_only".to_string(),
            interaction_boundaries: Vec::new(),
            forbidden_behaviors: vec![
                "no_authority_escalation".to_string(),
                "no_self_approval".to_string(),
                "no_credential_access".to_string(),
            ],
            change_policy: "owner_approval_required".to_string(),
            generation: 0,
            state: RevisionState::Draft,
            content_digest: String::new(),
            created_at: now,
            updated_at: now,
            authorized_by: owner_principal_id,
        }
    }

    /// Verify content digest matches.
    pub fn verify_digest(&self, content: &[u8]) -> Result<()> {
        let expected = content_digest(content);
        if self.content_digest != expected {
            return Err(AgentProfileError::DigestMismatch {
                expected: self.content_digest.clone(),
                found: expected,
            });
        }
        Ok(())
    }
}
