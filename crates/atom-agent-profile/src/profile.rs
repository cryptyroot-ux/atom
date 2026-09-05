use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::types::{content_digest, AgentProfileError, Result, RevisionState};

/// Domain separation tag for identity content addressing (ATOM-SELF-013).
const IDENTITY_DOMAIN: &str = "atom.agent-profile.identity.v1";

/// Domain separation tag for soul content addressing (ATOM-SELF-013).
const SOUL_DOMAIN: &str = "atom.agent-profile.soul.v1";

/// Append one field to a canonical byte buffer.
///
/// Length-prefixed and unit-separated so that no combination of field values
/// can be re-parsed as a different field layout (digest confusion defence).
fn push_field(buf: &mut Vec<u8>, value: &str) {
    buf.extend_from_slice(value.len().to_string().as_bytes());
    buf.push(b':');
    buf.extend_from_slice(value.as_bytes());
    buf.push(0x1f);
}

/// Append an optional field, distinguishing `None` from `Some("")`.
fn push_opt(buf: &mut Vec<u8>, value: Option<&String>) {
    match value {
        Some(v) => {
            buf.push(b'S');
            push_field(buf, v);
        }
        None => {
            buf.push(b'N');
            buf.push(0x1f);
        }
    }
}

/// Start a canonical buffer bound to a domain tag.
fn canonical_start(domain: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(256);
    buf.extend_from_slice(domain.as_bytes());
    buf.push(0x00);
    buf
}

/// AgentIdentityProfile — presentation identity, NOT security principal.
///
/// Constitutional constraint (ATOM-SELF-001): MUST NOT create/replace authority.
/// Constitutional constraint (ATOM-SELF-009): content-addressed presentation identity.
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
    /// Create a new identity profile in DRAFT state, sealed with its content digest.
    pub fn new(
        agent_id: String,
        owner_principal_id: String,
        display_name: String,
        role: String,
        constitution_digest: String,
    ) -> Self {
        let now = Utc::now();
        let mut profile = Self {
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
        };
        profile.content_digest = profile.compute_content_digest();
        profile
    }

    /// Deterministic canonical byte encoding of the presentation material.
    ///
    /// Binds material, not names: `content_digest` itself and the mutable
    /// lifecycle timestamps are excluded so the address is replay-stable.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = canonical_start(IDENTITY_DOMAIN);
        push_field(&mut buf, &self.profile_id);
        push_field(&mut buf, &self.agent_id);
        push_field(&mut buf, &self.owner_principal_id);
        push_field(&mut buf, &self.display_name);
        push_field(&mut buf, &self.role);
        push_opt(&mut buf, self.archetype.as_ref());
        push_opt(&mut buf, self.avatar_ref.as_ref());
        push_opt(&mut buf, self.signature_symbol.as_ref());
        push_field(&mut buf, &self.languages.len().to_string());
        for lang in &self.languages {
            push_field(&mut buf, lang);
        }
        push_field(&mut buf, &self.generation.to_string());
        push_field(&mut buf, &self.constitution_digest);
        buf
    }

    /// Compute the content digest this profile's material currently implies.
    #[must_use]
    pub fn compute_content_digest(&self) -> String {
        content_digest(&self.canonical_bytes())
    }

    /// Re-seal the profile after a presentation change: recompute the content
    /// digest and stamp `updated_at`.
    ///
    /// This does NOT touch `agent_id`, `owner_principal_id`, or any grant, so a
    /// presentation change can never move the security principal (ATOM-SELF-003).
    pub fn reseal(&mut self) {
        self.updated_at = Utc::now();
        self.content_digest = self.compute_content_digest();
    }

    /// Change the display name through the typed API (ATOM-SELF-006).
    pub fn set_display_name(&mut self, display_name: String) {
        self.display_name = display_name;
        self.reseal();
    }

    /// Change the role through the typed API.
    pub fn set_role(&mut self, role: String) {
        self.role = role;
        self.reseal();
    }

    /// Change the avatar reference through the typed API.
    pub fn set_avatar_ref(&mut self, avatar_ref: Option<String>) {
        self.avatar_ref = avatar_ref;
        self.reseal();
    }

    /// Change the archetype through the typed API.
    pub fn set_archetype(&mut self, archetype: Option<String>) {
        self.archetype = archetype;
        self.reseal();
    }

    /// Change the signature symbol through the typed API.
    pub fn set_signature_symbol(&mut self, signature_symbol: Option<String>) {
        self.signature_symbol = signature_symbol;
        self.reseal();
    }

    /// Change the declared languages through the typed API.
    pub fn set_languages(&mut self, languages: Vec<String>) {
        self.languages = languages;
        self.reseal();
    }

    /// Verify the stored digest still matches this profile's own material.
    ///
    /// # Errors
    ///
    /// Returns [`AgentProfileError::DigestMismatch`] when the material was
    /// mutated without re-sealing, i.e. the profile is tampered.
    pub fn verify_self_digest(&self) -> Result<()> {
        let expected = self.compute_content_digest();
        if self.content_digest != expected {
            return Err(AgentProfileError::DigestMismatch {
                expected: self.content_digest.clone(),
                found: expected,
            });
        }
        Ok(())
    }

    /// Verify content digest matches externally supplied material.
    ///
    /// # Errors
    ///
    /// Returns [`AgentProfileError::DigestMismatch`] when `content` does not
    /// hash to the stored digest.
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
    ///
    /// # Errors
    ///
    /// Returns [`AgentProfileError::DigestMismatch`] on constitution drift,
    /// which the caller must escalate to STARTUP_BLOCKED (ATOM-SELF-025).
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
    /// Create a new soul profile in DRAFT state, sealed with its content digest.
    pub fn new(agent_id: String, owner_principal_id: String) -> Self {
        let now = Utc::now();
        let mut soul = Self {
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
        };
        soul.content_digest = soul.compute_content_digest();
        soul
    }

    /// Deterministic canonical byte encoding of the soul material.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = canonical_start(SOUL_DOMAIN);
        push_field(&mut buf, &self.soul_id);
        push_field(&mut buf, &self.agent_id);
        push_field(&mut buf, &self.values.len().to_string());
        for v in &self.values {
            push_field(&mut buf, v);
        }
        push_field(&mut buf, &self.voice);
        push_field(&mut buf, &self.tone);
        push_field(&mut buf, &self.epistemic_stance);
        push_field(&mut buf, &self.uncertainty_policy);
        push_field(&mut buf, &self.disagreement_policy);
        push_field(&mut buf, &self.autonomy_posture);
        push_field(&mut buf, &self.interaction_boundaries.len().to_string());
        for b in &self.interaction_boundaries {
            push_field(&mut buf, b);
        }
        push_field(&mut buf, &self.forbidden_behaviors.len().to_string());
        for b in &self.forbidden_behaviors {
            push_field(&mut buf, b);
        }
        push_field(&mut buf, &self.change_policy);
        push_field(&mut buf, &self.generation.to_string());
        buf
    }

    /// Compute the content digest this soul's material currently implies.
    #[must_use]
    pub fn compute_content_digest(&self) -> String {
        content_digest(&self.canonical_bytes())
    }

    /// Re-seal the soul after a style change: recompute digest, stamp `updated_at`.
    ///
    /// Soul material never carries operations, resources, or budget, so re-sealing
    /// can never widen authority (ATOM-SELF-001 / ATOM-SELF-024).
    pub fn reseal(&mut self) {
        self.updated_at = Utc::now();
        self.content_digest = self.compute_content_digest();
    }

    /// Change the voice through the typed API.
    pub fn set_voice(&mut self, voice: String) {
        self.voice = voice;
        self.reseal();
    }

    /// Change the tone through the typed API.
    pub fn set_tone(&mut self, tone: String) {
        self.tone = tone;
        self.reseal();
    }

    /// Change the declared values through the typed API.
    pub fn set_values(&mut self, values: Vec<String>) {
        self.values = values;
        self.reseal();
    }

    /// Change the interaction boundaries through the typed API.
    pub fn set_interaction_boundaries(&mut self, boundaries: Vec<String>) {
        self.interaction_boundaries = boundaries;
        self.reseal();
    }

    /// Verify the stored digest still matches this soul's own material.
    ///
    /// # Errors
    ///
    /// Returns [`AgentProfileError::DigestMismatch`] when the material was
    /// mutated without re-sealing — the caller must QUARANTINE (ATOM-SELF-011).
    pub fn verify_self_digest(&self) -> Result<()> {
        let expected = self.compute_content_digest();
        if self.content_digest != expected {
            return Err(AgentProfileError::DigestMismatch {
                expected: self.content_digest.clone(),
                found: expected,
            });
        }
        Ok(())
    }

    /// Verify content digest matches externally supplied material.
    ///
    /// # Errors
    ///
    /// Returns [`AgentProfileError::DigestMismatch`] when `content` does not
    /// hash to the stored digest.
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
