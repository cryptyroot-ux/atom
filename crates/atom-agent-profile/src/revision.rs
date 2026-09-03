use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::types::{content_digest, AgentProfileError, ChangeType, Result, RevisionState};

/// AgentSelfRevision — versioned, auditable self-change.
///
/// Lifecycle: DRAFT → PROPOSED → PENDING_AUTHORIZATION → ACTIVE → SUPERSEDED/REVOKED/ROLLED_BACK
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentSelfRevision {
    pub revision_id: String,
    pub profile_id: String,
    pub change_type: ChangeType,
    pub proposal: serde_json::Value,
    pub state: RevisionState,
    pub generation: u64,
    pub content_digest: String,
    pub created_at: DateTime<Utc>,
    pub proposed_by: String,
    pub authorized_by: Option<String>,
}

impl AgentSelfRevision {
    /// Create a new revision in DRAFT state.
    pub fn new(
        profile_id: String,
        change_type: ChangeType,
        proposal: serde_json::Value,
        proposed_by: String,
    ) -> Self {
        let now = Utc::now();
        Self {
            revision_id: uuid::Uuid::new_v4().to_string(),
            profile_id,
            change_type,
            proposal,
            state: RevisionState::Draft,
            generation: 0,
            content_digest: String::new(),
            created_at: now,
            proposed_by,
            authorized_by: None,
        }
    }

    /// Propose the revision (DRAFT → PROPOSED).
    pub fn propose(&mut self) -> Result<()> {
        if !matches!(self.state, RevisionState::Draft) {
            return Err(AgentProfileError::InvalidStateTransition {
                from: format!("{:?}", self.state),
                to: "PROPOSED".to_string(),
            });
        }
        self.state = RevisionState::Proposed;
        Ok(())
    }

    /// Request authorization (PROPOSED → PENDING_AUTHORIZATION).
    pub fn request_authorization(&mut self) -> Result<()> {
        if !matches!(self.state, RevisionState::Proposed) {
            return Err(AgentProfileError::InvalidStateTransition {
                from: format!("{:?}", self.state),
                to: "PENDING_AUTHORIZATION".to_string(),
            });
        }
        self.state = RevisionState::PendingAuthorization;
        Ok(())
    }

    /// Authorize and activate (PENDING_AUTHORIZATION → ACTIVE).
    ///
    /// Constitutional constraint (ATOM-SELF-004): Self-approval is forbidden.
    pub fn authorize(&mut self, authorized_by: String) -> Result<()> {
        if !matches!(self.state, RevisionState::PendingAuthorization) {
            return Err(AgentProfileError::InvalidStateTransition {
                from: format!("{:?}", self.state),
                to: "ACTIVE".to_string(),
            });
        }
        // Self-approval check
        if authorized_by == self.proposed_by {
            return Err(AgentProfileError::SelfApprovalForbidden);
        }
        self.authorized_by = Some(authorized_by);
        self.state = RevisionState::Active;
        self.generation += 1;
        Ok(())
    }

    /// Quarantine the revision.
    pub fn quarantine(reason: &str) -> Self {
        let now = Utc::now();
        Self {
            revision_id: uuid::Uuid::new_v4().to_string(),
            profile_id: String::new(),
            change_type: ChangeType::Identity,
            proposal: serde_json::Value::Null,
            state: RevisionState::Quarantined,
            generation: 0,
            content_digest: String::new(),
            created_at: now,
            proposed_by: String::new(),
            authorized_by: None,
        }
    }

    /// Supersede the revision.
    pub fn supersede(&mut self) -> Result<()> {
        if !matches!(self.state, RevisionState::Active) {
            return Err(AgentProfileError::InvalidStateTransition {
                from: format!("{:?}", self.state),
                to: "SUPERSEDED".to_string(),
            });
        }
        self.state = RevisionState::Superseded;
        Ok(())
    }

    /// Rollback the revision.
    pub fn rollback(&mut self) -> Result<()> {
        if !matches!(self.state, RevisionState::Active) {
            return Err(AgentProfileError::InvalidStateTransition {
                from: format!("{:?}", self.state),
                to: "ROLLED_BACK".to_string(),
            });
        }
        self.state = RevisionState::RolledBack;
        Ok(())
    }
}
