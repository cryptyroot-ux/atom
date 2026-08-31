//! Tamper-evident, append-only audit records for architecture-safety decisions.
//!
//! Every entry commits to the preceding entry hash, its monotonic sequence, and
//! all decision metadata under a domain-separated SHA-256 identity. A sealed
//! [`AuditCheckpoint`] additionally makes deletion or insertion after a known
//! head detectable. The chain is intentionally deterministic: callers supply
//! event data, and this module never reads a clock or generates a random ID.

use atom_artifact::ArtifactId;
use atom_claim::ClaimId;
use atom_policy::PolicyDecision;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// SHA-256 identity of an audit-chain entry.
pub type AuditHash = ArtifactId;

const AUDIT_DOMAIN: &str = "atom-architecture-safety/audit/v1";

/// The decision recorded by an audit event.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuditAction {
    /// An adaptive artifact entered the LAB ring.
    CandidateRegistered,
    /// An artifact advanced one evolution ring.
    Promotion,
    /// Regression restored a prior active artifact.
    Rollback,
    /// The learner-external safety contract admitted a candidate.
    SafetyAccepted,
    /// The learner-external safety contract rejected a candidate.
    SafetyRejected,
    /// A domain-specific audited action.
    Custom(String),
}

impl AuditAction {
    /// Canonical action name included in the chain hash.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::CandidateRegistered => "CANDIDATE_REGISTERED",
            Self::Promotion => "PROMOTION",
            Self::Rollback => "ROLLBACK",
            Self::SafetyAccepted => "SAFETY_ACCEPTED",
            Self::SafetyRejected => "SAFETY_REJECTED",
            Self::Custom(value) => value,
        }
    }
}

/// The normalized result of a policy evaluation included in an audit event.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuditPolicyOutcome {
    /// `atom-policy` allowed the action.
    Allowed,
    /// `atom-policy` denied the action.
    Denied,
    /// `atom-policy` requires a durable approval before allowing the action.
    ApprovalRequired,
}

impl From<&PolicyDecision> for AuditPolicyOutcome {
    fn from(value: &PolicyDecision) -> Self {
        match value {
            PolicyDecision::Allow(_) => Self::Allowed,
            PolicyDecision::Deny(_) => Self::Denied,
            PolicyDecision::RequireApproval(_) => Self::ApprovalRequired,
        }
    }
}

/// The content hashed into one architecture-safety audit entry.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuditEvent {
    action: AuditAction,
    detail: String,
    artifact_id: Option<ArtifactId>,
    claim_id: Option<ClaimId>,
    policy_outcome: Option<AuditPolicyOutcome>,
}

impl AuditEvent {
    /// Creates an audit event with a non-empty human/auditor-readable detail.
    ///
    /// # Errors
    ///
    /// Returns [`AuditError`] if the action or detail is blank.
    pub fn new(action: AuditAction, detail: impl Into<String>) -> Result<Self, AuditError> {
        let event = Self {
            action,
            detail: detail.into(),
            artifact_id: None,
            claim_id: None,
            policy_outcome: None,
        };
        event.validate()?;
        Ok(event)
    }

    /// Binds a content-addressed artifact to this event.
    #[must_use]
    pub fn with_artifact(mut self, artifact_id: ArtifactId) -> Self {
        self.artifact_id = Some(artifact_id);
        self
    }

    /// Binds an evidence/evaluation claim to this event.
    #[must_use]
    pub fn with_claim(mut self, claim_id: ClaimId) -> Self {
        self.claim_id = Some(claim_id);
        self
    }

    /// Records a normalized `atom-policy` decision alongside the event.
    #[must_use]
    pub fn with_policy_decision(mut self, decision: &PolicyDecision) -> Self {
        self.policy_outcome = Some(AuditPolicyOutcome::from(decision));
        self
    }

    /// Action named by the event.
    #[must_use]
    pub fn action(&self) -> &AuditAction {
        &self.action
    }

    /// Immutable descriptive detail committed by the entry hash.
    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }

    /// Artifact associated with the event, if any.
    #[must_use]
    pub fn artifact_id(&self) -> Option<&ArtifactId> {
        self.artifact_id.as_ref()
    }

    /// Claim associated with the event, if any.
    #[must_use]
    pub fn claim_id(&self) -> Option<&ClaimId> {
        self.claim_id.as_ref()
    }

    /// Policy outcome recorded with the event, if any.
    #[must_use]
    pub const fn policy_outcome(&self) -> Option<AuditPolicyOutcome> {
        self.policy_outcome
    }

    fn validate(&self) -> Result<(), AuditError> {
        if self.action.as_str().trim().is_empty() {
            return Err(AuditError::BlankAction);
        }
        if self.detail.trim().is_empty() {
            return Err(AuditError::BlankDetail);
        }
        Ok(())
    }
}

/// An append-only audit record whose hash commits to its predecessor and event.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuditEntry {
    sequence: u64,
    previous_hash: AuditHash,
    event: AuditEvent,
    hash: AuditHash,
}

impl AuditEntry {
    /// One-based, contiguous sequence number.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Hash of the preceding entry (or the fixed genesis hash for sequence 1).
    #[must_use]
    pub fn previous_hash(&self) -> &AuditHash {
        &self.previous_hash
    }

    /// Immutable event data committed by this entry.
    #[must_use]
    pub fn event(&self) -> &AuditEvent {
        &self.event
    }

    /// Domain-separated SHA-256 hash of this record.
    #[must_use]
    pub fn hash(&self) -> &AuditHash {
        &self.hash
    }
}

/// A known sealed audit head.
///
/// Store this value outside the mutable audit-log storage (for example in a
/// signed artifact, ledger checkpoint, or operator-controlled evidence store)
/// to make tail deletion or replacement detectable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditCheckpoint {
    entry_count: u64,
    head_hash: AuditHash,
}

impl AuditCheckpoint {
    /// Number of entries committed by the checkpoint.
    #[must_use]
    pub const fn entry_count(&self) -> u64 {
        self.entry_count
    }

    /// Exact chain head committed by the checkpoint.
    #[must_use]
    pub fn head_hash(&self) -> &AuditHash {
        &self.head_hash
    }
}

/// Successful audit-chain verification information.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditVerification {
    entry_count: u64,
    head_hash: AuditHash,
}

impl AuditVerification {
    /// Number of contiguous, verified entries.
    #[must_use]
    pub const fn entry_count(&self) -> u64 {
        self.entry_count
    }

    /// Verified hash-chain head.
    #[must_use]
    pub fn head_hash(&self) -> &AuditHash {
        &self.head_hash
    }
}

/// Deterministic in-memory projection of an append-only architecture audit log.
///
/// Persist its [`AuditEntry`] values and reload them with
/// [`Self::from_entries`], which verifies before accepting them. Mutating a
/// serialized record without recalculating every successor hash is detected by
/// [`Self::verify`]; [`AuditCheckpoint`] also detects truncation relative to a
/// separately retained known head.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditLog {
    genesis_hash: AuditHash,
    entries: Vec<AuditEntry>,
}

impl Default for AuditLog {
    fn default() -> Self {
        Self {
            genesis_hash: genesis_hash(),
            entries: Vec::new(),
        }
    }
}

impl AuditLog {
    /// Creates an empty audit chain at its fixed, domain-separated genesis.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Verifies persisted entries before accepting them as this log's state.
    ///
    /// # Errors
    ///
    /// Returns [`AuditError`] if a sequence, predecessor pointer, event, or
    /// hash has been tampered with.
    pub fn from_entries(entries: Vec<AuditEntry>) -> Result<Self, AuditError> {
        let log = Self {
            genesis_hash: genesis_hash(),
            entries,
        };
        log.verify()?;
        Ok(log)
    }

    /// Immutable entries in sequence order.
    #[must_use]
    pub fn entries(&self) -> &[AuditEntry] {
        &self.entries
    }

    /// Current chain head, or the fixed genesis hash for an empty log.
    #[must_use]
    pub fn head_hash(&self) -> &AuditHash {
        self.entries
            .last()
            .map(AuditEntry::hash)
            .unwrap_or(&self.genesis_hash)
    }

    /// Appends a validated decision event and returns the immutable entry.
    ///
    /// # Errors
    ///
    /// Returns [`AuditError`] for malformed event data or an unrepresentable
    /// sequence number. Existing records are not modified on error.
    pub fn append(&mut self, event: AuditEvent) -> Result<AuditEntry, AuditError> {
        event.validate()?;
        let sequence = u64::try_from(self.entries.len())
            .ok()
            .and_then(|length| length.checked_add(1))
            .ok_or(AuditError::SequenceOverflow)?;
        let previous_hash = self.head_hash().clone();
        let hash = entry_hash(sequence, &previous_hash, &event);
        let entry = AuditEntry {
            sequence,
            previous_hash,
            event,
            hash,
        };
        self.entries.push(entry.clone());
        Ok(entry)
    }

    /// Captures the current known head for external/separate retention.
    #[must_use]
    pub fn checkpoint(&self) -> AuditCheckpoint {
        AuditCheckpoint {
            entry_count: u64::try_from(self.entries.len()).unwrap_or(u64::MAX),
            head_hash: self.head_hash().clone(),
        }
    }

    /// Verifies every event hash and predecessor link.
    ///
    /// # Errors
    ///
    /// Returns [`AuditError`] identifying the first invalid entry.
    pub fn verify(&self) -> Result<AuditVerification, AuditError> {
        let mut previous_hash = self.genesis_hash.clone();
        for (index, entry) in self.entries.iter().enumerate() {
            let expected_sequence = u64::try_from(index)
                .ok()
                .and_then(|value| value.checked_add(1))
                .ok_or(AuditError::SequenceOverflow)?;
            if entry.sequence != expected_sequence {
                return Err(AuditError::SequenceMismatch {
                    expected: expected_sequence,
                    observed: entry.sequence,
                });
            }
            entry.event.validate()?;
            if entry.previous_hash != previous_hash {
                return Err(AuditError::PreviousHashMismatch {
                    sequence: entry.sequence,
                    expected: previous_hash,
                    observed: entry.previous_hash.clone(),
                });
            }
            let expected_hash = entry_hash(entry.sequence, &entry.previous_hash, &entry.event);
            if entry.hash != expected_hash {
                return Err(AuditError::HashMismatch {
                    sequence: entry.sequence,
                    expected: expected_hash,
                    observed: entry.hash.clone(),
                });
            }
            previous_hash = entry.hash.clone();
        }
        Ok(AuditVerification {
            entry_count: u64::try_from(self.entries.len()).unwrap_or(u64::MAX),
            head_hash: previous_hash,
        })
    }

    /// Verifies this log and checks it is exactly the separately retained head.
    ///
    /// # Errors
    ///
    /// Returns [`AuditError::CheckpointMismatch`] if records were deleted,
    /// added, or replaced relative to `checkpoint`.
    pub fn verify_checkpoint(
        &self,
        checkpoint: &AuditCheckpoint,
    ) -> Result<AuditVerification, AuditError> {
        let verification = self.verify()?;
        if verification.entry_count != checkpoint.entry_count
            || verification.head_hash != checkpoint.head_hash
        {
            return Err(AuditError::CheckpointMismatch {
                expected_count: checkpoint.entry_count,
                observed_count: verification.entry_count,
                expected_head: checkpoint.head_hash.clone(),
                observed_head: verification.head_hash,
            });
        }
        Ok(verification)
    }
}

/// Audit-chain construction or verification failure.
#[derive(Clone, Debug, Error, PartialEq)]
pub enum AuditError {
    /// An event's action name was blank.
    #[error("audit action must not be blank")]
    BlankAction,
    /// An event's human/auditor-readable detail was blank.
    #[error("audit event detail must not be blank")]
    BlankDetail,
    /// More entries exist than a `u64` sequence can represent.
    #[error("audit sequence overflow")]
    SequenceOverflow,
    /// A persisted record was deleted, inserted, or reordered.
    #[error("audit sequence mismatch: expected {expected}, observed {observed}")]
    SequenceMismatch {
        /// Expected one-based sequence.
        expected: u64,
        /// Stored sequence.
        observed: u64,
    },
    /// A record does not point at the exact preceding hash.
    #[error("audit previous hash mismatch at sequence {sequence}")]
    PreviousHashMismatch {
        /// Invalid record sequence.
        sequence: u64,
        /// Hash required by the prior valid record.
        expected: AuditHash,
        /// Stored predecessor hash.
        observed: AuditHash,
    },
    /// A record's stored hash does not commit to its actual contents.
    #[error("audit hash mismatch at sequence {sequence}")]
    HashMismatch {
        /// Invalid record sequence.
        sequence: u64,
        /// Hash recomputed from the record.
        expected: AuditHash,
        /// Stored hash.
        observed: AuditHash,
    },
    /// This log does not match a separately held chain checkpoint.
    #[error(
        "audit checkpoint mismatch: expected {expected_count} entries at {expected_head}, observed {observed_count} at {observed_head}"
    )]
    CheckpointMismatch {
        /// Expected number of entries.
        expected_count: u64,
        /// Actual number of entries.
        observed_count: u64,
        /// Expected sealed head.
        expected_head: AuditHash,
        /// Actual verified head.
        observed_head: AuditHash,
    },
}

fn genesis_hash() -> AuditHash {
    hash_parts(&[AUDIT_DOMAIN.as_bytes(), b"genesis"])
}

fn entry_hash(sequence: u64, previous_hash: &AuditHash, event: &AuditEvent) -> AuditHash {
    let sequence = sequence.to_be_bytes();
    let artifact = event
        .artifact_id
        .as_ref()
        .map_or_else(Vec::new, |id| id.as_str().as_bytes().to_vec());
    let claim = event
        .claim_id
        .as_ref()
        .map_or_else(Vec::new, |id| id.as_str().as_bytes().to_vec());
    let policy = event
        .policy_outcome
        .map_or_else(Vec::new, |outcome| match outcome {
            AuditPolicyOutcome::Allowed => b"ALLOWED".to_vec(),
            AuditPolicyOutcome::Denied => b"DENIED".to_vec(),
            AuditPolicyOutcome::ApprovalRequired => b"APPROVAL_REQUIRED".to_vec(),
        });
    hash_parts(&[
        AUDIT_DOMAIN.as_bytes(),
        b"entry",
        &sequence,
        previous_hash.as_str().as_bytes(),
        event.action.as_str().as_bytes(),
        event.detail.as_bytes(),
        &artifact,
        &claim,
        &policy,
    ])
}

/// Domain-separated SHA-256 over unambiguous, length-prefixed components.
fn hash_parts(parts: &[&[u8]]) -> AuditHash {
    let mut encoded = Vec::new();
    for part in parts {
        let length = u64::try_from(part.len()).unwrap_or(u64::MAX);
        encoded.extend_from_slice(&length.to_be_bytes());
        encoded.extend_from_slice(part);
    }
    ArtifactId::of(&encoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(action: AuditAction, detail: &str) -> AuditEvent {
        AuditEvent::new(action, detail).expect("valid audit event")
    }

    #[test]
    fn chain_verifies_and_checkpoint_captures_head() {
        let mut log = AuditLog::new();
        log.append(event(
            AuditAction::CandidateRegistered,
            "candidate is in LAB",
        ))
        .expect("append candidate");
        log.append(event(AuditAction::Promotion, "LAB to SIMULATION"))
            .expect("append promotion");

        let checkpoint = log.checkpoint();
        let report = log.verify_checkpoint(&checkpoint).expect("intact chain");
        assert_eq!(report.entry_count(), 2);
        assert_eq!(report.head_hash(), checkpoint.head_hash());
    }

    #[test]
    fn edited_event_breaks_its_hash() {
        let mut log = AuditLog::new();
        log.append(event(AuditAction::Promotion, "LAB to SIMULATION"))
            .expect("append promotion");
        log.entries[0].event.detail = "LAB to ACTIVE".to_owned();

        assert!(matches!(log.verify(), Err(AuditError::HashMismatch { .. })));
    }

    #[test]
    fn checkpoint_detects_tail_truncation() {
        let mut log = AuditLog::new();
        log.append(event(
            AuditAction::CandidateRegistered,
            "candidate is in LAB",
        ))
        .expect("append candidate");
        log.append(event(AuditAction::Promotion, "LAB to SIMULATION"))
            .expect("append promotion");
        let checkpoint = log.checkpoint();
        log.entries.pop();

        assert!(matches!(
            log.verify_checkpoint(&checkpoint),
            Err(AuditError::CheckpointMismatch { .. })
        ));
    }

    #[test]
    fn policy_outcome_is_normalized_not_a_free_form_claim() {
        let event = event(AuditAction::SafetyAccepted, "approved")
            .with_policy_decision(&PolicyDecision::Allow("grant-1".to_owned()));
        assert_eq!(event.policy_outcome(), Some(AuditPolicyOutcome::Allowed));
    }
}
