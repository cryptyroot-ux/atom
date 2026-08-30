//! Typed claims, bitemporal visibility, and provenance DAGs.
//!
//! The authoritative Claim wire shape is embedded from
//! `spec/schemas/claim.schema.json`; this crate adds typed internals without
//! adding a field to that schema-owned shape.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;

pub use atom_evidence::{
    derive, validate_metadata, DerivationError, DerivedMetadata, Evidence, EvidenceError,
    EvidenceId, JsonObject, MetadataError, ProvenanceRef, RecordId, Sensitivity, SourceAuthority,
    TaintCarrier, TaintLabel, TaintLabels, VerifierLevel,
};

/// The byte-for-byte authoritative Claim schema.
pub const CLAIM_SCHEMA: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../spec/schemas/claim.schema.json"
));

/// Claim identifier; it retains the schema's string wire representation.
pub type ClaimId = RecordId;
/// Typed proposition object. Its domain fields intentionally remain open.
pub type Proposition = JsonObject;
/// Typed retrieval-policy object. Eligibility semantics live in atom-context/policy.
pub type RetrievalPolicy = JsonObject;
/// Typed retention-policy object. Retention enforcement is not owned by this crate.
pub type RetentionPolicy = JsonObject;

/// Evidential weight in the inclusive range `0..=1`.
///
/// This is intentionally not interchangeable with [`SourceAuthority`].
#[derive(Clone, Copy, Debug, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Confidence(f64);

impl Confidence {
    /// Creates a valid confidence value.
    ///
    /// # Errors
    ///
    /// Returns [`ConfidenceError`] for a non-finite number or a value outside
    /// the schema's inclusive `0..=1` range.
    pub fn new(value: f64) -> Result<Self, ConfidenceError> {
        if !value.is_finite() || !(0.0..=1.0).contains(&value) {
            return Err(ConfidenceError::OutOfRange { value });
        }
        Ok(Self(value))
    }

    /// Returns the numeric evidential weight.
    #[must_use]
    pub const fn value(self) -> f64 {
        self.0
    }
}

impl TryFrom<f64> for Confidence {
    type Error = ConfidenceError;

    fn try_from(value: f64) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl<'de> Deserialize<'de> for Confidence {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(f64::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

/// Error returned for a confidence value outside the schema range.
#[derive(Clone, Debug, Error, PartialEq)]
pub enum ConfidenceError {
    /// A confidence must be finite and in the schema's inclusive range.
    #[error("confidence must be a finite number in 0..=1, got {value}")]
    OutOfRange {
        /// Rejected value.
        value: f64,
    },
}

/// A half-open temporal interval: `[from, to)`, with `None` meaning open-ended.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TimeInterval {
    from: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    to: Option<DateTime<Utc>>,
}

impl TimeInterval {
    /// Creates a valid interval.
    ///
    /// # Errors
    ///
    /// Returns [`TimeIntervalError`] if the end is not strictly after the start.
    pub fn new(from: DateTime<Utc>, to: Option<DateTime<Utc>>) -> Result<Self, TimeIntervalError> {
        if let Some(to) = to.as_ref() {
            if to <= &from {
                return Err(TimeIntervalError::NonIncreasing { from, to: *to });
            }
        }
        Ok(Self { from, to })
    }

    /// Creates an open-ended interval.
    #[must_use]
    pub fn open(from: DateTime<Utc>) -> Self {
        Self { from, to: None }
    }

    /// Start of the interval (inclusive).
    #[must_use]
    pub fn from(&self) -> &DateTime<Utc> {
        &self.from
    }

    /// End of the interval (exclusive), if it is closed.
    #[must_use]
    pub fn to(&self) -> Option<&DateTime<Utc>> {
        self.to.as_ref()
    }

    /// Whether `instant` belongs to this interval.
    #[must_use]
    pub fn contains(&self, instant: DateTime<Utc>) -> bool {
        if instant < self.from {
            return false;
        }
        match self.to.as_ref() {
            Some(to) => instant < *to,
            None => true,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TimeIntervalWire {
    from: DateTime<Utc>,
    #[serde(default)]
    to: Option<DateTime<Utc>>,
}

impl<'de> Deserialize<'de> for TimeInterval {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = TimeIntervalWire::deserialize(deserializer)?;
        Self::new(wire.from, wire.to).map_err(D::Error::custom)
    }
}

/// Error returned for an invalid bitemporal interval.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum TimeIntervalError {
    /// A closed interval must have an end later than its start.
    #[error("time interval end {to} must be later than start {from}")]
    NonIncreasing {
        /// Interval start.
        from: DateTime<Utc>,
        /// Rejected end.
        to: DateTime<Utc>,
    },
}

/// Canonical claim kinds from `spec/enums.yaml`.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ClaimKind {
    Observation,
    Fact,
    Belief,
    Hypothesis,
    Prediction,
    Preference,
    Policy,
    Procedure,
    Commitment,
    Inference,
}

impl ClaimKind {
    /// Every kind in exact `spec/enums.yaml` order.
    pub const ALL: [Self; 10] = [
        Self::Observation,
        Self::Fact,
        Self::Belief,
        Self::Hypothesis,
        Self::Prediction,
        Self::Preference,
        Self::Policy,
        Self::Procedure,
        Self::Commitment,
        Self::Inference,
    ];

    /// Canonical wire representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Observation => "OBSERVATION",
            Self::Fact => "FACT",
            Self::Belief => "BELIEF",
            Self::Hypothesis => "HYPOTHESIS",
            Self::Prediction => "PREDICTION",
            Self::Preference => "PREFERENCE",
            Self::Policy => "POLICY",
            Self::Procedure => "PROCEDURE",
            Self::Commitment => "COMMITMENT",
            Self::Inference => "INFERENCE",
        }
    }
}

/// Canonical claim states from `spec/enums.yaml`.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ClaimState {
    Proposed,
    Supported,
    Disputed,
    Corroborated,
    Superseded,
    Retracted,
    Expired,
}

impl ClaimState {
    /// Every state in exact `spec/enums.yaml` order.
    pub const ALL: [Self; 7] = [
        Self::Proposed,
        Self::Supported,
        Self::Disputed,
        Self::Corroborated,
        Self::Superseded,
        Self::Retracted,
        Self::Expired,
    ];

    /// Canonical wire representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "PROPOSED",
            Self::Supported => "SUPPORTED",
            Self::Disputed => "DISPUTED",
            Self::Corroborated => "CORROBORATED",
            Self::Superseded => "SUPERSEDED",
            Self::Retracted => "RETRACTED",
            Self::Expired => "EXPIRED",
        }
    }

    /// Legal next states for the alpha lifecycle.
    ///
    /// The transition sequence is deliberately narrow: the normative task
    /// defines `PROPOSED -> SUPPORTED -> CORROBORATED / DISPUTED /
    /// SUPERSEDED / RETRACTED / EXPIRED`. Terminal states are retained, never
    /// deleted or rewritten out of lineage.
    #[must_use]
    pub const fn allowed_transitions(self) -> &'static [Self] {
        match self {
            Self::Proposed => &[Self::Supported],
            Self::Supported => &[
                Self::Corroborated,
                Self::Disputed,
                Self::Superseded,
                Self::Retracted,
                Self::Expired,
            ],
            Self::Disputed
            | Self::Corroborated
            | Self::Superseded
            | Self::Retracted
            | Self::Expired => &[],
        }
    }

    /// Whether `self -> target` is legal.
    #[must_use]
    pub fn can_transition_to(self, target: Self) -> bool {
        self.allowed_transitions().contains(&target)
    }

    /// Whether no further lifecycle transition exists.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        self.allowed_transitions().is_empty()
    }
}

/// An event consumed by the pure claim-state reducer.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ClaimEvent {
    Supported,
    Corroborated,
    Disputed,
    Superseded,
    Retracted,
    Expired,
}

impl ClaimEvent {
    /// Target state represented by this event.
    #[must_use]
    pub const fn target_state(self) -> ClaimState {
        match self {
            Self::Supported => ClaimState::Supported,
            Self::Corroborated => ClaimState::Corroborated,
            Self::Disputed => ClaimState::Disputed,
            Self::Superseded => ClaimState::Superseded,
            Self::Retracted => ClaimState::Retracted,
            Self::Expired => ClaimState::Expired,
        }
    }
}

/// Rejects an event that does not follow the alpha claim lifecycle.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("claim state {current:?} cannot transition to {target:?}")]
pub struct ClaimTransitionError {
    /// State before reduction.
    pub current: ClaimState,
    /// Requested state.
    pub target: ClaimState,
}

/// Applies one claim event without mutating a record.
///
/// # Errors
///
/// Returns [`ClaimTransitionError`] for a non-legal state edge.
pub fn reduce(current: ClaimState, event: ClaimEvent) -> Result<ClaimState, ClaimTransitionError> {
    let target = event.target_state();
    if current.can_transition_to(target) {
        Ok(target)
    } else {
        Err(ClaimTransitionError { current, target })
    }
}

/// Alias for callers that use `try_*` naming for fallible pure reducers.
///
/// # Errors
///
/// Returns [`ClaimTransitionError`] for a non-legal state edge.
pub fn try_reduce(
    current: ClaimState,
    event: ClaimEvent,
) -> Result<ClaimState, ClaimTransitionError> {
    reduce(current, event)
}

/// A schema-conformant typed Claim record.
///
/// The field declaration order is the authoritative schema order. Optional
/// policy fields are omitted rather than serialized as `null`, because the
/// schema defines them as objects when present.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Claim {
    claim_id: ClaimId,
    kind: ClaimKind,
    state: ClaimState,
    proposition: Proposition,
    confidence: Confidence,
    source_authority: SourceAuthority,
    valid_time: TimeInterval,
    transaction_time: TimeInterval,
    provenance: Vec<ProvenanceRef>,
    evidence_refs: Vec<EvidenceId>,
    supersedes: Vec<ClaimId>,
    contradicts: Vec<ClaimId>,
    taint_labels: TaintLabels,
    #[serde(skip_serializing_if = "Option::is_none")]
    retrieval_policy: Option<RetrievalPolicy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    retention_policy: Option<RetentionPolicy>,
}

impl Claim {
    /// Starts construction of a claim in the `PROPOSED` state.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn builder(
        claim_id: impl Into<ClaimId>,
        kind: ClaimKind,
        proposition: Proposition,
        confidence: Confidence,
        source_authority: SourceAuthority,
        valid_time: TimeInterval,
        transaction_time: TimeInterval,
    ) -> ClaimBuilder {
        ClaimBuilder {
            claim_id: claim_id.into(),
            kind,
            state: ClaimState::Proposed,
            proposition,
            confidence,
            source_authority,
            valid_time,
            transaction_time,
            provenance: Vec::new(),
            evidence_refs: Vec::new(),
            supersedes: Vec::new(),
            contradicts: Vec::new(),
            taint_labels: TaintLabels::default(),
            retrieval_policy: None,
            retention_policy: None,
        }
    }

    /// Creates a Claim with the schema-required fields and empty optional edges.
    ///
    /// # Errors
    ///
    /// Returns [`ClaimError`] if its taint and authority are inconsistent.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        claim_id: impl Into<ClaimId>,
        kind: ClaimKind,
        state: ClaimState,
        proposition: Proposition,
        confidence: Confidence,
        source_authority: SourceAuthority,
        valid_time: TimeInterval,
        transaction_time: TimeInterval,
        provenance: Vec<ProvenanceRef>,
        taint_labels: TaintLabels,
    ) -> Result<Self, ClaimError> {
        Self::from_parts(
            claim_id.into(),
            kind,
            state,
            proposition,
            confidence,
            source_authority,
            valid_time,
            transaction_time,
            provenance,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            taint_labels,
            None,
            None,
        )
    }

    /// Creates a proposed Claim from transformed inputs using monotonic taint
    /// union and the minimum input authority.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty input collection or invalid metadata.
    #[allow(clippy::too_many_arguments)]
    pub fn derived<I>(
        claim_id: impl Into<ClaimId>,
        kind: ClaimKind,
        proposition: Proposition,
        confidence: Confidence,
        valid_time: TimeInterval,
        transaction_time: TimeInterval,
        provenance: Vec<ProvenanceRef>,
        inputs: I,
    ) -> Result<Self, ClaimDerivationError>
    where
        I: IntoIterator,
        I::Item: TaintCarrier,
    {
        let metadata = derive(inputs)?;
        Ok(Self::builder(
            claim_id,
            kind,
            proposition,
            confidence,
            metadata.source_authority(),
            valid_time,
            transaction_time,
        )
        .provenance(provenance)
        .taint_labels(metadata.taint_labels().clone())
        .build()?)
    }

    #[allow(clippy::too_many_arguments)]
    fn from_parts(
        claim_id: ClaimId,
        kind: ClaimKind,
        state: ClaimState,
        proposition: Proposition,
        confidence: Confidence,
        source_authority: SourceAuthority,
        valid_time: TimeInterval,
        transaction_time: TimeInterval,
        provenance: Vec<ProvenanceRef>,
        evidence_refs: Vec<EvidenceId>,
        supersedes: Vec<ClaimId>,
        contradicts: Vec<ClaimId>,
        taint_labels: TaintLabels,
        retrieval_policy: Option<RetrievalPolicy>,
        retention_policy: Option<RetentionPolicy>,
    ) -> Result<Self, ClaimError> {
        validate_metadata(source_authority, &taint_labels)?;
        if contradicts.iter().any(|other| other == &claim_id) {
            return Err(ClaimError::SelfContradiction);
        }
        Ok(Self {
            claim_id,
            kind,
            state,
            proposition,
            confidence,
            source_authority,
            valid_time,
            transaction_time,
            provenance,
            evidence_refs,
            supersedes,
            contradicts,
            taint_labels,
            retrieval_policy,
            retention_policy,
        })
    }

    /// Claim identifier.
    #[must_use]
    pub fn claim_id(&self) -> &ClaimId {
        &self.claim_id
    }

    /// Claim kind.
    #[must_use]
    pub const fn kind(&self) -> ClaimKind {
        self.kind
    }

    /// Current lifecycle state.
    #[must_use]
    pub const fn state(&self) -> ClaimState {
        self.state
    }

    /// Typed proposition object.
    #[must_use]
    pub fn proposition(&self) -> &Proposition {
        &self.proposition
    }

    /// Evidential confidence, intentionally distinct from source authority.
    #[must_use]
    pub const fn confidence(&self) -> Confidence {
        self.confidence
    }

    /// Source authority.
    #[must_use]
    pub const fn source_authority(&self) -> SourceAuthority {
        self.source_authority
    }

    /// Interval during which the proposition is valid in the represented world.
    #[must_use]
    pub fn valid_time(&self) -> &TimeInterval {
        &self.valid_time
    }

    /// Interval during which this version was known to the system.
    #[must_use]
    pub fn transaction_time(&self) -> &TimeInterval {
        &self.transaction_time
    }

    /// Provenance parents (Claim or Evidence identifiers).
    #[must_use]
    pub fn provenance(&self) -> &[ProvenanceRef] {
        &self.provenance
    }

    /// Evidence records directly cited by this claim.
    #[must_use]
    pub fn evidence_refs(&self) -> &[EvidenceId] {
        &self.evidence_refs
    }

    /// Claims superseded by this version.
    #[must_use]
    pub fn supersedes(&self) -> &[ClaimId] {
        &self.supersedes
    }

    /// Claims contradicted by this claim. The targets remain present in lineage.
    #[must_use]
    pub fn contradicts(&self) -> &[ClaimId] {
        &self.contradicts
    }

    /// Taint carried by the claim.
    #[must_use]
    pub fn taint_labels(&self) -> &TaintLabels {
        &self.taint_labels
    }

    /// Optional downstream retrieval policy data.
    #[must_use]
    pub fn retrieval_policy(&self) -> Option<&RetrievalPolicy> {
        self.retrieval_policy.as_ref()
    }

    /// Optional downstream retention policy data.
    #[must_use]
    pub fn retention_policy(&self) -> Option<&RetentionPolicy> {
        self.retention_policy.as_ref()
    }

    /// Applies a state event purely, retaining all lineage and contradiction edges.
    ///
    /// # Errors
    ///
    /// Returns [`ClaimTransitionError`] for a non-legal transition.
    pub fn transitioned(&self, event: ClaimEvent) -> Result<Self, ClaimTransitionError> {
        let mut next = self.clone();
        next.state = reduce(self.state, event)?;
        Ok(next)
    }

    /// Adds a contradiction edge without deleting or changing either claim.
    ///
    /// # Errors
    ///
    /// Returns [`ClaimError::SelfContradiction`] when the target is this claim.
    pub fn with_contradiction(mut self, other: impl Into<ClaimId>) -> Result<Self, ClaimError> {
        let other = other.into();
        if other == self.claim_id {
            return Err(ClaimError::SelfContradiction);
        }
        if !self.contradicts.contains(&other) {
            self.contradicts.push(other);
        }
        Ok(self)
    }

    /// Whether this version is visible at the supplied bitemporal cut.
    #[must_use]
    pub fn is_visible_as_of(&self, valid_at: DateTime<Utc>, transaction_at: DateTime<Utc>) -> bool {
        self.valid_time.contains(valid_at) && self.transaction_time.contains(transaction_at)
    }

    /// Whether this claim's taint requires a separate policy authorization
    /// before it can participate in effect eligibility.
    #[must_use]
    pub fn blocks_unauthorized_effect_eligibility(&self) -> bool {
        self.taint_labels.blocks_unauthorized_effect_eligibility()
    }
}

impl TaintCarrier for Claim {
    fn source_authority(&self) -> SourceAuthority {
        self.source_authority
    }

    fn taint_labels(&self) -> &TaintLabels {
        &self.taint_labels
    }
}

/// Fluent constructor for [`Claim`].
#[derive(Clone, Debug)]
pub struct ClaimBuilder {
    claim_id: ClaimId,
    kind: ClaimKind,
    state: ClaimState,
    proposition: Proposition,
    confidence: Confidence,
    source_authority: SourceAuthority,
    valid_time: TimeInterval,
    transaction_time: TimeInterval,
    provenance: Vec<ProvenanceRef>,
    evidence_refs: Vec<EvidenceId>,
    supersedes: Vec<ClaimId>,
    contradicts: Vec<ClaimId>,
    taint_labels: TaintLabels,
    retrieval_policy: Option<RetrievalPolicy>,
    retention_policy: Option<RetentionPolicy>,
}

impl ClaimBuilder {
    /// Sets the lifecycle state. Defaults to `PROPOSED`.
    #[must_use]
    pub fn state(mut self, state: ClaimState) -> Self {
        self.state = state;
        self
    }

    /// Sets Claim/Evidence provenance parents.
    #[must_use]
    pub fn provenance(mut self, provenance: Vec<ProvenanceRef>) -> Self {
        self.provenance = provenance;
        self
    }

    /// Adds one provenance parent.
    #[must_use]
    pub fn add_provenance(mut self, parent: impl Into<ProvenanceRef>) -> Self {
        self.provenance.push(parent.into());
        self
    }

    /// Sets directly cited evidence identifiers.
    #[must_use]
    pub fn evidence_refs(mut self, evidence_refs: Vec<EvidenceId>) -> Self {
        self.evidence_refs = evidence_refs;
        self
    }

    /// Adds one directly cited evidence identifier.
    #[must_use]
    pub fn add_evidence_ref(mut self, evidence_id: impl Into<EvidenceId>) -> Self {
        self.evidence_refs.push(evidence_id.into());
        self
    }

    /// Sets superseded claim identifiers.
    #[must_use]
    pub fn supersedes(mut self, supersedes: Vec<ClaimId>) -> Self {
        self.supersedes = supersedes;
        self
    }

    /// Adds one superseded claim identifier.
    #[must_use]
    pub fn add_supersedes(mut self, claim_id: impl Into<ClaimId>) -> Self {
        self.supersedes.push(claim_id.into());
        self
    }

    /// Sets contradiction edges. Targets stay independently queryable.
    #[must_use]
    pub fn contradicts(mut self, contradicts: Vec<ClaimId>) -> Self {
        self.contradicts = contradicts;
        self
    }

    /// Adds one contradiction edge.
    #[must_use]
    pub fn add_contradicts(mut self, claim_id: impl Into<ClaimId>) -> Self {
        self.contradicts.push(claim_id.into());
        self
    }

    /// Sets the complete taint label set.
    #[must_use]
    pub fn taint_labels(mut self, taint_labels: TaintLabels) -> Self {
        self.taint_labels = taint_labels;
        self
    }

    /// Adds a taint label without removing existing labels.
    #[must_use]
    pub fn add_taint_label(mut self, taint_label: TaintLabel) -> Self {
        self.taint_labels
            .union_with(&TaintLabels::from([taint_label]));
        self
    }

    /// Attaches optional retrieval policy data.
    #[must_use]
    pub fn retrieval_policy(mut self, retrieval_policy: RetrievalPolicy) -> Self {
        self.retrieval_policy = Some(retrieval_policy);
        self
    }

    /// Attaches optional retention policy data.
    #[must_use]
    pub fn retention_policy(mut self, retention_policy: RetentionPolicy) -> Self {
        self.retention_policy = Some(retention_policy);
        self
    }

    /// Finishes construction and validates the metadata invariants.
    ///
    /// # Errors
    ///
    /// Returns [`ClaimError`] for inconsistent taint, authority, or a
    /// self-contradiction edge.
    pub fn build(self) -> Result<Claim, ClaimError> {
        Claim::from_parts(
            self.claim_id,
            self.kind,
            self.state,
            self.proposition,
            self.confidence,
            self.source_authority,
            self.valid_time,
            self.transaction_time,
            self.provenance,
            self.evidence_refs,
            self.supersedes,
            self.contradicts,
            self.taint_labels,
            self.retrieval_policy,
            self.retention_policy,
        )
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClaimWire {
    claim_id: ClaimId,
    kind: ClaimKind,
    state: ClaimState,
    proposition: Proposition,
    confidence: Confidence,
    source_authority: SourceAuthority,
    valid_time: TimeInterval,
    transaction_time: TimeInterval,
    provenance: Vec<ProvenanceRef>,
    #[serde(default)]
    evidence_refs: Vec<EvidenceId>,
    #[serde(default)]
    supersedes: Vec<ClaimId>,
    #[serde(default)]
    contradicts: Vec<ClaimId>,
    taint_labels: TaintLabels,
    #[serde(default)]
    retrieval_policy: Option<RetrievalPolicy>,
    #[serde(default)]
    retention_policy: Option<RetentionPolicy>,
}

impl<'de> Deserialize<'de> for Claim {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ClaimWire::deserialize(deserializer)?;
        Self::from_parts(
            wire.claim_id,
            wire.kind,
            wire.state,
            wire.proposition,
            wire.confidence,
            wire.source_authority,
            wire.valid_time,
            wire.transaction_time,
            wire.provenance,
            wire.evidence_refs,
            wire.supersedes,
            wire.contradicts,
            wire.taint_labels,
            wire.retrieval_policy,
            wire.retention_policy,
        )
        .map_err(D::Error::custom)
    }
}

/// Error returned by Claim construction.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ClaimError {
    /// Directly ingested metadata violates the taint authority cap.
    #[error(transparent)]
    Metadata(#[from] MetadataError),
    /// A claim cannot contradict itself.
    #[error("a claim cannot contradict itself")]
    SelfContradiction,
}

/// Error from constructing a derived Claim.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ClaimDerivationError {
    /// No inputs supplied transform metadata.
    #[error(transparent)]
    Derivation(#[from] DerivationError),
    /// The resulting Claim failed construction validation.
    #[error(transparent)]
    Claim(#[from] ClaimError),
}

/// Links two independently retained claims as a contradiction pair.
///
/// Neither input is deleted, retracted, or otherwise hidden. The result simply
/// carries reciprocal lineage edges.
///
/// # Errors
///
/// Returns [`ClaimError::SelfContradiction`] when both arguments have the same
/// identifier.
pub fn link_contradiction(left: &Claim, right: &Claim) -> Result<(Claim, Claim), ClaimError> {
    if left.claim_id == right.claim_id {
        return Err(ClaimError::SelfContradiction);
    }
    Ok((
        left.clone().with_contradiction(right.claim_id.clone())?,
        right.clone().with_contradiction(left.claim_id.clone())?,
    ))
}

/// Returns the version visible at a bitemporal cut.
///
/// If malformed historical input overlaps on both axes, the latest transaction
/// start wins deterministically; correct version histories normally have one
/// visible version. Contradicting *different* claims remain separate inputs and
/// are never filtered by this function.
#[must_use]
pub fn as_of<'a, I>(
    versions: I,
    valid_at: DateTime<Utc>,
    transaction_at: DateTime<Utc>,
) -> Option<&'a Claim>
where
    I: IntoIterator<Item = &'a Claim>,
{
    versions
        .into_iter()
        .filter(|claim| claim.is_visible_as_of(valid_at, transaction_at))
        .max_by(|left, right| {
            left.transaction_time
                .from
                .cmp(&right.transaction_time.from)
                .then_with(|| left.claim_id.cmp(&right.claim_id))
        })
}

/// A Claim/Evidence vertex borrowed while constructing a provenance graph.
#[derive(Clone, Copy, Debug)]
pub enum ProvenanceNode<'a> {
    Claim(&'a Claim),
    Evidence(&'a Evidence),
}

impl<'a> ProvenanceNode<'a> {
    /// Identifier of this vertex.
    #[must_use]
    pub fn record_id(self) -> &'a RecordId {
        match self {
            Self::Claim(claim) => claim.claim_id(),
            Self::Evidence(evidence) => evidence.evidence_id(),
        }
    }

    /// Provenance parents of this vertex.
    #[must_use]
    pub fn parents(self) -> &'a [ProvenanceRef] {
        match self {
            Self::Claim(claim) => claim.provenance(),
            Self::Evidence(evidence) => evidence.provenance(),
        }
    }
}

impl<'a> From<&'a Claim> for ProvenanceNode<'a> {
    fn from(claim: &'a Claim) -> Self {
        Self::Claim(claim)
    }
}

impl<'a> From<&'a Evidence> for ProvenanceNode<'a> {
    fn from(evidence: &'a Evidence) -> Self {
        Self::Evidence(evidence)
    }
}

/// A validated, immutable provenance DAG.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProvenanceGraph {
    parents: BTreeMap<RecordId, Vec<ProvenanceRef>>,
}

impl ProvenanceGraph {
    /// Builds and validates a graph from Claim and Evidence records.
    ///
    /// # Errors
    ///
    /// Returns [`ProvenanceError`] for duplicate IDs, dangling parent edges, or
    /// a provenance cycle.
    pub fn from_nodes<'a, I>(nodes: I) -> Result<Self, ProvenanceError>
    where
        I: IntoIterator<Item = ProvenanceNode<'a>>,
    {
        let mut parents = BTreeMap::new();
        for node in nodes {
            let record_id = node.record_id().clone();
            let node_parents = node.parents().to_vec();
            if parents.insert(record_id.clone(), node_parents).is_some() {
                return Err(ProvenanceError::DuplicateRecord { record_id });
            }
        }

        let graph = Self { parents };
        graph.validate()?;
        Ok(graph)
    }

    /// Checks that all parents exist and the graph has no directed cycle.
    ///
    /// # Errors
    ///
    /// Returns [`ProvenanceError`] for dangling edges or cycles.
    pub fn validate(&self) -> Result<(), ProvenanceError> {
        for (record_id, parents) in &self.parents {
            for parent_id in parents {
                if !self.parents.contains_key(parent_id) {
                    return Err(ProvenanceError::UnknownReference {
                        record_id: record_id.clone(),
                        parent_id: parent_id.clone(),
                    });
                }
            }
        }

        let mut marks = BTreeMap::new();
        let mut path = Vec::new();
        for record_id in self.parents.keys() {
            self.visit(record_id, &mut marks, &mut path)?;
        }
        Ok(())
    }

    /// Walks a root and all of its provenance ancestors in deterministic
    /// depth-first order, after validating that it is a DAG.
    ///
    /// # Errors
    ///
    /// Returns [`ProvenanceError`] for an unknown root, dangling edge, or cycle.
    pub fn walk_from(&self, root: &RecordId) -> Result<Vec<RecordId>, ProvenanceError> {
        self.validate()?;
        if !self.parents.contains_key(root) {
            return Err(ProvenanceError::UnknownRoot {
                record_id: root.clone(),
            });
        }

        let mut visited = BTreeSet::new();
        let mut walked = Vec::new();
        self.collect(root, &mut visited, &mut walked);
        Ok(walked)
    }

    /// Borrow provenance parents for a record in the graph.
    #[must_use]
    pub fn parents_of(&self, record_id: &RecordId) -> Option<&[ProvenanceRef]> {
        self.parents.get(record_id).map(Vec::as_slice)
    }

    fn visit(
        &self,
        record_id: &RecordId,
        marks: &mut BTreeMap<RecordId, VisitMark>,
        path: &mut Vec<RecordId>,
    ) -> Result<(), ProvenanceError> {
        match marks.get(record_id) {
            Some(VisitMark::Visited) => return Ok(()),
            Some(VisitMark::Visiting) => {
                let start = path
                    .iter()
                    .position(|item| item == record_id)
                    .expect("a visiting record is present in the DFS path");
                let mut cycle = path[start..].to_vec();
                cycle.push(record_id.clone());
                return Err(ProvenanceError::Cycle { path: cycle });
            }
            None => {}
        }

        marks.insert(record_id.clone(), VisitMark::Visiting);
        path.push(record_id.clone());
        let parents = self
            .parents
            .get(record_id)
            .expect("all DFS vertices originate from graph keys");
        for parent in parents {
            self.visit(parent, marks, path)?;
        }
        path.pop();
        marks.insert(record_id.clone(), VisitMark::Visited);
        Ok(())
    }

    fn collect(
        &self,
        record_id: &RecordId,
        visited: &mut BTreeSet<RecordId>,
        walked: &mut Vec<RecordId>,
    ) {
        if !visited.insert(record_id.clone()) {
            return;
        }
        walked.push(record_id.clone());
        for parent in self
            .parents
            .get(record_id)
            .expect("walk roots are validated graph vertices")
        {
            self.collect(parent, visited, walked);
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum VisitMark {
    Visiting,
    Visited,
}

/// Provenance graph validation error.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProvenanceError {
    /// Two supplied vertices use the same record identifier.
    #[error("duplicate provenance record {record_id}")]
    DuplicateRecord {
        /// Duplicate identifier.
        record_id: RecordId,
    },
    /// A provenance edge names a record absent from the supplied graph.
    #[error("provenance record {record_id} references missing parent {parent_id}")]
    UnknownReference {
        /// Child record carrying the invalid edge.
        record_id: RecordId,
        /// Missing parent identifier.
        parent_id: RecordId,
    },
    /// A requested graph-walk root does not exist.
    #[error("provenance root {record_id} is not in the graph")]
    UnknownRoot {
        /// Requested root identifier.
        record_id: RecordId,
    },
    /// A directed cycle was found; the first ID is repeated at the end.
    #[error("provenance graph contains cycle {path:?}")]
    Cycle {
        /// Cycle path.
        path: Vec<RecordId>,
    },
}

/// Validates a Claim/Evidence provenance DAG as a pure function.
///
/// # Errors
///
/// Returns [`ProvenanceError`] for duplicate IDs, dangling parent edges, or a
/// directed cycle.
pub fn validate_provenance_dag<'a, I>(nodes: I) -> Result<(), ProvenanceError>
where
    I: IntoIterator<Item = ProvenanceNode<'a>>,
{
    ProvenanceGraph::from_nodes(nodes).map(|_| ())
}

/// Builds a graph and walks `root` through all Claim/Evidence provenance.
///
/// # Errors
///
/// Returns [`ProvenanceError`] for invalid graph structure or an unknown root.
pub fn walk_provenance<'a, I>(nodes: I, root: &RecordId) -> Result<Vec<RecordId>, ProvenanceError>
where
    I: IntoIterator<Item = ProvenanceNode<'a>>,
{
    ProvenanceGraph::from_nodes(nodes)?.walk_from(root)
}

/// Marks this crate as the Phase 4 epistemic core rather than the old skeleton.
pub const CRATE_STAGE: &str = "F4-epistemic-core";
