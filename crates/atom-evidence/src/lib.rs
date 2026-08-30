//! Typed evidence, observations, and their epistemic metadata.
//!
//! This crate owns the authority and taint types shared by evidence and claims.
//! In particular, transformation metadata is deliberately derived rather than
//! inferred from confidence: source authority and evidential confidence are
//! different concepts.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use chrono::{DateTime, Duration, Utc};
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use thiserror::Error;

/// Stable identifier used by provenance edges.
///
/// The claim schema intentionally represents every identifier as a JSON string.
/// This transparent newtype keeps that wire form while preventing accidental use
/// of unrelated structured values as provenance references.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct RecordId(String);

impl RecordId {
    /// Creates a non-blank record identifier.
    ///
    /// # Errors
    ///
    /// Returns [`IdentifierError`] when `value` is blank.
    pub fn new(value: impl Into<String>) -> Result<Self, IdentifierError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(IdentifierError::Blank);
        }
        Ok(Self(value))
    }

    /// Borrows the wire identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for RecordId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for RecordId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl From<&str> for RecordId {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}

impl From<String> for RecordId {
    fn from(value: String) -> Self {
        Self(value)
    }
}

/// The identifier of an evidence record.
pub type EvidenceId = RecordId;
/// The identifier of an observation record.
pub type ObservationId = RecordId;
/// An edge in a provenance graph. It may name either a claim or evidence record.
pub type ProvenanceRef = RecordId;

/// Error returned for a structurally invalid identifier.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum IdentifierError {
    /// An identifier must contain at least one non-whitespace character.
    #[error("record identifier must not be blank")]
    Blank,
}

/// Source trust, ordered from least to most authoritative.
///
/// This is intentionally a different type from a claim's `Confidence`.
/// `Confidence` answers how much the evidence supports a proposition; this type
/// answers how much the source itself is trusted.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SourceAuthority {
    /// Content from an untrusted source.
    Untrusted,
    /// A source whose identity or reliability has not been independently verified.
    Unverified,
    /// A source independently verified for this use.
    Verified,
    /// An authoritative source for the relevant domain.
    Authoritative,
}

impl SourceAuthority {
    /// Every authority level in ascending order.
    pub const ALL: [Self; 4] = [
        Self::Untrusted,
        Self::Unverified,
        Self::Verified,
        Self::Authoritative,
    ];

    /// Canonical JSON representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Untrusted => "UNTRUSTED",
            Self::Unverified => "UNVERIFIED",
            Self::Verified => "VERIFIED",
            Self::Authoritative => "AUTHORITATIVE",
        }
    }

    /// The lower authority level, used by every transform.
    #[must_use]
    pub const fn minimum(self, other: Self) -> Self {
        if self.rank() <= other.rank() {
            self
        } else {
            other
        }
    }

    const fn rank(self) -> u8 {
        match self {
            Self::Untrusted => 0,
            Self::Unverified => 1,
            Self::Verified => 2,
            Self::Authoritative => 3,
        }
    }
}

impl fmt::Display for SourceAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Canonical sensitivity labels from `spec/enums.yaml`.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Sensitivity {
    Public,
    Internal,
    OwnerPrivate,
    Secret,
    Credential,
    UntrustedExternal,
}

impl Sensitivity {
    /// Every sensitivity in spec order.
    pub const ALL: [Self; 6] = [
        Self::Public,
        Self::Internal,
        Self::OwnerPrivate,
        Self::Secret,
        Self::Credential,
        Self::UntrustedExternal,
    ];

    /// Canonical JSON representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Public => "PUBLIC",
            Self::Internal => "INTERNAL",
            Self::OwnerPrivate => "OWNER_PRIVATE",
            Self::Secret => "SECRET",
            Self::Credential => "CREDENTIAL",
            Self::UntrustedExternal => "UNTRUSTED_EXTERNAL",
        }
    }
}

/// A label that must survive transforms unless a future governed path approves
/// its removal.
///
/// Sensitivity labels have dedicated variants. `InjectionRisk` and `Custom`
/// cover the injection-risk and source-specific labels required by CXT-001
/// without weakening their string wire representation.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum TaintLabel {
    Public,
    Internal,
    OwnerPrivate,
    Secret,
    Credential,
    UntrustedExternal,
    InjectionRisk,
    Custom(String),
}

impl TaintLabel {
    /// The standard injection-risk label.
    pub const INJECTION_RISK: Self = Self::InjectionRisk;

    /// Converts a canonical sensitivity to its equivalent taint label.
    #[must_use]
    pub const fn from_sensitivity(sensitivity: Sensitivity) -> Self {
        match sensitivity {
            Sensitivity::Public => Self::Public,
            Sensitivity::Internal => Self::Internal,
            Sensitivity::OwnerPrivate => Self::OwnerPrivate,
            Sensitivity::Secret => Self::Secret,
            Sensitivity::Credential => Self::Credential,
            Sensitivity::UntrustedExternal => Self::UntrustedExternal,
        }
    }

    /// Creates a non-empty source-specific taint label.
    ///
    /// # Errors
    ///
    /// Returns [`TaintLabelError`] when `value` is blank.
    pub fn custom(value: impl Into<String>) -> Result<Self, TaintLabelError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(TaintLabelError::Blank);
        }
        Ok(Self::Custom(value))
    }

    /// Canonical string form used in claim-schema arrays.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Public => "PUBLIC",
            Self::Internal => "INTERNAL",
            Self::OwnerPrivate => "OWNER_PRIVATE",
            Self::Secret => "SECRET",
            Self::Credential => "CREDENTIAL",
            Self::UntrustedExternal => "UNTRUSTED_EXTERNAL",
            Self::InjectionRisk => "INJECTION_RISK",
            Self::Custom(value) => value,
        }
    }

    /// Whether this label is the untrusted-external sensitivity boundary.
    #[must_use]
    pub const fn is_untrusted_external(&self) -> bool {
        matches!(self, Self::UntrustedExternal)
    }

    fn from_wire(value: String) -> Result<Self, TaintLabelError> {
        match value.as_str() {
            "PUBLIC" => Ok(Self::Public),
            "INTERNAL" => Ok(Self::Internal),
            "OWNER_PRIVATE" => Ok(Self::OwnerPrivate),
            "SECRET" => Ok(Self::Secret),
            "CREDENTIAL" => Ok(Self::Credential),
            "UNTRUSTED_EXTERNAL" => Ok(Self::UntrustedExternal),
            "INJECTION_RISK" => Ok(Self::InjectionRisk),
            _ => Self::custom(value),
        }
    }
}

impl Serialize for TaintLabel {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for TaintLabel {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::from_wire(value).map_err(D::Error::custom)
    }
}

/// Error returned for a malformed custom taint label.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum TaintLabelError {
    /// Empty labels cannot be audited or meaningfully unioned.
    #[error("taint label must not be blank")]
    Blank,
}

/// A deterministic, duplicate-free set of taint labels.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TaintLabels(BTreeSet<TaintLabel>);

impl TaintLabels {
    /// Creates a label set from any iterator.
    #[must_use]
    pub fn new(labels: impl IntoIterator<Item = TaintLabel>) -> Self {
        Self(labels.into_iter().collect())
    }

    /// Borrows the labels in stable order.
    pub fn iter(&self) -> impl Iterator<Item = &TaintLabel> {
        self.0.iter()
    }

    /// Whether no labels are present.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Whether `label` is present.
    #[must_use]
    pub fn contains(&self, label: &TaintLabel) -> bool {
        self.0.contains(label)
    }

    /// Extends this set with every label from `other`; no label is removed.
    pub fn union_with(&mut self, other: &Self) {
        self.0.extend(other.0.iter().cloned());
    }

    /// Returns the monotonic union of two label sets.
    #[must_use]
    pub fn union(&self, other: &Self) -> Self {
        let mut result = self.clone();
        result.union_with(other);
        result
    }

    /// Whether the record is tainted as untrusted external input.
    #[must_use]
    pub fn contains_untrusted_external(&self) -> bool {
        self.0.iter().any(TaintLabel::is_untrusted_external)
    }

    /// The local half of the effect gate: untrusted external taint requires a
    /// separate policy decision before an effect can use this record.
    #[must_use]
    pub fn blocks_unauthorized_effect_eligibility(&self) -> bool {
        self.contains_untrusted_external()
    }

    /// Applies the authority cap implied by this taint set.
    #[must_use]
    pub fn cap_authority(&self, authority: SourceAuthority) -> SourceAuthority {
        if self.contains_untrusted_external() {
            SourceAuthority::Untrusted
        } else {
            authority
        }
    }

    /// Whether all labels in `other` also appear here.
    #[must_use]
    pub fn is_superset(&self, other: &Self) -> bool {
        self.0.is_superset(&other.0)
    }
}

impl FromIterator<TaintLabel> for TaintLabels {
    fn from_iter<T: IntoIterator<Item = TaintLabel>>(iter: T) -> Self {
        Self::new(iter)
    }
}

impl<const N: usize> From<[TaintLabel; N]> for TaintLabels {
    fn from(labels: [TaintLabel; N]) -> Self {
        Self::new(labels)
    }
}

impl<'a> IntoIterator for &'a TaintLabels {
    type Item = &'a TaintLabel;
    type IntoIter = std::collections::btree_set::Iter<'a, TaintLabel>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

/// Metadata required of any input that can participate in a transform.
pub trait TaintCarrier {
    /// Trust assigned to the source before applying its taint cap.
    fn source_authority(&self) -> SourceAuthority;

    /// Labels carried by the input.
    fn taint_labels(&self) -> &TaintLabels;

    /// Trust after applying the input's non-bypassable taint cap.
    fn effective_source_authority(&self) -> SourceAuthority {
        self.taint_labels().cap_authority(self.source_authority())
    }
}

impl<T> TaintCarrier for &T
where
    T: TaintCarrier + ?Sized,
{
    fn source_authority(&self) -> SourceAuthority {
        (*self).source_authority()
    }

    fn taint_labels(&self) -> &TaintLabels {
        (*self).taint_labels()
    }
}

/// A metadata combination that is safe to attach to a derived record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DerivedMetadata {
    source_authority: SourceAuthority,
    taint_labels: TaintLabels,
}

impl DerivedMetadata {
    /// The minimum effective source authority across all inputs.
    #[must_use]
    pub const fn source_authority(&self) -> SourceAuthority {
        self.source_authority
    }

    /// The monotonic union of every input taint set.
    #[must_use]
    pub fn taint_labels(&self) -> &TaintLabels {
        &self.taint_labels
    }

    /// Whether policy must explicitly authorize use in effect eligibility.
    #[must_use]
    pub fn blocks_unauthorized_effect_eligibility(&self) -> bool {
        self.taint_labels.blocks_unauthorized_effect_eligibility()
    }
}

impl TaintCarrier for DerivedMetadata {
    fn source_authority(&self) -> SourceAuthority {
        self.source_authority
    }

    fn taint_labels(&self) -> &TaintLabels {
        &self.taint_labels
    }
}

/// Error from attempting to derive a record without inputs.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum DerivationError {
    /// Without an input, there is no authority or taint provenance to preserve.
    #[error("a derived record requires at least one input")]
    NoInputs,
}

/// Combines transform metadata according to INV-009 and CXT-001.
///
/// This is the only metadata operation needed by summarization, merge, and
/// consolidation: taint labels are unioned, while source authority is the
/// minimum *effective* authority of all inputs. Thus an
/// `UNTRUSTED_EXTERNAL` input always yields `UNTRUSTED` derived metadata.
///
/// # Errors
///
/// Returns [`DerivationError::NoInputs`] for an empty input collection.
pub fn derive<I>(inputs: I) -> Result<DerivedMetadata, DerivationError>
where
    I: IntoIterator,
    I::Item: TaintCarrier,
{
    let mut inputs = inputs.into_iter();
    let first = inputs.next().ok_or(DerivationError::NoInputs)?;
    let mut source_authority = first.effective_source_authority();
    let mut taint_labels = first.taint_labels().clone();

    for input in inputs {
        source_authority = source_authority.minimum(input.effective_source_authority());
        taint_labels.union_with(input.taint_labels());
    }

    Ok(DerivedMetadata {
        source_authority: taint_labels.cap_authority(source_authority),
        taint_labels,
    })
}

/// Error returned when a record's authority conflicts with its taint.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum MetadataError {
    /// Untrusted content cannot be labelled authoritative at ingestion.
    #[error(
        "UNTRUSTED_EXTERNAL taint requires UNTRUSTED source authority, got {source_authority}"
    )]
    UntrustedExternalAuthority {
        /// The attempted authority level.
        source_authority: SourceAuthority,
    },
}

/// Checks the taint/authority relationship for directly ingested records.
///
/// Derived records should use [`derive`], which applies this same cap
/// automatically.
///
/// # Errors
///
/// Returns [`MetadataError`] if untrusted-external data claims elevated source
/// authority.
pub fn validate_metadata(
    source_authority: SourceAuthority,
    taint_labels: &TaintLabels,
) -> Result<(), MetadataError> {
    if taint_labels.contains_untrusted_external() && source_authority != SourceAuthority::Untrusted
    {
        return Err(MetadataError::UntrustedExternalAuthority { source_authority });
    }
    Ok(())
}

// TODO(CXT-001): governed declassification belongs to a future authorized
// policy path. Alpha deliberately exposes no taint-removal operation.
#[allow(dead_code)]
fn governed_declassification_is_future_cxt_001() {}

/// A typed JSON object used for evidence and observation bodies.
///
/// The core intentionally owns only the fact that these fields are objects;
/// their domain-specific contents belong to the producer and policy layers.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct JsonObject(BTreeMap<String, Value>);

impl JsonObject {
    /// Creates an object from its fields.
    #[must_use]
    pub fn new(fields: BTreeMap<String, Value>) -> Self {
        Self(fields)
    }

    /// Creates an empty object.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Adds or replaces a field.
    pub fn insert(&mut self, key: impl Into<String>, value: Value) -> Option<Value> {
        self.0.insert(key.into(), value)
    }

    /// Looks up a field.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.0.get(key)
    }

    /// Borrows the object fields.
    #[must_use]
    pub fn as_map(&self) -> &BTreeMap<String, Value> {
        &self.0
    }
}

impl From<BTreeMap<String, Value>> for JsonObject {
    fn from(fields: BTreeMap<String, Value>) -> Self {
        Self::new(fields)
    }
}

impl FromIterator<(String, Value)> for JsonObject {
    fn from_iter<T: IntoIterator<Item = (String, Value)>>(iter: T) -> Self {
        Self(iter.into_iter().collect())
    }
}

/// An external system or person from which reality was observed.
///
/// It is intentionally distinct from [`ModelIdentity`], preventing a model
/// assertion from being passed to [`Observation::new`].
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ObservationSource(String);

impl ObservationSource {
    /// Creates a non-blank external source identity.
    ///
    /// # Errors
    ///
    /// Returns [`IdentifierError`] when `value` is blank.
    pub fn new(value: impl Into<String>) -> Result<Self, IdentifierError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(IdentifierError::Blank);
        }
        Ok(Self(value))
    }

    /// Borrows the external source identity.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for ObservationSource {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

/// Identity of a model that emitted an assertion.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ModelIdentity(String);

impl ModelIdentity {
    /// Creates a non-blank model identity.
    ///
    /// # Errors
    ///
    /// Returns [`IdentifierError`] when `value` is blank.
    pub fn new(value: impl Into<String>) -> Result<Self, IdentifierError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(IdentifierError::Blank);
        }
        Ok(Self(value))
    }

    /// Borrows the model identity.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for ModelIdentity {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

/// Non-negative freshness duration, serialized as whole seconds.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct StalenessHorizon(i64);

impl StalenessHorizon {
    /// Creates a freshness horizon measured in seconds.
    ///
    /// # Errors
    ///
    /// Returns [`FreshnessError`] for a negative duration.
    pub fn from_seconds(seconds: i64) -> Result<Self, FreshnessError> {
        if seconds < 0 {
            return Err(FreshnessError::NegativeHorizon { seconds });
        }
        Ok(Self(seconds))
    }

    /// Returns the horizon in seconds.
    #[must_use]
    pub const fn seconds(self) -> i64 {
        self.0
    }

    /// Returns the equivalent Chrono duration.
    #[must_use]
    pub fn duration(self) -> Duration {
        Duration::seconds(self.0)
    }
}

impl<'de> Deserialize<'de> for StalenessHorizon {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::from_seconds(i64::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

/// Error returned for an invalid observation freshness horizon.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum FreshnessError {
    /// A staleness horizon cannot end before the observation exists.
    #[error("staleness horizon must be non-negative, got {seconds}")]
    NegativeHorizon {
        /// Rejected duration in seconds.
        seconds: i64,
    },
}

/// A record of externally observed reality.
///
/// Its constructor accepts [`ObservationSource`] rather than a model identity,
/// and there is no conversion from [`ModelAssertion`]. This is the type-level
/// boundary required by OBS-001 / INV-015.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    observation_id: ObservationId,
    observed_at: DateTime<Utc>,
    source: ObservationSource,
    staleness_horizon: StalenessHorizon,
    provenance: Vec<ProvenanceRef>,
    source_authority: SourceAuthority,
    taint_labels: TaintLabels,
    payload: JsonObject,
}

impl Observation {
    /// Creates a provenance- and freshness-aware external observation.
    ///
    /// # Errors
    ///
    /// Returns [`EvidenceError`] for inconsistent authority and taint metadata.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        observation_id: impl Into<ObservationId>,
        observed_at: DateTime<Utc>,
        source: ObservationSource,
        staleness_horizon: StalenessHorizon,
        provenance: Vec<ProvenanceRef>,
        source_authority: SourceAuthority,
        taint_labels: TaintLabels,
        payload: JsonObject,
    ) -> Result<Self, EvidenceError> {
        validate_metadata(source_authority, &taint_labels)?;
        Ok(Self {
            observation_id: observation_id.into(),
            observed_at,
            source,
            staleness_horizon,
            provenance,
            source_authority,
            taint_labels,
            payload,
        })
    }

    /// Identifier of this observation.
    #[must_use]
    pub fn observation_id(&self) -> &ObservationId {
        &self.observation_id
    }

    /// Time at which reality was observed.
    #[must_use]
    pub const fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }

    /// External source of the observation.
    #[must_use]
    pub fn source(&self) -> &ObservationSource {
        &self.source
    }

    /// Duration for which this observation is fresh.
    #[must_use]
    pub const fn staleness_horizon(&self) -> StalenessHorizon {
        self.staleness_horizon
    }

    /// Provenance parents.
    #[must_use]
    pub fn provenance(&self) -> &[ProvenanceRef] {
        &self.provenance
    }

    /// Trust assigned to the external source.
    #[must_use]
    pub const fn source_authority(&self) -> SourceAuthority {
        self.source_authority
    }

    /// Taint labels carried from the observed source.
    #[must_use]
    pub fn taint_labels(&self) -> &TaintLabels {
        &self.taint_labels
    }

    /// Structured observed payload.
    #[must_use]
    pub fn payload(&self) -> &JsonObject {
        &self.payload
    }

    /// Whether the observation remains fresh at `at`.
    #[must_use]
    pub fn is_fresh_at(&self, at: DateTime<Utc>) -> bool {
        if at < self.observed_at {
            return false;
        }
        self.observed_at
            .checked_add_signed(self.staleness_horizon.duration())
            .is_some_and(|expires_at| at <= expires_at)
    }

    /// Whether policy must explicitly authorize effect eligibility.
    #[must_use]
    pub fn blocks_unauthorized_effect_eligibility(&self) -> bool {
        self.taint_labels.blocks_unauthorized_effect_eligibility()
    }
}

impl TaintCarrier for Observation {
    fn source_authority(&self) -> SourceAuthority {
        self.source_authority
    }

    fn taint_labels(&self) -> &TaintLabels {
        &self.taint_labels
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ObservationWire {
    observation_id: ObservationId,
    observed_at: DateTime<Utc>,
    source: ObservationSource,
    staleness_horizon: StalenessHorizon,
    provenance: Vec<ProvenanceRef>,
    source_authority: SourceAuthority,
    taint_labels: TaintLabels,
    payload: JsonObject,
}

impl<'de> Deserialize<'de> for Observation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ObservationWire::deserialize(deserializer)?;
        Self::new(
            wire.observation_id,
            wire.observed_at,
            wire.source,
            wire.staleness_horizon,
            wire.provenance,
            wire.source_authority,
            wire.taint_labels,
            wire.payload,
        )
        .map_err(D::Error::custom)
    }
}

/// The only kinds of model-originated assertion that can be persisted here.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ModelAssertionKind {
    Prediction,
    ModelOutput,
}

/// A model assertion, deliberately not an [`Observation`].
///
/// ```compile_fail
/// use atom_evidence::{ModelAssertion, Observation};
///
/// fn store_reality(_: Observation) {}
///
/// fn cannot_launder_a_model_assertion(assertion: ModelAssertion) {
///     store_reality(assertion);
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModelAssertion {
    assertion_id: RecordId,
    kind: ModelAssertionKind,
    model: ModelIdentity,
    asserted_at: DateTime<Utc>,
    output: JsonObject,
    provenance: Vec<ProvenanceRef>,
    source_authority: SourceAuthority,
    taint_labels: TaintLabels,
}

impl ModelAssertion {
    /// Creates a stored model assertion without claiming it observed reality.
    ///
    /// # Errors
    ///
    /// Returns [`EvidenceError`] for inconsistent authority and taint metadata.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        assertion_id: impl Into<RecordId>,
        kind: ModelAssertionKind,
        model: ModelIdentity,
        asserted_at: DateTime<Utc>,
        output: JsonObject,
        provenance: Vec<ProvenanceRef>,
        source_authority: SourceAuthority,
        taint_labels: TaintLabels,
    ) -> Result<Self, EvidenceError> {
        validate_metadata(source_authority, &taint_labels)?;
        Ok(Self {
            assertion_id: assertion_id.into(),
            kind,
            model,
            asserted_at,
            output,
            provenance,
            source_authority,
            taint_labels,
        })
    }

    /// Model assertion identifier.
    #[must_use]
    pub fn assertion_id(&self) -> &RecordId {
        &self.assertion_id
    }

    /// Declared model assertion kind.
    #[must_use]
    pub const fn kind(&self) -> ModelAssertionKind {
        self.kind
    }

    /// Model that produced the assertion.
    #[must_use]
    pub fn model(&self) -> &ModelIdentity {
        &self.model
    }

    /// The asserted model output.
    #[must_use]
    pub fn output(&self) -> &JsonObject {
        &self.output
    }

    /// Trust assigned to the model assertion source.
    #[must_use]
    pub const fn source_authority(&self) -> SourceAuthority {
        self.source_authority
    }

    /// Taint labels carried into the model assertion.
    #[must_use]
    pub fn taint_labels(&self) -> &TaintLabels {
        &self.taint_labels
    }
}

impl TaintCarrier for ModelAssertion {
    fn source_authority(&self) -> SourceAuthority {
        self.source_authority
    }

    fn taint_labels(&self) -> &TaintLabels {
        &self.taint_labels
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ModelAssertionWire {
    assertion_id: RecordId,
    kind: ModelAssertionKind,
    model: ModelIdentity,
    asserted_at: DateTime<Utc>,
    output: JsonObject,
    provenance: Vec<ProvenanceRef>,
    source_authority: SourceAuthority,
    taint_labels: TaintLabels,
}

impl<'de> Deserialize<'de> for ModelAssertion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ModelAssertionWire::deserialize(deserializer)?;
        Self::new(
            wire.assertion_id,
            wire.kind,
            wire.model,
            wire.asserted_at,
            wire.output,
            wire.provenance,
            wire.source_authority,
            wire.taint_labels,
        )
        .map_err(D::Error::custom)
    }
}

/// Verifier independence taxonomy V0--V5 from `spec/enums.yaml`.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum VerifierLevel {
    /// V0 — SELF_REPORT.
    V0,
    /// V1 — CORRELATED_MODEL.
    V1,
    /// V2 — INDEPENDENT_MODEL.
    V2,
    /// V3 — PROGRAMMATIC_ORACLE.
    V3,
    /// V4 — EXTERNAL_REALITY.
    V4,
    /// V5 — FORMAL_OR_CRYPTOGRAPHIC.
    V5,
}

impl VerifierLevel {
    /// Every verifier level in spec order.
    pub const ALL: [Self; 6] = [Self::V0, Self::V1, Self::V2, Self::V3, Self::V4, Self::V5];

    /// Canonical level code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::V0 => "V0",
            Self::V1 => "V1",
            Self::V2 => "V2",
            Self::V3 => "V3",
            Self::V4 => "V4",
            Self::V5 => "V5",
        }
    }

    /// The corresponding canonical description from `spec/enums.yaml`.
    #[must_use]
    pub const fn meaning(self) -> &'static str {
        match self {
            Self::V0 => "SELF_REPORT",
            Self::V1 => "CORRELATED_MODEL",
            Self::V2 => "INDEPENDENT_MODEL",
            Self::V3 => "PROGRAMMATIC_ORACLE",
            Self::V4 => "EXTERNAL_REALITY",
            Self::V5 => "FORMAL_OR_CRYPTOGRAPHIC",
        }
    }
}

impl fmt::Display for VerifierLevel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A typed evidence record that may be linked to an external observation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    evidence_id: EvidenceId,
    verifier_level: VerifierLevel,
    source_authority: SourceAuthority,
    taint_labels: TaintLabels,
    provenance: Vec<ProvenanceRef>,
    payload: JsonObject,
    #[serde(skip_serializing_if = "Option::is_none")]
    observation: Option<Observation>,
}

impl Evidence {
    /// Creates evidence that is not necessarily an observation of reality.
    ///
    /// # Errors
    ///
    /// Returns [`EvidenceError`] for inconsistent authority and taint metadata.
    pub fn new(
        evidence_id: impl Into<EvidenceId>,
        verifier_level: VerifierLevel,
        source_authority: SourceAuthority,
        taint_labels: TaintLabels,
        provenance: Vec<ProvenanceRef>,
        payload: JsonObject,
    ) -> Result<Self, EvidenceError> {
        Self::from_parts(
            evidence_id.into(),
            verifier_level,
            source_authority,
            taint_labels,
            provenance,
            payload,
            None,
        )
    }

    /// Converts an external observation into V4 (external reality) evidence.
    ///
    /// The observation's taint and authority are copied exactly, so they cannot
    /// be laundered while packaging the observation as evidence.
    ///
    /// # Errors
    ///
    /// Returns [`EvidenceError`] if the observation metadata is inconsistent.
    pub fn from_observation(
        evidence_id: impl Into<EvidenceId>,
        observation: Observation,
    ) -> Result<Self, EvidenceError> {
        Self::from_parts(
            evidence_id.into(),
            VerifierLevel::V4,
            observation.source_authority,
            observation.taint_labels.clone(),
            observation.provenance.clone(),
            observation.payload.clone(),
            Some(observation),
        )
    }

    /// Builds transformed evidence using the monotonic [`derive`] helper.
    ///
    /// # Errors
    ///
    /// Returns an error when no transform inputs are supplied or their metadata
    /// cannot be represented safely.
    pub fn derived<I>(
        evidence_id: impl Into<EvidenceId>,
        verifier_level: VerifierLevel,
        provenance: Vec<ProvenanceRef>,
        payload: JsonObject,
        inputs: I,
    ) -> Result<Self, EvidenceDerivationError>
    where
        I: IntoIterator,
        I::Item: TaintCarrier,
    {
        let metadata = derive(inputs)?;
        Ok(Self::new(
            evidence_id,
            verifier_level,
            metadata.source_authority(),
            metadata.taint_labels().clone(),
            provenance,
            payload,
        )?)
    }

    fn from_parts(
        evidence_id: EvidenceId,
        verifier_level: VerifierLevel,
        source_authority: SourceAuthority,
        taint_labels: TaintLabels,
        provenance: Vec<ProvenanceRef>,
        payload: JsonObject,
        observation: Option<Observation>,
    ) -> Result<Self, EvidenceError> {
        validate_metadata(source_authority, &taint_labels)?;
        if let Some(observation) = &observation {
            if !taint_labels.is_superset(&observation.taint_labels)
                || source_authority > observation.effective_source_authority()
            {
                return Err(EvidenceError::ObservationMetadataNotPreserved);
            }
        }
        Ok(Self {
            evidence_id,
            verifier_level,
            source_authority,
            taint_labels,
            provenance,
            payload,
            observation,
        })
    }

    /// Evidence identifier.
    #[must_use]
    pub fn evidence_id(&self) -> &EvidenceId {
        &self.evidence_id
    }

    /// Verification independence level.
    #[must_use]
    pub const fn verifier_level(&self) -> VerifierLevel {
        self.verifier_level
    }

    /// Provenance parents.
    #[must_use]
    pub fn provenance(&self) -> &[ProvenanceRef] {
        &self.provenance
    }

    /// Trust assigned to the evidence source.
    #[must_use]
    pub const fn source_authority(&self) -> SourceAuthority {
        self.source_authority
    }

    /// Taint labels carried by the evidence.
    #[must_use]
    pub fn taint_labels(&self) -> &TaintLabels {
        &self.taint_labels
    }

    /// Typed evidence payload.
    #[must_use]
    pub fn payload(&self) -> &JsonObject {
        &self.payload
    }

    /// Attached external observation, if this evidence was created from one.
    #[must_use]
    pub fn observation(&self) -> Option<&Observation> {
        self.observation.as_ref()
    }

    /// Whether policy must explicitly authorize effect eligibility.
    #[must_use]
    pub fn blocks_unauthorized_effect_eligibility(&self) -> bool {
        self.taint_labels.blocks_unauthorized_effect_eligibility()
    }
}

impl TaintCarrier for Evidence {
    fn source_authority(&self) -> SourceAuthority {
        self.source_authority
    }

    fn taint_labels(&self) -> &TaintLabels {
        &self.taint_labels
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceWire {
    evidence_id: EvidenceId,
    verifier_level: VerifierLevel,
    source_authority: SourceAuthority,
    taint_labels: TaintLabels,
    #[serde(default)]
    provenance: Vec<ProvenanceRef>,
    payload: JsonObject,
    #[serde(default)]
    observation: Option<Observation>,
}

impl<'de> Deserialize<'de> for Evidence {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = EvidenceWire::deserialize(deserializer)?;
        Self::from_parts(
            wire.evidence_id,
            wire.verifier_level,
            wire.source_authority,
            wire.taint_labels,
            wire.provenance,
            wire.payload,
            wire.observation,
        )
        .map_err(D::Error::custom)
    }
}

/// Error returned by evidence or observation construction.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum EvidenceError {
    /// Directly ingested metadata violates the taint authority cap.
    #[error(transparent)]
    Metadata(#[from] MetadataError),
    /// Evidence containing an observation must retain its authority and all taint.
    #[error("evidence containing an observation must preserve its taint and authority")]
    ObservationMetadataNotPreserved,
}

/// Error from constructing derived evidence.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum EvidenceDerivationError {
    /// No inputs supplied transform metadata.
    #[error(transparent)]
    Derivation(#[from] DerivationError),
    /// The resulting evidence failed construction validation.
    #[error(transparent)]
    Evidence(#[from] EvidenceError),
}

/// Marks this crate as the Phase 4 epistemic core rather than the old skeleton.
pub const CRATE_STAGE: &str = "F4-epistemic-core";
