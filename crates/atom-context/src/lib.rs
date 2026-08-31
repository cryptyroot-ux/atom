//! atom-context: context items with non-launderable security labels (CXT-001).
//!
//! Normative source is `spec/` (precedence 1):
//!
//! * **ATOM-CXT-001** — Every context item MUST carry provenance, trust,
//!   sensitivity and injection-risk labels, and transformations MUST preserve
//!   taint unless governed declassification occurs.
//! * **ATOM-INV-009** — Untrusted information cannot increase its source
//!   authority through model transformation, summarization, or consolidation.
//! * **ATOM-INV-019** — Context eligibility is a policy gate separate from
//!   effect eligibility.
//!
//! This crate deliberately does **not** duplicate `atom-evidence` provenance
//! logic. Evidence owns *observation*; context owns *labelled items and taint
//! propagation*. The shared authority/taint vocabulary (`SourceAuthority`,
//! `Sensitivity`, `TaintLabel`, `TaintLabels`) is re-used from `atom-evidence`
//! so that a label cannot be laundered while crossing the crate boundary.

#![forbid(unsafe_code)]

use atom_capability::{CapabilityGrant, RevocationState};
use atom_evidence::{
    validate_metadata, MetadataError, Sensitivity, SourceAuthority, TaintCarrier, TaintLabel,
    TaintLabels,
};
use chrono::{DateTime, Utc};
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;

/// The capability operation that authorizes governed declassification.
pub const DECLASSIFY_OPERATION: &str = "declassify";

/// How dangerous an item is as a prompt-injection vector.
///
/// Ordered from least to most dangerous. This ordering is what makes taint
/// non-launderable: transforms and merges only ever move toward `High`.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InjectionRisk {
    /// No known injection risk.
    None,
    /// Low injection risk.
    Low,
    /// Elevated injection risk.
    Medium,
    /// High injection risk — untrusted, likely adversarial content.
    High,
}

impl InjectionRisk {
    /// Every risk level in ascending order.
    pub const ALL: [Self; 4] = [Self::None, Self::Low, Self::Medium, Self::High];

    /// Canonical JSON representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "NONE",
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
        }
    }

    /// The stricter (higher) of two risk levels; used by every transform.
    #[must_use]
    pub fn strictest(self, other: Self) -> Self {
        self.max(other)
    }
}

/// A named context transformation. Every variant preserves taint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransformKind {
    /// Rewrite/format the content without changing its meaning.
    Reformat,
    /// Produce a shorter summary of the content.
    Summarize,
    /// Cut the content to a prefix.
    Truncate,
    /// Any other content-only rewrite.
    Other,
}

/// A single context item carrying the four CXT-001 labels plus its content.
///
/// Trust is represented with `atom_evidence::SourceAuthority` and sensitivity
/// with `atom_evidence::Sensitivity`, so the labels are identical to those the
/// evidence layer enforces. The taint label set is the non-bypassable carrier:
/// it can only grow under transforms/merges and only shrink under governed
/// [`declassify`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContextItem {
    item_id: String,
    provenance: Vec<String>,
    trust: SourceAuthority,
    sensitivity: Sensitivity,
    injection_risk: InjectionRisk,
    taint_labels: TaintLabels,
    content: String,
}

impl ContextItem {
    /// Creates a context item, rejecting incoherent label combinations.
    ///
    /// # Errors
    ///
    /// Returns [`ContextItemError`] when untrusted-external taint is paired with
    /// elevated trust (INV-009 / deny-by-default).
    pub fn new(
        item_id: impl Into<String>,
        provenance: Vec<String>,
        trust: SourceAuthority,
        sensitivity: Sensitivity,
        injection_risk: InjectionRisk,
        taint_labels: TaintLabels,
        content: impl Into<String>,
    ) -> Result<Self, ContextItemError> {
        let item = Self {
            item_id: item_id.into(),
            provenance,
            trust,
            sensitivity,
            injection_risk,
            taint_labels,
            content: content.into(),
        };
        item.validate()?;
        Ok(item)
    }

    fn validate(&self) -> Result<(), ContextItemError> {
        if self.item_id.trim().is_empty() {
            return Err(ContextItemError::BlankId);
        }
        validate_metadata(self.trust, &self.taint_labels)?;
        Ok(())
    }

    /// Stable item identifier.
    #[must_use]
    pub fn item_id(&self) -> &str {
        &self.item_id
    }

    /// Provenance parents (evidence/observation/context references).
    #[must_use]
    pub fn provenance(&self) -> &[String] {
        &self.provenance
    }

    /// Source trust for this item.
    #[must_use]
    pub const fn trust(&self) -> SourceAuthority {
        self.trust
    }

    /// Sensitivity label.
    #[must_use]
    pub const fn sensitivity(&self) -> Sensitivity {
        self.sensitivity
    }

    /// Injection-risk label.
    #[must_use]
    pub const fn injection_risk(&self) -> InjectionRisk {
        self.injection_risk
    }

    /// The carried taint label set.
    #[must_use]
    pub fn taint_labels(&self) -> &TaintLabels {
        &self.taint_labels
    }

    /// The item content.
    #[must_use]
    pub fn content(&self) -> &str {
        &self.content
    }

    /// Whether context eligibility must be gated because the item carries
    /// untrusted-external taint (INV-019).
    #[must_use]
    pub fn blocks_unauthorized_context_eligibility(&self) -> bool {
        self.taint_labels.contains_untrusted_external()
    }

    /// Applies a content-only transformation.
    ///
    /// Trust, sensitivity, injection risk and **all** taint labels are carried
    /// forward unchanged. Only the content is replaced. This is what makes
    /// prompt-injection laundering impossible: no transform can lower a label.
    #[must_use]
    pub fn transform(&self, _kind: TransformKind, new_content: impl Into<String>) -> Self {
        Self {
            item_id: self.item_id.clone(),
            provenance: self.provenance.clone(),
            trust: self.trust,
            sensitivity: self.sensitivity,
            injection_risk: self.injection_risk,
            taint_labels: self.taint_labels.clone(),
            content: new_content.into(),
        }
    }
}

impl TaintCarrier for ContextItem {
    fn source_authority(&self) -> SourceAuthority {
        self.trust
    }

    fn taint_labels(&self) -> &TaintLabels {
        &self.taint_labels
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ContextItemWire {
    item_id: String,
    #[serde(default)]
    provenance: Vec<String>,
    trust: SourceAuthority,
    sensitivity: Sensitivity,
    injection_risk: InjectionRisk,
    taint_labels: TaintLabels,
    content: String,
}

impl<'de> Deserialize<'de> for ContextItem {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ContextItemWire::deserialize(deserializer)?;
        Self::new(
            wire.item_id,
            wire.provenance,
            wire.trust,
            wire.sensitivity,
            wire.injection_risk,
            wire.taint_labels,
            wire.content,
        )
        .map_err(D::Error::custom)
    }
}

/// Error returned when a context item's labels are incoherent.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ContextItemError {
    /// A context item must have a non-blank identifier.
    #[error("context item identifier must not be blank")]
    BlankId,
    /// Trust/taint relationship is invalid (INV-009).
    #[error(transparent)]
    Metadata(#[from] MetadataError),
}

/// Error returned by [`merge`].
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum MergeError {
    /// A merge requires at least one source item.
    #[error("a merged context item requires at least one source")]
    NoInputs,
    /// The merged labels were incoherent.
    #[error(transparent)]
    Item(#[from] ContextItemError),
}

/// Merges several context items, taking the strictest taint from every source.
///
/// * trust  → the **minimum** effective source authority (untrusted-external
///   taint caps a source to `UNTRUSTED` first),
/// * injection risk → the **maximum** risk across sources,
/// * sensitivity → the **maximum** (strictest) sensitivity across sources,
/// * taint labels → the **union** of every source's labels.
///
/// One high-risk source therefore poisons the whole bundle; taint cannot be
/// diluted by merging with clean content.
///
/// # Errors
///
/// Returns [`MergeError::NoInputs`] when no sources are supplied, or a wrapped
/// [`ContextItemError`] if the combined labels are somehow incoherent.
pub fn merge<'a, I>(
    item_id: impl Into<String>,
    sources: I,
    merged_content: impl Into<String>,
) -> Result<ContextItem, MergeError>
where
    I: IntoIterator<Item = &'a ContextItem>,
{
    let mut sources = sources.into_iter();
    let first = sources.next().ok_or(MergeError::NoInputs)?;

    let mut trust = first.effective_source_authority();
    let mut injection_risk = first.injection_risk;
    let mut sensitivity = first.sensitivity;
    let mut taint_labels = first.taint_labels.clone();
    let mut provenance = first.provenance.clone();

    for source in sources {
        trust = trust.minimum(source.effective_source_authority());
        injection_risk = injection_risk.strictest(source.injection_risk);
        sensitivity = sensitivity.max(source.sensitivity);
        taint_labels.union_with(&source.taint_labels);
        provenance.extend(source.provenance.iter().cloned());
    }

    // Re-apply the taint cap after unioning: an untrusted-external label added
    // by any source forces the merged trust down.
    let trust = taint_labels.cap_authority(trust);

    Ok(ContextItem::new(
        item_id,
        provenance,
        trust,
        sensitivity,
        injection_risk,
        taint_labels,
        merged_content,
    )?)
}

/// A requested, attenuation-only change to an item's labels.
///
/// Declassification can only *lower* labels. Any request that would raise a
/// label is rejected by [`declassify`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Declassification {
    target_injection_risk: InjectionRisk,
    target_sensitivity: Option<Sensitivity>,
    remove_labels: Vec<TaintLabel>,
}

impl Declassification {
    /// Begins a declassification that lowers injection risk to `target`.
    #[must_use]
    pub fn new(target_injection_risk: InjectionRisk) -> Self {
        Self {
            target_injection_risk,
            target_sensitivity: None,
            remove_labels: Vec::new(),
        }
    }

    /// Also lowers the sensitivity label to `sensitivity`.
    #[must_use]
    pub fn lower_sensitivity_to(mut self, sensitivity: Sensitivity) -> Self {
        self.target_sensitivity = Some(sensitivity);
        self
    }

    /// Also removes `label` from the taint set.
    #[must_use]
    pub fn remove_label(mut self, label: TaintLabel) -> Self {
        self.remove_labels.push(label);
        self
    }
}

/// An audit record of a governed declassification.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DeclassificationRecord {
    item_id: String,
    authorized_by: String,
    at: DateTime<Utc>,
    before_injection_risk: InjectionRisk,
    after_injection_risk: InjectionRisk,
    before_sensitivity: Sensitivity,
    after_sensitivity: Sensitivity,
    removed_labels: Vec<TaintLabel>,
}

impl DeclassificationRecord {
    /// Identifier of the item that was declassified.
    #[must_use]
    pub fn item_id(&self) -> &str {
        &self.item_id
    }

    /// The grant id that authorized the declassification.
    #[must_use]
    pub fn authorized_by(&self) -> &str {
        &self.authorized_by
    }

    /// When the declassification occurred.
    #[must_use]
    pub const fn at(&self) -> DateTime<Utc> {
        self.at
    }

    /// Injection risk before declassification.
    #[must_use]
    pub const fn before_injection_risk(&self) -> InjectionRisk {
        self.before_injection_risk
    }

    /// Injection risk after declassification.
    #[must_use]
    pub const fn after_injection_risk(&self) -> InjectionRisk {
        self.after_injection_risk
    }

    /// Sensitivity before declassification.
    #[must_use]
    pub const fn before_sensitivity(&self) -> Sensitivity {
        self.before_sensitivity
    }

    /// Sensitivity after declassification.
    #[must_use]
    pub const fn after_sensitivity(&self) -> Sensitivity {
        self.after_sensitivity
    }

    /// Taint labels removed by the declassification.
    #[must_use]
    pub fn removed_labels(&self) -> &[TaintLabel] {
        &self.removed_labels
    }
}

/// Error returned by [`declassify`].
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum DeclassifyError {
    /// The grant does not authorize declassification at this time.
    #[error("declassification is not authorized by the supplied capability grant")]
    Unauthorized,
    /// The request would raise a label, which declassification can never do.
    #[error("declassification can only attenuate labels; the request would raise one")]
    WouldRaise,
    /// The resulting labels were incoherent.
    #[error(transparent)]
    Item(#[from] ContextItemError),
}

/// Performs a governed declassification — the **only** way to lower taint.
///
/// The grant must be `ACTIVE`, currently valid at `at`, and carry the
/// [`DECLASSIFY_OPERATION`]. The request is attenuation-only: it can never
/// raise injection risk or sensitivity. On success the lowered item and an
/// audit [`DeclassificationRecord`] are returned together, so a declassification
/// cannot occur without being recorded.
///
/// # Errors
///
/// * [`DeclassifyError::Unauthorized`] — grant missing the declassify operation,
///   revoked/expired, or outside its validity window.
/// * [`DeclassifyError::WouldRaise`] — the request would raise a label.
/// * [`DeclassifyError::Item`] — the resulting labels are incoherent.
pub fn declassify(
    item: &ContextItem,
    request: &Declassification,
    grant: &CapabilityGrant,
    at: DateTime<Utc>,
) -> Result<(ContextItem, DeclassificationRecord), DeclassifyError> {
    if !grant_authorizes_declassify(grant, at) {
        return Err(DeclassifyError::Unauthorized);
    }

    // Attenuation-only: never raise a label.
    if request.target_injection_risk > item.injection_risk {
        return Err(DeclassifyError::WouldRaise);
    }
    let target_sensitivity = request.target_sensitivity.unwrap_or(item.sensitivity);
    if target_sensitivity > item.sensitivity {
        return Err(DeclassifyError::WouldRaise);
    }

    let taint_labels: TaintLabels = item
        .taint_labels
        .iter()
        .filter(|label| !request.remove_labels.contains(label))
        .cloned()
        .collect();
    // Removing labels can only ever shrink the set; re-apply the cap so trust is
    // never silently raised as a side effect of dropping a label.
    let trust = taint_labels.cap_authority(item.trust);

    let declassified = ContextItem::new(
        item.item_id.clone(),
        item.provenance.clone(),
        trust,
        target_sensitivity,
        request.target_injection_risk,
        taint_labels,
        item.content.clone(),
    )?;

    let record = DeclassificationRecord {
        item_id: item.item_id.clone(),
        authorized_by: grant.grant_id.clone(),
        at,
        before_injection_risk: item.injection_risk,
        after_injection_risk: request.target_injection_risk,
        before_sensitivity: item.sensitivity,
        after_sensitivity: target_sensitivity,
        removed_labels: request.remove_labels.clone(),
    };

    Ok((declassified, record))
}

fn grant_authorizes_declassify(grant: &CapabilityGrant, at: DateTime<Utc>) -> bool {
    if grant.revocation_state != RevocationState::Active {
        return false;
    }
    if at < grant.not_before || at > grant.expires_at {
        return false;
    }
    grant.operations.iter().any(|op| op == DECLASSIFY_OPERATION)
}

/// Marks this crate as the Phase 4 context-labelling core.
pub const CRATE_STAGE: &str = "F4-context-labels";
