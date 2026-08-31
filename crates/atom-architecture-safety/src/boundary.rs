//! Evolution-ring enforcement for adaptive architecture artifacts.
//!
//! The boundary owns promotion state rather than exposing a mutable ring to a
//! learner. This keeps the `LAB -> SIMULATION -> SHADOW -> CANARY -> ACTIVE`
//! sequence and the E7/E8 self-promotion prohibition outside production
//! cognition.

use std::collections::BTreeMap;

use atom_artifact::{Artifact, ArtifactError, ArtifactId};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// One stage in the ordered adaptive-artifact evolution ring (ATOM-EVO-001).
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvolutionRing {
    /// Experimental only; no production traffic.
    Lab,
    /// Evaluated against simulated inputs and effects.
    Simulation,
    /// Observes production-shaped traffic without controlling it.
    Shadow,
    /// Receives limited production traffic.
    Canary,
    /// The selected production artifact.
    Active,
}

impl EvolutionRing {
    /// All promotable rings in their only legal order.
    pub const ALL: [Self; 5] = [
        Self::Lab,
        Self::Simulation,
        Self::Shadow,
        Self::Canary,
        Self::Active,
    ];

    /// Canonical spelling from `spec/enums.yaml`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Lab => "LAB",
            Self::Simulation => "SIMULATION",
            Self::Shadow => "SHADOW",
            Self::Canary => "CANARY",
            Self::Active => "ACTIVE",
        }
    }

    /// The one stage that may immediately follow this stage.
    #[must_use]
    pub const fn next(self) -> Option<Self> {
        match self {
            Self::Lab => Some(Self::Simulation),
            Self::Simulation => Some(Self::Shadow),
            Self::Shadow => Some(Self::Canary),
            Self::Canary => Some(Self::Active),
            Self::Active => None,
        }
    }
}

/// Compatibility name for an [`EvolutionRing`].
pub type Ring = EvolutionRing;
/// Compatibility name for an [`EvolutionRing`].
pub type Stage = EvolutionRing;

/// Classification of an adaptive change from `spec/enums.yaml`.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvolutionClass {
    /// E0: knowledge-only change.
    E0Knowledge,
    /// E1: skill change.
    E1Skill,
    /// E2: workflow change.
    E2Workflow,
    /// E3: tool change.
    E3Tool,
    /// E4: verifier change.
    E4Verifier,
    /// E5: harness or topology change.
    E5HarnessOrTopology,
    /// E6: model adaptation.
    E6ModelAdaptation,
    /// E7: trusted-core change.
    E7TrustedCoreChange,
    /// E8: authority or policy expansion.
    E8AuthorityOrPolicyExpansion,
}

impl EvolutionClass {
    /// Stable evolution-class code (for example, `E7`).
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::E0Knowledge => "E0",
            Self::E1Skill => "E1",
            Self::E2Workflow => "E2",
            Self::E3Tool => "E3",
            Self::E4Verifier => "E4",
            Self::E5HarnessOrTopology => "E5",
            Self::E6ModelAdaptation => "E6",
            Self::E7TrustedCoreChange => "E7",
            Self::E8AuthorityOrPolicyExpansion => "E8",
        }
    }

    /// Canonical evolution-class description from `spec/enums.yaml`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::E0Knowledge => "KNOWLEDGE",
            Self::E1Skill => "SKILL",
            Self::E2Workflow => "WORKFLOW",
            Self::E3Tool => "TOOL",
            Self::E4Verifier => "VERIFIER",
            Self::E5HarnessOrTopology => "HARNESS_OR_TOPOLOGY",
            Self::E6ModelAdaptation => "MODEL_ADAPTATION",
            Self::E7TrustedCoreChange => "TRUSTED_CORE_CHANGE",
            Self::E8AuthorityOrPolicyExpansion => "AUTHORITY_OR_POLICY_EXPANSION",
        }
    }

    /// Whether this class is protected by the E7/E8 self-promotion ban.
    #[must_use]
    pub const fn requires_independent_promotion(self) -> bool {
        matches!(
            self,
            Self::E7TrustedCoreChange | Self::E8AuthorityOrPolicyExpansion
        )
    }

    /// Alias for E7 used by policy-facing callers.
    #[allow(non_upper_case_globals)]
    pub const TrustedCore: Self = Self::E7TrustedCoreChange;
    /// Alias for E8 used by policy-facing callers.
    #[allow(non_upper_case_globals)]
    pub const AuthorityPolicy: Self = Self::E8AuthorityOrPolicyExpansion;
}

/// Compatibility name for an [`EvolutionClass`].
pub type ChangeClass = EvolutionClass;

/// The actor/process that created a candidate change.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ChangeOrigin {
    /// The currently running production cognition proposed the change.
    ProductionCognition,
    /// A reviewed human process proposed or approved the change.
    ReviewedHuman,
    /// An independently operated evaluation process proposed the change.
    IndependentEvaluator,
}

impl ChangeOrigin {
    /// Whether this origin is production cognition.
    #[must_use]
    pub const fn is_production_cognition(self) -> bool {
        matches!(self, Self::ProductionCognition)
    }
}

/// Current immutable facts the boundary tracks for one artifact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactState {
    artifact_id: ArtifactId,
    ring: EvolutionRing,
    class: Option<EvolutionClass>,
    origin: Option<ChangeOrigin>,
    prior_active_artifact: Option<ArtifactId>,
    generation: u64,
}

impl ArtifactState {
    /// Content-addressed identity of the artifact.
    #[must_use]
    pub fn artifact_id(&self) -> &ArtifactId {
        &self.artifact_id
    }

    /// Current evolution ring.
    #[must_use]
    pub const fn ring(&self) -> EvolutionRing {
        self.ring
    }

    /// Candidate class, if this was registered as an evolving candidate.
    #[must_use]
    pub const fn class(&self) -> Option<EvolutionClass> {
        self.class
    }

    /// Candidate origin, if this was registered as an evolving candidate.
    #[must_use]
    pub const fn origin(&self) -> Option<ChangeOrigin> {
        self.origin
    }

    /// Active artifact captured immediately before this artifact was promoted.
    #[must_use]
    pub fn prior_active_artifact(&self) -> Option<&ArtifactId> {
        self.prior_active_artifact.as_ref()
    }

    /// Monotonic transition generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }
}

/// Recorded result of one legal forward promotion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Promotion {
    artifact_id: ArtifactId,
    from: EvolutionRing,
    to: EvolutionRing,
    generation: u64,
}

impl Promotion {
    /// Artifact that moved forward.
    #[must_use]
    pub fn artifact_id(&self) -> &ArtifactId {
        &self.artifact_id
    }

    /// Ring before the promotion.
    #[must_use]
    pub const fn from(&self) -> EvolutionRing {
        self.from
    }

    /// Ring after the promotion.
    #[must_use]
    pub const fn to(&self) -> EvolutionRing {
        self.to
    }

    /// Generation after the promotion.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }
}

/// Outcome of checking live performance against a promotion baseline.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RollbackAction {
    /// The metric did not regress outside its allowed tolerance.
    Held,
    /// The active candidate was returned to CANARY and its captured predecessor
    /// was restored to active service.
    RolledBack {
        /// Ring from which the candidate was removed.
        from: EvolutionRing,
        /// Ring to which the candidate was downgraded.
        to: EvolutionRing,
        /// Exact content-addressed artifact restored to active service.
        restored_artifact: ArtifactId,
    },
}

impl RollbackAction {
    /// Whether a rollback was performed.
    #[must_use]
    pub const fn is_rolled_back(&self) -> bool {
        matches!(self, Self::RolledBack { .. })
    }
}

/// The safety boundary controlling all adaptive-artifact promotions.
///
/// Its fields are private deliberately: the learner can ask to register a
/// candidate, but cannot write an artifact's ring, replace the active route,
/// or erase the predecessor required for VT-012 rollback.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EvolutionBoundary {
    artifacts: BTreeMap<ArtifactId, ArtifactState>,
    active_artifact: Option<ArtifactId>,
}

impl EvolutionBoundary {
    /// Creates an empty boundary. Register a certified active artifact before
    /// promoting a candidate into `ACTIVE`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Current active content-addressed artifact, if one has been registered.
    #[must_use]
    pub fn active_artifact(&self) -> Option<&ArtifactId> {
        self.active_artifact.as_ref()
    }

    /// Returns a candidate's tracked state.
    #[must_use]
    pub fn artifact(&self, artifact_id: &ArtifactId) -> Option<&ArtifactState> {
        self.artifacts.get(artifact_id)
    }

    /// Returns just a candidate's current ring.
    #[must_use]
    pub fn ring_of(&self, artifact_id: &ArtifactId) -> Option<EvolutionRing> {
        self.artifact(artifact_id).map(ArtifactState::ring)
    }

    /// Registers the pre-existing certified production artifact.
    ///
    /// A second active artifact cannot be installed directly: it must advance
    /// through every ring via [`Self::promote`], which records the predecessor
    /// needed for automatic rollback.
    pub fn register_active(&mut self, artifact_id: ArtifactId) -> Result<(), BoundaryError> {
        if self.active_artifact.is_some() {
            return Err(BoundaryError::ActiveArtifactAlreadyRegistered);
        }
        self.insert(artifact_id.clone(), EvolutionRing::Active, None, None)?;
        self.active_artifact = Some(artifact_id);
        Ok(())
    }

    /// Registers a candidate in `LAB`.
    ///
    /// E7/E8 candidates are recorded rather than discarded so an independent
    /// review process can examine them, but [`Self::promote`] will reject their
    /// self-promotion if they originated from production cognition.
    pub fn register_lab(
        &mut self,
        artifact_id: ArtifactId,
        class: EvolutionClass,
        origin: ChangeOrigin,
    ) -> Result<(), BoundaryError> {
        self.insert(artifact_id, EvolutionRing::Lab, Some(class), Some(origin))
    }

    /// Registers a signed artifact as a lab candidate after verifying it.
    ///
    /// This convenience boundary prevents callers from treating an unverified
    /// artifact bundle as an evolvable candidate. It does not persist signing
    /// secrets; verification is performed before the identity is registered.
    pub fn register_verified_lab(
        &mut self,
        artifact: &Artifact,
        signing_secret: &[u8],
        class: EvolutionClass,
        origin: ChangeOrigin,
    ) -> Result<(), BoundaryError> {
        artifact.verify(signing_secret)?;
        self.register_lab(artifact.id().clone(), class, origin)
    }

    /// Registers a signed artifact as the initial active route after verifying
    /// its content address and signature.
    pub fn register_verified_active(
        &mut self,
        artifact: &Artifact,
        signing_secret: &[u8],
    ) -> Result<(), BoundaryError> {
        artifact.verify(signing_secret)?;
        self.register_active(artifact.id().clone())
    }

    /// Promotes an artifact by exactly one ring.
    ///
    /// The E7/E8 production-cognition ban is applied here rather than in the
    /// learner. A production cognition process therefore cannot move a
    /// trusted-core or authority/policy expansion out of `LAB` by repeatedly
    /// asking this boundary to promote it.
    pub fn promote(&mut self, artifact_id: &ArtifactId) -> Result<Promotion, BoundaryError> {
        let current = self.state_for(artifact_id)?;
        let target = current
            .ring
            .next()
            .ok_or_else(|| BoundaryError::AlreadyActive {
                artifact_id: artifact_id.clone(),
            })?;
        self.promote_to(artifact_id, target)
    }

    /// Promotes an artifact to a requested immediate next ring.
    ///
    /// This form makes attempted skips explicit and rejects them before any
    /// mutable state is changed.
    pub fn promote_to(
        &mut self,
        artifact_id: &ArtifactId,
        target: EvolutionRing,
    ) -> Result<Promotion, BoundaryError> {
        let (from, class, origin) = {
            let current = self.state_for(artifact_id)?;
            (current.ring, current.class, current.origin)
        };
        let expected = from.next().ok_or_else(|| BoundaryError::AlreadyActive {
            artifact_id: artifact_id.clone(),
        })?;
        if target != expected {
            return Err(BoundaryError::InvalidPromotion {
                artifact_id: artifact_id.clone(),
                from,
                attempted: target,
                expected,
            });
        }
        if let (Some(class), Some(origin)) = (class, origin) {
            if class.requires_independent_promotion() && origin.is_production_cognition() {
                return Err(BoundaryError::SelfPromotionForbidden {
                    artifact_id: artifact_id.clone(),
                    class,
                    origin,
                });
            }
        }

        let prior_active = if target == EvolutionRing::Active {
            Some(
                self.active_artifact
                    .clone()
                    .ok_or(BoundaryError::NoActiveArtifactForPromotion)?,
            )
        } else {
            None
        };

        let generation = {
            let state = self.state_for_mut(artifact_id)?;
            state.ring = target;
            state.generation = state.generation.saturating_add(1);
            if let Some(prior_active) = prior_active.as_ref() {
                state.prior_active_artifact = Some(prior_active.clone());
            }
            state.generation
        };
        if prior_active.is_some() {
            self.active_artifact = Some(artifact_id.clone());
        }
        Ok(Promotion {
            artifact_id: artifact_id.clone(),
            from,
            to: target,
            generation,
        })
    }

    /// Rolls an active candidate back to `CANARY` and restores the exact
    /// active artifact captured at the final promotion step.
    ///
    /// This is the data-only VT-012 transition. It is intentionally not a
    /// request for a learner decision: once a regression is established, the
    /// boundary restores the predecessor itself.
    pub fn rollback_on_regression(
        &mut self,
        artifact_id: &ArtifactId,
    ) -> Result<RollbackAction, BoundaryError> {
        let current = self.state_for(artifact_id)?;
        if current.ring != EvolutionRing::Active {
            return Err(BoundaryError::NotActive {
                artifact_id: artifact_id.clone(),
                observed: current.ring,
            });
        }
        let restored_artifact = current.prior_active_artifact.clone().ok_or_else(|| {
            BoundaryError::NoPriorActiveArtifact {
                artifact_id: artifact_id.clone(),
            }
        })?;

        let state = self.state_for_mut(artifact_id)?;
        state.ring = EvolutionRing::Canary;
        state.generation = state.generation.saturating_add(1);
        self.active_artifact = Some(restored_artifact.clone());
        Ok(RollbackAction::RolledBack {
            from: EvolutionRing::Active,
            to: EvolutionRing::Canary,
            restored_artifact,
        })
    }

    /// Evaluates a live metric and automatically rolls back on regression.
    ///
    /// A regression is strictly below `baseline - tolerance`; equality is
    /// tolerated. Inputs must be finite and `tolerance` cannot be negative,
    /// preventing NaN or a negative budget from silently bypassing rollback.
    pub fn auto_rollback_if_regressed(
        &mut self,
        artifact_id: &ArtifactId,
        live_metric: f64,
        baseline: f64,
        tolerance: f64,
    ) -> Result<RollbackAction, BoundaryError> {
        validate_metric("live_metric", live_metric)?;
        validate_metric("baseline", baseline)?;
        if !tolerance.is_finite() || tolerance < 0.0 {
            return Err(BoundaryError::InvalidTolerance { tolerance });
        }
        self.state_for(artifact_id)?;
        if live_metric < baseline - tolerance {
            self.rollback_on_regression(artifact_id)
        } else {
            Ok(RollbackAction::Held)
        }
    }

    fn insert(
        &mut self,
        artifact_id: ArtifactId,
        ring: EvolutionRing,
        class: Option<EvolutionClass>,
        origin: Option<ChangeOrigin>,
    ) -> Result<(), BoundaryError> {
        if self.artifacts.contains_key(&artifact_id) {
            return Err(BoundaryError::DuplicateArtifact { artifact_id });
        }
        self.artifacts.insert(
            artifact_id.clone(),
            ArtifactState {
                artifact_id,
                ring,
                class,
                origin,
                prior_active_artifact: None,
                generation: 0,
            },
        );
        Ok(())
    }

    fn state_for(&self, artifact_id: &ArtifactId) -> Result<&ArtifactState, BoundaryError> {
        self.artifacts
            .get(artifact_id)
            .ok_or_else(|| BoundaryError::UnknownArtifact {
                artifact_id: artifact_id.clone(),
            })
    }

    fn state_for_mut(
        &mut self,
        artifact_id: &ArtifactId,
    ) -> Result<&mut ArtifactState, BoundaryError> {
        self.artifacts
            .get_mut(artifact_id)
            .ok_or_else(|| BoundaryError::UnknownArtifact {
                artifact_id: artifact_id.clone(),
            })
    }
}

/// An evolution-boundary rejection or invalid metric input.
#[derive(Clone, Debug, Error, PartialEq)]
pub enum BoundaryError {
    /// The artifact failed its supply-chain verification before registration.
    #[error(transparent)]
    ArtifactVerification(#[from] ArtifactError),
    /// An artifact identity has already been registered.
    #[error("artifact {artifact_id} is already registered")]
    DuplicateArtifact {
        /// Duplicate content address.
        artifact_id: ArtifactId,
    },
    /// Only one pre-existing active artifact may be registered directly.
    #[error("an active artifact is already registered")]
    ActiveArtifactAlreadyRegistered,
    /// The referenced artifact is not managed by this boundary.
    #[error("artifact {artifact_id} is not registered")]
    UnknownArtifact {
        /// Missing content address.
        artifact_id: ArtifactId,
    },
    /// A promotion attempted to skip or reverse the fixed ring order.
    #[error(
        "invalid promotion for {artifact_id}: {from:?} -> {attempted:?}; expected {expected:?}"
    )]
    InvalidPromotion {
        /// Candidate content address.
        artifact_id: ArtifactId,
        /// Candidate's current ring.
        from: EvolutionRing,
        /// Requested ring.
        attempted: EvolutionRing,
        /// The sole legal next ring.
        expected: EvolutionRing,
    },
    /// An active artifact has no next promotion stage.
    #[error("artifact {artifact_id} is already ACTIVE")]
    AlreadyActive {
        /// Active artifact identity.
        artifact_id: ArtifactId,
    },
    /// E7/E8 cannot advance when proposed by production cognition.
    #[error(
        "self-promotion is forbidden: {class:?} artifact {artifact_id} originated from {origin:?}"
    )]
    SelfPromotionForbidden {
        /// Candidate content address.
        artifact_id: ArtifactId,
        /// Protected E7/E8 change class.
        class: EvolutionClass,
        /// Origin that may not promote this class.
        origin: ChangeOrigin,
    },
    /// A candidate cannot become active without an existing certified route to
    /// save for rollback.
    #[error("cannot promote to ACTIVE without a prior active artifact")]
    NoActiveArtifactForPromotion,
    /// Regression rollback is meaningful only for the current active artifact.
    #[error("artifact {artifact_id} is {observed:?}, not ACTIVE")]
    NotActive {
        /// Candidate content address.
        artifact_id: ArtifactId,
        /// Ring observed at rollback time.
        observed: EvolutionRing,
    },
    /// The active candidate lacks the predecessor required by VT-012.
    #[error("active artifact {artifact_id} has no saved predecessor")]
    NoPriorActiveArtifact {
        /// Candidate content address.
        artifact_id: ArtifactId,
    },
    /// A metric was NaN or infinite.
    #[error("{field} must be finite, got {value}")]
    InvalidMetric {
        /// Input field that was invalid.
        field: &'static str,
        /// Invalid value.
        value: f64,
    },
    /// Regression tolerance was negative, NaN, or infinite.
    #[error("tolerance must be finite and non-negative, got {tolerance}")]
    InvalidTolerance {
        /// Invalid tolerance.
        tolerance: f64,
    },
}

impl BoundaryError {
    /// Whether this error is the E7/E8 production self-promotion rejection.
    #[must_use]
    pub const fn is_self_promotion_forbidden(&self) -> bool {
        matches!(self, Self::SelfPromotionForbidden { .. })
    }

    /// Whether this error rejected a non-adjacent ring promotion.
    #[must_use]
    pub const fn is_invalid_promotion(&self) -> bool {
        matches!(self, Self::InvalidPromotion { .. })
    }
}

fn validate_metric(field: &'static str, value: f64) -> Result<(), BoundaryError> {
    if value.is_finite() {
        Ok(())
    } else {
        Err(BoundaryError::InvalidMetric { field, value })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(label: &str) -> ArtifactId {
        ArtifactId::of(label.as_bytes())
    }

    fn promoted_candidate(boundary: &mut EvolutionBoundary, candidate: &ArtifactId) {
        for _ in EvolutionRing::ALL.into_iter().skip(1) {
            boundary.promote(candidate).expect("promotes one ring");
        }
    }

    #[test]
    fn final_promotion_captures_the_prior_active_artifact() {
        let stable = id("stable");
        let candidate = id("candidate");
        let mut boundary = EvolutionBoundary::new();
        boundary.register_active(stable.clone()).expect("stable");
        boundary
            .register_lab(
                candidate.clone(),
                EvolutionClass::E2Workflow,
                ChangeOrigin::ReviewedHuman,
            )
            .expect("candidate");

        promoted_candidate(&mut boundary, &candidate);

        assert_eq!(boundary.active_artifact(), Some(&candidate));
        assert_eq!(
            boundary
                .artifact(&candidate)
                .expect("candidate state")
                .prior_active_artifact(),
            Some(&stable)
        );
    }

    #[test]
    fn metric_at_the_tolerance_boundary_holds() {
        let stable = id("stable");
        let candidate = id("candidate");
        let mut boundary = EvolutionBoundary::new();
        boundary.register_active(stable).expect("stable");
        boundary
            .register_lab(
                candidate.clone(),
                EvolutionClass::E1Skill,
                ChangeOrigin::ReviewedHuman,
            )
            .expect("candidate");
        promoted_candidate(&mut boundary, &candidate);

        assert_eq!(
            boundary
                .auto_rollback_if_regressed(&candidate, 0.75, 0.80, 0.05)
                .expect("valid metric"),
            RollbackAction::Held
        );
        assert_eq!(boundary.ring_of(&candidate), Some(EvolutionRing::Active));
    }

    #[test]
    fn active_candidate_requires_a_predecessor_for_promotion() {
        let candidate = id("candidate");
        let mut boundary = EvolutionBoundary::new();
        boundary
            .register_lab(
                candidate.clone(),
                EvolutionClass::E1Skill,
                ChangeOrigin::ReviewedHuman,
            )
            .expect("candidate");
        for _ in 0..3 {
            boundary.promote(&candidate).expect("pre-active promotion");
        }

        assert_eq!(
            boundary.promote(&candidate),
            Err(BoundaryError::NoActiveArtifactForPromotion)
        );
        assert_eq!(boundary.ring_of(&candidate), Some(EvolutionRing::Canary));
    }
}
