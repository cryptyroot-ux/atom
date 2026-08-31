//! atom-evolution: the evolution-safety contract for ATOM (G7 Evolution Proof).
//!
//! Normative sources (`spec/`, precedence 1):
//!
//! * **ATOM-EVO-001** — Adaptive artifacts MUST move through
//!   `Lab -> Simulation -> Shadow -> Canary -> Active` and support automatic
//!   downgrade/rollback on regression.
//! * **ATOM-EVO-002** — E7 trusted-core changes and E8 authority/policy
//!   expansion MUST NOT self-promote from production cognition.
//! * **ATOM-INV-003 / INV-012** — Delegation/evolution can only *attenuate*
//!   authority; child authority is never broader than parent, and resource
//!   pressure, urgency, model recommendation, or repeated success never
//!   increases authority. Enforced by reusing `atom_capability::subset_check`.
//!
//! This is real, tested code — not a G0 skeleton.

#![forbid(unsafe_code)]

use std::fmt;

use atom_capability::{subset_check, CapabilityGrant};
use serde::{Deserialize, Serialize};

/// The promotion lifecycle for an adaptive artifact (EVO-001).
/// Ordered: each stage is strictly less trusted than the next.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Stage {
    Lab,
    Simulation,
    Shadow,
    Canary,
    Active,
}

impl Stage {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Stage::Lab => "lab",
            Stage::Simulation => "simulation",
            Stage::Shadow => "shadow",
            Stage::Canary => "canary",
            Stage::Active => "active",
        }
    }

    /// The next stage forward, if any.
    #[must_use]
    pub fn next(self) -> Option<Stage> {
        match self {
            Stage::Lab => Some(Stage::Simulation),
            Stage::Simulation => Some(Stage::Shadow),
            Stage::Shadow => Some(Stage::Canary),
            Stage::Canary => Some(Stage::Active),
            Stage::Active => None,
        }
    }
}

/// An adaptive artifact under evolution control.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdaptiveArtifact {
    pub id: String,
    pub stage: Stage,
    /// The stage this artifact was promoted from (None at Lab).
    pub promoted_from: Option<Stage>,
    /// Monotonic generation counter; bumped on every promotion/demotion.
    pub generation: u64,
    /// Why the current stage holds (audit trail).
    pub reason: String,
}

impl AdaptiveArtifact {
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            stage: Stage::Lab,
            promoted_from: None,
            generation: 0,
            reason: "created in lab".into(),
        }
    }

    /// Promote exactly one stage forward. Fails if `to` is not the immediate
    /// next stage (no skipping the pipeline, and Active is terminal).
    pub fn promote(&self, to: Stage, reason: impl Into<String>) -> Result<Self, EvolutionError> {
        match self.stage.next() {
            Some(next) if next == to => Ok(Self {
                id: self.id.clone(),
                stage: to,
                promoted_from: Some(self.stage),
                generation: self.generation + 1,
                reason: reason.into(),
            }),
            Some(next) => Err(EvolutionError::InvalidPromotion {
                from: self.stage,
                attempted: to,
                expected: next,
            }),
            None => Err(EvolutionError::AlreadyActive(self.stage)),
        }
    }

    /// Demote (rollback) to a strictly lower stage on regression. Fails if `to`
    /// is not lower than the current stage.
    pub fn demote(&self, to: Stage, reason: impl Into<String>) -> Result<Self, EvolutionError> {
        if to >= self.stage {
            return Err(EvolutionError::InvalidDemotion {
                from: self.stage,
                attempted: to,
            });
        }
        Ok(Self {
            id: self.id.clone(),
            stage: to,
            promoted_from: Some(self.stage),
            generation: self.generation + 1,
            reason: reason.into(),
        })
    }

    /// Automatic rollback: if the live metric regressed beyond `tolerance`
    /// versus the `baseline` captured at promotion, drop to the previous stage.
    /// Returns the (possibly unchanged) artifact and what action was taken.
    #[must_use]
    pub fn auto_rollback_if_regressed(
        &self,
        live_metric: f64,
        baseline: f64,
        tolerance: f64,
    ) -> (Self, RollbackAction) {
        let regression = live_metric < baseline - tolerance;
        if regression && self.stage != Stage::Lab {
            let target = self.promoted_from.unwrap_or(Stage::Lab);
            let rolled = self
                .demote(
                    target,
                    format!(
                        "auto-rollback: live {live_metric:.4} < baseline {baseline:.4} - tol {tolerance:.4}"
                    ),
                )
                .unwrap_or_else(|_| self.clone());
            (rolled, RollbackAction::RolledBack { to: target })
        } else {
            (self.clone(), RollbackAction::Held)
        }
    }
}

/// What auto-rollback decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RollbackAction {
    Held,
    RolledBack { to: Stage },
}

/// Classification of a proposed self-change (EVO-002).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChangeClass {
    /// E7: change to the trusted core (kernel, ledger, cert, capability).
    TrustedCore,
    /// E8: authority / policy expansion.
    AuthorityPolicy,
    /// New capability or behavior, bounded by existing authority.
    Capability,
    /// Pure behavior tuning within current authority.
    Behavior,
}

/// Where a proposed change originated.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChangeOrigin {
    /// Produced by production cognition (the running agent itself).
    ProductionCognition,
    /// Produced by a reviewed, human-authored process.
    ReviewedHuman,
}

/// A proposed self-modification under evolution control.
#[derive(Clone, Debug)]
pub struct ProposedChange {
    pub class: ChangeClass,
    pub origin: ChangeOrigin,
    /// For authority-affecting changes: the parent grant already held, and the
    /// child grant the change would introduce. Used to enforce INV-003/012.
    pub parent_grant: Option<CapabilityGrant>,
    pub child_grant: Option<CapabilityGrant>,
}

impl ProposedChange {
    /// Assert this change does NOT self-promote (EVO-002) and does NOT expand
    /// authority (INV-003/012).
    pub fn assert_no_self_promotion(&self) -> Result<(), EvolutionError> {
        // EVO-002: trusted-core (E7) or authority/policy (E8) changes MUST NOT
        // self-promote from production cognition.
        let forbidden_class = matches!(
            self.class,
            ChangeClass::TrustedCore | ChangeClass::AuthorityPolicy
        );
        if forbidden_class && self.origin == ChangeOrigin::ProductionCognition {
            return Err(EvolutionError::SelfPromotionForbidden {
                class: self.class,
                origin: self.origin,
            });
        }
        // INV-003 / INV-012: if the change introduces a child grant, it must be
        // a strict subset of the parent. Authority can only attenuate.
        if let (Some(parent), Some(child)) = (&self.parent_grant, &self.child_grant) {
            subset_check(parent, child)
                .map_err(|e| EvolutionError::AuthorityExpansion(e.to_string()))?;
        }
        Ok(())
    }
}

/// Evolution-safety violation.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum EvolutionError {
    #[error("invalid promotion {from:?} -> {attempted:?}; expected next stage {expected:?}")]
    InvalidPromotion {
        from: Stage,
        attempted: Stage,
        expected: Stage,
    },
    #[error("artifact already at terminal stage {0:?}")]
    AlreadyActive(Stage),
    #[error("invalid demotion {from:?} -> {attempted:?}; target must be lower")]
    InvalidDemotion { from: Stage, attempted: Stage },
    #[error("EVO-002 violation: {class:?} change from {origin:?} may not self-promote")]
    SelfPromotionForbidden {
        class: ChangeClass,
        origin: ChangeOrigin,
    },
    #[error("INV-003/012 authority expansion rejected: {0}")]
    AuthorityExpansion(String),
}

// `thiserror::Error` already provides `Display` + `std::error::Error`; the
// manual impls below are only needed if a non-`thiserror` build is used.
#[allow(dead_code)]
fn _display_shim(e: &EvolutionError, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{e}")
}
