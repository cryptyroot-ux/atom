//! Deterministic restore fencing and adaptive-route rollback.
//!
//! Local mode is useful for a single instance but deliberately makes no
//! clone-proof split-brain claim. Fenced mode instead receives an injected
//! external lease/epoch connector and rechecks its current lease at every
//! authorization attempt. This crate is an additional restore fence; it does
//! not replace atom-kernel's effect/authority commit gates.
//!
//! The connector crate currently defines only its contract marker. The
//! [`LeaseConnector`] adapter below is therefore the narrow lease/epoch surface
//! that a concrete atom-connector implementation must satisfy.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use thiserror::Error;

/// Implementation maturity marker.
pub const CRATE_STAGE: &str = "G1-deterministic-restore-fencing";

/// Version marker for the connector contract this adapter is designed around.
pub const CONNECTOR_CONTRACT_STAGE: &str = atom_connector::CRATE_STAGE;

/// An externally coordinated authority epoch.
///
/// This is data supplied by the lease connector, never generated from a clock.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AuthorityEpoch(u64);

impl AuthorityEpoch {
    /// Wraps a connector-issued epoch.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the connector-issued epoch value.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }
}

/// An externally witnessed lease held by one instance at one epoch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExternalLease {
    authority_id: String,
    holder_id: String,
    epoch: AuthorityEpoch,
}

impl ExternalLease {
    /// Creates a validated externally issued lease witness.
    ///
    /// Concrete connectors should construct this only after their external
    /// coordination system has issued or read the lease.
    pub fn new(
        authority_id: impl Into<String>,
        holder_id: impl Into<String>,
        epoch: AuthorityEpoch,
    ) -> Result<Self, RestoreError> {
        let authority_id = authority_id.into();
        let holder_id = holder_id.into();
        validate_identifier("authority_id", &authority_id)?;
        validate_identifier("holder_id", &holder_id)?;
        Ok(Self {
            authority_id,
            holder_id,
            epoch,
        })
    }

    /// Authority namespace fenced by this lease.
    #[must_use]
    pub fn authority_id(&self) -> &str {
        &self.authority_id
    }

    /// External holder identity of this lease.
    #[must_use]
    pub fn holder_id(&self) -> &str {
        &self.holder_id
    }

    /// Connector-issued authority epoch.
    #[must_use]
    pub const fn epoch(&self) -> AuthorityEpoch {
        self.epoch
    }
}

/// Error reported by an injected external lease connector.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("lease connector error: {message}")]
pub struct LeaseConnectorError {
    message: String,
}

impl LeaseConnectorError {
    /// Creates an operator-safe connector error.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// Returns the connector's operator-safe error text.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

/// Injected external lease/epoch read boundary.
///
/// A connector implementation is responsible for making `current_lease`
/// externally coordinated. [`FencedRestore`] performs no local epoch minting
/// and cannot fall back to a local answer when this call fails.
pub trait LeaseConnector {
    /// Reads the externally current lease for one authority namespace.
    fn current_lease(&mut self, authority_id: &str) -> Result<ExternalLease, LeaseConnectorError>;
}

/// Operational restore mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RestoreMode {
    /// Single-instance local operation with no clone-proof guarantee.
    Local,
    /// External lease/epoch fencing is required before commit authorization.
    Fenced,
}

/// Truthful split-brain safety status exposed by a restore mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SplitBrainSafety {
    /// Local state alone cannot prove cloned instances are mutually excluded.
    Unsupported,
    /// An injected external lease/epoch connector is checked for every commit.
    ExternallyFenced,
}

/// Local restore mode.
///
/// It may be appropriate for a single local process, but it has no evidence to
/// make a clone-proof split-brain safety claim.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LocalRestore;

impl LocalRestore {
    /// Creates local restore mode.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Returns the explicit local restore mode.
    #[must_use]
    pub const fn mode(&self) -> RestoreMode {
        RestoreMode::Local
    }

    /// Reports the only truthful local split-brain safety status.
    #[must_use]
    pub const fn split_brain_safety(&self) -> SplitBrainSafety {
        SplitBrainSafety::Unsupported
    }

    /// Refuses a clone-proof split-brain safety claim in local mode.
    pub fn claim_clone_proof_split_brain_safety(&self) -> Result<(), RestoreError> {
        Err(RestoreError::LocalModeCannotClaimCloneProofSafety)
    }
}

/// Fenced restore mode backed by an injected external connector.
pub struct FencedRestore<C> {
    authority_id: String,
    connector: C,
}

impl<C> FencedRestore<C> {
    /// Creates a fenced restore authority for one external authority namespace.
    pub fn new(authority_id: impl Into<String>, connector: C) -> Result<Self, RestoreError> {
        let authority_id = authority_id.into();
        validate_identifier("authority_id", &authority_id)?;
        Ok(Self {
            authority_id,
            connector,
        })
    }

    /// Returns the explicit fenced restore mode.
    #[must_use]
    pub const fn mode(&self) -> RestoreMode {
        RestoreMode::Fenced
    }

    /// Reports that commits are guarded by an external fence.
    #[must_use]
    pub const fn split_brain_safety(&self) -> SplitBrainSafety {
        SplitBrainSafety::ExternallyFenced
    }

    /// Authority namespace checked against the connector.
    #[must_use]
    pub fn authority_id(&self) -> &str {
        &self.authority_id
    }

    /// Read-only access to the injected connector.
    #[must_use]
    pub fn connector(&self) -> &C {
        &self.connector
    }

    /// Mutable access to the injected connector for connection management.
    pub fn connector_mut(&mut self) -> &mut C {
        &mut self.connector
    }

    /// Unwraps the injected connector.
    #[must_use]
    pub fn into_connector(self) -> C {
        self.connector
    }
}

impl<C: LeaseConnector> FencedRestore<C> {
    /// Rechecks the external lease and authorizes only its current epoch/holder.
    ///
    /// The returned witness is not a kernel commit permit. Callers must still
    /// traverse atom-kernel before a consequential mutation. A connector error
    /// is a denial; fenced mode never substitutes a local epoch.
    pub fn authorize_commit(
        &mut self,
        presented: &ExternalLease,
    ) -> Result<FencedCommit, RestoreError> {
        if presented.authority_id != self.authority_id {
            return Err(RestoreError::LeaseAuthorityMismatch {
                expected: self.authority_id.clone(),
                observed: presented.authority_id.clone(),
            });
        }

        let current = self.connector.current_lease(&self.authority_id)?;
        if current.authority_id != self.authority_id {
            return Err(RestoreError::ConnectorAuthorityMismatch {
                expected: self.authority_id.clone(),
                observed: current.authority_id,
            });
        }
        if presented.epoch != current.epoch {
            return Err(RestoreError::StaleEpoch {
                presented: presented.epoch,
                current: current.epoch,
            });
        }
        if presented.holder_id != current.holder_id {
            return Err(RestoreError::LeaseHolderMismatch {
                expected: current.holder_id,
                observed: presented.holder_id.clone(),
            });
        }

        Ok(FencedCommit {
            authority_id: self.authority_id.clone(),
            holder_id: current.holder_id,
            epoch: current.epoch,
        })
    }
}

/// Proof that one restore authorization observed the current external fence.
///
/// This is deliberately distinct from atom-kernel's commit token and is only
/// evidence that the restore epoch check passed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FencedCommit {
    authority_id: String,
    holder_id: String,
    epoch: AuthorityEpoch,
}

impl FencedCommit {
    /// Namespace that was externally fenced.
    #[must_use]
    pub fn authority_id(&self) -> &str {
        &self.authority_id
    }

    /// Holder observed as current by the connector.
    #[must_use]
    pub fn holder_id(&self) -> &str {
        &self.holder_id
    }

    /// Epoch observed as current by the connector.
    #[must_use]
    pub const fn epoch(&self) -> AuthorityEpoch {
        self.epoch
    }
}

/// Lifecycle ring for an adaptive artifact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArtifactRing {
    /// Experimental artifact with no production route.
    Lab,
    /// Simulation-qualified artifact.
    Simulation,
    /// Shadow-evaluated artifact.
    Shadow,
    /// Limited-traffic candidate.
    Canary,
    /// Live route.
    Active,
    /// Regressed route that must not receive normal promotion.
    Degraded,
    /// Explicit rollback processing state.
    Rollback,
}

impl ArtifactRing {
    /// Stable specification spelling for the ring.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Lab => "LAB",
            Self::Simulation => "SIMULATION",
            Self::Shadow => "SHADOW",
            Self::Canary => "CANARY",
            Self::Active => "ACTIVE",
            Self::Degraded => "DEGRADED",
            Self::Rollback => "ROLLBACK",
        }
    }
}

/// A route whose certificate was already verified by the caller.
///
/// The type prevents a rollback from restoring an arbitrary string: only a
/// [`CertifiedRoute`] can become the prior route held by [`ArtifactRouter`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertifiedRoute {
    artifact_id: String,
    route_id: String,
}

impl CertifiedRoute {
    /// Creates a route after the caller has verified its certificate.
    pub fn new(
        artifact_id: impl Into<String>,
        route_id: impl Into<String>,
    ) -> Result<Self, RestoreError> {
        let artifact_id = artifact_id.into();
        let route_id = route_id.into();
        validate_identifier("artifact_id", &artifact_id)?;
        validate_identifier("route_id", &route_id)?;
        Ok(Self {
            artifact_id,
            route_id,
        })
    }

    /// Artifact the route serves.
    #[must_use]
    pub fn artifact_id(&self) -> &str {
        &self.artifact_id
    }

    /// Certified route identity.
    #[must_use]
    pub fn route_id(&self) -> &str {
        &self.route_id
    }
}

/// Current routing state for one artifact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactDeployment {
    route: CertifiedRoute,
    ring: ArtifactRing,
    prior_certified_route: Option<CertifiedRoute>,
}

impl ArtifactDeployment {
    /// Artifact identity.
    #[must_use]
    pub fn artifact_id(&self) -> &str {
        self.route.artifact_id()
    }

    /// Candidate's certified route.
    #[must_use]
    pub fn route(&self) -> &CertifiedRoute {
        &self.route
    }

    /// Current adaptive lifecycle ring.
    #[must_use]
    pub const fn ring(&self) -> ArtifactRing {
        self.ring
    }

    /// Route captured before this artifact replaced the active route.
    #[must_use]
    pub fn prior_certified_route(&self) -> Option<&CertifiedRoute> {
        self.prior_certified_route.as_ref()
    }
}

/// Recorded result of a CANARY -> ACTIVE promotion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Promotion {
    artifact_id: String,
    from: ArtifactRing,
    to: ArtifactRing,
}

impl Promotion {
    /// Promoted artifact identity.
    #[must_use]
    pub fn artifact_id(&self) -> &str {
        &self.artifact_id
    }

    /// Ring before promotion.
    #[must_use]
    pub const fn from(&self) -> ArtifactRing {
        self.from
    }

    /// Ring after promotion.
    #[must_use]
    pub const fn to(&self) -> ArtifactRing {
        self.to
    }
}

/// Recorded result of an automatic regression rollback.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Rollback {
    artifact_id: String,
    from: ArtifactRing,
    to: ArtifactRing,
    restored_route: CertifiedRoute,
}

impl Rollback {
    /// Regressed artifact identity.
    #[must_use]
    pub fn artifact_id(&self) -> &str {
        &self.artifact_id
    }

    /// Ring at which the regression was observed.
    #[must_use]
    pub const fn from(&self) -> ArtifactRing {
        self.from
    }

    /// Candidate's downgraded ring after rollback.
    #[must_use]
    pub const fn to(&self) -> ArtifactRing {
        self.to
    }

    /// The route restored to live traffic.
    #[must_use]
    pub fn restored_route(&self) -> &CertifiedRoute {
        &self.restored_route
    }
}

/// Deterministic active-route registry with rollback memory.
///
/// The registry holds one live route and captures it before a CANARY promotion.
/// A later regression restores that exact captured certified route and demotes
/// the candidate to CANARY, making VT-012 a data-only transition with no clock.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ArtifactRouter {
    artifacts: BTreeMap<String, ArtifactDeployment>,
    active_route: Option<CertifiedRoute>,
}

impl ArtifactRouter {
    /// Creates an empty route registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the currently selected live certified route.
    #[must_use]
    pub fn active_route(&self) -> Option<&CertifiedRoute> {
        self.active_route.as_ref()
    }

    /// Returns an artifact's lifecycle/routing state.
    #[must_use]
    pub fn artifact(&self, artifact_id: &str) -> Option<&ArtifactDeployment> {
        self.artifacts.get(artifact_id)
    }

    /// Registers the initial active certified route.
    ///
    /// Replacing an active route must use [`Self::promote_canary`] so its prior
    /// route is captured for a later regression rollback.
    pub fn register_active(&mut self, route: CertifiedRoute) -> Result<(), RestoreError> {
        if self.active_route.is_some() {
            return Err(RestoreError::ActiveRouteAlreadyPresent);
        }
        self.insert(route.clone(), ArtifactRing::Active)?;
        self.active_route = Some(route);
        Ok(())
    }

    /// Registers a new adaptive artifact at the LAB ring.
    pub fn register_lab(&mut self, route: CertifiedRoute) -> Result<(), RestoreError> {
        self.insert(route, ArtifactRing::Lab)
    }

    /// Registers a certified candidate at the CANARY ring.
    ///
    /// This is intended for recovery of a candidate that has already completed
    /// LAB, SIMULATION, and SHADOW outside this in-memory router. New artifacts
    /// should begin with [`Self::register_lab`] and use [`Self::promote`].
    pub fn register_canary(&mut self, route: CertifiedRoute) -> Result<(), RestoreError> {
        self.insert(route, ArtifactRing::Canary)
    }

    /// Advances an artifact through the canonical promotion sequence.
    ///
    /// The only legal sequence is LAB -> SIMULATION -> SHADOW -> CANARY ->
    /// ACTIVE. The final transition captures the prior active certified route
    /// through [`Self::promote_canary`] so regression can restore it.
    pub fn promote(&mut self, artifact_id: &str) -> Result<Promotion, RestoreError> {
        let ring = self
            .artifacts
            .get(artifact_id)
            .ok_or_else(|| RestoreError::UnknownArtifact {
                artifact_id: artifact_id.to_owned(),
            })?
            .ring;
        match ring {
            ArtifactRing::Lab => {
                self.advance_ring(artifact_id, ArtifactRing::Lab, ArtifactRing::Simulation)
            }
            ArtifactRing::Simulation => {
                self.advance_ring(artifact_id, ArtifactRing::Simulation, ArtifactRing::Shadow)
            }
            ArtifactRing::Shadow => {
                self.advance_ring(artifact_id, ArtifactRing::Shadow, ArtifactRing::Canary)
            }
            ArtifactRing::Canary => self.promote_canary(artifact_id),
            ArtifactRing::Active | ArtifactRing::Degraded | ArtifactRing::Rollback => {
                Err(RestoreError::NotPromotableArtifactRing {
                    artifact_id: artifact_id.to_owned(),
                    observed: ring,
                })
            }
        }
    }

    /// Promotes a CANARY route to ACTIVE while preserving the prior route.
    pub fn promote_canary(&mut self, artifact_id: &str) -> Result<Promotion, RestoreError> {
        let prior = self
            .active_route
            .clone()
            .ok_or(RestoreError::NoActiveCertifiedRoute)?;
        let deployment =
            self.artifacts
                .get_mut(artifact_id)
                .ok_or_else(|| RestoreError::UnknownArtifact {
                    artifact_id: artifact_id.to_owned(),
                })?;
        if deployment.ring != ArtifactRing::Canary {
            return Err(RestoreError::UnexpectedArtifactRing {
                artifact_id: artifact_id.to_owned(),
                expected: ArtifactRing::Canary,
                observed: deployment.ring,
            });
        }

        deployment.ring = ArtifactRing::Active;
        deployment.prior_certified_route = Some(prior);
        self.active_route = Some(deployment.route.clone());
        Ok(Promotion {
            artifact_id: artifact_id.to_owned(),
            from: ArtifactRing::Canary,
            to: ArtifactRing::Active,
        })
    }

    /// Handles a post-promotion regression automatically.
    ///
    /// This is the VT-012 transition: an artifact promoted from CANARY to ACTIVE
    /// is downgraded to CANARY and the exact prior certified route is restored.
    pub fn rollback_on_regression(&mut self, artifact_id: &str) -> Result<Rollback, RestoreError> {
        let deployment =
            self.artifacts
                .get_mut(artifact_id)
                .ok_or_else(|| RestoreError::UnknownArtifact {
                    artifact_id: artifact_id.to_owned(),
                })?;
        if deployment.ring != ArtifactRing::Active {
            return Err(RestoreError::UnexpectedArtifactRing {
                artifact_id: artifact_id.to_owned(),
                expected: ArtifactRing::Active,
                observed: deployment.ring,
            });
        }
        let restored_route = deployment.prior_certified_route.clone().ok_or_else(|| {
            RestoreError::NoPriorCertifiedRoute {
                artifact_id: artifact_id.to_owned(),
            }
        })?;

        deployment.ring = ArtifactRing::Canary;
        self.active_route = Some(restored_route.clone());
        Ok(Rollback {
            artifact_id: artifact_id.to_owned(),
            from: ArtifactRing::Active,
            to: ArtifactRing::Canary,
            restored_route,
        })
    }

    fn insert(&mut self, route: CertifiedRoute, ring: ArtifactRing) -> Result<(), RestoreError> {
        let artifact_id = route.artifact_id.clone();
        if self.artifacts.contains_key(&artifact_id) {
            return Err(RestoreError::DuplicateArtifact { artifact_id });
        }
        self.artifacts.insert(
            artifact_id,
            ArtifactDeployment {
                route,
                ring,
                prior_certified_route: None,
            },
        );
        Ok(())
    }

    fn advance_ring(
        &mut self,
        artifact_id: &str,
        expected: ArtifactRing,
        to: ArtifactRing,
    ) -> Result<Promotion, RestoreError> {
        let deployment =
            self.artifacts
                .get_mut(artifact_id)
                .ok_or_else(|| RestoreError::UnknownArtifact {
                    artifact_id: artifact_id.to_owned(),
                })?;
        if deployment.ring != expected {
            return Err(RestoreError::UnexpectedArtifactRing {
                artifact_id: artifact_id.to_owned(),
                expected,
                observed: deployment.ring,
            });
        }
        deployment.ring = to;
        Ok(Promotion {
            artifact_id: artifact_id.to_owned(),
            from: expected,
            to,
        })
    }
}

/// Errors that prevent a truthful fence or deterministic route transition.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum RestoreError {
    /// An identifier needed for a durable/externally scoped operation was blank.
    #[error("{field} must not be blank")]
    BlankIdentifier {
        /// Invalid field name.
        field: &'static str,
    },
    /// Local mode cannot honestly make the requested safety claim.
    #[error("local restore mode cannot claim clone-proof split-brain safety")]
    LocalModeCannotClaimCloneProofSafety,
    /// The lease was presented for another authority namespace.
    #[error("lease authority is {observed}, not {expected}")]
    LeaseAuthorityMismatch {
        /// Fenced namespace configured locally.
        expected: String,
        /// Namespace named by the presented lease.
        observed: String,
    },
    /// The injected connector returned a lease for the wrong namespace.
    #[error("connector returned lease authority {observed}, not {expected}")]
    ConnectorAuthorityMismatch {
        /// Namespace requested from the connector.
        expected: String,
        /// Namespace returned by the connector.
        observed: String,
    },
    /// The presented lease is not at the current external epoch.
    #[error("stale external epoch {presented:?}; current epoch is {current:?}")]
    StaleEpoch {
        /// Epoch held by the caller.
        presented: AuthorityEpoch,
        /// Epoch currently witnessed by the external connector.
        current: AuthorityEpoch,
    },
    /// The epoch matched but the external lease holder did not.
    #[error("lease holder is {observed}, not current holder {expected}")]
    LeaseHolderMismatch {
        /// Current external holder.
        expected: String,
        /// Holder named by the caller's lease.
        observed: String,
    },
    /// The external connector could not supply a current lease.
    #[error(transparent)]
    Connector(#[from] LeaseConnectorError),
    /// A route registry already has an initial active route.
    #[error("an active certified route is already registered")]
    ActiveRouteAlreadyPresent,
    /// An artifact identity was registered more than once.
    #[error("artifact {artifact_id} is already registered")]
    DuplicateArtifact {
        /// Duplicate artifact identity.
        artifact_id: String,
    },
    /// The requested artifact is absent from the route registry.
    #[error("artifact {artifact_id} is not registered")]
    UnknownArtifact {
        /// Missing artifact identity.
        artifact_id: String,
    },
    /// A transition was attempted from a ring other than its required source.
    #[error("artifact {artifact_id} is {observed:?}, not {expected:?}")]
    UnexpectedArtifactRing {
        /// Artifact whose transition was refused.
        artifact_id: String,
        /// Required source ring.
        expected: ArtifactRing,
        /// Actual source ring.
        observed: ArtifactRing,
    },
    /// The artifact cannot advance from its current lifecycle ring.
    #[error("artifact {artifact_id} cannot promote from {observed:?}")]
    NotPromotableArtifactRing {
        /// Artifact whose promotion was refused.
        artifact_id: String,
        /// Current ring that cannot advance.
        observed: ArtifactRing,
    },
    /// A canary cannot replace a route when no prior certified route exists.
    #[error("no active certified route is available for promotion")]
    NoActiveCertifiedRoute,
    /// A regression was reported for an active artifact without a saved route.
    #[error("artifact {artifact_id} has no prior certified route to restore")]
    NoPriorCertifiedRoute {
        /// Regressed artifact identity.
        artifact_id: String,
    },
}

fn validate_identifier(field: &'static str, value: &str) -> Result<(), RestoreError> {
    if value.trim().is_empty() {
        return Err(RestoreError::BlankIdentifier { field });
    }
    Ok(())
}
