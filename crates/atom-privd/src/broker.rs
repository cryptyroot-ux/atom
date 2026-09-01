//! The privilege broker: the one gate host operations cross (KRN-002).
//!
//! The broker owns its [`HostExecutor`] privately and never lends it out
//! mutably, so the only path that can run a [`HostOp`] against the host is
//! [`PrivilegeBroker::admit`] — and `admit` runs it only after a
//! [`atom_effect::CommitPermit`] has been spent through the real one-shot
//! [`NonceRegistry`]. There is, by construction, no code path that reaches the
//! executor without first burning a valid permit.
//!
//! `admit` layers its own deny-by-default checks *before* the permit is spent,
//! so a malformed op, an operation the grant never allowed, or a permit aimed
//! at another resource is refused without burning anything: the permit is still
//! good once the caller fixes the request.

use atom_capability::CapabilityGrant;
use atom_effect::{CommitPermit, EffectIntent};
use atom_effect::{ConsumeRequest, NonceRegistry, PermitError, ResourceWitness};
use chrono::{DateTime, Utc};
use thiserror::Error;

use crate::executor::{ExecError, HostExecutor, OpOutcome};
use crate::op::{HostOp, OpError};

/// A single request to cross the privilege boundary.
///
/// Every value the boundary is checked against is supplied here, including
/// `now`: the broker reads no clock, so an identical request always yields an
/// identical decision.
#[derive(Clone, Debug)]
pub struct AdmissionRequest<'a> {
    /// The typed operation being requested.
    pub op: &'a HostOp,
    /// The permit that claims to authorise it.
    pub permit: &'a CommitPermit,
    /// The effect the permit was issued for, as it stands now.
    pub intent: &'a EffectIntent,
    /// The grant the authority is drawn from, as it stands now.
    pub grant: &'a CapabilityGrant,
    /// The resource version observed at the boundary.
    pub observed_witness: &'a ResourceWitness,
    /// The instant of the crossing; supplied, never read from a clock.
    pub now: DateTime<Utc>,
}

/// The record of an operation that crossed the boundary and reached the host.
///
/// It names the spent permit, so the crossing can be tied in the ledger to the
/// one-shot nonce that authorised it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Admitted {
    /// What the host reported.
    pub outcome: OpOutcome,
    /// The permit that was spent to admit the op.
    pub permit_id: String,
    /// The nonce burned in doing so.
    pub one_shot_nonce: String,
}

/// Why a crossing was refused.
///
/// The first four variants are the broker's own deny-by-default checks, run and
/// reported *before* any permit is spent. [`DenyReason::PermitRejected`] is the
/// commit gate's own refusal, and [`DenyReason::ExecutionFailed`] is a host-side
/// failure *after* a valid crossing — the permit is already spent by then.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum DenyReason {
    /// The op failed its own schema check, so it never named a real resource.
    #[error("operation is not well-formed: {0}")]
    InvalidOp(#[source] OpError),
    /// The grant does not allow the operation the op requires.
    #[error("grant does not allow operation `{operation}`")]
    OperationNotGranted {
        /// The operation the op needed.
        operation: String,
    },
    /// The grant does not cover the resource the op targets.
    #[error("grant does not cover {resource_type} `{resource_id}`")]
    ResourceNotGranted {
        /// The type of the resource the op targets.
        resource_type: String,
        /// The resource itself.
        resource_id: String,
    },
    /// The permit is bound to a different resource than the op targets.
    #[error("permit is bound to `{permit_resource}`, not `{op_resource}`")]
    PermitResourceMismatch {
        /// The resource the permit was issued for.
        permit_resource: String,
        /// The resource the op targets.
        op_resource: String,
    },
    /// The commit gate refused to spend the permit (EFX-004, ATOM-VT-003).
    #[error("permit refused at the commit boundary: {0}")]
    PermitRejected(#[source] PermitError),
    /// The host failed the op *after* a valid crossing spent the permit.
    #[error(transparent)]
    ExecutionFailed(#[from] ExecError),
}

/// The one gate between the unprivileged runtime and the host (KRN-002).
///
/// Owns an executor it never exposes mutably and the burned-nonce registry that
/// makes permits one-shot. Because the executor is private, [`Self::admit`] is
/// the sole caller of [`HostExecutor::execute`].
#[derive(Clone, Debug)]
pub struct PrivilegeBroker<E: HostExecutor> {
    executor: E,
    nonces: NonceRegistry,
}

impl<E: HostExecutor> PrivilegeBroker<E> {
    /// A broker over `executor`, with no permits yet spent.
    #[must_use]
    pub fn new(executor: E) -> Self {
        Self {
            executor,
            nonces: NonceRegistry::new(),
        }
    }

    /// A shared view of the executor, for inspection only — never mutable.
    ///
    /// Handing out `&E` and never `&mut E` is what makes `admit` the sole path
    /// to [`HostExecutor::execute`].
    #[must_use]
    pub fn executor(&self) -> &E {
        &self.executor
    }

    /// How many permits this broker has spent.
    #[must_use]
    pub fn spent(&self) -> usize {
        self.nonces.len()
    }

    /// Admits `request` across the privilege boundary, or refuses it.
    ///
    /// The order is deliberate: every deny-by-default check that could refuse a
    /// well-formed permit runs *first*, so a mismatch never burns a good permit.
    /// Only once the op is well-formed, allowed by the grant, and aimed at the
    /// permit's own resource is the permit spent through the real one-shot
    /// registry — and only a spent permit reaches the executor.
    ///
    /// # Errors
    ///
    /// A [`DenyReason`] naming the first check that refused: a malformed op, an
    /// operation or resource the grant does not cover, a permit bound elsewhere,
    /// the commit gate's own refusal, or a host-side failure after a valid
    /// crossing.
    pub fn admit(&mut self, request: AdmissionRequest<'_>) -> Result<Admitted, DenyReason> {
        let AdmissionRequest {
            op,
            permit,
            intent,
            grant,
            observed_witness,
            now,
        } = request;

        // 1. Deny-by-default: an op that fails its own schema never named a
        //    resource, so there is nothing to authorise.
        op.validate().map_err(DenyReason::InvalidOp)?;

        // 2. The grant must allow the operation this op requires. Re-checked
        //    here because the commit gate's consume path does not: a permit
        //    carries no operation of its own.
        let operation = op.operation();
        if !grant.operations.iter().any(|granted| granted == operation) {
            return Err(DenyReason::OperationNotGranted {
                operation: operation.to_owned(),
            });
        }

        // 3. The grant must cover the exact resource this op targets.
        let resource_type = op.resource_type();
        let resource_id = op.resource_id();
        let covered = grant.resources.iter().any(|selector| {
            selector.resource_type == resource_type && selector.resource_id == resource_id
        });
        if !covered {
            return Err(DenyReason::ResourceNotGranted {
                resource_type: resource_type.to_owned(),
                resource_id,
            });
        }

        // 4. The permit is bound to one resource. It cannot be redirected to
        //    another the grant happens to cover, even before it is spent.
        if permit.resource_id() != resource_id {
            return Err(DenyReason::PermitResourceMismatch {
                permit_resource: permit.resource_id().to_owned(),
                op_resource: resource_id,
            });
        }

        // 5. Spend the permit through the *real* one-shot registry, which
        //    re-runs every issuance check (authority, witness, digest, window)
        //    against the values the permit froze. A refusal burns nothing.
        let permitted = self
            .nonces
            .consume(ConsumeRequest {
                permit,
                intent,
                grant,
                observed_witness,
                now,
            })
            .map_err(DenyReason::PermitRejected)?;

        // 6. Only now — permit spent — does the op reach the host. A failure
        //    here is not a boundary denial: the crossing already happened.
        let outcome = self.executor.execute(op)?;
        Ok(Admitted {
            outcome,
            permit_id: permitted.permit_id,
            one_shot_nonce: permitted.one_shot_nonce,
        })
    }
}
