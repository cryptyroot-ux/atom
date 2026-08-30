//! atom-worker: an isolated execution unit bound to exactly one capability
//! grant, with no ambient authority and deny-by-default operation admission.
//!
//! Normative source is `spec/` (precedence 1):
//!
//! * **WKR-001** (TASK invariant): a worker is an isolated execution unit,
//!   bound to a capability grant — no ambient authority.
//! * **KRN-001 / INV-003** (`requirements.yaml`): every consequential action
//!   traverses typed capability authorization; authority is never assumed.
//! * **ATOM-VT-005** (`acceptance/catalog.yaml`): authority cannot be widened;
//!   an operation the bound grant does not carry is denied.
//!
//! The single rule this crate enforces is that a worker's authority *is* its
//! bound grant and nothing else. There is no "default" operation, no fallback
//! to a caller's identity, no way to act while the grant is inactive. Every
//! operation is checked against the grant with [`atom_capability::validate_grant`]
//! plus a membership test, and anything not explicitly granted is refused.

#![forbid(unsafe_code)]

use atom_capability::{validate_grant, CapabilityError, CapabilityGrant};
use thiserror::Error;

/// Why a worker refused to run an operation (WKR-001, deny-by-default).
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum WorkerError {
    /// The bound grant is not currently usable (revoked, expired, not yet valid).
    #[error("worker `{worker_id}` grant is not usable: {source}")]
    GrantUnusable {
        /// The worker whose grant failed validation.
        worker_id: String,
        /// The capability-layer reason.
        #[source]
        source: CapabilityError,
    },
    /// The operation is not one the bound grant carries — deny-by-default.
    ///
    /// This is the core WKR-001 refusal: absence of a grant for an operation is
    /// a denial, never a silent allow.
    #[error("worker `{worker_id}` is not granted operation `{operation}` (deny-by-default)")]
    OperationNotGranted {
        /// The worker that refused.
        worker_id: String,
        /// The operation that was attempted.
        operation: String,
    },
    /// The operation targeted a resource the bound grant does not cover.
    #[error("worker `{worker_id}` grant does not cover {resource_type}:{resource_id}")]
    ResourceNotGranted {
        /// The worker that refused.
        worker_id: String,
        /// The type of the resource attempted.
        resource_type: String,
        /// The resource attempted.
        resource_id: String,
    },
    /// A caller tried to bind a worker to a grant issued to another subject.
    ///
    /// This blocks ambient authority: a worker cannot borrow a grant that was
    /// not issued for its own identity.
    #[error("grant subject `{grant_subject}` does not match worker subject `{worker_subject}`")]
    SubjectMismatch {
        /// The subject the grant was issued to.
        grant_subject: String,
        /// The subject the worker runs as.
        worker_subject: String,
    },
}

/// A request to run one operation on one resource inside a worker.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkRequest<'a> {
    /// The operation to perform.
    pub operation: &'a str,
    /// The type of the resource it acts on.
    pub resource_type: &'a str,
    /// The resource it acts on.
    pub resource_id: &'a str,
}

impl<'a> WorkRequest<'a> {
    /// A request to run `operation` on `resource_type`:`resource_id`.
    #[must_use]
    pub fn new(operation: &'a str, resource_type: &'a str, resource_id: &'a str) -> Self {
        Self {
            operation,
            resource_type,
            resource_id,
        }
    }
}

/// Proof that a worker admitted an operation against its bound grant.
///
/// Only [`Worker::admit`] constructs this, so possessing one means the grant
/// was validated and the operation and resource were both covered.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedWork {
    worker_id: String,
    grant_id: String,
    operation: String,
    resource_type: String,
    resource_id: String,
}

impl AdmittedWork {
    /// The worker that admitted the work.
    #[must_use]
    pub fn worker_id(&self) -> &str {
        &self.worker_id
    }

    /// The grant the authority came from.
    #[must_use]
    pub fn grant_id(&self) -> &str {
        &self.grant_id
    }

    /// The admitted operation.
    #[must_use]
    pub fn operation(&self) -> &str {
        &self.operation
    }

    /// The resource type it acts on.
    #[must_use]
    pub fn resource_type(&self) -> &str {
        &self.resource_type
    }

    /// The resource it acts on.
    #[must_use]
    pub fn resource_id(&self) -> &str {
        &self.resource_id
    }
}

/// An isolated execution unit bound to exactly one capability grant (WKR-001).
///
/// The worker holds no authority of its own. Its `subject_id` is the identity
/// it runs as; a grant may be bound only if it was issued to that same subject,
/// which is what prevents a worker from borrowing ambient authority.
#[derive(Clone, Debug)]
pub struct Worker {
    worker_id: String,
    subject_id: String,
    grant: CapabilityGrant,
}

impl Worker {
    /// Binds `grant` to a worker `worker_id` running as `subject_id`.
    ///
    /// The bind is the isolation boundary: the worker can never do more than
    /// the grant allows, and the grant must belong to the worker's own subject.
    ///
    /// # Errors
    ///
    /// [`WorkerError::SubjectMismatch`] if the grant was issued to a different
    /// subject — a worker cannot run on someone else's authority.
    pub fn bind(
        worker_id: &str,
        subject_id: &str,
        grant: CapabilityGrant,
    ) -> Result<Self, WorkerError> {
        if grant.subject_id != subject_id {
            return Err(WorkerError::SubjectMismatch {
                grant_subject: grant.subject_id,
                worker_subject: subject_id.to_owned(),
            });
        }
        Ok(Self {
            worker_id: worker_id.to_owned(),
            subject_id: subject_id.to_owned(),
            grant,
        })
    }

    /// The worker's identity.
    #[must_use]
    pub fn worker_id(&self) -> &str {
        &self.worker_id
    }

    /// The subject the worker runs as.
    #[must_use]
    pub fn subject_id(&self) -> &str {
        &self.subject_id
    }

    /// The single grant this worker is bound to.
    #[must_use]
    pub fn grant(&self) -> &CapabilityGrant {
        &self.grant
    }

    /// Admits one operation, or refuses it (WKR-001, deny-by-default).
    ///
    /// The checks, in order:
    ///
    /// 1. The bound grant must be currently usable (active, in its window).
    /// 2. The operation must be one the grant explicitly lists.
    /// 3. The resource must be covered by one of the grant's selectors, where a
    ///    `*` selector is a wildcard.
    ///
    /// Anything not explicitly granted is denied. There is no path that reaches
    /// an effect without passing all three.
    ///
    /// # Errors
    ///
    /// [`WorkerError::GrantUnusable`], [`WorkerError::OperationNotGranted`], or
    /// [`WorkerError::ResourceNotGranted`] naming what was refused.
    pub fn admit(&self, request: &WorkRequest<'_>) -> Result<AdmittedWork, WorkerError> {
        // 1. The grant itself must be live. A worker never acts on a dead grant.
        validate_grant(&self.grant).map_err(|source| WorkerError::GrantUnusable {
            worker_id: self.worker_id.clone(),
            source,
        })?;

        // 2. Deny-by-default: the operation must be explicitly present.
        if !self.grant.operations.iter().any(|op| op == request.operation) {
            return Err(WorkerError::OperationNotGranted {
                worker_id: self.worker_id.clone(),
                operation: request.operation.to_owned(),
            });
        }

        // 3. The resource must be covered by a selector ("*" is a wildcard).
        let covered = self.grant.resources.iter().any(|selector| {
            (selector.resource_type == "*" || selector.resource_type == request.resource_type)
                && (selector.resource_id == "*" || selector.resource_id == request.resource_id)
        });
        if !covered {
            return Err(WorkerError::ResourceNotGranted {
                worker_id: self.worker_id.clone(),
                resource_type: request.resource_type.to_owned(),
                resource_id: request.resource_id.to_owned(),
            });
        }

        Ok(AdmittedWork {
            worker_id: self.worker_id.clone(),
            grant_id: self.grant.grant_id.clone(),
            operation: request.operation.to_owned(),
            resource_type: request.resource_type.to_owned(),
            resource_id: request.resource_id.to_owned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use atom_capability::{Budget, CapabilityGrant, ResourceSelector, RevocationState};
    use chrono::{Duration, Utc};

    fn grant_for(
        subject: &str,
        ops: &[&str],
        resources: Vec<ResourceSelector>,
        state: RevocationState,
    ) -> CapabilityGrant {
        let now = Utc::now();
        CapabilityGrant {
            grant_id: "grant-1".into(),
            subject_id: subject.into(),
            workload_id: "w1".into(),
            operations: ops.iter().map(|s| (*s).to_owned()).collect(),
            resources,
            purpose: "test".into(),
            not_before: now - Duration::minutes(1),
            expires_at: now + Duration::hours(1),
            budget: Budget {
                max_cost: 1000,
                max_seconds: 3600,
            },
            delegation_depth: 3,
            audience: "test".into(),
            generation: 1,
            revocation_state: state,
            parent_grant_id: None,
            nonce: None,
            constraints: None,
        }
    }

    fn scoped(resource_type: &str, resource_id: &str) -> Vec<ResourceSelector> {
        vec![ResourceSelector {
            resource_type: resource_type.into(),
            resource_id: resource_id.into(),
        }]
    }

    // ─── WKR-001: no grant for the operation → DENY (deny-by-default) ────────
    #[test]
    fn ungranted_operation_is_denied() {
        let grant = grant_for("s1", &["read"], scoped("db", "row-1"), RevocationState::Active);
        let worker = Worker::bind("wkr-1", "s1", grant).expect("binds");
        // "write" is not in the grant → deny.
        let err = worker
            .admit(&WorkRequest::new("write", "db", "row-1"))
            .unwrap_err();
        assert!(matches!(err, WorkerError::OperationNotGranted { .. }));
    }

    #[test]
    fn granted_operation_on_covered_resource_is_admitted() {
        let grant = grant_for(
            "s1",
            &["read", "write"],
            scoped("db", "row-1"),
            RevocationState::Active,
        );
        let worker = Worker::bind("wkr-1", "s1", grant).expect("binds");
        let admitted = worker
            .admit(&WorkRequest::new("write", "db", "row-1"))
            .expect("granted op should admit");
        assert_eq!(admitted.operation(), "write");
        assert_eq!(admitted.grant_id(), "grant-1");
    }

    #[test]
    fn ungranted_resource_is_denied() {
        let grant = grant_for("s1", &["write"], scoped("db", "row-1"), RevocationState::Active);
        let worker = Worker::bind("wkr-1", "s1", grant).expect("binds");
        // resource row-2 is not covered.
        let err = worker
            .admit(&WorkRequest::new("write", "db", "row-2"))
            .unwrap_err();
        assert!(matches!(err, WorkerError::ResourceNotGranted { .. }));
    }

    // ─── no ambient authority: worker cannot borrow another subject's grant ──
    #[test]
    fn cannot_bind_grant_of_another_subject() {
        let grant = grant_for("other", &["read"], scoped("db", "row-1"), RevocationState::Active);
        let err = Worker::bind("wkr-1", "s1", grant).unwrap_err();
        assert!(matches!(err, WorkerError::SubjectMismatch { .. }));
    }

    // ─── a revoked grant cannot be used, even for a granted op ───────────────
    #[test]
    fn revoked_grant_cannot_act() {
        let grant = grant_for(
            "s1",
            &["read"],
            scoped("db", "row-1"),
            RevocationState::Revoked,
        );
        let worker = Worker::bind("wkr-1", "s1", grant).expect("bind checks subject, not liveness");
        let err = worker
            .admit(&WorkRequest::new("read", "db", "row-1"))
            .unwrap_err();
        assert!(matches!(err, WorkerError::GrantUnusable { .. }));
    }

    #[test]
    fn wildcard_resource_selector_covers_any_resource() {
        let grant = grant_for(
            "s1",
            &["read"],
            vec![ResourceSelector {
                resource_type: "*".into(),
                resource_id: "*".into(),
            }],
            RevocationState::Active,
        );
        let worker = Worker::bind("wkr-1", "s1", grant).expect("binds");
        assert!(worker
            .admit(&WorkRequest::new("read", "anything", "at-all"))
            .is_ok());
    }

    #[test]
    fn empty_grant_denies_everything() {
        // A worker bound to a grant with no operations can do nothing.
        let grant = grant_for("s1", &[], scoped("db", "row-1"), RevocationState::Active);
        let worker = Worker::bind("wkr-1", "s1", grant).expect("binds");
        let err = worker
            .admit(&WorkRequest::new("read", "db", "row-1"))
            .unwrap_err();
        assert!(matches!(err, WorkerError::OperationNotGranted { .. }));
    }
}
