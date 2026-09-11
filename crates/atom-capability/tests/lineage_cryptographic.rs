//! Cryptographic delegation lineage enforcement (AUT-008 / INV-017 / P0).
//!
//! `subset_check` must cryptographically commit the child to the exact parent
//! artifact. Possession of the parent fields is not enough: a substituted or
//! spliced parent must be rejected even when the semantic subset is valid.

use atom_capability::{
    authority_digest_of, subset_check, Budget, CapabilityError, CapabilityGrant, ResourceSelector,
    RevocationState,
};
use chrono::{Duration, Utc};

fn base_grant() -> CapabilityGrant {
    CapabilityGrant {
        grant_id: "parent-root".into(),
        subject_id: "owner".into(),
        workload_id: "wl-root".into(),
        operations: vec!["read".into(), "write".into(), "execute".into()],
        resources: vec![ResourceSelector {
            resource_type: "server".into(),
            resource_id: "srv-alpha".into(),
        }],
        purpose: "deployment".into(),
        not_before: Utc::now(),
        expires_at: Utc::now() + Duration::hours(4),
        budget: Budget {
            max_cost: 10_000,
            max_seconds: 14_400,
        },
        delegation_depth: 10,
        audience: "ops-team".into(),
        generation: 1,
        revocation_state: RevocationState::Active,
        parent_grant_id: None,
        parent_authority_digest: None,
        holder_binding: None,
        authority_digest: None,
        nonce: None,
        constraints: None,
    }
}

/// Build a valid parent with a computed self digest set on `authority_digest`.
fn parent_with_digest() -> CapabilityGrant {
    let mut parent = base_grant();
    parent.authority_digest = Some(authority_digest_of(&parent).expect("canonicalizable"));
    parent
}

/// Build a valid child that cryptographically commits to `parent` and carries
/// a self-consistent `authority_digest`.
fn child_of(parent: &CapabilityGrant) -> CapabilityGrant {
    let mut child = parent.clone();
    child.grant_id = "child-001".into();
    child.parent_grant_id = Some(parent.grant_id.clone());
    child.delegation_depth = parent.delegation_depth - 1;
    child.parent_authority_digest = parent.authority_digest.clone();
    child.holder_binding = parent.holder_binding.clone();
    child.authority_digest = Some(authority_digest_of(&child).expect("canonicalizable"));
    child
}

#[test]
fn valid_child_with_digests_passes() {
    let parent = parent_with_digest();
    let child = child_of(&parent);
    assert!(subset_check(&parent, &child).is_ok());
}

#[test]
fn substituted_parent_splicing_is_denied() {
    // Two parents with identical semantics but different substantive content
    // (different purpose -> different digest). The child commits to parent A but
    // is checked against parent B -> splicing must be denied.
    let parent_a = parent_with_digest();

    let mut parent_b = parent_a.clone();
    parent_b.purpose = "other-purpose".into();
    parent_b.authority_digest = Some(authority_digest_of(&parent_b).expect("canonicalizable"));

    // Child commits cryptographically to parent_a.
    let mut child = child_of(&parent_a);

    // Attack: attacker rewrites the child to point at parent_b with parent_b's
    // grant_id (so the semantic parent_grant_id check passes) but WITH the
    // digest commitment to parent_a.
    child.parent_grant_id = Some(parent_b.grant_id.clone());
    child.parent_authority_digest = parent_a.authority_digest.clone();

    let result = subset_check(&parent_b, &child);
    assert!(
        matches!(
            result,
            Err(CapabilityError::ParentAuthorityDigestMismatch { .. })
        ),
        "spliced parent must be denied, got {result:?}"
    );
}

#[test]
fn parent_without_digest_but_child_claims_one_is_denied() {
    // Child claims a parent_authority_digest but parent has no authority_digest:
    // lineage cannot be anchored, so it must be denied.
    let parent = base_grant(); // no authority_digest
    let mut child = child_of(&parent);
    child.parent_authority_digest = Some("sha256:0000".into());
    let result = subset_check(&parent, &child);
    assert!(
        matches!(
            result,
            Err(CapabilityError::ParentAuthorityDigestMismatch { .. })
        ),
        "got {result:?}"
    );
}

#[test]
fn child_missing_parent_digest_commitment_is_denied() {
    // Parent carries an authority_digest; child must commit to it.
    let parent = parent_with_digest();
    let mut child = child_of(&parent);
    child.parent_authority_digest = None;
    let result = subset_check(&parent, &child);
    assert!(
        matches!(
            result,
            Err(CapabilityError::MissingParentAuthorityDigest { .. })
        ),
        "got {result:?}"
    );
}

#[test]
fn self_digest_tampering_is_denied() {
    // Child's authority_digest must match its own canonical bytes; a tampered
    // self-claim is a forgery even if everything else is subset-valid.
    let parent = parent_with_digest();
    let mut child = child_of(&parent);
    child.authority_digest =
        Some("sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".into());
    let result = subset_check(&parent, &child);
    assert!(
        matches!(result, Err(CapabilityError::AuthorityDigestMismatch { .. })),
        "got {result:?}"
    );
}

#[test]
fn holder_binding_substitution_is_denied() {
    // Parent is bound to one holder; child claims a different holder.
    let mut parent = parent_with_digest();
    parent.holder_binding = Some("holder-owner".into());
    parent.authority_digest = Some(authority_digest_of(&parent).expect("canonicalizable"));

    let mut child = child_of(&parent);
    child.holder_binding = Some("holder-intruder".into());
    // Child's self-digest must be recomputed after the mutation so the check
    // exercises the holder-binding rule rather than the self-digest rule.
    child.authority_digest = Some(authority_digest_of(&child).expect("canonicalizable"));
    let result = subset_check(&parent, &child);
    assert!(
        matches!(result, Err(CapabilityError::HolderBindingMismatch { .. })),
        "got {result:?}"
    );
}

#[test]
fn child_cannot_invent_a_holder() {
    // Parent has no holder binding; child claims one -> child invents authority.
    let parent = parent_with_digest();
    let mut child = child_of(&parent);
    child.holder_binding = Some("holder-intruder".into());
    child.authority_digest = Some(authority_digest_of(&child).expect("canonicalizable"));
    let result = subset_check(&parent, &child);
    assert!(
        matches!(
            result,
            Err(CapabilityError::HolderBindingNotInParent { .. })
        ),
        "got {result:?}"
    );
}
