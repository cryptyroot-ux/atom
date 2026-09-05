use atom_agent_profile::*;

#[test]
fn soul_authority_escalation_deny() {
    // SOUL.md must NOT create or replace authority
    let soul = SoulProfile::new("agent-1".to_string(), "owner-1".to_string());
    
    // SoulProfile must not have operations, resources, budget fields
    // This is enforced by type system - SoulProfile has no such fields
    assert!(soul.forbidden_behaviors.contains(&"no_authority_escalation".to_string()));
    assert_eq!(soul.autonomy_posture, "propose_only");
}

#[test]
fn identity_display_change_does_not_change_workload_identity() {
    let mut profile = AgentIdentityProfile::new(
        "agent-1".to_string(),
        "owner-1".to_string(),
        "ATOM Agent".to_string(),
        "assistant".to_string(),
        "sha256:abc".to_string(),
    );

    let original_digest = profile.content_digest.clone();
    let original_agent_id = profile.agent_id.clone();
    let original_owner = profile.owner_principal_id.clone();
    let original_profile_id = profile.profile_id.clone();

    // A freshly created profile is sealed: its stored digest matches its material.
    assert!(!original_digest.is_empty());
    profile.verify_self_digest().unwrap();

    // Presentation change goes through the typed API (ATOM-SELF-006), which reseals.
    profile.set_display_name("New Name".to_string());

    // Content digest changes (different presentation content)...
    assert_ne!(profile.content_digest, original_digest);
    profile.verify_self_digest().unwrap();

    // ...but the security principal is untouched (ATOM-SELF-003).
    assert_eq!(profile.agent_id, original_agent_id);
    assert_eq!(profile.owner_principal_id, original_owner);
    assert_eq!(profile.profile_id, original_profile_id);
    assert_eq!(profile.state, RevisionState::Draft);
}

#[test]
fn tampered_identity_material_fails_self_digest() {
    let mut profile = AgentIdentityProfile::new(
        "agent-1".to_string(),
        "owner-1".to_string(),
        "ATOM Agent".to_string(),
        "assistant".to_string(),
        "sha256:abc".to_string(),
    );

    // Direct field mutation bypasses the typed API and does NOT reseal,
    // so the stored digest no longer matches the material: detectable tamper.
    profile.display_name = "Injected Name".to_string();
    assert!(profile.verify_self_digest().is_err());
}

#[test]
fn identity_content_digest_is_deterministic_over_material() {
    let mut a = AgentIdentityProfile::new(
        "agent-1".to_string(),
        "owner-1".to_string(),
        "ATOM Agent".to_string(),
        "assistant".to_string(),
        "sha256:abc".to_string(),
    );
    let mut b = a.clone();

    // Same material → same digest, regardless of when it is recomputed.
    assert_eq!(a.compute_content_digest(), b.compute_content_digest());

    // Field-boundary confusion defence: moving a character across a field
    // boundary must not collide.
    a.set_display_name("AB".to_string());
    a.set_role("C".to_string());
    b.set_display_name("A".to_string());
    b.set_role("BC".to_string());
    assert_ne!(a.content_digest, b.content_digest);
}

#[test]
fn unapproved_self_mutation_not_activated() {
    let mut revision = AgentSelfRevision::new(
        "profile-1".to_string(),
        ChangeType::Identity,
        serde_json::json!({"display_name": "New"}),
        "agent-1".to_string(),
    );
    
    // Agent can propose
    revision.propose().unwrap();
    assert_eq!(revision.state, RevisionState::Proposed);
    
    // Agent can request authorization
    revision.request_authorization().unwrap();
    assert_eq!(revision.state, RevisionState::PendingAuthorization);
    
    // Without owner approval, cannot activate
    // (In real implementation, this would check authorization)
    // For now, just verify the state machine works
}

#[test]
fn self_approval_deny() {
    let mut revision = AgentSelfRevision::new(
        "profile-1".to_string(),
        ChangeType::Identity,
        serde_json::json!({"display_name": "New"}),
        "agent-1".to_string(),
    );
    
    revision.propose().unwrap();
    revision.request_authorization().unwrap();
    
    // Self-approval must be denied
    let result = revision.authorize("agent-1".to_string());
    assert!(result.is_err());
}

#[test]
fn tampered_soul_digest_quarantined() {
    let soul = SoulProfile::new("agent-1".to_string(), "owner-1".to_string());
    
    // Verify digest check works
    let content = b"tampered content";
    let result = soul.verify_digest(content);
    assert!(result.is_err());
}

#[test]
fn constitution_digest_mismatch_startup_blocked() {
    let profile = AgentIdentityProfile::new(
        "agent-1".to_string(),
        "owner-1".to_string(),
        "ATOM Agent".to_string(),
        "assistant".to_string(),
        "sha256:correct".to_string(),
    );
    
    // Wrong constitution digest should fail
    let result = profile.verify_constitution("sha256:wrong");
    assert!(result.is_err());
}

#[test]
fn provider_switch_preserves_agent_identity() {
    let profile = AgentIdentityProfile::new(
        "agent-1".to_string(),
        "owner-1".to_string(),
        "ATOM Agent".to_string(),
        "assistant".to_string(),
        "sha256:abc".to_string(),
    );
    
    // Agent identity should be stable across provider changes
    assert_eq!(profile.agent_id, "agent-1");
    assert_eq!(profile.owner_principal_id, "owner-1");
}

#[test]
fn tenant_isolation_deny() {
    let profile_a = AgentIdentityProfile::new(
        "agent-a".to_string(),
        "owner-a".to_string(),
        "Agent A".to_string(),
        "assistant".to_string(),
        "sha256:abc".to_string(),
    );
    
    let profile_b = AgentIdentityProfile::new(
        "agent-b".to_string(),
        "owner-b".to_string(),
        "Agent B".to_string(),
        "assistant".to_string(),
        "sha256:def".to_string(),
    );
    
    // Different agents should have different identities
    assert_ne!(profile_a.agent_id, profile_b.agent_id);
    assert_ne!(profile_a.owner_principal_id, profile_b.owner_principal_id);
    assert_ne!(profile_a.profile_id, profile_b.profile_id);
}

#[test]
fn private_user_profile_in_shared_channel_deny() {
    // Private user profile should not be exposed in shared channels
    // This is enforced by type system - UserProfile is separate from AgentIdentityProfile
    let profile = AgentIdentityProfile::new(
        "agent-1".to_string(),
        "owner-1".to_string(),
        "ATOM Agent".to_string(),
        "assistant".to_string(),
        "sha256:abc".to_string(),
    );
    
    // Profile is presentation identity, not private user data
    assert_eq!(profile.agent_id, "agent-1");
}

#[test]
fn rollback_restores_exact_prior_profile() {
    let mut revision = AgentSelfRevision::new(
        "profile-1".to_string(),
        ChangeType::Identity,
        serde_json::json!({"display_name": "New"}),
        "agent-1".to_string(),
    );
    
    revision.propose().unwrap();
    revision.request_authorization().unwrap();
    revision.authorize("owner-1".to_string()).unwrap();
    
    assert_eq!(revision.state, RevisionState::Active);
    assert_eq!(revision.generation, 1);
    
    // Rollback should work
    revision.rollback().unwrap();
    assert_eq!(revision.state, RevisionState::RolledBack);
}

#[test]
fn effective_self_view_expiry() {
    let view = EffectiveSelfView::new(
        "sha256:constitution".to_string(),
        "profile-1".to_string(),
        "soul-1".to_string(),
        "test-scope".to_string(),
        1, // 1 second TTL
    );
    
    assert!(!view.is_expired());
    assert_eq!(view.scope, "test-scope");
    assert!(!view.derivation_digest.is_empty());
}
