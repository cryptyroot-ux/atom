//! ATOM-VT-008 and ATOM-VT-012 restore/fencing acceptance coverage.

use atom_restore::{
    ArtifactRing, ArtifactRouter, AuthorityEpoch, CertifiedRoute, ExternalLease, FencedRestore,
    LeaseConnector, LeaseConnectorError, LocalRestore, RestoreError, SplitBrainSafety,
};

#[derive(Debug)]
struct MockLeaseConnector {
    current: ExternalLease,
}

impl LeaseConnector for MockLeaseConnector {
    fn current_lease(&mut self, authority_id: &str) -> Result<ExternalLease, LeaseConnectorError> {
        if authority_id != self.current.authority_id() {
            return Err(LeaseConnectorError::new("unknown authority"));
        }
        Ok(self.current.clone())
    }
}

fn lease(epoch: u64) -> ExternalLease {
    ExternalLease::new(
        "primary-authority",
        "instance-a",
        AuthorityEpoch::new(epoch),
    )
    .expect("valid external lease")
}

#[test]
fn local_mode_explicitly_rejects_a_clone_proof_safety_claim() {
    let local = LocalRestore::new();

    assert_eq!(local.split_brain_safety(), SplitBrainSafety::Unsupported);
    assert!(matches!(
        local.claim_clone_proof_split_brain_safety(),
        Err(RestoreError::LocalModeCannotClaimCloneProofSafety)
    ));
}

#[test]
fn fenced_mode_rejects_a_stale_external_epoch() {
    let current = lease(9);
    let mut restore = FencedRestore::new(
        "primary-authority",
        MockLeaseConnector {
            current: current.clone(),
        },
    )
    .expect("fenced restore");

    assert!(matches!(
        restore.authorize_commit(&lease(8)),
        Err(RestoreError::StaleEpoch { presented, current })
            if presented == AuthorityEpoch::new(8) && current == AuthorityEpoch::new(9)
    ));
    assert_eq!(
        restore
            .authorize_commit(&current)
            .expect("only the current lease is admitted")
            .epoch(),
        AuthorityEpoch::new(9)
    );
}

#[test]
fn vt012_canary_regression_downgrades_and_restores_the_prior_certified_route() {
    let prior = CertifiedRoute::new("stable-artifact", "route-stable").expect("prior route");
    let candidate =
        CertifiedRoute::new("candidate-artifact", "route-candidate").expect("canary route");
    let mut router = ArtifactRouter::new();

    router
        .register_active(prior.clone())
        .expect("prior active route");
    router
        .register_canary(candidate.clone())
        .expect("candidate canary route");
    let promotion = router
        .promote_canary("candidate-artifact")
        .expect("canary promotion");
    assert_eq!(promotion.from(), ArtifactRing::Canary);
    assert_eq!(promotion.to(), ArtifactRing::Active);
    assert_eq!(router.active_route(), Some(&candidate));

    let rollback = router
        .rollback_on_regression("candidate-artifact")
        .expect("automatic regression rollback");
    assert_eq!(rollback.from(), ArtifactRing::Active);
    assert_eq!(rollback.to(), ArtifactRing::Canary);
    assert_eq!(rollback.restored_route(), &prior);
    assert_eq!(router.active_route(), Some(&prior));
    assert_eq!(
        router
            .artifact("candidate-artifact")
            .expect("candidate state")
            .ring(),
        ArtifactRing::Canary,
        "the regressed artifact is downgraded before further use"
    );
}

#[test]
fn artifacts_follow_the_canonical_promotion_path_before_active() {
    let prior = CertifiedRoute::new("stable-artifact", "route-stable").expect("prior route");
    let candidate =
        CertifiedRoute::new("candidate-artifact", "route-candidate").expect("candidate route");
    let mut router = ArtifactRouter::new();
    router.register_active(prior).expect("initial active route");
    router.register_lab(candidate).expect("lab candidate");

    for (from, to) in [
        (ArtifactRing::Lab, ArtifactRing::Simulation),
        (ArtifactRing::Simulation, ArtifactRing::Shadow),
        (ArtifactRing::Shadow, ArtifactRing::Canary),
        (ArtifactRing::Canary, ArtifactRing::Active),
    ] {
        let promotion = router
            .promote("candidate-artifact")
            .expect("ordered promotion");
        assert_eq!(promotion.from(), from);
        assert_eq!(promotion.to(), to);
    }
}
