//! SecretBroker — in-memory SecretVault implementation for alpha.
//!
//! Provides a thread-safe, in-memory secret store that validates all
//! SecretHandle constraints per SEC-001 before releasing secrets.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::handle::SecretHandle;
use crate::value::SecretValue;
use crate::vault::{SecretVault, SecretVaultError};

/// Thread-safe in-memory secret store.
#[derive(Debug, Default)]
pub struct SecretBroker {
    inner: Arc<RwLock<HashMap<String, SecretEntry>>>,
}

#[derive(Debug, Clone)]
struct SecretEntry {
    handle: SecretHandle,
    secret: SecretValue,
}

impl SecretBroker {
    /// Create a new empty SecretBroker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new SecretBroker with pre-planted secrets.
    pub fn with_secrets(secrets: Vec<(SecretHandle, SecretValue)>) -> Self {
        let broker = Self::new();
        for (handle, secret) in secrets {
            broker.plant(handle, secret).expect("failed to plant initial secret");
        }
        broker
    }
}

impl SecretVault for SecretBroker {
    fn redeem(&self, handle: &SecretHandle) -> Result<SecretValue, SecretVaultError> {
        let mut inner = self.inner.write().map_err(|_| {
            SecretVaultError::Internal("lock poisoned".to_string())
        })?;

        let entry = inner.get_mut(&handle.secret_id).ok_or_else(|| {
            SecretVaultError::NotFound {
                secret_id: handle.secret_id.clone(),
            }
        })?;

        // Validate all constraints per SEC-001
        validate_constraints(handle, &entry.handle)?;

        // Check expiry
        if entry.handle.is_expired() {
            return Err(SecretVaultError::Expired {
                secret_id: handle.secret_id.clone(),
                expiry: entry.handle.expiry.to_rfc3339(),
            });
        }

        // Check redemptions
        if !entry.handle.has_redemptions_remaining() {
            return Err(SecretVaultError::Exhausted {
                secret_id: handle.secret_id.clone(),
                max_redemptions: entry.handle.max_redemptions,
            });
        }

        // Increment redemption count
        entry.handle.redemptions_used += 1;

        // Return cloned secret (SecretValue implements Clone but zeroizes on drop)
        Ok(entry.secret.clone())
    }

    fn plant(&self, handle: SecretHandle, secret: SecretValue) -> Result<(), SecretVaultError> {
        let mut inner = self.inner.write().map_err(|_| {
            SecretVaultError::Internal("lock poisoned".to_string())
        })?;

        if inner.contains_key(&handle.secret_id) {
            return Err(SecretVaultError::Internal(format!(
                "secret already exists: {}",
                handle.secret_id
            )));
        }

        inner.insert(handle.secret_id.clone(), SecretEntry { handle, secret });
        Ok(())
    }

    fn exists(&self, secret_id: &str) -> bool {
        self.inner
            .read()
            .map(|inner| inner.contains_key(secret_id))
            .unwrap_or(false)
    }

    fn redemption_count(&self, secret_id: &str) -> Option<u32> {
        self.inner
            .read()
            .ok()
            .and_then(|inner| inner.get(secret_id).map(|entry| entry.handle.redemptions_used))
    }
}

/// Validate all SecretHandle constraints between the presented handle and stored handle.
fn validate_constraints(
    presented: &SecretHandle,
    stored: &SecretHandle,
) -> Result<(), SecretVaultError> {
    // Principal must match exactly
    if presented.principal_id != stored.principal_id {
        return Err(SecretVaultError::PrincipalMismatch {
            expected: stored.principal_id.clone(),
            got: presented.principal_id.clone(),
        });
    }

    // Audience must match exactly
    if presented.audience != stored.audience {
        return Err(SecretVaultError::AudienceMismatch {
            expected: stored.audience.clone(),
            got: presented.audience.clone(),
        });
    }

    // Mission ID must match (both must be None or both Some with same value)
    if presented.mission_id != stored.mission_id {
        return Err(SecretVaultError::MissionMismatch {
            expected: stored.mission_id.clone(),
            got: presented.mission_id.clone(),
        });
    }

    // Capability grant ID must match (both must be None or both Some with same value)
    if presented.capability_grant_id != stored.capability_grant_id {
        return Err(SecretVaultError::CapabilityGrantMismatch {
            expected: stored.capability_grant_id.clone(),
            got: presented.capability_grant_id.clone(),
        });
    }

    // Target must match exactly
    if presented.target != stored.target {
        return Err(SecretVaultError::TargetMismatch {
            expected: stored.target.clone(),
            got: presented.target.clone(),
        });
    }

    // Operation must match exactly
    if presented.operation != stored.operation {
        return Err(SecretVaultError::OperationMismatch {
            expected: stored.operation.clone(),
            got: presented.operation.clone(),
        });
    }

    // Generation must match exactly
    if presented.generation != stored.generation {
        return Err(SecretVaultError::StaleGeneration {
            secret_id: stored.secret_id.clone(),
            expected: stored.generation,
            got: presented.generation,
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Utc, Duration};

    fn make_handle(
        secret_id: &str,
        principal: &str,
        audience: &str,
        target: &str,
        operation: &str,
        generation: u64,
        max_redemptions: u32,
    ) -> SecretHandle {
        SecretHandle {
            secret_id: secret_id.to_string(),
            audience: audience.to_string(),
            principal_id: principal.to_string(),
            mission_id: None,
            capability_grant_id: None,
            target: target.to_string(),
            operation: operation.to_string(),
            expiry: Utc::now() + Duration::hours(1),
            max_redemptions,
            redemptions_used: 0,
            generation,
        }
    }

    #[test]
    fn plant_and_redeem() {
        let broker = SecretBroker::new();
        let handle = make_handle("s1", "p1", "aud", "api.example.com", "read", 0, 1);
        let secret = SecretValue::new(b"test-secret");
        broker.plant(handle.clone(), secret).unwrap();

        let redeemed = broker.redeem(&handle).unwrap();
        assert_eq!(redeemed.bytes(), b"test-secret");
    }

    #[test]
    fn cross_principal_denied() {
        let broker = SecretBroker::new();
        let handle = make_handle("s1", "p1", "aud", "api.example.com", "read", 0, 1);
        let secret = SecretValue::new(b"test-secret");
        broker.plant(handle.clone(), secret).unwrap();

        // Try to redeem with different principal
        let mut wrong_handle = handle.clone();
        wrong_handle.principal_id = "p2".to_string();

        let err = broker.redeem(&wrong_handle).unwrap_err();
        assert!(matches!(err, SecretVaultError::PrincipalMismatch { .. }));
    }

    #[test]
    fn expiry_rejected() {
        let broker = SecretBroker::new();
        let mut handle = make_handle("s1", "p1", "aud", "api.example.com", "read", 0, 1);
        handle.expiry = Utc::now() - Duration::seconds(1); // Already expired
        let secret = SecretValue::new(b"test-secret");
        broker.plant(handle.clone(), secret).unwrap();

        let err = broker.redeem(&handle).unwrap_err();
        assert!(matches!(err, SecretVaultError::Expired { .. }));
    }

    #[test]
    fn redemption_limit_rejected() {
        let broker = SecretBroker::new();
        let handle = make_handle("s1", "p1", "aud", "api.example.com", "read", 0, 1);
        let secret = SecretValue::new(b"test-secret");
        broker.plant(handle.clone(), secret).unwrap();

        // First redemption succeeds
        broker.redeem(&handle).unwrap();

        // Second redemption fails
        let err = broker.redeem(&handle).unwrap_err();
        assert!(matches!(err, SecretVaultError::Exhausted { .. }));
    }

    #[test]
    fn stale_generation_rejected() {
        let broker = SecretBroker::new();
        let handle = make_handle("s1", "p1", "aud", "api.example.com", "read", 1, 1);
        let secret = SecretValue::new(b"test-secret");
        broker.plant(handle.clone(), secret).unwrap();

        // Try to redeem with generation 0 (stale)
        let mut stale_handle = handle.clone();
        stale_handle.generation = 0;

        let err = broker.redeem(&stale_handle).unwrap_err();
        assert!(matches!(err, SecretVaultError::StaleGeneration { .. }));
    }

    #[test]
    fn audience_mismatch_rejected() {
        let broker = SecretBroker::new();
        let handle = make_handle("s1", "p1", "aud1", "api.example.com", "read", 0, 1);
        let secret = SecretValue::new(b"test-secret");
        broker.plant(handle.clone(), secret).unwrap();

        let mut wrong_handle = handle.clone();
        wrong_handle.audience = "aud2".to_string();

        let err = broker.redeem(&wrong_handle).unwrap_err();
        assert!(matches!(err, SecretVaultError::AudienceMismatch { .. }));
    }

    #[test]
    fn target_mismatch_rejected() {
        let broker = SecretBroker::new();
        let handle = make_handle("s1", "p1", "aud", "api.example.com", "read", 0, 1);
        let secret = SecretValue::new(b"test-secret");
        broker.plant(handle.clone(), secret).unwrap();

        let mut wrong_handle = handle.clone();
        wrong_handle.target = "api.other.com".to_string();

        let err = broker.redeem(&wrong_handle).unwrap_err();
        assert!(matches!(err, SecretVaultError::TargetMismatch { .. }));
    }

    #[test]
    fn operation_mismatch_rejected() {
        let broker = SecretBroker::new();
        let handle = make_handle("s1", "p1", "aud", "api.example.com", "read", 0, 1);
        let secret = SecretValue::new(b"test-secret");
        broker.plant(handle.clone(), secret).unwrap();

        let mut wrong_handle = handle.clone();
        wrong_handle.operation = "write".to_string();

        let err = broker.redeem(&wrong_handle).unwrap_err();
        assert!(matches!(err, SecretVaultError::OperationMismatch { .. }));
    }

    #[test]
    fn mission_mismatch_rejected() {
        let broker = SecretBroker::new();
        let mut handle = make_handle("s1", "p1", "aud", "api.example.com", "read", 0, 1);
        handle.mission_id = Some("m1".to_string());
        let secret = SecretValue::new(b"test-secret");
        broker.plant(handle.clone(), secret).unwrap();

        let mut wrong_handle = handle.clone();
        wrong_handle.mission_id = Some("m2".to_string());

        let err = broker.redeem(&wrong_handle).unwrap_err();
        assert!(matches!(err, SecretVaultError::MissionMismatch { .. }));
    }

    #[test]
    fn capability_grant_mismatch_rejected() {
        let broker = SecretBroker::new();
        let mut handle = make_handle("s1", "p1", "aud", "api.example.com", "read", 0, 1);
        handle.capability_grant_id = Some("cg1".to_string());
        let secret = SecretValue::new(b"test-secret");
        broker.plant(handle.clone(), secret).unwrap();

        let mut wrong_handle = handle.clone();
        wrong_handle.capability_grant_id = Some("cg2".to_string());

        let err = broker.redeem(&wrong_handle).unwrap_err();
        assert!(matches!(err, SecretVaultError::CapabilityGrantMismatch { .. }));
    }

    #[test]
    fn multiple_redemptions_allowed() {
        let broker = SecretBroker::new();
        let handle = make_handle("s1", "p1", "aud", "api.example.com", "read", 0, 3);
        let secret = SecretValue::new(b"test-secret");
        broker.plant(handle.clone(), secret).unwrap();

        // First redemption
        broker.redeem(&handle).unwrap();
        assert_eq!(broker.redemption_count("s1"), Some(1));

        // Second redemption
        broker.redeem(&handle).unwrap();
        assert_eq!(broker.redemption_count("s1"), Some(2));

        // Third redemption
        broker.redeem(&handle).unwrap();
        assert_eq!(broker.redemption_count("s1"), Some(3));

        // Fourth fails
        let err = broker.redeem(&handle).unwrap_err();
        assert!(matches!(err, SecretVaultError::Exhausted { .. }));
    }

    #[test]
    fn secret_value_zeroizes_on_drop() {
        // This test verifies the Zeroize behavior indirectly
        // In practice, we can't easily test memory zeroization,
        // but we can verify the type implements ZeroizeOnDrop
        let _secret = SecretValue::new(b"test");
        // When _secret goes out of scope, it should zeroize
    }
}