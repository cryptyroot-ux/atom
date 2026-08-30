//! Dispatch admission: the last check before an effect touches the world.
//!
//! EFX-003 and INV-002 meet here. An effect whose outcome is unknown must not
//! be dispatched again — a blind repeat is how one intent becomes two effects —
//! and neither must anything that declared a dependency on it.

use thiserror::Error;

use crate::intent::EffectIntent;
use crate::state::EffectState;

/// Why a dispatch was refused (EFX-003, INV-002).
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AdmissionError {
    /// The effect is not standing in the dispatch window.
    #[error("effect {effect_id} is {state}, not DISPATCHING")]
    NotDispatching {
        /// The effect that was offered for dispatch.
        effect_id: String,
        /// The state it is actually in.
        state: EffectState,
    },
    /// The effect's own outcome is unresolved (INV-002).
    #[error("effect {effect_id} is {state}: reconcile it before acting again")]
    AmbiguousOutcome {
        /// The effect that was offered for dispatch.
        effect_id: String,
        /// The ambiguous state it is held in.
        state: EffectState,
    },
    /// Something it depends on is unresolved (EFX-003).
    #[error("effect {effect_id} depends on {dependency_id}, which is {state}")]
    DependencyAmbiguous {
        /// The effect that was offered for dispatch.
        effect_id: String,
        /// The declared dependency that is holding it back.
        dependency_id: String,
        /// The state that dependency is in.
        state: EffectState,
    },
}

/// Whether `effect` may be dispatched now (EFX-003, INV-002).
///
/// `upstream` carries whatever the caller knows about other effects. Only the
/// ones `effect` actually declared as dependencies are consulted, so passing
/// more than that is harmless and passing none is not silently permissive: an
/// undeclared edge was never a blocker in the first place.
pub fn admit_dispatch(
    effect: &EffectIntent,
    upstream: &[&EffectIntent],
) -> Result<(), AdmissionError> {
    // Checked before the state test so an ambiguous effect is refused for the
    // reason that matters, rather than for merely being in the wrong state.
    if effect.state.is_ambiguous() {
        return Err(AdmissionError::AmbiguousOutcome {
            effect_id: effect.effect_id.clone(),
            state: effect.state,
        });
    }
    if effect.state != EffectState::Dispatching {
        return Err(AdmissionError::NotDispatching {
            effect_id: effect.effect_id.clone(),
            state: effect.state,
        });
    }

    for dependency in upstream {
        if !effect.dependencies.contains(&dependency.effect_id) {
            continue;
        }
        if dependency.state.blocks_dependents() {
            return Err(AdmissionError::DependencyAmbiguous {
                effect_id: effect.effect_id.clone(),
                dependency_id: dependency.effect_id.clone(),
                state: dependency.state,
            });
        }
    }

    Ok(())
}
