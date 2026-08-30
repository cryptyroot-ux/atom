//! R2 ACTIVITY_CASSETTE_REPLAY: a recording of external interactions.
//!
//! A cassette is a typed, ordered map from a `request_digest` to the response
//! that was recorded when the interaction really happened. Replay resolves
//! *only* from this map. There is no field on a [`Cassette`] that names a
//! connector, a URL or a live endpoint, so it is structurally impossible for a
//! cassette read to reach the outside world (TASK.md boundary decision:
//! "replay is read/derive only").
//!
//! A missing entry is a [`crate::ReplayError::CassetteMiss`] — never a live
//! call, never a fabricated response (INV-010, TASK.md item 4).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::ReplayError;

/// A response that was recorded when an external interaction really happened.
///
/// The body is opaque bytes plus a caller-declared outcome tag: the cassette
/// records what came back, and replay hands it straight back without
/// interpreting it. [`RecordedResponse::recorded`] is the recording-side
/// constructor; replay only ever *reads* these through [`Cassette::resolve`].
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct RecordedResponse {
    /// The outcome the real interaction concluded with, in the caller's terms.
    pub outcome: String,
    /// The response body exactly as it was recorded.
    pub body: Vec<u8>,
}

impl RecordedResponse {
    /// Records the `outcome`/`body` that a real external interaction returned.
    ///
    /// This is the *recording* side: it exists so a cassette can be built from
    /// observed reality. Replay reads these; it never uses them to reach out.
    #[must_use]
    pub fn recorded(outcome: &str, body: &[u8]) -> Self {
        Self {
            outcome: outcome.to_owned(),
            body: body.to_vec(),
        }
    }
}

/// A recording of external interactions, keyed by request digest.
///
/// Ordered (`BTreeMap`) so that two cassettes with the same entries serialize
/// and digest identically — a cassette is itself replay-stable data.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Cassette {
    entries: BTreeMap<String, RecordedResponse>,
}

impl Cassette {
    /// An empty cassette.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records `response` as what `request_digest` returned.
    ///
    /// Returns the previous recording if the request was already recorded, so a
    /// re-record is explicit rather than a silent overwrite.
    pub fn record(
        &mut self,
        request_digest: &str,
        response: RecordedResponse,
    ) -> Option<RecordedResponse> {
        self.entries.insert(request_digest.to_owned(), response)
    }

    /// How many interactions are recorded.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether nothing is recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Whether `request_digest` has a recorded response.
    #[must_use]
    pub fn contains(&self, request_digest: &str) -> bool {
        self.entries.contains_key(request_digest)
    }

    /// Resolves `request_digest` from the recording, and only from it.
    ///
    /// This is the whole of R2's external-interaction path: a lookup in a map.
    /// There is no `else` branch that calls out — a missing entry is the typed
    /// [`ReplayError::CassetteMiss`] (INV-010, TASK.md item 4).
    ///
    /// # Errors
    ///
    /// [`ReplayError::CassetteMiss`] when the cassette records no response for
    /// `request_digest`.
    pub fn resolve(&self, request_digest: &str) -> Result<&RecordedResponse, ReplayError> {
        self.entries
            .get(request_digest)
            .ok_or_else(|| ReplayError::CassetteMiss {
                request_digest: request_digest.to_owned(),
            })
    }
}
