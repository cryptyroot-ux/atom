//! Verification: what a walk over one stream found (ATOM-VT-006, ATOM-LED-001).
//!
//! Judgement lives here, storage lives in [`crate::store`]. The walk is fed events exactly
//! as they are stored — nothing is repaired or recomputed on the way in — because the whole
//! point is to compare stored bytes against derived ones.
//!
//! Order matters when a seal is checked. A checkpoint that fails its own digest or
//! signature check is not evidence about anything, so the walk records that and asks it
//! nothing further: reporting a "fork" against a head an attacker chose would be noise.

use crate::checkpoint::{Checkpoint, CheckpointSigner};
use crate::event::Event;
use crate::hash::{payload_digest_bytes, Hash};

/// One integrity problem found in a stream.
///
/// A finding is not an [`Error`](crate::Error): the store answered every question it was
/// asked, it just answered provably wrong ones.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Finding {
    /// The sequence jumped: everything from `expected_seq` up to `found_seq` is gone.
    MissingEvent { expected_seq: u64, found_seq: u64 },

    /// A stored `prev_hash` does not point at the previous event's identity: the chain was
    /// cut, or a foreign event was spliced in.
    ChainBreak {
        seq: u64,
        expected_prev_hash: Hash,
        stored_prev_hash: Hash,
    },

    /// The stored identity is not what this event's own fields derive.
    CanonicalHashMismatch {
        seq: u64,
        stored: Hash,
        recomputed: Hash,
    },

    /// The stored payload bytes do not hash to the stored `payload_digest`.
    PayloadDigestMismatch {
        seq: u64,
        stored: Hash,
        recomputed: Hash,
    },

    /// A seal names a head this stream no longer reaches — history was cut short after it
    /// was sealed.
    Truncated {
        checkpoint_seq: u64,
        head_seq: u64,
        sealed_head_hash: Hash,
    },

    /// A seal and the local stream disagree about the identity at `seq`: two different
    /// histories, one sequence number. This is what catches a wholesale rewrite, which is
    /// internally consistent and therefore invisible to the chain checks above.
    Fork {
        seq: u64,
        sealed_head_hash: Hash,
        local_hash: Hash,
    },

    /// A checkpoint's stored digest is not what its own fields derive.
    CheckpointDigestMismatch {
        seq: u64,
        stored: Hash,
        recomputed: Hash,
    },

    /// A checkpoint's signature does not verify under `key_id` — it was forged, resealed
    /// without the key, or tampered with after sealing.
    CheckpointSignatureInvalid { seq: u64, key_id: String },
}

/// The result of verifying one stream.
#[derive(Debug, Clone)]
pub struct VerifyReport {
    /// Stream that was walked.
    pub stream_id: String,
    /// Sequence of the last event found, or `0` for an empty stream.
    pub head_seq: u64,
    /// Identity of the last event found, or [`Hash::GENESIS`] for an empty stream.
    pub head_hash: Hash,
    /// How many events the walk read.
    pub events_verified: u64,
    /// How many checkpoints the walk examined. An examined seal may still have produced
    /// findings.
    pub checkpoints_verified: u64,
    /// Everything provably wrong, in the order it was found.
    pub findings: Vec<Finding>,
}

impl VerifyReport {
    /// True when nothing provably wrong was found.
    ///
    /// "Intact" is a claim about what was checked: a stream with no external witness can be
    /// intact and still be a rewrite (see [`Finding::Fork`]).
    #[must_use]
    pub fn is_intact(&self) -> bool {
        self.findings.is_empty()
    }
}

/// Accumulates findings while events are streamed past it in ascending sequence order.
///
/// Kept separate from the store so the judgement is testable without a database, and so the
/// store never has to hold a whole stream in memory to verify it.
pub(crate) struct StreamWalk {
    expected_seq: u64,
    prev_hash: Hash,
    head_seq: u64,
    head_hash: Hash,
    events_verified: u64,
    checkpoints_verified: u64,
    findings: Vec<Finding>,
}

impl StreamWalk {
    /// Begin at the genesis position: sequence 1 chained to [`Hash::GENESIS`].
    pub(crate) fn start() -> Self {
        Self {
            expected_seq: 1,
            prev_hash: Hash::GENESIS,
            head_seq: 0,
            head_hash: Hash::GENESIS,
            events_verified: 0,
            checkpoints_verified: 0,
            findings: Vec::new(),
        }
    }

    /// Judge one stored event together with its stored payload bytes. Events must arrive in
    /// ascending sequence order.
    ///
    /// The running chain head advances to the *stored* identity, not the recomputed one.
    /// That is deliberate: an edited timestamp then yields one
    /// [`Finding::CanonicalHashMismatch`] at the event that was edited, instead of that plus
    /// a [`Finding::ChainBreak`] at every event after it. One tamper, one finding.
    pub(crate) fn visit(&mut self, event: &Event, payload: &[u8]) {
        if event.seq != self.expected_seq {
            self.findings.push(Finding::MissingEvent {
                expected_seq: self.expected_seq,
                found_seq: event.seq,
            });
        }

        let payload_digest = payload_digest_bytes(payload);
        if payload_digest != event.payload_digest {
            self.findings.push(Finding::PayloadDigestMismatch {
                seq: event.seq,
                stored: event.payload_digest,
                recomputed: payload_digest,
            });
        }

        let canonical_hash = event.recompute_canonical_hash();
        if canonical_hash != event.canonical_hash {
            self.findings.push(Finding::CanonicalHashMismatch {
                seq: event.seq,
                stored: event.canonical_hash,
                recomputed: canonical_hash,
            });
        }

        if event.prev_hash != self.prev_hash {
            self.findings.push(Finding::ChainBreak {
                seq: event.seq,
                expected_prev_hash: self.prev_hash,
                stored_prev_hash: event.prev_hash,
            });
        }

        self.prev_hash = event.canonical_hash;
        self.head_seq = event.seq;
        self.head_hash = event.canonical_hash;
        self.expected_seq = event.seq + 1;
        self.events_verified += 1;
    }

    /// Judge one seal against the head this walk reached. Call only after every event has
    /// been visited: a seal is a statement about the whole stream.
    ///
    /// `local_hash` is the identity the stream stores at the sealed sequence, or `None` if
    /// it holds no such event. The caller supplies it because only the store can look it up.
    ///
    /// Checks run strictly in order and stop at the first failure. A seal whose digest or
    /// signature is wrong is not evidence, so it is never used to accuse the stream: an
    /// attacker who could forge seals could otherwise manufacture forks at will.
    pub(crate) fn seal(
        &mut self,
        checkpoint: &Checkpoint,
        signer: &dyn CheckpointSigner,
        local_hash: Option<Hash>,
    ) {
        self.checkpoints_verified += 1;

        let recomputed = checkpoint.recompute_digest();
        if recomputed != checkpoint.digest {
            self.findings.push(Finding::CheckpointDigestMismatch {
                seq: checkpoint.seq,
                stored: checkpoint.digest,
                recomputed,
            });
            return;
        }

        if !signer.verify(
            &checkpoint.key_id,
            &checkpoint.digest,
            &checkpoint.signature,
        ) {
            self.findings.push(Finding::CheckpointSignatureInvalid {
                seq: checkpoint.seq,
                key_id: checkpoint.key_id.clone(),
            });
            return;
        }

        if checkpoint.seq > self.head_seq {
            self.findings.push(Finding::Truncated {
                checkpoint_seq: checkpoint.seq,
                head_seq: self.head_seq,
                sealed_head_hash: checkpoint.head_hash,
            });
            return;
        }

        // A hole mid-stream was already reported by the walk; there is nothing to compare.
        if let Some(local_hash) = local_hash {
            if local_hash != checkpoint.head_hash {
                self.findings.push(Finding::Fork {
                    seq: checkpoint.seq,
                    sealed_head_hash: checkpoint.head_hash,
                    local_hash,
                });
            }
        }
    }

    /// Close the walk into a report.
    pub(crate) fn finish(self, stream_id: &str) -> VerifyReport {
        VerifyReport {
            stream_id: stream_id.to_owned(),
            head_seq: self.head_seq,
            head_hash: self.head_hash,
            events_verified: self.events_verified,
            checkpoints_verified: self.checkpoints_verified,
            findings: self.findings,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkpoint::HmacSha256Signer;

    /// Build a chained stream of `count` events with canonical payload bytes `b"{}"`.
    fn chain(count: u64) -> Vec<(Event, Vec<u8>)> {
        let payload = b"{}".to_vec();
        let payload_digest = payload_digest_bytes(&payload);
        let mut prev_hash = Hash::GENESIS;
        let mut events = Vec::new();
        for seq in 1..=count {
            let ts = 1_000 + i64::try_from(seq).unwrap();
            let canonical_hash =
                Event::compute_canonical_hash(seq, "s", &prev_hash, &payload_digest, ts);
            events.push((
                Event {
                    seq,
                    stream_id: "s".to_owned(),
                    prev_hash,
                    payload_digest,
                    canonical_hash,
                    ts,
                },
                payload.clone(),
            ));
            prev_hash = canonical_hash;
        }
        events
    }

    fn walked(events: &[(Event, Vec<u8>)]) -> StreamWalk {
        let mut walk = StreamWalk::start();
        for (event, payload) in events {
            walk.visit(event, payload);
        }
        walk
    }

    fn signer() -> HmacSha256Signer {
        HmacSha256Signer::new("k1", b"unit-test-key")
    }

    /// A correctly signed seal over `head`.
    fn sealed(signer: &HmacSha256Signer, head: &Event, event_count: u64) -> Checkpoint {
        let digest =
            Checkpoint::compute_digest("s", head.seq, &head.canonical_hash, event_count, 9_000);
        Checkpoint {
            stream_id: "s".to_owned(),
            seq: head.seq,
            head_hash: head.canonical_hash,
            event_count,
            ts: 9_000,
            digest,
            key_id: signer.key_id().to_owned(),
            signature: signer.sign(&digest),
        }
    }

    #[test]
    fn a_clean_chain_reports_nothing() {
        let events = chain(3);
        let signer = signer();
        let checkpoint = sealed(&signer, &events[2].0, 3);
        let mut walk = walked(&events);
        walk.seal(&checkpoint, &signer, Some(events[2].0.canonical_hash));

        let report = walk.finish("s");
        assert!(report.is_intact(), "{report:#?}");
        assert_eq!(report.stream_id, "s");
        assert_eq!(report.events_verified, 3);
        assert_eq!(report.checkpoints_verified, 1);
        assert_eq!(report.head_seq, 3);
        assert_eq!(report.head_hash, events[2].0.canonical_hash);
    }

    #[test]
    fn a_hole_is_reported_once_and_the_walk_keeps_going() {
        let events = chain(4);
        let kept: Vec<_> = events
            .iter()
            .filter(|(event, _)| event.seq != 3)
            .cloned()
            .collect();

        let report = walked(&kept).finish("s");
        assert!(report.findings.contains(&Finding::MissingEvent {
            expected_seq: 3,
            found_seq: 4,
        }));
        assert_eq!(report.events_verified, 3);
        assert_eq!(report.head_seq, 4, "the walk still reaches the tail");
    }

    #[test]
    fn an_edited_timestamp_is_pinned_to_its_own_event() {
        let mut events = chain(3);
        events[1].0.ts += 1;

        let report = walked(&events).finish("s");
        assert!(
            matches!(
                report.findings.as_slice(),
                [Finding::CanonicalHashMismatch { seq: 2, .. }]
            ),
            "one tamper, one finding: {report:#?}"
        );
    }

    #[test]
    fn edited_payload_bytes_are_reported() {
        let mut events = chain(2);
        events[1].1 = br#"{"x":1}"#.to_vec();

        let report = walked(&events).finish("s");
        assert!(
            matches!(
                report.findings.as_slice(),
                [Finding::PayloadDigestMismatch { seq: 2, .. }]
            ),
            "{report:#?}"
        );
    }

    #[test]
    fn a_cut_link_breaks_the_chain_and_the_identity() {
        let mut events = chain(3);
        events[2].0.prev_hash = Hash::GENESIS;

        let report = walked(&events).finish("s");
        assert!(report
            .findings
            .iter()
            .any(|f| matches!(f, Finding::ChainBreak { seq: 3, .. })));
        assert!(report
            .findings
            .iter()
            .any(|f| matches!(f, Finding::CanonicalHashMismatch { seq: 3, .. })));
    }

    #[test]
    fn a_seal_beyond_the_head_is_truncation() {
        let events = chain(3);
        let signer = signer();
        let mut walk = walked(&events[..2]);
        walk.seal(&sealed(&signer, &events[2].0, 3), &signer, None);

        let report = walk.finish("s");
        assert!(
            matches!(
                report.findings.as_slice(),
                [Finding::Truncated {
                    checkpoint_seq: 3,
                    head_seq: 2,
                    ..
                }]
            ),
            "{report:#?}"
        );
    }

    #[test]
    fn a_verifiable_seal_over_another_history_is_a_fork() {
        let events = chain(3);
        let signer = signer();
        let mut forked = sealed(&signer, &events[2].0, 3);
        forked.head_hash = Hash::GENESIS;
        forked.digest = forked.recompute_digest();
        forked.signature = signer.sign(&forked.digest);

        let mut walk = walked(&events);
        walk.seal(&forked, &signer, Some(events[2].0.canonical_hash));

        let report = walk.finish("s");
        assert!(
            matches!(report.findings.as_slice(), [Finding::Fork { seq: 3, .. }]),
            "{report:#?}"
        );
    }

    /// A seal that cannot be verified says nothing about the stream, so it must never be
    /// the source of a chain accusation.
    #[test]
    fn an_unverifiable_seal_accuses_only_itself() {
        let events = chain(3);
        let signer = signer();

        let mut edited = sealed(&signer, &events[2].0, 3);
        edited.head_hash = Hash::GENESIS;
        let mut walk = walked(&events);
        walk.seal(&edited, &signer, Some(events[2].0.canonical_hash));
        let report = walk.finish("s");
        assert!(
            matches!(
                report.findings.as_slice(),
                [Finding::CheckpointDigestMismatch { seq: 3, .. }]
            ),
            "{report:#?}"
        );
        let forger = HmacSha256Signer::new("k1", b"a-key-nobody-trusts");
        let mut forged = sealed(&forger, &events[2].0, 3);
        forged.head_hash = Hash::GENESIS;
        forged.digest = forged.recompute_digest();
        forged.signature = forger.sign(&forged.digest);
        let mut walk = walked(&events);
        walk.seal(&forged, &signer, Some(events[2].0.canonical_hash));
        let report = walk.finish("s");
        assert!(
            matches!(
                report.findings.as_slice(),
                [Finding::CheckpointSignatureInvalid { seq: 3, .. }]
            ),
            "{report:#?}"
        );
    }
}
