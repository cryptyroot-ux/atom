//! atom-adapter: the shared substrate for wrapping an external protocol
//! (MCP/A2A/Agent-Skills/Hermes/OpenClaw) that **preserves** the taint and
//! source authority of whatever crosses the boundary — it never launders it.
//!
//! Normative source is `spec/` (precedence 1):
//!
//! * **ADP-001 / INT-001** (`requirements.yaml`): interop profiles live outside
//!   the sovereign core semantics and MUST NOT smuggle authority. Content that
//!   arrives from an external peer is untrusted external input.
//! * **CXT-001 / INV-009** (`invariants.yaml`, `atom-evidence`): taint labels
//!   survive transforms; source authority is the minimum effective authority of
//!   the inputs. There is no ungoverned taint-removal path.
//! * **ATOM-VT-013** (`acceptance/catalog.yaml`): a hostile peer advertising
//!   broad authority stays bounded — importing it does not clear its taint.
//!
//! The one operation this crate offers over external content — [`AdapterMessage::wrap`]
//! — can only *add* taint and can only *lower* authority. An adapter physically
//! cannot present external content as cleaner or more trusted than it arrived,
//! because the type enforces the monotonic [`atom_evidence::derive`] rule.

#![forbid(unsafe_code)]

use atom_evidence::{
    derive, DerivationError, SourceAuthority, TaintCarrier, TaintLabel, TaintLabels,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// The external protocol an adapter speaks.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Protocol {
    /// Model Context Protocol.
    Mcp,
    /// Agent-to-agent.
    A2a,
    /// Agent Skills.
    AgentSkills,
    /// Hermes.
    Hermes,
    /// OpenClaw.
    OpenClaw,
}

impl Protocol {
    /// Canonical wire representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Mcp => "MCP",
            Self::A2a => "A2A",
            Self::AgentSkills => "AGENT_SKILLS",
            Self::Hermes => "HERMES",
            Self::OpenClaw => "OPEN_CLAW",
        }
    }
}

/// Raw content arriving from an external peer, with the metadata the peer's
/// boundary assigned it.
///
/// The `source_authority` here is what the *boundary* is willing to assert
/// about the peer — never what the peer claims about itself. A hostile peer
/// advertising broad authority does not get to set this field.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InboundContent {
    /// Opaque payload from the peer.
    pub payload: String,
    /// Trust the boundary assigns the peer, before taint capping.
    pub source_authority: SourceAuthority,
    /// Taint labels observed on the content at the boundary.
    pub taint_labels: TaintLabels,
}

impl InboundContent {
    /// External content with the given boundary-assigned metadata.
    #[must_use]
    pub fn new(
        payload: &str,
        source_authority: SourceAuthority,
        taint_labels: TaintLabels,
    ) -> Self {
        Self {
            payload: payload.to_owned(),
            source_authority,
            taint_labels,
        }
    }

    /// Untrusted external content: the default posture for an unknown peer.
    ///
    /// Authority is `UNTRUSTED` and the untrusted-external label is present, so
    /// nothing downstream can mistake it for governed input.
    #[must_use]
    pub fn untrusted(payload: &str) -> Self {
        Self {
            payload: payload.to_owned(),
            source_authority: SourceAuthority::Untrusted,
            taint_labels: TaintLabels::from([TaintLabel::UntrustedExternal]),
        }
    }
}

impl TaintCarrier for InboundContent {
    fn source_authority(&self) -> SourceAuthority {
        self.source_authority
    }

    fn taint_labels(&self) -> &TaintLabels {
        &self.taint_labels
    }
}

/// Why wrapping external content failed.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AdapterError {
    /// Wrapping needs content to derive metadata from.
    #[error("cannot wrap: no inbound content supplied")]
    NoContent,
}

impl From<DerivationError> for AdapterError {
    fn from(_: DerivationError) -> Self {
        Self::NoContent
    }
}

/// A protocol message that has crossed the adapter boundary, carrying metadata
/// that is provably no cleaner than the content it wrapped (ADP-001).
///
/// The metadata is computed by [`derive`], so:
///
/// * every taint label of the inbound content is present (labels only union);
/// * the authority is the minimum effective authority, capped by taint — so an
///   untrusted-external input forces `UNTRUSTED`.
///
/// The adapter may add its *own* taint (e.g. a protocol-specific label) but can
/// never remove one. Laundering is not an available operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdapterMessage {
    protocol: Protocol,
    peer_id: String,
    payload: String,
    source_authority: SourceAuthority,
    taint_labels: TaintLabels,
}

impl AdapterMessage {
    /// Wraps `content` from `peer_id` over `protocol`, preserving its taint and
    /// authority and optionally adding adapter-specific taint (ADP-001).
    ///
    /// `added_labels` can only make the result *more* tainted; there is no
    /// parameter that removes a label. The resulting authority is derived, so
    /// it can only be lower than or equal to the inbound authority.
    ///
    /// # Errors
    ///
    /// [`AdapterError::NoContent`] should never occur here since one content is
    /// always supplied; it exists to make the derive contract explicit.
    pub fn wrap(
        protocol: Protocol,
        peer_id: &str,
        content: &InboundContent,
        added_labels: impl IntoIterator<Item = TaintLabel>,
    ) -> Result<Self, AdapterError> {
        // Derive over the content plus a synthetic carrier holding only the
        // added labels at the highest authority, so the added labels cannot
        // *raise* authority — they can only contribute taint.
        let added = TaintLabels::new(added_labels);
        let extra = AddedTaint(added);
        let content_ref: &dyn TaintCarrier = content;
        let extra_ref: &dyn TaintCarrier = &extra;
        let metadata = derive([content_ref, extra_ref])?;
        Ok(Self {
            protocol,
            peer_id: peer_id.to_owned(),
            payload: content.payload.clone(),
            source_authority: metadata.source_authority(),
            taint_labels: metadata.taint_labels().clone(),
        })
    }

    /// The protocol this message came over.
    #[must_use]
    pub fn protocol(&self) -> Protocol {
        self.protocol
    }

    /// The peer that sent it.
    #[must_use]
    pub fn peer_id(&self) -> &str {
        &self.peer_id
    }

    /// The payload.
    #[must_use]
    pub fn payload(&self) -> &str {
        &self.payload
    }

    /// Whether the wrapped content is untrusted external input.
    #[must_use]
    pub fn is_untrusted_external(&self) -> bool {
        self.taint_labels.contains_untrusted_external()
    }
}

impl TaintCarrier for AdapterMessage {
    fn source_authority(&self) -> SourceAuthority {
        self.source_authority
    }

    fn taint_labels(&self) -> &TaintLabels {
        &self.taint_labels
    }
}

/// A carrier that contributes only taint labels, at the top authority, so it
/// never raises the derived authority but its labels still union in.
struct AddedTaint(TaintLabels);

impl TaintCarrier for AddedTaint {
    fn source_authority(&self) -> SourceAuthority {
        // Authoritative so the `minimum` in `derive` is decided by the real
        // content, not by this synthetic carrier.
        SourceAuthority::Authoritative
    }

    fn taint_labels(&self) -> &TaintLabels {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use atom_evidence::{SourceAuthority, TaintLabel, TaintLabels};

    // ─── ADP-001: untrusted-external taint survives the wrap ─────────────────
    #[test]
    fn untrusted_external_taint_is_preserved() {
        let content = InboundContent::untrusted("tool result from hostile peer");
        let msg = AdapterMessage::wrap(Protocol::Mcp, "peer-x", &content, []).expect("wraps");
        assert!(
            msg.is_untrusted_external(),
            "adapter must not strip the untrusted-external label"
        );
        assert_eq!(
            msg.source_authority(),
            SourceAuthority::Untrusted,
            "authority must stay UNTRUSTED"
        );
    }

    // ─── ADP-001: adapter cannot launder by "wrapping" it clean ──────────────
    #[test]
    fn adapter_cannot_raise_authority() {
        // A peer whose content is untrusted-external; even the base wrap keeps
        // it capped. Adding labels can only make it more tainted.
        let content = InboundContent::new(
            "payload",
            SourceAuthority::Untrusted,
            TaintLabels::from([TaintLabel::UntrustedExternal, TaintLabel::INJECTION_RISK]),
        );
        let msg = AdapterMessage::wrap(Protocol::A2a, "peer-y", &content, []).expect("wraps");
        assert_eq!(msg.source_authority(), SourceAuthority::Untrusted);
        assert!(msg.taint_labels().contains(&TaintLabel::UntrustedExternal));
        assert!(msg.taint_labels().contains(&TaintLabel::INJECTION_RISK));
    }

    #[test]
    fn every_inbound_label_survives() {
        let content = InboundContent::new(
            "p",
            SourceAuthority::Unverified,
            TaintLabels::from([
                TaintLabel::Internal,
                TaintLabel::custom("mcp:tool-output").unwrap(),
            ]),
        );
        let msg =
            AdapterMessage::wrap(Protocol::AgentSkills, "peer-z", &content, []).expect("wraps");
        assert!(msg.taint_labels().contains(&TaintLabel::Internal));
        assert!(msg
            .taint_labels()
            .contains(&TaintLabel::custom("mcp:tool-output").unwrap()));
    }

    #[test]
    fn adapter_may_add_taint_but_only_add() {
        let content = InboundContent::new(
            "p",
            SourceAuthority::Verified,
            TaintLabels::from([TaintLabel::Internal]),
        );
        // The adapter adds a protocol-provenance label.
        let added = TaintLabel::custom("hermes:imported").unwrap();
        let msg = AdapterMessage::wrap(Protocol::Hermes, "peer-h", &content, [added.clone()])
            .expect("wraps");
        // Original label still there, added label present too.
        assert!(msg.taint_labels().contains(&TaintLabel::Internal));
        assert!(msg.taint_labels().contains(&added));
        // Authority is not raised by the add: still capped by content (Verified,
        // no untrusted-external → stays Verified).
        assert_eq!(msg.source_authority(), SourceAuthority::Verified);
    }

    #[test]
    fn adding_untrusted_external_label_caps_authority_down() {
        // A "trusted-looking" peer, but the adapter marks the channel untrusted:
        // authority must collapse to UNTRUSTED via the taint cap.
        let content = InboundContent::new(
            "p",
            SourceAuthority::Authoritative,
            TaintLabels::from([TaintLabel::Internal]),
        );
        let msg = AdapterMessage::wrap(
            Protocol::OpenClaw,
            "peer-o",
            &content,
            [TaintLabel::UntrustedExternal],
        )
        .expect("wraps");
        assert_eq!(
            msg.source_authority(),
            SourceAuthority::Untrusted,
            "adding untrusted-external must cap authority to UNTRUSTED"
        );
    }

    #[test]
    fn protocol_round_trips() {
        assert_eq!(Protocol::Mcp.as_str(), "MCP");
        assert_eq!(Protocol::OpenClaw.as_str(), "OPEN_CLAW");
    }
}
