//! Session-bound, codec-opaque real-time flows.
//!
//! The outward half of the connector-local flow registry. The registry owns
//! admission, queueing and resource accounting and says nothing about codecs;
//! this module adds the two things an application needs and the registry
//! deliberately does not have: a binding to one authenticated session, and a
//! name both ends can say out loud.
//!
//! **Two names, two jobs, never substituted.** A flow has a process-local
//! identity (`RealtimeFlowKey`, an allocation address that is never serialized
//! and grants nothing) and a session-scoped label ([`RealtimeFlowLabel`]) that
//! does cross the wire. The identity answers "is this the same flow object";
//! the label answers "which of this session's flows do these bytes belong to".
//! Neither is ever used for the other's question, for the same reason the RPC
//! layer keeps a pending operation's identity apart from its binding.
//!
//! **Nothing here is authority.** Opening a flow and sending on one both
//! require a live [`RealtimeSessionBinding`]; a label gets a holder nothing at
//! all, because the receiving side has already been handed the bytes by the
//! time it reads one. That is what makes the label safe to publish and safe to
//! cite back after a restart.

use super::*;

/// This module's own result.
///
/// Spelled out rather than reusing the crate-wide `Result<T>` alias that
/// `super::*` brings in: a flow refusal is not a crate error. Every variant of
/// [`RealtimeFlowError`] is a typed answer this layer's callers match on and
/// act differently for — a stale session is retried on a new one, an exhausted
/// label space is not — and flattening them into `crate::Error` would turn
/// that distinction into a string.
type FlowResult<T> = std::result::Result<T, RealtimeFlowError>;

/// Which of one session's flows a unit belongs to.
///
/// This is the existing media lane coordinate generalized: assigned by the
/// opening side, pinned for the flow's lifetime, and published in the
/// application's own control messages so a receiver demultiplexes by explicit
/// binding rather than by inferring from arrival order. That inference was a
/// real bug — several concurrent feeds put one display's frames in another's
/// window — and the explicit label is what fixed it.
///
/// **Not a route or path identity, not a generation, not authority.** It names
/// one flow inside one authenticated session and nothing outside it. It is
/// never persisted. Session or connector-incarnation invalidation destroys the
/// whole label space with the session, and a value may be handed out again
/// only once the flow that held it is gone. Nothing orders two labels or
/// advances one.
///
/// `u8` deliberately, matching the coordinate it replaces: a wider identifier
/// would be a larger name adopted without evidence that the old width was the
/// constraint.
///
/// The one property that is easy to lose and is load-bearing: a receiver that
/// has lost its entire route table can still cite a label back to the sender,
/// and the sender can resolve it. That is the only way to report a dead flow
/// whose name is exactly what was lost, so a label must stay meaningful to the
/// *peer*, not merely inside the process that minted it.
/// How many flows one session can name at once.
///
/// Not a tunable and not a policy ceiling: it is the size of the label space
/// itself, fixed by [`RealtimeFlowLabel`] being a `u8`.
const REALTIME_LABEL_SPACE: u16 = u8::MAX as u16 + 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct RealtimeFlowLabel(u8);

impl RealtimeFlowLabel {
    /// The wire value. Only the application control path calls this; nothing
    /// in the flow path reads a label back as authority.
    pub(crate) fn get(self) -> u8 {
        self.0
    }

    /// Rebuild a label a peer cited back at us.
    ///
    /// Deliberately fallible-looking in use rather than in type: any `u8` is a
    /// syntactically valid label, so this cannot reject a hostile one. It
    /// grants nothing on its own — resolving it to a flow is a lookup in the
    /// session's own table, and a label naming no live flow simply finds
    /// nothing. Treat the result as a question, never as a claim.
    pub(crate) fn from_peer(value: u8) -> Self {
        Self(value)
    }
}

/// What an application says it will put on a flow.
///
/// The mime string is carried, compared for equality when a peer describes its
/// own flow, and otherwise never interpreted. Core does not know what
/// `video/H264` means and must not learn: the deployed set already includes
/// H.264 and Opus plus MJPEG and PCM fallbacks that exist to survive an older
/// daemon, and a core that branched on any of them would have to change to
/// admit the fifth.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RealtimeEncoding {
    kind: WebRtcRtpKind,
    mime: String,
    clock_rate: u32,
    channels: u16,
}

/// One RTCP feedback mechanism, as plain data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RealtimeRtcpFeedback {
    pub mechanism: String,
    pub parameter: String,
}

/// How a flow's RTP payloads become whole application units.
///
/// The application names a *strategy*; core resolves the strategy to one of
/// the framing adapters it implements. That resolution is a total map over
/// this enum, so it is not a codec-name branch and adding a codec never
/// touches core. The distinction is deliberately not inferable: two codecs
/// with the same MIME family could in principle be packetised either way, and
/// a wrong guess negotiates cleanly and then decodes to nothing — which is
/// exactly the failure that is hardest to attribute. So there is no default.
///
/// `non_exhaustive` because a third packetisation mode is a core capability,
/// and an application matching on this should be forced to say what it does
/// with one it has never heard of.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RealtimeFraming {
    /// Payloads are fragments carrying their own fragmentation headers, and
    /// the assembled unit is emitted as a start-code-delimited byte stream.
    AnnexB,
    /// Each payload is already one whole unit, carried through untouched.
    Whole,
}

/// What core does with a flow's RTP payloads, resolved from the strategy the
/// application declared.
///
/// Two policies rather than two framing adapters, because the difference is
/// not only *how* fragments are framed but *whether there is reassembly at
/// all*. [`RealtimeUnitAssembler`] completes a unit on the RTP marker bit; a
/// stream whose payloads are each already whole does not reliably set it —
/// Opus marks a talkspurt start and nothing after — so routing whole payloads
/// through the assembler would emit the first unit of each talkspurt and
/// silently swallow the rest. That failure is inaudible as an error and
/// audible as broken audio, which is the worst combination, so the two cases
/// stay structurally distinct instead of sharing a path with a flag.
pub(crate) enum RealtimeUnitPolicy {
    /// Payloads are fragments; reassemble, then frame with this adapter.
    Assembled(Arc<dyn RealtimeUnitFraming>),
    /// Each payload is one unit; hand it through with no reassembly state.
    PayloadPerUnit,
}

impl RealtimeFraming {
    /// The total map from declared strategy to core's implementation of it.
    ///
    /// Exhaustive by construction: a new strategy is a compile error here
    /// rather than a silent fallback. Nothing in this function reads a MIME
    /// name — the application chose the strategy, and core only supplies the
    /// machinery for the strategy it chose.
    pub(super) fn unit_policy(self) -> RealtimeUnitPolicy {
        match self {
            // Named for the codec it was written for, because it implements
            // that codec's fragmentation exactly. It is selected here by the
            // strategy the application named, never by recognising a codec.
            Self::AnnexB => RealtimeUnitPolicy::Assembled(Arc::new(H264Framing)),
            Self::Whole => RealtimeUnitPolicy::PayloadPerUnit,
        }
    }
}

/// One codec the application registers, complete enough to negotiate.
///
/// Plain data on purpose: no `webrtc` crate type appears here, so the
/// application boundary does not depend on the transport library. Core
/// converts these into registration parameters and never inspects what they
/// mean — there is no MIME-name branch anywhere on this path.
///
/// The fields are public because this is an input DTO with nothing to
/// protect: it grants nothing on its own, and the only way to turn a pile of
/// these into something the connector will use is [`RealtimeProfile::new`],
/// which validates and then owns an immutable copy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RealtimeCodec {
    /// Spelled in the provider's own vocabulary, which is the only one this
    /// concept has. A generic spelling would put a fixed audio/video taxonomy in
    /// the layer that must not have one, and a connector type reaching back into
    /// the generic vocabulary for its media kind is what would make it
    /// load-bearing there.
    pub kind: WebRtcRtpKind,
    pub payload_type: u8,
    pub mime: String,
    pub clock_rate: u32,
    pub channels: u16,
    pub fmtp: String,
    /// Stated per registration, but see [`RealtimeProfile::new`]: every
    /// variant of one encoding family must agree, because a flow opens
    /// against the family before a payload type has been negotiated.
    pub framing: RealtimeFraming,
    pub rtcp_feedback: Vec<RealtimeRtcpFeedback>,
}

impl RealtimeCodec {
    /// The four fields a flow selects on. Not the payload type: five H.264
    /// registrations differing only in `payload_type` and `fmtp` are one
    /// family, and a flow names the family.
    fn family(&self) -> (WebRtcRtpKind, String, u32, u16) {
        (
            self.kind,
            self.mime.to_ascii_lowercase(),
            self.clock_rate,
            self.channels,
        )
    }
}

/// Why an application profile was refused.
///
/// Every variant is a shape defect that would make negotiation or selection
/// ambiguous. None of them is a judgement about a codec: core does not have
/// an opinion about which codecs are acceptable, only about whether the
/// registration it was handed can be acted on unambiguously.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RealtimeProfileError {
    #[error("real-time profile registers no codecs")]
    NoCodecs,
    #[error("real-time profile declares a zero concurrent flow capacity")]
    NoCapacity,
    #[error(
        "real-time profile declares a concurrent flow capacity of {flow_capacity}, but a session \
         names its flows with a u8 label and so can hold at most {label_space}"
    )]
    CapacityExceedsLabelSpace {
        flow_capacity: u16,
        label_space: u16,
    },
    #[error("real-time codec with payload type {payload_type} has an empty MIME name")]
    EmptyMime { payload_type: u8 },
    #[error("real-time codec {mime} with payload type {payload_type} has a zero clock rate")]
    ZeroClockRate { mime: String, payload_type: u8 },
    #[error("real-time payload type {payload_type} is registered more than once")]
    DuplicatePayloadType { payload_type: u8 },
    #[error(
        "real-time codecs {mime} at {clock_rate} Hz disagree on framing, so a flow opened against \
         that family would have no framer to install"
    )]
    FamilyFramingConflict { mime: String, clock_rate: u32 },
}

/// The application's complete real-time profile, supplied before the peer
/// connection exists.
///
/// This replaces the two places the connector used to know codecs by name:
/// the frozen registration list, and the inbound track admission test. Both
/// now consult this, and both do it by equality against what the application
/// registered rather than by comparing a MIME string to a constant.
///
/// It must be supplied before `PeerConnection` creation because codec
/// registration is a property of the media engine the connection is built
/// from — there is no point after which a codec can be added to an existing
/// connection, so there is no point at which core could fall back to a
/// built-in list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RealtimeProfile {
    codecs: Vec<RealtimeCodec>,
    flow_capacity: u16,
}

impl RealtimeProfile {
    /// Validate and accept one application profile.
    ///
    /// The refusals are all shape, never codec judgement: something to
    /// register, no duplicate payload type (which would make negotiation
    /// ambiguous), no empty MIME or zero clock rate (which would make a
    /// capability unmatchable), no encoding family whose variants disagree on
    /// framing, and a non-zero capacity.
    ///
    /// Note what is deliberately *not* refused: two registrations agreeing on
    /// all four family fields. Deployed H.264 is five registrations differing
    /// only in payload type and fmtp, and rejecting that would reject the
    /// profile the daemon actually ships.
    pub fn new(
        codecs: Vec<RealtimeCodec>,
        flow_capacity: u16,
    ) -> std::result::Result<Self, RealtimeProfileError> {
        if codecs.is_empty() {
            return Err(RealtimeProfileError::NoCodecs);
        }
        if flow_capacity == 0 {
            return Err(RealtimeProfileError::NoCapacity);
        }
        // A session names its flows with a `u8`, so 256 is not a policy
        // ceiling to be tuned — it is the whole label space, and a capacity
        // above it is unsatisfiable rather than merely optimistic. Refused
        // here so it is a configuration error with a number attached, rather
        // than a `LabelInUse` on the 257th flow.
        if flow_capacity > REALTIME_LABEL_SPACE {
            return Err(RealtimeProfileError::CapacityExceedsLabelSpace {
                flow_capacity,
                label_space: REALTIME_LABEL_SPACE,
            });
        }
        let mut payload_types = std::collections::BTreeSet::new();
        let mut families: std::collections::BTreeMap<
            (WebRtcRtpKind, String, u32, u16),
            RealtimeFraming,
        > = std::collections::BTreeMap::new();
        for codec in &codecs {
            if codec.mime.trim().is_empty() {
                return Err(RealtimeProfileError::EmptyMime {
                    payload_type: codec.payload_type,
                });
            }
            if codec.clock_rate == 0 {
                return Err(RealtimeProfileError::ZeroClockRate {
                    mime: codec.mime.clone(),
                    payload_type: codec.payload_type,
                });
            }
            if !payload_types.insert(codec.payload_type) {
                return Err(RealtimeProfileError::DuplicatePayloadType {
                    payload_type: codec.payload_type,
                });
            }
            match families.entry(codec.family()) {
                std::collections::btree_map::Entry::Vacant(slot) => {
                    slot.insert(codec.framing);
                }
                std::collections::btree_map::Entry::Occupied(slot) => {
                    if *slot.get() != codec.framing {
                        return Err(RealtimeProfileError::FamilyFramingConflict {
                            mime: codec.mime.clone(),
                            clock_rate: codec.clock_rate,
                        });
                    }
                }
            }
        }
        Ok(Self {
            codecs,
            flow_capacity,
        })
    }

    /// Everything to register with the media engine, in the order supplied.
    pub(crate) fn codecs(&self) -> &[RealtimeCodec] {
        &self.codecs
    }

    /// Combined concurrent audio+video flows this peer will carry.
    pub(crate) fn flow_capacity(&self) -> u16 {
        self.flow_capacity
    }

    /// Every registered variant of the family an encoding names, in
    /// registration order.
    ///
    /// A family, not a tuple. The four fields answer "which transceiver, and
    /// did we register this at all"; they cannot answer "which payload type",
    /// because the offer advertises every variant and the *answerer* chooses.
    /// Resolving them to a single registration would pick a payload type the
    /// peer may not have selected, and that failure is silent: the track
    /// negotiates and then carries RTP the far side does not decode.
    fn variants<'a>(
        &'a self,
        encoding: &'a RealtimeEncoding,
    ) -> impl Iterator<Item = &'a RealtimeCodec> + 'a {
        self.family_of(
            encoding.kind(),
            encoding.mime(),
            encoding.clock_rate(),
            encoding.channels(),
        )
    }

    /// The lifetimes are named and unified rather than elided: the returned
    /// iterator borrows both the registration list and the MIME it is
    /// filtering against, and an edition-2021 opaque return type captures only
    /// lifetimes it can name.
    fn family_of<'a>(
        &'a self,
        kind: WebRtcRtpKind,
        mime: &'a str,
        clock_rate: u32,
        channels: u16,
    ) -> impl Iterator<Item = &'a RealtimeCodec> + 'a {
        self.codecs.iter().filter(move |codec| {
            codec.kind == kind
                && codec.clock_rate == clock_rate
                && codec.channels == channels
                && codec.mime.eq_ignore_ascii_case(mime)
        })
    }

    /// The framing to install for a flow, if this profile registered the
    /// family it names.
    ///
    /// One lookup answers both questions a flow open has: is this encoding
    /// registered at all (otherwise refuse), and which framer does the
    /// application want on it. `new` has already established that every
    /// variant of a family agrees, so taking the first is exact rather than
    /// first-wins.
    pub(crate) fn admits_encoding(&self, encoding: &RealtimeEncoding) -> Option<RealtimeFraming> {
        self.variants(encoding).next().map(|codec| codec.framing)
    }

    // An `admits(kind, mime, clock_rate, channels)` was here and is deliberately
    // gone rather than wired up. It asked whether a *shape* was registered,
    // which is a strictly weaker question than the one inbound admission
    // actually asks: `RealtimeInboundBindings::admit` compares an arriving
    // track against the exact binding this side recorded for the token it
    // arrived on, so a track can be the right shape and still be refused
    // because it is not the track we negotiated. Keeping a second, weaker gate
    // beside the exact one invites a future caller to reach for whichever it
    // finds first, and the weaker one answers `Some` for media the exact one
    // would refuse.
}

/// Which RTP media kind a flow negotiates.
///
/// An RTP transport primitive, not a codec name. A transceiver is audio or
/// video before any codec is chosen, so this is the one media distinction the
/// connector legitimately makes — and it is supplied by the application rather
/// than inferred from a MIME string, because inferring it would be the
/// codec-name branch this cutover removes.
///
/// **Named for its provider, and that is the whole point of the spelling.**
/// There is exactly one enum for this concept, it lives at the WebRTC edge, and
/// an application naming it is unambiguously naming a WebRTC fact. An
/// unqualified public spelling in the generic vocabulary would put a fixed
/// audio/video taxonomy in the layer that is supposed to know nothing about
/// media, and would make an application choose between two identical enums.
///
/// Serialized because the daemon's control request carries it verbatim, and
/// `"audio"` / `"video"` are the published wire contract. Relocating a type
/// across a boundary must not silently relocate the strings a client already
/// sends, so the spelling is pinned by a control rather than left to the derive.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebRtcRtpKind {
    Audio,
    Video,
}

impl RealtimeEncoding {
    /// An encoding an application declares for one flow.
    ///
    /// Refuses only what would make the flow meaningless to *either* end: an
    /// empty mime, which names nothing a peer could match, and a zero clock
    /// rate, which would make every inbound timestamp incomparable. Neither
    /// refusal is a codec judgement.
    /// Carries everything profile lookup needs to select one exact registered
    /// capability: the RTP kind, the MIME name, the clock rate, and the
    /// channel count. Nothing here is interpreted — the four are compared for
    /// equality against what the application registered, and a flow opens only
    /// if exactly one registered capability matches.
    pub(crate) fn new(
        kind: WebRtcRtpKind,
        mime: &str,
        clock_rate: u32,
        channels: u16,
    ) -> Option<Self> {
        (!mime.trim().is_empty() && clock_rate != 0).then(|| Self {
            kind,
            mime: mime.to_string(),
            clock_rate,
            channels,
        })
    }

    pub(crate) fn kind(&self) -> WebRtcRtpKind {
        self.kind
    }

    pub(crate) fn mime(&self) -> &str {
        &self.mime
    }

    /// Channel count. Zero is legitimate and means "not applicable", which is
    /// what a video capability carries — so it is deliberately not refused by
    /// [`Self::new`] the way an empty MIME or a zero clock rate are.
    pub(crate) fn channels(&self) -> u16 {
        self.channels
    }

    /// The rate inbound timestamps tick at. Supplied by the application, not
    /// derived from the mime, so a profile can carry a non-default clock
    /// without core holding a table of codec defaults.
    pub(crate) fn clock_rate(&self) -> u32 {
        self.clock_rate
    }
}

/// Which way units travel on a flow.
///
/// One direction per flow. A bidirectional application opens two, which keeps
/// each one's label, encoding and accounting its own — a display feed and a
/// return audio path have no reason to share a ceiling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RealtimeDirection {
    /// This endpoint sends; the peer receives.
    Outbound,
    /// This endpoint receives; the peer sends.
    Inbound,
}

/// One unit handed to a flow for sending.
///
/// Carries the pacing duration the application already has rather than an
/// absolute timestamp it would have to synthesise. The control surface these
/// applications use today supplies a per-frame duration — canonically 20 ms
/// for an Opus frame — and the RTP clock is advanced from it at the connector
/// edge, which is where the clock lives.
///
/// **No marker, deliberately, and the asymmetry with [`RealtimeRecvUnit`] is
/// the point.** On the wire the marker bit is a statement about packetization —
/// last packet of an access unit, first packet of a talkspurt — which this
/// flow's framing policy decides and the packetizer is the only thing
/// positioned to get right. An outbound marker would let a caller contradict
/// the packetizer that is about to run, producing a stream whose marker bits
/// disagree with its own fragmentation. It is also unimplementable: the native
/// send API carries no marker field, so a value accepted here could only ever
/// be discarded.
///
/// Inbound keeps one because there it is a *report* rather than an
/// instruction — the bit the sender set, carried through unchanged.
#[derive(Clone, Debug)]
pub(crate) struct RealtimeSendUnit {
    /// How long this unit occupies, which is what advances the RTP clock.
    pub(crate) pace: Duration,
    pub(crate) data: Bytes,
}

/// One unit received on a flow.
///
/// Deliberately *not* the same type as [`RealtimeSendUnit`]. Inbound really
/// does carry an absolute RTP timestamp at the flow's declared clock rate, and
/// outbound really does carry a duration; one type with a field meaning two
/// different things by direction is exactly the overload the applications
/// already suffer, where a single `u32` is documented as "µs for audio, RTP ts
/// for video". Two types cost one struct and remove the ambiguity entirely.
#[derive(Clone, Debug)]
pub(crate) struct RealtimeRecvUnit {
    /// Absolute, ticking at [`RealtimeEncoding::clock_rate`].
    pub(crate) timestamp: u32,
    /// The significance bit the sender set, carried through unchanged.
    pub(crate) marker: bool,
    pub(crate) data: Bytes,
}

/// What opening or sending on a flow can refuse.
///
/// Every variant is a refusal of *this* operation. None of them retire a flow
/// or a session on their own; a flow whose session has gone answers
/// [`Self::SessionNotCurrent`] for as long as anything still holds it, and is
/// reclaimed when its holder drops it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RealtimeFlowError {
    /// The session no longer names a live connector incarnation: it was
    /// replaced, retired, or the process restarted. Never re-bound — the
    /// application promotes a new session and opens new flows.
    SessionNotCurrent,
    /// This session already holds a flow under the requested label.
    ///
    /// Also what a full namespace looks like from here. The application is the
    /// sole allocator, so this side only ever claims one exact value: there is
    /// no path that inspects the whole space and no separate exhaustion
    /// answer, because nothing here could produce one.
    LabelInUse,
    /// The connector refused the flow: its own ceiling, or resources.
    FlowRefused,
    /// The encoding was not usable — empty mime or zero clock rate.
    EncodingInvalid,
}

/// What a real-time flow needs from a promoted session.
///
/// Stated as a trait on this side of the transport boundary on purpose. The
/// session type is transport-independent and must not learn about WebRTC
/// incarnations; this is the narrow question the flow path actually asks, so
/// the session owner satisfies it without either module importing the other's
/// vocabulary.
///
/// Both halves of currentness are asked together and neither is cached. The
/// identity is the session's — it privately retains the exact incarnation it
/// was promoted from — and the liveness is the connector's, which is the one
/// authoritative source for it. A flag on the session that answered the second
/// question would be a second source that could disagree with the first.
pub(crate) trait RealtimeSessionBinding {
    /// Whether this session was promoted from exactly `incarnation`, and that
    /// incarnation is still live.
    fn is_current_on(&self, incarnation: &Arc<crate::connector::ConnectorIncarnation>) -> bool;

    // One method, and a `remote_device_id` was deliberately removed from beside
    // it. It was offered for attribution and nothing ever read it — which is the
    // right outcome rather than a gap to fill: this trait is the *gate* a flow
    // operation passes, and a gate that also hands out the peer's identity
    // invites a caller to route on what it was given instead of presenting the
    // session again. A diagnostic that wants the Device asks the session
    // directly, where reading it is not adjacent to being authorized.
}

/// The labels one session has handed out.
///
/// Lives with the session, not with the registry: the label space is the
/// session's, so it dies with the session and cannot outlive the incarnation
/// its flows were bound to. A label is released when its flow is dropped, and
/// only then may the same value be handed out again.
#[derive(Default)]
pub(crate) struct RealtimeFlowLabels {
    held: std::collections::BTreeSet<u8>,
}

impl RealtimeFlowLabels {
    /// Claim the lowest free label, the way the lane pool it replaces did.
    ///
    /// Lowest-free is deliberate rather than incidental: it keeps the space
    /// dense, so a `u8` stays sufficient for the handful of concurrent flows a
    /// peer actually runs, and it makes the value a human reads in a trace the
    /// same one they would have read before this change.
    /// Claim the one label the application chose.
    ///
    /// The only way a label is ever taken. There is deliberately no
    /// lowest-free allocator here: the application owns route binding and
    /// dead-flow recovery, so it is the sole allocator, and a second one over
    /// the same space would agree until it did not — producing a collision on
    /// a live flow rather than a refusal at open.
    pub(crate) fn claim_exact(
        &mut self,
        label: RealtimeFlowLabel,
    ) -> FlowResult<RealtimeFlowLabel> {
        if !self.held.insert(label.0) {
            return Err(RealtimeFlowError::LabelInUse);
        }
        Ok(label)
    }

    /// Release a label, making it available again.
    ///
    /// Called when the flow that held it is gone, never merely because a peer
    /// said the flow was dead: a peer's report is a request to stop sending,
    /// and the label stays held until this side actually drops its flow. That
    /// ordering is what stops a stale report from freeing a label the next
    /// flow would immediately reuse.
    pub(crate) fn release(&mut self, label: RealtimeFlowLabel) {
        self.held.remove(&label.0);
    }

    /// Whether this label is currently held by a live flow of this session.
    ///
    /// **Controls only, and gated rather than merely documented as such.**
    /// Production never asks: `claim_exact` already answers "was this free" as
    /// part of taking it, and every other question about a label is really a
    /// question about the flow behind it, which the flow map answers. A second
    /// predicate over a second collection is a fact that can disagree with the
    /// first, and an ungated one reads as a check production could be expected
    /// to make.
    ///
    /// What the controls need it for is the opposite direction: asserting that
    /// a label is *released* at the exact moment its flow is dropped, which is
    /// not observable from the flow map because the entry is already gone.
    #[cfg(test)]
    pub(crate) fn holds(&self, label: RealtimeFlowLabel) -> bool {
        self.held.contains(&label.0)
    }
}

/// One real-time flow, bound to the session that opened it.
///
/// Holds the connector-local port (which owns admission, queueing and every
/// resource claim), the session-scoped label, and the exact connector
/// incarnation the session was promoted from. Dropping it returns the label
/// and releases the port, which removes the flow from the registry.
///
/// **Byte movement is not here.** Outbound units go to the connector's track
/// and inbound units arrive on the registry's ready queue, both through the
/// pump that already owns them; this type owns the *binding* — who may use the
/// flow, under which name, for how long. Putting the pump behind it would move
/// codec-shaped work back into the layer this cutover is taking it out of.
/// One unit waiting in a flow's queue, holding the bytes it is accounted for.
///
/// The lease travels with the unit and is released when the unit is taken or
/// when the queue is dropped. That is what makes teardown release memory
/// without a separate sweep: dropping the flow drops the queue drops the
/// leases.
struct QueuedUnit<T> {
    unit: T,
    _payload: RealtimePayloadLease,
}

/// A flow's own queue, in its own direction.
///
/// Deliberately not the inbound `QueuedTransportEvent` path. That queue
/// carries `TransportEvent` into the engine callback pump and only knows the
/// codec-specific sample variants; putting outbound units on it would send
/// them the wrong way through a type that cannot describe them.
///
/// Bounded by resource accounting rather than by a count. Every unit holds a
/// payload lease taken before it is queued, so the ceiling is the owner's
/// existing byte budget and there is no new queue-depth constant to choose.
struct RealtimeFlowQueue<T> {
    units: SyncMutex<std::collections::VecDeque<QueuedUnit<T>>>,
    ready: Arc<tokio::sync::Notify>,
    /// Whether a pump has already been issued for this queue.
    ///
    /// One permit from `Drop` wakes one waiter, so "at most one pump" is not a
    /// convention here — it is the precondition that makes closure reliable,
    /// and it is enforced rather than assumed.
    pump_issued: std::sync::atomic::AtomicBool,
}

/// Dropping the queue wakes its pump — durably.
///
/// This is what makes closure mechanical rather than announced. There is no
/// retirement event and no `closed` flag to set: dropping `PromotedSession`
/// drops the flow set, the flows, and their queues, and this is the wake. A
/// flag would be a second fact that could disagree with the drop; the wake
/// cannot, because it *is* the drop.
///
/// **`notify_one`, deliberately, not `notify_waiters`.** `notify_waiters`
/// wakes only tasks already registered and stores nothing, which loses the
/// wake in exactly the gap a pump spends most of its life in: it observes an
/// empty queue, and the drop lands before it registers. It would then park on
/// a queue that no longer exists, forever. `notify_one` stores a permit when
/// nobody is waiting, so the pump's next `notified()` returns immediately and
/// it sees the failed upgrade. One permit is enough because a queue issues at
/// most one pump — see [`RealtimeFlowQueue::claim_pump`].
impl<T> Drop for RealtimeFlowQueue<T> {
    fn drop(&mut self) {
        self.ready.notify_one();
    }
}

impl<T> RealtimeFlowQueue<T> {
    fn new() -> Self {
        Self {
            units: SyncMutex::new(std::collections::VecDeque::new()),
            ready: Arc::new(tokio::sync::Notify::new()),
            pump_issued: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Claim the right to be this queue's pump. Answers `false` if one was
    /// already issued.
    ///
    /// The single permit stored by `Drop` wakes one waiter. A second pump on
    /// the same queue would be the waiter that never wakes, so the invariant
    /// is enforced here rather than left to callers.
    fn claim_pump(&self) -> bool {
        !self
            .pump_issued
            .swap(true, std::sync::atomic::Ordering::AcqRel)
    }

    /// Append one unit. Synchronous and lock-scoped: the guard is dropped
    /// before the wake, so a waiting drainer never contends with the push that
    /// woke it.
    fn push(&self, unit: T, payload: RealtimePayloadLease) {
        {
            let mut units = self.units.lock();
            units.push_back(QueuedUnit {
                unit,
                _payload: payload,
            });
        }
        self.ready.notify_one();
    }

    /// Take the oldest unit, if any. Never blocks and never awaits — the
    /// caller may be holding the registry mutation lock.
    fn pop(&self) -> Option<T> {
        self.units.lock().pop_front().map(|queued| queued.unit)
    }

    /// A handle a pump can await on without holding any lock of this flow.
    fn ready(&self) -> Arc<tokio::sync::Notify> {
        Arc::clone(&self.ready)
    }
}

/// The queue a flow owns, typed by its direction.
///
/// Two distinct types rather than one with a direction field: an outbound unit
/// carries a pacing duration and an inbound one carries an absolute RTP
/// timestamp, and the whole reason those are separate types is that a single
/// overloaded slot is what the applications already suffer from. The queues
/// they sit in stay separate for the same reason.
/// Held behind `Arc` so a pump can observe the queue's death through a `Weak`
/// rather than be told about it.
enum FlowQueue {
    Outbound(Arc<RealtimeFlowQueue<RealtimeSendUnit>>),
    Inbound(Arc<RealtimeFlowQueue<RealtimeRecvUnit>>),
}

/// Everything the outbound pump needs, and deliberately nothing more.
///
/// The queue is `Weak`: the pump never keeps a flow alive. When the session
/// retires, the flow set drops, the queue drops, `ready` fires from the
/// queue's `Drop`, the pump wakes, `upgrade` answers `None`, and the pump
/// ends. No retirement event, no flag, no ordering to get right.
///
/// The pump holds `ready` as a strong `Arc` on purpose — it has to survive the
/// queue in order to deliver the very wake that announces the queue is gone.
pub(super) struct RealtimeOutboundPump {
    queue: std::sync::Weak<RealtimeFlowQueue<RealtimeSendUnit>>,
    ready: Arc<tokio::sync::Notify>,
}

impl RealtimeOutboundPump {
    /// Take the next unit to write, or answer why there is none.
    ///
    /// `Closed` is terminal: the flow is gone and the pump must stop rather
    /// than wait again. `Empty` means park on [`Self::ready`] and retry.
    pub(super) fn next(&self) -> RealtimePumpStep {
        let Some(queue) = self.queue.upgrade() else {
            return RealtimePumpStep::Closed;
        };
        match queue.pop() {
            Some(unit) => RealtimePumpStep::Unit(unit),
            None => RealtimePumpStep::Empty,
        }
    }

    /// Await the next wake — a push, or the queue's own drop.
    pub(super) async fn ready(&self) {
        self.ready.notified().await;
    }
}

/// What one turn of the outbound pump found.
pub(super) enum RealtimePumpStep {
    Unit(RealtimeSendUnit),
    Empty,
    /// The flow is gone. Terminal.
    Closed,
}

/// The native half a closed flow leaves behind, and how it gets finished.
///
/// Handed back by [`SessionRealtimeFlows::close`] rather than retired there:
/// close runs under the fence, which is a sync mutex and cannot await, and both
/// forms of retirement are async. The caller finishes outside it.
///
/// The two directions differ because their ownership does, not because of a
/// convention. An outbound flow's track was moved into its pump at attach, so
/// nothing here can hand it back — only a receipt for the retirement the pump
/// performs on its own. An inbound flow's transceiver is owned by the
/// connector's track table, so what comes back is the token that names it.
///
/// `None` is ordinary, not an error: a flow closed before negotiation reached
/// the native layer has nothing outstanding.
pub(crate) enum RealtimeFlowRemains {
    /// The token whose transceiver is still to be stopped. The caller stops it
    /// through the connector worker, which owns that decision; a token whose
    /// retirement someone else already claimed is a no-op there, which is what
    /// makes an explicit close and an implicit drop safe to race.
    Inbound(Arc<RealtimeTrackIdentity>),
    /// A receipt for the outbound pump's own retirement.
    ///
    /// The close that produced it dropped the flow's queue, which is what wakes
    /// the pump; the pump then removes its track and completes this. Awaiting it
    /// only makes the caller's acknowledgement truthful — the retirement happens
    /// whether anyone waits or not, and that is why an implicit session drop
    /// needs no hook.
    Outbound(RealtimeNativeRetired),
    None,
}

impl Default for RealtimeFlowRemains {
    fn default() -> Self {
        Self::None
    }
}

/// One flow's end-of-life wake.
///
/// Held by the flow and watched by its inbound pump. `Drop` is the whole signal,
/// so an explicit close and an implicit session drop fire it identically — the
/// pump cannot tell those apart and must not have to.
///
/// It exists because a failed port upgrade is not enough on its own. The pump
/// spends its life parked in `read_rtp`, and a peer that has stopped sending
/// never returns from it; without this the flow would be closed and its reader
/// still parked, holding a native read lease, until the connection died.
///
/// `notify_one`, not `notify_waiters`. The wake almost always arrives while the
/// pump is inside `read_rtp` rather than at its watch point, and
/// `notify_waiters` drops a signal with no one currently waiting. `notify_one`
/// stores a permit, so the wake is still there when the pump looks. This is the
/// same reason [`SessionStreamReader`] hands its reconnect permit the same way.
struct RealtimeFlowEnd(Arc<tokio::sync::Notify>);

impl RealtimeFlowEnd {
    fn new() -> Self {
        Self(Arc::new(tokio::sync::Notify::new()))
    }

    /// The watcher's half. Strong, because the watcher must still be able to
    /// observe the wake after the flow that sent it is gone.
    fn watch(&self) -> Arc<tokio::sync::Notify> {
        Arc::clone(&self.0)
    }
}

impl Drop for RealtimeFlowEnd {
    fn drop(&mut self) {
        self.0.notify_one();
    }
}

/// A non-owning claim on one already-open flow's port.
///
/// The inbound pump's only route to the flow it feeds, and deliberately not a
/// [`RealtimeFlowPort`]: that is `Clone` and owns an `Arc<RealtimeFlowLifetime>`,
/// so a pump holding one would keep the registry's active-flow lease alive for
/// as long as the pump ran — which is past the close that was supposed to
/// release it.
///
/// It is equally deliberately not a second `open_inbound_flow_checked`. The flow
/// this feeds is already open and already holds exactly one active-flow lease;
/// taking a second for the same application flow halves the configured capacity
/// and lets the second acquisition refuse media on a flow whose open had already
/// succeeded. One application flow, one lease.
///
/// Upgrade per unit and hold across nothing. A failed upgrade *is* the close and
/// needs no other signal; the reservations taken from the upgraded port hold it
/// strongly for the in-progress unit only, which is the one window where a flow
/// must not vanish under work already accounted for.
#[derive(Clone)]
pub(super) struct RealtimeFlowPortHandle {
    lifetime: std::sync::Weak<RealtimeFlowLifetime>,
}

impl RealtimeFlowPortHandle {
    /// A weak claim on an open flow, from a strong one.
    ///
    /// For a caller that legitimately owns the port already and needs to lend
    /// the assembler a claim without lending it the lease.
    pub(super) fn of(port: &RealtimeFlowPort) -> Self {
        Self {
            lifetime: Arc::downgrade(&port.lifetime),
        }
    }

    /// The port, while its flow is still open.
    pub(super) fn port(&self) -> Option<RealtimeFlowPort> {
        Some(RealtimeFlowPort {
            lifetime: self.lifetime.upgrade()?,
        })
    }
}

/// Everything one admitted inbound track needs to feed its flow.
///
/// Separate from [`RealtimeInboundBinding`], which stays a declarative record of
/// what was negotiated — comparable, printable, and free of runtime handles.
/// This is the live half, produced only by [`RealtimeInboundBindings::admit`].
pub(super) struct RealtimeInboundAttachment {
    pub(super) label: RealtimeFlowLabel,
    pub(super) policy: RealtimeUnitPolicy,
    pub(super) port: RealtimeFlowPortHandle,
    pub(super) end: Arc<tokio::sync::Notify>,
}

pub(crate) struct RealtimeFlow {
    port: RealtimeFlowPort,
    label: RealtimeFlowLabel,
    encoding: RealtimeEncoding,
    direction: RealtimeDirection,
    queue: FlowQueue,
    /// Dropped with this flow, waking whatever was reading for it.
    end: RealtimeFlowEnd,
    /// What this flow's close will leave for its caller to finish.
    ///
    /// Recorded as negotiation reaches the native layer — a token at
    /// `bind_inbound`, a completion lease at `attach_outbound` — and taken out
    /// exactly once, by close. A flow that never got that far leaves `None`.
    native: RealtimeFlowRemains,
    /// The incarnation the opening session was promoted from. Retained by
    /// value so the gate below compares against the connector this flow was
    /// actually opened on, never against whatever is current now — a
    /// replacement must fail the check, not silently satisfy it.
    incarnation: Arc<crate::connector::ConnectorIncarnation>,
}

impl RealtimeFlow {
    pub(crate) fn label(&self) -> RealtimeFlowLabel {
        self.label
    }

    pub(crate) fn encoding(&self) -> &RealtimeEncoding {
        &self.encoding
    }

    pub(crate) fn direction(&self) -> RealtimeDirection {
        self.direction
    }

    /// The connector-local port, for the pump that moves this flow's bytes.
    ///
    /// Reached only through [`Self::port_if_current`], never directly, so the
    /// gate cannot be skipped by a caller that happens to hold the flow.
    fn port(&self) -> &RealtimeFlowPort {
        &self.port
    }

    /// A weak claim on this flow's port, for the pump that feeds it.
    ///
    /// The gate is not skipped by handing this out. What the holder gets is the
    /// ability to reach *this* flow's accounting for as long as this flow is
    /// open, and nothing at all afterwards — which is exactly the authority an
    /// inbound pump needs and no more. Currentness is still proved before the
    /// binding that yields one is ever recorded.
    fn port_handle(&self) -> RealtimeFlowPortHandle {
        RealtimeFlowPortHandle::of(&self.port)
    }

    /// Whether `session` may still use this flow, given the connector's own
    /// currently-live incarnation.
    ///
    /// Three facts, and all three are needed. `live` proves the connector has
    /// not retired — it is `None` from the worker once it has. `Arc::ptr_eq`
    /// against the retained incarnation proves the live connector is the one
    /// this flow was opened on, not a replacement that took its place. And the
    /// session answers that it was promoted from that same incarnation.
    ///
    /// **Liveness cannot come from `session.is_current_on` and must not be
    /// asked of it.** That predicate is identity-only: `ConnectorIncarnation`
    /// deliberately carries no liveness, because the transport is the single
    /// authoritative source and a second flag could disagree with it. Asked
    /// against this flow's *retained* `Arc` it would answer true forever,
    /// including against a dead connector — so the retained value can only
    /// ever be one half of an identity comparison, never the source of the
    /// currentness answer.
    ///
    /// A replaced or retired connector fails here and is never re-bound: the
    /// application promotes a new session and opens new flows.
    pub(crate) fn is_current_for(
        &self,
        session: &impl RealtimeSessionBinding,
        live: &Arc<crate::connector::ConnectorIncarnation>,
    ) -> bool {
        Arc::ptr_eq(live, &self.incarnation) && session.is_current_on(&self.incarnation)
    }

    /// The port, but only while the session that opened this flow is still
    /// current on the connector it was opened on.
    ///
    /// This is the send- and receive-time gate. It is deliberately the *only*
    /// way to reach the port: a flow outlives its session's currentness — the
    /// holder may not have dropped it yet — so possession of a `RealtimeFlow`
    /// cannot be allowed to mean permission to use one.
    /// Visible only inside the connector, because it hands back a
    /// connector-local port. The binding checks above are `pub(crate)`; the
    /// port itself never leaves this layer.
    ///
    /// `live` is taken as the `Option` the worker actually returns, not as an
    /// unwrapped reference, so a caller cannot reach this gate holding a value
    /// it obtained some other way. A retired connector yields `None` and is
    /// refused here; that is the whole reason the argument is threaded in
    /// rather than read off `self`.
    pub(super) fn port_if_current(
        &self,
        session: &impl RealtimeSessionBinding,
        live: Option<&Arc<crate::connector::ConnectorIncarnation>>,
    ) -> FlowResult<&RealtimeFlowPort> {
        let Some(live) = live else {
            return Err(RealtimeFlowError::SessionNotCurrent);
        };
        if !self.is_current_for(session, live) {
            return Err(RealtimeFlowError::SessionNotCurrent);
        }
        Ok(self.port())
    }
}

/// Open one flow for `session` on `incarnation`.
///
/// The caller resolves a Device selector to a session through the registry
/// fence and lends the borrow in; nothing here retains it, which is what keeps
/// the session non-`Clone` promise intact — the flow holds a binding it
/// re-checks, never a capability it could re-present.
///
/// Refuses before claiming anything if the session is not current on this
/// incarnation, so a replaced session cannot consume a label or a flow slot on
/// its way to being refused.
pub(super) fn open_session_flow(
    session: &impl RealtimeSessionBinding,
    live: Option<&Arc<crate::connector::ConnectorIncarnation>>,
    registry: &Arc<RealtimeFlowRegistry>,
    labels: &mut RealtimeFlowLabels,
    spec: RealtimeFlowSpec,
) -> FlowResult<RealtimeFlow> {
    // Same acquisition rule as the send-time gate: `live` is the worker's own
    // `Option`, which is `None` once the connector has retired. A flow can
    // therefore only ever be opened on a connector that is alive at the moment
    // of opening, and the value retained below is that exact incarnation — so
    // the later gate has something true to compare against.
    let Some(incarnation) = live else {
        return Err(RealtimeFlowError::SessionNotCurrent);
    };
    if !session.is_current_on(incarnation) {
        return Err(RealtimeFlowError::SessionNotCurrent);
    }
    // One allocator, and it is not this one. The application names the label;
    // this side claims exactly that value or refuses. There is no lowest-free
    // path in production: a second allocator over one space would collide on a
    // live flow rather than fail at open.
    let label = labels.claim_exact(spec.label)?;
    // The checked forms deliberately, not the `Option` twins: those are
    // `#[cfg(test)]` or discard the reason, and a refused open is worth
    // knowing the cause of even where this layer answers one variant for all
    // of them.
    let port = match spec.direction {
        RealtimeDirection::Outbound => registry.open_outbound_flow_checked(),
        RealtimeDirection::Inbound => registry.open_inbound_flow_checked(),
    };
    // The connector refused: its own ceiling, or resources. Hand the label
    // back before returning, or a refused open would burn a name no flow ever
    // held. The reason stays inside the connector, which already recorded it
    // through its own drop accounting; surfacing it here would put a
    // connector-local vocabulary in this layer's public error.
    let port = match port {
        Ok(port) => port,
        Err(refused) => {
            labels.release(label);
            return Err(realtime_drop_refusal(refused));
        }
    };
    let queue = match spec.direction {
        RealtimeDirection::Outbound => FlowQueue::Outbound(Arc::new(RealtimeFlowQueue::new())),
        RealtimeDirection::Inbound => FlowQueue::Inbound(Arc::new(RealtimeFlowQueue::new())),
    };
    Ok(RealtimeFlow {
        port,
        label,
        encoding: spec.encoding,
        direction: spec.direction,
        queue,
        end: RealtimeFlowEnd::new(),
        native: RealtimeFlowRemains::None,
        incarnation: Arc::clone(incarnation),
    })
}

/// What an application asks for when opening a flow.
#[derive(Clone, Debug)]
pub(crate) struct RealtimeFlowSpec {
    pub(crate) direction: RealtimeDirection,
    pub(crate) encoding: RealtimeEncoding,
    /// The label the application chose. Required: this side never allocates.
    pub(crate) label: RealtimeFlowLabel,
}

/// Every real-time flow one promoted session holds, and the label namespace
/// they are drawn from.
///
/// One opaque bundle, stored with the peer's promoted-session state and
/// dropped with it. That placement is the whole design: session replacement or
/// retirement drops this set, which releases every label and every flow at
/// once, so there is no separate invalidation step that could be missed and no
/// label that can outlive the incarnation its flow was opened on.
///
/// The engine never reaches the label namespace. It calls the operations
/// below, each of which borrows the current session and takes the connector's
/// freshly acquired live incarnation; the namespace itself is not reachable
/// from outside this module. No durable id, no generation, no timer.
/// `pub(crate)` so the peer entry can hold one, and no wider. The two things
/// worth protecting stay private: `RealtimeFlowLabels` and the `RealtimeFlow`
/// handles are fields, not API, and every method answers a label or a unit —
/// never a `RealtimeFlowPort`, which stays `pub(super)` to the connector.
/// One session-scoped, single-consumer stream.
///
/// The same mechanical-closure shape as [`RealtimeFlowQueue`], for the same
/// reasons and with the same two non-negotiables: `notify_one` in `Drop`, so
/// the wake survives the gap between observing empty and parking; and a claim
/// guard, so exactly one consumer can ever be waiting on that single permit.
///
/// Session-scoped rather than per-flow because the consumer is one task
/// serving every flow of a session. Per-flow signals would leave it choosing
/// between polling each flow on a timer and sweeping the whole label space,
/// and both of those answer "has anything arrived" by asking 256 questions
/// instead of being told once. This way it parks once and is woken by exactly
/// the thing it was waiting for.
struct SessionStream<T> {
    items: SyncMutex<std::collections::VecDeque<T>>,
    ready: Arc<tokio::sync::Notify>,
    claimed: std::sync::atomic::AtomicBool,
}

/// Dropping the stream ends it.
///
/// Retirement is the drop, never a message inside the stream. A `Retired`
/// item would be a second fact that could be dropped, reordered, or emitted
/// twice; the end of the stream is the drop itself and can be none of those.
impl<T> Drop for SessionStream<T> {
    fn drop(&mut self) {
        self.ready.notify_one();
    }
}

impl<T> SessionStream<T> {
    fn new() -> Self {
        Self {
            items: SyncMutex::new(std::collections::VecDeque::new()),
            ready: Arc::new(tokio::sync::Notify::new()),
            claimed: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Claim the right to be this stream's reader, if nobody currently holds
    /// it.
    ///
    /// A CAS rather than a swap, and *currently* rather than *ever*: the claim
    /// is a lease held by a live [`SessionStreamReader`] and returned when
    /// that reader drops. A daemon whose consumer pipe dies must be able to
    /// reconnect to the same session, and a one-shot claim would have made the
    /// session unreadable for the rest of its life over a client that hung up.
    ///
    /// One holder at a time is still enforced, and still for the original
    /// reason: closure is delivered by a single stored permit, so two
    /// simultaneous waiters would leave one that never wakes.
    fn claim(&self) -> bool {
        self.claimed
            .compare_exchange(
                false,
                true,
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
            )
            .is_ok()
    }

    /// Append one item. Synchronous and lock-scoped: producers run under the
    /// registry mutation lock, and the guard is released before the wake.
    fn push(&self, item: T) {
        {
            let mut items = self.items.lock();
            items.push_back(item);
        }
        self.ready.notify_one();
    }

    fn take(&self) -> Option<T> {
        self.items.lock().pop_front()
    }
}

/// The consumer end of a session stream.
///
/// Deliberately holds only a `Weak`. A reader can never keep a session's flow
/// set alive, which is what lets the set's drop be the end-of-stream rather
/// than something that has to be announced before it happens.
pub(crate) struct SessionStreamReader<T> {
    stream: std::sync::Weak<SessionStream<T>>,
    /// Strong on purpose: it has to outlive the stream in order to deliver the
    /// very wake that says the stream is gone.
    ready: Arc<tokio::sync::Notify>,
}

/// The reader *is* the claim.
///
/// Returning it on drop is what makes a consumer reconnectable: a daemon whose
/// client pipe dies drops its reader, and the next one takes the lease and
/// picks up the queue where the first left it. Nothing is lost in the gap
/// because items accumulate on the stream, not in the reader.
///
/// Nothing to return once the stream is gone, and nothing that could take it:
/// a lease is only ever issued by the session's flow set, so when that set has
/// been dropped there is no object left to ask.
impl<T> Drop for SessionStreamReader<T> {
    fn drop(&mut self) {
        if let Some(stream) = self.stream.upgrade() {
            stream
                .claimed
                .store(false, std::sync::atomic::Ordering::Release);
        }
    }
}

impl<T> SessionStreamReader<T> {
    /// Whether this reader was claimed on `stream`.
    ///
    /// Pointer identity between the reader's `Weak` and a live `Arc`. A reader
    /// whose stream has already been dropped names nothing — `Weak::as_ptr`
    /// still returns its old address, so this compares against a strong
    /// reference the caller is holding, which cannot be a recycled allocation
    /// while that reference exists.
    fn names(&self, stream: &Arc<SessionStream<T>>) -> bool {
        std::ptr::eq(self.stream.as_ptr(), Arc::as_ptr(stream))
    }

    /// The next item, or `None` once the session's flow set has been dropped.
    ///
    /// `None` is terminal. It means the `PromotedSession` that owned these
    /// flows is gone, so there will never be another item and the consumer
    /// should end.
    ///
    /// **Holds nothing across the await.** Not the registry mutation lock —
    /// the caller obtained this reader and released that lock long before
    /// awaiting. Not the stream's own lock, which `take` releases before
    /// returning. And not a strong reference to the stream: the upgraded `Arc`
    /// is dropped at the end of the `if let`, because a reader parked while
    /// holding one would keep the flow set alive and wait forever for an end
    /// it was itself preventing.
    pub(crate) async fn next(&self) -> Option<T> {
        loop {
            if let Some(stream) = self.stream.upgrade() {
                if let Some(item) = stream.take() {
                    return Some(item);
                }
            } else {
                return None;
            }
            self.ready.notified().await;
        }
    }
}

/// What happened to one of this session's flows.
///
/// Emitted by the same call that mutated the flow set, under the same lock, so
/// there is no second bookkeeping to disagree with the first.
///
/// **There is no `Opened`, deliberately.** A flow only ever exists because the
/// authenticated local application asked for one, and that ask is already
/// answered by its own request response — an event would be a second, weaker
/// account of something the caller was told directly. More to the point, an
/// `Opened` event is the shape a peer-minted flow would arrive in, and a peer
/// cannot mint a flow here at all: inbound negotiation may only *attach* to a
/// flow this side already opened. Publishing the variant would advertise a
/// capability that does not exist and invite a consumer to wait for it.
///
/// There is no retirement variant either. The session going away is the
/// stream ending, which is the drop itself and cannot be dropped, reordered,
/// or emitted twice the way a message could.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RealtimeFlowEvent {
    /// A flow that existed under this label no longer does, and the label is
    /// free for the application to claim again.
    Closed { label: RealtimeFlowLabel },
}

/// A connector drop reason, as the refusal this layer reports.
///
/// Every reason but one is a capacity answer — a ceiling, an oversize unit, a
/// poisoned domain — and they are all `FlowRefused`, because the caller's flow
/// could succeed later and the connector's vocabulary has no business in this
/// layer's error.
///
/// `Retired` is the exception and is the reason this function exists. The
/// registry retires with its connector, so a retired registry means the
/// session this flow belonged to is already gone. Reporting that as
/// `FlowRefused` would tell a caller to back off and retry a flow that can
/// never come back, and would hide a replacement behind what looks like
/// pressure. `SessionNotCurrent` is terminal, which is what it actually is.
fn realtime_drop_refusal(reason: RealtimeFlowDropReason) -> RealtimeFlowError {
    match reason {
        RealtimeFlowDropReason::Retired => RealtimeFlowError::SessionNotCurrent,
        _ => RealtimeFlowError::FlowRefused,
    }
}

/// The profile the controls in this module and its parent open flows against.
///
/// Two families, one of each framing, so both unit policies are reachable
/// without a control having to build a profile of its own.
///
/// It exists because `open` now refuses an unregistered family *before* it
/// acquires a label or a flow slot. A control passing no profile would have
/// every open answer `EncodingInvalid`, which would make the assertions after
/// it vacuous rather than failing — the exact shape of silent test rot this
/// module's controls are written to avoid.
#[cfg(test)]
pub(super) fn control_realtime_profile() -> RealtimeProfile {
    RealtimeProfile::new(
        vec![
            RealtimeCodec {
                kind: WebRtcRtpKind::Video,
                payload_type: 102,
                mime: "video/H264".to_string(),
                clock_rate: 90_000,
                channels: 0,
                fmtp: "packetization-mode=1".to_string(),
                framing: RealtimeFraming::AnnexB,
                rtcp_feedback: Vec::new(),
            },
            RealtimeCodec {
                kind: WebRtcRtpKind::Audio,
                payload_type: 111,
                mime: "audio/opus".to_string(),
                clock_rate: 48_000,
                channels: 2,
                fmtp: "minptime=10".to_string(),
                framing: RealtimeFraming::Whole,
                rtcp_feedback: Vec::new(),
            },
        ],
        REALTIME_LABEL_SPACE,
    )
    .expect("the control profile registers two well-formed families")
}

/// What a negotiated inbound track has to be in order to attach to a flow.
///
/// Recorded by the connector when it negotiates a receive transceiver for a
/// flow the local application has *already* opened, and consulted when the
/// track actually arrives. Never built from anything the peer said.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RealtimeInboundBinding {
    label: RealtimeFlowLabel,
    encoding: RealtimeEncoding,
    framing: RealtimeFraming,
}

impl RealtimeInboundBinding {
    pub(crate) fn new(
        label: RealtimeFlowLabel,
        encoding: RealtimeEncoding,
        framing: RealtimeFraming,
    ) -> Self {
        Self {
            label,
            encoding,
            framing,
        }
    }

    /// The unit policy the application's profile chose for this family.
    ///
    /// There is deliberately no `label` accessor beside it. The destination is
    /// reached only through [`RealtimeInboundBindings::admit`], which hands back
    /// a [`RealtimeInboundAttachment`] carrying the label together with the
    /// handles on the flow that label names — so there is no way to learn where
    /// a track may go without having passed the admission that decided it may
    /// go anywhere.
    fn unit_policy(&self) -> RealtimeUnitPolicy {
        self.framing.unit_policy()
    }
}

/// Exact process-local identity for one negotiated inbound track.
///
/// **Minted by this side, before the transceiver that will carry the track
/// exists.** That ordering is the whole point: a binding is recorded against
/// the token first, and only then is a transceiver created against it, so any
/// track that can ever arrive under this token already had a binding when the
/// thing that would carry it was built. There is no window in which a track
/// arrives before its binding, and so no start-of-flow media to lose.
///
/// It deliberately replaces the obvious key, which was the transceiver's MID.
/// A MID is *a string that appears in SDP* — keying the demux table on one
/// makes the key a value that also crosses the wire, so the peer would have a
/// hand in naming its own destination. A minted token cannot appear in an
/// answer at all, and the peer has no way to name one.
///
/// Identity is the allocation, the same construction
/// [`crate::connector::ConnectorIncarnation`] uses. It carries no state, is not
/// `Clone` by value, is not serializable, and has no public constructor, so it
/// grants nothing on its own — it only answers "is this the track we built for
/// that flow".
pub(crate) struct RealtimeTrackIdentity {
    /// Zero fields, but not a unit struct: the `Arc` allocation *is* the
    /// identity, and a unit struct invites someone to construct one by value.
    _minted: (),
}

impl RealtimeTrackIdentity {
    /// Mint one identity.
    ///
    /// `pub(crate)` so the engine can mint one inside the same fence
    /// acquisition that claims the label and records the binding. That
    /// atomicity is what makes the ordering above structural rather than
    /// merely usual.
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self { _minted: () })
    }
}

/// Connector-owned demux from negotiated track identity to the flow it may
/// attach to.
///
/// **The label is not on this table because a peer sent it.** An entry exists
/// only because the local application opened an inbound flow and this side
/// then minted a token and negotiated a transceiver against it, so a track
/// resolving to no token on this table has nothing to attach to and is
/// dropped. That is the whole authority argument: a peer can influence *which*
/// of our flows a track lands on only to the extent of presenting a token we
/// already created, and it can create none.
pub(crate) struct RealtimeInboundBindings {
    /// A list rather than a map, deliberately. The obvious map key for an
    /// `Arc` identity is its address, and an address is exactly the thing that
    /// can be recycled once the allocation behind it is freed; holding the
    /// `Arc` strongly in the entry would prevent that, but then the key and
    /// the thing keeping it valid are two facts that have to stay in step.
    /// A linear scan compared by `Arc::ptr_eq` has no second fact at all.
    ///
    /// The scan is not a cost worth avoiding: it runs once per arriving track,
    /// never per packet, and the list is bounded by the session's label space.
    bound: SyncMutex<Vec<RealtimeInboundEntry>>,
}

/// One negotiated token and everything admitting its track needs.
struct RealtimeInboundEntry {
    identity: Arc<RealtimeTrackIdentity>,
    binding: RealtimeInboundBinding,
    /// The already-open flow this token's track feeds, weakly.
    port: RealtimeFlowPortHandle,
    /// The wake that ends its pump when that flow goes.
    end: Arc<tokio::sync::Notify>,
}

impl Default for RealtimeInboundBindings {
    fn default() -> Self {
        Self {
            bound: SyncMutex::new(Vec::new()),
        }
    }
}

impl RealtimeInboundBindings {
    /// Record what the connector will negotiate for one already-open inbound
    /// flow.
    ///
    /// Answers `false` if that token is already bound, rather than replacing:
    /// a second binding on one token would make attachment ambiguous, and
    /// silently taking the newer one would move a live flow's media onto a
    /// different flow.
    ///
    /// Refuses an outbound direction outright. Nothing outbound is ever
    /// attachable, so an outbound entry could only ever be a mistake that this
    /// table would then make look deliberate.
    pub(crate) fn bind(
        &self,
        identity: Arc<RealtimeTrackIdentity>,
        direction: RealtimeDirection,
        binding: RealtimeInboundBinding,
        port: RealtimeFlowPortHandle,
        end: Arc<tokio::sync::Notify>,
    ) -> bool {
        if direction != RealtimeDirection::Inbound {
            return false;
        }
        let mut bound = self.bound.lock();
        if bound
            .iter()
            .any(|entry| Arc::ptr_eq(&entry.identity, &identity))
        {
            return false;
        }
        bound.push(RealtimeInboundEntry {
            identity,
            binding,
            port,
            end,
        });
        true
    }

    /// Forget every binding for one label, when its flow closes.
    pub(crate) fn release(&self, label: RealtimeFlowLabel) {
        self.bound
            .lock()
            .retain(|entry| entry.binding.label != label);
    }

    /// The single admission decision for a negotiated inbound track.
    ///
    /// Fail-closed in both halves. A token with no binding answers `None`,
    /// because this side never offered it. A token whose negotiated shape is
    /// not the shape we bound also answers `None` — a peer that answered with
    /// a different codec than the flow was opened for is not delivering that
    /// flow's media, and attaching it would feed a decoder configured for
    /// something else.
    ///
    /// MIME comparison is case-insensitive because SDP is; everything else is
    /// exact.
    ///
    /// What comes back is the live half — the destination label, the framing
    /// policy, and the two handles on the already-open flow. It notably does not
    /// include an active-flow lease, because the flow being attached to already
    /// holds the only one it is entitled to.
    pub(super) fn admit(
        &self,
        identity: &Arc<RealtimeTrackIdentity>,
        kind: WebRtcRtpKind,
        mime: &str,
        clock_rate: u32,
        channels: u16,
    ) -> Option<RealtimeInboundAttachment> {
        let bound = self.bound.lock();
        let entry = bound
            .iter()
            .find(|entry| Arc::ptr_eq(&entry.identity, identity))?;
        let expected = &entry.binding.encoding;
        (expected.kind() == kind
            && expected.clock_rate() == clock_rate
            && expected.channels() == channels
            && expected.mime().eq_ignore_ascii_case(mime))
        .then(|| RealtimeInboundAttachment {
            label: entry.binding.label,
            policy: entry.binding.unit_policy(),
            port: entry.port.clone(),
            end: Arc::clone(&entry.end),
        })
    }
}

/// The reader an inbound consumer awaits: one label per unit that arrived.
pub(crate) type RealtimeInboundArrivals = SessionStreamReader<RealtimeFlowLabel>;

/// The reader a lifecycle consumer awaits.
pub(crate) type RealtimeFlowEvents = SessionStreamReader<RealtimeFlowEvent>;

/// The allocation whose address *is* one flow set's identity.
///
/// Its own type rather than reusing the arrivals stream, which is the other
/// per-set allocation to hand. Overloading that one would tie the identity of
/// a session's flows to an implementation detail of how its units are
/// delivered, and the two have no reason to change together.
struct RealtimeFlowSetToken;

/// A token naming one flow set, for a caller that has to prove it is
/// committing to the set it started against.
///
/// The window it closes: a promotion can drop a cached session and re-promote
/// on the **same live connector incarnation**, so a caller that opened a flow,
/// released the fence to do async work, and re-entered can find a different
/// flow set behind an identical incarnation — holding a live flow under the
/// same `u8`. Neither the label nor the incarnation separates those two. This
/// does.
///
/// Holds a `Weak` deliberately: a token must never keep a flow set alive, or
/// the retirement it exists to detect could not happen while one was
/// outstanding.
pub(crate) struct RealtimeFlowSetIdentity(std::sync::Weak<RealtimeFlowSetToken>);

pub(crate) struct SessionRealtimeFlows {
    labels: RealtimeFlowLabels,
    flows: std::collections::BTreeMap<u8, RealtimeFlow>,
    /// This set's identity. Nothing reads it but [`SessionRealtimeFlows::identity`]
    /// and [`SessionRealtimeFlows::is_same`]; it exists to be an address that
    /// belongs to exactly one flow set and dies with it.
    identity: Arc<RealtimeFlowSetToken>,
    /// One label per delivered unit, in arrival order — not a set of flows
    /// with something pending.
    ///
    /// One entry per unit means an arrival and a `recv` correspond exactly, so
    /// a consumer that takes one entry and does one `recv` never has to ask
    /// whether more remain on that flow. Deduplicating to a set would make an
    /// entry mean "at least one", and answering "how many" would put the
    /// sweep back.
    arrivals: Arc<SessionStream<RealtimeFlowLabel>>,
    /// Close, from the same mutation that maintains `flows`.
    lifecycle: Arc<SessionStream<RealtimeFlowEvent>>,
    /// What the connector negotiated for this session's inbound flows.
    ///
    /// Held here rather than on the connector so it dies with the session that
    /// owns the flows it names. A binding that outlived its session would be
    /// an identity still admitting media into a flow set that no longer
    /// exists, which is the one thing this table must never do.
    bindings: Arc<RealtimeInboundBindings>,
    /// Held from construction rather than passed per call, so the engine never
    /// names a connector-local type. The registry is the connector's; a set
    /// built against one connector cannot be used with another.
    registry: Arc<RealtimeFlowRegistry>,
    /// The application's registered codecs, for the one question binding a
    /// flow asks of them: which framing to install.
    ///
    /// Held here because the answer has to be available *inside* the fence, at
    /// the moment the label is claimed and the binding recorded, and the engine
    /// has no profile and must not learn about framing. `None` is a connector
    /// with no registered profile, which can hold no inbound bindings at all —
    /// a flow whose family nothing registered has no framer to install, so
    /// refusing is the only available answer.
    profile: Option<RealtimeProfile>,
}

impl SessionRealtimeFlows {
    /// An empty set for a session just promoted on `registry`'s connector.
    ///
    /// Deliberately not `Default`: a set with no registry could be constructed
    /// in a state that can never open a flow, and the peer entry would hold it
    /// looking valid.
    /// `pub(super)`, not `pub(crate)`: it names the connector-local registry,
    /// so exposing it crate-wide would leak that type into the engine's
    /// vocabulary. The engine constructs one through the worker accessor,
    /// which is the whole reason that accessor exists.
    pub(super) fn new(
        registry: Arc<RealtimeFlowRegistry>,
        profile: Option<RealtimeProfile>,
    ) -> Self {
        Self {
            labels: RealtimeFlowLabels::default(),
            flows: std::collections::BTreeMap::new(),
            identity: Arc::new(RealtimeFlowSetToken),
            registry,
            profile,
            arrivals: Arc::new(SessionStream::new()),
            lifecycle: Arc::new(SessionStream::new()),
            bindings: Arc::new(RealtimeInboundBindings::default()),
        }
    }

    /// A token naming this exact flow set.
    pub(crate) fn identity(&self) -> RealtimeFlowSetIdentity {
        RealtimeFlowSetIdentity(Arc::downgrade(&self.identity))
    }

    /// Whether `identity` names *this* flow set.
    ///
    /// Compares the caller's `Weak` against this set's **live strong**
    /// reference, never `Weak` against `Weak`. `Weak::as_ptr` keeps answering
    /// its old address after the allocation is freed, so a dead-versus-dead
    /// comparison can match a recycled allocation and report two unrelated
    /// sets as the same one. Comparing against a strong reference the callee is
    /// holding cannot: that address is occupied for as long as the comparison
    /// takes. Same construction as [`SessionStreamReader::names`].
    pub(crate) fn is_same(&self, identity: &RealtimeFlowSetIdentity) -> bool {
        std::ptr::eq(identity.0.as_ptr(), Arc::as_ptr(&self.identity))
    }

    /// The negotiated-track table for this session, as a **`Weak`**.
    ///
    /// `pub(super)`: the connector reads it when a track arrives. The engine
    /// never touches it, and the application cannot reach it at all — which is
    /// what keeps a token on it a fact this side established rather than a
    /// value a peer supplied.
    ///
    /// Weak, and that is a correctness property rather than a hygiene
    /// preference. The table's whole job is to stop admitting media the moment
    /// its session ends; a connector holding a strong reference would keep it
    /// alive past the `PromotedSession` that owns the flows it names, leaving
    /// a table that still resolves tokens to labels in a flow set that no
    /// longer exists. With a `Weak` the connector's upgrade simply fails, and
    /// the arriving track is dropped — which is the answer that was wanted.
    pub(super) fn inbound_bindings(&self) -> std::sync::Weak<RealtimeInboundBindings> {
        Arc::downgrade(&self.bindings)
    }

    /// The awaitable inbound stream for this whole session.
    ///
    /// `None` while another reader is live. Not `None` forever: the claim is
    /// an RAII lease, so a consumer that dies and reconnects takes it back and
    /// resumes on the same queue. A second *simultaneous* reader is what is
    /// refused, because closure is one stored permit and the second waiter
    /// would never wake — the same invariant as the outbound pump.
    ///
    /// A reclaiming reader drains what accumulated in the gap before it parks:
    /// `next` takes first and only awaits when there was nothing to take, so a
    /// reconnect never sleeps on a queue that already has work in it.
    ///
    /// The reader is detached by construction. A caller takes it while holding
    /// the registry mutation lock, releases the lock, and only then awaits, so
    /// the lock is never held across a suspension point. That is not a
    /// convention the caller has to remember: the reader borrows nothing from
    /// the flow set, so there is nothing it could still be holding.
    pub(crate) fn inbound_arrivals(&self) -> Option<RealtimeInboundArrivals> {
        self.arrivals.claim().then(|| SessionStreamReader {
            stream: Arc::downgrade(&self.arrivals),
            ready: Arc::clone(&self.arrivals.ready),
        })
    }

    /// The awaitable open/close stream for this whole session.
    ///
    /// A separate stream with its own signal rather than a second consumer of
    /// the arrival stream: one permit wakes one waiter, so two consumers
    /// sharing a signal would lose wakes for whichever one did not get it.
    ///
    /// Leased and reclaimable on exactly the same terms as
    /// [`Self::inbound_arrivals`].
    pub(crate) fn flow_events(&self) -> Option<RealtimeFlowEvents> {
        self.lifecycle.claim().then(|| SessionStreamReader {
            stream: Arc::downgrade(&self.lifecycle),
            ready: Arc::clone(&self.lifecycle.ready),
        })
    }

    /// Open one flow under the label the application chose.
    ///
    /// The application is the sole allocator: it owns route binding and the
    /// dead-flow recovery path, so it is the only side that can name a flow
    /// after losing its route table. This side validates rather than
    /// allocates — an already-held label answers `LabelInUse`, which is also
    /// what makes the application's own view self-correcting when it drifts.
    /// Two allocators over one space would agree until they did not, and the
    /// failure would be a collision on a live flow rather than an error here.
    pub(crate) fn open(
        &mut self,
        session: &impl RealtimeSessionBinding,
        live: Option<&Arc<crate::connector::ConnectorIncarnation>>,
        spec: RealtimeFlowSpec,
    ) -> FlowResult<RealtimeFlowLabel> {
        // Asked here, before anything is acquired, and for both directions.
        //
        // `open` is the contract boundary: an encoding the application never
        // registered has no framing to install and no codec to negotiate, and
        // that is a property of the *request*, not of what the transport later
        // makes of it. Inbound already learned this at `bind_inbound`, but
        // outbound had no such point — it claimed a label, opened a registry
        // flow, and only failed once the worker's negotiation guard refused,
        // which the engine then reports as `FlowRefused`. That tells a caller
        // to retry something that can never succeed. `EncodingInvalid` is what
        // it actually is, and answering it before the acquisitions means a
        // refused open costs neither a label nor a flow slot.
        //
        // `bind_inbound` still resolves framing from this same profile rather
        // than caching it here: this answers whether the family is registered,
        // that one answers what its framing is, and both come from one place.
        if !self
            .profile
            .as_ref()
            .is_some_and(|profile| profile.admits_encoding(&spec.encoding).is_some())
        {
            return Err(RealtimeFlowError::EncodingInvalid);
        }
        let registry = Arc::clone(&self.registry);
        let flow = open_session_flow(session, live, &registry, &mut self.labels, spec)?;
        let label = flow.label();
        // The label was claimed inside `open_session_flow` against this very
        // namespace, so an occupied slot here would mean the two had diverged.
        // Insert and assert the slot was free by construction rather than
        // silently replacing a live flow.
        // Checked before the insert, never after. `insert` returning the old
        // value would mean the flow it named had already been replaced and
        // dropped — so answering `LabelInUse` at that point would report a
        // refusal having already destroyed a live flow. The defensive branch
        // has to refuse without mutating, or it is not defensive.
        if self.flows.contains_key(&label.get()) {
            return Err(RealtimeFlowError::LabelInUse);
        }
        self.flows.insert(label.get(), flow);
        // No event. The caller asked for this flow and is being handed the
        // label right now; telling it again on a stream would be a second
        // account of the same fact.
        Ok(label)
    }

    /// Record what the connector is about to negotiate for an already-open
    /// inbound flow.
    ///
    /// Called in the **same fence acquisition** that claimed the label, before
    /// the transceiver exists. That ordering is the point: any track that can
    /// ever present this token is carried by a transceiver created against it
    /// afterwards, so the binding is never later than the media it admits.
    /// Binding after negotiation would only *usually* precede the first track,
    /// and a starved task would turn "usually" into lost units at flow start.
    ///
    /// A binding that briefly exists with no transceiver behind it is inert —
    /// nothing can present its token — so the failure direction is harmless.
    ///
    /// Gated like every other use, and additionally refused for a flow this
    /// side did not open inbound: an outbound flow has nothing to attach, and
    /// a binding on one could only ever be a mistake this table would then make
    /// look deliberate.
    pub(crate) fn bind_inbound(
        &mut self,
        session: &impl RealtimeSessionBinding,
        live: Option<&Arc<crate::connector::ConnectorIncarnation>>,
        label: RealtimeFlowLabel,
        identity: Arc<RealtimeTrackIdentity>,
    ) -> FlowResult<()> {
        let Some(flow) = self.flows.get(&label.get()) else {
            return Err(RealtimeFlowError::FlowRefused);
        };
        flow.port_if_current(session, live)?;
        if flow.direction() != RealtimeDirection::Inbound {
            return Err(RealtimeFlowError::FlowRefused);
        }
        // The framing is resolved here, from the application's own profile,
        // rather than carried in by the caller. The engine has no profile and
        // must not learn what framing means; and a family the profile never
        // registered has no framer to install, which is a refusal rather than
        // a default. This is the same question `admits_encoding` answers for
        // an arriving track, asked once at bind time so both ends of the
        // decision come from one place.
        let Some(framing) = self
            .profile
            .as_ref()
            .and_then(|profile| profile.admits_encoding(flow.encoding()))
        else {
            return Err(RealtimeFlowError::EncodingInvalid);
        };
        let binding = RealtimeInboundBinding::new(label, flow.encoding().clone(), framing);
        // The pump's two handles on this flow, taken here because this is the
        // last point at which the flow and the table are both in hand. Both are
        // non-owning in the sense that matters: the port claim cannot keep the
        // flow's registry lease alive, and the wake is a signal rather than a
        // reference to anything.
        let port = flow.port_handle();
        let end = flow.end.watch();
        if !self.bindings.bind(
            Arc::clone(&identity),
            RealtimeDirection::Inbound,
            binding,
            port,
            end,
        ) {
            return Err(RealtimeFlowError::FlowRefused);
        }
        // Recorded only once the table has accepted, so a refused bind leaves
        // nothing for close to hand back. Reached by a second lookup because the
        // checks above hold the flow immutably; the entry is known to exist.
        if let Some(flow) = self.flows.get_mut(&label.get()) {
            flow.native = RealtimeFlowRemains::Inbound(identity);
        }
        Ok(())
    }

    /// Attach the negotiated native track to an already-open outbound flow and
    /// start the flow-owned pump.
    ///
    /// **Hands the track back on every refusal.** Releasing a native track is
    /// async and this runs under the fence, which cannot await — so a refusal
    /// that swallowed the track would leak a native object with nothing left
    /// able to free it. Returning it puts it in the one place that can await:
    /// the caller, once it has left the fence.
    ///
    /// The pump claim is taken last, after every other check has passed, so a
    /// refusal never consumes the one pump a queue can issue.
    pub(crate) fn attach_outbound(
        &mut self,
        session: &impl RealtimeSessionBinding,
        live: Option<&Arc<crate::connector::ConnectorIncarnation>>,
        label: RealtimeFlowLabel,
        track: RealtimeOutboundTrack,
    ) -> std::result::Result<(), (RealtimeFlowError, RealtimeOutboundTrack)> {
        let Some(flow) = self.flows.get(&label.get()) else {
            return Err((RealtimeFlowError::FlowRefused, track));
        };
        if let Err(refusal) = flow.port_if_current(session, live) {
            return Err((refusal, track));
        }
        let FlowQueue::Outbound(queue) = &flow.queue else {
            return Err((RealtimeFlowError::FlowRefused, track));
        };
        // Last, and only once nothing else can refuse: a queue issues exactly
        // one pump, and a consumed claim cannot be handed back with the track.
        if !queue.claim_pump() {
            return Err((RealtimeFlowError::FlowRefused, track));
        }
        let pump = RealtimeOutboundPump {
            queue: Arc::downgrade(queue),
            ready: queue.ready(),
        };
        // The pump task owns the track from here, and is the only thing that
        // may retire it. That is what makes teardown mechanical: the flow drops,
        // its queue drops, the pump's upgrade fails, it removes its own track
        // and completes the lease below. No retirement event, and no second
        // owner that could remove the same track twice or keep a sender alive
        // past its session.
        let (retired, remains) = tokio::sync::oneshot::channel();
        spawn_outbound_realtime_pump(pump, track, retired);
        // Recorded after the spawn, so the lease on the flow always names a pump
        // that exists. `attach_outbound` is reached once per flow — the pump
        // claim above is single-issue — so this cannot overwrite an earlier one.
        if let Some(flow) = self.flows.get_mut(&label.get()) {
            flow.native = RealtimeFlowRemains::Outbound(remains);
        }
        Ok(())
    }

    /// Close one flow, release its label, and hand back its native remainder.
    ///
    /// Gated like every other use: a caller whose session is no longer current
    /// cannot close a flow, because it can no longer prove the flow is one of
    /// *its* flows. The set is dropped wholesale when the session goes, so a
    /// refused close never strands anything.
    ///
    /// **The return value is not optional bookkeeping.** A flow's native half
    /// outlives this call — retiring either kind awaits, and this runs under a
    /// sync fence — so the caller has to finish it outside. Discarding the
    /// [`RealtimeFlowRemains`] is not a leak in the outbound case (the pump
    /// retires regardless; the receipt is only how a caller learns it happened)
    /// but it is one in the inbound case, where the token is the only handle on
    /// a transceiver still offering to receive.
    pub(crate) fn close(
        &mut self,
        session: &impl RealtimeSessionBinding,
        live: Option<&Arc<crate::connector::ConnectorIncarnation>>,
        label: RealtimeFlowLabel,
    ) -> FlowResult<RealtimeFlowRemains> {
        let Some(flow) = self.flows.get(&label.get()) else {
            return Err(RealtimeFlowError::FlowRefused);
        };
        flow.port_if_current(session, live)?;
        // Order matters: take the flow out first, then release the label. The
        // label is only free once nothing holds the flow it named. The gate
        // above has already passed, so this removal cannot be the mutation of a
        // refused close.
        let mut flow = self
            .flows
            .remove(&label.get())
            .expect("the flow was just read under this same borrow");
        // Taken before the drop, because the drop is what makes it unreachable.
        let remains = std::mem::take(&mut flow.native);
        // Explicit, and the ordering matters twice over: dropping the flow
        // closes its queue, which wakes an outbound pump, and drops the end
        // guard, which wakes an inbound one. Both happen before this returns,
        // so a caller that then awaits the outbound receipt is waiting on a pump
        // that has already been told to stop.
        drop(flow);
        // Before the label is free: a negotiated identity still pointing at
        // this label after the label could be reclaimed would attach a peer's
        // media to whatever flow took the name next.
        self.bindings.release(label);
        self.labels.release(label);
        self.lifecycle.push(RealtimeFlowEvent::Closed { label });
        Ok(remains)
    }

    /// Queue one unit for sending on an outbound flow.
    ///
    /// **Synchronous, and it must stay so.** This runs under the registry
    /// mutation lock, which connector replacement also takes — that is what
    /// makes "the session is still current" and "the unit is queued" one
    /// atomic step rather than a check followed by an act. An await here would
    /// hold that lock across a suspension point and deadlock against the very
    /// replacement it is meant to be atomic with. The write to the native
    /// track happens on the pump's task, outside the lock.
    ///
    /// The unit is accounted before it is queued, so a flow cannot grow an
    /// unbounded backlog: a refused reservation refuses the send. That is
    /// correct for real-time — paced and lossy, freshness over delivery — and
    /// it uses the owner's existing byte budget rather than a new queue-depth
    /// constant.
    pub(crate) fn send(
        &self,
        session: &impl RealtimeSessionBinding,
        live: Option<&Arc<crate::connector::ConnectorIncarnation>>,
        label: RealtimeFlowLabel,
        unit: RealtimeSendUnit,
    ) -> FlowResult<()> {
        let Some(flow) = self.flows.get(&label.get()) else {
            return Err(RealtimeFlowError::FlowRefused);
        };
        let port = flow.port_if_current(session, live)?;
        // Sending on an inbound flow is a caller error, refused rather than
        // silently dropped — the queues are separate types precisely so this
        // cannot be a runtime coin-flip about which one a unit lands in.
        let FlowQueue::Outbound(queue) = &flow.queue else {
            return Err(RealtimeFlowError::FlowRefused);
        };
        let output = port
            .reserve_output_checked(unit.data.len())
            .map_err(realtime_drop_refusal)?;
        queue.push(unit, output.into_payload_lease());
        Ok(())
    }

    /// Take the next unit received on an inbound flow, if one is waiting.
    ///
    /// Answers `Ok(None)` for a live flow with nothing queued, which is an
    /// ordinary state and not a refusal. `Err` means the flow is gone, the
    /// session is not current, or the caller named an outbound flow.
    pub(crate) fn recv(
        &self,
        session: &impl RealtimeSessionBinding,
        live: Option<&Arc<crate::connector::ConnectorIncarnation>>,
        label: RealtimeFlowLabel,
    ) -> FlowResult<Option<RealtimeRecvUnit>> {
        let Some(flow) = self.flows.get(&label.get()) else {
            return Err(RealtimeFlowError::FlowRefused);
        };
        flow.port_if_current(session, live)?;
        let FlowQueue::Inbound(queue) = &flow.queue else {
            return Err(RealtimeFlowError::FlowRefused);
        };
        Ok(queue.pop())
    }

    // A `outbound_pump(label)` accessor was here and is deliberately gone. It
    // handed out a pump for any label, leaving "was a native track ever
    // attached to this flow" as a separate fact a caller had to keep in step.
    // `attach_outbound` now claims the pump and starts it in the same step that
    // takes custody of the track, so a pump cannot exist without the track it
    // writes to and the track cannot exist without a pump to release it.

    /// **Controls only.** One delivery accounted against `label`'s flow,
    /// exactly as the inbound pump accounts one.
    ///
    /// A control outside this module cannot build a deliverable unit. A
    /// `RealtimeInboundDelivery` assembled from its public constructor carries
    /// no payload lease, and [`Self::deliver_inbound`] refuses a leaseless
    /// delivery before it looks anything up — so a control that built one would
    /// observe that refusal rather than whatever it meant to test. Minting the
    /// lease itself is not open to it either, and deliberately: the lease type
    /// stays inside `transport::webrtc` so nothing upstream can hold an
    /// accounting claim apart from the unit it belongs to.
    ///
    /// So the mint happens here, through the same reservation the assembler's
    /// output takes, and hands back only the opaque delivery. The bytes are
    /// charged the way the real path charges them, which is the only reason a
    /// control driving this proves anything about the real path.
    ///
    /// `None` when the label names no flow of this set, or when the flow's
    /// envelope refuses the bytes — both of which a control should read as a
    /// fixture that cannot express what it wanted, not as the answer.
    ///
    /// Gated to the same audience as its callers: every control that mints one
    /// needs a real promoted session over a live link, which only the
    /// `transport-lab` harness builds.
    #[cfg(all(test, feature = "transport-lab"))]
    pub(crate) fn accounted_delivery_for_test(
        &self,
        label: RealtimeFlowLabel,
        unit: RealtimeRecvUnit,
    ) -> Option<RealtimeInboundDelivery> {
        let flow = self.flows.get(&label.get())?;
        let payload = flow
            .port
            .reserve_output(unit.data.len())?
            .into_payload_lease();
        let mut delivery = RealtimeInboundDelivery::new(label, unit);
        delivery
            .attach(payload)
            .expect("a freshly built delivery has no lease to displace");
        Some(delivery)
    }

    /// Deliver one assembled unit onto an inbound flow.
    ///
    /// Called by the connector's inbound track pump, which has already
    /// accounted the bytes through the assembler's output reservation and hands
    /// that lease over inside the delivery. Answers whether the flow was there
    /// to take it; a unit for a flow that has gone is dropped with its lease,
    /// which releases the bytes rather than stranding them.
    ///
    /// **Takes the delivery whole, and splits it here.** The engine drives this
    /// — it is where the promoted session's flow set lives, and the connector
    /// cannot deliver anything because it holds no session — but the engine must
    /// never hold the three parts separately. A `RealtimePayloadLease` in the
    /// engine's hands is an accounting claim it could drop independently of the
    /// unit it belongs to, so the type stays inside `transport::webrtc` and the
    /// split happens on this side of that line. `pub(crate)` on this method
    /// exposes only the opaque delivery.
    ///
    /// A delivery that arrives without a lease is refused before anything is
    /// looked up. Only the realtime queue mints one and it attaches before it
    /// queues, so a leaseless delivery did not come through the accounting path
    /// at all. That refusal used to sit in the engine, ahead of the fence; it is
    /// here now because splitting the delivery is what reveals it, and one place
    /// deciding what a leaseless delivery means is worth more than saving a lock
    /// acquisition on a path that cannot occur.
    pub(crate) fn deliver_inbound(&self, delivery: RealtimeInboundDelivery) -> bool {
        let Some((label, unit, payload)) = delivery.into_parts() else {
            return false;
        };
        let Some(flow) = self.flows.get(&label.get()) else {
            return false;
        };
        match &flow.queue {
            FlowQueue::Inbound(queue) => {
                queue.push(unit, payload);
                // Recorded only after the unit is really on the flow's queue,
                // so an arrival never names a unit a `recv` cannot find.
                self.arrivals.push(label);
                true
            }
            FlowQueue::Outbound(_) => false,
        }
    }

    /// Take the unit an arrival named, with the label it arrived on.
    ///
    /// The consumer's half of [`Self::inbound_arrivals`]: await a label
    /// outside the lock, then call this under it. Synchronous, like every
    /// other flow-set operation, so the session-currency check and the take
    /// are one atomic step against connector replacement.
    ///
    /// `Ok(None)` is ordinary rather than exceptional. An arrival is a hint
    /// that a unit was queued, not a claim that it still is: the flow may have
    /// been closed in the gap, in which case the unit went with it and its
    /// bytes were released. The consumer simply awaits the next arrival. That
    /// is why a stale arrival costs one lookup and not a sweep.
    pub(crate) fn recv_arrival(
        &self,
        session: &impl RealtimeSessionBinding,
        live: Option<&Arc<crate::connector::ConnectorIncarnation>>,
        label: RealtimeFlowLabel,
    ) -> FlowResult<Option<(RealtimeFlowLabel, RealtimeRecvUnit)>> {
        if !self.flows.contains_key(&label.get()) {
            return Ok(None);
        }
        Ok(self.recv(session, live, label)?.map(|unit| (label, unit)))
    }

    /// Whether `label` names a live flow of this session that may still be
    /// used right now.
    pub(crate) fn is_current(
        &self,
        session: &impl RealtimeSessionBinding,
        live: Option<&Arc<crate::connector::ConnectorIncarnation>>,
        label: RealtimeFlowLabel,
    ) -> bool {
        self.flows
            .get(&label.get())
            .is_some_and(|flow| flow.port_if_current(session, live).is_ok())
    }

    /// Whether `reader` is *this* flow set's arrivals reader.
    ///
    /// The fence a label alone cannot provide. A consumer awaits an arrival
    /// outside the registry mutation lock and then re-enters it to take the
    /// unit, and a session can be replaced in that window. The fence it
    /// re-enters would then resolve the *new* session entirely correctly —
    /// peer resolves, session current, incarnation live — and find a live flow
    /// under the same `u8`. The unit handed back would be real, current, and
    /// attributed to a flow the consumer believes is something else.
    ///
    /// Connector-incarnation identity does not separate the two, because a
    /// session can be dropped and re-promoted on the same live worker, giving
    /// a new flow set on the same incarnation. What does separate them is the
    /// stream itself: each flow set owns its own, and a reader claimed on the
    /// old session does not name the new one's. So the reader *is* the proof
    /// of which session the label was spoken about.
    ///
    /// Pointer identity, deliberately, not a generation counter: a counter is
    /// a second fact that can be stale or wrap, whereas the reader either
    /// points at this flow set's stream or it does not.
    pub(crate) fn owns_arrivals(&self, reader: &RealtimeInboundArrivals) -> bool {
        reader.names(&self.arrivals)
    }

    /// Whether `bindings` is *this* flow set's negotiated-track table.
    ///
    /// The connector holds the table weakly and upgrades it when a track
    /// arrives; this is how a control states which set an upgraded handle came
    /// from. Compared against the live strong reference this set holds, for the
    /// same reason as [`Self::is_same`].
    ///
    /// **Controls only, and gated rather than merely documented as such.**
    /// Production never asks: `on_track` upgrades the weak slot and uses
    /// whatever it gets, because that slot is installed by the same call that
    /// builds the set and there is no second candidate to distinguish from. An
    /// ungated accessor would read as a check production could be expected to
    /// make, and the next reader would wonder why it does not.
    #[cfg(test)]
    pub(super) fn owns_bindings(&self, bindings: &Arc<RealtimeInboundBindings>) -> bool {
        Arc::ptr_eq(&self.bindings, bindings)
    }

    // `with_current_port` was here and is deliberately gone. It lent a
    // `&RealtimeFlowPort` to an arbitrary `FnOnce(&RealtimeFlowPort) -> R`,
    // and `R` could be `RealtimeFlowPort` — a port is cloneable, so a caller
    // could pass `Clone::clone` and walk a live port out past the very
    // currentness fence the method exists to impose. Everything after that
    // point would be authorized by a check that had already stopped being
    // true.
    //
    // It had no callers, so this is a removal rather than a repair. When the
    // outbound pump needs a port it gets a purpose-built accessor whose return
    // type says what may escape, instead of a generic one that cannot.
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A label names one flow, and a released one is reusable only after its
    /// flow is gone.
    ///
    /// The positive half of the label contract: lowest-free allocation, exact
    /// reclaim, and the reuse ordering that stops a stale peer report from
    /// freeing a live flow's name.
    #[test]
    fn v4_macro1_a_label_is_held_for_its_flows_lifetime_and_reusable_only_after() {
        let mut labels = RealtimeFlowLabels::default();

        let first = labels
            .claim_exact(RealtimeFlowLabel::from_peer(0))
            .expect("the space starts empty");
        let second = labels
            .claim_exact(RealtimeFlowLabel::from_peer(1))
            .expect("a second flow takes the value the application chose for it");
        assert_ne!(first, second, "two live flows never share a label");

        // While held, the exact value is refused rather than quietly aliased.
        assert_eq!(
            labels.claim_exact(first),
            Err(RealtimeFlowError::LabelInUse),
            "a live flow's label cannot be taken from under it"
        );
        assert!(labels.holds(first));

        // Released only when the flow itself is gone; then, and not before,
        // the value is available again.
        labels.release(first);
        assert!(!labels.holds(first));
        let reused = labels
            .claim_exact(first)
            .expect("the freed value is available again");
        assert_eq!(reused, first, "and it is the same value, not a new one");
        assert!(
            labels.holds(second),
            "releasing one flow's label never disturbs another's"
        );
    }

    /// A pump distinguishes "nothing queued yet" from "the flow is gone", and
    /// the second is caused by the drop itself.
    ///
    /// This is the lifecycle ruling made mechanical: there is no retirement
    /// event and no `closed` flag. Dropping the session bundle drops the flow
    /// set, the flows, and their queues; the pump holds only a `Weak`, so the
    /// drop is what ends it. The discriminating half is the first assertion —
    /// a pump that reported `Closed` whenever it had nothing to do would pass
    /// a closure test trivially and would stop every idle flow.
    #[tokio::test]
    async fn v4_macro1_a_pump_ends_because_its_queue_dropped_not_because_it_was_told() {
        let queue = Arc::new(RealtimeFlowQueue::<RealtimeSendUnit>::new());
        let pump = queue
            .claim_pump()
            .then(|| RealtimeOutboundPump {
                queue: Arc::downgrade(&queue),
                ready: queue.ready(),
            })
            .expect("the first pump claims the queue");

        assert!(
            matches!(pump.next(), RealtimePumpStep::Empty),
            "a live flow with an empty queue is idle, not closed — a pump that \
             confused the two would stop the first time it caught up"
        );

        // The exact gap. The pump has just observed Empty and has NOT yet
        // parked; retirement lands here. A wake that only reached tasks
        // already registered would be lost in this window and the pump would
        // park on a queue that no longer exists, forever.
        drop(queue);

        // So the wake has to have been stored, and the park has to return
        // without anything further happening. `biased` polls the wait first:
        // if the permit is there it completes now, and the ready-branch never
        // runs. No timer, no polling, and no dependence on scheduling.
        tokio::select! {
            biased;
            _ = pump.ready() => {}
            _ = std::future::ready(()) => panic!(
                "the pump parked after the drop and was never woken — the \
                 closing wake was lost in the gap between observing Empty and \
                 registering"
            ),
        }

        assert!(
            matches!(pump.next(), RealtimePumpStep::Closed),
            "and having woken, the pump learns the flow is gone from the \
             failed upgrade, with no flag anyone had to remember to set"
        );
        assert!(
            matches!(pump.next(), RealtimePumpStep::Closed),
            "terminally — a closed pump never reports itself merely idle again"
        );
    }

    /// A queue issues one pump, which is what makes the single closing permit
    /// sufficient.
    #[test]
    fn v4_macro1_a_queue_issues_at_most_one_pump() {
        let queue = RealtimeFlowQueue::<RealtimeSendUnit>::new();
        assert!(queue.claim_pump(), "the first claim succeeds");
        assert!(
            !queue.claim_pump(),
            "and the second is refused — a second pump would be the waiter the \
             single closing permit can never reach"
        );
    }

    /// A label a peer cites back grants nothing on its own.
    ///
    /// The discriminating negative: reconstructing a label from a peer-supplied
    /// byte is a question about this session's table, not a claim on a flow. A
    /// label naming no live flow answers false, and one naming a live flow
    /// answers true without conferring anything — the caller still has to hold
    /// the session to do anything with the answer.
    #[test]
    fn v4_macro1_a_peer_cited_label_is_a_lookup_not_a_claim() {
        let mut labels = RealtimeFlowLabels::default();
        let live = labels
            .claim_exact(RealtimeFlowLabel::from_peer(0))
            .expect("the space starts empty");

        // Every byte is a syntactically valid label, so nothing is rejected
        // here — which is exactly why the answer has to be a lookup.
        assert!(
            labels.holds(RealtimeFlowLabel::from_peer(live.get())),
            "a peer can name a flow this session really does hold"
        );
        assert!(
            !labels.holds(RealtimeFlowLabel::from_peer(live.get().wrapping_add(1))),
            "and naming one it does not hold finds nothing"
        );
        assert!(
            !labels.holds(RealtimeFlowLabel::from_peer(u8::MAX)),
            "including the far end of the space"
        );

        // The cited label did not become held by being mentioned.
        assert_eq!(
            labels.claim_exact(RealtimeFlowLabel::from_peer(live.get().wrapping_add(1))),
            Ok(RealtimeFlowLabel(live.get().wrapping_add(1))),
            "a name a peer said is still free until this side claims it"
        );
    }

    /// A reader is a lease, not a one-shot: one holder at a time, returned on
    /// drop, and a reconnect resumes on the same queue.
    ///
    /// The discriminating case is the middle one. A one-shot claim would pass
    /// "second reader refused" and "reader ends on session drop" identically,
    /// and would still make a session permanently unreadable the first time a
    /// consumer pipe hung up. What separates the two designs is whether the
    /// lease comes back, and whether the item that arrived while nobody was
    /// listening is still there when someone is.
    ///
    /// Both readers are the same type, so this covers the flow-event reader
    /// as well as the arrival reader.
    #[tokio::test]
    async fn v4_macro1_a_a_stream_reader_is_a_lease_a_reconnect_can_take_back() {
        let stream = Arc::new(SessionStream::<u32>::new());
        let take_reader = |stream: &Arc<SessionStream<u32>>| {
            stream.claim().then(|| SessionStreamReader {
                stream: Arc::downgrade(stream),
                ready: Arc::clone(&stream.ready),
            })
        };

        let first = take_reader(&stream).expect("the first consumer takes the lease");
        assert!(
            take_reader(&stream).is_none(),
            "a second simultaneous reader is refused — closure is one stored \
             permit, so the second waiter would never wake"
        );

        // An item arrives, and then the consumer's pipe dies before it drains.
        stream.push(7);
        drop(first);

        let second = take_reader(&stream).expect("the lease comes back with the reader");
        assert_eq!(
            second.next().await,
            Some(7),
            "the reconnect drains what accumulated while nobody was listening, \
             and drains it before parking rather than sleeping on a queue that \
             already has work in it"
        );

        // Session retirement.
        let ghost = Arc::downgrade(&stream);
        drop(stream);
        assert_eq!(
            second.next().await,
            None,
            "the reader ends because the stream went, not because it was told"
        );
        assert!(
            ghost.upgrade().is_none(),
            "and there is no stream left to lease from — re-claim after \
             retirement is not refused, it is unreachable"
        );
    }

    /// An arrivals reader is owned by the flow set it was claimed on, and by
    /// no other — including the one that replaced it.
    ///
    /// This is the fence `next_realtime_arrival` re-enters with. A label is
    /// session-scoped demux data awaited *outside* the registry mutation lock,
    /// so a session can be replaced in the gap; the fence then resolves the
    /// replacement entirely correctly and finds a live flow under the same
    /// `u8`. Nothing already in that fence separates the two, which is what
    /// this predicate is for.
    ///
    /// The setup is deliberately bare — two flow sets over one registry, no
    /// connector and no peer connection — because everything that would
    /// otherwise be confused for the discriminator is held *identical* here:
    /// the same registry allocation, and the same label held in both
    /// namespaces. If ownership were derived from either, every negative below
    /// would fail.
    #[test]
    fn v4_macro1_a_an_arrivals_reader_is_owned_by_the_session_that_issued_it() {
        // No resources and no ceiling: this control never opens a flow, and a
        // registry that cannot admit one is the smallest thing that proves the
        // registry is not what tells two sessions apart.
        let registry = RealtimeFlowRegistry::new(None, None);
        let mut first =
            SessionRealtimeFlows::new(Arc::clone(&registry), Some(control_realtime_profile()));
        // Allocated while `first` is still alive, so the two streams cannot
        // share an address and the drop case below cannot pass by accident.
        let mut second =
            SessionRealtimeFlows::new(Arc::clone(&registry), Some(control_realtime_profile()));

        // The same label is live in both namespaces. A session's label space
        // is its own, so this is the ordinary state after a replacement — the
        // application reuses the value it always used.
        let label = RealtimeFlowLabel::from_peer(3);
        assert!(first.labels.claim_exact(label).is_ok());
        assert!(second.labels.claim_exact(label).is_ok());

        let from_first = first
            .inbound_arrivals()
            .expect("a fresh flow set issues its arrivals lease once");
        let from_second = second
            .inbound_arrivals()
            .expect("and each flow set has its own lease to issue");

        // Positive control first. Without it a predicate that answered `false`
        // unconditionally would satisfy every negative in this test and would
        // also make the session permanently unreadable in production.
        assert!(
            first.owns_arrivals(&from_first),
            "a reader is owned by the flow set that issued it"
        );
        assert!(second.owns_arrivals(&from_second));

        // The negatives, in both directions, with registry and label held
        // equal across the two sets.
        assert!(
            !second.owns_arrivals(&from_first),
            "and by no other — a label taken from one session's stream cannot \
             be spent against another's flow of the same number"
        );
        assert!(!first.owns_arrivals(&from_second));

        // The replacement shape, which is the one the race actually takes: the
        // session that issued the reader is gone, and the reader outlives it.
        // `Weak::as_ptr` still answers the dead stream's old address, so this
        // is exactly where a naive pointer read would report a match against
        // whatever now sits there.
        drop(from_second);
        drop(second);
        let replacement =
            SessionRealtimeFlows::new(Arc::clone(&registry), Some(control_realtime_profile()));
        assert!(
            !replacement.owns_arrivals(&from_first),
            "a reader claimed on a retired session names nothing the session \
             that replaced it owns"
        );

        // Non-vacuity for the drop case: the replacement really does issue
        // readers it owns, so the refusal above is the identity check and not
        // a flow set that has stopped recognising anything.
        let from_replacement = replacement
            .inbound_arrivals()
            .expect("the replacement issues its own lease");
        assert!(replacement.owns_arrivals(&from_replacement));

        // And the original is still owned by its own live set throughout, so
        // nothing above was a reader that had quietly stopped naming anything.
        assert!(first.owns_arrivals(&from_first));
    }

    /// A negotiated inbound track attaches only to a flow this side already
    /// opened, and only if it is the shape that flow was opened for.
    ///
    /// The discriminating control for peer-unilateral open. A peer cannot mint
    /// a flow here; the most it can do is name one we created. The three
    /// negatives are the ways it might try: an identity we never bound, an
    /// identity we bound for a different codec family, and an identity whose
    /// flow has since closed.
    ///
    /// The positive half matters just as much — a table that refused
    /// everything would pass all three negatives and deliver no media at all.
    ///
    /// The fixture uses **minted tokens**, which is the point rather than a
    /// detail. The identities here are `Arc` allocations this side created; a
    /// peer cannot produce one, cannot name one, and nothing about one appears
    /// in SDP. The "identity we never bound" negative is therefore literally
    /// unforgeable rather than merely unguessable — which is what replacing the
    /// old MID-string key bought.
    #[test]
    fn v4_macro1_a_a_negotiated_track_attaches_only_to_a_flow_we_opened() {
        let bindings = RealtimeInboundBindings::default();
        let label = RealtimeFlowLabel::from_peer(3);
        let encoding = RealtimeEncoding::new(WebRtcRtpKind::Video, "video/H264", 90_000, 0)
            .expect("the fixture encoding is one a flow can carry");
        let binding = RealtimeInboundBinding::new(label, encoding, RealtimeFraming::AnnexB);

        // The token for the transceiver this side negotiated, and one for a
        // transceiver it never did.
        let ours = RealtimeTrackIdentity::new();
        let never_offered = RealtimeTrackIdentity::new();

        // Detached handles, and honestly so: what this control exercises is the
        // demux decision, which never upgrades the port. That one flow feeds one
        // flow — and holds no lease of its own — is what the capacity control
        // below proves, on a real registry.
        let (port, end) = detached_attachment_handles();

        assert!(
            !bindings.bind(
                Arc::clone(&ours),
                RealtimeDirection::Outbound,
                binding.clone(),
                port.clone(),
                Arc::clone(&end),
            ),
            "nothing outbound is attachable, so an outbound entry is refused \
             rather than stored where it would later look deliberate"
        );
        assert!(bindings.bind(
            Arc::clone(&ours),
            RealtimeDirection::Inbound,
            binding.clone(),
            port.clone(),
            Arc::clone(&end),
        ));
        assert!(
            !bindings.bind(
                Arc::clone(&ours),
                RealtimeDirection::Inbound,
                binding,
                port,
                end,
            ),
            "a second binding on one token would make attachment ambiguous, \
             and taking the newer one would move a live flow's media"
        );

        // Positive: the exact token we bound, in the exact shape we bound it.
        assert_eq!(
            bindings
                .admit(&ours, WebRtcRtpKind::Video, "video/h264", 90_000, 0)
                .map(|admitted| admitted.label),
            Some(label),
            "the track this side negotiated reaches the flow it was negotiated for"
        );

        // Negative: a token we never bound. This is the peer-mint case, and
        // with a minted token it is unforgeable rather than merely unguessed.
        assert!(
            bindings
                .admit(
                    &never_offered,
                    WebRtcRtpKind::Video,
                    "video/h264",
                    90_000,
                    0
                )
                .is_none(),
            "a track on a transceiver we never negotiated has nothing to attach to"
        );

        // Negative: our token, a shape we did not open the flow for.
        assert!(
            bindings
                .admit(&ours, WebRtcRtpKind::Audio, "video/h264", 90_000, 0)
                .is_none(),
            "a kind we did not open for is not this flow's media"
        );
        assert!(
            bindings
                .admit(&ours, WebRtcRtpKind::Video, "video/VP8", 90_000, 0)
                .is_none(),
            "nor is a codec family we did not open for — attaching it would \
             feed a decoder configured for something else"
        );

        // Negative: the flow closed, so the binding is gone with it.
        bindings.release(label);
        assert!(
            bindings
                .admit(&ours, WebRtcRtpKind::Video, "video/h264", 90_000, 0)
                .is_none(),
            "a closed flow's negotiated token stops admitting anything"
        );
    }

    /// A binding fixture's two runtime handles, pointing at no flow.
    ///
    /// Only for controls that exercise the admission decision itself. A handle
    /// that upgrades to nothing is exactly what a pump would be left holding
    /// after its flow closed, so it is not a weaker fixture — it is the closed
    /// case, and admission is indifferent to it by design.
    fn detached_attachment_handles() -> (RealtimeFlowPortHandle, Arc<tokio::sync::Notify>) {
        (
            RealtimeFlowPortHandle {
                lifetime: std::sync::Weak::new(),
            },
            Arc::new(tokio::sync::Notify::new()),
        )
    }

    /// One registration of the deployed H.264 shape.
    fn h264_variant(payload_type: u8, fmtp: &str) -> RealtimeCodec {
        RealtimeCodec {
            kind: WebRtcRtpKind::Video,
            payload_type,
            mime: "video/H264".to_string(),
            clock_rate: 90_000,
            channels: 0,
            fmtp: fmtp.to_string(),
            framing: RealtimeFraming::AnnexB,
            rtcp_feedback: Vec::new(),
        }
    }

    /// A flow names an encoding *family*, and every payload variant of that
    /// family survives to the media engine.
    ///
    /// The discriminating case, because resolving the four fields to one
    /// registration is both plausible and silent: the offer advertises all
    /// five variants, the answerer picks one, and picking on our side would
    /// send RTP with a payload type the far end is not decoding. That does not
    /// surface as a refusal — it surfaces as black video.
    #[test]
    fn v4_macro1_a_an_encoding_names_a_family_not_a_payload_type() {
        let profile = RealtimeProfile::new(
            vec![
                h264_variant(102, "packetization-mode=1;profile-level-id=42001f"),
                h264_variant(127, "packetization-mode=0;profile-level-id=42001f"),
                h264_variant(125, "packetization-mode=1;profile-level-id=42e01f"),
                h264_variant(108, "packetization-mode=0;profile-level-id=42e01f"),
                h264_variant(123, "packetization-mode=1;profile-level-id=640032"),
            ],
            4,
        )
        .expect("the deployed five-variant H.264 profile is a shape core can act on");

        assert_eq!(
            profile.codecs().len(),
            5,
            "every variant reaches the media engine; registering fewer would \
             silently narrow what a peer is allowed to choose"
        );

        let named = RealtimeEncoding::new(WebRtcRtpKind::Video, "video/h264", 90_000, 0)
            .expect("an encoding naming that family");
        assert_eq!(
            profile.admits_encoding(&named),
            Some(RealtimeFraming::AnnexB),
            "the family resolves — case-insensitively, because SDP is — to the \
             one framing its variants agree on, with no payload type chosen"
        );

        let unregistered = RealtimeEncoding::new(WebRtcRtpKind::Audio, "audio/opus", 48_000, 2)
            .expect("an encoding naming a family this profile never registered");
        assert_eq!(
            profile.admits_encoding(&unregistered),
            None,
            "and a family nothing registered is refused, which is the only \
             judgement core makes about a codec"
        );
    }

    /// The profile refuses what it cannot act on, and nothing else.
    #[test]
    fn v4_macro1_a_profile_refuses_only_the_shapes_it_cannot_act_on() {
        assert_eq!(
            RealtimeProfile::new(vec![h264_variant(102, "a"), h264_variant(102, "b")], 4),
            Err(RealtimeProfileError::DuplicatePayloadType { payload_type: 102 }),
            "two registrations on one payload type make negotiation ambiguous"
        );

        let mut disagrees = h264_variant(127, "b");
        disagrees.framing = RealtimeFraming::Whole;
        assert_eq!(
            RealtimeProfile::new(vec![h264_variant(102, "a"), disagrees], 4),
            Err(RealtimeProfileError::FamilyFramingConflict {
                mime: "video/H264".to_string(),
                clock_rate: 90_000,
            }),
            "a flow opens against the family before a payload type exists, so a \
             family whose variants disagree on framing has no framer to install"
        );

        assert!(
            RealtimeProfile::new(vec![h264_variant(102, "a"), h264_variant(127, "b")], 4).is_ok(),
            "but two variants of one family are exactly the deployed shape and \
             must not be refused"
        );
    }
}
