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
/// **Opaque bytes, not a number.** What bounds a name's *size* is the frame
/// that carries it — [`crate::realtime::MAX_REALTIME_FLOW_LABEL_BYTES`], the
/// width of the encoded length prefix. What bounds how many exist at once is
/// admission, which answers with leases rather than with a fixed space. Those
/// are separate questions and neither is allowed to stand in for the other: a
/// numeric label makes the name's width into a concurrency ceiling, and a
/// concurrency ceiling stated anywhere but the owner's envelope is a second
/// number to drift from the first. The `Ord` below exists to key a map, not to
/// rank: nothing orders two labels meaningfully and nothing advances one.
///
/// The one property that is easy to lose and is load-bearing: a receiver that
/// has lost its entire route table can still cite a label back to the sender,
/// and the sender can resolve it. That is the only way to report a dead flow
/// whose name is exactly what was lost, so a label must stay meaningful to the
/// *peer*, not merely inside the process that minted it.
///
/// **One shared record and one lease, carried by every copy.** Not one
/// allocation: the record is an `Arc` block and the name is a `Box<[u8]>`
/// beside it, which is two, and `label_claim` charges both. What is singular
/// here is the record and the lease it holds, which is the property that
/// matters — cloning a label clones an `Arc`, so the held set, the flows map, a
/// queued arrival, an inbound binding and a close event all name the same bytes
/// and the same charge — released when the last of them drops, which is
/// deliberately *not* when the flow closes. A close event exists precisely to
/// outlive its flow, and a queued arrival can too; charging the flow's own
/// lease for the label would have released bytes that were still retained.
///
/// Equality, ordering and hashing are by bytes, never by allocation address:
/// two labels naming the same bytes are the same label, which is what lets a
/// peer cite one back after this side has rebuilt everything else.
#[derive(Clone, Debug)]
pub(crate) struct RealtimeFlowLabel(Arc<LeasedLabel>);

/// The one *record* behind every copy of a label — two allocations, one
/// lifetime.
///
/// The `Arc` block holds this struct; the name's `Box<[u8]>` is a second
/// allocation it points at. Both die together when the last copy drops, which
/// is why one lease covers both, and `label_claim` counts two residuals.
///
/// `_lease` is never read. Its whole job is to exist for exactly as long as the
/// name beside it and to release when this record drops.
#[derive(Debug)]
struct LeasedLabel {
    name: RealtimeFlowName,
    _lease: crate::resource::ResourceLease,
}

impl RealtimeFlowLabel {
    /// Mint the leased label for a name a session is accepting.
    ///
    /// The only way one is made, and it is made *at admission*. Before this
    /// point a name is unowned bytes costing a decode buffer and nothing else,
    /// so a refused open — a malformed name, a name already held, a provider
    /// under pressure — retains nothing this side accounted for. Minting first
    /// and refusing afterwards would let a peer drive retention with opens that
    /// never succeed.
    pub(super) fn mint(
        name: RealtimeFlowName,
        registry: &RealtimeFlowRegistry,
    ) -> FlowResult<Self> {
        let content_bytes = name.as_bytes().len();
        let lease = registry
            .acquire_label_lease(std::mem::size_of::<LeasedLabel>(), content_bytes)
            .map_err(realtime_drop_refusal)?;
        Ok(Self(Arc::new(LeasedLabel {
            name,
            _lease: lease,
        })))
    }

    /// The name this label carries.
    ///
    /// Only the application control path reads it; nothing in the flow path
    /// treats a label as authority.
    pub(crate) fn name(&self) -> &RealtimeFlowName {
        &self.0.name
    }

    /// Exactly what minting a name of this length will cost.
    ///
    /// Fixtures that derive a finite grant from the claims they exercise need
    /// this number, and `size_of::<LeasedLabel>()` is not theirs to compute —
    /// the record is private to this file, which is what keeps the production
    /// arithmetic and the fixture arithmetic the same expression rather than
    /// two that agree until the record gains a field.
    #[cfg(any(test, feature = "transport-lab"))]
    pub(super) fn mint_claim(
        content_bytes: usize,
    ) -> std::result::Result<crate::resource::ResourceClaim, crate::resource::ResourceUnavailable>
    {
        RealtimeFlowRegistry::label_claim(std::mem::size_of::<LeasedLabel>(), content_bytes)
    }
}

impl std::borrow::Borrow<[u8]> for RealtimeFlowLabel {
    /// Lets a collection keyed by label be looked up with the raw bytes a peer
    /// sent, without minting a lease merely to ask a question. Consistent with
    /// `Eq`, `Ord` and `Hash` because all four read the same bytes.
    fn borrow(&self) -> &[u8] {
        self.0.name.as_bytes()
    }
}

impl PartialEq for RealtimeFlowLabel {
    fn eq(&self, other: &Self) -> bool {
        self.0.name == other.0.name
    }
}

impl Eq for RealtimeFlowLabel {}

impl PartialOrd for RealtimeFlowLabel {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for RealtimeFlowLabel {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.name.cmp(&other.0.name)
    }
}

impl std::hash::Hash for RealtimeFlowLabel {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.name.hash(state);
    }
}

/// A label's bytes before anything has agreed to keep them.
///
/// This is what crosses the boundary in both directions: an application names
/// one to open or address a flow, and one comes back out on an arrival or a
/// close. It owns no lease and is not authority — it is a question, and
/// resolving it to a flow is a lookup in one session's own table, where a name
/// matching nothing simply finds nothing.
///
/// The bound is the frame's, not this type's invention:
/// [`crate::realtime::MAX_REALTIME_FLOW_LABEL_BYTES`] is the width of the
/// encoded label's single length byte, so a name is 1..=255 bytes and anything
/// longer could not have been transmitted. That constant lives in the basal
/// vocabulary because the daemon and this file must not each spell it. Empty is
/// refused rather than accepted as a degenerate name, so the binary and JSON
/// paths cannot disagree about what an absent label means.
///
/// `Box<[u8]>`, not `Vec<u8>`, and the difference is the accounting: a boxed
/// slice has no spare capacity, so its allocation is exactly its length and the
/// claim can charge the length rather than guess at a capacity the caller
/// happened to hand over.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RealtimeFlowName(Box<[u8]>);

impl RealtimeFlowName {
    /// Accept bytes as a name, or refuse them.
    ///
    /// Both refusals are shape, and both are cheap: they happen before any
    /// lease exists, so a peer sending unusable names pays for a decode buffer
    /// and nothing this side retains.
    pub fn new(bytes: Vec<u8>) -> Option<Self> {
        if bytes.is_empty() || bytes.len() > crate::realtime::MAX_REALTIME_FLOW_LABEL_BYTES {
            return None;
        }
        // Boxing drops any spare capacity, so what the lease is later asked to
        // charge is what is actually held.
        Some(Self(bytes.into_boxed_slice()))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
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
}

impl RealtimeProfile {
    /// Validate and accept one application profile.
    ///
    /// The refusals are all shape, never codec judgement: something to
    /// register, no duplicate payload type (which would make negotiation
    /// ambiguous), no empty MIME or zero clock rate (which would make a
    /// capability unmatchable), and no encoding family whose variants disagree
    /// on framing.
    ///
    /// A profile says **which encodings this application can carry** and
    /// nothing about how many flows may exist at once. Concurrency is the
    /// owner's, stated by its resource envelope and enforced by the registry;
    /// a capacity here would be the application stating a second number for
    /// something the envelope already decides, and it would leave an elastic
    /// deployment — codecs, no fixed ceiling — with nothing it could truthfully
    /// say.
    ///
    /// Note what is deliberately *not* refused: two registrations agreeing on
    /// all four family fields. Deployed H.264 is five registrations differing
    /// only in payload type and fmtp, and rejecting that would reject the
    /// profile the daemon actually ships.
    pub fn new(codecs: Vec<RealtimeCodec>) -> std::result::Result<Self, RealtimeProfileError> {
        if codecs.is_empty() {
            return Err(RealtimeProfileError::NoCodecs);
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
        Ok(Self { codecs })
    }

    /// Everything to register with the media engine, in the order supplied.
    pub(crate) fn codecs(&self) -> &[RealtimeCodec] {
        &self.codecs
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

    /// Everything this profile holds on the heap, walked rather than estimated.
    ///
    /// Three levels, because the profile has three: the codec vector's own
    /// buffer, each codec's two `String`s and its feedback vector's buffer, and
    /// each feedback entry's two `String`s. The deployed profile is five H.264
    /// variants whose `fmtp` lines differ in length, so any per-codec average
    /// would be wrong in both directions.
    ///
    /// `capacity`, not `len`, for every buffer: what is held is what was
    /// allocated, and a `Vec` built by `push` routinely holds more than it uses.
    fn heap_bytes(&self) -> usize {
        let codec_records = self.codecs.capacity() * std::mem::size_of::<RealtimeCodec>();
        self.codecs.iter().fold(codec_records, |total, codec| {
            let feedback_records =
                codec.rtcp_feedback.capacity() * std::mem::size_of::<RealtimeRtcpFeedback>();
            let feedback_strings = codec
                .rtcp_feedback
                .iter()
                .map(|entry| entry.mechanism.capacity() + entry.parameter.capacity())
                .sum::<usize>();
            total
                + codec.mime.capacity()
                + codec.fmtp.capacity()
                + feedback_records
                + feedback_strings
        })
    }

    /// How many separate allocations those bytes are spread across.
    ///
    /// Counted because allocator overhead has no portable size and the byte
    /// total cannot express it — the same arithmetic the label claim uses.
    ///
    /// **By capacity, not by presence.** An empty `String` or `Vec` owns no
    /// buffer, so counting one per field would charge a residual for something
    /// that was never allocated. That matters here rather than being pedantry:
    /// `fmtp` is routinely empty and `rtcp_feedback` usually is, so a
    /// per-field count would over-charge every ordinary profile — and an
    /// arithmetic that says "exact" while being conservative is worse than one
    /// that admits which it is.
    fn heap_allocations(&self) -> u64 {
        /// One allocation exists exactly when a container owns a buffer.
        fn allocated(capacity: usize) -> u64 {
            u64::from(capacity != 0)
        }

        let codec_vector = allocated(self.codecs.capacity());
        self.codecs.iter().fold(codec_vector, |total, codec| {
            let feedback_strings = codec
                .rtcp_feedback
                .iter()
                .map(|entry| {
                    allocated(entry.mechanism.capacity()) + allocated(entry.parameter.capacity())
                })
                .sum::<u64>();
            total
                + allocated(codec.mime.capacity())
                + allocated(codec.fmtp.capacity())
                + allocated(codec.rtcp_feedback.capacity())
                + feedback_strings
        })
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

/// One application profile, and the lease that owns its heap.
///
/// **The lease lives inside the shared record, beside the profile it pays
/// for.** A promoted session's flow set holds one of these, and a set can
/// outlive the connector field it was cloned from; a lease held as a sibling of
/// an `Arc<RealtimeProfile>` would release at the moment that *field* dropped
/// while the profile itself was still retained. Here the charge and the bytes
/// are one object, so the release is the last clone's drop and cannot be
/// anything else.
///
/// Minted once, by the connector, at the point the profile becomes the
/// session's. Every promotion after that is a refcount: a profile is immutable
/// registration data, so there is nothing for two sessions to disagree about
/// and no reason for either to hold its own deep copy. That is the defect this
/// replaces — every promotion used to clone the codec vector, both `String`s
/// per codec and every feedback entry, and pay for none of it.
///
/// Charged on the same three terms as a leased label — record, content, and
/// the `Arc`'s counter pair — because it is the same shape of object. Two
/// shared records costing differently would be an accident of which one was
/// written first.
#[derive(Clone, Debug)]
pub(crate) struct LeasedRealtimeProfile(Arc<LeasedProfile>);

/// The record a [`LeasedRealtimeProfile`] shares: one immutable profile and the
/// one lease that owns its bytes.
///
/// `_lease` is never read. Its whole job is to exist for exactly as long as the
/// profile beside it and to release when this record drops.
#[derive(Debug)]
struct LeasedProfile {
    profile: RealtimeProfile,
    _lease: crate::resource::ResourceLease,
}

impl LeasedRealtimeProfile {
    /// Take the lease that owns one profile's heap, or refuse it.
    ///
    /// Refusal is ordinary: a provider under pressure declines the profile and
    /// the connector fails to come up, rather than registering codecs whose
    /// retention nothing accounted for.
    pub(super) fn mint(
        profile: RealtimeProfile,
        registry: &RealtimeFlowRegistry,
    ) -> FlowResult<Self> {
        let (record_bytes, content_bytes, allocations) = Self::record_terms(&profile);
        let lease = registry
            .acquire_profile_lease(record_bytes, content_bytes, allocations)
            .map_err(realtime_drop_refusal)?;
        Ok(Self(Arc::new(LeasedProfile {
            profile,
            _lease: lease,
        })))
    }

    /// The profile this record carries.
    pub(crate) fn profile(&self) -> &RealtimeProfile {
        &self.0.profile
    }

    /// Everything the claim for one shared profile record is built from.
    ///
    /// **One expression, two callers.** The live mint and the fixture claim
    /// have to agree exactly or a derived grant is wrong by however much they
    /// differ, and two copies of this arithmetic would agree only until one of
    /// them was edited. So neither computes it: both ask here.
    ///
    /// The record term is the `LeasedProfile` struct; the content term is every
    /// buffer the profile points at; the allocation count is the `Arc` block,
    /// which always exists, plus each buffer the profile actually owns —
    /// counted by capacity, so an empty `fmtp` or an empty feedback list costs
    /// nothing rather than costing a residual for a buffer that was never
    /// allocated. The `Arc`'s strong/weak counter pair is added by
    /// `profile_claim`, in the same place and the same way the label's is.
    fn record_terms(profile: &RealtimeProfile) -> (usize, usize, u64) {
        (
            std::mem::size_of::<LeasedProfile>(),
            profile.heap_bytes(),
            1 + profile.heap_allocations(),
        )
    }

    /// Exactly what minting this profile will cost, for fixtures that derive a
    /// finite grant from the claims they exercise.
    #[cfg(any(test, feature = "transport-lab"))]
    pub(super) fn mint_claim(
        profile: &RealtimeProfile,
    ) -> std::result::Result<crate::resource::ResourceClaim, crate::resource::ResourceUnavailable>
    {
        let (record_bytes, content_bytes, allocations) = Self::record_terms(profile);
        RealtimeFlowRegistry::profile_claim(record_bytes, content_bytes, allocations)
    }
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
    held: std::collections::BTreeSet<RealtimeFlowLabel>,
}

impl RealtimeFlowLabels {
    /// Claim the one label the application chose.
    ///
    /// Takes the raw name and mints the leased label only once the name is
    /// known to be free, so a collision costs no lease. The order matters in
    /// the other direction too: the mint is what pays for the bytes this set is
    /// about to retain, so nothing enters `held` unaccounted for.
    ///
    /// The only way a label is ever taken. There is deliberately no
    /// lowest-free allocator here: the application owns route binding and
    /// dead-flow recovery, so it is the sole allocator, and a second one over
    /// the same space would agree until it did not — producing a collision on
    /// a live flow rather than a refusal at open.
    pub(crate) fn claim_exact(
        &mut self,
        name: &RealtimeFlowName,
        registry: &RealtimeFlowRegistry,
    ) -> FlowResult<RealtimeFlowLabel> {
        if self.held.contains(name.as_bytes()) {
            return Err(RealtimeFlowError::LabelInUse);
        }
        let label = RealtimeFlowLabel::mint(name.clone(), registry)?;
        self.held.insert(label.clone());
        Ok(label)
    }

    /// Release a label, making it available again.
    ///
    /// Called when the flow that held it is gone, never merely because a peer
    /// said the flow was dead: a peer's report is a request to stop sending,
    /// and the label stays held until this side actually drops its flow. That
    /// ordering is what stops a stale report from freeing a label the next
    /// flow would immediately reuse.
    pub(crate) fn release(&mut self, label: &RealtimeFlowLabel) {
        self.held.remove(label.name().as_bytes());
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
    pub(crate) fn holds(&self, name: &RealtimeFlowName) -> bool {
        self.held.contains(name.as_bytes())
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
    pub(crate) fn label(&self) -> &RealtimeFlowLabel {
        &self.label
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
    let label = labels.claim_exact(&spec.name, registry)?;
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
            labels.release(&label);
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
    /// The name the application chose. Required: this side never allocates one.
    ///
    /// Raw and unleased, because at this point nothing has agreed to keep it.
    /// The leased label is minted from it only once the session has accepted
    /// the name.
    pub(crate) name: RealtimeFlowName,
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
/// No longer `Copy`: the label it carries owns a lease, and a bitwise copy
/// would be a second holder the accounting never learned about.
#[derive(Clone, Debug, PartialEq, Eq)]
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
    RealtimeProfile::new(vec![
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
    ])
    .expect("the control profile registers two well-formed families")
}

/// The control profile as a session actually holds it: shared, and leased.
///
/// Minted rather than hand-built for the same reason a control label is. A
/// profile with no lease is not the shape a flow set ever carries, and a
/// fixture that built one would be proving something about a state production
/// cannot reach.
#[cfg(test)]
pub(super) fn leased_control_profile(registry: &RealtimeFlowRegistry) -> LeasedRealtimeProfile {
    LeasedRealtimeProfile::mint(control_realtime_profile(), registry)
        .expect("the fixture grant accounts for one control profile")
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
    pub(crate) fn release(&self, label: &RealtimeFlowLabel) {
        self.bound
            .lock()
            .retain(|entry| &entry.binding.label != label);
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
            label: entry.binding.label.clone(),
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
/// same name. Neither the label nor the incarnation separates those two. This
/// does.
///
/// Holds a `Weak` deliberately: a token must never keep a flow set alive, or
/// the retirement it exists to detect could not happen while one was
/// outstanding.
pub(crate) struct RealtimeFlowSetIdentity(std::sync::Weak<RealtimeFlowSetToken>);

pub(crate) struct SessionRealtimeFlows {
    labels: RealtimeFlowLabels,
    /// Keyed by the leased label, so the map entry is one of the shared copies
    /// rather than a second allocation of the same bytes. Lookups take raw
    /// bytes through `Borrow<[u8]>`, so asking about a name costs no lease.
    flows: std::collections::BTreeMap<RealtimeFlowLabel, RealtimeFlow>,
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
    ///
    /// Shared and leased rather than owned outright: promotion clones the
    /// pointer, and the charge for the codecs behind it is paid once by the
    /// connector that registered them and released by whichever holder drops
    /// last.
    profile: Option<LeasedRealtimeProfile>,
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
        profile: Option<LeasedRealtimeProfile>,
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

    /// The heap roots one promotion allocates for a session's flow set.
    ///
    /// Exactly what [`Self::new`] creates and the session then owns for its
    /// whole life: the flow-set token, both session streams, and the inbound
    /// bindings, each with the two counter words its `Arc` carries.
    ///
    /// It lives here, next to the constructor, because three of the four types
    /// are private to this module and the fourth is `pub(crate)`. A caller
    /// outside this file could only account for them by copying their sizes
    /// into its own arithmetic, and a field added to `SessionStream` would then
    /// stop being paid for without anything saying so. Adding a root to `new`
    /// and not to this function is a mistake the compiler cannot catch, so the
    /// two sit adjacent and the omission is at least visible.
    ///
    /// Two exclusions, both deliberate. `registry` is cloned, not allocated —
    /// it is the connector's and predates the session, so charging it here
    /// would bill one object to every session standing on it. And nothing
    /// per-flow, per-queue or per-payload appears: those are taken as their own
    /// leases where the work happens, which is what lets a session's cost track
    /// what it is actually carrying rather than what it might.
    pub(crate) fn promotion_root_claim() -> std::result::Result<
        crate::resource::ResourceClaim,
        crate::resource::ResourceClaimArithmeticError,
    > {
        let overflow = || crate::resource::ResourceClaimArithmeticError::Overflow {
            dimension: crate::resource::ResourceClass::AccountedMemoryBytes,
        };
        // Two words per `Arc`: strong and weak. The same pattern the connector
        // uses for its own `Arc`-rooted claims.
        let arc_counters = std::mem::size_of::<usize>()
            .checked_mul(2)
            .ok_or_else(overflow)?;
        let root = |contents: usize| contents.checked_add(arc_counters);
        let accounted = root(std::mem::size_of::<RealtimeFlowSetToken>())
            .and_then(|bytes| {
                bytes.checked_add(root(
                    std::mem::size_of::<SessionStream<RealtimeFlowLabel>>(),
                )?)
            })
            .and_then(|bytes| {
                bytes.checked_add(root(
                    std::mem::size_of::<SessionStream<RealtimeFlowEvent>>(),
                )?)
            })
            .and_then(|bytes| {
                bytes.checked_add(root(std::mem::size_of::<RealtimeInboundBindings>())?)
            })
            .ok_or_else(overflow)?;
        crate::resource::ResourceClaim::try_from_entries([
            (
                crate::resource::ResourceClass::AccountedMemoryBytes,
                u64::try_from(accounted).map_err(|_| overflow())?,
            ),
            // One residual per allocation, matching the connector's own
            // `Arc`-rooted claims. The byte term above measures what the roots
            // *contain*; this counts the allocations themselves, whose
            // allocator overhead has no portable size. Charging only the bytes
            // would state that the roots are fully represented when the
            // per-allocation cost is exactly what is missing.
            (
                crate::resource::ResourceClass::OpaqueDependencyResidual,
                Self::PROMOTION_ROOT_ALLOCATIONS,
            ),
        ])
    }

    /// How many separate allocations [`Self::new`] makes for a session's flow
    /// set: the flow-set token, both session streams, and the inbound bindings.
    ///
    /// Named beside the claim that spends it so the two cannot drift silently,
    /// and stated as a count rather than derived from the byte arithmetic
    /// above, because the two answer different questions — how much the roots
    /// hold, and how many objects the allocator is holding it in.
    const PROMOTION_ROOT_ALLOCATIONS: u64 = 4;

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
    ) -> FlowResult<RealtimeFlowName> {
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
        if self
            .profile
            .as_ref()
            .is_none_or(|profile| profile.profile().admits_encoding(&spec.encoding).is_none())
        {
            return Err(RealtimeFlowError::EncodingInvalid);
        }
        let registry = Arc::clone(&self.registry);
        let flow = open_session_flow(session, live, &registry, &mut self.labels, spec)?;
        // A refcount on the flow's own label record, not a second name: the key
        // and the flow's field are the same leased bytes, so the map costs one
        // Arc counter rather than another accounted allocation.
        let label = flow.label().clone();
        // The label was claimed inside `open_session_flow` against this very
        // namespace, so an occupied slot here would mean the two had diverged.
        // Insert and assert the slot was free by construction rather than
        // silently replacing a live flow.
        // Checked before the insert, never after. `insert` returning the old
        // value would mean the flow it named had already been replaced and
        // dropped — so answering `LabelInUse` at that point would report a
        // refusal having already destroyed a live flow. The defensive branch
        // has to refuse without mutating, or it is not defensive.
        if self.flows.contains_key(label.name().as_bytes()) {
            return Err(RealtimeFlowError::LabelInUse);
        }
        let name = label.name().clone();
        self.flows.insert(label, flow);
        // No event. The caller asked for this flow and is being handed the
        // name right now; telling it again on a stream would be a second
        // account of the same fact.
        Ok(name)
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
        name: &RealtimeFlowName,
        identity: Arc<RealtimeTrackIdentity>,
    ) -> FlowResult<()> {
        let Some(flow) = self.flows.get(name.as_bytes()) else {
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
            .and_then(|profile| profile.profile().admits_encoding(flow.encoding()))
        else {
            return Err(RealtimeFlowError::EncodingInvalid);
        };
        // Cloned from the map's own key, so the binding shares the label's one
        // allocation and its one lease rather than minting a second.
        let binding =
            RealtimeInboundBinding::new(flow.label().clone(), flow.encoding().clone(), framing);
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
        if let Some(flow) = self.flows.get_mut(name.as_bytes()) {
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
        name: &RealtimeFlowName,
        track: RealtimeOutboundTrack,
    ) -> std::result::Result<(), (RealtimeFlowError, RealtimeOutboundTrack)> {
        let Some(flow) = self.flows.get(name.as_bytes()) else {
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
        if let Some(flow) = self.flows.get_mut(name.as_bytes()) {
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
        name: &RealtimeFlowName,
    ) -> FlowResult<RealtimeFlowRemains> {
        let Some(flow) = self.flows.get(name.as_bytes()) else {
            return Err(RealtimeFlowError::FlowRefused);
        };
        flow.port_if_current(session, live)?;
        // Order matters: take the flow out first, then release the label. The
        // label is only free once nothing holds the flow it named. The gate
        // above has already passed, so this removal cannot be the mutation of a
        // refused close.
        // The map key is one of the label's shared copies, so taking it out here
        // is what hands this scope a leased label to release below — no mint,
        // no second allocation of the same bytes.
        let (label, mut flow) = self
            .flows
            .remove_entry(name.as_bytes())
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
        self.bindings.release(&label);
        self.labels.release(&label);
        // The event takes the last strong reference this scope holds. Its bytes
        // and its lease live on inside the event for as long as the event does,
        // which is the whole point: a close outlives the flow it reports.
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
        name: &RealtimeFlowName,
        unit: RealtimeSendUnit,
    ) -> FlowResult<()> {
        let Some(flow) = self.flows.get(name.as_bytes()) else {
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
        name: &RealtimeFlowName,
    ) -> FlowResult<Option<RealtimeRecvUnit>> {
        let Some(flow) = self.flows.get(name.as_bytes()) else {
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
        name: &RealtimeFlowName,
        unit: RealtimeRecvUnit,
    ) -> Option<RealtimeInboundDelivery> {
        let (label, flow) = self.flows.get_key_value(name.as_bytes())?;
        // The real reservation, taken from the flow's own port against the
        // owner's envelope — not a mint. A caller that has bypassed the session
        // flow has no port to reserve against and gets `None` here, which is
        // what makes a control built on this fail rather than pass on a fiction.
        let payload = flow
            .port
            .reserve_output(unit.data.len())?
            .into_payload_lease();
        let mut delivery = RealtimeInboundDelivery::new(label.clone(), unit);
        delivery
            .attach(payload)
            .expect("a freshly built delivery has no lease to displace");
        Some(delivery)
    }

    /// **Controls only.** One delivery taken through the *whole* accounting
    /// path: reserved on the flow's own port, enqueued by `enqueue_checked`,
    /// and taken back off the registry exactly as the connector's event loop
    /// takes it.
    ///
    /// This is the seam [`Self::accounted_delivery_for_test`] cannot be. That
    /// one reserves and converts by hand, which skips the three things
    /// `enqueue_checked` alone does: validating the reservation against this
    /// registry, this key and this flow's liveness; taking the queue and ready
    /// claims; and performing the queued-to-delivered lease transition on the
    /// way back out. A control built on this is therefore standing on the real
    /// path rather than on a faithful imitation of it.
    ///
    /// It is deliberately **not** the lab seam. `try_recv` is the connector
    /// event loop's call, and in a fixture with a live connector this would
    /// race that loop for the event it just queued — sometimes losing it, and
    /// sometimes taking one the loop was about to deliver. It is gated to plain
    /// `test` for that reason: the controls that use it own their registry
    /// outright and nothing else is draining it.
    ///
    /// `None` when the name holds no flow, when the envelope refuses the bytes,
    /// or when the enqueue is refused — all of which a control should read as a
    /// fixture that cannot express what it wanted.
    #[cfg(test)]
    pub(super) fn enqueued_delivery_for_test(
        &self,
        name: &RealtimeFlowName,
        unit: RealtimeRecvUnit,
    ) -> Option<RealtimeInboundDelivery> {
        let (label, flow) = self.flows.get_key_value(name.as_bytes())?;
        let reservation = flow.port.reserve_output(unit.data.len())?;
        let queued = flow
            .port
            .enqueue_checked(
                QueuedTransportEvent {
                    event: TransportEvent::RealtimeUnit(RealtimeInboundDelivery::new(
                        label.clone(),
                        unit,
                    )),
                    observation: None,
                    callback_work: None,
                },
                reservation,
            )
            .ok()?;
        if !queued {
            return None;
        }
        match self.registry.try_recv()?.event {
            TransportEvent::RealtimeUnit(delivery) => Some(delivery),
            _ => None,
        }
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
        let Some(flow) = self.flows.get(label.name().as_bytes()) else {
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
        name: &RealtimeFlowName,
    ) -> FlowResult<Option<(RealtimeFlowName, RealtimeRecvUnit)>> {
        if !self.flows.contains_key(name.as_bytes()) {
            return Ok(None);
        }
        Ok(self
            .recv(session, live, name)?
            .map(|unit| (name.clone(), unit)))
    }

    /// Whether `label` names a live flow of this session that may still be
    /// used right now.
    pub(crate) fn is_current(
        &self,
        session: &impl RealtimeSessionBinding,
        live: Option<&Arc<crate::connector::ConnectorIncarnation>>,
        name: &RealtimeFlowName,
    ) -> bool {
        self.flows
            .get(name.as_bytes())
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

    /// A name from a literal, for controls that care about identity rather
    /// than about the bytes.
    fn control_name(bytes: &[u8]) -> RealtimeFlowName {
        RealtimeFlowName::new(bytes.to_vec()).expect("a control name is within the frame bound")
    }

    /// An elastic registry: a real provider scope, and **no** owner ceilings.
    ///
    /// This is `Enabled(None)` as a deployment actually states it, and it is
    /// the arrangement the label controls run against on purpose. A label still
    /// takes a real lease here — absence of a ceiling is not absence of
    /// accounting — so a control that mints one is proving the elastic path
    /// admits, not that admission was skipped.
    fn control_label_registry() -> (
        Arc<RealtimeFlowRegistry>,
        super::super::realtime::ElasticControlResources,
    ) {
        RealtimeFlowRegistry::elastic_for_control(control_label_grant())
    }

    /// Generous enough that nothing in the label controls is refused for
    /// capacity. Admission under pressure has its own controls; these are about
    /// what a label *is*.
    ///
    /// One definition for the whole crate, in the parent module: the structural
    /// half has to match the scope stack `elastic_for_control` really builds,
    /// and a per-file copy could only match it by luck.
    fn control_label_grant() -> crate::resource::ResourceClaim {
        super::super::elastic_control_grant()
    }

    /// A label names one flow, and a released one is reusable only after its
    /// flow is gone.
    ///
    /// The positive half of the label contract: lowest-free allocation, exact
    /// reclaim, and the reuse ordering that stops a stale peer report from
    /// freeing a live flow's name.
    #[test]
    fn v4_macro1_a_label_is_held_for_its_flows_lifetime_and_reusable_only_after() {
        let (registry, _resources) = control_label_registry();
        let mut labels = RealtimeFlowLabels::default();
        let alpha = control_name(b"alpha");
        let beta = control_name(b"beta");

        let first = labels
            .claim_exact(&alpha, &registry)
            .expect("the space starts empty");
        let second = labels
            .claim_exact(&beta, &registry)
            .expect("a second flow takes the name the application chose for it");
        assert_ne!(first, second, "two live flows never share a label");

        // While held, the exact name is refused rather than quietly aliased.
        assert_eq!(
            labels.claim_exact(&alpha, &registry).err(),
            Some(RealtimeFlowError::LabelInUse),
            "a live flow's label cannot be taken from under it"
        );
        assert!(labels.holds(&alpha));

        // Released only when the flow itself is gone; then, and not before,
        // the name is available again.
        labels.release(&first);
        assert!(!labels.holds(&alpha));
        let reused = labels
            .claim_exact(&alpha, &registry)
            .expect("the freed name is available again");
        assert_eq!(
            reused.name(),
            &alpha,
            "and it is the same name, not a new one"
        );
        assert!(
            labels.holds(&beta),
            "releasing one flow's label never disturbs another's"
        );
    }

    /// A fixture session bound to one connector incarnation.
    struct ControlSession {
        incarnation: Arc<crate::connector::ConnectorIncarnation>,
    }

    impl RealtimeSessionBinding for ControlSession {
        fn is_current_on(&self, incarnation: &Arc<crate::connector::ConnectorIncarnation>) -> bool {
            Arc::ptr_eq(&self.incarnation, incarnation)
        }
    }

    /// The encoding the elastic controls open against.
    fn control_encoding() -> RealtimeEncoding {
        RealtimeEncoding::new(WebRtcRtpKind::Video, "video/H264", 90_000, 0)
            .expect("the control encoding names a family the control profile registers")
    }

    /// An elastic session — `Enabled(None)`, no owner ceilings anywhere — opens
    /// a flow and carries a unit all the way through the accounting path.
    ///
    /// **The discriminating positive for the elastic case.** Every ceiling this
    /// registry could consult is `None`, so nothing here is admitted by a limit
    /// comparison: the label, the flow, the output bytes, the queue slot and the
    /// ready node are each a real provider lease or they do not exist. A build
    /// that treated absent ceilings as zero would refuse at the first
    /// acquisition, and one that treated them as unlimited would skip the leases
    /// entirely — and the release assertion at the end is what tells those two
    /// apart, because an unaccounted path has nothing to give back.
    ///
    /// It goes through `enqueue_checked` rather than around it. That call is
    /// where the reservation is validated against this registry and this flow,
    /// where the queue and ready claims are taken, and where the queued lease
    /// becomes a delivered one, so a control that reserved and converted by hand
    /// would be proving something about its own arithmetic.
    #[test]
    fn v4_macro1_an_elastic_session_moves_a_unit_through_real_leases_end_to_end() {
        let (registry, resources) = control_label_registry();
        let incarnation = crate::connector::ConnectorIncarnation::new();
        let session = ControlSession {
            incarnation: Arc::clone(&incarnation),
        };
        let mut flows = SessionRealtimeFlows::new(
            Arc::clone(&registry),
            Some(leased_control_profile(&registry)),
        );

        let name = flows
            .open(
                &session,
                Some(&incarnation),
                RealtimeFlowSpec {
                    direction: RealtimeDirection::Inbound,
                    encoding: control_encoding(),
                    name: control_name(b"elastic"),
                },
            )
            .expect("an owner that selected no ceiling still admits a flow");

        let idle = resources.accounted_bytes();
        assert!(
            idle > 0,
            "the open really did take leases — without this every assertion \
             below would be about a path that charges nothing"
        );

        let delivery = flows
            .enqueued_delivery_for_test(
                &name,
                RealtimeRecvUnit {
                    timestamp: 90_000,
                    marker: true,
                    data: Bytes::from_static(b"unit"),
                },
            )
            .expect("the elastic flow reserves, enqueues and delivers one unit");
        assert!(
            resources.accounted_bytes() > idle,
            "the delivered unit is holding its own payload lease, so the \
             elastic path accounted for the bytes rather than waving them \
             through"
        );

        assert!(
            flows.deliver_inbound(delivery),
            "and the flow set takes a delivery the accounting path built"
        );
        assert_eq!(
            flows
                .recv_arrival(&session, Some(&incarnation), &name)
                .expect("the session is current")
                .map(|(arrived, unit)| (arrived, unit.data)),
            Some((name.clone(), Bytes::from_static(b"unit"))),
            "exactly the unit that was delivered comes off the flow it named"
        );

        // The release half. Closing returns everything the flow took; the label
        // is the one thing that stays, because the close event still names it.
        let _remains = flows
            .close(&session, Some(&incarnation), &name)
            .expect("the session that opened this flow may close it");
        assert!(
            resources.accounted_bytes() < idle,
            "closing gave the flow's leases back — an elastic path that had \
             skipped accounting would have nothing to return here"
        );
    }

    /// A provider under pressure refuses, and the refusal is the only thing
    /// that happened.
    ///
    /// The negative half of the elastic pair, and it discriminates in both
    /// directions. Absent ceilings do not mean unlimited: with the provider
    /// exhausted, the next acquisition is refused as a typed refusal rather
    /// than admitted. And the refusal is not a leak: releasing the holder makes
    /// the very same acquisition succeed, so what refused was pressure rather
    /// than a claim that had gone missing.
    #[test]
    fn v4_macro1_an_elastic_registry_refuses_under_provider_pressure_and_recovers() {
        let name = control_name(b"pressure");
        // A grant sized for exactly one label and nothing more, derived from the
        // claim itself rather than chosen. Anything larger would leave the
        // refusal below to some other exhaustion.
        let grant = control_label_grant()
            .checked_add(
                RealtimeFlowLabel::mint_claim(name.as_bytes().len())
                    .expect("the label claim is representable"),
            )
            .expect("the pressure grant is representable");
        let (registry, _resources) = RealtimeFlowRegistry::elastic_for_control(grant);
        let mut labels = RealtimeFlowLabels::default();

        // Drain everything the grant will give, so the provider is genuinely at
        // its ceiling rather than merely busy.
        let mut held = Vec::new();
        while let Ok(label) = labels.claim_exact(
            &control_name(format!("fill-{}", held.len()).as_bytes()),
            &registry,
        ) {
            held.push(label);
        }
        assert!(
            !held.is_empty(),
            "the fixture admitted something before it refused — without this \
             the refusal below could be a registry that refuses everything"
        );

        assert_eq!(
            labels.claim_exact(&name, &registry).err(),
            Some(RealtimeFlowError::FlowRefused),
            "an elastic registry under provider pressure refuses the name \
             rather than retaining bytes nothing accounted for"
        );

        // Release exactly one holder and the same claim succeeds. This is what
        // makes the refusal above pressure rather than a lost claim.
        let released = held.pop().expect("the fill loop admitted at least one");
        labels.release(&released);
        drop(released);
        let recovered = labels
            .claim_exact(&name, &registry)
            .expect("the released charge is available again to the next claim");
        assert_eq!(recovered.name(), &name);
    }

    /// A name is bytes, and the two shapes that are not a name are refused
    /// before anything can be charged for them.
    ///
    /// Both refusals matter for the same reason: they happen ahead of the mint,
    /// so a peer sending them drives no retention at all. The upper bound is
    /// the frame's own length prefix rather than a number chosen here, and the
    /// positive case sits between them so neither refusal can be passing
    /// because nothing is ever accepted.
    #[test]
    fn v4_macro1_a_flow_name_is_bounded_by_the_frame_and_never_empty() {
        assert!(
            RealtimeFlowName::new(Vec::new()).is_none(),
            "an empty name is not a degenerate name, it is not a name"
        );
        assert!(
            RealtimeFlowName::new(vec![b'x'; crate::realtime::MAX_REALTIME_FLOW_LABEL_BYTES])
                .is_some(),
            "the largest name the length prefix can carry is a name"
        );
        assert!(
            RealtimeFlowName::new(vec![
                b'x';
                crate::realtime::MAX_REALTIME_FLOW_LABEL_BYTES + 1
            ])
            .is_none(),
            "one byte past what the frame can encode could never have arrived"
        );
    }

    /// The label's bytes outlive the flow, and the lease goes with them —
    /// through the queue, not merely in a hand-built event.
    ///
    /// **This is the property the shared record exists for, asserted where it
    /// can actually fail.** A close queues its event on the lifecycle stream
    /// and the consumer may not read it for arbitrarily long. If the queued
    /// item carried a *copy of the bytes* instead of the leased label, the
    /// charge would be released at close while the bytes were still retained —
    /// which is precisely the counterexample the shared lease is for. So the
    /// control drives the real close, observes that the charge is still held
    /// while nothing has dequeued, and only then takes the event.
    ///
    /// The name is free to claim again the whole time. Reusability and
    /// accounting are separate facts: the label space is the session's and the
    /// charge belongs to the bytes, so a reclaim while a close event is still
    /// queued is ordinary rather than a conflict.
    #[tokio::test]
    async fn v4_macro1_a_queued_close_event_still_owns_the_labels_lease() {
        let (registry, resources) = control_label_registry();
        let incarnation = crate::connector::ConnectorIncarnation::new();
        let session = ControlSession {
            incarnation: Arc::clone(&incarnation),
        };
        let mut flows = SessionRealtimeFlows::new(
            Arc::clone(&registry),
            Some(leased_control_profile(&registry)),
        );
        let events = flows
            .flow_events()
            .expect("a fresh flow set issues its lifecycle lease once");

        let empty = resources.accounted_bytes();
        let name = flows
            .open(
                &session,
                Some(&incarnation),
                RealtimeFlowSpec {
                    direction: RealtimeDirection::Outbound,
                    encoding: control_encoding(),
                    name: control_name(b"outlives"),
                },
            )
            .expect("the space starts empty");

        let _remains = flows
            .close(&session, Some(&incarnation), &name)
            .expect("the session that opened this flow may close it");

        // Nothing has dequeued. The flow is gone and its name is free, and the
        // charge for the bytes the queued event holds is still outstanding.
        assert!(
            !flows.labels.holds(&name),
            "the name is claimable again the moment the flow is gone"
        );
        assert!(
            resources.accounted_bytes() > empty,
            "and the queued close event is still holding the label's lease — a \
             design that copied the bytes out at close would have released it \
             here, with the bytes still retained"
        );

        let event = events
            .next()
            .await
            .expect("the close is waiting on the lifecycle stream");
        let RealtimeFlowEvent::Closed { label: retained } = &event;
        assert_eq!(
            retained.name(),
            &name,
            "the event names the flow after every other copy is gone"
        );

        // And only the consumer taking it releases the charge.
        drop(event);
        assert_eq!(
            resources.accounted_bytes(),
            empty,
            "the last holder dropping is what returns the bytes, not the close"
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
        let (registry, _resources) = control_label_registry();
        let mut labels = RealtimeFlowLabels::default();
        let held = control_name(b"held");
        let cited = control_name(b"cited");
        labels
            .claim_exact(&held, &registry)
            .expect("the space starts empty");

        // Any bytes within the frame bound are a syntactically valid name, so
        // nothing is rejected here — which is exactly why the answer has to be
        // a lookup rather than a judgement.
        assert!(
            labels.holds(&held),
            "a peer can name a flow this session really does hold"
        );
        assert!(
            !labels.holds(&cited),
            "and naming one it does not hold finds nothing"
        );
        assert!(
            !labels.holds(&control_name(
                &[b'z'; crate::realtime::MAX_REALTIME_FLOW_LABEL_BYTES]
            )),
            "including the largest name the frame can carry"
        );

        // The cited name did not become held by being mentioned.
        let claimed = labels
            .claim_exact(&cited, &registry)
            .expect("a name a peer said is still free until this side claims it");
        assert_eq!(claimed.name(), &cited);
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
    /// name. Nothing already in that fence separates the two, which is what
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
        // A real provider scope and no ceiling. This control never opens a
        // flow, but it does claim a name in each namespace, and a name costs a
        // real lease — so the elastic registry is the smallest thing that both
        // admits the claims and holds the registry identical across the two
        // sets.
        let (registry, _resources) = control_label_registry();
        let mut first = SessionRealtimeFlows::new(
            Arc::clone(&registry),
            Some(leased_control_profile(&registry)),
        );
        // Allocated while `first` is still alive, so the two streams cannot
        // share an address and the drop case below cannot pass by accident.
        let mut second = SessionRealtimeFlows::new(
            Arc::clone(&registry),
            Some(leased_control_profile(&registry)),
        );

        // The same name is live in both namespaces. A session's label space is
        // its own, so this is the ordinary state after a replacement — the
        // application reuses the name it always used.
        let name = control_name(b"shared");
        assert!(first.labels.claim_exact(&name, &registry).is_ok());
        assert!(second.labels.claim_exact(&name, &registry).is_ok());

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
            "and by no other — a reader taken from one session's stream cannot \
             be spent against another's flow of the same name"
        );
        assert!(!first.owns_arrivals(&from_second));

        // The replacement shape, which is the one the race actually takes: the
        // session that issued the reader is gone, and the reader outlives it.
        // `Weak::as_ptr` still answers the dead stream's old address, so this
        // is exactly where a naive pointer read would report a match against
        // whatever now sits there.
        drop(from_second);
        drop(second);
        let replacement = SessionRealtimeFlows::new(
            Arc::clone(&registry),
            Some(leased_control_profile(&registry)),
        );
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
        // Minted, not hand-built: a binding retains its label for as long as it
        // exists, so the copy it holds is one the session paid for.
        let (registry, _resources) = control_label_registry();
        let label = RealtimeFlowLabel::mint(control_name(b"bound"), &registry)
            .expect("the elastic control grant admits one label");
        let encoding = RealtimeEncoding::new(WebRtcRtpKind::Video, "video/H264", 90_000, 0)
            .expect("the fixture encoding is one a flow can carry");
        // Cloned into the binding, exactly as `bind_inbound` clones from the
        // flows map's own key: the binding and the releasing scope name the
        // same record and the same lease, not two copies of the bytes.
        let binding = RealtimeInboundBinding::new(label.clone(), encoding, RealtimeFraming::AnnexB);

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
            Some(label.clone()),
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
        bindings.release(&label);
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
        let profile = RealtimeProfile::new(vec![
            h264_variant(102, "packetization-mode=1;profile-level-id=42001f"),
            h264_variant(127, "packetization-mode=0;profile-level-id=42001f"),
            h264_variant(125, "packetization-mode=1;profile-level-id=42e01f"),
            h264_variant(108, "packetization-mode=0;profile-level-id=42e01f"),
            h264_variant(123, "packetization-mode=1;profile-level-id=640032"),
        ])
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
            RealtimeProfile::new(vec![h264_variant(102, "a"), h264_variant(102, "b")]),
            Err(RealtimeProfileError::DuplicatePayloadType { payload_type: 102 }),
            "two registrations on one payload type make negotiation ambiguous"
        );

        let mut disagrees = h264_variant(127, "b");
        disagrees.framing = RealtimeFraming::Whole;
        assert_eq!(
            RealtimeProfile::new(vec![h264_variant(102, "a"), disagrees]),
            Err(RealtimeProfileError::FamilyFramingConflict {
                mime: "video/H264".to_string(),
                clock_rate: 90_000,
            }),
            "a flow opens against the family before a payload type exists, so a \
             family whose variants disagree on framing has no framer to install"
        );

        assert!(
            RealtimeProfile::new(vec![h264_variant(102, "a"), h264_variant(127, "b")]).is_ok(),
            "but two variants of one family are exactly the deployed shape and \
             must not be refused"
        );
    }
}
