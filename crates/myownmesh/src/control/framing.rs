//! Bytes on the wire, in both of the shapes this socket carries, and the
//! admission that funds them.
//!
//! Two framings, deliberately together. A control connection speaks
//! line-delimited JSON until it becomes a `realtime_pipe`, after which it speaks
//! `[u32 len][body]` and nothing else — so a connection uses one or the other,
//! never both at once, and the thing they share is the only interesting part:
//! every inbound byte is acquired from the process owner's grant before it is
//! buffered. Splitting them would have put one admission rule in two files.
//!
//! Nothing here knows what a request means, what a network is, or which client
//! is asking. It reads bytes, refuses the ones nobody funded, and hands the rest
//! up. That is the whole of its authority: it decides *how much*, never *what*.

use anyhow::{Context, Result};
use tokio::io::AsyncBufReadExt;

/// Read one optional owner-selected byte ceiling.
///
/// Absent is a valid answer and the ordinary one: it means the owner has not
/// chosen to bound inbound frames more tightly than the grant already does.
/// Present but unparseable is not — an owner who set the value meant something
/// by it, and starting anyway would silently ignore a stated policy.
pub(super) fn optional_nonzero_bytes(name: &str) -> Result<Option<usize>> {
    let value = match std::env::var(name) {
        Ok(value) => value,
        Err(std::env::VarError::NotPresent) => return Ok(None),
        // Set, and not text. That is a stated policy this daemon cannot read,
        // which is a different thing from no policy — matching it against
        // `NotPresent` would start the daemon with the owner's bound silently
        // discarded, in the one case where they had definitely set one.
        Err(std::env::VarError::NotUnicode(_)) => {
            anyhow::bail!("{name} is set but is not valid Unicode")
        }
    };
    value
        .parse::<std::num::NonZeroUsize>()
        .with_context(|| format!("{name} must be a nonzero integer"))
        .map(|bytes| Some(bytes.get()))
}

/// What bounds the inbound frames of one control connection.
///
/// Two independent bounds, and only one of them is optional. The resource bound
/// always applies: every inbound byte this daemon buffers is acquired from the
/// process owner's grant at the size actually read, so an absent ceiling means
/// *measured and admitted*, never *unbounded*. An explicit ceiling is an
/// additional owner policy layered on top, and it can only refuse more — a
/// number here can never admit something the provider would not.
///
/// This replaces two mandatory `usize` ceilings, and the change is not merely
/// that they became optional. Requiring them made the daemon refuse to start
/// without figures its owner had no basis to choose; and having chosen them, the
/// bytes behind them were still never accounted, because a ceiling says how
/// large one frame may be and nothing at all about how much the process is
/// holding. A thousand connections each one byte under the ceiling passed every
/// check.
#[derive(Clone)]
pub(super) struct FrameAdmission {
    resources: myownmesh_core::LocalApplicationResourceScope,
    ceiling: Option<usize>,
}

/// Why one inbound frame was not admitted.
///
/// Three arms because an operator reads them differently: a ceiling refusal is
/// their own policy answering, a provider refusal is the daemon at the edge of
/// its grant, and an unrepresentable claim is a defect here. Reporting a
/// too-large frame and an out-of-capacity daemon as the same thing would send an
/// operator to change the wrong number.
#[derive(Debug, thiserror::Error)]
pub(super) enum FrameRefusal {
    #[error("frame of {frame} bytes exceeds the owner-selected ceiling of {ceiling} bytes")]
    Ceiling { frame: usize, ceiling: usize },
    #[error("frame byte claim is not representable: {0}")]
    Claim(myownmesh_core::ResourceClaimArithmeticError),
    #[error("frame bytes were refused by the resource provider: {0:?}")]
    Resources(myownmesh_core::ResourceUnavailable),
}

impl FrameAdmission {
    pub(super) fn new(
        resources: myownmesh_core::LocalApplicationResourceScope,
        ceiling: Option<usize>,
    ) -> Self {
        Self { resources, ceiling }
    }

    /// Admit one whole frame of `bytes` and answer the funding that holds it.
    ///
    /// The lease must be held for as long as the frame's bytes are, and dropped
    /// when they are — that is the whole of the accounting, and holding it
    /// longer would report the daemon as fuller than it is.
    pub(super) fn admit(
        &self,
        bytes: usize,
    ) -> std::result::Result<myownmesh_core::ResourceLease, FrameRefusal> {
        self.admit_growth(0, bytes)
    }

    /// Admit `more` further bytes of a frame already holding `held` of them.
    ///
    /// The ceiling is checked against the total, because it bounds a frame and
    /// not a read; the claim is taken for the growth alone, because that is what
    /// is newly held. Checking the ceiling per chunk would let a line arrive in
    /// pieces and pass a bound it exceeded.
    pub(super) fn admit_growth(
        &self,
        held: usize,
        more: usize,
    ) -> std::result::Result<myownmesh_core::ResourceLease, FrameRefusal> {
        let overflow = || {
            FrameRefusal::Claim(myownmesh_core::ResourceClaimArithmeticError::Overflow {
                dimension: myownmesh_core::ResourceClass::AccountedMemoryBytes,
            })
        };
        let frame = held.checked_add(more).ok_or_else(overflow)?;
        if let Some(ceiling) = self.ceiling {
            if frame > ceiling {
                return Err(FrameRefusal::Ceiling { frame, ceiling });
            }
        }
        let more = u64::try_from(more).map_err(|_| overflow())?;
        let claim = myownmesh_core::ResourceClaim::try_from_entries([(
            myownmesh_core::ResourceClass::AccountedMemoryBytes,
            more,
        )])
        .map_err(FrameRefusal::Claim)?;
        self.resources
            .acquire(claim)
            .map_err(FrameRefusal::Resources)
    }

    /// The widest frame this connection's framing may express.
    ///
    /// Only the owner's ceiling, because this answers a *representation*
    /// question — can the encoder write a length prefix for it — and the
    /// provider does not answer that one. With no owner ceiling the only bound
    /// is the wire's own `u32`, which the encoder checks separately and always.
    pub(super) fn framing_ceiling(&self) -> usize {
        self.ceiling.unwrap_or(usize::MAX)
    }
}

/// One admitted line of the control protocol, and the funding that holds it.
///
/// The two travel together because they have to. The line's bytes are alive
/// until the caller drops the line, and the caller does not drop it at once —
/// it parses a `Request` out of it first, which is precisely the moment the
/// daemon is holding the most on that connection's behalf. Releasing the
/// funding when the reader returned would have reported the daemon as holding
/// nothing over exactly that window.
///
/// So the leases live in here, are never read, and exist to be dropped with the
/// bytes they paid for. Field order matters and is not incidental: `line` is
/// destroyed before `_held`, so the funding outlives what it funds rather than
/// the other way round.
pub(super) struct AdmittedLine {
    line: String,
    _held: Vec<myownmesh_core::ResourceLease>,
}

impl AdmittedLine {
    pub(super) fn as_str(&self) -> &str {
        &self.line
    }
}

/// Read one line of the control protocol, admitting its bytes as they arrive.
///
/// Every chunk taken off the reader is funded before it is buffered, so the
/// daemon holds no unaccounted request bytes at any point — including a request
/// that is still arriving. That is what an absent owner ceiling now means:
/// bounded by the grant, at measured size, rather than unbounded.
///
/// The funding leaves with the line rather than with this function; see
/// [`AdmittedLine`].
pub(super) async fn read_bounded_json_line<R>(
    reader: &mut R,
    admission: &FrameAdmission,
) -> Result<Option<AdmittedLine>>
where
    R: tokio::io::AsyncBufRead + Unpin,
{
    let mut bytes = Vec::new();
    // Accumulated beside the buffer and handed out with it. On the error paths
    // it is dropped here instead, together with the buffer it paid for — a line
    // that never became one funds nothing.
    let mut held = Vec::new();
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            if bytes.is_empty() {
                return Ok(None);
            }
            return admitted_line(bytes, held).map(Some);
        }
        let take = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |at| at + 1);
        held.push(
            admission
                .admit_growth(bytes.len(), take)
                .context("control request was not admitted")?,
        );
        bytes.extend_from_slice(&available[..take]);
        reader.consume(take);
        if bytes.last() == Some(&b'\n') {
            bytes.pop();
            if bytes.last() == Some(&b'\r') {
                bytes.pop();
            }
            return admitted_line(bytes, held).map(Some);
        }
    }
}

/// Pair the decoded line with the funding that has been holding its bytes.
///
/// The trailing newline and any carriage return are popped before this, so the
/// line is a little shorter than what was admitted. That slack is not reclaimed
/// and should not be: it was really held while the line was being read, and
/// re-acquiring the exact remainder would mean releasing funding and asking for
/// it back — a window in which a concurrent connection could take it and this
/// one would fail on bytes it already had.
fn admitted_line(bytes: Vec<u8>, held: Vec<myownmesh_core::ResourceLease>) -> Result<AdmittedLine> {
    let line = String::from_utf8(bytes).context("control request is not UTF-8")?;
    Ok(AdmittedLine { line, _held: held })
}

// ---- binary realtime pipe frame codec ---------------------------------------
//
// The frames a [`Request::RealtimePipe`] connection carries. Each frame on the
// wire is `[u32 len LE][body]`; `body` is what these encode and parse.
// Round-trip tested below.
//
// This codec is defined here and answers to nothing outside this crate. An
// earlier version of this comment instructed maintainers to keep it
// byte-for-byte identical to a client application's codec, which had it exactly
// backwards — a client's encoder is a consumer of this format, not its
// specification — and was in any case untrue, since that layout leads with a
// kind byte this one does not have. Clients are held to this wire; it is not
// held to theirs.

/// Defensive cap on one frame body — a corrupt length never allocates more.
#[cfg(test)]
const TEST_REALTIME_FRAME_CEILING: usize = 64 * 1024 * 1024;

/// Fixed prefix width of a realtime frame body, identical in both directions:
/// the label's length, a one-byte slot, a four-byte slot, and the payload
/// length. The label's bytes and then the payload's follow it, in that order.
///
/// Both slots are named by direction rather than here, because both mean
/// different things each way: the one-byte slot is the marker inbound and
/// reserved zero outbound, and the four-byte slot is an absolute timestamp
/// inbound and a duration outbound. Equal width is what lets the two encoders be
/// read against each other; it is not a shared meaning.
///
/// The leading byte is a *length*, not a label. A label is opaque bytes chosen
/// by the application, so it cannot be a fixed-width field, and length-prefixing
/// it with one byte is what makes [`MAX_REALTIME_FLOW_LABEL_BYTES`] 255 —
/// the bound is the field's width, not a policy. Both variable-length runs are
/// counted, so a body's total width is fully determined by its prefix, and a
/// body whose bytes disagree with its own prefix is refused rather than
/// resolved.
pub(super) const REALTIME_FRAME_HEADER: usize = 1 + 1 + 4 + 4;

/// The longest label the frame above can carry, and therefore the longest core
/// will accept.
///
/// Re-exported rather than restated. The bound is a representation fact about
/// the single length byte in this frame, and the frame encoder here, the
/// provider edge that refuses an over-long open, and the name constructor in the
/// connector all have to agree on it — so there is one constant, in the basal
/// vocabulary, and this is a second spelling of that one value rather than a
/// second value.
pub use myownmesh_core::realtime::MAX_REALTIME_FLOW_LABEL_BYTES;

/// One unit read off an **outbound** pipe, on its way to a flow.
///
/// The pipe is bound to a session, so the body carries no network, peer, or
/// codec — only which flow of that session, and what the connector needs to
/// pace it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealtimeSendUnit {
    /// The flow's opaque name, exactly as the application chose it. Never
    /// parsed, ordered, or ranged over here; it is carried to core, which
    /// resolves it by equality against one session's own table. Empty is
    /// refused rather than accepted as a degenerate name, so the binary and
    /// JSON paths cannot disagree about what an absent label means.
    pub flow_label: Vec<u8>,
    /// Presentation duration of this unit. Paces the flow clock on the way
    /// out; it is *not* a timestamp, and deliberately does not share a type
    /// with one.
    pub duration_us: u32,
    pub payload: Vec<u8>,
}

// There is no `marker` on an outbound unit, and the byte that would hold it is
// reserved zero on the wire.
//
// It was never the application's to set. Under `AnnexB` framing the app hands
// over whole access units and the transport library sets the RTP marker on the
// last packet of each — the unit boundary IS the marker, so a field here would
// be an input nothing reads. Keeping it would have been an invitation to set it
// and to reason about what it did.
//
// The byte stays so both directions keep one header width, which is what lets
// the two encoders be reviewed against each other. It is reserved rather than
// free: a sender that writes anything but zero is refused, because a nonzero
// value there means either a client that believes it is setting something or a
// body from an encoder whose second byte means something else.

/// One unit written to an **inbound** pipe, as received from a flow.
///
/// Deliberately a distinct type from [`RealtimeSendUnit`] even though the two
/// bodies are the same width. The 4-byte slot means different things in each
/// direction — a duration going out, an absolute timestamp coming in — and one
/// shared `timestamp` field would let a value from one direction be used as
/// the other with nothing to catch it. The layout is shared; the meaning is
/// not, so the types are not either.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealtimeRecvUnit {
    /// The flow's opaque name, as core reported it on arrival. A copy of the
    /// bytes, not a handle: it grants nothing and outlives nothing.
    pub flow_label: Vec<u8>,
    pub marker: bool,
    /// Absolute, at the flow's declared `clock_rate`. Uninterpretable without
    /// it, which is why that is a field on the flow rather than a codec detail.
    pub rtp_timestamp: u32,
    pub payload: Vec<u8>,
}

/// Parse an outbound unit body (the bytes after the `u32` length prefix).
///
/// Returns `None` on any truncation or a payload length that disagrees with
/// the frame — a malformed frame is dropped, never panics, and never trusts a
/// length it did not check against the bytes actually present.
pub fn decode_realtime_send_unit(body: &[u8]) -> Option<RealtimeSendUnit> {
    let header = body.get(..REALTIME_FRAME_HEADER)?;
    let label_len = header[0] as usize;
    // Zero is refused rather than read as "no label". A flow is always named,
    // and a body that named nothing could only be resolved by guessing which
    // flow it meant.
    if label_len == 0 {
        return None;
    }
    let payload_len = u32::from_le_bytes(header[6..10].try_into().ok()?) as usize;
    // Byte 1 is reserved and must be zero. Every other value is refused, which
    // is the strongest check available at this offset: the encoders
    // neighbouring this one put a stream index, a payload type or a keyframe
    // flag here, and those are usually nonzero, so a body that arrived from the
    // wrong encoder fails on its second byte rather than being interpreted.
    //
    // It also refuses a client that writes a marker it believes in. Nothing
    // downstream would read it, and accepting the byte would let that belief
    // survive indefinitely without ever being contradicted.
    if header[1] != 0 {
        return None;
    }
    // The two counted runs must account for the body exactly. Not `>=`: a body
    // longer than its own prefix describes is as malformed as a short one, and
    // accepting the excess would let a trailing tail ride along unread. This is
    // also the check a one-byte-shifted body from a neighbouring encoder cannot
    // survive, which is why it is arithmetic on both lengths rather than a
    // bounds test on one.
    let rest = body.get(REALTIME_FRAME_HEADER..)?;
    if rest.len() != label_len.checked_add(payload_len)? {
        return None;
    }
    let (label, payload) = rest.split_at(label_len);
    Some(RealtimeSendUnit {
        flow_label: label.to_vec(),
        duration_us: u32::from_le_bytes(header[2..6].try_into().ok()?),
        payload: payload.to_vec(),
    })
}

/// Serialize an inbound unit body (no length prefix).
///
/// Layout, integers little-endian:
/// `label_len u8 · marker u8 · rtp_timestamp u32 · payload_len u32 · label… ·
/// payload…`
///
/// Both lengths are redundant with the frame's own `u32` prefix and both are
/// kept anyway, because the redundancy is the check. Every neighbouring encoder
/// in the tree starts with a `kind u8` this one does not have, so a sender that
/// reaches for the wrong one produces a body shifted by exactly one byte —
/// where `label_len` reads a kind, `marker` reads a stream index, and every
/// field is plausible. The two counted runs are what cannot survive that shift:
/// they must account for the body exactly, and a shifted body's do not. Five
/// bytes a unit is cheap for turning a silent misinterpretation into a refusal.
///
/// See `a_neighbouring_encoders_frame_is_refused_not_reinterpreted`.
pub fn encode_realtime_recv_unit_with_ceiling(
    unit: &RealtimeRecvUnit,
    frame_ceiling: usize,
) -> Option<Vec<u8>> {
    // Every check happens before anything is allocated, and every one is
    // checked rather than cast. `payload.len() as u32` would truncate a payload
    // past 4 GiB and produce a body whose inner length disagreed with its own
    // contents — the exact malformation the decoder on the other side refuses,
    // manufactured by us. A frame that cannot be encoded correctly must not be
    // half-encoded.
    //
    // The label bound is the same rule the decoder enforces, applied here so a
    // name that could not be framed is never half-written: empty is refused,
    // and so is anything the one-byte length prefix could not count.
    if unit.flow_label.is_empty() || unit.flow_label.len() > MAX_REALTIME_FLOW_LABEL_BYTES {
        return None;
    }
    let label_len = u8::try_from(unit.flow_label.len()).ok()?;
    let payload_len = u32::try_from(unit.payload.len()).ok()?;
    let total = REALTIME_FRAME_HEADER
        .checked_add(unit.flow_label.len())?
        .checked_add(unit.payload.len())?;
    if total > frame_ceiling || total > u32::MAX as usize {
        return None;
    }
    let mut out = Vec::with_capacity(total);
    out.push(label_len);
    out.push(unit.marker as u8);
    out.extend_from_slice(&unit.rtp_timestamp.to_le_bytes());
    out.extend_from_slice(&payload_len.to_le_bytes());
    out.extend_from_slice(&unit.flow_label);
    out.extend_from_slice(&unit.payload);
    Some(out)
}

#[cfg(test)]
fn encode_realtime_recv_unit(unit: &RealtimeRecvUnit) -> Option<Vec<u8>> {
    encode_realtime_recv_unit_with_ceiling(unit, TEST_REALTIME_FRAME_CEILING)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::control::Request;

    /// A label of two or more bytes, used everywhere a fixture needs one.
    ///
    /// Deliberately not one byte. A single-byte label makes the length prefix
    /// and the label indistinguishable in width, so a body built by hand would
    /// pass several of the checks below by coincidence — the shift control in
    /// particular would stop testing what it exists to test. It is also not
    /// valid UTF-8, because the binary path carries bytes and must not quietly
    /// acquire a text assumption from the JSON path that happens to sit beside
    /// it.
    const LABEL: &[u8] = &[b's', b'c', b'r', 0xff];

    /// A frame from a *neighbouring* encoder must be refused, never reinterpreted.
    ///
    /// The hazard is structural rather than particular to any one client. A
    /// layout of `kind u8 · stream u8 · key u8 · timestamp u32 · len u32 ·
    /// payload` — our fixed prefix behind one extra leading byte — is a shape
    /// encoders in this problem space converge on, and a sender that reaches for
    /// one produces a body shifted by exactly one byte where every field stays
    /// plausible: `label_len` reads a kind (1 or 2, both perfectly good label
    /// lengths), the reserved byte reads a stream index, and the u32 slots read
    /// a keyframe flag glued to three bytes of timestamp and then a length
    /// glued to a byte of its own.
    ///
    /// Nothing is acknowledged per unit, so if this were interpreted rather than
    /// refused the failure would be one hundred percent of media going nowhere
    /// with no signal on the sending side. The two counted runs are what make
    /// that impossible: `label_len + payload_len` must account for the body
    /// exactly, and a shifted body's cannot.
    #[test]
    fn a_neighbouring_encoders_frame_is_refused_not_reinterpreted() {
        let payload = [7u8, 7, 7, 7, 7, 7];
        // The shifted layout: our prefix plus one leading `kind` byte.
        //
        // `kind` is 1 and `stream` is 0, and neither choice is incidental.
        // After the shift `kind` lands in `label_len`, so it must be nonzero or
        // the empty-label check rejects the body before the arithmetic runs;
        // `stream` lands in the reserved byte, which accepts only zero, so a
        // nonzero stream index would be refused there instead. Both are the
        // commonest values a real sender writes, and both are chosen here so the
        // body reaches the one check this control exists to prove.
        let mut foreign = Vec::new();
        foreign.push(1u8); // kind
        foreign.push(0u8); // stream
        foreign.push(1u8); // key
        foreign.extend_from_slice(&90_000u32.to_le_bytes()); // timestamp
        foreign.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        foreign.extend_from_slice(&payload);

        assert_eq!(
            foreign.len(),
            REALTIME_FRAME_HEADER + 1 + payload.len(),
            "the foreign body is our prefix plus exactly one leading byte — if \
             this ever stops holding, the shift this test protects against has \
             changed shape and the assertion below is no longer testing it"
        );
        assert!(
            decode_realtime_send_unit(&foreign).is_none(),
            "a one-byte-shifted body must be refused: with the reserved byte \
             zeroed and the label length nonzero, the counted-run arithmetic is \
             the only thing standing between it and silently misrouted media"
        );
        // Non-vacuity, both halves. Neither cheap check may be what rejected
        // this body, or the control would keep passing after the arithmetic it
        // exists to protect was deleted.
        assert_ne!(
            foreign[0], 0,
            "the shifted body must reach the length arithmetic, not stop at the \
             empty-label check"
        );
        assert_eq!(
            foreign[1], 0,
            "the shifted body must reach the length arithmetic, not stop at the \
             reserved byte"
        );
        // And the arithmetic really is what disagrees: the shifted body claims
        // one label byte plus six payload bytes, and carries eleven after the
        // prefix.
        let shifted_claim = foreign[0] as usize
            + u32::from_le_bytes(foreign[6..10].try_into().expect("ten bytes present")) as usize;
        assert_ne!(
            shifted_claim,
            foreign.len() - REALTIME_FRAME_HEADER,
            "if a shifted body's counted runs ever add up, this control proves \
             nothing and the layout must be reconsidered"
        );
    }

    /// Local copy of the client's writer, so the round-trip is asserted
    /// against the exact layout the client produces rather than against our
    /// own decoder's assumptions.
    ///
    /// `reserved` is a raw byte rather than a `bool`, because the field it
    /// occupies is reserved zero and the interesting cases are the values a
    /// correct client never writes. `label_len` is taken separately from
    /// `label` so a fixture can state a length its bytes do not back, which is
    /// the malformation the decoder has to refuse.
    fn encode_send_unit_parts(
        label_len: u8,
        label: &[u8],
        reserved: u8,
        duration_us: u32,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut out = Vec::with_capacity(REALTIME_FRAME_HEADER + label.len() + payload.len());
        out.push(label_len);
        out.push(reserved);
        out.extend_from_slice(&duration_us.to_le_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(label);
        out.extend_from_slice(payload);
        out
    }

    /// The well-formed case: the stated length is the label's own.
    fn encode_send_unit(label: &[u8], reserved: u8, duration_us: u32, payload: &[u8]) -> Vec<u8> {
        encode_send_unit_parts(
            u8::try_from(label.len()).expect("a fixture label is within the prefix width"),
            label,
            reserved,
            duration_us,
            payload,
        )
    }

    #[test]
    fn send_units_round_trip_without_naming_a_codec() {
        let body = encode_send_unit(LABEL, 0, 33_333, &[1, 2, 3, 9]);
        let unit = decode_realtime_send_unit(&body).expect("decode");
        // Exact opaque bytes, not a rendering of them: the label is four bytes
        // and the last is not valid UTF-8, so anything that went through a
        // string on the way here would come back changed.
        assert_eq!(unit.flow_label, LABEL.to_vec());
        assert_eq!(unit.duration_us, 33_333);
        assert_eq!(unit.payload, vec![1, 2, 3, 9]);

        // An empty payload is a legitimate unit, and the same decode path. An
        // empty *label* is not — see `a_frame_naming_no_flow_is_refused`.
        let empty = decode_realtime_send_unit(&encode_send_unit(LABEL, 0, 20_000, &[]))
            .expect("decode empty");
        assert!(empty.payload.is_empty());
        assert_eq!(empty.flow_label, LABEL.to_vec());

        // The longest label the prefix can count still round-trips whole.
        let longest = vec![0xab; MAX_REALTIME_FLOW_LABEL_BYTES];
        let long = decode_realtime_send_unit(&encode_send_unit(&longest, 0, 1, &[4]))
            .expect("a 255-byte label is within the prefix width");
        assert_eq!(long.flow_label, longest);
    }

    /// A body that names no flow is refused rather than read as naming none.
    ///
    /// Zero is the one label length that would otherwise decode into something
    /// — a unit with an empty name, which core could only resolve by guessing.
    /// Refusing it here is also what keeps the binary path and the JSON path
    /// agreeing: neither has a spelling for "a flow with no name".
    #[test]
    fn a_frame_naming_no_flow_is_refused() {
        let body = encode_send_unit_parts(0, &[], 0, 1, &[7, 7, 7]);
        assert!(
            decode_realtime_send_unit(&body).is_none(),
            "a zero-length label must be refused, not read as an absent one"
        );
        // Non-vacuity: with a real label of the same shape the body decodes, so
        // it is the zero that was rejected and not the rest of the frame.
        let ok = encode_send_unit(LABEL, 0, 1, &[7, 7, 7]);
        assert!(decode_realtime_send_unit(&ok).is_some());
    }

    #[test]
    fn truncation_is_none_not_panic() {
        let body = encode_send_unit(LABEL, 0, 1, &[7, 7, 7]);
        for cut in 0..body.len() {
            assert!(
                decode_realtime_send_unit(&body[..cut]).is_none(),
                "short {cut}"
            );
        }
    }

    /// The two counted runs are redundant with the frame's own prefix, which is
    /// exactly why a disagreement between them must be refused rather than
    /// resolved: silently trusting any one of them lets a corrupt frame hand a
    /// truncated or over-long payload — or a label sliced out of a payload — to
    /// a decoder as if it were whole.
    #[test]
    fn a_length_that_disagrees_with_the_frame_is_refused() {
        // A payload length larger than the bytes present.
        let mut body = encode_send_unit(LABEL, 0, 1, &[7, 7, 7]);
        body[6] = 9;
        assert!(decode_realtime_send_unit(&body).is_none());

        // A body longer than its own counted runs describe. The excess is not
        // ignored: accepting it would let a trailing tail ride along unread.
        let mut over = encode_send_unit(LABEL, 0, 1, &[7, 7, 7]);
        over.push(0);
        assert!(decode_realtime_send_unit(&over).is_none());

        // A label length longer than the label actually written. Every field
        // after the prefix stays plausible — the decoder would simply take
        // payload bytes as name bytes — so only the total can catch it.
        let overlong_label = encode_send_unit_parts(
            u8::try_from(LABEL.len() + 1).expect("fits"),
            LABEL,
            0,
            1,
            &[7, 7, 7],
        );
        assert!(
            decode_realtime_send_unit(&overlong_label).is_none(),
            "a label length its bytes do not back must be refused, not filled \
             from the payload"
        );

        // And shorter, which would otherwise silently rename the flow and
        // prepend the leftover byte to its payload.
        let short_label = encode_send_unit_parts(
            u8::try_from(LABEL.len() - 1).expect("fits"),
            LABEL,
            0,
            1,
            &[7, 7, 7],
        );
        assert!(
            decode_realtime_send_unit(&short_label).is_none(),
            "a label length shorter than its bytes must be refused, not read as \
             a different flow"
        );
    }

    /// Byte 1 of an outbound body is reserved: zero decodes, everything else is
    /// refused.
    ///
    /// Not pedantry about an unused field. The byte is the one position where a
    /// body from a neighbouring encoder differs most reliably — a stream index,
    /// a payload type or a keyframe flag lands here after the one-byte shift,
    /// and those are usually nonzero. Requiring zero turns that offset into a
    /// check rather than a place to store a value nothing reads.
    ///
    /// It also refuses a client that writes a marker it believes in. Under
    /// `AnnexB` framing the transport library sets the RTP marker from the unit
    /// boundary, so an application-supplied one was never an input; accepting
    /// the byte would let that belief survive without ever being contradicted.
    #[test]
    fn a_nonzero_reserved_byte_is_refused() {
        let ok = encode_send_unit(LABEL, 0, 1, &[7]);
        let unit = decode_realtime_send_unit(&ok).expect("a zeroed reserved byte decodes");
        assert_eq!(unit.flow_label, LABEL.to_vec());
        assert_eq!(unit.payload, vec![7]);

        // Every nonzero value, not a sample. 1 is the important one — it is
        // what a client that still thinks it is sending a marker would write,
        // and the value most likely to be waved through by a `!= 0` reading.
        for byte in 1u8..=255 {
            let body = encode_send_unit(LABEL, byte, 1, &[7]);
            assert!(
                decode_realtime_send_unit(&body).is_none(),
                "reserved byte {byte} must be refused"
            );
        }
    }

    /// A unit too large to frame yields `None` rather than a malformed body.
    ///
    /// The failure this prevents is not the loss of one unit. An encoder that
    /// cast the length would write an inner length disagreeing with its own
    /// contents — precisely what the decoder at the far end refuses — so the
    /// client could neither use that frame nor resynchronise after it, and one
    /// unusable unit would cost every unit behind it.
    #[test]
    fn a_unit_too_large_to_frame_is_not_half_encoded() {
        let ok = encode_realtime_recv_unit(&RealtimeRecvUnit {
            flow_label: LABEL.to_vec(),
            marker: true,
            rtp_timestamp: 90_000,
            payload: vec![1, 2, 3],
        })
        .expect("an ordinary unit encodes");
        assert_eq!(ok.len(), REALTIME_FRAME_HEADER + LABEL.len() + 3);

        // One byte past what the framing may carry. The label counts toward the
        // ceiling too, which is why it is subtracted here: a bound that only
        // considered the payload would emit bodies a byte over. Allocated rather
        // than faked, so the bound under test is the real one.
        let headroom = TEST_REALTIME_FRAME_CEILING - REALTIME_FRAME_HEADER - LABEL.len();
        let oversize = RealtimeRecvUnit {
            flow_label: LABEL.to_vec(),
            marker: false,
            rtp_timestamp: 0,
            payload: vec![0u8; headroom + 1],
        };
        assert!(
            encode_realtime_recv_unit(&oversize).is_none(),
            "a body over the selected frame ceiling must not be encoded at all"
        );

        // The largest unit that still fits is accepted — the check is a ceiling,
        // not an off-by-one that also rejects the boundary.
        let exact = RealtimeRecvUnit {
            flow_label: LABEL.to_vec(),
            marker: false,
            rtp_timestamp: 0,
            payload: vec![0u8; headroom],
        };
        assert_eq!(
            encode_realtime_recv_unit(&exact).map(|body| body.len()),
            Some(TEST_REALTIME_FRAME_CEILING)
        );
    }

    /// A label the framing cannot express is refused outright, not truncated.
    ///
    /// Both ends of the rule, because both are reachable: an empty name would
    /// produce a body the decoder must refuse, and a name past the one-byte
    /// prefix would have its length silently wrapped into a different, valid
    /// number — which is worse than a dropped unit, since it names a real flow
    /// that is not this one.
    #[test]
    fn a_label_the_frame_cannot_carry_is_not_half_encoded() {
        let unnamed = RealtimeRecvUnit {
            flow_label: Vec::new(),
            marker: false,
            rtp_timestamp: 0,
            payload: vec![1],
        };
        assert!(encode_realtime_recv_unit(&unnamed).is_none());

        let overlong = RealtimeRecvUnit {
            flow_label: vec![b'x'; MAX_REALTIME_FLOW_LABEL_BYTES + 1],
            marker: false,
            rtp_timestamp: 0,
            payload: vec![1],
        };
        assert!(encode_realtime_recv_unit(&overlong).is_none());

        // The boundary itself encodes, so the rule is a ceiling and not an
        // off-by-one that also rejects the longest usable name.
        let longest = RealtimeRecvUnit {
            flow_label: vec![b'x'; MAX_REALTIME_FLOW_LABEL_BYTES],
            marker: false,
            rtp_timestamp: 0,
            payload: vec![1],
        };
        assert!(encode_realtime_recv_unit(&longest).is_some());
    }

    /// Pins the exact bytes, because this body is shared with the
    /// applications' decoder: a silent layout change here desynchronises the
    /// two ends rather than failing a build. Note there is no peer and no
    /// codec on the wire — the pipe's session binding supplies the first and
    /// the flow's declared encoding the second.
    #[test]
    fn recv_unit_layout_is_pinned() {
        let body = encode_realtime_recv_unit(&RealtimeRecvUnit {
            flow_label: vec![b'a', b'b', 0xff],
            marker: true,
            rtp_timestamp: 0x0001_0203,
            payload: vec![9, 8],
        })
        .expect("a two-byte payload is within the frame ceiling");
        assert_eq!(
            body,
            vec![
                3, // label_len
                1, // marker
                0x03, 0x02, 0x01, 0x00, // rtp_timestamp LE
                2, 0, 0, 0, // payload len LE
                b'a', b'b', 0xff, // label, verbatim and not text
                9, 8, // payload
            ]
        );
    }

    /// Demonstrates the hazard the type split exists to remove: the two
    /// directions share a body width, so an inbound unit's bytes can parse as an
    /// outbound one, with the absolute timestamp landing silently in the
    /// duration field. That is exactly why `RealtimeSendUnit` and
    /// `RealtimeRecvUnit` are distinct types with distinct functions, so the
    /// compiler catches what the bytes cannot. If they are ever merged back into
    /// one type with a shared `timestamp`, this misreading becomes expressible
    /// in ordinary code.
    ///
    /// The reserved outbound byte narrows this without closing it. An inbound
    /// unit carrying a real marker has 1 where an outbound body must have 0, so
    /// that half is now caught — which is a side benefit of the reserved rule
    /// and not a reason to rely on it. Unmarked units are the ordinary case,
    /// and they still cross undetected, as the second half of this asserts.
    #[test]
    fn wire_bytes_alone_cannot_distinguish_the_two_directions() {
        // A marked inbound unit is now refused: its marker byte is 1 where the
        // outbound reserved byte must be 0.
        let marked = RealtimeRecvUnit {
            flow_label: LABEL.to_vec(),
            marker: true,
            rtp_timestamp: 90_000,
            payload: vec![1],
        };
        let marked_body = encode_realtime_recv_unit(&marked).expect("encodes");
        assert!(
            decode_realtime_send_unit(&marked_body).is_none(),
            "the reserved byte catches a marked inbound unit read as outbound"
        );

        // An unmarked one still crosses silently, which is the case the type
        // split has to cover, because no byte distinguishes it.
        let recv = RealtimeRecvUnit {
            flow_label: LABEL.to_vec(),
            marker: false,
            rtp_timestamp: 90_000,
            payload: vec![1],
        };
        let body = encode_realtime_recv_unit(&recv).expect("a one-byte payload encodes");
        let decoded = decode_realtime_send_unit(&body).expect("same width, so the bytes parse");
        assert_eq!(decoded.flow_label, recv.flow_label);
        assert_eq!(
            decoded.duration_us, recv.rtp_timestamp,
            "a 90 kHz timestamp read as a 90-millisecond duration, undetectably"
        );
    }

    /// An admission bounded only by the process owner's grant — no owner
    /// ceiling — which is what a daemon started with no `MYOWNMESH_IPC_*` value
    /// now has.
    fn granted_admission() -> FrameAdmission {
        FrameAdmission::new(crate::test_application_scope(), None)
    }

    /// The same grant with an owner policy layered over it.
    fn admission_capped_at(ceiling: usize) -> FrameAdmission {
        FrameAdmission::new(crate::test_application_scope(), Some(ceiling))
    }

    #[tokio::test]
    async fn json_reader_refuses_before_crossing_selected_ceiling() {
        let input = b"123456789\n";
        let mut reader = tokio::io::BufReader::new(&input[..]);
        let error = match read_bounded_json_line(&mut reader, &admission_capped_at(8)).await {
            Err(error) => error,
            Ok(_) => panic!("nine bytes exceed eight"),
        };
        // Alternate form, so the assertion reads the whole chain. Plain
        // `to_string` on an `anyhow::Error` answers only the outermost context,
        // which would pass this test for any refusal at all — including a
        // provider refusal, which is the other thing this reader can report and
        // is not what is under test here.
        assert!(
            format!("{error:#}").contains("owner-selected ceiling"),
            "the ceiling's own reason has to survive to the caller: {error:#}"
        );
    }

    #[tokio::test]
    async fn json_reader_accepts_exact_ceiling_without_hidden_slack() {
        let input = b"12345678\n";
        let mut reader = tokio::io::BufReader::new(&input[..]);
        let line = read_bounded_json_line(&mut reader, &admission_capped_at(9))
            .await
            .unwrap()
            .expect("eight bytes and a newline are exactly nine");
        assert_eq!(line.as_str(), "12345678");
    }

    /// No owner ceiling does not mean no bound.
    ///
    /// This is the property the whole optional-ceiling change turns on: a daemon
    /// started with neither `MYOWNMESH_IPC_*` value set still reads only what its
    /// grant funds, at the size actually read. The line is admitted here because
    /// the test grant covers it — what is being asserted is that absence took
    /// the funded path at all, not that nothing was checked.
    #[tokio::test]
    async fn an_absent_owner_ceiling_still_funds_every_byte_it_reads() {
        let input = b"12345678\n";
        let mut reader = tokio::io::BufReader::new(&input[..]);
        let line = read_bounded_json_line(&mut reader, &granted_admission())
            .await
            .unwrap()
            .expect("a complete line");
        assert_eq!(line.as_str(), "12345678");
    }

    /// The funding leaves the reader with the line, not before it.
    ///
    /// What this can check is that the line outlives the reader that produced it
    /// and still carries its own storage — so nothing about it depends on the
    /// connection buffer that is gone. What it cannot check is the release
    /// *instant*, because observing that needs either a provider of this test's
    /// own — which the binary's single-provider rule refuses, deliberately — or
    /// a readout of outstanding usage, which no scope exposes. The ownership is
    /// therefore enforced by [`AdmittedLine`]'s shape rather than asserted here,
    /// and this control exists to say so where someone changing that shape will
    /// read it.
    #[tokio::test]
    async fn an_admitted_line_carries_its_own_storage_past_its_reader() {
        let input = b"{\"op\":\"status\"}\n";
        let line = {
            let mut reader = tokio::io::BufReader::new(&input[..]);
            read_bounded_json_line(&mut reader, &granted_admission())
                .await
                .unwrap()
                .expect("a complete line")
        };
        assert_eq!(line.as_str(), "{\"op\":\"status\"}");
        let request: Request = serde_json::from_str(line.as_str()).expect("a status request");
        assert!(matches!(request, Request::Status));
    }

    /// A ceiling bounds the frame, not one read of it.
    ///
    /// Checked directly, because the incremental reader is the place this is
    /// easy to get wrong: charging each chunk against the ceiling separately
    /// would let a line arrive in pieces and pass a bound it exceeded.
    #[test]
    fn a_ceiling_bounds_the_whole_frame_and_not_one_read_of_it() {
        let admission = admission_capped_at(8);
        let first = admission.admit_growth(0, 5).expect("five of eight");
        let refusal = admission
            .admit_growth(5, 4)
            .expect_err("five already held plus four more is nine");
        assert!(refusal.to_string().contains("owner-selected ceiling"));
        assert!(
            admission.admit_growth(5, 3).is_ok(),
            "and the eighth byte is still admitted"
        );
        drop(first);
    }

    #[test]
    fn realtime_length_refusal_is_checked_before_body_allocation() {
        let admission = admission_capped_at(8);
        assert!(admission.admit(8).is_ok());
        assert!(admission.admit(9).is_err());
    }
}
