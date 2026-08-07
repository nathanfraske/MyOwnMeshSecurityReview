//! Structurally bounded H.264 compatibility assembly.

use super::*;

/// Reassembles H.264 access units from RTP, loss- and reorder-aware:
/// payloads collect per RTP timestamp keyed by *unwrapped sequence
/// number*, and a unit is emitted only when the chain from its first
/// packet to its marker packet is **contiguous** — so a packet lost
/// mid-unit can never splice the survivors into a corrupt unit that
/// reaches a decoder (the bug shape: at streaming bitrates a keyframe
/// spans hundreds of packets, and one hole per keyframe means a decode
/// error every time). A hole simply waits — the NACK interceptor's
/// retransmit fills it out of order and the unit still emits — and a
/// unit whose hole never fills is dropped whole when the next timestamp
/// arrives. Late retransmits of an abandoned unit can't clobber the
/// live one. Exact Annex-B planning and assembly run per unit in sequence
/// order, so FU-A fragment state never straddles a loss.
#[derive(Default)]
pub(super) struct H264AuAssembler {
    /// RTP timestamp of the unit being collected.
    timestamp: u32,
    /// Unwrapped seq → raw RTP payload, for the current timestamp only.
    pub(super) parts: std::collections::BTreeMap<i64, Bytes>,
    /// Unwrapped seq of the current unit's marker packet, once seen.
    marker_seq: Option<i64>,
    /// Unwrapped seq of the last *emitted* unit's marker — the next unit
    /// must start at exactly +1, which is what makes the contiguity
    /// check exact. `None` after an abandoned unit (the anchor is lost);
    /// the next unit then re-anchors on a payload that *starts* an AU.
    prev_end: Option<i64>,
    /// Sequence unwrapper state: (last raw seq, its unwrapped value).
    last_seq: Option<(u16, i64)>,
    flow: Option<RealtimeFlowPort>,
    assembly: Option<RealtimeAssemblyReservation>,
}

pub(super) struct GuardedVideoSample {
    pub(super) sample: VideoSample,
    pub(super) output: Option<RealtimeOutputReservation>,
}

/// More packets than any sane unit (a 40 Mbps keyframe is ~400): a unit
/// this size means the stream is wedged — drop it rather than balloon.
pub(super) const MAX_AU_PARTS: usize = super::LEGACY_H264_MAX_FRAGMENTS_PER_UNIT;
const ANNEXB_START_CODE: [u8; 4] = [0, 0, 0, 1];

fn output_length_overflow() -> Error {
    Error::Transport("video unit output length overflowed".into())
}

fn add_output_len(total: usize, bytes: usize) -> Result<usize> {
    total.checked_add(bytes).ok_or_else(output_length_overflow)
}

/// Validate the exact webrtc-rs H.264 compatibility shape and compute the
/// complete Annex-B output length without allocating output storage.
fn annexb_output_len(
    parts: &std::collections::BTreeMap<i64, Bytes>,
    start: i64,
    end: i64,
) -> Result<usize> {
    let mut output_len = 0usize;
    let mut fua_content_bytes = None;
    for (_, payload) in parts.range(start..=end) {
        if payload.len() <= 2 {
            return Err(Error::Transport("h264 depacketize: short packet".into()));
        }
        match payload[0] & 0x1f {
            1..=23 => {
                output_len = add_output_len(output_len, ANNEXB_START_CODE.len())?;
                output_len = add_output_len(output_len, payload.len())?;
            }
            24 => {
                let mut offset = 1usize;
                while offset < payload.len() {
                    let length_end = offset.checked_add(2).ok_or_else(output_length_overflow)?;
                    if length_end > payload.len() {
                        return Err(Error::Transport(
                            "h264 depacketize: truncated STAP-A length".into(),
                        ));
                    }
                    let nalu_len =
                        (usize::from(payload[offset]) << 8) | usize::from(payload[offset + 1]);
                    let nalu_end = length_end
                        .checked_add(nalu_len)
                        .ok_or_else(output_length_overflow)?;
                    if nalu_end > payload.len() {
                        return Err(Error::Transport(
                            "h264 depacketize: STAP-A unit exceeds packet".into(),
                        ));
                    }
                    output_len = add_output_len(output_len, ANNEXB_START_CODE.len())?;
                    output_len = add_output_len(output_len, nalu_len)?;
                    offset = nalu_end;
                }
            }
            28 => {
                let accumulated = fua_content_bytes
                    .unwrap_or(0usize)
                    .checked_add(payload.len() - 2)
                    .ok_or_else(output_length_overflow)?;
                if payload[1] & 0x40 != 0 {
                    output_len = add_output_len(output_len, ANNEXB_START_CODE.len())?;
                    output_len = add_output_len(output_len, 1)?;
                    output_len = add_output_len(output_len, accumulated)?;
                    fua_content_bytes = None;
                } else {
                    fua_content_bytes = Some(accumulated);
                }
            }
            nalu_type => {
                return Err(Error::Transport(format!(
                    "h264 depacketize: NAL type {nalu_type} is not handled"
                )));
            }
        }
    }
    Ok(output_len)
}

/// Build the exact output validated by `annexb_output_len`. FU-A contents are
/// copied only when their end fragment is encountered, matching webrtc-rs
/// ordering without retaining a second dependency-owned assembly buffer.
fn write_annexb_output(
    parts: &std::collections::BTreeMap<i64, Bytes>,
    start: i64,
    end: i64,
    output_len: usize,
) -> Result<Vec<u8>> {
    let mut output = Vec::with_capacity(output_len);
    let mut fua_start = None;
    for (&sequence, payload) in parts.range(start..=end) {
        match payload[0] & 0x1f {
            1..=23 => {
                output.extend_from_slice(&ANNEXB_START_CODE);
                output.extend_from_slice(payload);
            }
            24 => {
                let mut offset = 1usize;
                while offset < payload.len() {
                    let nalu_len =
                        (usize::from(payload[offset]) << 8) | usize::from(payload[offset + 1]);
                    offset += 2;
                    let nalu_end = offset + nalu_len;
                    output.extend_from_slice(&ANNEXB_START_CODE);
                    output.extend_from_slice(&payload[offset..nalu_end]);
                    offset = nalu_end;
                }
            }
            28 => {
                let chain_start = *fua_start.get_or_insert(sequence);
                if payload[1] & 0x40 != 0 {
                    output.extend_from_slice(&ANNEXB_START_CODE);
                    output.push((payload[0] & 0x60) | (payload[1] & 0x1f));
                    for (_, fragment) in parts.range(chain_start..=sequence) {
                        if fragment[0] & 0x1f == 28 {
                            output.extend_from_slice(&fragment[2..]);
                        }
                    }
                    fua_start = None;
                }
            }
            _ => {
                return Err(Error::Transport(
                    "validated H.264 payload changed during assembly".into(),
                ));
            }
        }
    }
    if output.len() != output_len {
        return Err(Error::Transport(
            "validated H.264 output length changed during assembly".into(),
        ));
    }
    Ok(output)
}

impl H264AuAssembler {
    pub(super) fn guarded(flow: RealtimeFlowPort) -> Self {
        Self {
            flow: Some(flow),
            ..Self::default()
        }
    }

    #[cfg(test)]
    pub(super) fn push(
        &mut self,
        pkt: &webrtc::rtp::packet::Packet,
    ) -> Result<Option<VideoSample>> {
        self.push_guarded(pkt)
            .map(|sample| sample.map(|sample| sample.sample))
    }

    pub(super) fn push_guarded(
        &mut self,
        pkt: &webrtc::rtp::packet::Packet,
    ) -> Result<Option<GuardedVideoSample>> {
        if pkt.payload.is_empty() {
            return Ok(None); // padding / probe
        }
        let seq = self.unwrap_seq(pkt.header.sequence_number);
        let ts = pkt.header.timestamp;
        if ts != self.timestamp {
            if self.parts.is_empty() || newer_rtp_ts(ts, self.timestamp) {
                // The next unit begins; an unfinished current one is
                // dropped whole (its hole is now hopeless) and the exact
                // start anchor is gone with it.
                if !self.parts.is_empty() {
                    self.prev_end = None;
                }
                self.clear_current();
                self.marker_seq = None;
                self.timestamp = ts;
            } else {
                // A late retransmit of a unit we already abandoned —
                // never let it wipe the one being collected.
                return Ok(None);
            }
        }
        if self.parts.len() >= MAX_AU_PARTS {
            self.clear_current();
            self.marker_seq = None;
            self.prev_end = None;
            return Err(Error::Transport("video unit overflowed reassembly".into()));
        }
        if self.parts.contains_key(&seq) {
            if pkt.header.marker {
                self.marker_seq = Some(seq);
            }
            return self.try_emit_guarded();
        }
        if let Some(flow) = self.flow.as_ref() {
            if self.assembly.is_none() {
                self.assembly = flow.begin_unit();
            }
            let Some(assembly) = self.assembly.as_mut() else {
                self.clear_current();
                return Ok(None);
            };
            if !assembly.retain_ordered_fragment(pkt.payload.len()) {
                self.clear_current();
                self.prev_end = None;
                return Err(Error::Transport(
                    "video unit exceeded its owner-selected byte envelope".into(),
                ));
            }
        }
        self.parts.insert(seq, pkt.payload.clone());
        if pkt.header.marker {
            self.marker_seq = Some(seq);
        }
        self.try_emit_guarded()
    }

    fn clear_current(&mut self) {
        self.parts.clear();
        self.assembly = None;
    }

    fn try_emit_guarded(&mut self) -> Result<Option<GuardedVideoSample>> {
        let Some(end) = self.marker_seq else {
            return Ok(None);
        };
        let start = match self.prev_end {
            Some(prev) => prev + 1,
            None => {
                // No anchor (stream start, or the previous unit was
                // abandoned): accept the lowest packet we hold only if it
                // plausibly *begins* a unit — a mid-unit join waits for
                // the next one instead of emitting a headless tail.
                let Some((&lo, first)) = self.parts.iter().next() else {
                    return Ok(None);
                };
                if !payload_starts_au(first) {
                    return Ok(None);
                }
                lo
            }
        };
        if end < start {
            return Ok(None); // a stale marker from before the anchor
        }
        let need = (end - start + 1) as usize;
        if self.parts.range(start..=end).count() < need {
            return Ok(None); // a hole — wait for the retransmit
        }
        let output_len = match annexb_output_len(&self.parts, start, end) {
            Ok(output_len) => output_len,
            Err(error) => {
                self.prev_end = Some(end);
                self.clear_current();
                self.marker_seq = None;
                return Err(error);
            }
        };
        // Acquire the exact complete-output claim before allocating any output
        // storage. The provider owns the logical bytes and one opaque residual
        // covers allocator-managed storage beyond that logical length.
        let output = match self.flow.as_ref() {
            Some(flow) if output_len != 0 => match flow.reserve_output(output_len) {
                Some(output) => Some(output),
                None => {
                    self.clear_current();
                    self.marker_seq = None;
                    self.prev_end = None;
                    return Ok(None);
                }
            },
            _ => None,
        };
        let data = write_annexb_output(&self.parts, start, end, output_len);
        // Either way this unit is consumed and the next one anchors
        // right after it.
        self.prev_end = Some(end);
        self.clear_current();
        self.marker_seq = None;
        let data = data?;
        if data.is_empty() {
            return Ok(None);
        }
        let data = Bytes::from(data);
        Ok(Some(GuardedVideoSample {
            sample: VideoSample {
                rtp_timestamp: self.timestamp,
                key: au_has_idr(&data),
                // The pump that owns the track stamps the real lane; the
                // assembler is lane-agnostic.
                lane: 0,
                data,
                _reservation: None,
            },
            output,
        }))
    }

    /// Map a raw 16-bit RTP sequence number onto an unbounded line, so
    /// ordering survives wraparound. The anchor only advances forward;
    /// older arrivals (retransmits) resolve to their original position.
    fn unwrap_seq(&mut self, raw: u16) -> i64 {
        match self.last_seq {
            None => {
                let unwrapped = i64::from(raw);
                self.last_seq = Some((raw, unwrapped));
                unwrapped
            }
            Some((last_raw, last_unwrapped)) => {
                let delta = i64::from(raw.wrapping_sub(last_raw) as i16);
                let unwrapped = last_unwrapped + delta;
                if delta > 0 {
                    self.last_seq = Some((raw, unwrapped));
                }
                unwrapped
            }
        }
    }
}

/// RTP timestamp `a` is newer than `b` (mod 2³², shortest distance).
fn newer_rtp_ts(a: u32, b: u32) -> bool {
    a != b && a.wrapping_sub(b) < u32::MAX / 2
}

/// Whether an RTP payload can be the *first* packet of an access unit:
/// a single NAL (types 1–23), a STAP-A aggregate (24), or a fragment
/// with its start bit set (FU-A/FU-B, 28/29). Mid-unit fragments fail.
pub(super) fn payload_starts_au(payload: &Bytes) -> bool {
    let Some(&b0) = payload.first() else {
        return false;
    };
    match b0 & 0x1F {
        1..=23 => true,
        24 => true,
        28 | 29 => payload.get(1).is_some_and(|b1| b1 & 0x80 != 0),
        _ => false,
    }
}

/// Whether an Annex-B access unit contains an IDR slice (NAL type 5)
/// — a safe decoder entry point. (SPS/PPS ride along with IDRs but
/// don't make a frame decodable by themselves.)
pub(super) fn au_has_idr(data: &[u8]) -> bool {
    annexb_nal_types(data).any(|t| t == 5)
}

/// Iterate the NAL unit types of an Annex-B stream (both 3- and
/// 4-byte start codes).
pub(super) fn annexb_nal_types(data: &[u8]) -> impl Iterator<Item = u8> + '_ {
    let mut i = 0usize;
    std::iter::from_fn(move || {
        while i + 3 <= data.len() {
            if data[i] == 0 && data[i + 1] == 0 {
                if data[i + 2] == 1 {
                    if i + 3 < data.len() {
                        let t = data[i + 3] & 0x1F;
                        i += 4;
                        return Some(t);
                    }
                    i += 3;
                    continue;
                }
                if i + 4 <= data.len() && data[i + 2] == 0 && data[i + 3] == 1 {
                    if i + 4 < data.len() {
                        let t = data[i + 4] & 0x1F;
                        i += 5;
                        return Some(t);
                    }
                    i += 4;
                    continue;
                }
            }
            i += 1;
        }
        None
    })
}

#[cfg(test)]
mod exact_output_tests {
    use super::*;
    use webrtc::rtp::packetizer::Depacketizer;

    #[test]
    fn planned_output_exactly_matches_single_stap_and_fu_assembly() {
        let mut parts = std::collections::BTreeMap::new();
        parts.insert(1, Bytes::from_static(&[0x65, 0x11, 0x12]));
        parts.insert(
            2,
            Bytes::from_static(&[0x78, 0x00, 0x02, 0x67, 0x21, 0x00, 0x03, 0x68, 0x31, 0x32]),
        );
        parts.insert(3, Bytes::from_static(&[0x7c, 0x85, 0x41]));
        parts.insert(4, Bytes::from_static(&[0x7c, 0x45, 0x42]));

        let planned = annexb_output_len(&parts, 1, 4).expect("the test unit is valid");
        let output =
            write_annexb_output(&parts, 1, 4, planned).expect("the validated unit is stable");
        let mut dependency = webrtc::rtp::codecs::h264::H264Packet::default();
        let mut dependency_output = Vec::new();
        for payload in parts.values() {
            dependency_output.extend_from_slice(
                &dependency
                    .depacketize(payload)
                    .expect("the dependency accepts the test unit"),
            );
        }
        assert_eq!(output.len(), planned);
        assert_eq!(output, dependency_output);
        assert_eq!(
            output,
            [
                &[0, 0, 0, 1, 0x65, 0x11, 0x12][..],
                &[0, 0, 0, 1, 0x67, 0x21][..],
                &[0, 0, 0, 1, 0x68, 0x31, 0x32][..],
                &[0, 0, 0, 1, 0x65, 0x41, 0x42][..],
            ]
            .concat()
        );
    }

    #[test]
    fn malformed_stap_is_rejected_before_output_allocation() {
        let mut parts = std::collections::BTreeMap::new();
        parts.insert(1, Bytes::from_static(&[0x78, 0x00, 0x04, 0x67]));
        assert!(annexb_output_len(&parts, 1, 1).is_err());
    }
}
