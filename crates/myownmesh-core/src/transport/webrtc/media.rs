//! Legacy WebRTC media-lane compatibility over generic real-time owners.

#![allow(
    deprecated,
    dead_code,
    reason = "this module is the frozen implementation behind the deprecated legacy media facade"
)]

use super::*;
use webrtc::rtp_transceiver::rtp_codec::RTCRtpCodecCapability;

/// One H.264 access unit off a peer's video track. This compatibility-adapter
/// value contains Annex-B bytes ready for a decoder. `rtp_timestamp` ticks at
/// the 90 kHz video clock, `key` marks an IDR, and `lane` identifies the
/// adapter lane on which it arrived.
#[derive(Debug, Clone)]
pub struct VideoSample {
    pub rtp_timestamp: u32,
    pub key: bool,
    pub lane: u8,
    pub data: Bytes,
    pub(super) _reservation: Option<RealtimePayloadLease>,
}

/// One Opus frame from the temporary compatibility adapter. Each RTP packet
/// contains one frame, so no assembly is required. `rtp_timestamp` ticks at
/// the 48 kHz Opus clock and `lane` identifies the compatibility lane.
#[derive(Debug, Clone)]
pub struct AudioSample {
    pub rtp_timestamp: u32,
    pub lane: u8,
    pub data: Bytes,
    pub(super) _reservation: Option<RealtimePayloadLease>,
}

/// Crate-test constructors for the two compatibility media units.
///
/// These exist so a control outside this module can present a unit to the
/// engine's inbound promotion fence. Only the payload fields are accepted; the
/// resource lease stays private and is always `None`, so a control can state
/// what arrived on a track but can never mint the output reservation a real
/// pump holds. Nothing built here carries admission, ownership, peer identity,
/// or connector provenance — a unit is inert until the engine gate decides to
/// deliver it — so this seam cannot be used to construct a witness.
///
/// No re-export is added for them: both types are already nameable crate-wide,
/// so an inherent `pub(crate)` constructor is the narrowest exposure that
/// works.
#[cfg(test)]
impl VideoSample {
    pub(crate) fn for_test(rtp_timestamp: u32, key: bool, lane: u8, data: Bytes) -> Self {
        Self {
            rtp_timestamp,
            key,
            lane,
            data,
            _reservation: None,
        }
    }
}

/// The audio twin of the video constructor above, under the same terms.
#[cfg(test)]
impl AudioSample {
    pub(crate) fn for_test(rtp_timestamp: u32, lane: u8, data: Bytes) -> Self {
        Self {
            rtp_timestamp,
            lane,
            data,
            _reservation: None,
        }
    }
}

/// Historical per-kind lane ceiling for the temporary H.264 and Opus adapter.
/// The generic connector does not read this value or create media tracks.
pub const MEDIA_LANES: usize = LEGACY_MEDIA_MAX_LANES_PER_KIND;

/// Historical adapter behavior pre-provisions lane zero. This constant is
/// available only to tests and the raw transport lab. A production owner must
/// put the value in an explicit [`LegacyWebRtcMediaProfile`].
#[cfg(any(test, feature = "transport-lab"))]
pub(super) const PRE_PROVISIONED_LANES: usize = 1;

/// Resolve the historical raw-lab lane ceiling. Generic connector construction
/// does not call this function.
#[allow(
    deprecated,
    reason = "the frozen compatibility resolver uses its legacy ceiling"
)]
pub(super) fn resolve_media_lanes() -> usize {
    match std::env::var("MYOWNMESH_MEDIA_LANES") {
        Ok(v) => match v.trim().parse::<usize>() {
            Ok(n) => n.clamp(1, MEDIA_LANES),
            Err(_) => MEDIA_LANES,
        },
        Err(_) => MEDIA_LANES,
    }
}

/// Report the historical raw compatibility lane ceiling.
#[deprecated(
    since = "0.3.2",
    note = "temporary legacy H.264/Opus lane compatibility query"
)]
pub fn resolved_media_lanes() -> usize {
    resolve_media_lanes()
}

#[allow(
    deprecated,
    reason = "legacy track identifiers use the frozen lane ceiling"
)]
pub(super) fn lane_of_track_id(id: &str, kind: LaneKind, max_lanes: usize) -> Option<u8> {
    let expected = match kind {
        LaneKind::Video => "video",
        LaneKind::Audio => "audio",
    };
    let (prefix, raw_lane) = id.split_once('-')?;
    if prefix != expected || raw_lane.is_empty() || raw_lane.contains('-') {
        return None;
    }
    raw_lane
        .parse::<u8>()
        .ok()
        .filter(|lane| usize::from(*lane) < max_lanes && raw_lane == lane.to_string())
}

pub(super) fn legacy_track_identity(
    kind: RTPCodecType,
    mime: &str,
    id: &str,
    profile: LegacyWebRtcMediaProfile,
) -> Option<(LaneKind, bool, u8)> {
    let (lane_kind, expected_mime, is_video) = match kind {
        RTPCodecType::Video => (LaneKind::Video, MIME_TYPE_H264, true),
        RTPCodecType::Audio => (LaneKind::Audio, MIME_TYPE_OPUS, false),
        _ => return None,
    };
    if !mime.eq_ignore_ascii_case(expected_mime) {
        return None;
    }
    lane_of_track_id(id, lane_kind, profile.max_lanes_per_kind().get())
        .map(|lane| (lane_kind, is_video, lane))
}

pub(super) fn admit_legacy_track_shape(
    kind: RTPCodecType,
    mime: &str,
    id: &str,
    profile: LegacyWebRtcMediaProfile,
    admitted: &mut std::collections::HashSet<(bool, u8)>,
) -> std::result::Result<(bool, u8), &'static str> {
    let Some((_kind, is_video, lane)) = legacy_track_identity(kind, mime, id, profile) else {
        return Err("media track is outside the compatibility provider");
    };
    let key = (is_video, lane);
    if !admitted.insert(key) {
        return Err("duplicate compatibility media track");
    }
    Ok(key)
}

/// Which media pool a lane belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaneKind {
    Video,
    Audio,
}

/// One lifecycle-managed lane slot's state. `None` means never opened or
/// explicitly finalized.
#[derive(Clone)]
pub(super) enum LaneSlot {
    /// Negotiated (or negotiating) and writable.
    Open(Arc<TrackLocalStaticSample>),
    /// Suspended by an explicit event. Reopening resumes the same track. Only
    /// a separate explicit finalize event removes it.
    Suspended { track: Arc<TrackLocalStaticSample> },
    #[cfg(any(test, feature = "legacy-media", feature = "transport-lab"))]
    #[allow(
        dead_code,
        reason = "the failure state is exercised only by owners that finalize legacy media lanes"
    )]
    FailedRemove {
        track: Arc<TrackLocalStaticSample>,
        flow: RealtimeFlowPort,
    },
}

/// Build the local track for one lane. The id carries the lane index
/// (`video-3`) — that's how the far side routes inbound samples.
pub(super) fn make_media_track(kind: LaneKind, lane: u8) -> Arc<TrackLocalStaticSample> {
    let (mime, prefix) = match kind {
        LaneKind::Video => (MIME_TYPE_H264, "video"),
        LaneKind::Audio => (MIME_TYPE_OPUS, "audio"),
    };
    Arc::new(TrackLocalStaticSample::new(
        RTCRtpCodecCapability {
            mime_type: mime.to_owned(),
            ..Default::default()
        },
        format!("{prefix}-{lane}"),
        "myownmesh".to_string(),
    ))
}

/// Attach a local track to the connection and drain its sender's RTCP
/// so the interceptors (NACK responder, reports) actually run; the
/// drain task ends with the connection.
const LEGACY_RTCP_DRAIN_BUFFER_BYTES: usize = 1_500;

pub(super) fn legacy_rtcp_drain_claim() -> Result<crate::resource::ResourceClaim> {
    let retained_bytes = std::mem::size_of::<Vec<u8>>()
        .checked_add(LEGACY_RTCP_DRAIN_BUFFER_BYTES)
        .ok_or_else(|| Error::Transport("RTCP drain claim size overflowed".to_string()))?;
    let retained_bytes = u64::try_from(retained_bytes)
        .map_err(|_| Error::Transport("RTCP drain claim is not representable".to_string()))?;
    crate::resource::ResourceClaim::try_from_entries([
        (
            crate::resource::ResourceClass::AccountedMemoryBytes,
            retained_bytes,
        ),
        (crate::resource::ResourceClass::WorkerOrTask, 1),
        // The runtime task allocation and dependency-owned sender allocation
        // are not exposed as exact byte quantities.
        (crate::resource::ResourceClass::OpaqueDependencyResidual, 2),
    ])
    .map_err(|error| Error::Transport(format!("RTCP drain claim overflowed: {error}")))
}

pub(super) async fn attach_track(
    pc: &Arc<RTCPeerConnection>,
    track: &Arc<TrackLocalStaticSample>,
    resource_scope: Option<&PeerConnectionResourceScope>,
    work_resources: Option<&ConnectorWorkResourceScope>,
) -> Result<()> {
    let task_lease = match work_resources {
        Some(resources) => Some(
            resources
                .acquire(
                    crate::resource::ResourceAuthorityClass::Admitted,
                    legacy_rtcp_drain_claim()?,
                )
                .map_err(Error::from)?,
        ),
        #[cfg(any(test, feature = "transport-lab"))]
        None => None,
        #[cfg(not(any(test, feature = "transport-lab")))]
        None => return Err(Error::ConnectorPolicyRequired),
    };
    let sender = pc
        .add_track(Arc::clone(track) as Arc<dyn TrackLocal + Send + Sync>)
        .await
        .map_err(|e| Error::Transport(format!("add_track ({}): {e}", track.id())))?;
    let task_observation =
        observe_inexact_item_if(resource_scope, PreAuthResourceFamily::Task, 1, 1);
    tokio::spawn(async move {
        let _task_lease = task_lease;
        let _task_observation = task_observation;
        let mut buf = vec![0u8; LEGACY_RTCP_DRAIN_BUFFER_BYTES];
        while sender.read(&mut buf).await.is_ok() {}
    });
    Ok(())
}

/// Exact ownership retained by one temporary compatibility track pump.
pub(super) struct LegacyInboundTrackOwner {
    pub(super) task_observation: Option<ObservationLease>,
    pub(super) registration: LegacyRemoteTrackRegistration,
    pub(super) flow: RealtimeFlowPort,
    pub(super) transceiver: Arc<webrtc::rtp_transceiver::RTCRtpTransceiver>,
    pub(super) lane: u8,
}

pub(super) struct LegacyRemoteTrackRegistration {
    pub(super) remote_tracks: Arc<SyncMutex<std::collections::HashSet<(bool, u8)>>>,
    pub(super) track_key: (bool, u8),
}

impl Drop for LegacyRemoteTrackRegistration {
    fn drop(&mut self) {
        self.remote_tracks.lock().remove(&self.track_key);
    }
}

/// Drain one remote audio track: every RTP packet carries exactly one
/// Opus frame (RFC 7587 — no fragmentation, no aggregation), so each
/// non-empty payload surfaces directly as [`TransportEvent::AudioSample`].
/// Ends when the track does (peer connection closed).
pub(super) async fn pump_audio_track(
    track: Arc<TrackRemote>,
    tx: ConnectorEventSink,
    owner: LegacyInboundTrackOwner,
) {
    let LegacyInboundTrackOwner {
        task_observation: _task_observation,
        registration: _registration,
        flow,
        transceiver,
        lane,
    } = owner;
    loop {
        let native_read = match flow.lifetime.registry.begin_native_read_checked() {
            Ok(read) => read,
            Err(_) => {
                let _ = transceiver.stop().await;
                break;
            }
        };
        let pkt = match track.read_rtp().await {
            Ok((pkt, _)) => pkt,
            Err(_) => break, // track ended with its connection
        };
        if pkt.payload.is_empty() {
            continue; // padding / probe
        }
        let promoted = tx.realtime_delivery.load(Ordering::Acquire);
        let _pre_auth_work = match flow
            .lifetime
            .registry
            .admit_pre_auth_packet_checked(pkt.payload.len(), promoted)
        {
            Ok(work) => work,
            Err(_) => {
                let _ = transceiver.stop().await;
                break;
            }
        };
        // The exact content-byte work lease now owns the returned packet. The
        // opaque native-read lease no longer has to cover dependency output.
        drop(native_read);
        if !promoted {
            continue;
        }
        let Some(mut fragment) = flow.begin_unit() else {
            continue;
        };
        if !fragment.retain_fragment(pkt.payload.len()) {
            continue;
        }
        let Some(output) = flow.reserve_output(pkt.payload.len()) else {
            continue;
        };
        let sample = AudioSample {
            rtp_timestamp: pkt.header.timestamp,
            lane,
            data: pkt.payload.clone(),
            _reservation: None,
        };
        drop(fragment);
        if !tx.emit_realtime(&flow, TransportEvent::AudioSample(sample), output) {
            break;
        }
    }
}

/// Drain one remote video track: depacketize H.264 RTP into access
/// units and surface each as [`TransportEvent::VideoSample`]. Ends
/// when the track does (peer connection closed).
pub(super) async fn pump_video_track(
    track: Arc<TrackRemote>,
    tx: ConnectorEventSink,
    owner: LegacyInboundTrackOwner,
) {
    let LegacyInboundTrackOwner {
        task_observation: _task_observation,
        registration: _registration,
        flow,
        transceiver,
        lane,
    } = owner;
    let mut assembler = H264AuAssembler::guarded(flow.clone());
    loop {
        let native_read = match flow.lifetime.registry.begin_native_read_checked() {
            Ok(read) => read,
            Err(_) => {
                let _ = transceiver.stop().await;
                break;
            }
        };
        let pkt = match track.read_rtp().await {
            Ok((pkt, _)) => pkt,
            Err(_) => break, // track ended with its connection
        };
        let promoted = tx.realtime_delivery.load(Ordering::Acquire);
        let _pre_auth_work = match flow
            .lifetime
            .registry
            .admit_pre_auth_packet_checked(pkt.payload.len(), promoted)
        {
            Ok(work) => work,
            Err(_) => {
                let _ = transceiver.stop().await;
                break;
            }
        };
        // The exact content-byte work lease now owns the returned packet. The
        // opaque native-read lease no longer has to cover dependency output.
        drop(native_read);
        if !promoted {
            continue;
        }
        match assembler.push_guarded(&pkt) {
            Ok(Some(mut sample)) => {
                sample.sample.lane = lane;
                let Some(output) = sample.output.take() else {
                    break;
                };
                if !tx.emit_realtime(&flow, TransportEvent::VideoSample(sample.sample), output) {
                    break;
                }
            }
            Ok(None) => {}
            // A malformed packet (or one straddling a loss the NACK
            // retransmit didn't cover) costs the current unit only —
            // the stream re-syncs on the next timestamp, and the
            // sender's periodic IDR bounds any visible damage.
            Err(e) => trace!("video depacketize: {e}"),
        }
    }
}

impl PeerSession {
    pub(super) fn realtime_enabled(&self) -> bool {
        self.legacy_media_profile.is_some() && self.events_tx.realtime_flows.is_enabled()
    }

    /// Write one encoded H.264 access unit (Annex-B) onto `lane` of this
    /// peer's video pool. `duration` paces the RTP timestamp advance
    /// (1/fps). Before the lane's negotiation completes, webrtc-rs treats
    /// the write as a no-op (the track has no bound sender yet) — callers
    /// can simply start writing once the peer is up. A lane past the pool
    /// (or one a pre-pool peer never negotiated) errors rather than writing
    /// to the wrong stream.
    pub(super) async fn send_video(
        &self,
        lane: u8,
        data: Bytes,
        duration: std::time::Duration,
    ) -> Result<()> {
        let (track, flow) = self.ensure_owned_lane(LaneKind::Video, lane).await?;
        let _reservation = flow.reserve_output(data.len()).ok_or_else(|| {
            Error::Transport(
                "outbound real-time unit was refused by its owner-selected byte envelope"
                    .to_string(),
            )
        })?;
        track
            .write_sample(&Sample {
                data,
                duration,
                ..Default::default()
            })
            .await
            .map_err(|e| Error::Transport(format!("video write_sample (lane {lane}): {e}")))
    }

    /// Write one encoded Opus frame onto `lane` of this peer's audio pool.
    /// `duration` paces the RTP timestamp advance (the frame length —
    /// 20 ms for the canonical Opus frame). Same pre-negotiation no-op and
    /// out-of-range semantics as [`Self::send_video`].
    pub(super) async fn send_audio(
        &self,
        lane: u8,
        data: Bytes,
        duration: std::time::Duration,
    ) -> Result<()> {
        let (track, flow) = self.ensure_owned_lane(LaneKind::Audio, lane).await?;
        let _reservation = flow.reserve_output(data.len()).ok_or_else(|| {
            Error::Transport(
                "outbound real-time unit was refused by its owner-selected byte envelope"
                    .to_string(),
            )
        })?;
        track
            .write_sample(&Sample {
                data,
                duration,
                ..Default::default()
            })
            .await
            .map_err(|e| Error::Transport(format!("audio write_sample (lane {lane}): {e}")))
    }

    fn acquire_outbound_realtime_flow(
        &self,
        kind: LaneKind,
        lane: u8,
    ) -> Result<(RealtimeFlowPort, bool)> {
        let key = (kind == LaneKind::Video, lane);
        let mut flows = self.outbound_realtime_flows.lock();
        if let Some(flow) = flows.get(&key) {
            return Ok((flow.clone(), false));
        }
        let flow = self
            .events_tx
            .open_outbound_realtime_flow()
            .ok_or_else(|| {
                Error::Transport(
                    "outbound real-time flow was refused by its owner-selected flow envelope"
                        .to_string(),
                )
            })?;
        flows.insert(key, flow.clone());
        Ok((flow, true))
    }

    fn rollback_outbound_realtime_flow(&self, kind: LaneKind, lane: u8, flow: &RealtimeFlowPort) {
        let key = (kind == LaneKind::Video, lane);
        let mut flows = self.outbound_realtime_flows.lock();
        if flows
            .get(&key)
            .is_some_and(|owned| Arc::ptr_eq(&owned.lifetime, &flow.lifetime))
        {
            flows.remove(&key);
        }
    }

    fn lane_has_track(&self, kind: LaneKind, lane: u8) -> bool {
        self.pool(kind)
            .lock()
            .expect("lane pool")
            .get(lane as usize)
            .is_some_and(Option::is_some)
    }

    async fn ensure_owned_lane(
        &self,
        kind: LaneKind,
        lane: u8,
    ) -> Result<(Arc<TrackLocalStaticSample>, RealtimeFlowPort)> {
        let _operation = self.lane_operations.lock().await;
        #[cfg(any(test, feature = "legacy-media", feature = "transport-lab"))]
        if self
            .pool(kind)
            .lock()
            .expect("lane pool")
            .get(usize::from(lane))
            .is_some_and(|slot| matches!(slot, Some(LaneSlot::FailedRemove { .. })))
        {
            return Err(Error::Transport(format!(
                "legacy media lane {lane} is non-reusable after native track removal failed"
            )));
        }
        let (flow, newly_owned) = self.acquire_outbound_realtime_flow(kind, lane)?;
        match self.ensure_lane_after_owner(kind, lane).await {
            Ok(track) => Ok((track, flow)),
            Err(error) => {
                if newly_owned && !self.lane_has_track(kind, lane) {
                    self.rollback_outbound_realtime_flow(kind, lane, &flow);
                }
                Err(error)
            }
        }
    }

    fn pool(&self, kind: LaneKind) -> &std::sync::Mutex<Vec<Option<LaneSlot>>> {
        match kind {
            LaneKind::Video => &self.video_tracks,
            LaneKind::Audio => &self.audio_tracks,
        }
    }

    /// The lane's track, opening it on demand: the first write to a
    /// lane that doesn't exist yet creates the track, attaches it, and
    /// flags a renegotiation — writes are no-ops until the new m-line
    /// negotiates, exactly the semantics callers already tolerate at
    /// stream start. A suspended lane revives in place: the track
    /// never left the SDP, so the write flows immediately and nothing
    /// is renegotiated — this is the settings stop→start fast path. A
    /// lane at or past the device ceiling errors.
    async fn ensure_lane_after_owner(
        &self,
        kind: LaneKind,
        lane: u8,
    ) -> Result<Arc<TrackLocalStaticSample>> {
        if lane as usize >= self.max_lanes {
            let k = if kind == LaneKind::Video {
                "video"
            } else {
                "audio"
            };
            return Err(Error::Transport(format!("no {k} lane {lane}")));
        }
        {
            let mut pool = self.pool(kind).lock().expect("lane pool");
            match &pool[lane as usize] {
                Some(LaneSlot::Open(track)) => return Ok(track.clone()),
                Some(LaneSlot::Suspended { track }) => {
                    let track = track.clone();
                    pool[lane as usize] = Some(LaneSlot::Open(track.clone()));
                    return Ok(track);
                }
                #[cfg(any(test, feature = "legacy-media", feature = "transport-lab"))]
                Some(LaneSlot::FailedRemove { track, flow }) => {
                    let _ = (track, flow);
                    return Err(Error::Transport(format!(
                        "legacy media lane {lane} is non-reusable after native track removal failed"
                    )));
                }
                None => {}
            }
        }
        let track = make_media_track(kind, lane);
        #[cfg(test)]
        if self.fail_next_track_attach.swap(false, Ordering::AcqRel) {
            return Err(Error::Transport(
                "injected native track attachment failure".to_string(),
            ));
        }
        attach_track(
            &self.pc,
            &track,
            self.resource_scope.as_ref(),
            self.work_resource_scope.as_ref(),
        )
        .await?;
        // First writer wins if two racers opened the same lane; the
        // loser's track was attached too, but the slot's track is the
        // one everyone writes — the duplicate is harmless and gone on
        // the next renegotiation sweep. (In practice lane opens are
        // serialized by the engine driver.)
        let stored = {
            let mut pool = self.pool(kind).lock().expect("lane pool");
            match &pool[lane as usize] {
                None => {
                    pool[lane as usize] = Some(LaneSlot::Open(track.clone()));
                    track
                }
                Some(LaneSlot::Open(winner)) => winner.clone(),
                Some(LaneSlot::Suspended { track: winner }) => {
                    let winner = winner.clone();
                    pool[lane as usize] = Some(LaneSlot::Open(winner.clone()));
                    winner
                }
                #[cfg(any(test, feature = "legacy-media", feature = "transport-lab"))]
                Some(LaneSlot::FailedRemove { .. }) => {
                    return Err(Error::Transport(format!(
                        "legacy media lane {lane} is non-reusable after native track removal failed"
                    )))
                }
            }
        };
        if !self
            .events_tx
            .emit(TransportEvent::RenegotiationNeeded)
            .await
        {
            return Err(Error::Transport(
                "connector event queue overloaded during renegotiation".to_string(),
            ));
        }
        Ok(stored)
    }

    /// Open a lane of `kind`, returning its id. The explicit twin of
    /// the write-time auto-open, for callers that want to reserve a
    /// lane before producing media. Prefers resuming a suspended lane
    /// (its track is still negotiated — the open costs zero SDP work)
    /// over claiming a fresh slot (one in-place renegotiation); errors
    /// only when every slot is genuinely open.
    pub(super) async fn open_media_lane(&self, kind: LaneKind) -> Result<u8> {
        let _operation = self.lane_operations.lock().await;
        let target = {
            let pool = self.pool(kind).lock().expect("lane pool");
            pool.iter()
                .position(|slot| matches!(slot, Some(LaneSlot::Suspended { .. })))
                .or_else(|| pool.iter().position(|slot| slot.is_none()))
        };
        let Some(lane) = target else {
            return Err(Error::Transport(format!(
                "all {} media lanes are open (device ceiling)",
                self.max_lanes
            )));
        };
        let lane = lane as u8;
        let (flow, newly_owned) = self.acquire_outbound_realtime_flow(kind, lane)?;
        if let Err(error) = self.ensure_lane_after_owner(kind, lane).await {
            if newly_owned && !self.lane_has_track(kind, lane) {
                self.rollback_outbound_realtime_flow(kind, lane, &flow);
            }
            return Err(error);
        }
        Ok(lane)
    }

    /// Suspend an open legacy lane without removing its native track. Reopening
    /// revives that exact track. Finalization is a separate explicit event.
    /// Closing a missing or already-suspended lane is idempotent.
    pub(super) async fn close_media_lane(&self, kind: LaneKind, lane: u8) -> Result<()> {
        let _operation = self.lane_operations.lock().await;
        if lane as usize >= self.max_lanes {
            return Ok(());
        }
        let mut pool = self.pool(kind).lock().expect("lane pool");
        if let Some(LaneSlot::Open(track)) = &pool[lane as usize] {
            pool[lane as usize] = Some(LaneSlot::Suspended {
                track: track.clone(),
            });
        }
        Ok(())
    }

    /// Finalize every explicitly suspended transient lane. The exact track and
    /// flow owner move together into this operation. A failed native removal
    /// installs a non-reusable failure state that retains both values.
    #[cfg(any(test, feature = "legacy-media", feature = "transport-lab"))]
    #[allow(
        dead_code,
        reason = "this explicit event is used only by the deprecated legacy-media deployment owner"
    )]
    pub(super) async fn finalize_suspended_lanes(&self) -> usize {
        let Some(profile) = self.legacy_media_profile else {
            return 0;
        };
        let _operation = self.lane_operations.lock().await;
        let mut candidates = Vec::new();
        for kind in [LaneKind::Video, LaneKind::Audio] {
            let pinned = match kind {
                LaneKind::Video => profile.preprovisioned_video_lanes(),
                LaneKind::Audio => profile.preprovisioned_audio_lanes(),
            };
            let pool = self.pool(kind).lock().expect("lane pool");
            for (idx, slot) in pool.iter().enumerate() {
                // The pre-provisioned lane is pinned: it suspends silently but
                // never loses its track, so a re-open always hits the
                // zero-SDP free-revive path instead of a recycled-m-line
                // renegotiation (which doesn't reliably re-`ontrack` on the
                // viewer — the CEC console re-open hang). Only transient
                // lanes may be finalized only by an explicit owner event.
                if idx < pinned {
                    continue;
                }
                if matches!(slot, Some(LaneSlot::Suspended { .. })) {
                    candidates.push((kind, idx as u8));
                }
            }
        }
        if candidates.is_empty() {
            return 0;
        }
        let owned_candidates = {
            let flows = self.outbound_realtime_flows.lock();
            candidates
                .into_iter()
                .filter_map(|(kind, lane)| {
                    flows
                        .get(&(kind == LaneKind::Video, lane))
                        .cloned()
                        .map(|flow| (kind, lane, flow))
                })
                .collect::<Vec<_>>()
        };
        let mut victims = Vec::new();
        for (kind, lane, flow) in owned_candidates {
            let mut pool = self.pool(kind).lock().expect("lane pool");
            if let Some(LaneSlot::Suspended { track }) = pool[usize::from(lane)].take() {
                victims.push((kind, lane, track, flow));
            }
        }
        let senders = self.pc.get_senders().await;
        let mut finalized = 0usize;
        for (kind, lane, track, flow) in victims {
            let mut matching_sender = None;
            for sender in &senders {
                if sender
                    .track()
                    .await
                    .is_some_and(|sender_track| sender_track.id() == track.id())
                {
                    matching_sender = Some(sender);
                    break;
                }
            }
            #[cfg(test)]
            let injected_failure = self.fail_next_track_remove.swap(false, Ordering::AcqRel);
            #[cfg(not(test))]
            let injected_failure = false;
            let failed = if injected_failure {
                true
            } else if let Some(sender) = matching_sender {
                if let Err(error) = self.pc.remove_track(sender).await {
                    warn!("finalize: remove_track failed: {error}");
                    true
                } else {
                    false
                }
            } else {
                false
            };
            let key = (kind == LaneKind::Video, lane);
            self.outbound_realtime_flows.lock().remove(&key);
            if failed {
                self.pool(kind).lock().expect("lane pool")[usize::from(lane)] =
                    Some(LaneSlot::FailedRemove { track, flow });
            } else {
                finalized = finalized.saturating_add(1);
            }
        }
        finalized
    }

    /// How many lanes of `kind` are currently occupied. Suspended and failed
    /// lanes count because they retain their native track.
    #[cfg(test)]
    pub(super) fn open_lane_count(&self, kind: LaneKind) -> usize {
        self.pool(kind)
            .lock()
            .expect("lane pool")
            .iter()
            .filter(|slot| slot.is_some())
            .count()
    }
}
