//! `myownmesh serve`: run the daemon in the foreground.
//!
//! A thin wrapper over [`myownmesh::embedded`]: load the config, start the
//! daemon on this runtime, and hold it until SIGINT/SIGTERM asks for the
//! graceful teardown. Everything the daemon owns, including the mesh instance, the
//! network registry, hosted services, the updater tick, the control-socket
//! listener, lives in the library, so an embedder (an iOS app, which can't
//! spawn processes) runs the identical daemon in-process.

use std::num::NonZeroUsize;

use anyhow::{anyhow, Context, Result};

/// Run the daemon in the foreground.
///
/// There is one way to start, and that is the point. This used to select among
/// four compatibility deployments — plain, frozen pre-V4 routing, a fixed
/// H.264/Opus lane provider, and both — chosen by CLI flags. All three
/// compatibility forms and the enum that carried them are gone, so there is no
/// authority left for a flag to select and no branch left to take by mistake.
pub async fn run() -> Result<()> {
    let cfg = myownmesh_core::MeshConfig::load().context("load config")?;
    let daemon = if cfg.services.node.enabled {
        let ConnectorStartup {
            policy,
            realtime_flows,
        } = connector_policy_from_lookup(|name| std::env::var(name).ok())?;
        myownmesh::embedded::start_connector_capable(cfg, policy, realtime_flows).await?
    } else {
        myownmesh::embedded::start_infrastructure_only(cfg).await?
    };

    // Wait for SIGINT (Ctrl-C) or SIGTERM.
    wait_for_shutdown_signal().await;
    tracing::info!("shutdown requested");
    daemon.shutdown().await;
    Ok(())
}

// The types below are the *configuration* shape — what the application writes
// in `MYOWNMESH_REALTIME_PROFILE`, with `deny_unknown_fields` so a misspelled
// key is a startup error rather than a silently missing codec. They are parsed
// here and converted straight into `myownmesh_core`'s registration types; the
// daemon holds no realtime profile of its own and interprets none of the
// values it carries.
//
// The split is not duplication for its own sake. Core's constructor refuses the
// same malformations, but it sees a `Vec<RealtimeCodec>` and can only describe
// the shape of the problem; parsing here is what lets the error name the
// configuration that caused it. Both refusals are kept for that reason.

/// One RTCP feedback message to register alongside a codec.
///
/// The two SDP fields, carried as plain strings. The daemon does not interpret
/// either; it passes them through to registration.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealtimeRtcpFeedback {
    /// e.g. `nack`, `ccm`, `goog-remb`. Core calls this `mechanism`; the
    /// configuration key stays `kind` because that is the SDP spelling
    /// applications already write.
    pub kind: String,
    /// e.g. `pli`, `fir`, or empty.
    #[serde(default)]
    pub parameter: String,
}

/// The RTP media kind a codec registers under, as configured.
///
/// Supplied, never inferred from `mime`: which transceiver a codec occupies is
/// a connector decision, and deriving it by matching on `video/` would be the
/// same hardcoded branch the profile exists to remove.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RealtimeKind {
    Audio,
    Video,
}

/// How the connector turns a codec's RTP into units, as configured.
///
/// Chosen by the application per codec, never selected by core from a MIME
/// name — picking this by codec name is the same hardcoded branch the profile
/// exists to remove, one layer down. A codec whose framing is not stated cannot
/// be registered, because there is no correct default: choosing wrong produces
/// a stream that negotiates and then decodes to nothing.
///
/// Stated per registration tuple, but it is the *encoding family* that has to
/// agree — a flow names a family and negotiation picks which of that family's
/// tuples is used, so a family whose tuples disagreed would have no determinate
/// answer at open time. Both [`realtime_profile_from_lookup`] and core's
/// constructor refuse such a profile.
///
/// These are two structurally different treatments, not two interchangeable
/// adapters. `AnnexB` reassembles RTP into an access unit and then splits it at
/// start codes; `Whole` does no reassembly at all, because one payload is
/// already one unit. Opus needs `Whole` specifically: reassembly completes a
/// unit on the RTP marker bit, and Opus sets the marker only on the first packet
/// of a talkspurt, so reassembling it would emit that packet and drop the rest
/// of the speech — silent as an error, obvious as broken audio.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RealtimeFraming {
    /// Reassemble, then split at start codes. What current H.264 video needs.
    AnnexB,
    /// One payload is one unit, carried as-is with no reassembly state. What
    /// Opus needs, and the right answer for any codec whose units already
    /// arrive one per packet.
    Whole,
}

impl RealtimeKind {
    fn to_core(self) -> myownmesh_core::WebRtcRtpKind {
        use myownmesh_core::WebRtcRtpKind;
        match self {
            Self::Audio => WebRtcRtpKind::Audio,
            Self::Video => WebRtcRtpKind::Video,
        }
    }
}

impl RealtimeFraming {
    fn to_core(self) -> myownmesh_core::WebRtcRealtimeFraming {
        match self {
            Self::AnnexB => myownmesh_core::WebRtcRealtimeFraming::AnnexB,
            Self::Whole => myownmesh_core::WebRtcRealtimeFraming::Whole,
        }
    }
}

/// One complete codec registration, exactly as the application supplies it.
///
/// Everything the connector needs to register a capability and to frame units
/// for it is stated here, so core registers and frames what it is given rather
/// than deriving values from a MIME name. That is the point: a profile that
/// carried only `mime` would force core to know that `video/H264` implies
/// 90 kHz, which fmtp lines are acceptable, and Annex-B framing — which is the
/// hardcoded branch this replaces.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealtimeCodec {
    /// Which transceiver this codec occupies. See [`RealtimeKind`].
    pub kind: RealtimeKind,
    pub payload_type: u8,
    pub mime: String,
    pub clock_rate: u32,
    /// 0 for video; 2 for stereo Opus.
    #[serde(default)]
    pub channels: u16,
    /// The SDP `a=fmtp` parameter line, verbatim.
    #[serde(default)]
    pub fmtp: String,
    #[serde(default)]
    pub rtcp_feedback: Vec<RealtimeRtcpFeedback>,
    /// Required, with no default: see [`RealtimeFraming`].
    pub framing: RealtimeFraming,
}

/// The application-supplied realtime profile, read once at daemon start.
///
/// Registration happens before any `PeerConnection` exists, so this is read
/// and validated at startup rather than per flow. Every tuple listed here is
/// registered on the `MediaEngine`; a per-flow encoding then names an encoding
/// *family* among them, and SDP negotiation picks which tuple of that family is
/// actually used. Deployed H.264 is five payload/fmtp variants sharing one
/// mime, clock rate and channel count, so a flow that had to name one exact
/// tuple could not be opened against a peer that chose a different variant. A
/// flow never introduces a codec that was not registered here.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealtimeProfile {
    pub codecs: Vec<RealtimeCodec>,
    /// Combined concurrent audio+video capacity per peer, over the one shared
    /// flow-label space. A ceiling, not a live count. This is the value the
    /// daemon publishes as the required `realtime_flows` status field, and
    /// applications size their allocation pool off it — so it is deliberately
    /// stated once by the application rather than derived from a per-kind
    /// figure that would halve it silently.
    pub flow_capacity: u16,
}

/// Parse and validate the application-supplied realtime profile.
///
/// Refuses rather than defaulting: a daemon that guessed a codec set would
/// advertise capabilities the application cannot actually produce, and the
/// failure would surface as a negotiated-but-dead track rather than a startup
/// error.
fn realtime_profile_from_lookup(
    mut lookup: impl FnMut(&str) -> Option<String>,
) -> Result<RealtimeProfile> {
    const VAR: &str = "MYOWNMESH_REALTIME_PROFILE";
    let raw = lookup(VAR).ok_or_else(|| {
        anyhow!("realtime media requires the application-supplied profile in {VAR}")
    })?;
    let profile: RealtimeProfile = serde_json::from_str(&raw)
        .map_err(|error| anyhow!("{VAR} is not a valid realtime profile: {error}"))?;

    if profile.codecs.is_empty() {
        return Err(anyhow!("{VAR} registers no codecs"));
    }
    if profile.flow_capacity == 0 {
        return Err(anyhow!("{VAR} flow_capacity must be nonzero"));
    }
    let mut seen = std::collections::HashSet::new();
    let mut families: std::collections::HashMap<(String, u32, u16), RealtimeFraming> =
        std::collections::HashMap::new();
    for codec in &profile.codecs {
        if codec.mime.trim().is_empty() {
            return Err(anyhow!("{VAR} has a codec with an empty mime"));
        }
        if codec.clock_rate == 0 {
            return Err(anyhow!(
                "{VAR} codec {} has a zero clock_rate; it is what makes a flow's \
                 timestamp interpretable",
                codec.mime
            ));
        }
        // A duplicate payload type is the one malformation that would not fail
        // loudly at registration: the second tuple silently replaces the first,
        // and the loss only shows up as a codec that negotiates and then
        // carries nothing.
        if !seen.insert(codec.payload_type) {
            return Err(anyhow!(
                "{VAR} reuses payload_type {} across codecs",
                codec.payload_type
            ));
        }
        // Several tuples per family is expected and correct — deployed H.264 is
        // five payload/fmtp variants — but a flow names the family and
        // negotiation picks the variant, so the family is what has to fix the
        // framer. Disagreement here has no answer at open time.
        let family = (
            codec.mime.trim().to_ascii_lowercase(),
            codec.clock_rate,
            codec.channels,
        );
        match families.insert(family, codec.framing) {
            Some(prior) if prior != codec.framing => {
                return Err(anyhow!(
                    "{VAR} gives codec family {} two framings; a flow selects the \
                     family, not one payload type, so its treatment would be \
                     undetermined",
                    codec.mime
                ));
            }
            _ => {}
        }
    }
    Ok(profile)
}

/// Convert the parsed configuration into core's registration profile.
///
/// Core's constructor validates again and is the only way to make one. Its
/// refusals should be unreachable from here — everything it checks, the parse
/// above has already checked against the configuration text — so a failure is
/// reported as what it is: a disagreement between the two, not a user error.
fn realtime_profile_into_core(
    profile: RealtimeProfile,
) -> Result<myownmesh_core::WebRtcRealtimeProfile> {
    let codecs = profile
        .codecs
        .into_iter()
        .map(|codec| myownmesh_core::WebRtcRealtimeCodec {
            kind: codec.kind.to_core(),
            payload_type: codec.payload_type,
            mime: codec.mime,
            clock_rate: codec.clock_rate,
            channels: codec.channels,
            fmtp: codec.fmtp,
            framing: codec.framing.to_core(),
            rtcp_feedback: codec
                .rtcp_feedback
                .into_iter()
                .map(|fb| myownmesh_core::WebRtcRealtimeRtcpFeedback {
                    mechanism: fb.kind,
                    parameter: fb.parameter,
                })
                .collect(),
        })
        .collect();
    myownmesh_core::WebRtcRealtimeProfile::new(codecs, profile.flow_capacity).map_err(|error| {
        anyhow!(
            "realtime profile was accepted by the daemon and refused by the \
             connector ({error}); the two validations have drifted apart"
        )
    })
}

// There is no legacy media profile reader here any more.
//
// It parsed three owner-selected environment values — a per-kind lane ceiling
// and preprovisioned video and audio lane counts — into a fixed H.264/Opus
// provider. Every part of that is retired: lanes are not a per-kind pool, the
// codec set is supplied by the application through `MYOWNMESH_REALTIME_PROFILE`
// rather than fixed in the daemon, and a flow's capacity is one combined figure
// over a shared label space. Reading those variables now would configure
// nothing.

/// The connector policy plus the one number the control socket has to publish
/// alongside it.
///
/// They travel together because they have one origin: `realtime_flows` is the
/// `flow_capacity` of the profile that was actually registered on `policy`, so
/// a daemon cannot advertise a ceiling it did not register for. Reading the
/// capacity from configuration a second time somewhere else is exactly how the
/// two would drift.
struct ConnectorStartup {
    policy: myownmesh_core::WebRtcConnectorCapablePolicy,
    realtime_flows: u16,
}

fn connector_policy_from_lookup(
    mut lookup: impl FnMut(&str) -> Option<String>,
) -> Result<ConnectorStartup> {
    fn nonzero(
        lookup: &mut impl FnMut(&str) -> Option<String>,
        name: &'static str,
    ) -> Result<NonZeroUsize> {
        let raw = lookup(name).ok_or_else(|| {
            anyhow!("connector-capable serve requires owner-selected environment value {name}")
        })?;
        raw.parse::<usize>()
            .ok()
            .and_then(NonZeroUsize::new)
            .ok_or_else(|| anyhow!("{name} must be a nonzero integer"))
    }

    fn finite(lookup: &mut impl FnMut(&str) -> Option<String>, name: &'static str) -> Result<u64> {
        let raw = lookup(name).ok_or_else(|| {
            anyhow!("connector-capable serve requires owner-selected environment value {name}")
        })?;
        raw.parse::<u64>()
            .map_err(|_| anyhow!("{name} must be a finite nonnegative integer"))
    }

    let provider_grant = myownmesh_core::ResourceClaim::try_from_entries([
        (
            myownmesh_core::ResourceClass::AccountedMemoryBytes,
            finite(&mut lookup, "MYOWNMESH_RESOURCE_ACCOUNTED_MEMORY_BYTES")?,
        ),
        (
            myownmesh_core::ResourceClass::QueuedBytes,
            finite(&mut lookup, "MYOWNMESH_RESOURCE_QUEUED_BYTES")?,
        ),
        (
            myownmesh_core::ResourceClass::SocketOrHandle,
            finite(&mut lookup, "MYOWNMESH_RESOURCE_SOCKET_OR_HANDLE")?,
        ),
        (
            myownmesh_core::ResourceClass::NativeTransportObject,
            finite(&mut lookup, "MYOWNMESH_RESOURCE_NATIVE_TRANSPORT_OBJECT")?,
        ),
        (
            myownmesh_core::ResourceClass::WorkerOrTask,
            finite(&mut lookup, "MYOWNMESH_RESOURCE_WORKER_OR_TASK")?,
        ),
        (
            myownmesh_core::ResourceClass::CallbackOrScheduledWork,
            finite(&mut lookup, "MYOWNMESH_RESOURCE_CALLBACK_OR_SCHEDULED_WORK")?,
        ),
        (
            myownmesh_core::ResourceClass::StorageBytes,
            finite(&mut lookup, "MYOWNMESH_RESOURCE_STORAGE_BYTES")?,
        ),
        (
            myownmesh_core::ResourceClass::StorageObject,
            finite(&mut lookup, "MYOWNMESH_RESOURCE_STORAGE_OBJECT")?,
        ),
        (
            myownmesh_core::ResourceClass::RelayOrProviderAllocation,
            finite(
                &mut lookup,
                "MYOWNMESH_RESOURCE_RELAY_OR_PROVIDER_ALLOCATION",
            )?,
        ),
        (
            myownmesh_core::ResourceClass::ParsingOrCpuWork,
            finite(&mut lookup, "MYOWNMESH_RESOURCE_PARSING_OR_CPU_WORK")?,
        ),
        (
            myownmesh_core::ResourceClass::OpaqueDependencyResidual,
            finite(&mut lookup, "MYOWNMESH_RESOURCE_OPAQUE_DEPENDENCY_RESIDUAL")?,
        ),
    ])?;
    let resources = myownmesh_core::ResourceProviderPort::new(
        myownmesh_core::FiniteResourceProvider::new(provider_grant),
    )?;
    let local_ceiling_mode = lookup("MYOWNMESH_CONNECTOR_LOCAL_CEILING_POLICY").ok_or_else(|| {
        anyhow!(
            "connector-capable serve requires MYOWNMESH_CONNECTOR_LOCAL_CEILING_POLICY=none or enabled"
        )
    })?;
    let local_ceiling_mode = local_ceiling_mode.trim().to_ascii_lowercase();
    let realtime_mode = lookup("MYOWNMESH_CONNECTOR_REALTIME_POLICY").ok_or_else(|| {
        anyhow!(
            "connector-capable serve requires owner-selected environment value MYOWNMESH_CONNECTOR_REALTIME_POLICY"
        )
    })?;
    let realtime_enabled = match realtime_mode.trim().to_ascii_lowercase().as_str() {
        "disabled" => false,
        "enabled" => true,
        _ => {
            return Err(anyhow!(
                "MYOWNMESH_CONNECTOR_REALTIME_POLICY must be disabled or enabled"
            ))
        }
    };
    let (callbacks, remote_candidates) = match local_ceiling_mode.as_str() {
        "none" => (
            if realtime_enabled {
                myownmesh_core::ConnectorCallbackPolicy::elastic_realtime()
            } else {
                myownmesh_core::ConnectorCallbackPolicy::elastic_data_only()
            },
            myownmesh_core::PendingRemoteCandidatePolicy::elastic(),
        ),
        "enabled" => {
            let pending_candidate_items =
                nonzero(&mut lookup, "MYOWNMESH_CONNECTOR_PENDING_CANDIDATE_ITEMS")?;
            let pending_candidate_content_bytes = nonzero(
                &mut lookup,
                "MYOWNMESH_CONNECTOR_PENDING_CANDIDATE_CONTENT_BYTES",
            )?;
            let pending_candidate_duplicates = nonzero(
                &mut lookup,
                "MYOWNMESH_CONNECTOR_PENDING_CANDIDATE_DUPLICATES",
            )?;
            let pending_candidate_application_work = nonzero(
                &mut lookup,
                "MYOWNMESH_CONNECTOR_PENDING_CANDIDATE_APPLICATION_WORK",
            )?;
            let control_capacity = nonzero(&mut lookup, "MYOWNMESH_CONNECTOR_CONTROL_CAPACITY")?;
            let endpoint_capacity =
                nonzero(&mut lookup, "MYOWNMESH_CONNECTOR_ENDPOINT_DATA_CAPACITY")?;
            let control_weight = nonzero(&mut lookup, "MYOWNMESH_CONNECTOR_CONTROL_WEIGHT")?;
            let endpoint_weight = nonzero(&mut lookup, "MYOWNMESH_CONNECTOR_ENDPOINT_DATA_WEIGHT")?;
            let (service_weights, realtime) = if realtime_enabled {
                let realtime_weight = nonzero(&mut lookup, "MYOWNMESH_CONNECTOR_REALTIME_WEIGHT")?;
                let max_realtime_unit_bytes =
                    nonzero(&mut lookup, "MYOWNMESH_CONNECTOR_MAX_REALTIME_UNIT_BYTES")?;
                let max_inbound_flows = nonzero(
                    &mut lookup,
                    "MYOWNMESH_CONNECTOR_REALTIME_MAX_INBOUND_FLOWS",
                )?;
                let max_outbound_flows = nonzero(
                    &mut lookup,
                    "MYOWNMESH_CONNECTOR_REALTIME_MAX_OUTBOUND_FLOWS",
                )?;
                let queue_capacity_per_flow = nonzero(
                    &mut lookup,
                    "MYOWNMESH_CONNECTOR_REALTIME_QUEUE_CAPACITY_PER_FLOW",
                )?;
                let max_inbound_fragment_bytes = nonzero(
                    &mut lookup,
                    "MYOWNMESH_CONNECTOR_REALTIME_MAX_INBOUND_FRAGMENT_BYTES",
                )?;
                let max_inbound_fragments_per_unit = nonzero(
                    &mut lookup,
                    "MYOWNMESH_CONNECTOR_REALTIME_MAX_INBOUND_FRAGMENTS_PER_UNIT",
                )?;
                let max_in_progress_units_per_flow = nonzero(
                    &mut lookup,
                    "MYOWNMESH_CONNECTOR_REALTIME_MAX_IN_PROGRESS_UNITS_PER_FLOW",
                )?;
                let max_inbound_accounted_bytes = nonzero(
                    &mut lookup,
                    "MYOWNMESH_CONNECTOR_REALTIME_MAX_INBOUND_ACCOUNTED_BYTES",
                )?;
                let max_outbound_accounted_bytes = nonzero(
                    &mut lookup,
                    "MYOWNMESH_CONNECTOR_REALTIME_MAX_OUTBOUND_ACCOUNTED_BYTES",
                )?;
                let flows = myownmesh_core::ConnectorRealtimeFlowPolicy::new(
                    myownmesh_core::ConnectorRealtimeFlowCapacities::new(
                        max_inbound_flows,
                        max_outbound_flows,
                        queue_capacity_per_flow,
                    ),
                    myownmesh_core::ConnectorRealtimeInboundLimits::new(
                        max_inbound_fragment_bytes,
                        max_inbound_fragments_per_unit,
                        max_in_progress_units_per_flow,
                    ),
                    myownmesh_core::ConnectorRealtimeByteBudgets::new(
                        max_inbound_accounted_bytes,
                        max_outbound_accounted_bytes,
                    ),
                    myownmesh_core::RealtimeQueueOverflowRule::DropNewest,
                );
                (
                    myownmesh_core::ConnectorCallbackServiceWeights::new(
                        control_weight,
                        endpoint_weight,
                        realtime_weight,
                    ),
                    myownmesh_core::RealtimeConnectorPolicy::enabled_with_local_ceiling(
                        max_realtime_unit_bytes,
                        flows,
                    )?,
                )
            } else {
                (
                    myownmesh_core::ConnectorCallbackServiceWeights::data_only(
                        control_weight,
                        endpoint_weight,
                    ),
                    myownmesh_core::RealtimeConnectorPolicy::Disabled,
                )
            };
            (
                myownmesh_core::ConnectorCallbackPolicy::new(
                    myownmesh_core::ConnectorCallbackMailboxCapacities::new(
                        control_capacity,
                        endpoint_capacity,
                    ),
                    service_weights,
                    realtime,
                )?,
                myownmesh_core::PendingRemoteCandidatePolicy::new(
                    pending_candidate_items,
                    pending_candidate_content_bytes,
                    pending_candidate_duplicates,
                    pending_candidate_application_work,
                ),
            )
        }
        _ => {
            return Err(anyhow!(
                "MYOWNMESH_CONNECTOR_LOCAL_CEILING_POLICY must be none or enabled"
            ))
        }
    };

    // Codec registration happens here, before any `PeerConnection` exists, and
    // only where the connector can actually accept it. `with_realtime_profile`
    // refuses a policy whose realtime is `Disabled`, and refuses an elastic
    // realtime policy too — with no owner ceiling there is nothing to check the
    // advertised `flow_capacity` against. Requiring the profile in those
    // configurations would make them unstartable rather than honest, so the
    // rule is: register exactly where flows can be carried.
    let realtime_registration = if realtime_enabled && local_ceiling_mode == "enabled" {
        let parsed = realtime_profile_from_lookup(&mut lookup)?;
        let advertised = parsed.flow_capacity;
        Some((realtime_profile_into_core(parsed)?, advertised))
    } else {
        // Refused, not ignored. A profile supplied to a daemon that cannot
        // register it would otherwise be read as configured-and-working right
        // up until the first flow open, which is the expensive place to find
        // out no codec was ever registered.
        if lookup("MYOWNMESH_REALTIME_PROFILE").is_some() {
            return Err(anyhow!(
                "MYOWNMESH_REALTIME_PROFILE was supplied but this daemon cannot register \
                 it: realtime codec registration requires \
                 MYOWNMESH_CONNECTOR_REALTIME_POLICY=enabled together with \
                 MYOWNMESH_CONNECTOR_LOCAL_CEILING_POLICY=enabled, because the advertised \
                 flow_capacity is checked against the owner's flow ceiling"
            ));
        }
        None
    };

    let webrtc = myownmesh_core::WebRtcConnectorProfile::new(callbacks, remote_candidates);
    let (webrtc, realtime_flows) = match realtime_registration {
        Some((profile, advertised)) => (webrtc.with_realtime_profile(profile)?, advertised),
        // Honestly disabled: no codecs registered, so no flows can be carried,
        // and the status field says so rather than naming a capacity that would
        // invite a caller to allocate labels against nothing.
        None => (webrtc, 0),
    };
    Ok(ConnectorStartup {
        policy: myownmesh_core::WebRtcConnectorCapablePolicy::new(resources, webrtc),
        realtime_flows,
    })
}

async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigint = match signal(SignalKind::interrupt()) {
            Ok(s) => s,
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
        let mut sigterm = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(_) => {
                let _ = sigint.recv().await;
                return;
            }
        };
        tokio::select! {
            _ = sigint.recv() => {}
            _ = sigterm.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    const BASE_POLICY_KEYS: [&str; 13] = [
        "MYOWNMESH_RESOURCE_ACCOUNTED_MEMORY_BYTES",
        "MYOWNMESH_RESOURCE_QUEUED_BYTES",
        "MYOWNMESH_RESOURCE_SOCKET_OR_HANDLE",
        "MYOWNMESH_RESOURCE_NATIVE_TRANSPORT_OBJECT",
        "MYOWNMESH_RESOURCE_WORKER_OR_TASK",
        "MYOWNMESH_RESOURCE_CALLBACK_OR_SCHEDULED_WORK",
        "MYOWNMESH_RESOURCE_STORAGE_BYTES",
        "MYOWNMESH_RESOURCE_STORAGE_OBJECT",
        "MYOWNMESH_RESOURCE_RELAY_OR_PROVIDER_ALLOCATION",
        "MYOWNMESH_RESOURCE_PARSING_OR_CPU_WORK",
        "MYOWNMESH_RESOURCE_OPAQUE_DEPENDENCY_RESIDUAL",
        "MYOWNMESH_CONNECTOR_LOCAL_CEILING_POLICY",
        "MYOWNMESH_CONNECTOR_REALTIME_POLICY",
    ];

    const LOCAL_CEILING_KEYS: [&str; 8] = [
        "MYOWNMESH_CONNECTOR_PENDING_CANDIDATE_ITEMS",
        "MYOWNMESH_CONNECTOR_PENDING_CANDIDATE_CONTENT_BYTES",
        "MYOWNMESH_CONNECTOR_PENDING_CANDIDATE_DUPLICATES",
        "MYOWNMESH_CONNECTOR_PENDING_CANDIDATE_APPLICATION_WORK",
        "MYOWNMESH_CONNECTOR_CONTROL_CAPACITY",
        "MYOWNMESH_CONNECTOR_ENDPOINT_DATA_CAPACITY",
        "MYOWNMESH_CONNECTOR_CONTROL_WEIGHT",
        "MYOWNMESH_CONNECTOR_ENDPOINT_DATA_WEIGHT",
    ];

    const ENABLED_REALTIME_KEYS: [&str; 10] = [
        "MYOWNMESH_CONNECTOR_REALTIME_WEIGHT",
        "MYOWNMESH_CONNECTOR_MAX_REALTIME_UNIT_BYTES",
        "MYOWNMESH_CONNECTOR_REALTIME_MAX_INBOUND_FLOWS",
        "MYOWNMESH_CONNECTOR_REALTIME_MAX_OUTBOUND_FLOWS",
        "MYOWNMESH_CONNECTOR_REALTIME_QUEUE_CAPACITY_PER_FLOW",
        "MYOWNMESH_CONNECTOR_REALTIME_MAX_INBOUND_FRAGMENT_BYTES",
        "MYOWNMESH_CONNECTOR_REALTIME_MAX_INBOUND_FRAGMENTS_PER_UNIT",
        "MYOWNMESH_CONNECTOR_REALTIME_MAX_IN_PROGRESS_UNITS_PER_FLOW",
        "MYOWNMESH_CONNECTOR_REALTIME_MAX_INBOUND_ACCOUNTED_BYTES",
        "MYOWNMESH_CONNECTOR_REALTIME_MAX_OUTBOUND_ACCOUNTED_BYTES",
    ];

    /// The application-supplied profile half of the complete explicit vector.
    ///
    /// Two codecs with different framings, because that is the deployed shape
    /// and because a one-codec profile would not exercise the per-family
    /// framing check at all. `flow_capacity` is 2, which is exactly what the
    /// fixture's owner ceiling admits: `ENABLED_REALTIME_KEYS` sets both the
    /// inbound and outbound flow maxima to 1, and the connector measures a
    /// profile's combined audio-plus-video capacity against their sum. A
    /// larger number here is refused at registration, which is the behaviour
    /// [`realtime_profile_into_core`] exists to surface rather than a fixture
    /// detail to tune around.
    const REALTIME_PROFILE_FIXTURE: &str = r#"{
        "codecs": [
            {
                "kind": "video", "payload_type": 96, "mime": "video/H264",
                "clock_rate": 90000, "framing": "annex_b"
            },
            {
                "kind": "audio", "payload_type": 111, "mime": "audio/opus",
                "clock_rate": 48000, "channels": 2, "framing": "whole"
            }
        ],
        "flow_capacity": 2
    }"#;

    fn fixture_values(realtime: &str, local_ceiling: bool) -> HashMap<&'static str, String> {
        let mut values: HashMap<_, _> = BASE_POLICY_KEYS
            .into_iter()
            .map(|key| (key, "1".to_string()))
            .collect();
        values.insert(
            "MYOWNMESH_CONNECTOR_LOCAL_CEILING_POLICY",
            if local_ceiling { "enabled" } else { "none" }.to_string(),
        );
        values.insert("MYOWNMESH_CONNECTOR_REALTIME_POLICY", realtime.to_string());
        if local_ceiling {
            values.extend(
                LOCAL_CEILING_KEYS
                    .into_iter()
                    .map(|key| (key, "1".to_string())),
            );
        }
        // The profile is added under exactly the condition that makes it
        // required, which is the same condition `connector_policy_from_lookup`
        // uses to register it. Supplying it in any other configuration is a
        // startup error there, not a harmless extra, so a fixture that always
        // set it would make the other vectors invalid rather than complete.
        if local_ceiling && realtime == "enabled" {
            values.extend(
                ENABLED_REALTIME_KEYS
                    .into_iter()
                    .map(|key| (key, "1".to_string())),
            );
            values.insert(
                "MYOWNMESH_CONNECTOR_REALTIME_MAX_INBOUND_ACCOUNTED_BYTES",
                "2".to_string(),
            );
            values.insert(
                "MYOWNMESH_REALTIME_PROFILE",
                REALTIME_PROFILE_FIXTURE.to_string(),
            );
        }
        values
    }

    #[test]
    fn connector_capable_serve_requires_every_provider_dimension() {
        let mut values = fixture_values("disabled", false);
        values.remove("MYOWNMESH_RESOURCE_NATIVE_TRANSPORT_OBJECT");
        // See the note in `optional_local_ceiling_rejects_zero_...` for why this
        // is `.err().expect(..)` and not `.expect_err(..)`.
        let error = connector_policy_from_lookup(|name| values.get(name).cloned())
            .err()
            .expect("an omitted owner value is rejected");
        assert!(error
            .to_string()
            .contains("MYOWNMESH_RESOURCE_NATIVE_TRANSPORT_OBJECT"));
    }

    #[test]
    fn optional_local_ceiling_rejects_zero_instead_of_inventing_a_value() {
        let mut values = fixture_values("disabled", true);
        values.insert("MYOWNMESH_CONNECTOR_CONTROL_CAPACITY", "0".to_string());
        // `.err().expect(..)` rather than `.expect_err(..)`: the latter formats
        // the Ok value on failure and so would require `Debug` on
        // `ConnectorStartup`, which carries the live connector policy. Deriving
        // it to satisfy a test would put the whole policy — resource grants,
        // capacities, the registered codec set — one `{:?}` away from any log
        // line, to improve a message that only prints when this test fails.
        let error = connector_policy_from_lookup(|name| values.get(name).cloned())
            .err()
            .expect("zero cannot become an optional local queue limit");
        assert!(error.to_string().contains("must be a nonzero integer"));
    }

    #[test]
    fn optional_local_ceiling_is_present_only_when_explicitly_selected() {
        let values = fixture_values("enabled", true);
        let ConnectorStartup {
            policy,
            realtime_flows,
        } = connector_policy_from_lookup(|name| values.get(name).cloned())
            .expect("the complete explicit test vector is accepted");
        assert!(policy.webrtc().callbacks().local_mailboxes().is_some());
        assert!(policy
            .webrtc()
            .remote_candidates()
            .local_ceiling()
            .is_some());
        assert!(matches!(
            policy.webrtc().callbacks().realtime(),
            myownmesh_core::RealtimeConnectorPolicy::Enabled(Some(_))
        ));
        // The published ceiling comes from the profile that was registered, not
        // from a default. Asserting the exact number is what makes the profile
        // half of this vector load-bearing: a build that accepted the vector
        // and registered nothing would still satisfy the three assertions
        // above, and would advertise 0 here.
        assert_eq!(realtime_flows, 2);
    }

    /// The profile is required, and this vector's completeness is what carries
    /// the positive above.
    ///
    /// Without this control, the profile could quietly become optional and
    /// `optional_local_ceiling_is_present_only_when_explicitly_selected` would
    /// keep passing — the local-ceiling assertions there do not depend on it.
    /// So the same vector is run with exactly one thing removed, and the error
    /// must name the variable an operator has to set.
    #[test]
    fn the_complete_vector_is_refused_without_its_application_profile() {
        let mut values = fixture_values("enabled", true);
        assert!(
            values.remove("MYOWNMESH_REALTIME_PROFILE").is_some(),
            "the positive fixture must actually supply the profile, or this \
             control proves nothing"
        );
        // See the note in `optional_local_ceiling_rejects_zero_...` for why this
        // is `.err().expect(..)` and not `.expect_err(..)`.
        let error = connector_policy_from_lookup(|name| values.get(name).cloned())
            .err()
            .expect("a connector that can carry flows must be told which codecs");
        assert!(
            error.to_string().contains("MYOWNMESH_REALTIME_PROFILE"),
            "the error must name the variable to set: {error}"
        );
    }

    #[test]
    fn elastic_data_only_connector_requires_no_cardinality_values() {
        let values = fixture_values("disabled", false);
        let ConnectorStartup { policy, .. } =
            connector_policy_from_lookup(|name| values.get(name).cloned())
                .expect("elastic data-only construction needs no cardinality limits");
        assert!(policy.webrtc().callbacks().local_mailboxes().is_none());
        assert!(policy
            .webrtc()
            .remote_candidates()
            .local_ceiling()
            .is_none());
        assert!(matches!(
            policy.webrtc().callbacks().realtime(),
            myownmesh_core::RealtimeConnectorPolicy::Disabled
        ));
    }

    #[test]
    fn elastic_realtime_connector_requires_no_flow_or_queue_count() {
        let values = fixture_values("enabled", false);
        let ConnectorStartup { policy, .. } =
            connector_policy_from_lookup(|name| values.get(name).cloned())
                .expect("elastic generic real-time construction needs no local count vector");
        assert!(matches!(
            policy.webrtc().callbacks().realtime(),
            myownmesh_core::RealtimeConnectorPolicy::Enabled(None)
        ));
    }

    /// The retired lane variables configure nothing, and are not quietly
    /// tolerated either.
    ///
    /// A profile that still named per-kind lane counts would be a live
    /// configuration file describing a surface that no longer exists. Because
    /// the realtime profile is parsed with `deny_unknown_fields`, an operator
    /// who ports one across gets a startup error naming the offending key rather
    /// than a daemon that silently ignores half its configuration and then
    /// carries no media.
    #[test]
    fn a_profile_naming_retired_lane_configuration_is_refused() {
        let with_lanes = r#"{
            "codecs": [{
                "kind": "video", "payload_type": 96, "mime": "video/H264",
                "clock_rate": 90000, "framing": "annex_b"
            }],
            "flow_capacity": 4,
            "max_lanes_per_kind": 2
        }"#;
        let error = realtime_profile_from_lookup(|_| Some(with_lanes.to_string()))
            .err()
            .expect("a retired lane field is not a valid realtime profile");
        assert!(
            error.to_string().contains("max_lanes_per_kind"),
            "the error must name the offending key so it can be removed: {error}"
        );
    }
}
