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

pub async fn run() -> Result<()> {
    run_with_compatibility(ServeCompatibility::V4).await
}

#[cfg(feature = "legacy-v1")]
#[allow(
    deprecated,
    reason = "this exact entry point is the explicit frozen LegacyV1 daemon option"
)]
pub async fn run_with_legacy_v1() -> Result<()> {
    run_with_compatibility(ServeCompatibility::LegacyV1(
        myownmesh_core::legacy_v1::LegacyV1Runtime::frozen(),
    ))
    .await
}

#[cfg(feature = "legacy-media")]
#[allow(
    deprecated,
    reason = "this exact entry point is the explicit legacy-media-only daemon option"
)]
pub async fn run_with_legacy_media() -> Result<()> {
    let media_profile = legacy_media_profile_from_lookup(|name| std::env::var(name).ok())?;
    run_with_compatibility(ServeCompatibility::LegacyMedia(media_profile)).await
}

#[cfg(all(feature = "legacy-v1", feature = "legacy-media"))]
#[allow(
    deprecated,
    reason = "this exact entry point is the explicit LegacyV1 media sidecar option"
)]
pub async fn run_with_legacy_v1_and_media() -> Result<()> {
    let media_profile = legacy_media_profile_from_lookup(|name| std::env::var(name).ok())?;
    run_with_compatibility(ServeCompatibility::LegacyV1WithMedia(
        myownmesh_core::legacy_v1::LegacyV1Runtime::frozen(),
        media_profile,
    ))
    .await
}

enum ServeCompatibility {
    V4,
    #[cfg(feature = "legacy-v1")]
    LegacyV1(myownmesh_core::legacy_v1::LegacyV1Runtime),
    #[cfg(feature = "legacy-media")]
    LegacyMedia(myownmesh_core::LegacyWebRtcMediaProfile),
    #[cfg(all(feature = "legacy-v1", feature = "legacy-media"))]
    LegacyV1WithMedia(
        myownmesh_core::legacy_v1::LegacyV1Runtime,
        myownmesh_core::LegacyWebRtcMediaProfile,
    ),
}

async fn run_with_compatibility(compatibility: ServeCompatibility) -> Result<()> {
    let cfg = myownmesh_core::MeshConfig::load().context("load config")?;
    let daemon = if cfg.services.node.enabled {
        let policy = connector_policy_from_lookup(|name| std::env::var(name).ok())?;
        match compatibility {
            ServeCompatibility::V4 => {
                myownmesh::embedded::start_connector_capable(cfg, policy).await?
            }
            #[cfg(feature = "legacy-v1")]
            ServeCompatibility::LegacyV1(runtime) => {
                start_legacy_v1_daemon(cfg, policy, runtime).await?
            }
            #[cfg(feature = "legacy-media")]
            ServeCompatibility::LegacyMedia(media_profile) => {
                start_legacy_media_sidecar(cfg, policy, media_profile).await?
            }
            #[cfg(all(feature = "legacy-v1", feature = "legacy-media"))]
            ServeCompatibility::LegacyV1WithMedia(runtime, media_profile) => {
                start_legacy_v1_media_sidecar(cfg, policy, runtime, media_profile).await?
            }
        }
    } else {
        myownmesh::embedded::start_infrastructure_only(cfg).await?
    };

    // Wait for SIGINT (Ctrl-C) or SIGTERM.
    wait_for_shutdown_signal().await;
    tracing::info!("shutdown requested");
    daemon.shutdown().await;
    Ok(())
}

#[cfg(feature = "legacy-media")]
#[allow(
    deprecated,
    reason = "this helper is the explicit legacy-media-only sidecar boundary"
)]
async fn start_legacy_media_sidecar(
    cfg: myownmesh_core::MeshConfig,
    policy: myownmesh_core::WebRtcConnectorCapablePolicy,
    media_profile: myownmesh_core::LegacyWebRtcMediaProfile,
) -> std::result::Result<myownmesh::embedded::EmbeddedDaemon, myownmesh::embedded::EmbeddedStartError>
{
    myownmesh::embedded::start_connector_capable_with_legacy_media(cfg, policy, media_profile).await
}

#[cfg(feature = "legacy-v1")]
#[allow(
    deprecated,
    reason = "this exact helper is the explicit frozen LegacyV1 daemon option"
)]
async fn start_legacy_v1_daemon(
    cfg: myownmesh_core::MeshConfig,
    policy: myownmesh_core::WebRtcConnectorCapablePolicy,
    runtime: myownmesh_core::legacy_v1::LegacyV1Runtime,
) -> std::result::Result<myownmesh::embedded::EmbeddedDaemon, myownmesh::embedded::EmbeddedStartError>
{
    myownmesh::embedded::start_connector_capable_with_legacy_v1(cfg, policy, runtime).await
}

#[cfg(all(feature = "legacy-v1", feature = "legacy-media"))]
#[allow(
    deprecated,
    reason = "this helper is the explicit LegacyV1 media sidecar boundary"
)]
async fn start_legacy_v1_media_sidecar(
    cfg: myownmesh_core::MeshConfig,
    policy: myownmesh_core::WebRtcConnectorCapablePolicy,
    runtime: myownmesh_core::legacy_v1::LegacyV1Runtime,
    media_profile: myownmesh_core::LegacyWebRtcMediaProfile,
) -> std::result::Result<myownmesh::embedded::EmbeddedDaemon, myownmesh::embedded::EmbeddedStartError>
{
    myownmesh::embedded::start_connector_capable_with_legacy_v1_and_media(
        cfg,
        policy,
        runtime,
        media_profile,
    )
    .await
}

#[cfg(feature = "legacy-media")]
fn legacy_media_profile_from_lookup(
    mut lookup: impl FnMut(&str) -> Option<String>,
) -> Result<myownmesh_core::LegacyWebRtcMediaProfile> {
    fn required(
        lookup: &mut impl FnMut(&str) -> Option<String>,
        name: &'static str,
    ) -> Result<String> {
        lookup(name).ok_or_else(|| {
            anyhow!("legacy-media sidecar requires owner-selected environment value {name}")
        })
    }
    let max_lanes = required(&mut lookup, "MYOWNMESH_LEGACY_MEDIA_MAX_LANES_PER_KIND")?
        .parse::<usize>()
        .ok()
        .and_then(NonZeroUsize::new)
        .ok_or_else(|| {
            anyhow!("MYOWNMESH_LEGACY_MEDIA_MAX_LANES_PER_KIND must be a nonzero integer")
        })?;
    let video_lanes = required(
        &mut lookup,
        "MYOWNMESH_LEGACY_MEDIA_PREPROVISIONED_VIDEO_LANES",
    )?
    .parse::<usize>()
    .map_err(|_| {
        anyhow!("MYOWNMESH_LEGACY_MEDIA_PREPROVISIONED_VIDEO_LANES must be a nonnegative integer")
    })?;
    let audio_lanes = required(
        &mut lookup,
        "MYOWNMESH_LEGACY_MEDIA_PREPROVISIONED_AUDIO_LANES",
    )?
    .parse::<usize>()
    .map_err(|_| {
        anyhow!("MYOWNMESH_LEGACY_MEDIA_PREPROVISIONED_AUDIO_LANES must be a nonnegative integer")
    })?;
    myownmesh_core::LegacyWebRtcMediaProfile::h264_opus(max_lanes, video_lanes, audio_lanes)
        .map_err(Into::into)
}

fn connector_policy_from_lookup(
    mut lookup: impl FnMut(&str) -> Option<String>,
) -> Result<myownmesh_core::WebRtcConnectorCapablePolicy> {
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
    let (callbacks, remote_candidates) = match local_ceiling_mode
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
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
                let max_pre_auth_packets = nonzero(
                    &mut lookup,
                    "MYOWNMESH_CONNECTOR_REALTIME_MAX_PRE_AUTH_PACKETS",
                )?;
                let max_pre_auth_content_bytes = nonzero(
                    &mut lookup,
                    "MYOWNMESH_CONNECTOR_REALTIME_MAX_PRE_AUTH_CONTENT_BYTES",
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
                        max_pre_auth_packets,
                        max_pre_auth_content_bytes,
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

    let webrtc = myownmesh_core::WebRtcConnectorProfile::new(callbacks, remote_candidates);
    Ok(myownmesh_core::WebRtcConnectorCapablePolicy::new(
        resources, webrtc,
    ))
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

    const ENABLED_REALTIME_KEYS: [&str; 12] = [
        "MYOWNMESH_CONNECTOR_REALTIME_WEIGHT",
        "MYOWNMESH_CONNECTOR_MAX_REALTIME_UNIT_BYTES",
        "MYOWNMESH_CONNECTOR_REALTIME_MAX_INBOUND_FLOWS",
        "MYOWNMESH_CONNECTOR_REALTIME_MAX_OUTBOUND_FLOWS",
        "MYOWNMESH_CONNECTOR_REALTIME_QUEUE_CAPACITY_PER_FLOW",
        "MYOWNMESH_CONNECTOR_REALTIME_MAX_INBOUND_FRAGMENT_BYTES",
        "MYOWNMESH_CONNECTOR_REALTIME_MAX_INBOUND_FRAGMENTS_PER_UNIT",
        "MYOWNMESH_CONNECTOR_REALTIME_MAX_IN_PROGRESS_UNITS_PER_FLOW",
        "MYOWNMESH_CONNECTOR_REALTIME_MAX_PRE_AUTH_PACKETS",
        "MYOWNMESH_CONNECTOR_REALTIME_MAX_PRE_AUTH_CONTENT_BYTES",
        "MYOWNMESH_CONNECTOR_REALTIME_MAX_INBOUND_ACCOUNTED_BYTES",
        "MYOWNMESH_CONNECTOR_REALTIME_MAX_OUTBOUND_ACCOUNTED_BYTES",
    ];

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
        }
        values
    }

    #[test]
    fn connector_capable_serve_requires_every_provider_dimension() {
        let mut values = fixture_values("disabled", false);
        values.remove("MYOWNMESH_RESOURCE_NATIVE_TRANSPORT_OBJECT");
        let error = connector_policy_from_lookup(|name| values.get(name).cloned())
            .expect_err("an omitted owner value is rejected");
        assert!(error
            .to_string()
            .contains("MYOWNMESH_RESOURCE_NATIVE_TRANSPORT_OBJECT"));
    }

    #[test]
    fn optional_local_ceiling_rejects_zero_instead_of_inventing_a_value() {
        let mut values = fixture_values("disabled", true);
        values.insert("MYOWNMESH_CONNECTOR_CONTROL_CAPACITY", "0".to_string());
        let error = connector_policy_from_lookup(|name| values.get(name).cloned())
            .expect_err("zero cannot become an optional local queue limit");
        assert!(error.to_string().contains("must be a nonzero integer"));
    }

    #[test]
    fn optional_local_ceiling_is_present_only_when_explicitly_selected() {
        let values = fixture_values("enabled", true);
        let policy = connector_policy_from_lookup(|name| values.get(name).cloned())
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
    }

    #[test]
    fn elastic_data_only_connector_requires_no_cardinality_values() {
        let values = fixture_values("disabled", false);
        let policy = connector_policy_from_lookup(|name| values.get(name).cloned())
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
        let policy = connector_policy_from_lookup(|name| values.get(name).cloned())
            .expect("elastic generic real-time construction needs no local count vector");
        assert!(matches!(
            policy.webrtc().callbacks().realtime(),
            myownmesh_core::RealtimeConnectorPolicy::Enabled(None)
        ));
    }

    #[cfg(feature = "legacy-media")]
    #[test]
    fn v4_arc03j_legacy_media_sidecar_rejects_an_incomplete_owner_vector() {
        let mut values = HashMap::from([
            ("MYOWNMESH_LEGACY_MEDIA_MAX_LANES_PER_KIND", "2".to_string()),
            (
                "MYOWNMESH_LEGACY_MEDIA_PREPROVISIONED_VIDEO_LANES",
                "1".to_string(),
            ),
        ]);
        let error = legacy_media_profile_from_lookup(|name| values.remove(name))
            .expect_err("an omitted owner field is rejected");
        assert!(error
            .to_string()
            .contains("MYOWNMESH_LEGACY_MEDIA_PREPROVISIONED_AUDIO_LANES"));
    }

    #[cfg(feature = "legacy-media")]
    #[test]
    fn v4_arc03j_legacy_media_sidecar_uses_only_the_complete_owner_vector() {
        let mut values = HashMap::from([
            ("MYOWNMESH_LEGACY_MEDIA_MAX_LANES_PER_KIND", "2".to_string()),
            (
                "MYOWNMESH_LEGACY_MEDIA_PREPROVISIONED_VIDEO_LANES",
                "1".to_string(),
            ),
            (
                "MYOWNMESH_LEGACY_MEDIA_PREPROVISIONED_AUDIO_LANES",
                "1".to_string(),
            ),
        ]);
        legacy_media_profile_from_lookup(|name| values.remove(name))
            .expect("the complete explicit test vector is accepted");
        assert!(values.is_empty());
    }
}
