//! Owner-selected connector policy values.

use super::*;
use crate::transport::webrtc::WebRtcConnectorProfile;

/// Owner-selected bounds for the connector's closed callback-class set.
///
/// Codec and media names belong to the WebRTC provider. The connector resource
/// owner accounts only for control, endpoint data, and codec-neutral real-time
/// flow callbacks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectorCallbackMailboxCapacities {
    control: NonZeroUsize,
    endpoint_data: NonZeroUsize,
}

impl ConnectorCallbackMailboxCapacities {
    pub const fn new(control: NonZeroUsize, endpoint_data: NonZeroUsize) -> Self {
        Self {
            control,
            endpoint_data,
        }
    }

    pub const fn control(self) -> NonZeroUsize {
        self.control
    }

    pub const fn endpoint_data(self) -> NonZeroUsize {
        self.endpoint_data
    }
}

/// Owner-selected scheduler weights for the closed callback-class set.
///
/// No default exists. A weight is a maximum consecutive service quantum when
/// the selected class remains ready. Empty classes are skipped, so a stalled
/// class cannot block the others.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectorCallbackServiceWeights {
    control: NonZeroUsize,
    endpoint_data: NonZeroUsize,
    realtime: Option<NonZeroUsize>,
}

impl ConnectorCallbackServiceWeights {
    pub const fn new(
        control: NonZeroUsize,
        endpoint_data: NonZeroUsize,
        realtime: NonZeroUsize,
    ) -> Self {
        Self {
            control,
            endpoint_data,
            realtime: Some(realtime),
        }
    }

    pub const fn data_only(control: NonZeroUsize, endpoint_data: NonZeroUsize) -> Self {
        Self {
            control,
            endpoint_data,
            realtime: None,
        }
    }

    pub const fn control(self) -> NonZeroUsize {
        self.control
    }

    pub const fn endpoint_data(self) -> NonZeroUsize {
        self.endpoint_data
    }

    pub const fn realtime(self) -> Option<NonZeroUsize> {
        self.realtime
    }
}

/// Owner-selected callback behavior for one connector.
///
/// Endpoint frames retain the protocol's independent frame limit. The
/// real-time unit and structural queue limits are separate operational inputs
/// because an encoded access unit is not an endpoint message frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectorCallbackPolicy {
    local_mailboxes: Option<ConnectorCallbackMailboxCapacities>,
    local_service_weights: Option<ConnectorCallbackServiceWeights>,
    realtime: RealtimeConnectorPolicy,
}

/// Owner-selected real-time behavior for one connector.
///
/// `Disabled` is a complete data-only policy. It carries no placeholder
/// media limits. `Enabled` contains every value needed by the generic
/// real-time owner and has no production default.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RealtimeConnectorPolicy {
    Disabled,
    Enabled(Option<EnabledRealtimeConnectorPolicy>),
}

/// Validated resource and queue policy for enabled real-time work.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EnabledRealtimeConnectorPolicy {
    max_unit_bytes: NonZeroUsize,
    flows: ConnectorRealtimeFlowPolicy,
}

/// Deterministic compatibility behavior when one bounded real-time flow
/// queue is full. This is connector-local backpressure, not application flow
/// policy. Arc 03 supports only dropping the newly offered complete unit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RealtimeQueueOverflowRule {
    DropNewest,
}

/// Owner-selected concurrency and queue bounds for real-time flows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectorRealtimeFlowCapacities {
    max_inbound_active_flows: NonZeroUsize,
    max_outbound_active_flows: NonZeroUsize,
    queue_capacity_per_flow: NonZeroUsize,
}

impl ConnectorRealtimeFlowCapacities {
    pub const fn new(
        max_inbound_active_flows: NonZeroUsize,
        max_outbound_active_flows: NonZeroUsize,
        queue_capacity_per_flow: NonZeroUsize,
    ) -> Self {
        Self {
            max_inbound_active_flows,
            max_outbound_active_flows,
            queue_capacity_per_flow,
        }
    }
}

/// Owner-selected structural bounds for one inbound real-time flow.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectorRealtimeInboundLimits {
    max_fragment_bytes: NonZeroUsize,
    max_fragments_per_unit: NonZeroUsize,
    max_in_progress_units: NonZeroUsize,
}

impl ConnectorRealtimeInboundLimits {
    pub const fn new(
        max_fragment_bytes: NonZeroUsize,
        max_fragments_per_unit: NonZeroUsize,
        max_in_progress_units: NonZeroUsize,
    ) -> Self {
        Self {
            max_fragment_bytes,
            max_fragments_per_unit,
            max_in_progress_units,
        }
    }
}

/// Optional owner-selected local ceiling for connector-local real-time flows.
///
/// The ceiling is codec-neutral. It can restrict independent flow queues and
/// bytes retained by real-time work on one connector. No production default
/// exists. Omitting this ceiling leaves provider-backed elastic real-time
/// admission available when the generic connector policy enables it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectorRealtimeFlowPolicy {
    max_inbound_active_flows: NonZeroUsize,
    max_outbound_active_flows: NonZeroUsize,
    queue_capacity_per_flow: NonZeroUsize,
    max_inbound_fragment_bytes: NonZeroUsize,
    max_inbound_fragments_per_unit: NonZeroUsize,
    max_in_progress_units_per_flow: NonZeroUsize,
    byte_budgets: ConnectorRealtimeByteBudgets,
    overflow_rule: RealtimeQueueOverflowRule,
}

/// Owner-selected byte partitions for one connector's real-time work.
///
/// The inbound and outbound ceilings are independent hard partitions. There is
/// no borrowing and therefore no third aggregate input for an owner to select.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectorRealtimeByteBudgets {
    max_inbound_bytes: NonZeroUsize,
    max_outbound_bytes: NonZeroUsize,
}

impl ConnectorRealtimeByteBudgets {
    pub const fn new(max_inbound_bytes: NonZeroUsize, max_outbound_bytes: NonZeroUsize) -> Self {
        Self {
            max_inbound_bytes,
            max_outbound_bytes,
        }
    }

    pub const fn max_inbound_bytes(self) -> NonZeroUsize {
        self.max_inbound_bytes
    }

    pub const fn max_outbound_bytes(self) -> NonZeroUsize {
        self.max_outbound_bytes
    }
}

impl ConnectorRealtimeFlowPolicy {
    pub const fn new(
        capacities: ConnectorRealtimeFlowCapacities,
        inbound: ConnectorRealtimeInboundLimits,
        byte_budgets: ConnectorRealtimeByteBudgets,
        overflow_rule: RealtimeQueueOverflowRule,
    ) -> Self {
        Self {
            max_inbound_active_flows: capacities.max_inbound_active_flows,
            max_outbound_active_flows: capacities.max_outbound_active_flows,
            queue_capacity_per_flow: capacities.queue_capacity_per_flow,
            max_inbound_fragment_bytes: inbound.max_fragment_bytes,
            max_inbound_fragments_per_unit: inbound.max_fragments_per_unit,
            max_in_progress_units_per_flow: inbound.max_in_progress_units,
            byte_budgets,
            overflow_rule,
        }
    }

    pub const fn max_inbound_active_flows(self) -> NonZeroUsize {
        self.max_inbound_active_flows
    }

    pub const fn max_outbound_active_flows(self) -> NonZeroUsize {
        self.max_outbound_active_flows
    }

    pub const fn queue_capacity_per_flow(self) -> NonZeroUsize {
        self.queue_capacity_per_flow
    }

    pub const fn max_inbound_fragment_bytes(self) -> NonZeroUsize {
        self.max_inbound_fragment_bytes
    }

    pub const fn max_inbound_fragments_per_unit(self) -> NonZeroUsize {
        self.max_inbound_fragments_per_unit
    }

    pub const fn max_in_progress_units_per_flow(self) -> NonZeroUsize {
        self.max_in_progress_units_per_flow
    }

    /// Bytes whose ownership is visible to this connector's real-time
    /// reservations. Allocator slack and memory retained internally by native
    /// WebRTC dependencies are intentionally outside this exact quantity.
    pub const fn byte_budgets(self) -> ConnectorRealtimeByteBudgets {
        self.byte_budgets
    }

    pub const fn overflow_rule(self) -> RealtimeQueueOverflowRule {
        self.overflow_rule
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ConnectorCallbackPolicyError {
    #[error("real-time inbound fragment limit {fragment_bytes} exceeds unit limit {unit_bytes}")]
    InboundFragmentExceedsUnit {
        fragment_bytes: usize,
        unit_bytes: usize,
    },
    #[error("real-time unit limit is too large to derive the guarded assembly bound")]
    AssemblyBoundOverflow,
    #[error(
        "accounted real-time byte limit {available_bytes} cannot hold one guarded assembly requiring {required_bytes} bytes"
    )]
    AccountedBytesCannotHoldOneAssembly {
        required_bytes: usize,
        available_bytes: usize,
    },
    #[error(
        "outbound real-time byte limit {available_bytes} cannot hold one complete unit requiring {required_bytes} bytes"
    )]
    OutboundBytesCannotHoldOneUnit {
        required_bytes: usize,
        available_bytes: usize,
    },
    #[error("data-only callback policy must not carry a real-time service weight")]
    DisabledRealtimeHasServiceWeight,
    #[error("enabled real-time callback policy requires an explicit real-time service weight")]
    EnabledRealtimeMissingServiceWeight,
}

impl ConnectorCallbackPolicy {
    pub fn new(
        mailboxes: ConnectorCallbackMailboxCapacities,
        service_weights: ConnectorCallbackServiceWeights,
        realtime: RealtimeConnectorPolicy,
    ) -> std::result::Result<Self, ConnectorCallbackPolicyError> {
        match (realtime, service_weights.realtime()) {
            (RealtimeConnectorPolicy::Disabled, Some(_)) => {
                return Err(ConnectorCallbackPolicyError::DisabledRealtimeHasServiceWeight)
            }
            (RealtimeConnectorPolicy::Enabled(_), None) => {
                return Err(ConnectorCallbackPolicyError::EnabledRealtimeMissingServiceWeight)
            }
            _ => {}
        }
        Ok(Self {
            local_mailboxes: Some(mailboxes),
            local_service_weights: Some(service_weights),
            realtime,
        })
    }

    /// Resource-backed data-only callbacks without a product item ceiling or
    /// owner-selected scheduler weights.
    pub const fn elastic_data_only() -> Self {
        Self {
            local_mailboxes: None,
            local_service_weights: None,
            realtime: RealtimeConnectorPolicy::Disabled,
        }
    }

    /// Resource-backed generic real-time callbacks with structurally fair,
    /// work-conserving service and no codec or flow meaning.
    pub const fn elastic_realtime() -> Self {
        Self {
            local_mailboxes: None,
            local_service_weights: None,
            realtime: RealtimeConnectorPolicy::Enabled(None),
        }
    }

    pub const fn local_mailboxes(self) -> Option<ConnectorCallbackMailboxCapacities> {
        self.local_mailboxes
    }

    pub const fn local_service_weights(self) -> Option<ConnectorCallbackServiceWeights> {
        self.local_service_weights
    }

    pub const fn realtime(self) -> RealtimeConnectorPolicy {
        self.realtime
    }
}

impl RealtimeConnectorPolicy {
    pub const fn enabled() -> Self {
        Self::Enabled(None)
    }

    pub fn enabled_with_local_ceiling(
        max_unit_bytes: NonZeroUsize,
        flows: ConnectorRealtimeFlowPolicy,
    ) -> std::result::Result<Self, ConnectorCallbackPolicyError> {
        if flows.max_inbound_fragment_bytes().get() > max_unit_bytes.get() {
            return Err(ConnectorCallbackPolicyError::InboundFragmentExceedsUnit {
                fragment_bytes: flows.max_inbound_fragment_bytes().get(),
                unit_bytes: max_unit_bytes.get(),
            });
        }
        let required_bytes = max_unit_bytes
            .get()
            .checked_mul(2)
            .ok_or(ConnectorCallbackPolicyError::AssemblyBoundOverflow)?;
        let byte_budgets = flows.byte_budgets();
        if byte_budgets.max_inbound_bytes().get() < required_bytes {
            return Err(
                ConnectorCallbackPolicyError::AccountedBytesCannotHoldOneAssembly {
                    required_bytes,
                    available_bytes: byte_budgets.max_inbound_bytes().get(),
                },
            );
        }
        if byte_budgets.max_outbound_bytes().get() < max_unit_bytes.get() {
            return Err(
                ConnectorCallbackPolicyError::OutboundBytesCannotHoldOneUnit {
                    required_bytes: max_unit_bytes.get(),
                    available_bytes: byte_budgets.max_outbound_bytes().get(),
                },
            );
        }
        Ok(Self::Enabled(Some(EnabledRealtimeConnectorPolicy {
            max_unit_bytes,
            flows,
        })))
    }
}

impl EnabledRealtimeConnectorPolicy {
    pub const fn max_unit_bytes(self) -> NonZeroUsize {
        self.max_unit_bytes
    }

    pub const fn flows(self) -> ConnectorRealtimeFlowPolicy {
        self.flows
    }
}

/// Point-in-time report from the connector resource owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectorResourceOwnerReport {
    pub active_candidates: usize,
    /// Exact candidate claims retained after a native cleanup failure. These
    /// slots remain consumed until process exit and cannot be reused.
    pub failed_cleanup_candidates: usize,
    /// Aggregate accounting is no longer exact, so all later admissions are
    /// refused. A known per-candidate cleanup failure does not set this flag.
    pub accounting_poisoned: bool,
    pub cleanup: ConnectorCleanupHealth,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ConnectorCleanupHealth {
    pub queued_jobs: usize,
    pub active_jobs: usize,
    pub completed_jobs: u64,
    pub failed_jobs: u64,
    pub executor_failed: bool,
}

/// Complete connector admission policy for one connector-capable [`crate::Mesh`].
///
/// The resource port refers to one owner-selected, process-local provider.
/// Cloning this policy does not create capacity. Every Mesh and connector
/// scope created through a clone still draws from the same provider grant.
#[derive(Clone, Debug)]
pub struct WebRtcConnectorCapablePolicy {
    resources: crate::resource::ResourceProviderPort,
    webrtc: WebRtcConnectorProfile,
}

impl WebRtcConnectorCapablePolicy {
    pub fn new(
        resources: crate::resource::ResourceProviderPort,
        webrtc: WebRtcConnectorProfile,
    ) -> Self {
        Self { resources, webrtc }
    }

    pub fn resources(&self) -> crate::resource::ResourceProviderPort {
        self.resources.clone()
    }

    /// Borrowed since the profile stopped being `Copy`: it now carries the
    /// application's real-time codec registrations, which are owned data.
    pub const fn webrtc(&self) -> &WebRtcConnectorProfile {
        &self.webrtc
    }
}
