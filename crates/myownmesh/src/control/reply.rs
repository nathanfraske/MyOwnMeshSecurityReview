//! One sealed reply envelope, and the exact line admission that funds it.
//!
//! Split out of `framing.rs`, which is documented as knowing nothing about
//! request meaning and had come to name roster snapshots, governance
//! snapshots, updater outcomes, RPC results and MFA enrollments. The funding
//! boundary those types enforce was never the problem; the file they lived in
//! was. Bytes and admission stayed there, the vocabulary of what a reply *is*
//! came here.
//!
//! What this module may do: describe a reply, measure it before it exists, and
//! keep the owner that funds it alive until the bytes are written. What it may
//! not do: perform an operation. Every value here is constructed by a domain
//! module that knows what it is answering — see `dispatch/network.rs` for the
//! shape — and this module only says what such an answer costs and how it
//! encodes.
//!
//! `pub(super)` here means `pub(in crate::control)`, exactly as it did in
//! `framing.rs`, so the domain modules already reach these names and nothing
//! widened on the way across.

use anyhow::Result;

use super::framing::{
    AdmittedLineOut, CountingSink, DecodeRefusal, EncodeRefusal, FrameAdmission, FrameRefusal,
    PreparedLineCapacity,
};

/// Everything this control socket writes, as a closed set.
///
/// Closed, and not `impl Serialize`, and that is what makes the admission below
/// enforceable rather than merely intended. The measurement is taken by running
/// the encoder into a sink that counts, so the promise the seam depends on is
/// that *counting allocates nothing* — and a generic `Serialize` bound cannot
/// promise that. A caller's impl is free to build a `String`, collect a `Vec` or
/// do arbitrary work on its way past, and the refusal path would then have
/// allocated before it refused.
///
/// Every arm here is one this module can check. [`Response`] and [`ServerOut`]
/// are derived impls over scalars, `String`s and `serde_json::Value`s; `Value`'s
/// own impl walks the tree it already holds; [`ConnTrace`] is a derived impl
/// over scalars, `String`s and `Vec<String>`. None of them allocates to
/// serialize. Adding an arm is a deliberate act with that sentence attached to
/// it.
///
/// [`Response`]: super::wire::Response
/// [`ServerOut`]: crate::ipc::ServerOut
/// [`ConnTrace`]: myownmesh_core::ConnTrace
pub(super) enum ControlOut<'a> {
    /// One request's answer as the untyped envelope, which production no longer
    /// writes: every live arm now answers through [`Self::Prepared`], where the
    /// reply's width is admitted before any owned field exists. The variant
    /// stays for the controls that assert this end still encodes as the wire
    /// contract `Response` describes, and is gated so a release build does not
    /// carry a shape nothing constructs.
    #[cfg(test)]
    Response(&'a super::wire::Response),
    /// One pushed frame on an events subscription.
    Frame(&'a crate::ipc::ServerOut),
    /// One connection-state record on a trace subscription.
    Trace(&'a myownmesh_core::ConnTrace),
    /// The trace stream's lag marker, which is a bare JSON object rather than
    /// one of the protocol's own shapes.
    Marker(&'a serde_json::Value),
    /// A response whose typed representation was admitted before any owned
    /// field was constructed.
    Prepared(&'a PreparedReply),
}

impl serde::Serialize for ControlOut<'_> {
    /// Delegates, and adds nothing. The wire shape of each arm is the arm's own
    /// and this wrapper must not change it: a client parses a `Response`, not a
    /// `ControlOut`.
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            #[cfg(test)]
            Self::Response(value) => value.serialize(serializer),
            Self::Frame(value) => value.serialize(serializer),
            Self::Trace(value) => value.serialize(serializer),
            Self::Marker(value) => value.serialize(serializer),
            Self::Prepared(value) => value.serialize(serializer),
        }
    }
}

/// The allocation-free and exactly funded response shapes migrated to the
/// prepared boundary. New variants must remain closed and must serialize
/// without constructing a `Value`, `String`, or collection.
pub(super) enum PreparedReply {
    StaticError(&'static str),
    Error(PreparedText),
    Bool { key: &'static str, value: bool },
    Usize { key: &'static str, value: usize },
    TraceSubscribed { network: PreparedText },
    EventsSubscribed(myownmesh_core::FundedArc<crate::ipc::ClientHandle>),
    ServicesStatus(crate::services::FundedServicesStatus),
    Config(myownmesh_core::config::FundedMeshConfig),
    NetworkId(myownmesh_core::identity::FundedNetworkId),
    Status(crate::registry::FundedStatus),
    Networks(crate::registry::FundedNetworksList),
    Variable(FundedVariableReply),
}

/// One owned response string and the funding that outlives its buffer.
pub(super) struct PreparedText {
    value: String,
    _retention: myownmesh_core::ResourceLease,
}

#[derive(Debug, thiserror::Error)]
pub(super) enum PreparedTextRefusal {
    #[error(transparent)]
    Admission(#[from] FrameRefusal),
    #[error("prepared response text could not be formatted")]
    Format,
    #[error("prepared response text changed length between measurement and construction")]
    Unstable,
}

impl PreparedText {
    pub(super) fn copying(
        value: &str,
        admission: &FrameAdmission,
    ) -> std::result::Result<Self, PreparedTextRefusal> {
        Self::building(value.len(), admission, || value.to_owned())
    }

    fn surrounded(
        prefix: &'static str,
        value: &str,
        suffix: &'static str,
        admission: &FrameAdmission,
    ) -> std::result::Result<Self, PreparedTextRefusal> {
        let bytes = prefix
            .len()
            .checked_add(value.len())
            .and_then(|bytes| bytes.checked_add(suffix.len()))
            .ok_or(PreparedTextRefusal::Format)?;
        Self::building(bytes, admission, || {
            let mut text = String::with_capacity(bytes);
            text.push_str(prefix);
            text.push_str(value);
            text.push_str(suffix);
            text
        })
    }

    /// Acquire the exact typed-string claim before invoking its sole builder.
    pub(super) fn building<B>(
        bytes: usize,
        admission: &FrameAdmission,
        build: B,
    ) -> std::result::Result<Self, PreparedTextRefusal>
    where
        B: FnOnce() -> String,
    {
        let claim = match myownmesh_core::mailbox_retained_claim::<String>(bytes, 0, 1) {
            Ok(claim) => claim,
            Err(myownmesh_core::ResourceMailboxItemError::Claim(error)) => {
                return Err(FrameRefusal::Claim(error).into());
            }
            Err(myownmesh_core::ResourceMailboxItemError::Measurement(_)) => {
                unreachable!("a claim built from scalar counts performs no measurement")
            }
        };
        let retention = admission.acquire_claim(claim)?;
        let value = build();
        if value.len() != bytes {
            return Err(PreparedTextRefusal::Unstable);
        }
        Ok(Self {
            value,
            _retention: retention,
        })
    }

    /// Format the one closed error source currently admitted at this boundary.
    pub(super) fn core_error(
        value: &myownmesh_core::Error,
        admission: &FrameAdmission,
    ) -> std::result::Result<Self, PreparedTextRefusal> {
        use std::fmt::Write as _;

        struct Count(usize);
        impl std::fmt::Write for Count {
            fn write_str(&mut self, value: &str) -> std::fmt::Result {
                self.0 = self.0.checked_add(value.len()).ok_or(std::fmt::Error)?;
                Ok(())
            }
        }

        let mut count = Count(0);
        write!(&mut count, "{value}").map_err(|_| PreparedTextRefusal::Format)?;
        let claim = match myownmesh_core::mailbox_retained_claim::<String>(count.0, 0, 1) {
            Ok(claim) => claim,
            Err(myownmesh_core::ResourceMailboxItemError::Claim(error)) => {
                return Err(FrameRefusal::Claim(error).into());
            }
            Err(myownmesh_core::ResourceMailboxItemError::Measurement(_)) => {
                unreachable!("a claim built from scalar counts performs no measurement")
            }
        };
        let retention = admission.acquire_claim(claim)?;
        let mut text = String::with_capacity(count.0);
        write!(&mut text, "{value}").map_err(|_| PreparedTextRefusal::Format)?;
        if text.len() != count.0 {
            return Err(PreparedTextRefusal::Unstable);
        }
        Ok(Self {
            value: text,
            _retention: retention,
        })
    }

    /// The exact daemon-owned lookup refusal; no generic formatter crosses the
    /// prepared boundary.
    pub(super) fn unknown_network(
        network: &str,
        admission: &FrameAdmission,
    ) -> std::result::Result<Self, PreparedTextRefusal> {
        const PREFIX: &str = "unknown network: ";
        let bytes = PREFIX
            .len()
            .checked_add(network.len())
            .ok_or(PreparedTextRefusal::Format)?;
        Self::building(bytes, admission, || {
            let mut text = String::with_capacity(bytes);
            text.push_str(PREFIX);
            text.push_str(network);
            text
        })
    }

    pub(super) fn no_inflight_rpc(
        request_id: &str,
        admission: &FrameAdmission,
    ) -> std::result::Result<Self, PreparedTextRefusal> {
        Self::surrounded("no in-flight inbound RPC for '", request_id, "'", admission)
    }

    pub(super) fn no_inflight_stream(
        request_id: &str,
        admission: &FrameAdmission,
    ) -> std::result::Result<Self, PreparedTextRefusal> {
        Self::surrounded(
            "no in-flight inbound stream for '",
            request_id,
            "'",
            admission,
        )
    }

    pub(super) fn rpc_advertise_error(
        value: &myownmesh_core::rpc::RpcError,
        admission: &FrameAdmission,
    ) -> std::result::Result<Self, PreparedTextRefusal> {
        use std::fmt::Write as _;
        const PREFIX: &str =
            "capabilities were not advertised; the node is still publishing its previous ones: ";
        let mut count = DisplayCount(PREFIX.len());
        write!(&mut count, "{value}").map_err(|_| PreparedTextRefusal::Format)?;
        let bytes = count.0;
        Self::building(bytes, admission, || {
            let mut text = String::with_capacity(bytes);
            text.push_str(PREFIX);
            write!(&mut text, "{value}").expect("formatting an error into String cannot fail");
            text
        })
    }

    pub(super) fn channel_error(
        value: &myownmesh_core::ChannelError,
        admission: &FrameAdmission,
    ) -> std::result::Result<Self, PreparedTextRefusal> {
        use std::fmt::Write as _;
        let mut count = DisplayCount(0);
        write!(&mut count, "{value}").map_err(|_| PreparedTextRefusal::Format)?;
        Self::building(count.0, admission, || value.to_string())
    }

    pub(super) fn decode_admission_error(
        value: &DecodeRefusal,
        admission: &FrameAdmission,
    ) -> std::result::Result<Self, PreparedTextRefusal> {
        use std::fmt::Write as _;
        let mut count = DisplayCount(0);
        write!(&mut count, "{value}").map_err(|_| PreparedTextRefusal::Format)?;
        Self::building(count.0, admission, || value.to_string())
    }

    pub(super) fn no_inbound_realtime_stream(
        peer: &str,
        admission: &FrameAdmission,
    ) -> std::result::Result<Self, PreparedTextRefusal> {
        Self::surrounded(
            "no inbound realtime stream for ",
            peer,
            ": the session is not current, or a live pipe already holds it — one inbound pipe per session, and the lease returns when that pipe ends",
            admission,
        )
    }
}

struct DisplayCount(usize);

impl std::fmt::Write for DisplayCount {
    fn write_str(&mut self, value: &str) -> std::fmt::Result {
        self.0 = self.0.checked_add(value.len()).ok_or(std::fmt::Error)?;
        Ok(())
    }
}

macro_rules! closed_prefixed_error {
    ($name:ident, $ty:ty, $prefix:literal) => {
        impl PreparedText {
            pub(super) fn $name(
                value: &$ty,
                admission: &FrameAdmission,
            ) -> std::result::Result<Self, PreparedTextRefusal> {
                use std::fmt::Write as _;
                let mut count = DisplayCount($prefix.len());
                write!(&mut count, "{value}").map_err(|_| PreparedTextRefusal::Format)?;
                let bytes = count.0;
                Self::building(bytes, admission, || {
                    let mut text = String::with_capacity(bytes);
                    text.push_str($prefix);
                    write!(&mut text, "{value}")
                        .expect("formatting a concrete error into String cannot fail");
                    text
                })
            }
        }
    };
}

closed_prefixed_error!(
    rpc_registration_error,
    crate::ipc::clients::RegistrationError,
    "rpc register refused: "
);
closed_prefixed_error!(json_parse_error, serde_json::Error, "parse: ");
closed_prefixed_error!(
    network_id_error,
    myownmesh_core::identity::NetworkIdRefusal,
    ""
);
closed_prefixed_error!(
    events_registration_error,
    crate::ipc::clients::IpcAdmissionError,
    "events subscribe refused: "
);
closed_prefixed_error!(
    rpc_gateway_error,
    myownmesh_core::application_gateway::GatewayRefusal,
    "rpc register refused: "
);
closed_prefixed_error!(
    channel_registration_error,
    crate::ipc::clients::RegistrationError,
    "channel subscribe refused: "
);
closed_prefixed_error!(
    channel_pump_error,
    crate::ipc::bridge::ChannelPumpError,
    "channel subscribe refused: "
);

impl serde::Serialize for PreparedReply {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;

        struct Field<'a, T: ?Sized> {
            key: &'static str,
            value: &'a T,
        }
        impl<T: serde::Serialize + ?Sized> serde::Serialize for Field<'_, T> {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                let mut data = serializer.serialize_struct("ResponseData", 1)?;
                data.serialize_field(self.key, self.value)?;
                data.end()
            }
        }

        match self {
            Self::StaticError(message) => {
                let mut response = serializer.serialize_struct("Response", 2)?;
                response.serialize_field("ok", &false)?;
                response.serialize_field("error", message)?;
                response.end()
            }
            Self::Error(message) => {
                let mut response = serializer.serialize_struct("Response", 2)?;
                response.serialize_field("ok", &false)?;
                response.serialize_field("error", &message.value)?;
                response.end()
            }
            Self::Bool { key, value } => {
                let mut response = serializer.serialize_struct("Response", 2)?;
                response.serialize_field("ok", &true)?;
                response.serialize_field("data", &Field { key, value })?;
                response.end()
            }
            Self::Usize { key, value } => {
                let mut response = serializer.serialize_struct("Response", 2)?;
                response.serialize_field("ok", &true)?;
                response.serialize_field("data", &Field { key, value })?;
                response.end()
            }
            Self::TraceSubscribed { network } => {
                #[derive(serde::Serialize)]
                struct TraceData<'a> {
                    subscribed: bool,
                    stream: &'static str,
                    network: &'a str,
                }
                let mut response = serializer.serialize_struct("Response", 2)?;
                response.serialize_field("ok", &true)?;
                response.serialize_field(
                    "data",
                    &TraceData {
                        subscribed: true,
                        stream: "conn_trace",
                        network: &network.value,
                    },
                )?;
                response.end()
            }
            Self::EventsSubscribed(client) => {
                #[derive(serde::Serialize)]
                struct EventsData<'a> {
                    subscribed: bool,
                    client_id: crate::ipc::ClientId,
                    client_capability: &'a str,
                }
                let mut response = serializer.serialize_struct("Response", 2)?;
                response.serialize_field("ok", &true)?;
                response.serialize_field(
                    "data",
                    &EventsData {
                        subscribed: true,
                        client_id: client.id,
                        client_capability: client.capability(),
                    },
                )?;
                response.end()
            }
            Self::ServicesStatus(status) => {
                #[derive(serde::Serialize)]
                struct ServicesData<'a> {
                    status: &'a crate::services::ServicesReport,
                    config: &'a myownmesh_core::ServicesConfig,
                }
                let mut response = serializer.serialize_struct("Response", 2)?;
                response.serialize_field("ok", &true)?;
                response.serialize_field(
                    "data",
                    &ServicesData {
                        status: status.report(),
                        config: status.config(),
                    },
                )?;
                response.end()
            }
            Self::Config(config) => {
                let mut response = serializer.serialize_struct("Response", 2)?;
                response.serialize_field("ok", &true)?;
                response.serialize_field(
                    "data",
                    &Field {
                        key: "config",
                        value: config.get(),
                    },
                )?;
                response.end()
            }
            Self::NetworkId(network_id) => {
                let mut response = serializer.serialize_struct("Response", 2)?;
                response.serialize_field("ok", &true)?;
                response.serialize_field(
                    "data",
                    &Field {
                        key: "network_id",
                        value: network_id.get(),
                    },
                )?;
                response.end()
            }
            Self::Status(status) => {
                #[derive(serde::Serialize)]
                struct StatusData<'a> {
                    version: &'static str,
                    device_id: &'a str,
                    joined_networks: &'a [String],
                    realtime: &'a crate::control::RealtimeAdvert,
                }
                let mut response = serializer.serialize_struct("Response", 2)?;
                response.serialize_field("ok", &true)?;
                response.serialize_field(
                    "data",
                    &StatusData {
                        version: status.version(),
                        device_id: status.device_id(),
                        joined_networks: status.joined_networks(),
                        realtime: status.realtime(),
                    },
                )?;
                response.end()
            }
            Self::Networks(networks) => {
                let mut response = serializer.serialize_struct("Response", 2)?;
                response.serialize_field("ok", &true)?;
                response.serialize_field("data", networks)?;
                response.end()
            }
            Self::Variable(variable) => variable.serialize(serializer),
        }
    }
}

#[derive(serde::Serialize)]
struct RosterData<'a> {
    roster: &'a [myownmesh_core::AuthorizedPeer],
}

pub(super) enum VariableReplySource<'a> {
    Roster(myownmesh_core::PreparedRosterSnapshot<'a>),
    Governance(myownmesh_core::PreparedGovernanceSnapshot<'a>),
}

impl<'a> VariableReplySource<'a> {
    pub(super) fn roster(plan: myownmesh_core::PreparedRosterSnapshot<'a>) -> Self {
        Self::Roster(plan)
    }

    pub(super) fn governance(plan: myownmesh_core::PreparedGovernanceSnapshot<'a>) -> Self {
        Self::Governance(plan)
    }

    pub(super) fn typed_claim(&self) -> myownmesh_core::ResourceClaim {
        match self {
            Self::Roster(plan) => plan.typed_retention_claim(),
            Self::Governance(plan) => plan.typed_retention_claim(),
        }
    }

    pub(super) fn data_ceiling(&self) -> std::result::Result<usize, FrameRefusal> {
        match self {
            Self::Roster(plan) => "{\"roster\":"
                .len()
                .checked_add(plan.encoding_ceiling())
                .and_then(|bytes| bytes.checked_add(1))
                .ok_or(FrameRefusal::Claim(
                    myownmesh_core::ResourceClaimArithmeticError::Overflow {
                        dimension: myownmesh_core::ResourceClass::AccountedMemoryBytes,
                    },
                )),
            Self::Governance(plan) => Ok(plan.encoding_ceiling()),
        }
    }

    pub(super) async fn commit(
        self,
        lease: myownmesh_core::ResourceLease,
    ) -> anyhow::Result<FundedVariableReply> {
        match self {
            Self::Roster(plan) => plan
                .commit(lease)
                .map(FundedVariableReply::Roster)
                .map_err(|_| anyhow::anyhow!("RosterList grew before commit")),
            Self::Governance(plan) => plan
                .commit(lease)
                .await
                .map(FundedVariableReply::Governance)
                .map_err(anyhow::Error::from),
        }
    }
}

pub(super) enum FundedVariableReply {
    Roster(myownmesh_core::FundedRosterSnapshot),
    Governance(myownmesh_core::FundedGovernanceSnapshot),
    UpdaterStatus(myownmesh_updater::FundedUpdaterResult<myownmesh_updater::UpdateStatus>),
    UpdaterCheck(myownmesh_updater::FundedUpdaterResult<myownmesh_updater::CheckOutcome>),
    RpcCall(FundedRpcCallOutcome),
    MfaEnrollment(FundedMfaEnrollment),
    Operation(FundedOperationReply),
}

pub(super) enum OperationReplyData {
    Approved(String),
    Removed(String),
    Topology(String),
    ProposalId(String),
    Signed(String),
    Denied(String),
    Withdrawn(String),
    NewNetworkId(String),
    Reconnecting(String),
    Connecting {
        peer: String,
        network: String,
        pinned: bool,
        active: bool,
    },
    Forgotten(Vec<String>),
    Reset,
    UpdatedId {
        id: String,
        restarted: bool,
    },
    Added(NetworkLifecycleSummary),
    Updated(NetworkLifecycleSummary),
    Identity {
        device_id: String,
        pubkey: String,
        label: String,
    },
    Applied(Option<String>),
    RealtimeOpened {
        flow_label: String,
        capability: String,
    },
    Closed,
    RpcStreamStarted(String),
    ServicesStatus(crate::services::ServicesReport),
    RealtimeRefused {
        error: String,
        code: String,
    },
}

#[derive(serde::Serialize)]
pub(super) struct NetworkLifecycleSummary {
    pub(super) config_id: String,
    pub(super) network_id: String,
    pub(super) label: String,
    pub(super) phase: myownmesh_core::MeshPhase,
    pub(super) topology: myownmesh_core::TopologyMode,
    #[serde(skip)]
    pub(super) restarted: bool,
}

pub(super) struct VariableOperationPlan {
    operation: myownmesh_core::ResourceLease,
}

pub(super) struct FundedOperationReply {
    result: std::result::Result<OperationReplyData, String>,
    _operation: myownmesh_core::ResourceLease,
}

const VARIABLE_OPERATION_CLAIM: myownmesh_core::ResourceClaim =
    myownmesh_core::ResourceClaim::single(
        myownmesh_core::ResourceClass::OpaqueDependencyResidual,
        1,
    );

pub(super) const fn variable_operation_claim() -> myownmesh_core::ResourceClaim {
    VARIABLE_OPERATION_CLAIM
}

pub(super) struct FundedRpcCallOutcome {
    result: std::result::Result<
        myownmesh_core::rpc::FundedRpcCallResult,
        myownmesh_core::rpc::RpcError,
    >,
    _operation: myownmesh_core::ResourceLease,
}

#[cfg(test)]
static RPC_CALL_REPLY_BUILDS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

#[cfg(test)]
pub(super) fn rpc_call_reply_builds() -> usize {
    RPC_CALL_REPLY_BUILDS.load(std::sync::atomic::Ordering::Relaxed)
}

pub(super) struct FundedMfaEnrollment {
    result: myownmesh_core::Result<myownmesh_core::custody::Enrolled>,
    _operation: myownmesh_core::ResourceLease,
}

impl FundedVariableReply {
    #[expect(
        clippy::result_large_err,
        reason = "a mismatched admitted lease must be returned intact without allocating"
    )]
    pub(super) fn begin_operation(
        operation: myownmesh_core::ResourceLease,
    ) -> std::result::Result<VariableOperationPlan, myownmesh_core::ResourceLease> {
        if operation.claim() != VARIABLE_OPERATION_CLAIM {
            return Err(operation);
        }
        Ok(VariableOperationPlan { operation })
    }

    #[expect(
        clippy::result_large_err,
        reason = "a mismatched admitted lease must be returned intact without allocating"
    )]
    pub(super) fn operation(
        result: std::result::Result<OperationReplyData, String>,
        operation: myownmesh_core::ResourceLease,
    ) -> std::result::Result<Self, myownmesh_core::ResourceLease> {
        if operation.claim() != VARIABLE_OPERATION_CLAIM {
            return Err(operation);
        }
        Ok(Self::Operation(FundedOperationReply {
            result,
            _operation: operation,
        }))
    }

    pub(super) fn updater_status(
        value: myownmesh_updater::FundedUpdaterResult<myownmesh_updater::UpdateStatus>,
    ) -> Self {
        Self::UpdaterStatus(value)
    }

    pub(super) fn updater_check(
        value: myownmesh_updater::FundedUpdaterResult<myownmesh_updater::CheckOutcome>,
    ) -> Self {
        Self::UpdaterCheck(value)
    }

    #[expect(
        clippy::result_large_err,
        reason = "a mismatched admitted lease is returned intact; boxing adds an unpriced allocation on the accounting refusal path"
    )]
    pub(super) fn rpc_call(
        result: std::result::Result<
            myownmesh_core::rpc::FundedRpcCallResult,
            myownmesh_core::rpc::RpcError,
        >,
        operation: myownmesh_core::ResourceLease,
    ) -> std::result::Result<Self, myownmesh_core::ResourceLease> {
        if operation.claim() != VARIABLE_OPERATION_CLAIM {
            return Err(operation);
        }
        #[cfg(test)]
        RPC_CALL_REPLY_BUILDS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(Self::RpcCall(FundedRpcCallOutcome {
            result,
            _operation: operation,
        }))
    }

    #[expect(
        clippy::result_large_err,
        reason = "a mismatched admitted lease is returned intact; boxing adds an unpriced allocation on the accounting refusal path"
    )]
    pub(super) fn mfa_enrollment(
        result: myownmesh_core::Result<myownmesh_core::custody::Enrolled>,
        operation: myownmesh_core::ResourceLease,
    ) -> std::result::Result<Self, myownmesh_core::ResourceLease> {
        if operation.claim() != VARIABLE_OPERATION_CLAIM {
            return Err(operation);
        }
        Ok(Self::MfaEnrollment(FundedMfaEnrollment {
            result,
            _operation: operation,
        }))
    }

    pub(super) fn exact_line_len(&self) -> std::result::Result<usize, FrameRefusal> {
        let mut count = CountingSink::default();
        serde_json::to_writer(&mut count, self).map_err(|_| {
            FrameRefusal::Claim(myownmesh_core::ResourceClaimArithmeticError::Overflow {
                dimension: myownmesh_core::ResourceClass::AccountedMemoryBytes,
            })
        })?;
        count.measured().checked_add(1).ok_or(FrameRefusal::Claim(
            myownmesh_core::ResourceClaimArithmeticError::Overflow {
                dimension: myownmesh_core::ResourceClass::AccountedMemoryBytes,
            },
        ))
    }
}

impl VariableOperationPlan {
    pub(super) fn finish(
        self,
        result: std::result::Result<OperationReplyData, String>,
    ) -> FundedVariableReply {
        FundedVariableReply::Operation(FundedOperationReply {
            result,
            _operation: self.operation,
        })
    }
}

impl serde::Serialize for FundedVariableReply {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct as _;
        match self {
            Self::Roster(roster) => {
                let mut response = serializer.serialize_struct("Response", 2)?;
                response.serialize_field("ok", &true)?;
                response.serialize_field(
                    "data",
                    &RosterData {
                        roster: roster.get(),
                    },
                )?;
                response.end()
            }
            Self::Governance(governance) => {
                #[derive(serde::Serialize)]
                struct GovernanceData<'a> {
                    state: &'a myownmesh_core::NetworkState,
                    evicted: &'a [String],
                }
                let mut response = serializer.serialize_struct("Response", 2)?;
                response.serialize_field("ok", &true)?;
                response.serialize_field(
                    "data",
                    &GovernanceData {
                        state: governance.state(),
                        evicted: governance.evicted(),
                    },
                )?;
                response.end()
            }
            Self::UpdaterStatus(value) => serialize_updater_result(serializer, value),
            Self::UpdaterCheck(value) => serialize_updater_result(serializer, value),
            Self::RpcCall(value) => serialize_rpc_call(serializer, value),
            Self::MfaEnrollment(value) => serialize_mfa_enrollment(serializer, value),
            Self::Operation(value) => serialize_operation_reply(serializer, value),
        }
    }
}

fn serialize_operation_reply<S: serde::Serializer>(
    serializer: S,
    value: &FundedOperationReply,
) -> Result<S::Ok, S::Error> {
    use serde::ser::SerializeStruct as _;
    match &value.result {
        Ok(OperationReplyData::RealtimeRefused { error, code }) => {
            #[derive(serde::Serialize)]
            struct RefusalData<'a> {
                code: &'a str,
            }
            let mut response = serializer.serialize_struct("Response", 3)?;
            response.serialize_field("ok", &false)?;
            response.serialize_field("error", error)?;
            response.serialize_field("data", &RefusalData { code })?;
            response.end()
        }
        Ok(data) => {
            #[derive(serde::Serialize)]
            #[serde(untagged)]
            enum OperationField<'a> {
                Approved {
                    approved: &'a str,
                },
                Removed {
                    removed: &'a str,
                },
                Topology {
                    topology: &'a str,
                },
                ProposalId {
                    proposal_id: &'a str,
                },
                Signed {
                    signed: &'a str,
                },
                Denied {
                    denied: &'a str,
                },
                Withdrawn {
                    withdrawn: &'a str,
                },
                NewNetworkId {
                    new_network_id: &'a str,
                },
                Reconnecting {
                    reconnecting: &'a str,
                },
                Connecting {
                    connecting: &'a str,
                    network: &'a str,
                    pinned: bool,
                    active: bool,
                },
                Forgotten {
                    forgotten: &'a [String],
                    restarting: bool,
                },
                Reset {
                    reset: bool,
                    restarting: bool,
                },
                UpdatedId {
                    updated: &'a str,
                    restarted: bool,
                },
                Added {
                    added: &'a NetworkLifecycleSummary,
                },
                Updated {
                    updated: &'a NetworkLifecycleSummary,
                    restarted: bool,
                },
                Identity {
                    device_id: &'a str,
                    pubkey: &'a str,
                    label: &'a str,
                },
                Applied {
                    applied: &'a Option<String>,
                },
                RealtimeOpened {
                    flow_label: &'a str,
                    flow_capability: &'a str,
                },
                Closed {
                    closed: bool,
                },
                RpcStreamStarted {
                    request_id: &'a str,
                },
                ServicesStatus {
                    status: &'a crate::services::ServicesReport,
                },
            }
            let field = match data {
                OperationReplyData::Approved(value) => OperationField::Approved { approved: value },
                OperationReplyData::Removed(value) => OperationField::Removed { removed: value },
                OperationReplyData::Topology(value) => OperationField::Topology { topology: value },
                OperationReplyData::ProposalId(value) => {
                    OperationField::ProposalId { proposal_id: value }
                }
                OperationReplyData::Signed(value) => OperationField::Signed { signed: value },
                OperationReplyData::Denied(value) => OperationField::Denied { denied: value },
                OperationReplyData::Withdrawn(value) => {
                    OperationField::Withdrawn { withdrawn: value }
                }
                OperationReplyData::NewNetworkId(value) => OperationField::NewNetworkId {
                    new_network_id: value,
                },
                OperationReplyData::Reconnecting(value) => OperationField::Reconnecting {
                    reconnecting: value,
                },
                OperationReplyData::Connecting {
                    peer,
                    network,
                    pinned,
                    active,
                } => OperationField::Connecting {
                    connecting: peer,
                    network,
                    pinned: *pinned,
                    active: *active,
                },
                OperationReplyData::Forgotten(values) => OperationField::Forgotten {
                    forgotten: values,
                    restarting: true,
                },
                OperationReplyData::Reset => OperationField::Reset {
                    reset: true,
                    restarting: true,
                },
                OperationReplyData::UpdatedId { id, restarted } => OperationField::UpdatedId {
                    updated: id,
                    restarted: *restarted,
                },
                OperationReplyData::Added(summary) => OperationField::Added { added: summary },
                OperationReplyData::Updated(summary) => OperationField::Updated {
                    updated: summary,
                    restarted: summary.restarted,
                },
                OperationReplyData::Identity {
                    device_id,
                    pubkey,
                    label,
                } => OperationField::Identity {
                    device_id,
                    pubkey,
                    label,
                },
                OperationReplyData::Applied(applied) => OperationField::Applied { applied },
                OperationReplyData::RealtimeOpened {
                    flow_label,
                    capability,
                } => OperationField::RealtimeOpened {
                    flow_label,
                    flow_capability: capability,
                },
                OperationReplyData::Closed => OperationField::Closed { closed: true },
                OperationReplyData::RpcStreamStarted(request_id) => {
                    OperationField::RpcStreamStarted { request_id }
                }
                OperationReplyData::ServicesStatus(status) => {
                    OperationField::ServicesStatus { status }
                }
                OperationReplyData::RealtimeRefused { .. } => unreachable!("handled above"),
            };
            let mut response = serializer.serialize_struct("Response", 2)?;
            response.serialize_field("ok", &true)?;
            response.serialize_field("data", &field)?;
            response.end()
        }
        Err(error) => {
            let mut response = serializer.serialize_struct("Response", 2)?;
            response.serialize_field("ok", &false)?;
            response.serialize_field("error", error)?;
            response.end()
        }
    }
}

fn serialize_mfa_enrollment<S: serde::Serializer>(
    serializer: S,
    value: &FundedMfaEnrollment,
) -> Result<S::Ok, S::Error> {
    use serde::ser::SerializeStruct as _;
    struct DisplayRef<'a, T>(&'a T);
    impl<T: std::fmt::Display> serde::Serialize for DisplayRef<'_, T> {
        fn serialize<R: serde::Serializer>(&self, serializer: R) -> Result<R::Ok, R::Error> {
            serializer.collect_str(self.0)
        }
    }
    match &value.result {
        Ok(enrollment) => {
            #[derive(serde::Serialize)]
            struct EnrollmentData<'a> {
                secret: &'a str,
                otpauth_uri: &'a str,
                recovery_codes: &'a [String],
            }
            let mut response = serializer.serialize_struct("Response", 2)?;
            response.serialize_field("ok", &true)?;
            response.serialize_field(
                "data",
                &EnrollmentData {
                    secret: &enrollment.secret_b32,
                    otpauth_uri: &enrollment.otpauth_uri,
                    recovery_codes: &enrollment.recovery_codes,
                },
            )?;
            response.end()
        }
        Err(error) => {
            let mut response = serializer.serialize_struct("Response", 2)?;
            response.serialize_field("ok", &false)?;
            response.serialize_field("error", &DisplayRef(error))?;
            response.end()
        }
    }
}

fn serialize_rpc_call<S: serde::Serializer>(
    serializer: S,
    value: &FundedRpcCallOutcome,
) -> Result<S::Ok, S::Error> {
    use serde::ser::SerializeStruct as _;
    struct DisplayRef<'a, T>(&'a T);
    impl<T: std::fmt::Display> serde::Serialize for DisplayRef<'_, T> {
        fn serialize<R: serde::Serializer>(&self, serializer: R) -> Result<R::Ok, R::Error> {
            serializer.collect_str(self.0)
        }
    }
    match &value.result {
        Ok(funded) => match (funded.body(), funded.error()) {
            (Some(body), None) => {
                #[derive(serde::Serialize)]
                struct RpcData<'a> {
                    response: &'a serde_json::Value,
                }
                let mut response = serializer.serialize_struct("Response", 2)?;
                response.serialize_field("ok", &true)?;
                response.serialize_field("data", &RpcData { response: body })?;
                response.end()
            }
            (None, Some(error)) => {
                let mut response = serializer.serialize_struct("Response", 2)?;
                response.serialize_field("ok", &false)?;
                response.serialize_field("error", error)?;
                response.end()
            }
            _ => Err(serde::ser::Error::custom(
                "funded RPC result had neither or both body and error",
            )),
        },
        Err(error) => {
            let mut response = serializer.serialize_struct("Response", 2)?;
            response.serialize_field("ok", &false)?;
            response.serialize_field("error", &DisplayRef(error))?;
            response.end()
        }
    }
}

fn serialize_updater_result<S: serde::Serializer, T: serde::Serialize>(
    serializer: S,
    value: &myownmesh_updater::FundedUpdaterResult<T>,
) -> Result<S::Ok, S::Error> {
    use serde::ser::SerializeStruct as _;
    struct DisplayRef<'a, T>(&'a T);
    impl<T: std::fmt::Display> serde::Serialize for DisplayRef<'_, T> {
        fn serialize<R: serde::Serializer>(&self, serializer: R) -> Result<R::Ok, R::Error> {
            serializer.collect_str(self.0)
        }
    }
    match value.get() {
        Ok(success) => {
            let mut response = serializer.serialize_struct("Response", 2)?;
            response.serialize_field("ok", &true)?;
            response.serialize_field("data", success)?;
            response.end()
        }
        Err(error) => {
            let mut response = serializer.serialize_struct("Response", 2)?;
            response.serialize_field("ok", &false)?;
            response.serialize_field("error", &DisplayRef(error))?;
            response.end()
        }
    }
}

pub(super) fn variable_data_reply_line_ceiling(
    encoded_data: usize,
) -> std::result::Result<usize, FrameRefusal> {
    const PREFIX: usize = "{\"ok\":true,\"data\":".len();
    const SUFFIX: usize = "}\n".len();
    PREFIX
        .checked_add(encoded_data)
        .and_then(|bytes| bytes.checked_add(SUFFIX))
        .ok_or(FrameRefusal::Claim(
            myownmesh_core::ResourceClaimArithmeticError::Overflow {
                dimension: myownmesh_core::ResourceClass::AccountedMemoryBytes,
            },
        ))
}

const NETWORK_ID_REPLY_PREFIX: &str = "{\"ok\":true,\"data\":{\"network_id\":";
const NETWORK_ID_REPLY_SUFFIX: &str = "}}\n";

pub(super) fn network_id_reply_line_ceiling(
    encoded_network_id: usize,
) -> std::result::Result<usize, FrameRefusal> {
    NETWORK_ID_REPLY_PREFIX
        .len()
        .checked_add(encoded_network_id)
        .and_then(|bytes| bytes.checked_add(NETWORK_ID_REPLY_SUFFIX.len()))
        .ok_or(FrameRefusal::Claim(
            myownmesh_core::ResourceClaimArithmeticError::Overflow {
                dimension: myownmesh_core::ResourceClass::AccountedMemoryBytes,
            },
        ))
}

/// Maximum encoded EventsSubscribe success line, derived by running the real
/// closed serializer over the widest id and then adding the capability's fixed
/// encoded width. No client or response value is constructed to answer it.
pub(super) fn events_subscribed_line_ceiling() -> std::result::Result<usize, FrameRefusal> {
    #[derive(serde::Serialize)]
    struct EventsData<'a> {
        subscribed: bool,
        client_id: crate::ipc::ClientId,
        client_capability: &'a str,
    }
    #[derive(serde::Serialize)]
    struct Envelope<'a> {
        ok: bool,
        data: EventsData<'a>,
    }

    let mut counted = CountingSink::default();
    serde_json::to_writer(
        &mut counted,
        &Envelope {
            ok: true,
            data: EventsData {
                subscribed: true,
                client_id: crate::ipc::ClientId(u64::MAX),
                client_capability: "",
            },
        },
    )
    .map_err(|_| {
        FrameRefusal::Claim(myownmesh_core::ResourceClaimArithmeticError::Overflow {
            dimension: myownmesh_core::ResourceClass::AccountedMemoryBytes,
        })
    })?;
    counted
        .measured()
        .checked_add(crate::ipc::ClientHandle::capability_encoded_len())
        .and_then(|bytes| bytes.checked_add(1))
        .ok_or(FrameRefusal::Claim(
            myownmesh_core::ResourceClaimArithmeticError::Overflow {
                dimension: myownmesh_core::ResourceClass::AccountedMemoryBytes,
            },
        ))
}

/// Bytes surrounding the compact config encoding in a successful response.
///
/// Named from the exact wire shape serialized by `PreparedReply::Config`, so
/// the core ceiling is extended only by bytes this layer itself adds.
const CONFIG_REPLY_PREFIX: &str = "{\"ok\":true,\"data\":{\"config\":";
const CONFIG_REPLY_SUFFIX: &str = "}}\n";

pub(super) fn config_reply_line_ceiling(
    config_encoding_ceiling: usize,
) -> std::result::Result<usize, FrameRefusal> {
    CONFIG_REPLY_PREFIX
        .len()
        .checked_add(config_encoding_ceiling)
        .and_then(|bytes| bytes.checked_add(CONFIG_REPLY_SUFFIX.len()))
        .ok_or(FrameRefusal::Claim(
            myownmesh_core::ResourceClaimArithmeticError::Overflow {
                dimension: myownmesh_core::ResourceClass::AccountedMemoryBytes,
            },
        ))
}

/// Fund one prepared reply's line, then build whatever the caller is answering
/// with — in that order, so the answer is constructed only past admission.
pub(super) fn prepare_reply_then<R, B>(
    reply: &PreparedReply,
    admission: &FrameAdmission,
    build: B,
) -> std::result::Result<(R, PreparedLineCapacity), EncodeRefusal>
where
    B: FnOnce() -> R,
{
    let output = AdmittedLineOut::prepare(&ControlOut::Prepared(reply), admission)?;
    Ok((build(), output))
}

/// Exact encoded-line admission for a reply.
///
/// The buffer type is framing's — it owns the bytes and the leases that paid
/// for them. What lives here is the half that has to know what a reply is: the
/// measuring pass runs over the closed [`ControlOut`] envelope, which is what
/// makes counting allocation-free and therefore makes the refusal arrive before
/// the allocation rather than after it.
impl AdmittedLineOut {
    /// Measure and fund an encoded line without constructing its byte buffer.
    pub(super) fn prepare(
        value: &ControlOut<'_>,
        admission: &FrameAdmission,
    ) -> std::result::Result<PreparedLineCapacity, EncodeRefusal> {
        let mut counted = CountingSink::default();
        serde_json::to_writer(&mut counted, &value).map_err(EncodeRefusal::Malformed)?;
        let capacity = counted.measured().checked_add(1).ok_or({
            EncodeRefusal::Admission(FrameRefusal::Claim(
                myownmesh_core::ResourceClaimArithmeticError::Overflow {
                    dimension: myownmesh_core::ResourceClass::AccountedMemoryBytes,
                },
            ))
        })?;
        Self::prepare_capacity(capacity, admission).map_err(EncodeRefusal::Admission)
    }

    pub(super) fn encode_prepared(
        value: ControlOut<'_>,
        prepared: PreparedLineCapacity,
    ) -> std::result::Result<Self, EncodeRefusal> {
        Self::encode_into_funded_line(&value, prepared, Vec::with_capacity)
    }

    /// Measure, fund, then encode — in that order and no other.
    pub(super) fn encode(
        value: ControlOut<'_>,
        admission: &FrameAdmission,
    ) -> std::result::Result<Self, EncodeRefusal> {
        Self::encode_building(value, admission, Vec::with_capacity)
    }

    /// [`Self::encode`] with the buffer's construction passed in, so a control
    /// can count constructions. See [`Self::encode_into_funded_line`], which is
    /// where the single allocating expression lives.
    pub(super) fn encode_building<B>(
        value: ControlOut<'_>,
        admission: &FrameAdmission,
        build: B,
    ) -> std::result::Result<Self, EncodeRefusal>
    where
        B: FnOnce(usize) -> Vec<u8>,
    {
        let prepared = Self::prepare(&value, admission)?;
        Self::encode_into_funded_line(&value, prepared, build)
    }
}
