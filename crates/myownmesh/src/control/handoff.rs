//! State that is not this daemon's until the client has been told about it.
//!
//! Three operations answer with the caller's *only* copy of something: the
//! capability naming a realtime flow, the coordinate naming a started RPC
//! stream, and the secret and recovery codes of an MFA enrollment. None of the
//! three is queryable afterwards. If the response line is refused, or the
//! socket ends before it is written, the daemon is left holding live state
//! whose only handle went nowhere — a flow nobody can close, a stream nobody
//! can read, a custody lock nobody can satisfy.
//!
//! So each of those three hands its new state back to the connection loop
//! rather than keeping it, and the loop settles it against the one fact only
//! the loop has: whether the answer was actually written.
//!
//! This is deliberately not a transaction framework. There is one value, it
//! moves, and it has exactly two outcomes. Operations with queryable or
//! idempotent results — labels, ordinary governance mutations, dials, joins —
//! do not use it and do not need it.

use std::sync::Arc;

use tracing::warn;

use super::ControlState;

/// One handoff that is not final until the client has the answer.
///
/// Move-only and `#[must_use]`: the settle call is the only thing that consumes
/// it, so an arm that forgets to settle is a compiler warning rather than a
/// silent commit. [`Self::None`] is the ordinary case — nothing was created
/// that a failed handoff could strand — and it exists so every one of these
/// operations has the same shape whether or not it got as far as making
/// something.
#[must_use = "a provisional handoff must be settled against the write disposition"]
pub(in crate::control) enum ProvisionalHandoff {
    /// Nothing was created, or the operation refused before it created
    /// anything.
    None,
    /// A realtime flow installed under one exact client, named by one exact
    /// capability.
    ///
    /// The client handle is held rather than the id: the rollback has to reach
    /// *that* client's flow table, and a client that reconnected in the
    /// meantime is a different record with a different id, so an id-keyed undo
    /// could take a flow out from under a successor.
    RealtimeFlow {
        client: myownmesh_core::FundedArc<crate::ipc::ClientHandle>,
        capability: String,
    },
    /// A filed remote stream and the forwarding work that has not been started
    /// yet.
    ///
    /// Nothing is spawned until commit, which is what makes "no forwarding task
    /// survives an unhanded setup response" true by construction rather than by
    /// cancellation.
    RpcStream(super::dispatch::rpc::PendingStreamForward),
    /// Custody material that has been generated but not written.
    MfaEnrollment(myownmesh_core::custody::PreparedEnrollment),
}

impl ProvisionalHandoff {
    /// Settle against the write disposition.
    ///
    /// `sent` is true only for [`Wrote::Sent`](super::Wrote::Sent) — a refused
    /// line and an ended socket are both "the client does not have this", and
    /// both roll back. Nothing here consults a duration or retries anything.
    pub(in crate::control) async fn settle(self, state: &Arc<ControlState>, sent: bool) {
        if sent {
            self.commit();
        } else {
            self.roll_back(state).await;
        }
    }

    /// The client has the answer, so the new state is this daemon's to keep.
    fn commit(self) {
        match self {
            Self::None | Self::RealtimeFlow { .. } => {}
            // Only now does a task exist to forward into the writer the client
            // is reading, and only now does the client hold the coordinate that
            // names what it will carry.
            Self::RpcStream(pending) => pending.spawn(),
            // A commit that fails leaves this device unlocked, which is the
            // recoverable direction: the caller holds material for an
            // enrollment that does not exist and can enroll again. The opposite
            // — a lock installed whose secret was never delivered — is what
            // this ordering exists to prevent.
            Self::MfaEnrollment(prepared) => {
                let network = prepared.network_id().to_owned();
                if let Err(error) = prepared.commit() {
                    warn!(
                        %network,
                        "MFA enrollment was handed to its caller but could not be persisted: {error}"
                    );
                }
            }
        }
    }

    /// The client does not have the answer, so undo exactly what was made.
    async fn roll_back(self, state: &Arc<ControlState>) {
        match self {
            Self::None => {}
            // The exact capability out of the exact client's table, then the
            // flow closed through its own network — the same two steps
            // `flow_close` performs, so the flow is retired by its existing
            // cleanup owner rather than by a second path.
            Self::RealtimeFlow { client, capability } => {
                let Some(flow) = client.take_realtime_flow(&capability) else {
                    // Already gone: the client disconnected and the drain
                    // closed it, which is the same end state.
                    return;
                };
                let Some(net) = state.registry.get(flow.network()) else {
                    return;
                };
                let _ = flow.close_through(&net).await;
            }
            // Dropping the pending forward drops the filed stream's receiver,
            // which withdraws it, and no task was ever spawned to outlive it.
            Self::RpcStream(pending) => drop(pending),
            // Nothing was written, so there is nothing to remove.
            Self::MfaEnrollment(prepared) => drop(prepared),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One registered client, and the reading half of its writer.
    ///
    /// The realtime controls are about the flow table rather than about frames,
    /// so the mailbox exists only because a client record needs one — but the
    /// receiver is handed back rather than dropped: dropping it would close the
    /// mailbox, and a control would then be running against a client whose
    /// writer is already gone. It is also what releases the mailbox's funding
    /// when the control ends, which a leak would not.
    fn registered_client(
        state: &Arc<ControlState>,
    ) -> (
        myownmesh_core::FundedArc<crate::ipc::ClientHandle>,
        myownmesh_core::ResourceMailboxReceiver<crate::ipc::ServerOut>,
    ) {
        let (tx, rx) = myownmesh_core::resource_mailbox(crate::test_application_scope())
            .expect("the daemon test grant opens one client writer mailbox");
        let client = state
            .clients
            .register(tx)
            .expect("the fixture registry admits one client");
        (client, rx)
    }

    /// Install one flow on one client and answer the capability naming it.
    ///
    /// Written out rather than `expect`ed because a refusal is not `Debug` and
    /// must not become one: it carries the live handle back, and a derived
    /// `Debug` would print a flow's identities into a panic message. The reason
    /// is what a reader needs, and `RegistrationError` already displays it, so
    /// the failure says as much as `expect` would have.
    fn install_flow(
        state: &Arc<ControlState>,
        client: &myownmesh_core::FundedArc<crate::ipc::ClientHandle>,
        device_id: &str,
        label: &[u8],
        what: &str,
    ) -> String {
        match state.clients.install_realtime_flow(
            client,
            "control-net".to_owned(),
            myownmesh_core::realtime::transport_lab_retired_flow_handle(device_id, label),
        ) {
            Ok(capability) => capability.expose().to_owned(),
            Err(rejected) => panic!("{what}: {}", rejected.reason),
        }
    }

    /// An installed realtime flow whose response was never written is taken back
    /// out of the exact client it was installed on.
    ///
    /// The discriminating case for A1's realtime arm. The capability naming a
    /// flow is minted once and handed to the client in the response line; if
    /// that line is refused or the socket ends first, the client has no name for
    /// the flow and the daemon is holding one nothing can close. So the flow is
    /// not the daemon's until the answer is written, and the rollback takes it
    /// back out — the same two steps `flow_close` performs.
    ///
    /// The handle is a real one for a flow that is already gone; see
    /// [`myownmesh_core::realtime::transport_lab_retired_flow_handle`] for why
    /// that is the honest fixture and what it bounds. The installation, the
    /// table, the capability and the removal are all production's.
    ///
    /// The second client is what makes this *exact* rather than approximate: it
    /// holds its own flow under its own capability, and the rollback of the
    /// first leaves it alone.
    #[tokio::test]
    async fn v4_r6_daemon_a1_an_unhanded_realtime_flow_leaves_its_client_holding_nothing() {
        let state = crate::control::joinless_control_state().await;
        let (client, _writer) = registered_client(&state);
        let (bystander, _bystander_writer) = registered_client(&state);

        let capability = install_flow(
            &state,
            &client,
            "device-b",
            b"flow-a",
            "the registry installs one flow on a registered client",
        );
        let bystander_capability = install_flow(
            &state,
            &bystander,
            "device-c",
            b"flow-b",
            "and one on the second client",
        );

        ProvisionalHandoff::RealtimeFlow {
            client: client.clone(),
            capability: capability.clone(),
        }
        .settle(&state, false)
        .await;

        assert!(
            client.take_realtime_flow(&capability).is_none(),
            "the exact capability names nothing on the exact client: the \
             rollback took the flow out and handed it to the close path"
        );
        assert!(
            bystander
                .take_realtime_flow(&bystander_capability)
                .is_some(),
            "and the other client's flow is untouched — the undo is keyed to \
             the handle and the capability it was given, not to a client id or \
             a label"
        );
    }

    /// The positive twin: a flow whose response *was* written stays installed.
    ///
    /// Without this the control above would be satisfied by a build that undid
    /// every open, which is worse than never undoing one. The capability still
    /// resolves to a flow afterwards, which is the whole of what the client was
    /// promised.
    #[tokio::test]
    async fn v4_r6_daemon_a1_a_delivered_realtime_flow_stays_installed() {
        let state = crate::control::joinless_control_state().await;
        let (client, _writer) = registered_client(&state);

        let capability = install_flow(
            &state,
            &client,
            "device-b",
            b"flow-a",
            "the registry installs one flow on a registered client",
        );

        ProvisionalHandoff::RealtimeFlow {
            client: client.clone(),
            capability: capability.clone(),
        }
        .settle(&state, true)
        .await;

        assert!(
            client.take_realtime_flow(&capability).is_some(),
            "the client holds the capability, so the flow it names is the \
             daemon's to keep"
        );
    }
}
