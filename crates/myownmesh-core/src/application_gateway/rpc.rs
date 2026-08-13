//! The gateway's RPC seam: installing the one RPC owner, and the request and
//! capability operations that reach the engine through it.

use crate::resource::LocalApplicationResourceScope;

use super::{ApplicationGateway, GatewayRefusal};

impl ApplicationGateway {
    pub(crate) fn rpc(&self) -> Option<std::sync::Arc<crate::rpc::RpcInner>> {
        self.rpc.read().clone()
    }

    pub(crate) fn install_rpc(
        &self,
        candidate: std::sync::Arc<crate::rpc::RpcInner>,
    ) -> Result<std::sync::Arc<crate::rpc::RpcInner>, GatewayRefusal> {
        if self.closed.load(std::sync::atomic::Ordering::Acquire) {
            return Err(GatewayRefusal::Revoked);
        }
        let mut installed = self.rpc.write();
        if self.closed.load(std::sync::atomic::Ordering::Acquire) {
            return Err(GatewayRefusal::Revoked);
        }
        Ok(std::sync::Arc::clone(installed.get_or_insert(candidate)))
    }

    pub(crate) fn rpc_resource_scope(
        &self,
    ) -> Result<LocalApplicationResourceScope, GatewayRefusal> {
        if self.closed.load(std::sync::atomic::Ordering::Acquire) {
            return Err(GatewayRefusal::Revoked);
        }
        self.resources.child().map_err(GatewayRefusal::Pressure)
    }

    pub(crate) fn register_rpc_request(
        &self,
        state: &crate::engine::state::NetworkState,
        peer: &str,
        effect: crate::rpc::PendingEntry,
    ) -> Result<crate::rpc::LocalRequest, crate::rpc::RpcRegistrationRefusal> {
        let owner = state
            .peers
            .owner(peer)
            .ok_or(crate::rpc::RpcRegistrationRefusal::SessionNotCurrent)?;
        state
            .peers
            .with_live_session_state(
                &owner,
                state.session_broker.as_ref(),
                &state.network_id,
                |session, app| app.rpc_mut().register_local_request(peer, session, effect),
            )
            .ok_or(crate::rpc::RpcRegistrationRefusal::SessionNotCurrent)?
    }

    pub(crate) fn abandon_rpc_request(
        &self,
        state: &crate::engine::state::NetworkState,
        peer: &str,
        filed: &crate::rpc::LocalRequest,
    ) {
        let Some(owner) = state.peers.owner(peer) else {
            return;
        };
        let _ = state.peers.with_live_session_state(
            &owner,
            state.session_broker.as_ref(),
            &state.network_id,
            |_session, app| app.rpc_mut().abandon_local_request(filed),
        );
    }

    pub(crate) async fn send_rpc_request(
        &self,
        state: &crate::engine::state::NetworkState,
        peer: &str,
        request: crate::protocol::rpc::RpcRequestMessage,
    ) -> crate::error::Result<()> {
        let (reply, rx) = tokio::sync::oneshot::channel();
        state
            .cmd_tx
            .send(crate::engine::state::NetworkCmd::SendRpcRequest {
                peer: peer.to_string(),
                request,
                reply,
            })
            .map_err(|error| error.into_admission_error())?;
        rx.await
            .map_err(|_| crate::error::Error::Network("engine dropped reply".into()))?
    }
}
