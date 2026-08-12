//! The device services config: validate it against the live runtime, persist
//! it, then reconcile what is running.
//!
//! Persist-before-reconcile is deliberate and is the reason this is its own
//! module rather than an arm: a daemon restart must re-apply the config the
//! caller was told was saved, even when the live reconcile only partly took.

use std::sync::Arc;

use anyhow::Result;
use myownmesh_core::{MeshConfig, ServicesConfig};

use super::super::{ControlState, Response};

/// Replace the device services config: persist it, then reconcile the
/// running services. Persist first so a daemon restart re-applies the
/// same config even if the live reconcile partly fails (a failed service
/// start is logged inside `apply`, not surfaced as an error here).
pub(super) async fn services_set(state: &Arc<ControlState>, services: ServicesConfig) -> Response {
    // Validate against the live daemon before persistence. In particular, an
    // infrastructure-only runtime must not save node participation as enabled
    // when it has no connector resource owner capable of admitting that state.
    if let Err(e) = state.services.validate_config_for_runtime(&services) {
        return Response::err(format!("services policy rejected: {e}"));
    }
    if let Err(e) = persist_services(&services) {
        return Response::err(format!("services config save failed: {e}"));
    }
    let status = match state.services.apply(services).await {
        Ok(status) => status,
        Err(e) => return Response::err(format!("services policy rejected: {e}")),
    };
    Response::ok(serde_json::json!({ "status": status }))
}

fn persist_services(services: &ServicesConfig) -> Result<()> {
    let mut cfg = MeshConfig::load().map_err(anyhow::Error::msg)?;
    cfg.services = services.clone();
    cfg.save().map_err(anyhow::Error::msg)?;
    Ok(())
}
