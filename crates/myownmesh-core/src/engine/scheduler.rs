//! Checked per-network scheduler policy plumbing.
//!
//! Timing and bounded-work choices are persisted in
//! [`crate::config::SchedulerPolicyConfig`]. This module deliberately does
//! not retain process-wide production constants: every engine path must copy
//! the checked policy from its owning [`crate::config::NetworkConfig`] before
//! starting a timer, task, or bounded await.

/// The inbound staleness horizon is a signaling dependency contract, not an
/// engine scheduler choice. Keep its single source in the signaling crate.
pub use myownmesh_signaling::upstream::STALE_INBOUND_MS;
