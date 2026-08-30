//! Closed-member opaque relay runtime.
//!
//! A relay allocation owns only a bounded ciphertext queue and lifecycle
//! witnesses. Endpoint key material lives in [`OpaqueRelaySession`] and never
//! crosses into this relay-side port.

use std::sync::Arc;
use std::time::{Duration, Instant};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use parking_lot::Mutex;
use rand_core::OsRng;
use sha2::Sha256;
use thiserror::Error;
use tokio::sync::mpsc;
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::config::ClosedRelayPolicyConfig;
use crate::identity::Identity;
use crate::protocol::relay::{
    OpaqueRelayPacket, RelayKeyShare, OPAQUE_RELAY_NONCE_BYTES, OPAQUE_RELAY_VERSION,
};
use crate::resource::{ResourceClaim, ResourceClass, ResourceLease};
use crate::runtime::session_broker::SessionValidityWitness;
use crate::semantic::{DeviceId, MeshContextId};

const AEAD_TAG_BYTES: usize = 16;
const KEY_BYTES: usize = 32;
const NONCE_PREFIX_BYTES: usize = 4;
const DERIVED_BYTES: usize = KEY_BYTES * 2 + NONCE_PREFIX_BYTES * 2;

/// Convert the owner-selected plaintext ceiling into the corresponding wire
/// ciphertext ceiling.  The AEAD tag is part of the ciphertext, and the
/// conversion is checked so malformed platform-sized values fail closed.
pub(crate) fn checked_ciphertext_ceiling(
    plaintext_ceiling: u64,
) -> Result<usize, ClosedRelayRefusal> {
    usize::try_from(plaintext_ceiling)
        .ok()
        .and_then(|value| value.checked_add(AEAD_TAG_BYTES))
        .ok_or(ClosedRelayRefusal::InvalidProfile)
}

/// Typed failures at the relay and endpoint envelope boundaries.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ClosedRelayRefusal {
    #[error("closed relay profile is invalid")]
    InvalidProfile,
    #[error("closed relay owner witness is not live")]
    OwnerNotLive,
    #[error("closed relay owner witnesses do not match")]
    OwnerMismatch,
    #[error("closed relay endpoints are invalid: {0}")]
    InvalidEndpoints(String),
    #[error("closed relay packet is invalid: {0}")]
    InvalidPacket(String),
    #[error("closed relay queue is full")]
    QueueFull,
    #[error("closed relay queue is closed")]
    QueueClosed,
    #[error("closed relay carrier is unavailable")]
    CarrierUnavailable,
    #[error("closed relay allocation expired")]
    Expired,
    #[error("closed relay cryptographic operation failed: {0}")]
    Crypto(String),
}

/// The two independently bounded directions of one A–B–C allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayDirection {
    RequesterToTarget,
    TargetToRequester,
}

impl RelayDirection {
    const fn index(self) -> usize {
        match self {
            Self::RequesterToTarget => 0,
            Self::TargetToRequester => 1,
        }
    }
}

/// Route metadata for one exact closed allocation. It contains no IP address,
/// fanout selector, endpoint key, or authority-bearing capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClosedRelayEndpoints {
    pub mesh: MeshContextId,
    pub requester: DeviceId,
    pub target: DeviceId,
    pub session_id: [u8; 16],
}

impl ClosedRelayEndpoints {
    pub(crate) fn new(
        mesh: MeshContextId,
        requester: DeviceId,
        target: DeviceId,
        session_id: [u8; 16],
    ) -> Result<Self, ClosedRelayRefusal> {
        let endpoints = Self {
            mesh: mesh.into(),
            requester: requester.into(),
            target: target.into(),
            session_id,
        };
        endpoints.validate()?;
        Ok(endpoints)
    }

    fn validate(&self) -> Result<(), ClosedRelayRefusal> {
        if self.requester == self.target {
            return Err(ClosedRelayRefusal::InvalidEndpoints(
                "requester and target must differ".into(),
            ));
        }
        Ok(())
    }
}

/// A provider-backed, move-only lease for one closed relay allocation.
///
/// There is no public constructor: the engine must first present an exact
/// current session witness, so a caller cannot fabricate relay authority from
/// route strings alone.
pub struct RelayAllocationPermit {
    owner: SessionValidityWitness,
    _lease: ResourceLease,
}

impl RelayAllocationPermit {
    pub(crate) fn allocation_claim(
        profile: &ClosedRelayPolicyConfig,
    ) -> Result<ResourceClaim, ClosedRelayRefusal> {
        if !profile.enabled || !profile.validate() {
            return Err(ClosedRelayRefusal::InvalidProfile);
        }
        let queue = usize::try_from(profile.queue_items_per_direction)
            .map_err(|_| ClosedRelayRefusal::InvalidProfile)?;
        let queue_bytes = queue
            .checked_mul(std::mem::size_of::<OpaqueRelayPacket>())
            .and_then(|value| value.checked_mul(2))
            .ok_or(ClosedRelayRefusal::InvalidProfile)?;
        let bytes = std::mem::size_of::<Self>()
            .checked_add(std::mem::size_of::<ClosedRelayHandle>())
            .and_then(|value| value.checked_add(queue_bytes))
            .ok_or(ClosedRelayRefusal::InvalidProfile)?;
        ResourceClaim::try_from_entries([
            (
                ResourceClass::AccountedMemoryBytes,
                u64::try_from(bytes).map_err(|_| ClosedRelayRefusal::InvalidProfile)?,
            ),
            (ResourceClass::OpaqueDependencyResidual, 2),
        ])
        .map_err(|_| ClosedRelayRefusal::InvalidProfile)
    }

    pub(crate) fn try_new(
        owner: SessionValidityWitness,
        profile: &ClosedRelayPolicyConfig,
    ) -> Result<Self, ClosedRelayRefusal> {
        if !profile.enabled || !profile.validate() {
            return Err(ClosedRelayRefusal::InvalidProfile);
        }
        if !owner.is_live() {
            return Err(ClosedRelayRefusal::OwnerNotLive);
        }
        let claim = Self::allocation_claim(profile)?;
        let lease = owner
            .reserve_retained(claim)
            .map_err(|_| ClosedRelayRefusal::OwnerNotLive)?;
        Ok(Self {
            owner,
            _lease: lease,
        })
    }
}

/// Runtime port for relay-side allocation admission and settlement.
pub struct ClosedRelayRuntime {
    profile: ClosedRelayPolicyConfig,
    local_device_id: DeviceId,
    state: Arc<Mutex<RelayAdmissionState>>,
}

impl ClosedRelayRuntime {
    pub(crate) fn new(
        profile: ClosedRelayPolicyConfig,
        local_device_id: DeviceId,
    ) -> Result<Self, ClosedRelayRefusal> {
        if !profile.enabled || !profile.validate() {
            return Err(ClosedRelayRefusal::InvalidProfile);
        }
        usize::try_from(profile.max_allocations).map_err(|_| ClosedRelayRefusal::InvalidProfile)?;
        Ok(Self {
            profile,
            local_device_id,
            state: Arc::new(Mutex::new(RelayAdmissionState {
                active_allocations: Vec::new(),
                pending_handshakes: 0,
                next_allocation_id: 0,
            })),
        })
    }

    /// The owner-selected grace interval retained by shutdown coordinators.
    pub(crate) fn shutdown_grace(&self) -> Duration {
        Duration::from_millis(self.profile.shutdown_grace_ms)
    }

    pub(crate) fn try_begin_handshake(
        &self,
    ) -> Result<ClosedRelayHandshakeGuard, ClosedRelayRefusal> {
        let mut state = self.state.lock();
        let limit = usize::try_from(self.profile.max_pending_handshakes)
            .map_err(|_| ClosedRelayRefusal::InvalidProfile)?;
        if state.pending_handshakes >= limit {
            return Err(ClosedRelayRefusal::QueueFull);
        }
        state.pending_handshakes += 1;
        Ok(ClosedRelayHandshakeGuard {
            state: Arc::clone(&self.state),
        })
    }

    pub(crate) fn admit_closed_relay(
        &self,
        permit: RelayAllocationPermit,
        requester: SessionValidityWitness,
        target: SessionValidityWitness,
        endpoints: ClosedRelayEndpoints,
    ) -> Result<ClosedRelayHandle, ClosedRelayRefusal> {
        if !requester.is_live() || !target.is_live() {
            return Err(ClosedRelayRefusal::OwnerNotLive);
        }
        if !permit.owner.same_validity(&requester) {
            return Err(ClosedRelayRefusal::OwnerMismatch);
        }
        endpoints.validate()?;
        if endpoints.requester == self.local_device_id || endpoints.target == self.local_device_id {
            return Err(ClosedRelayRefusal::InvalidEndpoints(
                "relay host cannot be an endpoint".into(),
            ));
        }
        let capacity = usize::try_from(self.profile.queue_items_per_direction)
            .map_err(|_| ClosedRelayRefusal::InvalidProfile)?;
        let member = endpoints.requester.base32();
        let max_allocations = usize::try_from(self.profile.max_allocations)
            .map_err(|_| ClosedRelayRefusal::InvalidProfile)?;
        let max_per_member = usize::try_from(self.profile.max_allocations_per_member)
            .map_err(|_| ClosedRelayRefusal::InvalidProfile)?;
        let max_ciphertext_bytes =
            checked_ciphertext_ceiling(self.profile.max_frame_ciphertext_bytes)?;
        let max_control_bytes = usize::try_from(self.profile.max_control_bytes)
            .map_err(|_| ClosedRelayRefusal::InvalidProfile)?;
        let queue_bytes_capacity = usize::try_from(self.profile.queue_bytes_per_direction)
            .map_err(|_| ClosedRelayRefusal::InvalidProfile)?;
        {
            let mut state = self.state.lock();
            if state.active_allocations.len() >= max_allocations
                || state
                    .active_allocations
                    .iter()
                    .filter(|active| active.member == member)
                    .count()
                    >= max_per_member
            {
                return Err(ClosedRelayRefusal::QueueFull);
            }
            let allocation_id = state.next_allocation_id;
            state.next_allocation_id = state
                .next_allocation_id
                .checked_add(1)
                .ok_or(ClosedRelayRefusal::InvalidProfile)?;
            state.active_allocations.push(ActiveAllocation {
                id: allocation_id,
                member: member.clone(),
            });
            let (requester_tx, requester_rx) = mpsc::channel(capacity);
            let (target_tx, target_rx) = mpsc::channel(capacity);
            return Ok(ClosedRelayHandle {
                permit,
                requester,
                target,
                endpoints,
                max_ciphertext_bytes,
                max_control_bytes,
                queue_items_capacity: capacity,
                queue_bytes_capacity,
                queue: Mutex::new([QueueAccounting::default(), QueueAccounting::default()]),
                bandwidth: Mutex::new(BandwidthBucket::new(
                    self.profile.bandwidth_rate_bytes_per_second,
                    self.profile.bandwidth_burst_bytes,
                )),
                state: Arc::clone(&self.state),
                allocation_id,
                opened_at: Instant::now(),
                last_activity: Instant::now(),
                idle_timeout: Duration::from_millis(self.profile.idle_timeout_ms),
                lifetime: Duration::from_millis(self.profile.max_lifetime_ms),
                shutdown_grace: Duration::from_millis(self.profile.shutdown_grace_ms),
                requester_tx,
                requester_rx,
                target_tx,
                target_rx,
                settled: false,
            });
        }
    }
}

/// One exact relay allocation. This is intentionally keyless: it can forward
/// an endpoint-authenticated ciphertext but cannot decrypt or mint authority.
pub struct ClosedRelayHandle {
    permit: RelayAllocationPermit,
    requester: SessionValidityWitness,
    target: SessionValidityWitness,
    endpoints: ClosedRelayEndpoints,
    max_ciphertext_bytes: usize,
    max_control_bytes: usize,
    queue_items_capacity: usize,
    queue_bytes_capacity: usize,
    queue: Mutex<[QueueAccounting; 2]>,
    bandwidth: Mutex<BandwidthBucket>,
    state: Arc<Mutex<RelayAdmissionState>>,
    allocation_id: u64,
    opened_at: Instant,
    last_activity: Instant,
    idle_timeout: Duration,
    lifetime: Duration,
    shutdown_grace: Duration,
    requester_tx: mpsc::Sender<OpaqueRelayPacket>,
    requester_rx: mpsc::Receiver<OpaqueRelayPacket>,
    target_tx: mpsc::Sender<OpaqueRelayPacket>,
    target_rx: mpsc::Receiver<OpaqueRelayPacket>,
    settled: bool,
}

impl ClosedRelayHandle {
    pub(crate) fn try_forward(
        &mut self,
        packet: OpaqueRelayPacket,
    ) -> Result<(), ClosedRelayRefusal> {
        let requester = self.endpoints.requester.base32();
        let target = self.endpoints.target.base32();
        let direction = if packet.from == requester && packet.to == target {
            RelayDirection::RequesterToTarget
        } else if packet.from == target && packet.to == requester {
            RelayDirection::TargetToRequester
        } else {
            return Err(ClosedRelayRefusal::InvalidPacket(
                "packet route does not match allocation".into(),
            ));
        };
        self.try_forward_direction(direction, packet)
    }

    pub(crate) fn try_forward_direction(
        &mut self,
        direction: RelayDirection,
        packet: OpaqueRelayPacket,
    ) -> Result<(), ClosedRelayRefusal> {
        self.ensure_active()?;
        packet
            .validate(self.max_ciphertext_bytes)
            .map_err(ClosedRelayRefusal::InvalidPacket)?;
        let (from, to) = match direction {
            RelayDirection::RequesterToTarget => (
                self.endpoints.requester.base32(),
                self.endpoints.target.base32(),
            ),
            RelayDirection::TargetToRequester => (
                self.endpoints.target.base32(),
                self.endpoints.requester.base32(),
            ),
        };
        if packet.mesh != self.endpoints.mesh.base32()
            || packet.session_id != self.endpoints.session_id
            || packet.from != from
            || packet.to != to
        {
            return Err(ClosedRelayRefusal::InvalidPacket(
                "packet route does not match allocation".into(),
            ));
        }
        let bytes = packet.ciphertext.len();
        let mut queue = self.queue.lock();
        let queue = &mut queue[direction.index()];
        if queue.items >= self.queue_items_capacity
            || queue
                .bytes
                .checked_add(bytes)
                .is_none_or(|total| total > self.queue_bytes_capacity)
        {
            return Err(ClosedRelayRefusal::QueueFull);
        }
        if !self.bandwidth.lock().consume(bytes) {
            return Err(ClosedRelayRefusal::QueueFull);
        }
        let sender = match direction {
            RelayDirection::RequesterToTarget => &self.requester_tx,
            RelayDirection::TargetToRequester => &self.target_tx,
        };
        sender.try_send(packet).map_err(|error| match error {
            mpsc::error::TrySendError::Full(_) => ClosedRelayRefusal::QueueFull,
            mpsc::error::TrySendError::Closed(_) => ClosedRelayRefusal::QueueClosed,
        })?;
        queue.items += 1;
        queue.bytes += bytes;
        self.last_activity = Instant::now();
        Ok(())
    }

    pub(crate) fn try_forward_control(
        &mut self,
        packet: OpaqueRelayPacket,
    ) -> Result<(), ClosedRelayRefusal> {
        if packet.ciphertext.len() > self.max_control_bytes {
            return Err(ClosedRelayRefusal::InvalidPacket(
                "control packet exceeds configured bound".into(),
            ));
        }
        self.try_forward(packet)
    }

    pub(crate) fn try_forward_control_direction(
        &mut self,
        direction: RelayDirection,
        packet: OpaqueRelayPacket,
    ) -> Result<(), ClosedRelayRefusal> {
        if packet.ciphertext.len() > self.max_control_bytes {
            return Err(ClosedRelayRefusal::InvalidPacket(
                "control packet exceeds configured bound".into(),
            ));
        }
        self.try_forward_direction(direction, packet)
    }

    pub(crate) async fn recv(&mut self) -> Option<OpaqueRelayPacket> {
        self.ensure_active().ok()?;
        let deadline = self.expiration_deadline()?;
        let sleep = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline));
        tokio::pin!(sleep);
        let (direction, packet) = tokio::select! {
            packet = self.requester_rx.recv() => Some((RelayDirection::RequesterToTarget, packet)),
            packet = self.target_rx.recv() => Some((RelayDirection::TargetToRequester, packet)),
            _ = &mut sleep => None,
        }?;
        let packet = packet?;
        self.account_received(direction, packet)
    }

    pub(crate) async fn recv_direction(
        &mut self,
        direction: RelayDirection,
    ) -> Option<OpaqueRelayPacket> {
        self.ensure_active().ok()?;
        let deadline = self.expiration_deadline()?;
        let sleep = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline));
        tokio::pin!(sleep);
        let packet = match direction {
            RelayDirection::RequesterToTarget => tokio::select! {
                packet = self.requester_rx.recv() => packet,
                _ = &mut sleep => None,
            },
            RelayDirection::TargetToRequester => tokio::select! {
                packet = self.target_rx.recv() => packet,
                _ = &mut sleep => None,
            },
        }?;
        self.account_received(direction, packet)
    }

    fn account_received(
        &mut self,
        direction: RelayDirection,
        packet: OpaqueRelayPacket,
    ) -> Option<OpaqueRelayPacket> {
        let bytes = packet.ciphertext.len();
        let mut queue = self.queue.lock();
        let queue = &mut queue[direction.index()];
        queue.items = queue.items.saturating_sub(1);
        queue.bytes = queue.bytes.saturating_sub(bytes);
        self.last_activity = Instant::now();
        Some(packet)
    }

    pub(crate) fn settle(mut self) -> ClosedRelayTerminal {
        self.release_allocation();
        self.settled = true;
        ClosedRelayTerminal::Settled
    }

    /// The policy-owned shutdown grace used by a caller coordinating close.
    pub(crate) fn shutdown_grace(&self) -> Duration {
        self.shutdown_grace
    }

    /// Transfer the exact allocation into a shutdown owner. The provider
    /// lease remains held while the caller drains or closes both directions;
    /// no later admission can reuse this allocation until `settle` consumes
    /// that owner.
    pub(crate) fn begin_shutdown(self) -> ClosedRelayShutdown {
        let now = Instant::now();
        let deadline = now.checked_add(self.shutdown_grace).unwrap_or(now);
        ClosedRelayShutdown {
            handle: Some(self),
            deadline,
        }
    }

    fn ensure_active(&self) -> Result<(), ClosedRelayRefusal> {
        if self.settled {
            return Err(ClosedRelayRefusal::OwnerNotLive);
        }
        if !self.requester.is_live() || !self.target.is_live() {
            return Err(ClosedRelayRefusal::OwnerNotLive);
        }
        let now = Instant::now();
        if now.duration_since(self.opened_at) >= self.lifetime
            || now.duration_since(self.last_activity) >= self.idle_timeout
        {
            return Err(ClosedRelayRefusal::Expired);
        }
        Ok(())
    }

    fn expiration_deadline(&self) -> Option<Instant> {
        let lifetime = self.opened_at.checked_add(self.lifetime)?;
        let idle = self.last_activity.checked_add(self.idle_timeout)?;
        Some(lifetime.min(idle))
    }

    fn release_allocation(&mut self) {
        let mut state = self.state.lock();
        if let Some(index) = state
            .active_allocations
            .iter()
            .position(|active| active.id == self.allocation_id)
        {
            state.active_allocations.swap_remove(index);
        }
    }
}

impl Drop for ClosedRelayHandle {
    fn drop(&mut self) {
        if self.settled {
            return;
        }
        self.release_allocation();
        self.settled = true;
    }
}

/// Exact owner of a relay allocation during its configured shutdown grace.
pub(crate) struct ClosedRelayShutdown {
    handle: Option<ClosedRelayHandle>,
    deadline: Instant,
}

impl ClosedRelayShutdown {
    pub(crate) fn deadline(&self) -> Instant {
        self.deadline
    }

    pub(crate) fn settle(mut self) -> ClosedRelayTerminal {
        self.handle
            .take()
            .expect("shutdown owner has exactly one relay handle")
            .settle()
    }
}

#[derive(Default)]
struct QueueAccounting {
    items: usize,
    bytes: usize,
}

struct RelayAdmissionState {
    active_allocations: Vec<ActiveAllocation>,
    pending_handshakes: usize,
    next_allocation_id: u64,
}

struct ActiveAllocation {
    id: u64,
    member: String,
}

pub(crate) struct ClosedRelayHandshakeGuard {
    state: Arc<Mutex<RelayAdmissionState>>,
}

impl Drop for ClosedRelayHandshakeGuard {
    fn drop(&mut self) {
        let mut state = self.state.lock();
        state.pending_handshakes = state.pending_handshakes.saturating_sub(1);
    }
}

struct BandwidthBucket {
    rate: u64,
    burst: u64,
    tokens: u64,
    last: Instant,
}

impl BandwidthBucket {
    fn new(rate: u64, burst: u64) -> Self {
        Self {
            rate,
            burst,
            tokens: burst,
            last: Instant::now(),
        }
    }

    fn consume(&mut self, bytes: usize) -> bool {
        let elapsed = self.last.elapsed();
        let Some(refill) = u128::from(self.rate)
            .checked_mul(elapsed.as_nanos())
            .and_then(|value| value.checked_div(1_000_000_000))
            .and_then(|value| u64::try_from(value).ok())
        else {
            return false;
        };
        self.tokens = self.tokens.saturating_add(refill).min(self.burst);
        self.last = Instant::now();
        let Ok(bytes) = u64::try_from(bytes) else {
            return false;
        };
        if bytes > self.tokens {
            return false;
        }
        self.tokens -= bytes;
        true
    }
}

/// Exactly one terminal transition for a consumed relay allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClosedRelayTerminal {
    Settled,
}

/// Pending endpoint side of the authenticated key agreement. This object is
/// move-only so the ephemeral secret cannot be copied into relay state.
pub struct PendingEndpointKeyAgreement {
    mesh: MeshContextId,
    local_id: DeviceId,
    peer_id: DeviceId,
    session_id: [u8; 16],
    local_public: [u8; 32],
    secret: EphemeralSecret,
    max_packet_bytes: usize,
    replay_window: usize,
    _handshake: Option<ClosedRelayHandshakeGuard>,
}

impl PendingEndpointKeyAgreement {
    /// Begin endpoint negotiation through the runtime's bounded handshake
    /// admission. The guard stays owned by the move-only pending agreement
    /// until finish or refusal, so a production caller cannot bypass the
    /// configured pending-handshake ceiling.
    pub(crate) fn begin_with_runtime(
        runtime: &ClosedRelayRuntime,
        identity: &Identity,
        mesh: MeshContextId,
        peer_id: DeviceId,
        session_id: [u8; 16],
        profile: &ClosedRelayPolicyConfig,
    ) -> Result<(Self, RelayKeyShare), ClosedRelayRefusal> {
        let guard = runtime.try_begin_handshake()?;
        let (mut pending, share) = Self::begin(identity, mesh, peer_id, session_id, profile)?;
        pending._handshake = Some(guard);
        Ok((pending, share))
    }

    pub(crate) fn begin(
        identity: &Identity,
        mesh: MeshContextId,
        peer_id: DeviceId,
        session_id: [u8; 16],
        profile: &ClosedRelayPolicyConfig,
    ) -> Result<(Self, RelayKeyShare), ClosedRelayRefusal> {
        if !profile.validate() {
            return Err(ClosedRelayRefusal::InvalidProfile);
        }
        let local_id = DeviceId::from_canonical_str(identity.public_id())
            .map_err(ClosedRelayRefusal::Crypto)?;
        if local_id == peer_id {
            return Err(ClosedRelayRefusal::Crypto(
                "endpoint key agreement requires distinct peers".into(),
            ));
        }
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let local_public = PublicKey::from(&secret).to_bytes();
        let mut share = RelayKeyShare {
            version: OPAQUE_RELAY_VERSION,
            mesh: mesh.base32(),
            session_id,
            from: local_id.base32(),
            to: peer_id.base32(),
            ephemeral_public: local_public,
            signature: String::new(),
        };
        share.signature = crate::signing::sign_with(identity.signing_key(), &share.signing_bytes());
        Ok((
            Self {
                mesh,
                local_id,
                peer_id,
                session_id,
                local_public,
                secret,
                max_packet_bytes: usize::try_from(profile.max_frame_ciphertext_bytes)
                    .map_err(|_| ClosedRelayRefusal::InvalidProfile)?,
                replay_window: usize::try_from(profile.replay_window)
                    .map_err(|_| ClosedRelayRefusal::InvalidProfile)?,
                _handshake: None,
            },
            share,
        ))
    }

    pub(crate) fn finish(
        self,
        peer_share: &RelayKeyShare,
    ) -> Result<OpaqueRelaySession, ClosedRelayRefusal> {
        peer_share.validate().map_err(ClosedRelayRefusal::Crypto)?;
        if peer_share.mesh != self.mesh.base32()
            || peer_share.session_id != self.session_id
            || peer_share.from != self.peer_id.base32()
            || peer_share.to != self.local_id.base32()
        {
            return Err(ClosedRelayRefusal::Crypto(
                "key-share context does not match pending endpoint".into(),
            ));
        }
        if !crate::signing::verify(
            &peer_share.from,
            &peer_share.signing_bytes(),
            &peer_share.signature,
        )
        .map_err(|error| ClosedRelayRefusal::Crypto(error.to_string()))?
        {
            return Err(ClosedRelayRefusal::Crypto(
                "peer key-share signature did not verify".into(),
            ));
        }
        let peer_public = PublicKey::from(peer_share.ephemeral_public);
        let shared = self.secret.diffie_hellman(&peer_public);
        if shared.as_bytes().iter().all(|byte| *byte == 0) {
            return Err(ClosedRelayRefusal::Crypto(
                "peer supplied a low-order X25519 key".into(),
            ));
        }
        let mut info = Vec::new();
        info.extend_from_slice(b"myownmesh-closed-opaque-relay-session-v1:");
        push_field(&mut info, self.mesh.base32().as_bytes());
        info.extend_from_slice(&self.session_id);
        let (first_id, second_id, first_key, second_key) = if self.local_id < self.peer_id {
            (
                &self.local_id,
                &self.peer_id,
                &self.local_public,
                &peer_share.ephemeral_public,
            )
        } else {
            (
                &self.peer_id,
                &self.local_id,
                &peer_share.ephemeral_public,
                &self.local_public,
            )
        };
        let first_id_bytes = first_id.as_bytes();
        let second_id_bytes = second_id.as_bytes();
        push_field(&mut info, &first_id_bytes);
        push_field(&mut info, &second_id_bytes);
        info.extend_from_slice(first_key);
        info.extend_from_slice(second_key);
        let hk = Hkdf::<Sha256>::new(None, shared.as_bytes());
        let mut material = [0u8; DERIVED_BYTES];
        hk.expand(&info, &mut material)
            .map_err(|_| ClosedRelayRefusal::Crypto("HKDF expansion failed".into()))?;
        let first_key = &material[..KEY_BYTES];
        let second_key = &material[KEY_BYTES..KEY_BYTES * 2];
        let first_prefix = &material[KEY_BYTES * 2..KEY_BYTES * 2 + NONCE_PREFIX_BYTES];
        let second_prefix = &material[KEY_BYTES * 2 + NONCE_PREFIX_BYTES..];
        let (send_key, recv_key, send_prefix, recv_prefix) = if self.local_id < self.peer_id {
            (first_key, second_key, first_prefix, second_prefix)
        } else {
            (second_key, first_key, second_prefix, first_prefix)
        };
        let mut send_key_bytes = [0u8; KEY_BYTES];
        let mut recv_key_bytes = [0u8; KEY_BYTES];
        let mut send_prefix_bytes = [0u8; NONCE_PREFIX_BYTES];
        let mut recv_prefix_bytes = [0u8; NONCE_PREFIX_BYTES];
        send_key_bytes.copy_from_slice(send_key);
        recv_key_bytes.copy_from_slice(recv_key);
        send_prefix_bytes.copy_from_slice(send_prefix);
        recv_prefix_bytes.copy_from_slice(recv_prefix);
        Ok(OpaqueRelaySession {
            mesh: self.mesh,
            local_id: self.local_id,
            peer_id: self.peer_id,
            session_id: self.session_id,
            send_key: send_key_bytes,
            recv_key: recv_key_bytes,
            send_prefix: send_prefix_bytes,
            recv_prefix: recv_prefix_bytes,
            next_send_sequence: 0,
            replay: ReplayWindow::new(self.replay_window),
            max_packet_bytes: self.max_packet_bytes,
        })
    }
}

/// Endpoint-only AEAD session. The relay runtime never receives this type.
pub struct OpaqueRelaySession {
    mesh: MeshContextId,
    local_id: DeviceId,
    peer_id: DeviceId,
    session_id: [u8; 16],
    send_key: [u8; KEY_BYTES],
    recv_key: [u8; KEY_BYTES],
    send_prefix: [u8; NONCE_PREFIX_BYTES],
    recv_prefix: [u8; NONCE_PREFIX_BYTES],
    next_send_sequence: u64,
    replay: ReplayWindow,
    max_packet_bytes: usize,
}

impl OpaqueRelaySession {
    pub(crate) fn seal(
        &mut self,
        plaintext: &[u8],
    ) -> Result<OpaqueRelayPacket, ClosedRelayRefusal> {
        if plaintext.len() > self.max_packet_bytes {
            return Err(ClosedRelayRefusal::InvalidPacket(
                "plaintext exceeds configured bound".into(),
            ));
        }
        let sequence = self.next_send_sequence;
        self.next_send_sequence = sequence
            .checked_add(1)
            .ok_or_else(|| ClosedRelayRefusal::Crypto("send sequence exhausted".into()))?;
        let nonce = nonce_for(self.send_prefix, sequence);
        let mesh = self.mesh.base32();
        let local_id = self.local_id.base32();
        let peer_id = self.peer_id.base32();
        let aad = aad_for(&mesh, &self.session_id, &local_id, &peer_id, sequence);
        let cipher = Aes256Gcm::new_from_slice(&self.send_key)
            .map_err(|_| ClosedRelayRefusal::Crypto("invalid AES key".into()))?;
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| ClosedRelayRefusal::Crypto("AEAD seal failed".into()))?;
        let packet = OpaqueRelayPacket {
            version: OPAQUE_RELAY_VERSION,
            mesh,
            session_id: self.session_id,
            from: local_id,
            to: peer_id,
            sequence,
            nonce,
            ciphertext,
        };
        packet
            .validate(
                self.max_packet_bytes
                    .checked_add(AEAD_TAG_BYTES)
                    .ok_or(ClosedRelayRefusal::InvalidProfile)?,
            )
            .map_err(ClosedRelayRefusal::InvalidPacket)?;
        Ok(packet)
    }

    pub(crate) fn open(
        &mut self,
        packet: &OpaqueRelayPacket,
    ) -> Result<Vec<u8>, ClosedRelayRefusal> {
        packet
            .validate(
                self.max_packet_bytes
                    .checked_add(AEAD_TAG_BYTES)
                    .ok_or(ClosedRelayRefusal::InvalidProfile)?,
            )
            .map_err(ClosedRelayRefusal::InvalidPacket)?;
        if packet.mesh != self.mesh.base32()
            || packet.session_id != self.session_id
            || packet.from != self.peer_id.base32()
            || packet.to != self.local_id.base32()
            || packet.nonce != nonce_for(self.recv_prefix, packet.sequence)
        {
            return Err(ClosedRelayRefusal::InvalidPacket(
                "packet context or nonce does not match session".into(),
            ));
        }
        if !self.replay.can_accept(packet.sequence) {
            return Err(ClosedRelayRefusal::InvalidPacket(
                "packet replayed or outside replay window".into(),
            ));
        }
        let aad = aad_for(
            &self.mesh.base32(),
            &self.session_id,
            &packet.from,
            &packet.to,
            packet.sequence,
        );
        let cipher = Aes256Gcm::new_from_slice(&self.recv_key)
            .map_err(|_| ClosedRelayRefusal::Crypto("invalid AES key".into()))?;
        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(&packet.nonce),
                Payload {
                    msg: &packet.ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| ClosedRelayRefusal::Crypto("AEAD open failed".into()))?;
        self.replay.record(packet.sequence);
        Ok(plaintext)
    }
}

struct ReplayWindow {
    width: usize,
    highest: Option<u64>,
    seen: Vec<bool>,
}

impl ReplayWindow {
    fn new(width: usize) -> Self {
        Self {
            width,
            highest: None,
            seen: vec![false; width],
        }
    }

    fn can_accept(&self, sequence: u64) -> bool {
        let Some(highest) = self.highest else {
            return true;
        };
        if sequence > highest {
            return true;
        }
        let delta = highest - sequence;
        delta < self.width as u64 && !self.seen[delta as usize]
    }

    fn record(&mut self, sequence: u64) {
        let Some(highest) = self.highest else {
            self.highest = Some(sequence);
            self.seen[0] = true;
            return;
        };
        if sequence > highest {
            let advance = sequence - highest;
            if advance >= self.width as u64 {
                self.seen.fill(false);
            } else {
                self.seen.rotate_right(advance as usize);
                self.seen[..advance as usize].fill(false);
            }
            self.highest = Some(sequence);
            self.seen[0] = true;
        } else {
            self.seen[(highest - sequence) as usize] = true;
        }
    }
}

fn nonce_for(prefix: [u8; NONCE_PREFIX_BYTES], sequence: u64) -> [u8; OPAQUE_RELAY_NONCE_BYTES] {
    let mut nonce = [0u8; OPAQUE_RELAY_NONCE_BYTES];
    nonce[..NONCE_PREFIX_BYTES].copy_from_slice(&prefix);
    nonce[NONCE_PREFIX_BYTES..].copy_from_slice(&sequence.to_be_bytes());
    nonce
}

fn aad_for(mesh: &str, session_id: &[u8; 16], from: &str, to: &str, sequence: u64) -> Vec<u8> {
    let mut aad = Vec::new();
    aad.extend_from_slice(b"myownmesh-closed-opaque-relay-packet-v1:");
    push_field(&mut aad, mesh.as_bytes());
    aad.extend_from_slice(session_id);
    push_field(&mut aad, from.as_bytes());
    push_field(&mut aad, to.as_bytes());
    aad.extend_from_slice(&sequence.to_be_bytes());
    aad
}

fn push_field(output: &mut Vec<u8>, field: &[u8]) {
    output.extend_from_slice(&u64::try_from(field.len()).unwrap_or(u64::MAX).to_be_bytes());
    output.extend_from_slice(field);
}

#[cfg(test)]
mod behavior_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_aead_round_trip_and_replay_fence() {
        let profile = ClosedRelayPolicyConfig::default();
        let alice = Identity::ephemeral();
        let bob = Identity::ephemeral();
        let mesh = MeshContextId::from_bytes([3; 32]);
        let alice_id = DeviceId::from_canonical_str(alice.public_id()).expect("alice id");
        let bob_id = DeviceId::from_canonical_str(bob.public_id()).expect("bob id");
        let (alice_pending, alice_share) =
            PendingEndpointKeyAgreement::begin(&alice, mesh, bob_id.clone(), [7; 16], &profile)
                .expect("alice key share");
        let (bob_pending, bob_share) =
            PendingEndpointKeyAgreement::begin(&bob, mesh, alice_id, [7; 16], &profile)
                .expect("bob key share");
        let mut alice_session = alice_pending.finish(&bob_share).expect("alice session");
        let mut bob_session = bob_pending.finish(&alice_share).expect("bob session");
        let packet = alice_session.seal(b"opaque").expect("seal");
        assert_eq!(bob_session.open(&packet).expect("open"), b"opaque");
        assert!(bob_session.open(&packet).is_err(), "replay must be refused");
    }

    #[test]
    fn relay_profile_refuses_zero_queue_and_oversized_packets() {
        let zero = ClosedRelayPolicyConfig {
            queue_items_per_direction: 0,
            ..ClosedRelayPolicyConfig::default()
        };
        assert!(!zero.validate());
        let oversized = ClosedRelayPolicyConfig {
            max_frame_ciphertext_bytes: crate::config::MAX_CLOSED_RELAY_PACKET_BYTES + 1,
            ..ClosedRelayPolicyConfig::default()
        };
        assert!(!oversized.validate());
    }

    #[test]
    fn relay_profile_accepts_only_the_sctp_safe_plaintext_boundary() {
        let exact = ClosedRelayPolicyConfig {
            max_frame_ciphertext_bytes: crate::protocol::relay::CLOSED_RELAY_MAX_PLAINTEXT_BYTES,
            ..ClosedRelayPolicyConfig::default()
        };
        assert!(exact.validate());
        assert_eq!(
            checked_ciphertext_ceiling(exact.max_frame_ciphertext_bytes)
                .expect("safe plaintext boundary adds the AEAD tag"),
            usize::try_from(
                crate::protocol::relay::CLOSED_RELAY_MAX_PLAINTEXT_BYTES
                    + crate::protocol::relay::CLOSED_RELAY_AEAD_TAG_BYTES
            )
            .expect("safe boundary fits usize")
        );
        assert!(!ClosedRelayPolicyConfig {
            max_frame_ciphertext_bytes: crate::protocol::relay::CLOSED_RELAY_MAX_PLAINTEXT_BYTES
                + 1,
            ..exact
        }
        .validate());
    }
}
