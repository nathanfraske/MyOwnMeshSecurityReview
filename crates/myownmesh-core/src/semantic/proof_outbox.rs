//! Durable proof-delivery records.
//!
//! A proof record is an exact semantic delivery obligation.  Its identity is
//! derived only from the authenticated mesh context, target device, and the
//! canonical sorted fact set; owner and binding metadata describe custody but
//! cannot create a second delivery identity.  The records are persisted by
//! [`DurableSemanticStore`] in the same atomic snapshot as the semantic graph.

use data_encoding::BASE32_NOPAD;
use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use thiserror::Error;

use super::store::{DurableSemanticOwner, DurableSemanticStore, DurableStoreError};
use super::{DeviceId, FactId, MeshContextId};
use std::sync::Arc;

const PROOF_DELIVERY_DOMAIN: &[u8] = b"myownmesh-semantic-v4-proof-delivery-v1";
const PROOF_RECORD_VERSION: u16 = 1;

/// Stable identity for one exact proof delivery obligation.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProofDeliveryId([u8; 32]);

impl ProofDeliveryId {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn base32(&self) -> String {
        BASE32_NOPAD.encode(&self.0).to_lowercase()
    }

    /// Derive the delivery identity from exactly the context, target, and
    /// sorted/deduplicated fact identities.
    pub fn digest(context_id: MeshContextId, target: &DeviceId, fact_ids: &[FactId]) -> Self {
        let mut canonical = fact_ids.to_vec();
        canonical.sort();
        canonical.dedup();
        let mut hasher = Sha256::new();
        hasher.update(PROOF_DELIVERY_DOMAIN);
        hasher.update(context_id.as_bytes());
        hasher.update(target.as_bytes());
        hasher.update((canonical.len() as u64).to_be_bytes());
        for fact_id in canonical {
            hasher.update(fact_id.as_bytes());
        }
        let digest = hasher.finalize();
        let mut bytes = [0; 32];
        bytes.copy_from_slice(&digest);
        Self(bytes)
    }
}

impl std::fmt::Debug for ProofDeliveryId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("ProofDeliveryId")
            .field(&self.base32())
            .finish()
    }
}

impl std::fmt::Display for ProofDeliveryId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.base32())
    }
}

impl Serialize for ProofDeliveryId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.base32())
    }
}

impl<'de> Deserialize<'de> for ProofDeliveryId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        if encoded != encoded.to_lowercase() {
            return Err(D::Error::custom(
                "ProofDeliveryId must use lowercase base32",
            ));
        }
        let bytes = BASE32_NOPAD
            .decode(encoded.to_uppercase().as_bytes())
            .map_err(D::Error::custom)?;
        if bytes.len() != 32 {
            return Err(D::Error::custom("ProofDeliveryId must decode to 32 bytes"));
        }
        let mut value = [0; 32];
        value.copy_from_slice(&bytes);
        let id = Self(value);
        if encoded != id.base32() {
            return Err(D::Error::custom("ProofDeliveryId is not canonical base32"));
        }
        Ok(id)
    }
}

/// Terminal state retained for exact idempotent settlement and restart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofRecordState {
    Pending,
    Settled,
    Superseded,
}

/// One pending or settled proof delivery, including its exact custody
/// binding.  The fields are public for transport adapters, but every adapter
/// must pass [`ProofRecord::validate`] before using a record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofRecord {
    pub version: u16,
    pub context_id: MeshContextId,
    pub target: DeviceId,
    pub delivery_id: ProofDeliveryId,
    pub fact_ids: Vec<FactId>,
    pub owner: String,
    pub binding: String,
    pub state: ProofRecordState,
}

impl ProofRecord {
    /// Create a canonical pending record.  Fact identities are sorted and
    /// deduplicated before the stable delivery identity is derived.
    pub fn pending(
        context_id: MeshContextId,
        target: DeviceId,
        mut fact_ids: Vec<FactId>,
        owner: impl Into<String>,
        binding: impl Into<String>,
    ) -> Result<Self, ProofOutboxError> {
        fact_ids.sort();
        fact_ids.dedup();
        let delivery_id = ProofDeliveryId::digest(context_id, &target, &fact_ids);
        let record = Self {
            version: PROOF_RECORD_VERSION,
            context_id,
            target,
            delivery_id,
            fact_ids,
            owner: owner.into(),
            binding: binding.into(),
            state: ProofRecordState::Pending,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn validate(&self) -> Result<(), ProofOutboxError> {
        if self.version != PROOF_RECORD_VERSION {
            return Err(ProofOutboxError::InvalidRecord(format!(
                "unsupported proof record version {}",
                self.version
            )));
        }
        if self.fact_ids.is_empty() {
            return Err(ProofOutboxError::InvalidRecord(
                "proof record has no canonical facts".into(),
            ));
        }
        if self.fact_ids.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(ProofOutboxError::InvalidRecord(
                "proof fact identities are not sorted and unique".into(),
            ));
        }
        if self.owner.is_empty() || self.binding.is_empty() {
            return Err(ProofOutboxError::InvalidRecord(
                "proof owner and binding are required".into(),
            ));
        }
        let expected = ProofDeliveryId::digest(self.context_id, &self.target, &self.fact_ids);
        if self.delivery_id != expected {
            return Err(ProofOutboxError::InvalidRecord(
                "proof delivery identity does not match canonical facts".into(),
            ));
        }
        Ok(())
    }

    pub fn is_pending(&self) -> bool {
        self.state == ProofRecordState::Pending
    }
}

/// Durable access to proof records for one local semantic store.
#[derive(Debug, Clone)]
pub struct DurableProofOutbox {
    backend: ProofOutboxBackend,
}

#[derive(Debug, Clone)]
enum ProofOutboxBackend {
    Store(DurableSemanticStore),
    Owner(Arc<DurableSemanticOwner>),
}

impl DurableProofOutbox {
    /// Construct an outbox addressing the same durable semantic slot as the
    /// corresponding [`DurableSemanticStore`].
    pub fn new(instance_root: impl Into<std::path::PathBuf>, local_slot: impl AsRef<str>) -> Self {
        Self {
            backend: ProofOutboxBackend::Store(DurableSemanticStore::new(
                instance_root,
                local_slot,
            )),
        }
    }

    pub(crate) fn from_owner(owner: Arc<DurableSemanticOwner>) -> Self {
        Self {
            backend: ProofOutboxBackend::Owner(owner),
        }
    }

    /// Enumerate only still-pending records for the exact authenticated
    /// context.  Settled records remain persisted so replay is idempotent.
    pub fn pending(&self, context_id: MeshContextId) -> Result<Vec<ProofRecord>, ProofOutboxError> {
        Ok(self
            .proof_records(context_id)?
            .into_iter()
            .filter(ProofRecord::is_pending)
            .collect())
    }

    /// Persist one exact pending/settled record.  Re-enqueuing the identical
    /// record is a no-op; a conflicting record with the same stable identity
    /// is refused without changing the existing custody.
    pub fn enqueue(&self, record: ProofRecord) -> Result<ProofRecord, ProofOutboxError> {
        record.validate()?;
        let mut result = record.clone();
        let context_id = record.context_id;
        self.mutate_proof_records(context_id, |records| {
            if let Some(existing) = records
                .iter()
                .find(|existing| existing.delivery_id == record.delivery_id)
            {
                if !same_delivery_payload(existing, &record) {
                    return Err(DurableStoreError::ProofConflict);
                }
                result = existing.clone();
                return Ok(());
            }
            records.push(record.clone());
            records.sort_by_key(|record| record.delivery_id);
            Ok(())
        })?;
        Ok(result)
    }

    /// Atomically rebind a pending delivery after an authenticated live
    /// binding transition. The expected owner and binding are a CAS witness;
    /// only those two fields may change, and the stable delivery identity and
    /// fact set remain untouched.
    pub fn rebind(
        &self,
        context_id: MeshContextId,
        delivery_id: ProofDeliveryId,
        expected_owner: &str,
        expected_binding: &str,
        new_owner: impl Into<String>,
        new_binding: impl Into<String>,
    ) -> Result<ProofRecord, ProofOutboxError> {
        let new_owner = new_owner.into();
        let new_binding = new_binding.into();
        if new_owner.is_empty() || new_binding.is_empty() {
            return Err(ProofOutboxError::InvalidRecord(
                "proof owner and binding are required".into(),
            ));
        }
        match self
            .proof_records(context_id)?
            .into_iter()
            .find(|record| record.delivery_id == delivery_id)
            .ok_or(ProofOutboxError::NotFound)?
            .state
        {
            ProofRecordState::Pending => {}
            ProofRecordState::Settled => return Err(ProofOutboxError::AlreadySettled),
            ProofRecordState::Superseded => return Err(ProofOutboxError::AlreadySuperseded),
        }
        let mut rebound = None;
        self.mutate_proof_records(context_id, |records| {
            let record = records
                .iter_mut()
                .find(|record| record.delivery_id == delivery_id)
                .ok_or(DurableStoreError::ProofNotFound)?;
            if record.state != ProofRecordState::Pending {
                return Err(DurableStoreError::ProofSettled);
            }
            if record.owner != expected_owner || record.binding != expected_binding {
                return Err(DurableStoreError::StaleProofBinding);
            }
            record.owner = new_owner.clone();
            record.binding = new_binding.clone();
            rebound = Some(record.clone());
            Ok(())
        })?;
        rebound.ok_or_else(|| ProofOutboxError::InvalidRecord("rebind produced no record".into()))
    }

    /// Settle one exact delivery identity.  Repeated settlement is a no-op;
    /// a different context cannot select or settle the record.
    pub fn settle(
        &self,
        context_id: MeshContextId,
        delivery_id: ProofDeliveryId,
    ) -> Result<bool, ProofOutboxError> {
        let mut settled = false;
        self.mutate_proof_records(context_id, |records| {
            if let Some(record) = records
                .iter_mut()
                .find(|record| record.delivery_id == delivery_id)
            {
                match record.state {
                    ProofRecordState::Pending => {
                        record.state = ProofRecordState::Settled;
                        settled = true;
                    }
                    ProofRecordState::Settled | ProofRecordState::Superseded => {}
                }
            }
            Ok(())
        })?;
        Ok(settled)
    }

    /// Retire one obsolete Pending delivery without representing an
    /// acknowledgement. The exact target is a CAS witness; an optional
    /// replacement identity documents the successor selected by the caller
    /// but never makes this record replayable or settles the successor.
    pub fn supersede(
        &self,
        context_id: MeshContextId,
        delivery_id: ProofDeliveryId,
        expected_target: &DeviceId,
        replacement_delivery_id: Option<ProofDeliveryId>,
    ) -> Result<bool, ProofOutboxError> {
        if replacement_delivery_id == Some(delivery_id) {
            return Err(ProofOutboxError::InvalidRecord(
                "proof replacement must have a distinct delivery identity".into(),
            ));
        }
        let mut superseded = false;
        self.mutate_proof_records(context_id, |records| {
            let record = records
                .iter_mut()
                .find(|record| record.delivery_id == delivery_id)
                .ok_or(DurableStoreError::ProofNotFound)?;
            if &record.target != expected_target {
                return Err(DurableStoreError::StaleProofTarget);
            }
            match record.state {
                ProofRecordState::Pending => {
                    record.state = ProofRecordState::Superseded;
                    superseded = true;
                }
                ProofRecordState::Settled => return Err(DurableStoreError::ProofSettled),
                ProofRecordState::Superseded => {}
            }
            Ok(())
        })?;
        Ok(superseded)
    }

    fn proof_records(
        &self,
        context_id: MeshContextId,
    ) -> Result<Vec<ProofRecord>, DurableStoreError> {
        match &self.backend {
            ProofOutboxBackend::Store(store) => store.proof_records(context_id),
            ProofOutboxBackend::Owner(owner) => owner.proof_records(context_id),
        }
    }

    fn mutate_proof_records<F>(
        &self,
        context_id: MeshContextId,
        mutation: F,
    ) -> Result<Vec<ProofRecord>, DurableStoreError>
    where
        F: FnOnce(&mut Vec<ProofRecord>) -> Result<(), DurableStoreError>,
    {
        match &self.backend {
            ProofOutboxBackend::Store(store) => store.mutate_proof_records(context_id, mutation),
            ProofOutboxBackend::Owner(owner) => owner.mutate_proof_records(context_id, mutation),
        }
    }
}

fn same_delivery_payload(left: &ProofRecord, right: &ProofRecord) -> bool {
    left.version == right.version
        && left.context_id == right.context_id
        && left.target == right.target
        && left.delivery_id == right.delivery_id
        && left.fact_ids == right.fact_ids
        && left.owner == right.owner
        && left.binding == right.binding
}

#[derive(Debug, Error)]
pub enum ProofOutboxError {
    #[error("invalid proof record: {0}")]
    InvalidRecord(String),
    #[error("proof outbox context mismatch: expected {expected}, found {actual}")]
    ContextMismatch {
        expected: MeshContextId,
        actual: MeshContextId,
    },
    #[error("proof delivery identity is already bound to different metadata")]
    Conflict,
    #[error("proof delivery identity was not found")]
    NotFound,
    #[error("proof delivery is already settled")]
    AlreadySettled,
    #[error("proof delivery is already superseded")]
    AlreadySuperseded,
    #[error("proof delivery binding is stale")]
    StaleBinding,
    #[error("proof delivery target is stale")]
    StaleTarget,
    #[error("durable proof outbox storage failed: {0}")]
    Storage(String),
}

impl From<DurableStoreError> for ProofOutboxError {
    fn from(error: DurableStoreError) -> Self {
        match error {
            DurableStoreError::ContextMismatch { expected, actual } => {
                Self::ContextMismatch { expected, actual }
            }
            DurableStoreError::ProofConflict => Self::Conflict,
            DurableStoreError::ProofNotFound => Self::NotFound,
            DurableStoreError::ProofSettled => Self::AlreadySettled,
            DurableStoreError::StaleProofBinding => Self::StaleBinding,
            DurableStoreError::StaleProofTarget => Self::StaleTarget,
            error => Self::Storage(error.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::semantic::{
        FactBody, FactContent, FactDomain, FactGraph, Role, SignedFact, VerifiedBootstrap,
    };
    use ed25519_dalek::SigningKey;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static NEXT_ROOT: AtomicUsize = AtomicUsize::new(0);

    fn root() -> std::path::PathBuf {
        let id = NEXT_ROOT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "myownmesh-proof-outbox-{}-{id}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).expect("test root");
        root
    }

    fn shared_owner_fixture() -> (
        std::path::PathBuf,
        Arc<DurableProofOutbox>,
        MeshContextId,
        ProofRecord,
    ) {
        let root = root();
        let key = SigningKey::from_bytes(&[9; 32]);
        let bootstrap =
            VerifiedBootstrap::create_closed("proof-outbox-race", vec![key.clone()], [9; 32])
                .expect("bootstrap");
        let device =
            DeviceId::from_public_key_bytes(*key.verifying_key().as_bytes()).expect("device");
        let fact = SignedFact::sign(
            FactContent::new(
                FactDomain::Governance,
                bootstrap.context_id(),
                FactBody::RoleGrant {
                    target: device.clone(),
                    role: Role::Member,
                },
                device.clone(),
                Vec::new(),
            ),
            &key,
        )
        .expect("fact");
        let mut graph = FactGraph::from_bootstrap(&bootstrap);
        graph.admit(fact.clone()).expect("fact admission");
        let store = DurableSemanticStore::new(&root, "slot");
        store.commit(&graph, Vec::new()).expect("snapshot");
        let owner = Arc::new(store.open_writable().expect("shared owner"));
        let outbox = Arc::new(DurableProofOutbox::from_owner(owner));
        let record = ProofRecord::pending(
            bootstrap.context_id(),
            device,
            vec![fact.id],
            "race-owner",
            "race-binding",
        )
        .expect("record");
        outbox.enqueue(record.clone()).expect("enqueue");
        (root, outbox, bootstrap.context_id(), record)
    }

    #[test]
    fn identity_is_order_independent_and_metadata_bound() {
        let context = MeshContextId::from_bytes([1; 32]);
        let target_key = SigningKey::from_bytes(&[2; 32]);
        let target = DeviceId::from_public_key_bytes(*target_key.verifying_key().as_bytes())
            .expect("target");
        let first = FactId::from_bytes([3; 32]);
        let second = FactId::from_bytes([4; 32]);
        let left = ProofRecord::pending(
            context,
            target.clone(),
            vec![first, second],
            "owner",
            "binding",
        )
        .expect("left record");
        let right = ProofRecord::pending(
            context,
            target,
            vec![second, first, first],
            "different-owner",
            "different-binding",
        )
        .expect("right record");
        assert_eq!(left.delivery_id, right.delivery_id);
        assert_eq!(left.fact_ids, vec![first, second]);
        assert_ne!(left.owner, right.owner);
    }

    #[test]
    fn pending_record_survives_reopen_and_settlement_is_idempotent() {
        let root = root();
        let key = SigningKey::from_bytes(&[7; 32]);
        let bootstrap =
            VerifiedBootstrap::create_closed("proof-outbox", vec![key.clone()], [7; 32])
                .expect("bootstrap");
        let device =
            DeviceId::from_public_key_bytes(*key.verifying_key().as_bytes()).expect("device");
        let fact = SignedFact::sign(
            FactContent::new(
                FactDomain::Governance,
                bootstrap.context_id(),
                FactBody::RoleGrant {
                    target: device.clone(),
                    role: Role::Member,
                },
                device.clone(),
                Vec::new(),
            ),
            &key,
        )
        .expect("fact");
        let mut graph = FactGraph::from_bootstrap(&bootstrap);
        graph.admit(fact.clone()).expect("fact admission");
        let store = DurableSemanticStore::new(&root, "slot");
        store.commit(&graph, Vec::new()).expect("snapshot");

        let outbox = DurableProofOutbox::new(&root, "slot");
        let record = ProofRecord::pending(
            bootstrap.context_id(),
            device,
            vec![fact.id],
            "semantic-owner",
            "proof-binding",
        )
        .expect("record");
        assert_eq!(outbox.enqueue(record.clone()).expect("enqueue"), record);
        assert_eq!(
            outbox.pending(bootstrap.context_id()).expect("pending"),
            vec![record.clone()]
        );
        let conflict = ProofRecord::pending(
            bootstrap.context_id(),
            record.target.clone(),
            record.fact_ids.clone(),
            "other-owner",
            record.binding.clone(),
        )
        .expect("conflicting record");
        assert!(matches!(
            outbox.enqueue(conflict),
            Err(ProofOutboxError::Conflict)
        ));
        let rebound = outbox
            .rebind(
                bootstrap.context_id(),
                record.delivery_id,
                "semantic-owner",
                "proof-binding",
                "rebound-owner",
                "rebound-binding",
            )
            .expect("rebind");
        assert_eq!(rebound.delivery_id, record.delivery_id);
        assert_eq!(rebound.fact_ids, record.fact_ids);
        assert_eq!(rebound.owner, "rebound-owner");
        assert_eq!(rebound.binding, "rebound-binding");
        assert!(matches!(
            outbox.rebind(
                bootstrap.context_id(),
                record.delivery_id,
                "semantic-owner",
                "proof-binding",
                "stale-owner",
                "stale-binding",
            ),
            Err(ProofOutboxError::StaleBinding)
        ));
        let unknown = ProofRecord::pending(
            bootstrap.context_id(),
            rebound.target.clone(),
            vec![FactId::from_bytes([0xa5; 32])],
            "semantic-owner",
            "unknown-binding",
        )
        .expect("unknown record");
        assert!(matches!(
            outbox.enqueue(unknown),
            Err(ProofOutboxError::Storage(_))
        ));
        let obsolete_target_key = SigningKey::from_bytes(&[8; 32]);
        let obsolete_target =
            DeviceId::from_public_key_bytes(*obsolete_target_key.verifying_key().as_bytes())
                .expect("obsolete target");
        let obsolete = ProofRecord::pending(
            bootstrap.context_id(),
            obsolete_target.clone(),
            vec![fact.id],
            "obsolete-owner",
            "obsolete-binding",
        )
        .expect("obsolete record");
        outbox.enqueue(obsolete.clone()).expect("obsolete enqueue");
        assert!(outbox
            .supersede(
                bootstrap.context_id(),
                obsolete.delivery_id,
                &obsolete_target,
                Some(rebound.delivery_id),
            )
            .expect("supersede"));
        assert!(!outbox
            .supersede(
                bootstrap.context_id(),
                obsolete.delivery_id,
                &obsolete_target,
                None,
            )
            .expect("repeat supersede"));
        assert!(!outbox
            .pending(bootstrap.context_id())
            .expect("pending after supersede")
            .iter()
            .any(|record| record.delivery_id == obsolete.delivery_id));
        assert!(matches!(
            outbox.rebind(
                bootstrap.context_id(),
                obsolete.delivery_id,
                &obsolete.owner,
                &obsolete.binding,
                "stale-owner",
                "stale-binding",
            ),
            Err(ProofOutboxError::AlreadySuperseded)
        ));
        let superseded_reopen = DurableProofOutbox::new(&root, "slot");
        let superseded_records = superseded_reopen
            .proof_records(bootstrap.context_id())
            .expect("superseded tombstone reopen");
        let mut expected_obsolete = obsolete.clone();
        expected_obsolete.state = ProofRecordState::Superseded;
        assert_eq!(
            superseded_records
                .iter()
                .find(|persisted| persisted.delivery_id == obsolete.delivery_id),
            Some(&expected_obsolete)
        );
        store
            .commit(&graph, Vec::new())
            .expect("graph commit preserves proof");

        let reopened = DurableProofOutbox::new(&root, "slot");
        assert_eq!(
            reopened.pending(bootstrap.context_id()).expect("reopen"),
            vec![rebound.clone()]
        );
        assert!(reopened
            .settle(bootstrap.context_id(), record.delivery_id)
            .expect("settle"));
        assert!(!reopened
            .settle(bootstrap.context_id(), record.delivery_id)
            .expect("repeat settle"));
        assert!(reopened
            .pending(bootstrap.context_id())
            .expect("settled pending")
            .is_empty());
        let settled_reopen = DurableProofOutbox::new(&root, "slot");
        let settled_records = settled_reopen
            .proof_records(bootstrap.context_id())
            .expect("settled tombstone reopen");
        assert_eq!(settled_records.len(), 2);
        assert!(settled_records.iter().any(|persisted| {
            persisted.delivery_id == obsolete.delivery_id
                && persisted.state == ProofRecordState::Superseded
        }));
        assert!(settled_records.iter().any(|persisted| {
            persisted.delivery_id == record.delivery_id
                && persisted.state == ProofRecordState::Settled
        }));
        assert!(settled_reopen
            .pending(bootstrap.context_id())
            .expect("settled tombstone pending")
            .is_empty());
        assert!(matches!(
            reopened.rebind(
                bootstrap.context_id(),
                record.delivery_id,
                "rebound-owner",
                "rebound-binding",
                "settled-owner",
                "settled-binding",
            ),
            Err(ProofOutboxError::AlreadySettled)
        ));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn shared_owner_rebind_vs_supersede_has_one_terminal_and_exact_metadata() {
        let (root, outbox, context, record) = shared_owner_fixture();
        let barrier = Arc::new(std::sync::Barrier::new(3));
        let rebind_outbox = Arc::clone(&outbox);
        let rebind_barrier = Arc::clone(&barrier);
        let rebind_record = record.clone();
        let rebind_thread = std::thread::spawn(move || {
            rebind_barrier.wait();
            rebind_outbox.rebind(
                context,
                rebind_record.delivery_id,
                "race-owner",
                "race-binding",
                "rebound-owner",
                "rebound-binding",
            )
        });

        let supersede_outbox = Arc::clone(&outbox);
        let supersede_barrier = Arc::clone(&barrier);
        let supersede_record = record.clone();
        let supersede_thread = std::thread::spawn(move || {
            supersede_barrier.wait();
            supersede_outbox.supersede(
                context,
                supersede_record.delivery_id,
                &supersede_record.target,
                None,
            )
        });
        barrier.wait();
        let rebind_result = rebind_thread.join().expect("rebind race thread");
        let supersede_result = supersede_thread.join().expect("supersede race thread");
        assert!(
            supersede_result.is_ok(),
            "supersede must complete under the shared owner: {supersede_result:?}"
        );
        assert!(
            rebind_result.is_ok()
                || matches!(
                    &rebind_result,
                    Err(ProofOutboxError::AlreadySettled)
                        | Err(ProofOutboxError::AlreadySuperseded)
                ),
            "rebind may win or observe the terminal supersession: {rebind_result:?}"
        );

        let pending = outbox.pending(context).expect("pending race records");
        assert!(pending.is_empty(), "a terminal race cannot leave Pending");
        let persisted = outbox
            .proof_records(context)
            .expect("terminal race record")
            .into_iter()
            .find(|candidate| candidate.delivery_id == record.delivery_id)
            .expect("terminal race tombstone");
        assert_eq!(persisted.state, ProofRecordState::Superseded);
        assert_eq!(persisted.version, record.version);
        assert_eq!(persisted.context_id, record.context_id);
        assert_eq!(persisted.target, record.target);
        assert_eq!(persisted.delivery_id, record.delivery_id);
        assert_eq!(persisted.fact_ids, record.fact_ids);
        assert!(
            (persisted.owner == "race-owner" && persisted.binding == "race-binding")
                || (persisted.owner == "rebound-owner" && persisted.binding == "rebound-binding"),
            "only the exact original or CAS-rebound custody metadata is valid"
        );
        drop(outbox);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn shared_owner_settle_vs_supersede_has_one_terminal_and_exact_metadata() {
        let (root, outbox, context, record) = shared_owner_fixture();
        let barrier = Arc::new(std::sync::Barrier::new(3));
        let settle_outbox = Arc::clone(&outbox);
        let settle_barrier = Arc::clone(&barrier);
        let settle_id = record.delivery_id;
        let settle_thread = std::thread::spawn(move || {
            settle_barrier.wait();
            settle_outbox.settle(context, settle_id)
        });

        let supersede_outbox = Arc::clone(&outbox);
        let supersede_barrier = Arc::clone(&barrier);
        let supersede_record = record.clone();
        let supersede_thread = std::thread::spawn(move || {
            supersede_barrier.wait();
            supersede_outbox.supersede(
                context,
                supersede_record.delivery_id,
                &supersede_record.target,
                None,
            )
        });
        barrier.wait();
        let settled = settle_thread.join().expect("settle race thread");
        let superseded = supersede_thread.join().expect("supersede race thread");
        let terminal_state = match (settled, superseded) {
            (Ok(true), Err(ProofOutboxError::AlreadySettled)) => ProofRecordState::Settled,
            (Ok(false), Ok(true)) => ProofRecordState::Superseded,
            (settled, superseded) => panic!(
                "shared-owner race returned an invalid terminal pair: {settled:?}, {superseded:?}"
            ),
        };

        let pending = outbox.pending(context).expect("pending race records");
        assert!(pending.is_empty(), "a terminal race cannot leave Pending");
        let persisted = outbox
            .proof_records(context)
            .expect("terminal race record")
            .into_iter()
            .find(|candidate| candidate.delivery_id == record.delivery_id)
            .expect("terminal race tombstone");
        assert_eq!(persisted.state, terminal_state);
        assert_eq!(persisted.version, record.version);
        assert_eq!(persisted.context_id, record.context_id);
        assert_eq!(persisted.target, record.target);
        assert_eq!(persisted.delivery_id, record.delivery_id);
        assert_eq!(persisted.fact_ids, record.fact_ids);
        assert_eq!(persisted.owner, record.owner);
        assert_eq!(persisted.binding, record.binding);
        drop(outbox);
        let _ = std::fs::remove_dir_all(root);
    }
}
