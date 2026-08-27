//! Persistence for the local canonical bootstrap pair.
//!
//! The temporary file is synchronized before the create-once hard link on all
//! platforms. Unix also synchronizes the containing directory and propagates
//! that failure. Other platforms retain functional create-once persistence,
//! but a successful return does not claim parent-directory crash durability.
//!
//! The local slot is only a storage locator.  It is hashed before it reaches
//! the path and is never consulted as a source of semantic authority; the
//! [`BootstrapRecord`] stored there must still pass all of the bootstrap
//! module's context, basis, and root-signature checks.

use std::borrow::Borrow;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(unix)]
use std::os::fd::AsRawFd;

#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;
#[cfg(windows)]
use std::os::windows::fs::OpenOptionsExt;

use data_encoding::BASE32_NOPAD;
use serde::{Deserialize, Serialize};
use serde_json::Error as JsonError;
use sha2::{Digest, Sha256};
use thiserror::Error;

use super::{
    BootstrapError, BootstrapRecord, ExpectedMeshContext, FactGraph, FactId, MeshContextId,
    Projection, SignedFact, VerifiedBootstrap,
};

const BOOTSTRAP_DIRECTORY: &str = "bootstrap";
const SEMANTIC_DIRECTORY: &str = "semantic";
const SEMANTIC_SNAPSHOT_FILE: &str = "snapshot.json";
const SEMANTIC_SNAPSHOT_VERSION: u16 = 2;
static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

/// A local store for one bootstrap record.
///
/// `local_slot` is deliberately only a locator.  It is hashed for the file
/// name and never enters [`BootstrapRecord`] validation or authority checks.
#[derive(Debug, Clone)]
pub struct BootstrapStore {
    path: PathBuf,
}

/// One process-local provisional custody claim carried by a durable semantic
/// snapshot. It is bookkeeping only: the fact identity and owner are stored
/// together so an interrupted write cannot publish one without the other.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvisionalCustody {
    pub fact_id: FactId,
    pub owner: String,
}

impl ProvisionalCustody {
    pub fn new(fact_id: FactId, owner: impl Into<String>) -> Self {
        Self {
            fact_id,
            owner: owner.into(),
        }
    }
}

/// The verified result of reopening a durable semantic snapshot.
#[derive(Debug, Clone)]
pub struct RestoredSemanticState {
    graph: FactGraph,
    provisional: Vec<ProvisionalCustody>,
}

impl RestoredSemanticState {
    pub fn graph(&self) -> &FactGraph {
        &self.graph
    }

    pub fn provisional_custody(&self) -> &[ProvisionalCustody] {
        &self.provisional
    }
}

/// A single atomic durable fact/projection/custody store.
///
/// The snapshot is self-checksummed and written through `persist::write_atomic`.
/// A create-new sidecar lease serializes writers across processes; readers do
/// not hold it and therefore always observe either the old complete snapshot
/// or the new complete snapshot after a reopen.
#[derive(Debug, Clone)]
pub struct DurableSemanticStore {
    path: PathBuf,
    lock_path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DurableSnapshot {
    version: u16,
    context_id: MeshContextId,
    facts: Vec<SignedFact>,
    quarantined: Vec<SignedFact>,
    projection_commitment: [u8; 32],
    provisional: Vec<ProvisionalCustody>,
    checksum: [u8; 32],
}

#[derive(Debug, Serialize)]
struct SnapshotPayload<'a> {
    version: u16,
    context_id: MeshContextId,
    facts: &'a [SignedFact],
    quarantined: &'a [SignedFact],
    projection_commitment: [u8; 32],
    provisional: &'a [ProvisionalCustody],
}

#[derive(Debug)]
struct WriterLease {
    #[cfg(not(any(unix, windows)))]
    path: PathBuf,
    #[cfg(unix)]
    _file: std::fs::File,
    #[cfg(windows)]
    _file: std::fs::File,
}

impl WriterLease {
    fn acquire(path: &Path) -> Result<Self, DurableStoreError> {
        #[cfg(unix)]
        {
            let mut options = OpenOptions::new();
            options.read(true).write(true).create(true);
            let mut file = options.open(path).map_err(|source| DurableStoreError::Io {
                path: path.to_path_buf(),
                source,
            })?;
            // LOCK_NB keeps a competing process fail-closed rather than
            // waiting behind an unbounded writer. The kernel releases this
            // advisory lease if its process is interrupted.
            const LOCK_EX: std::os::raw::c_int = 2;
            const LOCK_NB: std::os::raw::c_int = 4;
            if unsafe { flock(file.as_raw_fd(), LOCK_EX | LOCK_NB) } != 0 {
                return Err(DurableStoreError::WriterBusy {
                    path: path.to_path_buf(),
                });
            }
            file.set_len(0).map_err(|source| DurableStoreError::Io {
                path: path.to_path_buf(),
                source,
            })?;
            writeln!(file, "pid={}", std::process::id()).map_err(|source| {
                DurableStoreError::Io {
                    path: path.to_path_buf(),
                    source,
                }
            })?;
            file.sync_all().map_err(|source| DurableStoreError::Io {
                path: path.to_path_buf(),
                source,
            })?;
            Ok(Self { _file: file })
        }

        #[cfg(windows)]
        {
            // Delete-on-close makes a hard-dead writer recoverable without
            // unlink/recreate races or a PID/timeout oracle. The zero share
            // mode keeps the live lease exclusive across processes.
            const FILE_FLAG_DELETE_ON_CLOSE: u32 = 0x0400_0000;
            let mut options = OpenOptions::new();
            options
                .read(true)
                .write(true)
                .create_new(true)
                .share_mode(0)
                .custom_flags(FILE_FLAG_DELETE_ON_CLOSE);
            let mut file = options.open(path).map_err(|source| {
                if source.kind() == std::io::ErrorKind::AlreadyExists {
                    DurableStoreError::WriterBusy {
                        path: path.to_path_buf(),
                    }
                } else {
                    DurableStoreError::Io {
                        path: path.to_path_buf(),
                        source,
                    }
                }
            })?;
            if let Err(source) = writeln!(file, "pid={}", std::process::id()) {
                return Err(DurableStoreError::Io {
                    path: path.to_path_buf(),
                    source,
                });
            }
            file.sync_all().map_err(|source| DurableStoreError::Io {
                path: path.to_path_buf(),
                source,
            })?;
            Ok(Self { _file: file })
        }

        #[cfg(not(any(unix, windows)))]
        {
            let mut file = OpenOptions::new();
            file.write(true).create_new(true);
            let mut file = file.open(path).map_err(|source| {
                if source.kind() == std::io::ErrorKind::AlreadyExists {
                    DurableStoreError::WriterBusy {
                        path: path.to_path_buf(),
                    }
                } else {
                    DurableStoreError::Io {
                        path: path.to_path_buf(),
                        source,
                    }
                }
            })?;
            if let Err(source) = writeln!(file, "pid={}", std::process::id()) {
                let _ = std::fs::remove_file(path);
                return Err(DurableStoreError::Io {
                    path: path.to_path_buf(),
                    source,
                });
            }
            if let Err(source) = file.sync_all() {
                let _ = std::fs::remove_file(path);
                return Err(DurableStoreError::Io {
                    path: path.to_path_buf(),
                    source,
                });
            }
            Ok(Self {
                path: path.to_path_buf(),
            })
        }
    }
}

#[cfg(unix)]
unsafe extern "C" {
    fn flock(fd: std::os::raw::c_int, operation: std::os::raw::c_int) -> std::os::raw::c_int;
}

impl Drop for WriterLease {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            const LOCK_UN: std::os::raw::c_int = 8;
            let _ = unsafe { flock(self._file.as_raw_fd(), LOCK_UN) };
        }
        // Unix deliberately retains the lock pathname. flock owns the
        // inode lease and removing the name after unlock would permit a
        // competing process to create a second inode in the gap. Windows
        // uses FILE_FLAG_DELETE_ON_CLOSE, so the kernel removes its path
        // only after the owning handle is gone.
        #[cfg(not(any(unix, windows)))]
        let _ = std::fs::remove_file(&self.path);
    }
}

impl BootstrapStore {
    /// Open a store rooted below one explicit instance directory.
    pub fn new(instance_root: impl Into<PathBuf>, local_slot: impl AsRef<str>) -> Self {
        let digest = Sha256::digest(local_slot.as_ref().as_bytes());
        let slot = BASE32_NOPAD.encode(&digest).to_lowercase();
        Self {
            path: instance_root
                .into()
                .join(BOOTSTRAP_DIRECTORY)
                .join(format!("{slot}.json")),
        }
    }

    /// The resolved storage path, exposed for diagnostics and controls only.
    #[cfg(test)]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Persist a newly created local record, or return the identical record
    /// already established at this slot. Local creation is crate-local and
    /// requires the authenticated process principal; callers cannot turn an
    /// arbitrary record into first-install authority from outside the crate.
    pub(crate) fn persist_new<R>(
        &self,
        principal: &crate::application_gateway::LocalPrincipalCapability,
        record: R,
    ) -> Result<VerifiedBootstrap, BootstrapStoreError>
    where
        R: Borrow<BootstrapRecord>,
    {
        let verified = VerifiedBootstrap::from_record(record.borrow().clone())
            .map_err(BootstrapStoreError::Invalid)?;
        let _expected_context =
            ExpectedMeshContext::for_local_import(principal, verified.context_id());
        self.persist_verified(verified)
    }

    /// Import a record only when it matches the already authenticated context.
    ///
    /// The candidate is fully verified before the store is consulted, and the
    /// sealed expected context is compared before any install can occur.
    pub fn import_expected<R>(
        &self,
        expected_context: &ExpectedMeshContext,
        record: R,
    ) -> Result<VerifiedBootstrap, BootstrapStoreError>
    where
        R: Borrow<BootstrapRecord>,
    {
        let verified = VerifiedBootstrap::from_record(record.borrow().clone())
            .map_err(BootstrapStoreError::Invalid)?;
        if !expected_context.matches(&verified.context_id()) {
            return Err(BootstrapStoreError::ContextMismatch {
                expected: expected_context.context_id(),
                actual: verified.context_id(),
            });
        }
        self.persist_verified(verified)
    }

    /// Restore and verify the exact persisted pair.
    pub fn restore(&self) -> Result<VerifiedBootstrap, BootstrapStoreError> {
        let record = self
            .read_record()?
            .ok_or_else(|| BootstrapStoreError::Missing {
                path: self.path.clone(),
            })?;
        VerifiedBootstrap::from_record(record).map_err(|source| BootstrapStoreError::Corrupt {
            path: self.path.clone(),
            reason: source.to_string(),
        })
    }

    /// Restore and verify the record expected for an authenticated context.
    #[cfg(test)]
    pub fn restore_expected(
        &self,
        expected_context: &ExpectedMeshContext,
    ) -> Result<VerifiedBootstrap, BootstrapStoreError> {
        let verified = self.restore()?;
        if !expected_context.matches(&verified.context_id()) {
            return Err(BootstrapStoreError::ContextMismatch {
                expected: expected_context.context_id(),
                actual: verified.context_id(),
            });
        }
        Ok(verified)
    }

    fn persist_verified(
        &self,
        verified: VerifiedBootstrap,
    ) -> Result<VerifiedBootstrap, BootstrapStoreError> {
        let bytes = serde_json::to_vec(verified.record())?;

        if let Some(existing) = self.read_record()? {
            if existing == *verified.record() {
                let parent = self
                    .path
                    .parent()
                    .ok_or_else(|| BootstrapStoreError::InvalidPath(self.path.clone()))?;
                sync_directory_chain(parent)?;
                return Ok(verified);
            }
            return Err(BootstrapStoreError::Conflict {
                path: self.path.clone(),
            });
        }

        let parent = self
            .path
            .parent()
            .ok_or_else(|| BootstrapStoreError::InvalidPath(self.path.clone()))?;
        ensure_directory_chain(parent)?;
        sync_directory_chain(parent)?;
        let temp = self.write_temp(&bytes)?;
        match std::fs::hard_link(&temp, &self.path) {
            Ok(()) => {
                let _ = std::fs::remove_file(&temp);
                sync_directory_chain(parent)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let _ = std::fs::remove_file(&temp);
                let existing = self.read_record()?.ok_or_else(|| BootstrapStoreError::Io {
                    path: self.path.clone(),
                    source: std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "bootstrap appeared and disappeared during create",
                    ),
                })?;
                if existing == *verified.record() {
                    sync_directory_chain(parent)?;
                    return Ok(verified);
                }
                return Err(BootstrapStoreError::Conflict {
                    path: self.path.clone(),
                });
            }
            Err(source) => {
                let _ = std::fs::remove_file(&temp);
                return Err(BootstrapStoreError::Io {
                    path: self.path.clone(),
                    source,
                });
            }
        }
        Ok(verified)
    }

    fn write_temp(&self, bytes: &[u8]) -> Result<PathBuf, BootstrapStoreError> {
        let parent = self
            .path
            .parent()
            .ok_or_else(|| BootstrapStoreError::InvalidPath(self.path.clone()))?;
        let name = self
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| BootstrapStoreError::InvalidPath(self.path.clone()))?;
        let counter = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let temp = parent.join(format!(".{name}.{}.{}.tmp", std::process::id(), counter));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&temp)
            .map_err(|source| BootstrapStoreError::Io {
                path: temp.clone(),
                source,
            })?;
        if let Err(source) = file.write_all(bytes).and_then(|_| file.sync_all()) {
            let _ = std::fs::remove_file(&temp);
            return Err(BootstrapStoreError::Io { path: temp, source });
        }
        Ok(temp)
    }

    fn read_record(&self) -> Result<Option<BootstrapRecord>, BootstrapStoreError> {
        let bytes = match std::fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(source) => {
                return Err(BootstrapStoreError::Io {
                    path: self.path.clone(),
                    source,
                });
            }
        };
        let record: BootstrapRecord =
            serde_json::from_slice(&bytes).map_err(|source| BootstrapStoreError::Corrupt {
                path: self.path.clone(),
                reason: source.to_string(),
            })?;
        VerifiedBootstrap::from_record(record.clone()).map_err(|source| {
            BootstrapStoreError::Corrupt {
                path: self.path.clone(),
                reason: source.to_string(),
            }
        })?;
        Ok(Some(record))
    }
}

impl DurableSemanticStore {
    pub fn new(instance_root: impl Into<PathBuf>, local_slot: impl AsRef<str>) -> Self {
        let root = instance_root.into();
        let digest = Sha256::digest(local_slot.as_ref().as_bytes());
        let slot = BASE32_NOPAD.encode(&digest).to_lowercase();
        let directory = root.join(SEMANTIC_DIRECTORY);
        Self {
            path: directory.join(format!("{slot}-{SEMANTIC_SNAPSHOT_FILE}")),
            lock_path: directory.join(format!("{slot}.lock")),
        }
    }

    /// The resolved snapshot path, exposed for diagnostics and interruption
    /// controls only.
    #[cfg(test)]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Commit facts, their derived projection commitment, and provisional
    /// custody as one durable record. The writer lease covers validation and
    /// publication, so a competing process cannot interleave a partial state.
    pub fn commit<I>(&self, graph: &FactGraph, provisional: I) -> Result<(), DurableStoreError>
    where
        I: IntoIterator<Item = ProvisionalCustody>,
    {
        let lease = self.begin_write()?;
        lease.commit(graph, provisional)
    }

    /// Acquire the cross-process writer lease and hold it until commit or
    /// drop. Readers remain lock-free and only consume complete snapshots.
    pub fn begin_write(&self) -> Result<DurableSemanticWriter, DurableStoreError> {
        let parent = self
            .path
            .parent()
            .ok_or_else(|| DurableStoreError::InvalidPath(self.path.clone()))?;
        std::fs::create_dir_all(parent).map_err(|source| DurableStoreError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
        let lease = WriterLease::acquire(&self.lock_path)?;
        Ok(DurableSemanticWriter {
            store: self.clone(),
            lease,
        })
    }

    /// Reopen, verify, and rebuild the exact graph and projection commitment.
    /// A stale temporary file from an interrupted writer is ignored because
    /// the published snapshot itself is never truncated.
    pub fn restore(
        &self,
        bootstrap: &VerifiedBootstrap,
    ) -> Result<RestoredSemanticState, DurableStoreError> {
        self.restore_unlocked(bootstrap)
    }

    /// Rewrite the canonical sorted representation under the writer lease.
    /// Compaction has no separate correctness path: it first verifies the
    /// existing snapshot, then atomically republishes the same state.
    pub fn compact(
        &self,
        bootstrap: &VerifiedBootstrap,
    ) -> Result<RestoredSemanticState, DurableStoreError> {
        let lease = self.begin_write()?;
        let state = self.restore_unlocked(bootstrap)?;
        lease
            .store
            .store_snapshot(&state.graph, state.provisional.clone())?;
        Ok(state)
    }

    fn restore_unlocked(
        &self,
        bootstrap: &VerifiedBootstrap,
    ) -> Result<RestoredSemanticState, DurableStoreError> {
        let bytes = match std::fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(DurableStoreError::Missing {
                    path: self.path.clone(),
                })
            }
            Err(source) => {
                return Err(DurableStoreError::Io {
                    path: self.path.clone(),
                    source,
                })
            }
        };
        let snapshot: DurableSnapshot =
            serde_json::from_slice(&bytes).map_err(|source| DurableStoreError::Corrupt {
                path: self.path.clone(),
                reason: source.to_string(),
            })?;
        snapshot.verify(self.path.as_path())?;
        if snapshot.context_id != bootstrap.context_id() {
            return Err(DurableStoreError::ContextMismatch {
                expected: bootstrap.context_id(),
                actual: snapshot.context_id,
            });
        }

        let expected_facts = snapshot.facts.len();
        let expected_quarantined: std::collections::BTreeSet<_> =
            snapshot.quarantined.iter().map(|fact| fact.id).collect();
        let mut graph = FactGraph::from_bootstrap(bootstrap);
        for fact in snapshot.facts {
            graph
                .admit(fact)
                .map_err(|error| DurableStoreError::Rebuild {
                    path: self.path.clone(),
                    reason: error.to_string(),
                })?;
        }
        for fact in snapshot.quarantined {
            match graph.admit(fact) {
                Ok(crate::semantic::Admission::Quarantined { .. }) => {}
                Ok(crate::semantic::Admission::AlreadyPresent) => {
                    return Err(DurableStoreError::Rebuild {
                        path: self.path.clone(),
                        reason: "snapshot marks an already-admitted fact unresolved".into(),
                    })
                }
                Ok(crate::semantic::Admission::Inserted) => {
                    return Err(DurableStoreError::Rebuild {
                        path: self.path.clone(),
                        reason: "snapshot unresolved fact has no missing dependency".into(),
                    })
                }
                Err(error) => {
                    return Err(DurableStoreError::Rebuild {
                        path: self.path.clone(),
                        reason: error.to_string(),
                    })
                }
            }
        }
        graph
            .retry_quarantined()
            .map_err(|error| DurableStoreError::Rebuild {
                path: self.path.clone(),
                reason: error.to_string(),
            })?;
        let actual_quarantined: std::collections::BTreeSet<_> =
            graph.quarantined().map(|(id, _)| *id).collect();
        if graph.len() != expected_facts || actual_quarantined != expected_quarantined {
            return Err(DurableStoreError::Rebuild {
                path: self.path.clone(),
                reason: "snapshot contains unresolved or missing fact dependencies".into(),
            });
        }
        validate_provisional_for_state(&snapshot.provisional, &graph)?;
        let actual_projection = projection_commitment(&graph.projection());
        if actual_projection != snapshot.projection_commitment {
            return Err(DurableStoreError::ProjectionMismatch {
                path: self.path.clone(),
            });
        }
        Ok(RestoredSemanticState {
            graph,
            provisional: snapshot.provisional,
        })
    }
}

/// A held durable writer lease. Dropping without commit is an explicit abort;
/// the previously published snapshot remains untouched.
pub struct DurableSemanticWriter {
    store: DurableSemanticStore,
    lease: WriterLease,
}

impl DurableSemanticWriter {
    pub fn commit<I>(self, graph: &FactGraph, provisional: I) -> Result<(), DurableStoreError>
    where
        I: IntoIterator<Item = ProvisionalCustody>,
    {
        let result = self.store.store_snapshot(graph, provisional);
        drop(self.lease);
        result
    }
}

impl DurableSemanticStore {
    fn store_snapshot<I>(&self, graph: &FactGraph, provisional: I) -> Result<(), DurableStoreError>
    where
        I: IntoIterator<Item = ProvisionalCustody>,
    {
        let mut facts: Vec<_> = graph.facts.values().cloned().collect();
        facts.sort_by_key(|fact| fact.id);
        let mut quarantined: Vec<_> = graph.quarantined().map(|(_, fact)| fact.clone()).collect();
        quarantined.sort_by_key(|fact| fact.id);
        let provisional = canonical_provisional(provisional)?;
        validate_provisional_for_state(&provisional, graph)?;
        let projection_commitment = projection_commitment(&graph.projection());
        let snapshot = DurableSnapshot::new(
            graph.context_id(),
            facts,
            quarantined,
            projection_commitment,
            provisional,
        )?;
        let bytes = serde_json::to_vec(&snapshot)?;
        let parent = self
            .path
            .parent()
            .ok_or_else(|| DurableStoreError::InvalidPath(self.path.clone()))?;
        std::fs::create_dir_all(parent).map_err(|source| DurableStoreError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
        write_snapshot_atomic(&self.path, &bytes)
    }
}

impl DurableSnapshot {
    fn new(
        context_id: MeshContextId,
        facts: Vec<SignedFact>,
        quarantined: Vec<SignedFact>,
        projection_commitment: [u8; 32],
        provisional: Vec<ProvisionalCustody>,
    ) -> Result<Self, DurableStoreError> {
        let mut snapshot = Self {
            version: SEMANTIC_SNAPSHOT_VERSION,
            context_id,
            facts,
            quarantined,
            projection_commitment,
            provisional,
            checksum: [0; 32],
        };
        snapshot.checksum = snapshot.calculate_checksum()?;
        Ok(snapshot)
    }

    fn calculate_checksum(&self) -> Result<[u8; 32], DurableStoreError> {
        let payload = SnapshotPayload {
            version: self.version,
            context_id: self.context_id,
            facts: &self.facts,
            quarantined: &self.quarantined,
            projection_commitment: self.projection_commitment,
            provisional: &self.provisional,
        };
        let bytes = serde_json::to_vec(&payload)?;
        let digest = Sha256::digest(bytes);
        let mut checksum = [0; 32];
        checksum.copy_from_slice(&digest);
        Ok(checksum)
    }

    fn verify(&self, path: &Path) -> Result<(), DurableStoreError> {
        if self.version != SEMANTIC_SNAPSHOT_VERSION {
            return Err(DurableStoreError::UnsupportedVersion {
                path: path.to_path_buf(),
                version: self.version,
            });
        }
        if self.checksum != self.calculate_checksum()? {
            return Err(DurableStoreError::ChecksumMismatch {
                path: path.to_path_buf(),
            });
        }
        canonical_provisional(self.provisional.clone())?;
        Ok(())
    }
}

fn canonical_provisional<I>(values: I) -> Result<Vec<ProvisionalCustody>, DurableStoreError>
where
    I: IntoIterator<Item = ProvisionalCustody>,
{
    let mut values: Vec<_> = values.into_iter().collect();
    if values.iter().any(|claim| claim.owner.is_empty()) {
        return Err(DurableStoreError::InvalidCustody);
    }
    values.sort_by(|left, right| {
        left.fact_id
            .cmp(&right.fact_id)
            .then_with(|| left.owner.cmp(&right.owner))
    });
    if values.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(DurableStoreError::DuplicateCustody);
    }
    Ok(values)
}

fn validate_provisional_for_state(
    claims: &[ProvisionalCustody],
    graph: &FactGraph,
) -> Result<(), DurableStoreError> {
    let unresolved: std::collections::BTreeSet<_> =
        graph.quarantined().map(|(id, _)| *id).collect();
    if claims.len() != unresolved.len()
        || claims
            .iter()
            .any(|claim| !unresolved.contains(&claim.fact_id))
    {
        return Err(DurableStoreError::UnknownCustodyFact);
    }
    Ok(())
}

fn projection_commitment(projection: &Projection) -> [u8; 32] {
    let mut bytes = Vec::new();
    for (cell, value) in projection.cells() {
        bytes.extend_from_slice(cell.to_string().as_bytes());
        bytes.push(0);
        match value {
            super::CellProjection::Value(id) => {
                bytes.push(1);
                bytes.extend_from_slice(id.as_bytes());
            }
            super::CellProjection::Conflict(ids) => {
                bytes.push(2);
                for id in ids {
                    bytes.extend_from_slice(id.as_bytes());
                }
            }
        }
        bytes.push(0xff);
    }
    for target in projection.stand_down_targets() {
        bytes.extend_from_slice(b"stand_down:");
        bytes.extend_from_slice(target.to_string().as_bytes());
        if let Some(stand_down) = projection.stand_down(target) {
            bytes.extend_from_slice(stand_down.proof.as_bytes());
        }
        bytes.push(0xfe);
    }
    let digest = Sha256::digest(bytes);
    let mut commitment = [0; 32];
    commitment.copy_from_slice(&digest);
    commitment
}

fn write_snapshot_atomic(path: &Path, bytes: &[u8]) -> Result<(), DurableStoreError> {
    #[cfg(not(windows))]
    {
        crate::persist::write_atomic(path, bytes).map_err(|source| DurableStoreError::Io {
            path: path.to_path_buf(),
            source,
        })
    }

    #[cfg(windows)]
    {
        let parent = path
            .parent()
            .ok_or_else(|| DurableStoreError::InvalidPath(path.to_path_buf()))?;
        let name = path
            .file_name()
            .ok_or_else(|| DurableStoreError::InvalidPath(path.to_path_buf()))?;
        let counter = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let temp = parent.join(format!(
            ".{}.{}.{}.tmp",
            name.to_string_lossy(),
            std::process::id(),
            counter
        ));
        let mut file = OpenOptions::new();
        file.write(true).create_new(true);
        let mut file = file.open(&temp).map_err(|source| DurableStoreError::Io {
            path: temp.clone(),
            source,
        })?;
        if let Err(source) = file.write_all(bytes).and_then(|_| file.sync_all()) {
            let _ = std::fs::remove_file(&temp);
            return Err(DurableStoreError::Io { path: temp, source });
        }
        let source = wide_path(&temp);
        let destination = wide_path(path);
        const MOVEFILE_REPLACE_EXISTING: u32 = 1;
        const MOVEFILE_WRITE_THROUGH: u32 = 8;
        if unsafe {
            MoveFileExW(
                source.as_ptr(),
                destination.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        } == 0
        {
            let source = std::io::Error::last_os_error();
            let _ = std::fs::remove_file(&temp);
            return Err(DurableStoreError::Io {
                path: path.to_path_buf(),
                source,
            });
        }
        Ok(())
    }
}

#[cfg(windows)]
fn wide_path(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(Some(0)).collect()
}

#[cfg(windows)]
#[link(name = "kernel32")]
unsafe extern "system" {
    fn MoveFileExW(existing_file_name: *const u16, new_file_name: *const u16, flags: u32) -> i32;
}

/// Create a missing directory hierarchy one component at a time. Each newly
/// created child is followed by a sync of its containing directory, so a
/// first install does not rely on `create_dir_all`'s unsignaled hierarchy.
fn ensure_directory_chain(path: &Path) -> Result<(), BootstrapStoreError> {
    let mut missing = Vec::new();
    let mut cursor = path.to_path_buf();
    loop {
        match std::fs::symlink_metadata(&cursor) {
            Ok(metadata) => {
                if !metadata.is_dir() {
                    return Err(BootstrapStoreError::Io {
                        path: cursor,
                        source: std::io::Error::new(
                            std::io::ErrorKind::NotADirectory,
                            "bootstrap store component is not a directory",
                        ),
                    });
                }
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                missing.push(cursor.clone());
                cursor = cursor
                    .parent()
                    .map(|parent| {
                        if parent.as_os_str().is_empty() {
                            PathBuf::from(".")
                        } else {
                            parent.to_path_buf()
                        }
                    })
                    .ok_or_else(|| BootstrapStoreError::InvalidPath(path.to_path_buf()))?;
            }
            Err(source) => {
                return Err(BootstrapStoreError::Io {
                    path: cursor,
                    source,
                });
            }
        }
    }

    for child in missing.iter().rev() {
        match std::fs::create_dir(child) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let metadata =
                    std::fs::symlink_metadata(child).map_err(|source| BootstrapStoreError::Io {
                        path: child.clone(),
                        source,
                    })?;
                if !metadata.is_dir() {
                    return Err(BootstrapStoreError::Io {
                        path: child.clone(),
                        source: std::io::Error::new(
                            std::io::ErrorKind::NotADirectory,
                            "bootstrap store component is not a directory",
                        ),
                    });
                }
            }
            Err(source) => {
                return Err(BootstrapStoreError::Io {
                    path: child.clone(),
                    source,
                });
            }
        }
        let containing = child
            .parent()
            .map(|parent| {
                if parent.as_os_str().is_empty() {
                    PathBuf::from(".")
                } else {
                    parent.to_path_buf()
                }
            })
            .ok_or_else(|| BootstrapStoreError::InvalidPath(child.clone()))?;
        sync_parent(&containing)?;
    }
    Ok(())
}

/// Re-establish directory durability edges from the record directory through
/// its existing ancestors. This is needed both after linking and on an
/// identical-record retry, where the file already exists but a prior caller's
/// directory sync may have failed or been interrupted.
fn sync_directory_chain(path: &Path) -> Result<(), BootstrapStoreError> {
    let mut current = Some(path.to_path_buf());
    while let Some(directory) = current {
        sync_parent(&directory)?;
        current = directory.parent().and_then(|parent| {
            if parent.as_os_str().is_empty() {
                (directory.as_path() != Path::new(".")).then(|| PathBuf::from("."))
            } else if parent == directory.as_path() {
                None
            } else {
                Some(parent.to_path_buf())
            }
        });
    }
    Ok(())
}

#[cfg(unix)]
fn sync_parent(parent: &Path) -> Result<(), BootstrapStoreError> {
    let directory = std::fs::File::open(parent).map_err(|source| BootstrapStoreError::Io {
        path: parent.to_path_buf(),
        source,
    })?;
    directory
        .sync_all()
        .map_err(|source| BootstrapStoreError::Io {
            path: parent.to_path_buf(),
            source,
        })
}

#[cfg(not(unix))]
fn sync_parent(parent: &Path) -> Result<(), BootstrapStoreError> {
    let _ = parent;
    Ok(())
}

/// Fail-closed storage and validation failures.
#[derive(Debug, Error)]
pub enum BootstrapStoreError {
    #[error("bootstrap store is missing: {path}")]
    Missing { path: PathBuf },
    #[error("bootstrap store is corrupt at {path}: {reason}")]
    Corrupt { path: PathBuf, reason: String },
    #[error("bootstrap record conflicts with the established record at {path}")]
    Conflict { path: PathBuf },
    #[error("bootstrap context mismatch: expected {expected}, found {actual}")]
    ContextMismatch {
        expected: MeshContextId,
        actual: MeshContextId,
    },
    #[error("bootstrap record is invalid: {0}")]
    Invalid(#[source] BootstrapError),
    #[error("bootstrap store path has no parent: {0}")]
    InvalidPath(PathBuf),
    #[error("bootstrap store I/O at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("bootstrap record serialization failed: {0}")]
    Serialization(#[from] JsonError),
}

/// Fail-closed errors for the atomic semantic snapshot store.
#[derive(Debug, Error)]
pub enum DurableStoreError {
    #[error("semantic snapshot is missing: {path}")]
    Missing { path: PathBuf },
    #[error("semantic snapshot is corrupt at {path}: {reason}")]
    Corrupt { path: PathBuf, reason: String },
    #[error("semantic snapshot has unsupported version {version} at {path}")]
    UnsupportedVersion { path: PathBuf, version: u16 },
    #[error("semantic snapshot checksum mismatch at {path}")]
    ChecksumMismatch { path: PathBuf },
    #[error("semantic snapshot context mismatch: expected {expected}, found {actual}")]
    ContextMismatch {
        expected: MeshContextId,
        actual: MeshContextId,
    },
    #[error("semantic snapshot projection commitment mismatch at {path}")]
    ProjectionMismatch { path: PathBuf },
    #[error("semantic snapshot cannot rebuild at {path}: {reason}")]
    Rebuild { path: PathBuf, reason: String },
    #[error("semantic snapshot writer is busy: {path}")]
    WriterBusy { path: PathBuf },
    #[error("semantic snapshot path has no parent: {0}")]
    InvalidPath(PathBuf),
    #[error("semantic snapshot I/O at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("semantic snapshot contains invalid provisional custody")]
    InvalidCustody,
    #[error("semantic snapshot provisional custody names an unknown fact")]
    UnknownCustodyFact,
    #[error("semantic snapshot contains duplicate provisional custody")]
    DuplicateCustody,
    #[error("semantic snapshot serialization failed: {0}")]
    Serialization(#[from] JsonError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::semantic::{FactBody, FactContent, FactDomain};
    use ed25519_dalek::SigningKey;
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    static NEXT_ROOT: AtomicUsize = AtomicUsize::new(0);

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn root() -> PathBuf {
        let id = NEXT_ROOT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "myownmesh-bootstrap-store-{}-{id}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).expect("test store root");
        root
    }

    fn closed(scope: &str, seed: u8, creation_id: [u8; 32]) -> VerifiedBootstrap {
        VerifiedBootstrap::create_closed(scope, vec![key(seed)], creation_id)
            .expect("test bootstrap")
    }

    fn expected(verified: &VerifiedBootstrap) -> ExpectedMeshContext {
        let principal = principal();
        ExpectedMeshContext::for_local_import(&principal, verified.context_id())
    }

    fn principal() -> crate::application_gateway::LocalPrincipalCapability {
        let runtime = crate::runtime::runtime_for_test();
        crate::application_gateway::LocalPrincipalCapability::for_test(runtime)
    }

    fn root_fact(bootstrap: &VerifiedBootstrap, signing_key: &SigningKey) -> SignedFact {
        let author =
            super::super::DeviceId::from_public_key_bytes(*signing_key.verifying_key().as_bytes())
                .expect("test root id");
        SignedFact::sign(
            FactContent::new(
                FactDomain::Governance,
                bootstrap.context_id(),
                FactBody::RoleGrant {
                    target: author.clone(),
                    role: super::super::Role::Member,
                },
                author,
                Vec::new(),
            ),
            signing_key,
        )
        .expect("test root fact")
    }

    #[test]
    fn round_trip_preserves_exact_pair_and_uses_local_slot_hash() {
        let root = root();
        let first = closed("scope-a", 1, [1; 32]);
        let store = BootstrapStore::new(&root, "local-device-slot");
        let principal = principal();
        let saved = store
            .persist_new(&principal, first.record())
            .expect("persist");
        assert_eq!(saved.record(), first.record());
        let restored = store.restore().expect("restore");
        assert_eq!(restored.record(), first.record());
        assert!(store.path().starts_with(root.join(BOOTSTRAP_DIRECTORY)));
        assert!(!store.path().to_string_lossy().contains("local-device-slot"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn hierarchy_obstruction_propagates_without_installing_a_record() {
        let root = root();
        let first = closed("scope-a", 10, [10; 32]);
        let blocked = root.join("blocked");
        std::fs::write(&blocked, b"not a directory").expect("blocking file");
        let store = BootstrapStore::new(&blocked, "slot");
        let principal = principal();
        assert!(matches!(
            store.persist_new(&principal, first.record()),
            Err(BootstrapStoreError::Io { .. })
        ));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn nested_missing_hierarchy_is_created_before_first_install() {
        let root = root();
        let first = closed("scope-a", 11, [11; 32]);
        let instance = root.join("mesh").join("instance");
        let store = BootstrapStore::new(&instance, "slot");
        let principal = principal();
        store
            .persist_new(&principal, first.record())
            .expect("nested hierarchy persist");
        assert!(instance.join(BOOTSTRAP_DIRECTORY).is_dir());
        assert_eq!(store.restore().expect("nested hierarchy restore"), first);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn relative_dot_ancestor_chain_terminates() {
        sync_directory_chain(Path::new(".")).expect("relative dot sync");
    }

    #[test]
    fn identical_persist_and_import_are_idempotent() {
        let root = root();
        let first = closed("scope-a", 2, [2; 32]);
        let store = BootstrapStore::new(&root, "slot");
        let principal = principal();
        store
            .persist_new(&principal, first.record())
            .expect("first persist");
        assert_eq!(
            store
                .persist_new(&principal, first.record())
                .expect("same persist")
                .record(),
            first.record()
        );
        assert_eq!(
            store
                .import_expected(&expected(&first), first.record())
                .expect("same import")
                .record(),
            first.record()
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn conflicting_record_is_refused_without_replacement() {
        let root = root();
        let first = closed("scope-a", 3, [3; 32]);
        let second = closed("scope-a", 3, [4; 32]);
        let store = BootstrapStore::new(&root, "slot");
        let principal = principal();
        store
            .persist_new(&principal, first.record())
            .expect("first persist");
        assert!(matches!(
            store.persist_new(&principal, second.record()),
            Err(BootstrapStoreError::Conflict { .. })
        ));
        assert_eq!(store.restore().expect("original remains"), first);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn missing_corrupt_and_mutated_records_fail_closed() {
        let root = root();
        let first = closed("scope-a", 4, [5; 32]);
        let store = BootstrapStore::new(&root, "slot");
        assert!(matches!(
            store.restore(),
            Err(BootstrapStoreError::Missing { .. })
        ));
        std::fs::create_dir_all(store.path().parent().expect("store parent")).expect("parent");
        std::fs::write(store.path(), b"not-json").expect("corrupt bytes");
        assert!(matches!(
            store.restore(),
            Err(BootstrapStoreError::Corrupt { .. })
        ));
        std::fs::write(
            store.path(),
            serde_json::to_vec(first.record()).expect("record json"),
        )
        .expect("valid record");
        let other = closed("other-scope", 4, [5; 32]);
        assert!(matches!(
            store.restore_expected(&expected(&other)),
            Err(BootstrapStoreError::ContextMismatch { .. })
        ));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn reopened_store_reads_the_same_established_record() {
        let root = root();
        let first = closed("scope-a", 5, [6; 32]);
        let store = BootstrapStore::new(&root, "slot");
        let principal = principal();
        store
            .persist_new(&principal, first.record())
            .expect("persist");
        let reopened = BootstrapStore::new(&root, "slot");
        assert_eq!(reopened.restore().expect("reopen"), first);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn opposite_order_unmatched_valid_candidates_install_neither() {
        let root = root();
        let first = closed("scope-a", 8, [8; 32]);
        let second = closed("scope-b", 9, [9; 32]);
        let store = BootstrapStore::new(&root, "slot");
        assert!(matches!(
            store.import_expected(&expected(&first), second.record()),
            Err(BootstrapStoreError::ContextMismatch { .. })
        ));
        assert!(matches!(
            store.import_expected(&expected(&second), first.record()),
            Err(BootstrapStoreError::ContextMismatch { .. })
        ));
        assert!(matches!(
            store.restore(),
            Err(BootstrapStoreError::Missing { .. })
        ));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn concurrent_conflicting_writers_have_one_winner_and_no_replacement() {
        let root = root();
        let first = closed("scope-a", 6, [6; 32]);
        let second = closed("scope-a", 7, [7; 32]);
        let store = std::sync::Arc::new(BootstrapStore::new(&root, "slot"));
        let first_record = first.record().clone();
        let second_record = second.record().clone();
        let first_expected = expected(&first);
        let second_expected = expected(&second);
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
        let left_store = std::sync::Arc::clone(&store);
        let left_barrier = std::sync::Arc::clone(&barrier);
        let left = std::thread::spawn(move || {
            left_barrier.wait();
            left_store.import_expected(&first_expected, first_record)
        });
        let right_store = std::sync::Arc::clone(&store);
        let right_barrier = std::sync::Arc::clone(&barrier);
        let right = std::thread::spawn(move || {
            right_barrier.wait();
            right_store.import_expected(&second_expected, second_record)
        });
        barrier.wait();
        let left = left.join().expect("left writer");
        let right = right.join().expect("right writer");
        assert_eq!(left.is_ok(), right.is_err());
        assert_eq!(left.is_err(), right.is_ok());
        let restored = store.restore().expect("one established record remains");
        assert!(restored == first || restored == second);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn semantic_snapshot_round_trips_projection_and_provisional_custody() {
        let root = root();
        let signing_key = key(12);
        let bootstrap = closed("scope-a", 12, [12; 32]);
        let fact = root_fact(&bootstrap, &signing_key);
        let mut graph = FactGraph::from_bootstrap(&bootstrap);
        graph.admit(fact.clone()).expect("root fact admits");
        let author =
            super::super::DeviceId::from_public_key_bytes(*signing_key.verifying_key().as_bytes())
                .expect("test root id");
        let missing = FactId::from_bytes([0xabu8; 32]);
        let unresolved = SignedFact::sign(
            FactContent::new(
                FactDomain::Governance,
                bootstrap.context_id(),
                FactBody::RoleGrant {
                    target: author.clone(),
                    role: super::super::Role::Member,
                },
                author,
                vec![missing],
            ),
            &signing_key,
        )
        .expect("unresolved fact signs");
        graph
            .admit(unresolved.clone())
            .expect("missing-parent fact quarantines");
        let store = DurableSemanticStore::new(&root, "semantic-slot");
        let custody = ProvisionalCustody::new(unresolved.id, "writer-a");
        store
            .commit(&graph, vec![custody.clone()])
            .expect("atomic semantic commit");
        let restored = store.restore(&bootstrap).expect("semantic reopen");
        assert_eq!(restored.graph().len(), 1);
        assert_eq!(
            restored
                .graph()
                .quarantined()
                .map(|(id, _)| *id)
                .collect::<Vec<_>>(),
            vec![unresolved.id]
        );
        assert_eq!(restored.provisional_custody(), &[custody]);
        let compacted = store.compact(&bootstrap).expect("compact and reopen");
        assert_eq!(compacted.graph().len(), 1);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn writer_lease_excludes_a_competing_process_and_releases_on_drop() {
        let root = root();
        let store = DurableSemanticStore::new(&root, "lease-slot");
        let lease = store.begin_write().expect("first writer lease");
        assert!(matches!(
            store.begin_write(),
            Err(DurableStoreError::WriterBusy { .. })
        ));
        drop(lease);
        store.begin_write().expect("lease released");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn interrupted_temporary_write_does_not_hide_the_last_complete_snapshot() {
        let root = root();
        let bootstrap = closed("scope-a", 13, [13; 32]);
        let graph = FactGraph::from_bootstrap(&bootstrap);
        let store = DurableSemanticStore::new(&root, "restart-slot");
        store.commit(&graph, Vec::new()).expect("initial snapshot");

        #[cfg(not(windows))]
        let stale_temp = store.path().with_extension("json.tmp");
        #[cfg(windows)]
        let stale_temp = store
            .path()
            .parent()
            .expect("snapshot parent")
            .join(format!(
                ".{}.{}.{}.tmp",
                store
                    .path()
                    .file_name()
                    .expect("snapshot name")
                    .to_string_lossy(),
                std::process::id(),
                u64::MAX
            ));
        std::fs::write(&stale_temp, b"interrupted replacement").expect("interrupted temp");
        assert_eq!(
            store
                .restore(&bootstrap)
                .expect("reopen old snapshot")
                .graph()
                .len(),
            0
        );
        store
            .commit(&graph, Vec::new())
            .expect("next commit replaces interrupted temp");
        #[cfg(not(windows))]
        assert!(!stale_temp.exists());
        #[cfg(windows)]
        {
            assert!(
                stale_temp.exists(),
                "unrelated unique stale temp is not broad-cleaned"
            );
            let _ = std::fs::remove_file(stale_temp);
        }
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn tampered_projection_or_custody_envelope_is_rejected_by_checksum() {
        let root = root();
        let bootstrap = closed("scope-a", 14, [14; 32]);
        let graph = FactGraph::from_bootstrap(&bootstrap);
        let store = DurableSemanticStore::new(&root, "checksum-slot");
        store.commit(&graph, Vec::new()).expect("initial snapshot");
        let mut snapshot: DurableSnapshot =
            serde_json::from_slice(&std::fs::read(store.path()).expect("snapshot bytes"))
                .expect("snapshot envelope");
        snapshot.projection_commitment[0] ^= 1;
        std::fs::write(
            store.path(),
            serde_json::to_vec(&snapshot).expect("tampered envelope"),
        )
        .expect("tampered snapshot");
        assert!(matches!(
            store.restore(&bootstrap),
            Err(DurableStoreError::ChecksumMismatch { .. })
        ));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn provisional_custody_must_name_a_fact_in_the_rebuilt_graph() {
        let root = root();
        let bootstrap = closed("scope-a", 15, [15; 32]);
        let graph = FactGraph::from_bootstrap(&bootstrap);
        let store = DurableSemanticStore::new(&root, "custody-fact-slot");
        store.commit(&graph, Vec::new()).expect("initial snapshot");
        let mut snapshot: DurableSnapshot =
            serde_json::from_slice(&std::fs::read(store.path()).expect("snapshot bytes"))
                .expect("snapshot envelope");
        snapshot.provisional = vec![ProvisionalCustody::new(
            FactId::from_bytes([0xabu8; 32]),
            "orphan",
        )];
        snapshot.checksum = snapshot.calculate_checksum().expect("custody checksum");
        std::fs::write(
            store.path(),
            serde_json::to_vec(&snapshot).expect("custody envelope"),
        )
        .expect("custody snapshot");
        assert!(matches!(
            store.restore(&bootstrap),
            Err(DurableStoreError::UnknownCustodyFact)
        ));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn child_process_contention_and_hard_death_release_the_writer() {
        let root = root();
        let ready = root.join("child-ready");
        let store = DurableSemanticStore::new(&root, "child-slot");
        let mut child = Command::new(std::env::current_exe().expect("test executable"))
            .arg("child_writer_holds_lease")
            .env("MYOWNMESH_STORE_CHILD_ROOT", &root)
            .env("MYOWNMESH_STORE_CHILD_READY", &ready)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn child writer");
        let deadline = Instant::now() + Duration::from_secs(5);
        while !ready.exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        let child_ready = ready.exists();
        let contended = matches!(
            store.begin_write(),
            Err(DurableStoreError::WriterBusy { .. })
        );
        child.kill().expect("hard-stop child writer");
        child.wait().expect("reap child writer");
        assert!(child_ready, "child must publish that its lease is held");
        assert!(contended, "live child writer must exclude this process");
        store
            .begin_write()
            .expect("hard-dead child must not strand the writer lease");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn child_writer_holds_lease() {
        let (Some(root), Some(ready)) = (
            std::env::var_os("MYOWNMESH_STORE_CHILD_ROOT"),
            std::env::var_os("MYOWNMESH_STORE_CHILD_READY"),
        ) else {
            return;
        };
        let store = DurableSemanticStore::new(root, "child-slot");
        let _lease = store.begin_write().expect("child writer lease");
        std::fs::write(ready, b"ready").expect("child ready marker");
        std::thread::sleep(Duration::from_secs(30));
    }
}
