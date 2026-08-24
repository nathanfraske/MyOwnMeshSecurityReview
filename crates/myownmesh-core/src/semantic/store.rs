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
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use data_encoding::BASE32_NOPAD;
use serde_json::Error as JsonError;
use sha2::{Digest, Sha256};
use thiserror::Error;

use super::{
    BootstrapError, BootstrapRecord, ExpectedMeshContext, MeshContextId, VerifiedBootstrap,
};

const BOOTSTRAP_DIRECTORY: &str = "bootstrap";
static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

/// A local store for one bootstrap record.
///
/// `local_slot` is deliberately only a locator.  It is hashed for the file
/// name and never enters [`BootstrapRecord`] validation or authority checks.
#[derive(Debug, Clone)]
pub struct BootstrapStore {
    path: PathBuf,
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

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use std::sync::atomic::{AtomicUsize, Ordering};

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
}
