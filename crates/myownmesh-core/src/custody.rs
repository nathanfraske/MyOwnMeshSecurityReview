//! Per-device custody MFA (TOTP) for closed-network governance.
//!
//! A device may enroll a TOTP authenticator (RFC 6238, HMAC-SHA1, the
//! shape every standard authenticator app speaks) against a specific
//! network. Once enrolled, **this device refuses to *author* — propose or
//! co-sign — a governance transition for that network without a fresh
//! second-factor code**. It is a *local custody lock*: it guards this
//! device's signing authority against misuse (a transferred laptop, a
//! shoulder-surfer, a stray script), and it is deliberately **not** a
//! replacement for the network's cryptographic owner-quorum — that still
//! protects against *remote* forgery. The two compose: quorum says "enough
//! owners agreed", custody says "and this owner really meant it, here and
//! now".
//!
//! Scope is per `(device, network)`: each owner device enrolls its own
//! secret; there is no shared "fleet password" to leak. Enrollment lives in
//! `~/.myownmesh/.secrets/custody.json` (0600), never gossiped.
//!
//! The gate is [`require`]; enrollment management is [`enroll`] /
//! [`is_enrolled`] / [`disable`]. Higher layers decide *which* networks must
//! enroll (e.g. a Fleet mandates it, a Mesh may not) — this module only
//! enforces the lock once it exists. Provisional installs carry a local
//! process-incarnation fence, so startup recovery can remove a handoff left
//! behind by hard process death without removing a live handoff.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

type HmacSha1 = Hmac<Sha1>;

/// TOTP digits — 6 is the universal authenticator default.
const DIGITS: u32 = 6;
/// TOTP step in seconds — 30 is the universal default.
const PERIOD: u64 = 30;
/// Accept the code from one step either side of now, to tolerate clock
/// skew and a code typed as the window rolls. (±30s.)
const SKEW_STEPS: i64 = 1;
/// Shared-secret length. RFC 4226 recommends ≥160 bits.
const SECRET_LEN: usize = 20;
/// One-time recovery codes minted at enrollment.
const RECOVERY_CODES: usize = 10;
/// Issuer label shown in the authenticator app.
const ISSUER: &str = "MyOwnMesh";

// ---------------------------------------------------------------------------
// On-disk model
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct CustodyStore {
    #[serde(default)]
    networks: BTreeMap<String, Enrollment>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Enrollment {
    /// Base32 (RFC 4648, no pad) TOTP shared secret.
    secret_b32: String,
    /// SHA-256 hex of each *unused* one-time recovery code. A code is
    /// removed from this list the moment it is consumed.
    recovery_hashes: Vec<String>,
    created_at: u64,
    /// True only between the durable install and the caller's handoff.
    #[serde(default)]
    provisional: bool,
    #[serde(default)]
    process_nonce: String,
}

/// What [`enroll`] hands back to show the user exactly once: the secret (as
/// base32 and as an `otpauth://` URI for QR rendering) and the cleartext
/// recovery codes. None of the cleartext is persisted — only the secret and
/// the recovery-code *hashes* live on disk.
#[derive(Debug, Clone, Serialize)]
pub struct Enrolled {
    pub secret_b32: String,
    pub otpauth_uri: String,
    pub recovery_codes: Vec<String>,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Whether this device holds a custody enrollment for `network_id`.
pub fn is_enrolled(network_id: &str) -> bool {
    store_path()
        .ok()
        .and_then(|p| {
            recover_provisional_at(&p).ok()?;
            load_at(&p).ok()
        })
        .map(|s| s.networks.contains_key(network_id))
        .unwrap_or(false)
}

/// One enrollment that is **installed** but is not yet its caller's.
///
/// Custody material is the one thing a caller cannot ask for twice: the secret
/// and the recovery codes are shown exactly once and are never recoverable from
/// disk. That makes both orderings wrong on their own. Writing after the
/// response is sent lets a device be told it is locked when the write then
/// failed and it is not; never writing until then lets two callers both be told
/// they are locked, because neither one exists to refuse the other.
///
/// So the lock is installed *first*, under the store's serializing lock, and
/// this value is the
/// rollback that owns it until the material has been handed over. A successful
/// response therefore names a lock that already exists, and an install that
/// failed is an error response rather than a promise.
///
/// **Armed while it lives.** The undo runs on drop, so an unwind between the
/// install and the handoff cannot strand a lock whose secret went nowhere —
/// which, since `disable` requires a valid code, is a lock nobody could satisfy
/// and nobody could remove. [`Self::keep`] disarms it; [`Self::roll_back`]
/// performs it now and reports what happened.
///
/// **Exactly this record.** The undo compares the currently-installed secret
/// against the one it installed and removes only on equality, so a rollback that
/// runs late cannot take a successor's lock away: a second enrollment carries 20
/// fresh random bytes, and the comparison fails.
#[must_use = "an enrollment that is neither kept nor rolled back is undone on drop"]
pub struct ProvisionalEnrollment {
    /// The store this was installed in — held so the undo cannot be pointed at
    /// a different one, and so the controls never touch the real one.
    path: PathBuf,
    network_id: String,
    enrolled: Enrolled,
    /// An OS-held lease for this exact provisional record. The kernel drops
    /// it when the process dies, which is the cross-process liveness fence
    /// recovery needs; a nonce in the JSON alone cannot distinguish a live
    /// process from a different process that merely started later.
    lease: Option<OwnerLease>,
    /// False once [`Self::keep`] or [`Self::roll_back`] has settled this.
    armed: bool,
}

impl ProvisionalEnrollment {
    /// The material the caller must show exactly once.
    pub fn enrolled(&self) -> &Enrolled {
        &self.enrolled
    }

    /// The network this locks.
    pub fn network_id(&self) -> &str {
        &self.network_id
    }

    /// The caller has the material, so the installed lock is this device's.
    ///
    /// Durably hand the installed lock to the caller and disarm the undo.
    ///
    /// The handoff is itself atomic. If the process dies during this write,
    /// restart recovery sees either the old provisional record and removes it,
    /// or the new committed record and keeps it. The historical `keep` API is
    /// intentionally infallible for callers that are already sending a
    /// response; on an I/O error the value stays armed and its `Drop` performs
    /// the exact rollback instead of stranding an unowned lock.
    pub fn keep(mut self) {
        if let Err(error) = self.commit() {
            tracing::warn!(
                network = %self.network_id,
                "a provisional MFA enrollment could not be committed: {error}"
            );
        }
    }

    fn commit(&mut self) -> Result<()> {
        commit_exact_at(&self.path, &self.network_id, &self.enrolled.secret_b32)?;
        self.lease.take();
        self.armed = false;
        Ok(())
    }

    /// The caller does not have the material, so remove exactly this lock.
    ///
    /// Reported rather than swallowed, so a daemon whose store it could not
    /// reach says so. The drop below runs the same removal for the paths that
    /// cannot report — an unwind, or a caller that dropped the value.
    ///
    /// Disarmed only once the removal has actually happened. A failed explicit
    /// rollback that gave up ownership would leave the very lock this exists to
    /// remove installed and unowned; instead the value stays armed, so the drop
    /// that immediately follows tries once more. The retry is safe because the
    /// removal is exact and idempotent: it removes this record or nothing.
    pub fn roll_back(mut self) -> Result<()> {
        remove_exact_at(&self.path, &self.network_id, &self.enrolled.secret_b32)?;
        self.lease.take();
        self.armed = false;
        Ok(())
    }
}

impl Drop for ProvisionalEnrollment {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if let Err(error) = remove_exact_at(&self.path, &self.network_id, &self.enrolled.secret_b32)
        {
            tracing::warn!(
                network = %self.network_id,
                "a provisional MFA enrollment could not be rolled back: {error}"
            );
        }
        self.lease.take();
    }
}

/// Enroll a fresh TOTP authenticator for `network_id` on this device.
/// `account` is the human label shown in the authenticator app (e.g. the
/// device label). Fails if an enrollment already exists — [`disable`] it
/// first (which itself requires a valid code), so the lock can't be
/// silently rotated away.
///
/// Installs and keeps in one step. A caller that has to hand the material to
/// somebody else before it can say the enrollment succeeded uses
/// [`install_provisional_enroll`] and settles it against whether the handoff
/// actually happened.
pub fn enroll(network_id: &str, account: &str) -> Result<Enrolled> {
    let mut provisional = install_provisional_enroll(network_id, account)?;
    let enrolled = provisional.enrolled.clone();
    provisional.commit()?;
    Ok(enrolled)
}

/// Install an enrollment whose rollback the caller owns. See
/// [`ProvisionalEnrollment`].
pub fn install_provisional_enroll(
    network_id: &str,
    account: &str,
) -> Result<ProvisionalEnrollment> {
    let path = store_path()?;
    recover_provisional_at(&path)?;
    install_provisional_enroll_at(&path, network_id, account)
}

/// Remove provisional enrollments whose OS owner lease is no longer held.
///
/// Callers may invoke this at daemon startup, and all public custody entry
/// points perform the same check before reading or mutating the store. A live
/// provisional handoff in another process is retained by its kernel-held lease;
/// a record written by a process that died before its response was handed off
/// is removed. The operation is exact, serialized, and idempotent.
pub fn recover_provisional_enrollments() -> Result<usize> {
    recover_provisional_at(&store_path()?)
}

/// The gate. `Ok(())` when the network has no enrollment on this device (the
/// lock is a no-op) **or** when `code` verifies — a TOTP for the current
/// window, or a one-time recovery code, which is then consumed. `Err`
/// otherwise. Custody-affecting governance authoring calls this before it
/// signs.
pub fn require(network_id: &str, code: Option<&str>) -> Result<()> {
    let path = store_path()?;
    recover_provisional_at(&path)?;
    require_at(&path, network_id, code)
}

/// Remove the custody lock for `network_id` — but only on presentation of a
/// valid code, so the lock can't be undone by someone who doesn't already
/// satisfy it.
pub fn disable(network_id: &str, code: &str) -> Result<()> {
    let path = store_path()?;
    recover_provisional_at(&path)?;
    disable_at(&path, network_id, code)
}

// ---------------------------------------------------------------------------
// Path-injectable core (so unit tests never touch the real secrets dir)
// ---------------------------------------------------------------------------

/// Serializes every read-modify-write of the custody store.
///
/// The store is one file read, checked, edited and written back, and the check
/// is what makes "this device has one lock" true. Two of those sequences
/// interleaving is the whole failure: both read a store with no entry for the
/// network, both pass the duplicate check, both write, and the last write wins —
/// so two callers are told they are enrolled and only one of the two secrets
/// opens the lock that survives. `write_atomic` prevents a torn file; it cannot
/// prevent a lost update, because the loser's read happened before the winner's
/// write existed to be read.
///
/// Held across load → check → save and never across an `await`, since nothing
/// under it is async. Poison-tolerant: a caller that panicked mid-sequence left
/// the *file* consistent — `save_at` is atomic — so refusing every later
/// enrollment because of it would turn one panic into a permanently unusable
/// custody store.
static STORE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
static PROCESS_NONCE: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// A process-owned lease for one exact provisional record. The file is
/// deliberately retained only as long as its owner is live; its advisory
/// kernel lock is the authority and the contents are diagnostic metadata,
/// never a liveness decision. The record secret is part of the lease path, so
/// disabling this record permits a successor to acquire a distinct lease even
/// while a stale same-process handle still awaits its exact rollback.
struct OwnerLease {
    file: File,
    #[cfg(windows)]
    overlapped: Box<WinOverlapped>,
}

impl OwnerLease {
    fn acquire(path: &Path, network_id: &str, record_secret: &str, nonce: &str) -> Result<Self> {
        let lease_path = owner_lease_path(path, network_id, record_secret);
        if let Some(parent) = lease_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| Error::Custody(format!("create custody lease dir: {e}")))?;
        }
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&lease_path)
            .map_err(|e| Error::Custody(format!("open custody owner lease: {e}")))?;
        #[cfg(unix)]
        if !try_lock_owner_file(&file)
            .map_err(|e| Error::Custody(format!("lock custody owner lease: {e}")))?
        {
            return Err(Error::Custody(format!(
                "a live process owns the provisional custody lease for {network_id}"
            )));
        }
        #[cfg(windows)]
        let overlapped = try_lock_owner_file(&file)
            .map_err(|e| Error::Custody(format!("lock custody owner lease: {e}")))?;
        #[cfg(not(any(unix, windows)))]
        return Err(Error::Custody(
            "cross-process custody leases are unsupported on this platform".into(),
        ));

        let mut lease = Self {
            file,
            #[cfg(windows)]
            overlapped,
        };
        lease
            .file
            .set_len(0)
            .and_then(|_| {
                lease
                    .file
                    .write_all(format!("{} {nonce}\n", std::process::id()).as_bytes())
            })
            .and_then(|_| lease.file.sync_data())
            .map_err(|e| Error::Custody(format!("write custody owner lease: {e}")))?;
        restrict_file(&lease_path);
        Ok(lease)
    }
}

impl Drop for OwnerLease {
    fn drop(&mut self) {
        #[cfg(unix)]
        unlock_owner_file(&self.file);
        #[cfg(windows)]
        unlock_owner_file(&self.file, &mut self.overlapped);
        // Retain the stable pathname. Removing it after unlock allows a
        // contender to lock the old inode/handle before unlink while another
        // process creates and locks a replacement file. The kernel lock, not
        // pathname lifetime, is the liveness authority.
    }
}

/// The shared custody file is one logical map even when two processes mutate
/// different network keys. This lease serializes the complete load/check/
/// mutate/save transaction across processes; it is never unlinked, so every
/// contender always refers to the same inode.
struct WriterLease {
    file: File,
    #[cfg(windows)]
    overlapped: Box<WinOverlapped>,
}

impl WriterLease {
    fn acquire(path: &Path) -> Result<Self> {
        let lease_path = writer_lease_path(path);
        if let Some(parent) = lease_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| Error::Custody(format!("create writer lease dir: {e}")))?;
        }
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&lease_path)
            .map_err(|e| Error::Custody(format!("open custody writer lease: {e}")))?;
        restrict_file(&lease_path);
        #[cfg(unix)]
        lock_writer_file(&file)
            .map_err(|e| Error::Custody(format!("lock custody writer lease: {e}")))?;
        #[cfg(windows)]
        let overlapped = lock_writer_file(&file)
            .map_err(|e| Error::Custody(format!("lock custody writer lease: {e}")))?;
        #[cfg(not(any(unix, windows)))]
        return Err(Error::Custody(
            "cross-process custody leases are unsupported on this platform".into(),
        ));
        Ok(Self {
            file,
            #[cfg(windows)]
            overlapped,
        })
    }
}

impl Drop for WriterLease {
    fn drop(&mut self) {
        #[cfg(unix)]
        unlock_owner_file(&self.file);
        #[cfg(windows)]
        unlock_owner_file(&self.file, &mut self.overlapped);
    }
}

fn owner_lease_path(path: &Path, network_id: &str, record_secret: &str) -> PathBuf {
    let mut digest = Sha256::new();
    digest.update(network_id.as_bytes());
    digest.update([0]);
    digest.update(record_secret.as_bytes());
    path.with_file_name(format!(
        "{}.{}.lease",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("custody"),
        hex::encode(digest.finalize())
    ))
}

fn writer_lease_path(path: &Path) -> PathBuf {
    path.with_file_name(format!(
        "{}.writer.lock",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("custody")
    ))
}

#[cfg(unix)]
fn try_lock_owner_file(file: &File) -> io::Result<bool> {
    use std::os::fd::AsRawFd;
    unsafe {
        unsafe extern "C" {
            fn flock(fd: i32, operation: i32) -> i32;
        }
        const LOCK_EX: i32 = 2;
        const LOCK_NB: i32 = 4;
        if flock(file.as_raw_fd(), LOCK_EX | LOCK_NB) == 0 {
            Ok(true)
        } else if io::Error::last_os_error().kind() == io::ErrorKind::WouldBlock {
            Ok(false)
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

#[cfg(unix)]
fn unlock_owner_file(file: &File) {
    use std::os::fd::AsRawFd;
    unsafe {
        unsafe extern "C" {
            fn flock(fd: i32, operation: i32) -> i32;
        }
        const LOCK_UN: i32 = 8;
        let _ = flock(file.as_raw_fd(), LOCK_UN);
    }
}

#[cfg(unix)]
fn lock_writer_file(file: &File) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    unsafe {
        unsafe extern "C" {
            fn flock(fd: i32, operation: i32) -> i32;
        }
        const LOCK_EX: i32 = 2;
        if flock(file.as_raw_fd(), LOCK_EX) == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

#[cfg(windows)]
#[repr(C)]
struct WinOverlapped {
    internal: usize,
    internal_high: usize,
    offset: u32,
    offset_high: u32,
    event: *mut std::ffi::c_void,
}

#[cfg(windows)]
// SAFETY: The OVERLAPPED value is allocated in a Box and is never moved after
// LockFileEx receives its address. Moving the owning Box between threads keeps
// that address stable. `event` is always null, so there is no event handle or
// other pointed-to state to transfer. Windows associates the byte-range lock
// with the file handle, and UnlockFileEx accepts that same handle from the
// thread that owns the moved lease. The lease remains uniquely owned, so no
// concurrent access to the OVERLAPPED value is possible.
unsafe impl Send for WinOverlapped {}

#[cfg(windows)]
fn try_lock_owner_file(file: &File) -> io::Result<Box<WinOverlapped>> {
    use std::os::windows::io::AsRawHandle;
    unsafe {
        unsafe extern "system" {
            fn LockFileEx(
                file: *mut std::ffi::c_void,
                flags: u32,
                reserved: u32,
                low: u32,
                high: u32,
                overlapped: *mut WinOverlapped,
            ) -> i32;
        }
        const LOCKFILE_EXCLUSIVE_LOCK: u32 = 2;
        const LOCKFILE_FAIL_IMMEDIATELY: u32 = 1;
        let mut overlapped = Box::new(WinOverlapped {
            internal: 0,
            internal_high: 0,
            offset: 0,
            offset_high: 0,
            event: std::ptr::null_mut(),
        });
        if LockFileEx(
            file.as_raw_handle(),
            LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
            0,
            u32::MAX,
            u32::MAX,
            &mut *overlapped,
        ) != 0
        {
            Ok(overlapped)
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

#[cfg(windows)]
fn unlock_owner_file(file: &File, overlapped: &mut WinOverlapped) {
    use std::os::windows::io::AsRawHandle;
    unsafe {
        unsafe extern "system" {
            fn UnlockFileEx(
                file: *mut std::ffi::c_void,
                reserved: u32,
                low: u32,
                high: u32,
                overlapped: *mut WinOverlapped,
            ) -> i32;
        }
        let _ = UnlockFileEx(file.as_raw_handle(), 0, u32::MAX, u32::MAX, overlapped);
    }
}

#[cfg(windows)]
fn lock_writer_file(file: &File) -> io::Result<Box<WinOverlapped>> {
    use std::os::windows::io::AsRawHandle;
    unsafe {
        unsafe extern "system" {
            fn LockFileEx(
                file: *mut std::ffi::c_void,
                flags: u32,
                reserved: u32,
                low: u32,
                high: u32,
                overlapped: *mut WinOverlapped,
            ) -> i32;
        }
        const LOCKFILE_EXCLUSIVE_LOCK: u32 = 2;
        let mut overlapped = Box::new(WinOverlapped {
            internal: 0,
            internal_high: 0,
            offset: 0,
            offset_high: 0,
            event: std::ptr::null_mut(),
        });
        if LockFileEx(
            file.as_raw_handle(),
            LOCKFILE_EXCLUSIVE_LOCK,
            0,
            u32::MAX,
            u32::MAX,
            &mut *overlapped,
        ) != 0
        {
            Ok(overlapped)
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

#[cfg(not(any(unix, windows)))]
fn unlock_owner_file(_file: &File) {}

fn store_guard() -> std::sync::MutexGuard<'static, ()> {
    STORE_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

fn store_transaction_guard(
    path: &Path,
) -> Result<(std::sync::MutexGuard<'static, ()>, WriterLease)> {
    let serialized = store_guard();
    let writer = WriterLease::acquire(path)?;
    Ok((serialized, writer))
}

fn install_provisional_enroll_at(
    path: &Path,
    network_id: &str,
    account: &str,
) -> Result<ProvisionalEnrollment> {
    recover_provisional_at(path)?;
    let (_serialized, _writer) = store_transaction_guard(path)?;
    let mut store = load_at(path)?;
    if store.networks.contains_key(network_id) {
        return Err(Error::Custody(format!(
            "network {network_id} already has MFA enrolled on this device; disable it first"
        )));
    }
    let secret = random_bytes(SECRET_LEN);
    let secret_b32 = BASE32_NOPAD.encode(&secret);
    let recovery_codes = gen_recovery_codes();
    let recovery_hashes = recovery_codes.iter().map(|c| hash_code(c)).collect();
    let otpauth_uri = provisioning_uri(&secret_b32, account);
    let lease = OwnerLease::acquire(path, network_id, &secret_b32, process_nonce())?;
    store.networks.insert(
        network_id.to_string(),
        Enrollment {
            secret_b32: secret_b32.clone(),
            recovery_hashes,
            created_at: now_unix(),
            provisional: true,
            process_nonce: process_nonce().to_string(),
        },
    );
    // Written before anything is answered, so what comes back names a lock that
    // exists. A failure here is the caller's failure: no material has been
    // shown, and nothing is installed.
    save_at(path, &store)?;
    Ok(ProvisionalEnrollment {
        path: path.to_path_buf(),
        network_id: network_id.to_string(),
        enrolled: Enrolled {
            secret_b32,
            otpauth_uri,
            recovery_codes,
        },
        lease: Some(lease),
        armed: true,
    })
}

/// Commit the exact installed record, preserving the same generation fence
/// used by rollback. A stale handle can never commit a successor, and a
/// record already committed by an earlier idempotent handoff is left alone.
fn commit_exact_at(path: &Path, network_id: &str, secret_b32: &str) -> Result<()> {
    let (_serialized, _writer) = store_transaction_guard(path)?;
    let mut store = load_at(path)?;
    let Some(installed) = store.networks.get_mut(network_id) else {
        return Ok(());
    };
    if !constant_eq(installed.secret_b32.as_bytes(), secret_b32.as_bytes())
        || !installed.provisional
        || installed.process_nonce != process_nonce()
    {
        return Ok(());
    }
    installed.provisional = false;
    installed.process_nonce.clear();
    save_at(path, &store)
}

/// Recover only records whose provisional owner belongs to a dead process.
///
/// Liveness is decided by the kernel-held owner lease, not by comparing the
/// diagnostic process nonce.
fn recover_provisional_at(path: &Path) -> Result<usize> {
    #[cfg(not(any(unix, windows)))]
    return Err(Error::Custody(
        "cross-process custody recovery is unsupported on this platform".into(),
    ));

    let (_serialized, _writer) = store_transaction_guard(path)?;
    let mut store = load_at(path)?;
    let mut stale = Vec::new();
    let mut leases = Vec::new();
    for (network_id, enrollment) in &store.networks {
        // The nonce is diagnostic metadata only. A failed rollback may release
        // its OS lease while leaving the current process nonce on disk, so
        // every provisional record must still be checked against its exact
        // per-secret kernel lease.
        if !enrollment.provisional {
            continue;
        }
        let lease_path = owner_lease_path(path, network_id, &enrollment.secret_b32);
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&lease_path)
            .map_err(|e| Error::Custody(format!("open custody recovery lease: {e}")))?;
        #[cfg(unix)]
        let acquired = try_lock_owner_file(&file)
            .map_err(|e| Error::Custody(format!("lock custody recovery lease: {e}")))?;
        #[cfg(windows)]
        let overlapped = match try_lock_owner_file(&file) {
            Ok(overlapped) => Some(overlapped),
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock
                    || error.raw_os_error() == Some(33) =>
            {
                None
            }
            Err(error) => {
                return Err(Error::Custody(format!(
                    "lock custody recovery lease: {error}"
                )));
            }
        };
        #[cfg(windows)]
        let acquired = overlapped.is_some();
        #[cfg(not(any(unix, windows)))]
        let acquired = false;
        if acquired {
            stale.push(network_id.clone());
            leases.push(OwnerLease {
                file,
                #[cfg(windows)]
                overlapped: overlapped.expect("acquired lease has lock state"),
            });
        }
    }
    if stale.is_empty() {
        return Ok(0);
    }
    for network_id in &stale {
        store.networks.remove(network_id);
    }
    save_at(path, &store)?;
    drop(leases);
    Ok(stale.len())
}

/// Remove `network_id`'s lock, but only while it is still the exact one
/// `secret_b32` names.
///
/// The comparison is the difference between an undo and a denial of service. A
/// rollback that keys on the network alone removes whatever lock is installed by
/// the time it runs — including a successor the operator enrolled after the
/// first attempt failed, whose material *was* delivered. Constant-time, for the
/// same reason every other comparison against stored custody material here is.
fn remove_exact_at(path: &Path, network_id: &str, secret_b32: &str) -> Result<()> {
    let (_serialized, _writer) = store_transaction_guard(path)?;
    let mut store = load_at(path)?;
    let Some(installed) = store.networks.get(network_id) else {
        // Already gone — disabled, or rolled back once already. Same end state.
        return Ok(());
    };
    if !constant_eq(installed.secret_b32.as_bytes(), secret_b32.as_bytes()) {
        // A successor holds this network. It is not this rollback's to remove.
        return Ok(());
    }
    store.networks.remove(network_id);
    save_at(path, &store)
}

#[cfg(test)]
fn enroll_at(path: &Path, network_id: &str, account: &str) -> Result<Enrolled> {
    let mut provisional = install_provisional_enroll_at(path, network_id, account)?;
    let enrolled = provisional.enrolled.clone();
    provisional.commit()?;
    Ok(enrolled)
}

/// What a supplied code earns against one exact enrollment record.
enum CodeVerdict {
    /// A TOTP for the current window. Nothing about the record changes, and
    /// nothing is owed to disk.
    Totp,
    /// A one-time recovery code, at this position in `recovery_hashes`.
    ///
    /// Consuming it is the *caller's* write, not this check's, because whether
    /// a write is owed depends on what the caller does with the record next: a
    /// gate that keeps the enrollment has to burn the code, and a disable that
    /// removes the whole record has nothing left to burn it out of.
    Recovery(usize),
}

/// Check `code` against one already-loaded enrollment.
///
/// Factored out so both callers authorize identically **and neither has to
/// reach for the store lock to do it**. That second half is the load-bearing
/// one: `disable_at` used to authorize by calling the lock-taking gate, which
/// released [`STORE_LOCK`] before the removal ran, and the removal then deleted
/// whichever record existed by the time it reacquired. Two local control
/// requests were enough — a disable against a network with no enrollment
/// returned `Ok` without validating anything, and then removed a *successor*
/// that a concurrent enroll had installed and already answered for. Verification
/// is a pure function of one record, so it belongs where the record is, under
/// the caller's own guard.
fn verify_code(enrollment: &Enrollment, code: Option<&str>) -> Result<CodeVerdict> {
    let Some(code) = code.map(str::trim).filter(|c| !c.is_empty()) else {
        return Err(Error::Custody(
            "this change requires your authenticator code".into(),
        ));
    };
    // TOTP for the current window (±1 step) first.
    let secret = BASE32_NOPAD
        .decode(enrollment.secret_b32.as_bytes())
        .map_err(|e| Error::Custody(format!("stored secret is not valid base32: {e}")))?;
    if verify_totp_at(&secret, code, now_unix()) {
        return Ok(CodeVerdict::Totp);
    }
    // Otherwise a one-time recovery code.
    let h = hash_code(code);
    if let Some(pos) = enrollment
        .recovery_hashes
        .iter()
        .position(|x| constant_eq(x.as_bytes(), h.as_bytes()))
    {
        return Ok(CodeVerdict::Recovery(pos));
    }
    Err(Error::Custody("invalid authenticator code".into()))
}

fn require_at(path: &Path, network_id: &str, code: Option<&str>) -> Result<()> {
    // A recovery code is *consumed* on match, which makes this a store mutation
    // like any other: two gates racing on the same code could otherwise both
    // read it unused and both be admitted by it.
    let (_serialized, _writer) = store_transaction_guard(path)?;
    let mut store = load_at(path)?;
    let Some(enr) = store.networks.get_mut(network_id) else {
        return Ok(()); // not enrolled on this device → the gate is a no-op
    };
    match verify_code(enr, code)? {
        CodeVerdict::Totp => Ok(()),
        CodeVerdict::Recovery(pos) => {
            enr.recovery_hashes.remove(pos);
            save_at(path, &store)
        }
    }
}

fn disable_at(path: &Path, network_id: &str, code: &str) -> Result<()> {
    // One guard, one load, one verify, one removal, one save. The record the
    // code is checked against and the record that is removed are the same
    // borrow of the same loaded store, so nothing can be installed, rolled back
    // or replaced between the two — which is the whole correction here. The
    // previous shape authorized through the lock-taking gate and reacquired for
    // the removal, and that gap was enough for a disable to delete an
    // enrollment nobody had authorized it against.
    let (_serialized, _writer) = store_transaction_guard(path)?;
    let mut store = load_at(path)?;
    let Some(enrollment) = store.networks.get(network_id) else {
        // Nothing is installed, so there is nothing to remove and nothing to
        // write. Answering `Ok` keeps disable idempotent — the end state it
        // promises is "this network has no lock", which already holds — and
        // writing nothing is what makes that answer safe: the old shape's
        // unconditional removal-and-save is exactly what could take a
        // successor away.
        return Ok(());
    };
    // The verdict itself is spent here. A recovery code needs no consumption
    // write on this path: the same locked mutation removes the record the code
    // would have been burned out of, and saves once.
    verify_code(enrollment, Some(code))?;
    store.networks.remove(network_id);
    save_at(path, &store)
}

// ---------------------------------------------------------------------------
// TOTP / HOTP (RFC 6238 / RFC 4226)
// ---------------------------------------------------------------------------

fn hotp(secret: &[u8], counter: u64) -> u32 {
    let mut mac = HmacSha1::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    // Dynamic truncation (RFC 4226 §5.3).
    let offset = (digest[digest.len() - 1] & 0x0f) as usize;
    let bin = (u32::from(digest[offset] & 0x7f) << 24)
        | (u32::from(digest[offset + 1]) << 16)
        | (u32::from(digest[offset + 2]) << 8)
        | u32::from(digest[offset + 3]);
    bin % 10u32.pow(DIGITS)
}

// Computing a code *from the secret* is what an authenticator app does, not
// the daemon — the whole point of the second factor is that it comes from a
// separate device. So this lives test-only; production never derives its own
// code (it only ever `verify`s one supplied from outside).
#[cfg(test)]
fn totp_at(secret: &[u8], unix: u64) -> String {
    format!(
        "{:0width$}",
        hotp(secret, unix / PERIOD),
        width = DIGITS as usize
    )
}

fn verify_totp_at(secret: &[u8], code: &str, unix: u64) -> bool {
    let code = code.trim();
    if code.len() != DIGITS as usize || !code.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let step = (unix / PERIOD) as i64;
    for d in -SKEW_STEPS..=SKEW_STEPS {
        let counter = (step + d).max(0) as u64;
        let candidate = format!("{:0width$}", hotp(secret, counter), width = DIGITS as usize);
        if constant_eq(candidate.as_bytes(), code.as_bytes()) {
            return true;
        }
    }
    false
}

fn provisioning_uri(secret_b32: &str, account: &str) -> String {
    let label = format!("{}:{}", pct(ISSUER), pct(account));
    format!(
        "otpauth://totp/{label}?secret={secret_b32}&issuer={}&algorithm=SHA1&digits={DIGITS}&period={PERIOD}",
        pct(ISSUER)
    )
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Percent-encode everything but the RFC 3986 unreserved set.
fn pct(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn random_bytes(n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    if getrandom::getrandom(&mut v).is_err() {
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut v);
    }
    v
}

/// `RECOVERY_CODES` formatted as `xxxxx-xxxxx` (base32, lowercase).
fn gen_recovery_codes() -> Vec<String> {
    (0..RECOVERY_CODES)
        .map(|_| {
            let raw = BASE32_NOPAD.encode(&random_bytes(8)).to_lowercase();
            let c: String = raw.chars().take(10).collect();
            format!("{}-{}", &c[..5], &c[5..])
        })
        .collect()
}

/// Normalise (strip separators + case) then SHA-256-hex, so a recovery code
/// matches whether the user types the dashes or not.
fn hash_code(code: &str) -> String {
    let normalized: String = code
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .flat_map(|c| c.to_lowercase())
        .collect();
    let mut h = Sha256::new();
    h.update(normalized.as_bytes());
    hex::encode(h.finalize())
}

fn constant_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn process_nonce() -> &'static str {
    PROCESS_NONCE
        .get_or_init(|| hex::encode(random_bytes(16)))
        .as_str()
}

fn store_path() -> Result<PathBuf> {
    Ok(crate::dirs::secrets_dir()?.join("custody.json"))
}

fn load_at(path: &Path) -> Result<CustodyStore> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(serde_json::from_slice(&bytes)?),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(CustodyStore::default()),
        Err(e) => Err(Error::Custody(format!("read custody store: {e}"))),
    }
}

fn save_at(path: &Path, store: &CustodyStore) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| Error::Custody(format!("create secrets dir: {e}")))?;
        restrict_dir(parent);
    }
    let bytes = serde_json::to_vec_pretty(store)?;
    // Atomic so a power cut can't truncate the store. Note load_at
    // deliberately stays hard-fail on a corrupt file: falling back to
    // an empty store would silently turn OFF custody (MFA) for every
    // enrolled network — fail-open. Corruption is prevented here
    // instead of forgiven there.
    crate::persist::write_atomic(path, &bytes)
        .map_err(|e| Error::Custody(format!("write custody store: {e}")))?;
    restrict_file(path);
    Ok(())
}

#[cfg(unix)]
fn restrict_dir(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700));
}
#[cfg(unix)]
fn restrict_file(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}
#[cfg(not(unix))]
fn restrict_dir(_path: &Path) {}
#[cfg(not(unix))]
fn restrict_file(_path: &Path) {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6238 Appendix B reference vector (SHA-1 seed, T=59s). The 8-digit
    /// reference is 94287082; truncated to our 6 digits that's 287082.
    #[test]
    fn totp_matches_rfc6238_vector() {
        let secret = b"12345678901234567890";
        assert_eq!(totp_at(secret, 59), "287082");
        assert!(verify_totp_at(secret, "287082", 59));
        // A code from ten steps away is outside the ±1 skew window.
        assert!(!verify_totp_at(secret, "287082", 59 + 10 * PERIOD));
        // Wrong shape is rejected outright.
        assert!(!verify_totp_at(secret, "1234567", 59));
        assert!(!verify_totp_at(secret, "abcdef", 59));
    }

    #[test]
    fn skew_window_accepts_adjacent_steps() {
        let secret = b"12345678901234567890";
        let code = totp_at(secret, 1000);
        assert!(verify_totp_at(secret, &code, 1000));
        assert!(verify_totp_at(secret, &code, 1000 + PERIOD)); // +1 step
        assert!(verify_totp_at(secret, &code, 1000 - PERIOD)); // -1 step
        assert!(!verify_totp_at(secret, &code, 1000 + 2 * PERIOD)); // +2 steps: out
    }

    #[test]
    fn recovery_hash_is_separator_and_case_insensitive() {
        assert_eq!(hash_code("ABCDE-FGHIJ"), hash_code("abcdefghij"));
        assert_eq!(hash_code("ab cd ef"), hash_code("ABCDEF"));
        assert_ne!(hash_code("abcde"), hash_code("abcdf"));
    }

    #[test]
    fn provisioning_uri_is_authenticator_shaped() {
        let uri = provisioning_uri("JBSWY3DPEHPK3PXP", "my laptop");
        assert!(uri.starts_with("otpauth://totp/MyOwnMesh:my%20laptop?"));
        assert!(uri.contains("secret=JBSWY3DPEHPK3PXP"));
        assert!(uri.contains("algorithm=SHA1"));
        assert!(uri.contains("digits=6"));
        assert!(uri.contains("period=30"));
    }

    fn tmp() -> PathBuf {
        // A process-global counter guarantees a distinct path per call even
        // when tests run concurrently and the clock is too coarse to separate
        // them (observed flaking on macOS, where two disk tests collided on
        // one file and stomped each other's store).
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        std::env::temp_dir().join(format!(
            "mom-custody-test-{}-{}-{}.json",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed),
            now_unix_nanos()
        ))
    }
    fn now_unix_nanos() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    }

    #[test]
    fn enroll_then_gate_accepts_totp_and_consumes_recovery() {
        let path = tmp();
        let net = "fleet-xyz";

        // Not enrolled → the gate is a no-op even with no code.
        assert!(require_at(&path, net, None).is_ok());

        let enrolled = enroll_at(&path, net, "laptop").expect("enroll");
        assert_eq!(enrolled.recovery_codes.len(), RECOVERY_CODES);

        // Enrolled → a custody change with no code is refused.
        assert!(require_at(&path, net, None).is_err());
        // Wrong code refused.
        assert!(require_at(&path, net, Some("000000")).is_err());

        // A correct TOTP (computed from the returned secret, as an
        // authenticator app would) is accepted, and is reusable within its
        // window (TOTP is not one-time).
        let secret = BASE32_NOPAD.decode(enrolled.secret_b32.as_bytes()).unwrap();
        let code = totp_at(&secret, now_unix());
        assert!(require_at(&path, net, Some(&code)).is_ok());
        assert!(require_at(&path, net, Some(&code)).is_ok());

        // A recovery code works once, then is burned.
        let rc = &enrolled.recovery_codes[0];
        assert!(require_at(&path, net, Some(rc)).is_ok());
        assert!(
            require_at(&path, net, Some(rc)).is_err(),
            "a recovery code must be single-use"
        );

        // Other networks are unaffected (per-network scope).
        assert!(require_at(&path, "some-mesh", None).is_ok());

        let _ = std::fs::remove_file(&path);
    }

    /// Two callers enrolling one network at once leave one lock, and the one
    /// success is the secret that opens it.
    ///
    /// The discriminating case for install-before-answer. Two clients used to be
    /// able to run load → duplicate check → insert → save concurrently: both
    /// read a store with no entry, both passed the check, and the last write
    /// won. Both callers were told they were enrolled, and only one of the two
    /// secrets opened the lock that survived — the other held material for a
    /// lock that does not exist, on a device that now refuses to author
    /// governance without a code it cannot produce.
    ///
    /// Real threads and a barrier, so the two sequences genuinely overlap rather
    /// than being asserted to. The *outcome* is deterministic under every
    /// interleaving, which is the property: whichever thread takes
    /// [`STORE_LOCK`] first installs, and the other one's duplicate check now
    /// sees the entry the first wrote, because it is behind that same lock.
    #[test]
    fn v4_r7_core_b1_two_concurrent_enrollments_leave_one_lock_and_one_success() {
        let path = tmp();
        let net = "fleet-concurrent";

        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let racing: Vec<_> = (0..2)
            .map(|_| {
                let path = path.clone();
                let barrier = std::sync::Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    install_provisional_enroll_at(&path, net, "phone").map(|installed| {
                        let material = installed.enrolled().clone();
                        // The response reached its caller, so the lock stands.
                        installed.keep();
                        material
                    })
                })
            })
            .collect();
        let answered: Vec<Enrolled> = racing
            .into_iter()
            .filter_map(|thread| thread.join().expect("neither enrollment panics").ok())
            .collect();

        assert_eq!(
            answered.len(),
            1,
            "exactly one caller is told it enrolled; the other is refused, \
             rather than both being told yes and one of them being wrong"
        );
        let secret = BASE32_NOPAD
            .decode(answered[0].secret_b32.as_bytes())
            .expect("the answered secret is base32");
        let code = totp_at(&secret, now_unix());
        assert!(
            require_at(&path, net, Some(&code)).is_ok(),
            "and the secret that came back is the installed lock — not the \
             loser's, and not one that was overwritten"
        );
        assert!(
            require_at(&path, net, Some("000000")).is_err(),
            "non-vacuity: the gate is really locked, not accepting everything"
        );

        let _ = std::fs::remove_file(&path);
    }

    /// An enrollment whose material never reached its caller is removed — and a
    /// successor is not removed by that undo arriving late.
    ///
    /// Both halves of the rollback's contract, in the order production reaches
    /// them. The lock is installed *before* the response, so a response that is
    /// refused or whose socket ended leaves a lock nobody holds: `disable`
    /// requires a valid code, which is exactly what was lost, so nothing could
    /// ever remove it. The armed drop is what removes it, and the drop rather
    /// than an explicit call is deliberate — an unwind between the install and
    /// the handoff must not strand one either.
    ///
    /// The stale-undo half is driven end to end rather than asserted about: the
    /// first attempt's lock is cleared by the operator's own `disable`, a second
    /// enrollment is installed and *delivered*, and only then does the first
    /// attempt's rollback finally run. Keyed on the network alone it would take
    /// the successor's lock away; keyed on the exact installed secret it finds
    /// somebody else's 20 random bytes and leaves them alone.
    #[test]
    fn v4_r7_core_b1_an_unhanded_enrollment_is_removed_and_a_successor_survives_its_late_undo() {
        let path = tmp();
        let net = "fleet-unhanded";

        let unhanded = install_provisional_enroll_at(&path, net, "laptop").expect("install");
        assert_eq!(
            unhanded.enrolled().recovery_codes.len(),
            RECOVERY_CODES,
            "the caller is given the whole of what it must show exactly once"
        );
        assert_eq!(unhanded.network_id(), net);
        assert!(
            is_enrolled_at(&path, net),
            "non-vacuity: the lock is on disk before anything is answered, which \
             is the ordering the whole repair rests on"
        );

        // The response never reached `Sent`, so the armed rollback runs.
        drop(unhanded);
        assert!(
            !is_enrolled_at(&path, net),
            "an unhanded enrollment leaves no lock behind"
        );
        assert!(
            require_at(&path, net, None).is_ok(),
            "so the gate is a no-op again and this device is not locked out of \
             its own governance"
        );

        // A first attempt that *did* answer, and is then surrendered the
        // ordinary way — which is what lets a successor exist while the first
        // attempt's rollback is still owed.
        let first = install_provisional_enroll_at(&path, net, "laptop").expect("install again");
        let first_material = first.enrolled().clone();
        let first_secret = BASE32_NOPAD
            .decode(first_material.secret_b32.as_bytes())
            .expect("the first secret is base32");
        disable_at(&path, net, &totp_at(&first_secret, now_unix()))
            .expect("the operator surrenders the first lock with its own code");

        let successor = install_provisional_enroll_at(&path, net, "laptop").expect("the successor");
        let successor_material = successor.enrolled().clone();
        successor.keep();
        assert!(
            is_enrolled_at(&path, net),
            "non-vacuity: there is a successor lock for a stale undo to threaten"
        );

        // The late rollback of the first attempt, arriving now.
        drop(first);
        assert!(
            is_enrolled_at(&path, net),
            "the successor's lock is not the first attempt's to remove"
        );
        let successor_secret = BASE32_NOPAD
            .decode(successor_material.secret_b32.as_bytes())
            .expect("the successor secret is base32");
        assert!(
            require_at(&path, net, Some(&totp_at(&successor_secret, now_unix()))).is_ok(),
            "and it is still satisfied by the secret its own caller was shown"
        );

        let _ = std::fs::remove_file(&path);
    }

    /// A live owner lease preserves its provisional record even if its
    /// diagnostic process nonce differs; hard-death reclamation is covered by
    /// the cross-process R2 control.
    #[test]
    fn v4_r2_hard_death_recovery_removes_only_an_old_process_provisional() {
        let path = tmp();
        let net = "fleet-hard-death";

        let live = install_provisional_enroll_at(&path, net, "laptop").expect("install");
        assert_eq!(
            recover_provisional_at(&path).expect("live recovery"),
            0,
            "startup recovery must not steal a handoff owned by this process"
        );

        // A different nonce alone is not evidence of a dead owner: the live
        // kernel lease remains authoritative and must preserve this record.
        let mut store = load_at(&path).expect("read installed record");
        store
            .networks
            .get_mut(net)
            .expect("installed network")
            .process_nonce = "dead-process-incarnation".into();
        save_at(&path, &store).expect("persist crash snapshot");

        assert_eq!(
            recover_provisional_at(&path).expect("live recovery"),
            0,
            "the next recovery pass cannot steal a record with a live lease"
        );
        assert!(is_enrolled_at(&path, net));
        drop(live);
        let _ = std::fs::remove_file(&path);
    }

    /// A process nonce is only diagnostic metadata. If rollback released the
    /// exact owner lease but failed before removing its durable record, a
    /// recovery pass in the same process must still reclaim that orphan.
    #[test]
    fn v4_r2_current_nonce_without_owner_lease_is_recovered() {
        let path = tmp();
        let net = "fleet-current-nonce-orphan";
        let secret_b32 = BASE32_NOPAD.encode(&[0x42; SECRET_LEN]);
        let lease_path = owner_lease_path(&path, net, &secret_b32);
        assert!(
            !lease_path.exists(),
            "the control starts with no live exact-secret owner lease"
        );
        let mut store = CustodyStore::default();
        store.networks.insert(
            net.into(),
            Enrollment {
                secret_b32: secret_b32.clone(),
                recovery_hashes: Vec::new(),
                created_at: now_unix(),
                provisional: true,
                process_nonce: process_nonce().to_owned(),
            },
        );
        save_at(&path, &store).expect("materialize current-nonce orphan");

        let before = load_at(&path).expect("read materialized orphan");
        assert_eq!(
            before
                .networks
                .get(net)
                .expect("orphaned network")
                .process_nonce,
            process_nonce(),
            "the control must exercise the nonce-equality case"
        );
        assert_eq!(
            recover_provisional_at(&path).expect("recover current-nonce orphan"),
            1,
            "recovery follows the exact kernel lease, not diagnostic nonce equality"
        );
        assert!(
            !load_at(&path)
                .expect("read recovered store")
                .networks
                .contains_key(net),
            "an orphaned provisional record is removed even in the current process"
        );

        let _ = std::fs::remove_file(lease_path);
        let _ = std::fs::remove_file(&path);
    }

    /// The commit side of the restart transaction is just as important as
    /// rollback: an atomic handoff leaves a committed record that a later
    /// recovery pass preserves, and the exact handle is no longer armed.
    #[test]
    fn v4_r2_committed_handoff_survives_restart_recovery() {
        let path = tmp();
        let net = "fleet-committed-restart";

        let mut provisional = install_provisional_enroll_at(&path, net, "phone").expect("install");
        provisional.commit().expect("commit handoff");
        let store = load_at(&path).expect("read committed record");
        let enrollment = store.networks.get(net).expect("committed network");
        assert!(!enrollment.provisional);
        assert!(enrollment.process_nonce.is_empty());
        assert_eq!(
            recover_provisional_at(&path).expect("restart recovery"),
            0,
            "committed custody is not provisional recovery input"
        );
        assert!(is_enrolled_at(&path, net));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn disable_requires_a_valid_code_then_clears_the_lock() {
        let path = tmp();
        let net = "fleet-abc";
        let enrolled = enroll_at(&path, net, "phone").expect("enroll");
        let secret = BASE32_NOPAD.decode(enrolled.secret_b32.as_bytes()).unwrap();

        // Can't disable without satisfying the lock.
        assert!(disable_at(&path, net, "000000").is_err());
        assert!(is_enrolled_at(&path, net));

        // With a valid code it clears, and the gate is a no-op again.
        let code = totp_at(&secret, now_unix());
        assert!(disable_at(&path, net, &code).is_ok());
        assert!(!is_enrolled_at(&path, net));
        assert!(require_at(&path, net, None).is_ok());

        let _ = std::fs::remove_file(&path);
    }

    // Test-only mirror of `is_enrolled` against an explicit path.
    fn is_enrolled_at(path: &Path, network_id: &str) -> bool {
        load_at(path)
            .map(|s| s.networks.contains_key(network_id))
            .unwrap_or(false)
    }
}
