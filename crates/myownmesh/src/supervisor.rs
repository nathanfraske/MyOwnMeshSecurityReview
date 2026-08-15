//! The one way to ask this daemon's runtime to shut down.
//!
//! Two callers submit the same request through the same object: an embedder
//! calling [`EmbeddedDaemon::shutdown`](crate::embedded::EmbeddedDaemon::shutdown),
//! and the control surface after a reset has removed the state the daemon was
//! running on. Neither ends the host process. What ends the daemon is the
//! ordinary drain the request starts — the control surface returns, hosted
//! services stop, every joined network says goodbye and is torn down — and the
//! process the daemon happens to be hosted in outlives all of it.
//!
//! No duration participates. The request carries no deadline, starts no timer,
//! and does not become true by elapsing; it is submitted once and the drain
//! runs to completion on its own terms.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use tokio::sync::broadcast;

/// A handle on the daemon runtime's shutdown request.
///
/// Idempotent by construction. The first submission signals; every later one is
/// a no-op, so a reset that has already asked for shutdown and an embedder that
/// then calls `shutdown` do not signal twice — which matters because the
/// receivers are a broadcast channel of capacity one and a second send would be
/// a lost message rather than a second drain.
#[derive(Clone, Debug)]
pub struct RuntimeSupervisor {
    shutdown: broadcast::Sender<()>,
    submitted: Arc<AtomicBool>,
}

impl RuntimeSupervisor {
    /// Wrap the sender whose receivers drive this daemon's drain.
    pub fn new(shutdown: broadcast::Sender<()>) -> Self {
        Self {
            shutdown,
            submitted: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Take a receiver *before* any request can be submitted.
    ///
    /// A broadcast receiver only sees sends that happen after it subscribes, so
    /// every party that must observe the drain subscribes while the daemon is
    /// being built rather than at the moment it starts waiting.
    pub fn subscribe(&self) -> broadcast::Receiver<()> {
        self.shutdown.subscribe()
    }

    /// Submit the one shutdown request.
    ///
    /// `true` when this call was the submission, `false` when one was already
    /// made. Callers do not need the answer to be correct about lifecycle — the
    /// drain runs exactly once either way — but a control can read it, and it
    /// is what makes "exactly one orderly shutdown request" observable rather
    /// than asserted.
    pub fn request_shutdown(&self) -> bool {
        if self.submitted.swap(true, Ordering::SeqCst) {
            return false;
        }
        // A send with no live receiver means the drain has already taken every
        // listener away, which is the shutdown this asks for having happened.
        let _ = self.shutdown.send(());
        true
    }

    /// Whether a shutdown request has been submitted.
    pub fn shutdown_requested(&self) -> bool {
        self.submitted.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both reset arms and the embedder's own `shutdown` submit exactly one
    /// request, and every waiter is woken by it.
    ///
    /// The discriminating shape. A reset whose write was refused still submits —
    /// the state it removed is gone either way — so the reset path and an
    /// embedder shutting the same daemon down afterwards are two submissions of
    /// one request. The receivers are a broadcast of capacity one: a second
    /// `send` would overwrite an unread first, so "the second caller is a no-op"
    /// is what makes the drain exactly one drain rather than a lost wake.
    ///
    /// Nothing here waits on a duration. The receiver is subscribed before the
    /// request and read after it, and `try_recv` answers from what has already
    /// been delivered.
    #[test]
    fn one_runtime_shutdown_request_survives_every_later_caller() {
        let (tx, _keepalive) = broadcast::channel(1);
        let supervisor = RuntimeSupervisor::new(tx);
        // Both waiters subscribe first, as the daemon's builder does: `serve`
        // takes one and the accept loop another.
        let mut serving = supervisor.subscribe();
        let mut hosting = supervisor.subscribe();

        assert!(
            !supervisor.shutdown_requested(),
            "non-vacuity: nothing has asked yet"
        );
        assert!(
            serving.try_recv().is_err(),
            "and no drain has been signalled"
        );

        // The reset arm, after its response reached its write disposition.
        assert!(
            supervisor.request_shutdown(),
            "the first submission is the submission"
        );
        // The embedder's `shutdown`, on the same object, afterwards.
        assert!(
            !supervisor.request_shutdown(),
            "and a later caller submits nothing second"
        );
        assert!(
            !supervisor.clone().request_shutdown(),
            "including through a clone — the submission is the daemon's, not \
             the handle's"
        );

        assert!(supervisor.shutdown_requested());
        assert!(
            serving.try_recv().is_ok(),
            "the serve loop is woken by the one request"
        );
        assert!(
            hosting.try_recv().is_ok(),
            "and so is every other waiter — one request, not one wake"
        );
        assert!(
            serving.try_recv().is_err(),
            "and there is exactly one: a second send would have queued a second \
             wake, or overwritten this one"
        );
    }

    /// A request with nothing left listening is still the request.
    ///
    /// The ended-writer case reaches this: the connection is gone, and on a
    /// daemon already drained there may be no receiver at all. A supervisor that
    /// treated a receiverless send as a failure — or that panicked on it — would
    /// make the reset path's correctness depend on who happened to still be
    /// listening.
    #[test]
    fn a_request_with_no_listener_left_is_still_submitted() {
        let (tx, keepalive) = broadcast::channel(1);
        let supervisor = RuntimeSupervisor::new(tx);
        drop(keepalive);

        assert!(supervisor.request_shutdown());
        assert!(supervisor.shutdown_requested());
        assert!(
            !supervisor.request_shutdown(),
            "and it is still the only one"
        );
    }
}
