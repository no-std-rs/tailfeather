//! Making a run clean up after itself.
//!
//! # The failure this prevents
//!
//! Every run that reaches `control.register` leaves a node behind on the lab
//! server. They accumulate. `ts_netmap::MAX_PEERS` is 32, and a netmap naming
//! more peers than that is *refused outright* rather than truncated — so once
//! roughly thirty runs have gone by, `netmap.to_peers` and all three `disco.*`
//! checks begin failing for a reason that has nothing to do with the code.
//!
//! That is not hypothetical. It happened while this module was being written:
//! two consecutive `cargo test` runs took the lab from 34/34 to five failures
//! and 42 registered nodes, and `lab.sh prune` restored it. A suite whose result
//! depends on how many times it has been run before is not measuring the code.
//!
//! # The shape
//!
//! Each run picks an id and registers its nodes under `esp-gateway-<runid>`.
//! [`RunScope`] deletes exactly the nodes carrying that id when the last handle
//! to it drops — so cleanup happens on the failure path and the panic path too,
//! which is where it matters, since a run that fails half way through is
//! precisely the run that leaves debris.
//!
//! `Drop` is necessary but not sufficient. `std::process::exit` does not run
//! destructors, so the binary computes its exit code, lets the environment fall
//! out of scope, and only then exits — see `main.rs`. Getting that ordering
//! wrong skipped cleanup on failing runs specifically, which is self-reinforcing:
//! the orphans from one failure are what make the next run fail.
//!
//! Deleting by our own id rather than by the `esp-gateway` prefix is what makes
//! concurrent runs safe: two suites against one lab do not delete each other's
//! nodes mid-run.
//!
//! `lab.sh prune` still exists, and still deletes everything with the prefix.
//! Its role changes from "run this before every suite or the suite lies" to
//! crash recovery.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};

use crate::headscale;

/// The hostname prefix every node this suite registers carries.
///
/// `lab.sh prune` matches on this, so the two must agree.
pub const PREFIX: &str = "esp-gateway";

/// Identifies one run's nodes, and deletes them when the run ends.
///
/// # Why this is shared rather than owned
///
/// A `RunScope` is a handle onto one process-wide run, not a fresh run each
/// time it is constructed. Two things force that.
///
/// The suite memoizes its registration session in a `static OnceLock`, so
/// whichever caller reaches it first registers the nodes that everyone else
/// then makes claims about. Meanwhile `tests/matrix.rs` builds an [`Env`] per
/// `#[test]`, and cargo runs those in parallel threads of one process. With a
/// per-`Env` id, `control.hostinfo` compared the server's node name against
/// *its* id while the node had been registered under a *different* test's —
/// which is not hypothetical, it failed on the first run after this module
/// landed.
///
/// Cleanup therefore happens when the last handle drops, not the first: a test
/// finishing early must not delete nodes that a test still running is asserting
/// about.
///
/// [`Env`]: crate::Env
#[derive(Clone)]
pub struct RunScope(Arc<Inner>);

struct Inner {
    id: String,
    hostname: String,
    /// Whether there is a lab to clean up. Interior mutability because the
    /// answer is not known until `Env::discover` has probed the control server,
    /// by which point the shared scope already exists.
    enabled: AtomicBool,
    reported: AtomicBool,
}

/// The live scope for this process, if one is still held.
///
/// A `Weak`, deliberately: a strong reference here would keep `Inner` alive for
/// the life of the process and its `Drop` — which is what performs cleanup —
/// would never run.
fn shared() -> &'static Mutex<Weak<Inner>> {
    static SHARED: OnceLock<Mutex<Weak<Inner>>> = OnceLock::new();
    SHARED.get_or_init(|| Mutex::new(Weak::new()))
}

impl RunScope {
    /// Obtain this process's run scope.
    ///
    /// `enabled` is sticky in the permissive direction: any caller that knows
    /// there is a lab to clean up turns cleanup on for the whole process.
    /// Nothing turns it back off, because a scope that stopped cleaning up half
    /// way through a run would leave exactly the debris this exists to prevent.
    pub fn new(enabled: bool) -> Self {
        let mut slot = shared().lock().unwrap_or_else(|e| e.into_inner());
        if let Some(existing) = slot.upgrade() {
            if enabled {
                existing.enabled.store(true, Ordering::SeqCst);
            }
            return Self(existing);
        }
        let id = run_id();
        let inner = Arc::new(Inner {
            hostname: format!("{PREFIX}-{id}"),
            id,
            enabled: AtomicBool::new(enabled),
            reported: AtomicBool::new(false),
        });
        *slot = Arc::downgrade(&inner);
        Self(inner)
    }

    /// The short identifier for this run.
    pub fn id(&self) -> &str {
        &self.0.id
    }

    /// The hostname to register under: `esp-gateway-<runid>`.
    ///
    /// Headscale derives the name it displays from `Hostinfo.Hostname`, so this
    /// is what makes a node attributable to a run — both for cleanup here and
    /// for a human reading `headscale nodes list` after a crash.
    pub fn hostname(&self) -> &str {
        &self.0.hostname
    }

    /// Delete this run's nodes now, rather than waiting for the last handle to
    /// drop.
    pub fn cleanup(&self) -> Cleanup {
        self.0.cleanup()
    }
}

impl Inner {
    /// Delete this run's nodes, returning how many went and any errors.
    ///
    /// Idempotent: calling it twice is harmless, and `Drop` calls it if the
    /// caller did not.
    fn cleanup(&self) -> Cleanup {
        if !self.enabled.load(Ordering::SeqCst) || self.reported.swap(true, Ordering::SeqCst) {
            return Cleanup::default();
        }

        let nodes = match headscale::nodes() {
            Ok(nodes) => nodes,
            // The lab going away mid-run is not a cleanup failure worth
            // shouting about; there is nothing to delete on a server that is
            // not answering.
            Err(e) => {
                return Cleanup {
                    errors: vec![format!("could not list nodes: {e}")],
                    ..Cleanup::default()
                };
            }
        };

        let mut cleanup = Cleanup::default();
        for node in nodes.iter().filter(|n| self.owns(&n.name)) {
            match headscale::delete_node(node.id) {
                Ok(()) => cleanup.deleted += 1,
                Err(e) => cleanup.errors.push(e),
            }
        }
        cleanup.left_behind = nodes
            .iter()
            .filter(|n| n.name.starts_with(PREFIX) && !self.owns(&n.name))
            .count();
        cleanup
    }

    /// Whether a node name belongs to this run.
    ///
    /// Headscale may append a disambiguating suffix to the *given* name, but
    /// `name` is the hostname we sent, so an exact match is right here. The
    /// `starts_with` fallback covers a server that decorates it anyway.
    fn owns(&self, name: &str) -> bool {
        name == self.hostname || name.starts_with(&format!("{}-", self.hostname))
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        let cleanup = self.cleanup();
        if cleanup.deleted > 0 {
            eprintln!(
                "== cleaned up {} node(s) registered by run {}",
                cleanup.deleted, self.id
            );
        }
        for error in &cleanup.errors {
            eprintln!("== cleanup: {error}");
        }
        if cleanup.left_behind > 0 {
            eprintln!(
                "== {} node(s) from earlier runs remain; 'tests/lab/lab.sh prune' \
                 removes them. Past {} the netmap checks start failing for reasons \
                 unrelated to the code.",
                cleanup.left_behind,
                ts_netmap::MAX_PEERS,
            );
        }
    }
}

/// What one cleanup did.
#[derive(Debug, Default)]
pub struct Cleanup {
    pub deleted: usize,
    /// Nodes matching the suite's prefix that belong to *other* runs. Reported
    /// rather than deleted, so concurrent runs do not interfere.
    pub left_behind: usize,
    pub errors: Vec<String>,
}

/// A short, per-run identifier.
///
/// Process id and start time together: the pid alone repeats after a reboot or
/// a pid-namespace reset, and a run whose id collides with a crashed
/// predecessor's would adopt and delete its nodes. Eight hex digits keeps the
/// hostname readable in `headscale nodes list`.
fn run_id() -> String {
    use std::hash::{DefaultHasher, Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    std::process::id().hash(&mut hasher);
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default()
        .hash(&mut hasher);
    format!("{:08x}", hasher.finish() as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_hostname_carries_the_prefix_and_the_run_id() {
        let scope = RunScope::new(false);
        assert!(scope.hostname().starts_with(PREFIX));
        assert!(scope.hostname().ends_with(scope.id()));
        assert_eq!(scope.id().len(), 8);
        // `lab.sh prune` matches on the prefix, so a hostname that did not carry
        // it would be invisible to crash recovery.
        assert!(scope.hostname().starts_with("esp-gateway"));
    }

    #[test]
    fn every_handle_in_a_process_shares_one_run_id() {
        // Not an optimisation: the registration session is memoized in a
        // `static`, so a second handle with a different id would describe nodes
        // it did not register. `control.hostinfo` compares the server's node
        // name against this, and got it wrong until the scope became shared.
        let a = RunScope::new(false);
        let b = RunScope::new(false);
        assert_eq!(a.id(), b.id());
        assert_eq!(a.hostname(), b.hostname());
    }

    #[test]
    fn enabling_any_handle_enables_cleanup_for_all_of_them() {
        let quiet = RunScope::new(false);
        let live = RunScope::new(true);
        assert!(live.0.enabled.load(Ordering::SeqCst));
        // Sticky: the handle that asked for nothing now shares an enabled scope,
        // because turning cleanup back off mid-run would strand nodes.
        assert!(quiet.0.enabled.load(Ordering::SeqCst));
    }

    #[test]
    fn cleanup_is_a_no_op_when_disabled() {
        let scope = RunScope::new(false);
        let cleanup = scope.cleanup();
        assert_eq!(cleanup.deleted, 0);
        assert!(cleanup.errors.is_empty());
    }
}
