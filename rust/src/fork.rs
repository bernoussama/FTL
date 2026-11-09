// Pi-hole: A black hole for Internet advertisements
// (c) 2026 Pi-hole, LLC (https://pi-hole.net)
// Network-wide ad blocking via your own hardware.
//
// FTL Engine
// Rust static library linked into pihole-FTL
//
// This file is copyright under the latest version of the EUPL.
// Please see LICENSE file for your rights under this license.

//! Process-local state and the after-fork hook.
//!
//! dnsmasq forks TCP workers without exec. The child gets a copy of the
//! parent's memory, but only the forking thread. A lock that another parent
//! thread held at fork time therefore stays locked in the child, and nothing
//! in the child can release it. The rules that avoid this:
//!
//! - The library keeps no threads.
//! - No lock is held across a call that returns to C.
//! - Per-process state is only reached through `with_state()`, and
//!   `ftl_rs_after_fork()` replaces it in every forked child before the child
//!   calls anything else in the library.

use std::ptr;
use std::sync::atomic::{AtomicPtr, Ordering};
use std::sync::{Mutex, PoisonError};

/// Per-process state, only accessed through `with_state()`.
#[derive(Default)]
pub struct State {
    /// Number of ftl_rs_selftest_tick() calls since the state was created
    pub ticks: u64,
}

/// The current state, created on first use and replaced by
/// `ftl_rs_after_fork()`. Once created, it is never null.
static STATE: AtomicPtr<Mutex<State>> = AtomicPtr::new(ptr::null_mut());

/// Runs `f` with the process-local state locked.
pub fn with_state<R>(f: impl FnOnce(&mut State) -> R) -> R {
    // Poisoning needs unwinding, which panic = "abort" rules out
    let mut guard = current().lock().unwrap_or_else(PoisonError::into_inner);
    f(&mut guard)
}

fn current() -> &'static Mutex<State> {
    let mut state_ptr = STATE.load(Ordering::Acquire);
    if state_ptr.is_null() {
        let fresh = Box::into_raw(Box::new(Mutex::new(State::default())));
        // If another thread installed a state first, use that one
        state_ptr = match STATE.compare_exchange(
            ptr::null_mut(),
            fresh,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => fresh,
            Err(existing) => {
                drop(unsafe { Box::from_raw(fresh) });
                existing
            }
        };
    }
    // SAFETY: states are never freed, see ftl_rs_after_fork()
    unsafe { &*state_ptr }
}

/// Replaces the per-process state with a fresh one. Call it in every forked
/// child before the child uses the library. The parent never calls it.
///
/// Locks: none. Never panics.
#[no_mangle]
pub extern "C" fn ftl_rs_after_fork() {
    let fresh = Box::into_raw(Box::new(Mutex::new(State::default())));
    // The old state is leaked on purpose. A parent thread may have held its
    // lock at fork time, and no thread in the child will ever release it, so
    // dropping it would drop a locked mutex. Leaking it also keeps valid any
    // reference a thread that no longer exists still holds.
    STATE.store(fresh, Ordering::Release);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::selftest::ftl_rs_selftest_tick;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    // Only this test touches the state, because the test threads run in
    // parallel and a reset from another test would change the counts below.
    #[test]
    fn after_fork_gives_a_fresh_state_even_if_a_lock_was_held() {
        // Stands in for a parent thread that holds the state lock at fork time
        let (held_tx, held_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let holder = thread::spawn(move || {
            with_state(|_| {
                held_tx.send(()).unwrap();
                release_rx.recv().unwrap();
            })
        });
        held_rx.recv().unwrap();

        ftl_rs_after_fork();

        // Run the tick on another thread, so that a block shows up as a timeout
        let (tick_tx, tick_rx) = mpsc::channel();
        thread::spawn(move || tick_tx.send(ftl_rs_selftest_tick()).unwrap());
        let first = tick_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("the child blocked on a lock that was held at fork time");
        assert_eq!(first, 1);
        assert_eq!(ftl_rs_selftest_tick(), 2);

        release_tx.send(()).unwrap();
        holder.join().unwrap();
    }
}
