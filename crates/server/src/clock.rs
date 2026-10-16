//! The server's one source of time (spec 032-storage-ttl R14): a wall
//! reading for the times stored with a blob and the purge's `now`, and a
//! monotonic reading for every deadline and window, so that a clock stepped
//! forward or back fires none of them early or late.

#![allow(
    clippy::disallowed_methods,
    reason = "the one file of the server that reads the clock (spec 032 R14)"
)]

use std::sync::OnceLock;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

#[cfg(any(test, feature = "test-support"))]
use std::sync::atomic::{AtomicU64, Ordering};

/// The two readings every time of the server comes from (spec 032 R14).
pub trait Clock: Send + Sync {
    /// Unix milliseconds of the wall clock: `received_at`, `expires_at` and
    /// the `now` of the purge and of the backlog read, nothing else.
    fn wall_ms(&self) -> u64;
    /// Milliseconds of a monotonic clock: every deadline and window.
    fn mono_ms(&self) -> u64;
}

/// The host's clocks.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

/// The instant the monotonic reading counts from, the first time it is read.
static START: OnceLock<Instant> = OnceLock::new();

impl Clock for SystemClock {
    fn wall_ms(&self) -> u64 {
        // A clock before 1970 reads 0, one past `u64::MAX` ms reads the maximum.
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |since| {
                u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
            })
    }

    fn mono_ms(&self) -> u64 {
        let start = *START.get_or_init(Instant::now);
        u64::try_from(Instant::now().duration_since(start).as_millis()).unwrap_or(u64::MAX)
    }
}

/// A clock the tests move by hand; its monotonic reading starts at 0.
#[cfg(any(test, feature = "test-support"))]
#[derive(Debug)]
pub struct ManualClock {
    wall: AtomicU64,
    mono: AtomicU64,
}

#[cfg(any(test, feature = "test-support"))]
impl ManualClock {
    /// A clock whose wall reading is `wall_ms` and monotonic reading 0.
    pub fn new(wall_ms: u64) -> ManualClock {
        ManualClock {
            wall: AtomicU64::new(wall_ms),
            mono: AtomicU64::new(0),
        }
    }

    /// Moves both readings forward by `ms`, as real time does.
    pub fn advance(&self, ms: u64) {
        self.wall.fetch_add(ms, Ordering::SeqCst);
        self.mono.fetch_add(ms, Ordering::SeqCst);
    }

    /// Moves the monotonic reading alone forward by `ms`.
    pub fn advance_mono(&self, ms: u64) {
        self.mono.fetch_add(ms, Ordering::SeqCst);
    }

    /// Sets the wall reading alone, forward or back, as a stepped clock does.
    pub fn set_wall(&self, wall_ms: u64) {
        self.wall.store(wall_ms, Ordering::SeqCst);
    }
}

#[cfg(any(test, feature = "test-support"))]
impl Clock for ManualClock {
    fn wall_ms(&self) -> u64 {
        self.wall.load(Ordering::SeqCst)
    }

    fn mono_ms(&self) -> u64 {
        self.mono.load(Ordering::SeqCst)
    }
}
