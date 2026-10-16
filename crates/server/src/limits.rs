//! The limits of spec 033-rate-limit-quotas. Those of one connection are
//! part of the protocol, since the client paces itself against them (spec
//! 028-session-sans-io R6, R15; spec 027-core-api R10), so they are constants
//! here, the same on every server (R11).

use std::collections::VecDeque;

/// The most `publish`es one connection hands to the writer within
/// `CONN_PUBLISH_WINDOW_MS` (R1).
pub(crate) const CONN_PUBLISH_MAX: usize = 30;

/// The window of R1: the client keeps to 30 in 60 000 ms, and the 3 000 ms
/// less absorb network jitter.
pub(crate) const CONN_PUBLISH_WINDOW_MS: u64 = 57_000;

/// The least time between two `subscribe`s of one connection (R2), below the
/// 1 100 ms the client waits (spec 028 R6).
pub(crate) const SUBSCRIBE_GAP_MS: u64 = 1_000;

/// The most subscriptions of one connection (R3).
pub(crate) const MAX_SUBSCRIPTIONS: usize = 16;

/// How often the server pings a connection, on the monotonic clock (R4).
pub(crate) const PING_INTERVAL_MS: u64 = 30_000;

/// How long a ping may wait, from when it was due, with no pong and no other
/// write completing, before the connection closes with 1001 (R4).
pub(crate) const PONG_TIMEOUT_MS: u64 = 30_000;

/// How long one write or flush may stay pending before the TCP connection is
/// dropped with no close frame (R5).
pub(crate) const WRITE_TIMEOUT_MS: u64 = 30_000;

/// The most frames of one connection's queue not yet written (R5).
pub(crate) const SEND_QUEUE_FRAMES: usize = 256;

/// The most bytes of those frames (R5).
pub(crate) const SEND_QUEUE_BYTES: usize = 4 * 1024 * 1024;

/// Whether the ping that was due at `due` has waited `PONG_TIMEOUT_MS` at
/// `now` with no pong and no other write completing since it was due, the
/// last one having completed at `progress`: the peer is gone (R4). A slow
/// link still taking frames is not.
pub(crate) fn pong_overdue(now: u64, due: Option<u64>, progress: u64) -> bool {
    due.is_some_and(|due| now.saturating_sub(due) >= PONG_TIMEOUT_MS && progress < due)
}

/// The `publish`es of one connection handed to the writer within the
/// window of R1, by the monotonic time they were handed.
#[derive(Debug, Default)]
pub(crate) struct PublishWindow(VecDeque<u64>);

impl PublishWindow {
    /// Whether a `publish` at `now` stays within R1; those older than the
    /// window are forgotten.
    pub(crate) fn allows(&mut self, now: u64) -> bool {
        while self
            .0
            .front()
            .is_some_and(|handed| now.saturating_sub(*handed) > CONN_PUBLISH_WINDOW_MS)
        {
            self.0.pop_front();
        }
        self.0.len() < CONN_PUBLISH_MAX
    }

    /// A `publish` handed to the writer at `now`; a refused one is not.
    pub(crate) fn handed(&mut self, now: u64) {
        self.0.push_back(now);
    }
}
