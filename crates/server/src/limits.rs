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
