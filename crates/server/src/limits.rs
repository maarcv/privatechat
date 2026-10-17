//! The limits of spec 033-rate-limit-quotas. Those of one connection are
//! part of the protocol, since the client paces itself against them (spec
//! 028-session-sans-io R6, R15; spec 027-core-api R10), so they are constants
//! here, the same on every server (R11).

use std::collections::VecDeque;

/// The limits of one channel, which the operator may change (R6, R7, R11;
/// spec 035-server-ops), checked by the writer before each insert.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ChannelLimits {
    /// Blobs inserted per 60 000 ms (R6).
    pub(crate) publish_per_min: u32,
    /// Bytes inserted per 60 000 ms (R6).
    pub(crate) bytes_per_min: u64,
    /// Blobs held (R7).
    pub(crate) max_blobs: u32,
    /// Bytes held (R7).
    pub(crate) max_bytes: u64,
}

impl Default for ChannelLimits {
    /// The defaults of the table "Limits".
    fn default() -> ChannelLimits {
        ChannelLimits {
            publish_per_min: 120,
            bytes_per_min: 4 * 1024 * 1024,
            max_blobs: 20_000,
            max_bytes: 64 * 1024 * 1024,
        }
    }
}

impl ChannelLimits {
    /// No limit a test reaches, for the tests of other rules ("with the
    /// channel limits raised").
    #[cfg(test)]
    pub(crate) const RAISED: ChannelLimits = ChannelLimits {
        publish_per_min: u32::MAX,
        bytes_per_min: u64::MAX,
        max_blobs: u32::MAX,
        max_bytes: u64::MAX,
    };
}

/// The window of R6: what a channel inserted within it counts.
pub(crate) const CHANNEL_WINDOW_MS: u64 = 60_000;

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
