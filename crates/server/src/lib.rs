//! Exchange server: blind mailbox with TTL (`docs/spec.md` §6).
//!
//! It stores opaque blobs per `channel_id`, relays them and deletes them at
//! their TTL; it holds no secret and decrypts nothing. Phase 3 builds it in
//! the order of specs 032, 031, 030, 033, 035 and 034; only the `pub` items
//! spec 035-server-ops R10 names leave the crate (spec 027-core-api R16).

#![forbid(unsafe_code)]
// Tests may relax these four lints to build fixtures; production code never does (AGENTS 4).
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )
)]

#[allow(
    dead_code,
    reason = "reached through the connections, spec 030-ws-protocol"
)]
mod auth;

mod clock;

#[allow(dead_code, reason = "reached from the binary, spec 035-server-ops")]
mod connection;

#[allow(dead_code, reason = "reached from the binary, spec 035-server-ops")]
mod frames;

#[allow(dead_code, reason = "reached from the binary, spec 035-server-ops")]
mod http;

#[allow(dead_code, reason = "reached from the binary, spec 035-server-ops")]
mod hub;

#[allow(
    dead_code,
    reason = "reached through the connections, spec 030-ws-protocol"
)]
mod store;

#[cfg(test)]
mod tests;

#[cfg(any(test, feature = "test-support"))]
pub use clock::ManualClock;
pub use clock::{Clock, SystemClock};

/// Why the server did not start (spec 035-server-ops R8, R10).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StartError {
    /// What was refused.
    pub reason: StartReason,
}

/// What refused the start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartReason {
    /// The database, for its cause (spec 032-storage-ttl R3).
    Database(DbCause),
    /// A listener that could not bind (spec 035-server-ops).
    Bind,
}

/// Why the database was refused at start-up (spec 032-storage-ttl R3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DbCause {
    /// A `user_version` neither 0 (new) nor 1.
    UserVersion,
    /// The journal does not read back as WAL.
    JournalMode,
    /// The vacuum mode does not read back as incremental.
    AutoVacuum,
    /// The file cannot be opened for writing.
    Open,
}
