//! Exchange server: blind mailbox with TTL (`docs/spec.md` §6).
//!
//! Skeleton created by spec 000; the protocol arrives with specs 030–035.
//! Until then the binary exits immediately with code 0 and opens no port.

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

fn main() {}
