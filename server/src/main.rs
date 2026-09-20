//! Servidor d'intercanvi: bústia cega amb TTL (`docs/spec.md` §6).
//!
//! Esquelet creat per la spec 000; el protocol arriba amb les specs 030–035.
//! Fins llavors el binari surt immediatament amb codi 0 i no obre cap port.

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
