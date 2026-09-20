//! Local client storage (`docs/spec.md` §8, ADR 0020, 0021).
//!
//! Implements the `Store` trait of `privatechat_core` over two encrypted files
//! per channel with an atomic commit by `rename`. Lives outside `core` because
//! it does I/O. Skeleton created by spec 000; contents arrive with spec 020.

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
