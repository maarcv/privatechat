//! Emmagatzematge local del client (`docs/spec.md` §8, ADR 0020, 0021).
//!
//! Implementa el trait `Store` de `privatechat_core` sobre dos fitxers xifrats
//! per canal amb commit atòmic per `rename`. Viu fora de `core` perquè fa I/O.
//! Esquelet creat per la spec 000; contingut a la spec 020.

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
