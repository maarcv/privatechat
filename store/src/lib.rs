//! Emmagatzematge local del client (`docs/spec.md` §8, ADR 0020, 0021).
//!
//! Implementa el trait `Store` de `privatechat_core` sobre dos fitxers xifrats
//! per canal amb commit atòmic per `rename`. Viu fora de `core` perquè fa I/O.
//! Esquelet creat per la spec 000; contingut a la spec 020.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
