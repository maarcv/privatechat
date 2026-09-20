# ADR 0002 — A single AEAD (XChaCha20-Poly1305) via libsodium

Date: 2026-09-19 · Status: accepted

## Context
The initial proposal envisaged encrypting each message in n layers with different algorithms defined in the channel config.

## Decision
Each message is encrypted exactly once with libsodium's `crypto_aead_xchacha20poly1305_ietf` (32 B key, 24 B random nonce, 16 B tag). No other cryptographic primitive in the protocol or in the `core` crate.

## Alternatives considered
- Cipher cascade: adds no provable security if the first algorithm is secure, and multiplies the points of failure (nonces, padding, unauthenticated modes).
- AES-256-GCM: equivalent in security; XChaCha allows a 24 B random nonce with no collision risk and does not depend on hardware acceleration.
- Nonce derived from the counter (saves 24 B): rejected in review B (2026-09-20). This design has a real message-key reuse failure mode (device cloning or restore, identity imported twice); with a random nonce the reuse leaks nothing, with a derived nonce it yields keystream reuse and forgery.

## Consequences
- A single primitive to audit and to version (`proto_version`).
- The channel config carries no algorithm parameter.
- The scope of "no other cryptographic library" is the `core` crate and everything that touches `K_ch`, `sk_u` or the wire format. The server may use TLS (`rustls`) and the clients the platform Keystore / Secure Enclave to wrap `K_db`; none of them implements anything of the protocol. Local storage encrypts with the same libsodium (ADR 0021). List of forbidden crates in `AGENTS.md` rule 2 and in `deny.toml`.
