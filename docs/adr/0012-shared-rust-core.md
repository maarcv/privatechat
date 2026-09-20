# ADR 0012 — Cryptographic and protocol core in Rust, shared by all clients

Date: 2026-09-19 · Status: accepted

## Context
There are three clients (desktop, Android, iOS) and one server. All the cryptography and the protocol must be identical in all of them.

## Decision
A Rust crate `core` contains crypto (libsodium via `libsodium-sys-stable`), the binary message envelope (ADR 0015), CBOR payload (`ciborium`), key derivation, signatures, peer management and the sans-I/O protocol session (ADR 0020). Storage is a separate Rust crate, `store`, also shared (ADR 0020, 0021). It is exposed to Kotlin and Swift with `uniffi` (proc macros) and to the Tauri desktop client as a directly linked Rust crate (ADR 0017). The UI never touches a key; the core never touches the network or the clock.

## Alternatives considered
- Reimplementing the protocol in Kotlin, Swift and TypeScript: three implementations to audit and to keep in sync; divergences almost certain.
- Compiling the core to wasm for a web client: rejected together with the hosted web client (ADR 0017); reconsidered for a browser extension in v2.

## Consequences
- A single auditable implementation; shared test vectors in `specs/vectors/` validated by the bindings.
- Initial tooling cost (uniffi, Tauri, compiling libsodium for Android and iOS).
- Server also in Rust (`axum`) to share types and integration tests.
