# ADR 0017 — No hosted web client in v1; native desktop client

Date: 2026-09-20 · Status: accepted

## Context
The first version included a web client (Svelte + wasm) served by the server, with a permanent "fewer guarantees" notice. Review B (finding B9) showed that the notice informs the web member but not the rest: the served JS has `K_ch`, `sk_u` and the plaintext, and with ADR 0001 and 0004 whoever compromises the web origin (operator, hosting, CDN, fraudulent certificate, old vulnerable version with correct hashes) reads **the whole channel for all members**, the native ones too. SRI and CSP do not protect against the origin itself. The weakest member sets the channel's guarantees.

## Decision
V1 has no hosted web client. The third client is a Tauri 2 desktop app (macOS, Windows, Linux) with a Svelte + TypeScript UI that links the Rust core directly: pinned and signed code, OS keychain, the same encrypted `store` as the mobile clients, one more reproducible build. Nothing of the core is compiled to wasm in v1.

## Alternatives considered
- Hosted web with a permanent notice: not mitigable for the rest of the members.
- Hosted web from an origin and operator different from the message server, with `platform` visible to members via `presence`: reduces the risk but does not eliminate it; kept as a v2 option (`docs/spec.md` §12).
- Browser extension with pinned code: viable and compatible with the Svelte UI; reserved for v2 because it requires compiling libsodium to wasm and validating its randomness.

## Consequences
- The stack loses wasm, IndexedDB and Argon2id in the browser: less risk (§12 "badly compiled libsodium in wasm" disappears) and less tooling.
- Specs 041 and 050 move from web to desktop (`041-desktop-bridge`, `050-desktop-mvp`).
- The Svelte UI is reusable for a future browser extension.
- The desktop client has the same §8 measures, adapted (keychain, locking, screenshots cannot be blocked).
