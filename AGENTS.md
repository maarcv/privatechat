# AGENTS.md — Rules for any agent working in this repository

Read this whole file before touching anything.

## Sources of truth and precedence

1. The accepted spec `specs/NNN-*.md` for the feature you are implementing.
2. `docs/spec.md` (full specification; canonical on the default branch (`mvp` until the first release)).
3. The ADRs in `docs/adr/` (historical context of every decision).

The conversation with the user is **not** a source of truth. If you find a contradiction between two sources, or between a source and the conversation, stop and open an entry under `## Open questions` in the affected spec. Do not decide on your own.

The read copy linked from the header of `docs/spec.md` may lag behind; nothing is edited there.

## Rules

1. Read `docs/spec.md` §3 (ADR), §4 (cryptographic model) and the feature spec before writing code. If the spec does not exist, write it first with `specs/TEMPLATE.md` and ask for human review before continuing.
2. **No home-made cryptographic primitives.** In `core` (and in anything that touches `K_ch`, `sk_u`, message keys or the wire format) only libsodium through `crates/core/src/crypto`. No cryptographic primitive, randomness source or compression crate anywhere in the workspace outside libsodium: the exact list is `[bans]` in `deny.toml`, and any wrapper exception is justified in the PR. `[dev-dependencies]` may carry `proptest` (and therefore `rand`), never a cryptographic crate. The one exception outside the workspace is `scripts/reference/`, the reference script of spec 015, which produces the vectors of `specs/vectors/` with the Python standard library and whose values the Rust tests (and later Kotlin and Swift) reproduce; it is never shipped and nothing imports it. The `Store` lives in the `store` crate, outside `core` because it does I/O; it encrypts only with `core::crypto`. TLS terminates at the reverse proxy (`deploy/`); the server verifies Ed25519 signatures exclusively through `core::crypto`; no other crate implements any part of the protocol.
3. No change to the wire format, the channel config, the domain tags or the key derivations without a new numbered ADR in `docs/adr/` approved by a human. The `adr-guard` CI job enforces it.
4. In `core`, `store` and `server` the workspace lints of the root `Cargo.toml` (`[workspace.lints]`, the single source) are at `deny` for the whole crate; tests may relax exactly `unwrap_used`, `expect_used`, `indexing_slicing` and `arithmetic_side_effects` under `#[cfg(test)]`. `[profile.release] overflow-checks = true`. Every integer that comes from outside uses `checked_*` or `saturating_*`. All code that receives external data returns `Result<_, Error>`.
5. All key material lives in the single type `Secret<const N: usize>` of `crates/core/src/crypto` (`Zeroize` + `ZeroizeOnDrop`, no `Clone`, no `Default`, manual `Debug` = `[REDACTED]`, `PartialEq` via `sodium_memcmp`); no key `[u8; 32]` outside this module. Never in a `String`, never in logs, never in error messages. Every new secret type is added to `SECRET_TYPES` and the redacted-`Debug` test of spec 010 covers it (PR checklist). libsodium buffers are wiped with `sodium_memzero` inside `crates/core/src/crypto`.
6. Every requirement R* of a spec has at least one test T* named `sNNN_tTT_rRR_<description>` (spec, test and requirement with two digits): `fn s013_t03_r02_rejects_bad_signature()`. `scripts/check_requirements.sh` checks it in CI. Visibility, absent trait impls and signatures are stated in the spec's `## Interface`, which the compiler enforces; they are not requirements and need no test.
7. Small commits, one per requirement when possible. The message starts with `NNN:` and cites the requirement: `013: R4 random 24-byte nonce`. Other allowed prefixes: `docs:`, `ci:`, `chore:`, `adr:`.
8. Do not add dependencies without justifying them in the PR and without `cargo deny check` passing. Dev dependencies too.
9. Before marking a feature as done, check the Definition of done in `docs/spec.md` §10 (mirrored as checkboxes in the PR template).
10. `core` does no I/O and never reads the clock: no `std::net`, `std::fs`, `tokio`, `reqwest`, `SystemTime::now`. Time comes in as a parameter. `cargo deny` (bans) and clippy `disallowed_methods` (`clippy.toml`, spec 010) enforce it.
11. Language: English for everything — identifiers, comments, error messages, test names, specs, ADRs, `docs/`, commit messages, pull requests and issues. The only exception is user-facing text translated into the UI languages of `docs/spec.md` §9 with English as the source: the string resources of `clients/` and the copy of `landing/`. Code, comments and file names there stay in English.
12. `unsafe`: `#![forbid(unsafe_code)]` in `store` and `server`; `core` uses `#![deny(unsafe_code)]` at the crate root and `#![allow(unsafe_code)]` only in `crates/core/src/crypto/ffi.rs`, the single point of contact with `libsodium-sys-stable`. There, `#![deny(unsafe_op_in_unsafe_fn)]`, every block carries `// SAFETY:` and clippy `undocumented_unsafe_blocks` is at `deny`.
13. No `TODO`, `FIXME` or `XXX` in merged code. Whatever remains pending goes under `## Open questions` of the spec, with the id `NNN-Rk`.
14. One PR: one spec, ≤ 400 lines of net diff (excluding `specs/vectors/*.json`, the embedded BIP-39 word list and generated code), title starting with `NNN:`.
15. If a test T* cannot be written before implementing (for instance, it needs a vector the reference script has not written yet), it is written anyway with `#[ignore = "pending: NNN-Tk"]` and enabled in the same PR. No PR merges ignored tests.
16. Generated code (uniffi, Tauri bindings) is not committed; it is generated in CI.
17. The local CI commands of `.github/CONTRIBUTING.md` clean before every commit.
18. The vectors in `specs/vectors/*.json` freeze when phase 1 closes, once `cargo test` reproduces every vector the reference script of spec 015 wrote; from then on they are rewritten only with a `proto_version` change and an ADR. Until then a vector change needs the `adr-not-needed` label and the reviewer's reason in the PR. CI (`adr-guard`) fails a diff that touches `specs/vectors/` without adding a new ADR file, unless a human sets that label.
19. No log with content, names, keys, full `channel_id` or full `pk`; at most the 4-byte hex prefix. The log test of spec 035-server-ops checks it over the server, the first crate that emits.
20. The UI never touches a key and never touches the storage files. `Config`, `Channel`, `Session` and `Settings` are opaque handles (uniffi `Object`); only `Received`, `Peer`, `Fingerprint`, `Gap` and `Event` are `Record`s. Passwords cross the FFI boundary as bytes (`ByteArray`, `[UInt8]`, `Uint8Array`) and are zeroized on the UI side after the call. Outside the core no wiping is promised: what is promised is not retaining (no cache, no log, no `toString`).
21. Every function of `core` that reads external bytes — each `parse`, `decrypt` and `open_*`, and each entry of the `fuzz_entry` module of spec 016 — is called by a target in `crates/core/fuzz` and has a round-trip property test (`proptest`); spec 016 adds a CI check that every such function is reached by some target, with a named exclusion list.
22. No `==` on `[u8; N]` in `core`: every fixed-size comparison goes through `crypto::ct_eq` (`sodium_memcmp`). No exceptions, so nobody has to decide where constant time is needed.
23. Every write to the state goes through `Store::commit(WriteBatch)`, a single commit per logical operation. A rejection path commits nothing but the cursor; in tests and vectors `commits` counts the commits other than the cursor's, so a rejection has `commits = 0`. Every stateful spec has a test with `FailingStore` that fails at commit *n* and checks the state on reopening.
24. The payload is never compressed, in any version: compressing before encrypting leaks content through the size. No crate of the workspace may compress protocol data. A decompressor reached only by a build script (libsodium ships its sources as an archive) is not protocol data: it is allowed only as an entry of `[bans]` in `deny.toml` naming its exact wrapper, so every path that brings one in has been read by a human.
25. Before writing code in a language, read `.claude/skills/architecture/SKILL.md` and then `.claude/skills/<language>/SKILL.md` (`rust`, `kotlin`, `swift`, `typescript-svelte`). They are the project's coding standard: layers, sizes, names, errors, tests and tooling. Non-Claude agents read them as ordinary documents.

## Per-feature flow

spec written → human review → tests T* red → implementation → CI green → human review (+ ADR if needed) → merge.

Human review before implementing and before merging is mandatory in `crates/core`, `crates/store` and `crates/server`. In the clients (`clients/`) review before merge is enough.

## Structure and order of work

The repository tree is in `docs/spec.md` §11; the phases, the specs of each phase and the exit criteria in §10. Not repeated here: one source. Fixed principle: no UI work starts until phases 1 and 2 are closed.
