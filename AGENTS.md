# AGENTS.md — Rules for any agent working in this repository

Read this whole file before touching anything.

## Sources of truth and precedence

1. The accepted spec `specs/NNN-*.md` for the feature you are implementing.
2. `docs/spec.md` (full specification; canonical on `main`).
3. The ADRs in `docs/adr/` (historical context of every decision).

The conversation with the user is **not** a source of truth. If you find a contradiction between two sources, or between a source and the conversation, stop and open an entry under `## Open questions` in the affected spec. Do not decide on your own.

The Claude live document linked from the README is a read copy that may lag behind; nothing is edited there.

## Rules

1. Read `docs/spec.md` §3 (ADR), §4 (cryptographic model) and the feature spec before writing code. If the spec does not exist, write it first with `specs/TEMPLATE.md` and ask for human review before continuing.
2. **No home-made cryptographic primitives.** In the `core` crate (and in anything that touches `K_ch`, `sk_u`, message keys or the wire format): only libsodium through `crates/core/src/crypto`. Forbidden as a dependency of `core`, direct or dev: `rand`, `rand_core`, `getrandom`, `sha2`, `sha3`, `blake2`, `md-5`, `aes*`, `chacha20*`, `ring`, `openssl`, `ed25519-dalek`, `x25519-dalek`, `curve25519-dalek`, `argon2`, `hkdf`, `hmac`, `sodiumoxide`. `deny.toml` enforces it. The ban applies to `[dependencies]` of `core`; `[dev-dependencies]` may carry `proptest` (and therefore `rand`), never a cryptographic crate. The `Store` lives in the `store` crate, outside `core` because it does I/O; it encrypts only with `core::crypto` and carries no cryptographic dependency of its own. The server may use TLS (`rustls`) but verifies Ed25519 signatures **exclusively** through `core::crypto`; no other crate implements any part of the protocol.
3. No change to the wire format, the channel config, the domain tags or the key derivations without a new numbered ADR in `docs/adr/` approved by a human. The `adr-guard` CI job enforces it.
4. In `core`, `store` and `server`, clippy with `unwrap_used`, `expect_used`, `panic`, `unreachable`, `indexing_slicing`, `arithmetic_side_effects`, `cast_possible_truncation`, `cast_sign_loss`, `todo`, `unimplemented`, `dbg_macro`, `print_stdout`, `print_stderr` at `deny` for the whole crate (tests may relax it with `#[cfg(test)]`); `[profile.release] overflow-checks = true`. Every integer that comes from outside uses `checked_*` or `saturating_*`. All code that receives external data returns `Result<_, Error>`.
5. All key material lives in the single type `Secret<const N: usize>` of `crates/core/src/crypto` (`Zeroize` + `ZeroizeOnDrop`, no `Clone`, no `Default`, manual `Debug` = `[REDACTED]`, `PartialEq` via `sodium_memcmp`); no key `[u8; 32]` outside this module. Never in a `String`, never in logs, never in error messages. Every new secret type is added to `SECRET_TYPES` and the test `s010_t02_debug_is_redacted` covers it (PR checklist). libsodium buffers are wiped with `sodium_memzero` inside `crates/core/src/crypto`.
6. Every requirement R* of a spec has at least one test T* named `sNNN_tTT_rRR_<description>` (spec, test and requirement with two digits): `fn s013_t03_r02_rejects_bad_signature()`. `scripts/check_requirements.sh` checks it in CI.
7. Small commits, one per requirement when possible. The message starts with `NNN:` and cites the requirement: `013: R4 random 24-byte nonce`. Other allowed prefixes: `docs:`, `ci:`, `chore:`, `adr:`.
8. Do not add dependencies without justifying them in the PR and without `cargo deny check` passing. Dev dependencies too.
9. Before marking a feature as done, check the Definition of done in `docs/spec.md` §10 and the PR template.
10. `core` does no I/O and never reads the clock: no `std::net`, `std::fs`, `tokio`, `reqwest`, `SystemTime::now`. Time comes in as a parameter. `cargo deny` (bans) and clippy `disallowed_methods` enforce it.
11. Language: English for everything — identifiers, comments, error messages, test names, specs, ADRs, `docs/`, commit messages, pull requests and issues. This is an open project; English is the reference language for absolutely everything that goes into the repository.
12. `unsafe`: `#![forbid(unsafe_code)]` in every crate except `crates/core/src/crypto/ffi.rs`, the single point of contact with `libsodium-sys-stable`. There, `#![deny(unsafe_op_in_unsafe_fn)]`, every block carries `// SAFETY:` and clippy `undocumented_unsafe_blocks` is at `deny`.
13. No `TODO`, `FIXME` or `XXX` in merged code. Whatever remains pending goes under `## Open questions` of the spec, with the id `NNN-Rk`.
14. One PR: one spec, ≤ 400 lines of net diff (excluding `specs/vectors/*.json` and generated code), title starting with `NNN:`.
15. If a test T* cannot be written before implementing (for instance, it needs the generated vector), it is written anyway with `#[ignore = "pending: NNN-Tk"]` and enabled in the same PR. No PR merges ignored tests.
16. Generated code (uniffi, Tauri bindings) is not committed; it is generated in CI.
17. `cargo fmt` and `cargo clippy --all-targets -- -D warnings` clean before every commit.
18. The vectors in `specs/vectors/*.json` are regenerated only with a `proto_version` change and an ADR. CI fails if the diff touches vectors without touching `docs/adr/`.
19. No log with content, names, keys, full `channel_id` or full `pk`; at most the 4-byte hex prefix. The test `s010_t01_no_secrets_in_logs` checks it.
20. The UI never touches a key and never touches the storage files. `Config`, `Channel` and `Session` are exposed as opaque handles (uniffi `Object`); only `Received`, `Peer`, `Fingerprint`, `Gap` and `Event` are `Record`. Passwords cross the FFI boundary as bytes (`ByteArray`, `[UInt8]`, `Uint8Array`) and are zeroized on the UI side after the call. Outside the core no wiping is promised: what is promised is not retaining (no cache, no log, no `toString`).
21. Every `parse`, `decrypt` and `open_*` of `core` has a target in `crates/core/fuzz` and a round-trip property test (`proptest`); CI checks that the number of targets is ≥ the number of public functions that take `&[u8]`.
22. No `==` on `[u8; N]` in `core`: every fixed-size comparison goes through `crypto::ct_eq` (`sodium_memcmp`). No exceptions, so nobody has to decide where constant time is needed.
23. Every write to the state goes through `Store::commit(WriteBatch)`, a single commit per logical operation. No rejection path performs any commit except the cursor one. Every stateful spec has a test with `FailingStore` that fails at commit *n* and checks the state on reopening.
24. The payload is never compressed. No compression crate in the workspace.
25. Before writing code in a language, read `.claude/skills/architecture/SKILL.md` and then `.claude/skills/<language>/SKILL.md` (`rust`, `kotlin`, `swift`, `typescript-svelte`). They are the project's coding standard: layers, sizes, names, errors, tests and tooling. If an agent is not Claude, they are ordinary documents; read them anyway.

## Per-feature flow

spec written → human review → tests T* red → implementation → CI green → human review (+ ADR if needed) → merge.

Human review before implementing and before merging is mandatory in `core/`, `store/` and `server/`. In the clients (`clients/`) review before merge is enough.

## Structure and order of work

The repository tree is in `docs/spec.md` §11; the phases, the specs of each phase and the exit criteria in §10. We do not duplicate the list here to avoid two sources. Fixed principle: no UI work starts until phases 1 and 2 are closed.
