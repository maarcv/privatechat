# 000 — Repository layout

Status: implemented
Phase: 0
Related ADRs: 0012, 0020, 0021, 0022
Depends on: —
Blocks: 001, 002, 003, 010
Human reviewer: Marc Vilardebó · Accepted on: 2026-09-20

## Context

Before any line of product code we need a monorepo where the spec is the source of truth, the lints enforce `AGENTS.md` mechanically and no secret or private document can end up in it by mistake. `docs/spec.md` §11 gives the tree; §10 the Definition of done; AGENTS 2, 4, 10, 12 and 25 the rules this layout has to enforce. A local `inici/` directory (source material, not part of the project) may exist in the working tree and must never be tracked.

## Requirements

- R1 The Cargo workspace with the crates `core`, `store` and `server` MUST compile empty with `cargo build --workspace --all-targets` without warnings.
- R2 `cargo test --workspace` MUST pass, with the tests of this spec included.
- R3 The workspace lints MUST deny in `core`, `store` and `server`: `unwrap_used`, `expect_used`, `panic`, `unreachable`, `indexing_slicing`, `arithmetic_side_effects`, `cast_possible_truncation`, `cast_sign_loss`, `todo`, `unimplemented`, `dbg_macro`, `print_stdout`, `print_stderr`, `undocumented_unsafe_blocks`; `unsafe_code` at `deny` in the workspace; `#![forbid(unsafe_code)]` in `store` and `server`, `#![deny(unsafe_code)]` in `core` (with `allow` only in `crates/core/src/crypto/ffi.rs` once it exists); `overflow-checks = true` in the `release` profile.
- R4 The only server URL in the code MUST be the constant `privatechat_core::DEFAULT_SERVER_URL`, with the `wss://` scheme and, until there is a domain, the reserved TLD `.invalid`.
- R5 `.gitignore` MUST exclude `/inici/`, `.DS_Store`, `/target`, `node_modules/`, `dist/`, `.env` and generated code (`bindings/**/generated/`); `git ls-files inici` MUST return zero files.
- R6 The repository MUST contain, at the root: `AGENTS.md`, `CLAUDE.md`, `README.md`, `LICENSE` (MIT), `Cargo.toml`, `rust-toolchain.toml`, `rustfmt.toml`, `deny.toml`, `.editorconfig`, `.gitignore`; under `.github/`: `CONTRIBUTING.md`, `SECURITY.md`, `CODEOWNERS`; and `docs/assistant.example.md`, `docs/spec.md`, `docs/audit-log.md`, `docs/threat-model.md`, `docs/adr/README.md`, `docs/adr/TEMPLATE.md`, `specs/TEMPLATE.md`, `specs/README.md`, `specs/vectors/README.md` and the five skills in `.claude/skills/`.
- R7 `rust-toolchain.toml` MUST pin the channel to a specific stable version (`1.98.1`) with `rustfmt` and `clippy`; `edition = "2024"` and `rust-version` in the workspace.
- R8 `deny.toml` MUST ban across the whole workspace `rand`, `rand_core` and `getrandom` (allowed only as transitive dependencies of `proptest`, through `wrappers`), `sha2`, `sha3`, `blake2`, `md-5`, `aes`, `aes-gcm`, `chacha20`, `chacha20poly1305`, `ed25519-dalek`, `x25519-dalek`, `curve25519-dalek`, `argon2`, `hkdf`, `hmac`, `ring`, `openssl`, `openssl-sys`, `sodiumoxide` (AGENTS 2) and the compression crates `flate2`, `zstd`, `brotli`, `lz4` (AGENTS 24); allowed licences: MIT, Apache-2.0 (also `WITH LLVM-exception`), BSD-2-Clause, BSD-3-Clause, ISC, Unicode-3.0, Zlib, MPL-2.0; registry crates.io only.

## Limits

- None. This spec processes no external input.

## Interface

```
/
├─ Cargo.toml                (workspace: members crates/core, crates/store, crates/server; [workspace.lints]; [profile.release])
├─ crates/core/ (lib privatechat_core)   crates/store/ (lib privatechat_store)   crates/server/ (bin privatechat-server)
├─ rust-toolchain.toml · rustfmt.toml · deny.toml · .editorconfig · .gitignore
├─ AGENTS.md · CLAUDE.md · README.md · LICENSE
├─ .claude/skills/{architecture,rust,kotlin,swift,typescript-svelte}/SKILL.md
├─ .github/{workflows/ci.yml, PULL_REQUEST_TEMPLATE.md, dependabot.yml, CONTRIBUTING.md, SECURITY.md, CODEOWNERS}
├─ docs/{spec.md, threat-model.md, audit-log.md, assistant.example.md, adr/}    specs/{TEMPLATE.md, README.md, NNN-*.md, vectors/}
├─ bindings/ · clients/ · deploy/   (README.md only; contents in phases 3–5)
└─ scripts/{doc_lint.sh, doc_lint.py, check_requirements.sh, check_requirements.py}
```

```rust
/// Default exchange server of the installation (ADR 0022).
pub const DEFAULT_SERVER_URL: &str = "wss://server.invalid";
```

## Security

- `server.invalid` never resolves (RFC 2606): an unconfigured build cannot connect anywhere by mistake.
- The lints are the mechanism that enforces AGENTS 4 and 12; no `allow` is added without a comment.

## Public API changes

- New: `privatechat_core::DEFAULT_SERVER_URL`.

## Test cases

- T01 (covers R1): `cargo build --workspace --all-targets` → exit 0 (CI step `s000_t01_r01_workspace_builds`).
- T02 (covers R2): `cargo test --workspace` → exit 0 (CI step `s000_t02_r02_workspace_tests_pass`).
- T03 (covers R3): `s000_t03_r03_workspace_lints_deny_unwrap_and_arithmetic` reads `Cargo.toml` and checks every workspace lint, `unsafe_code = "deny"`, `overflow-checks` and `#![forbid(unsafe_code)]` in `store` and `server`.
- T04 (covers R4): `s000_t04_r04_default_server_url_is_wss_placeholder`; the "only" clause is a review grep until spec 027.
- T05 (covers R5): CI step `s000_t05_r05_inici_is_ignored` (`git check-ignore inici` and `git ls-files inici` empty).
- T06 (covers R6): CI step `s000_t06_r06_root_files_exist`.
- T07 (covers R7): `s000_t07_r07_toolchain_is_pinned` checks `rust-toolchain.toml`.
- T08 (covers R8): `cargo deny check` green (step `s001_t03_r03_cargo_deny`) and `s000_t08_r08_deny_bans_crypto_crates` checks every banned crate, the `rand` wrappers rule and every allowed licence in `deny.toml`.

## Vectors

- None: there is no format or derivation.

## Acceptance criterion

`cargo build --workspace --all-targets && cargo test --workspace && cargo clippy --all-targets -- -D warnings && cargo deny check` green, and the CI `doc-lint` job green.

## Out of scope

- No product code: `core`, `store` and `server` are skeletons with module documentation.
- The final value of `DEFAULT_SERVER_URL` (open decision in §12).
- The *contents* of `crates/core/fuzz/` (spec 016), `bindings/`, `clients/`, `deploy/` (phases 3–5); their `README.md` files are scaffolds.

## Open questions

- [ ] 000-R4: when there is a domain, the constant changes with a `chore:` commit; is an ADR needed? Proposal: no, it is configuration, not protocol.

## History

- 2026-09-20 draft · 2026-09-20 in review · 2026-09-20 accepted (Marc Vilardebó) · 2026-09-20 implemented
