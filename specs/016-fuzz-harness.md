# 016 — Fuzz harness

Status: in review
Phase: 1
Related ADRs: 0012, 0023, 0027
Depends on: 010-primitives-wrapper, 015-test-vectors, 017-record-encoding, 011-config-format, 012-message-keys, 013-wire-message, 014-fingerprint
Blocks: 021-channel-session, 063-beta
Human reviewer: Marc Vilardebó · Accepted on: —

## Context

Every byte the core parses comes from a hostile network or a file that may be corrupt: a blob the server relayed, a config someone scanned or typed, a record read back from disk. The workspace lints already turn most panics on that path into compile errors (AGENTS 4), but only a fuzzer finds the input nobody thought of. AGENTS 21 fixes the rule: every function of `core` that reads external bytes is reached by a target in `crates/core/fuzz` and has a round-trip property test, and this spec adds the CI check that keeps it true.

Everything phase 1 fuzzes is a pure function (specs 017-record-encoding, 011-config-format, 013-wire-message, 014-fingerprint). No target needs a `Store` or a `Channel`, so this spec closes in phase 1 and blocks spec 021-channel-session instead of waiting for it.

The fuzz crate sits outside the workspace, so it can only call `pub` items of `core`. The crate-internal parsers are reached through a module that exists only when `cargo fuzz` builds: `#[cfg(fuzzing)] pub mod fuzz_entry`. `cargo fuzz` sets `--cfg fuzzing` itself. It is not a Cargo feature, so the product build never contains it.

The phase 1 exit criterion asks for one hour per target without a crash (`docs/spec.md` §10).

## Requirements

- R1 `crates/core/fuzz` MUST be a `cargo-fuzz` crate excluded from the workspace, so that its dependencies never reach `core`, `store` or `server`.
- R2 `core` MUST expose its crate-internal parsers to the fuzz crate only through `#[cfg(fuzzing)] pub mod fuzz_entry`, which MUST NOT exist in any build without `--cfg fuzzing`, and `[workspace.lints.rust]` MUST declare `unexpected_cfgs = { level = "warn", check-cfg = ['cfg(fuzzing)'] }` so that the gate does not break clippy under `-D warnings`.
- R3 There MUST be exactly these seven targets, each calling the `fuzz_entry` function of the same name: `record_decode`, `config_parse`, `config_parse_qr`, `payload_decode`, `receive`, `receive_signed` and `verify_qr_parse`.
- R4 `fuzz_entry::record_decode` MUST drive the test schema of spec 017-record-encoding (compiled under `cfg(any(test, fuzzing))`), which uses every type of `docs/spec.md` §4 "Record encoding" — `u8`, `u32`, `u64`, `bool`, `bytes`, `bytesN`, `text`, a nested record and a `list` — under the unknown-key policy chosen by the first input byte, so that the nested and list paths are fuzzed before any phase 2 schema uses them.
- R5 `fuzz_entry::receive` MUST run `verify` and then `Verified::open` of spec 013-wire-message with fixed keys, taking `received_at`, `now` and `ttl_seconds` from the first bytes of the input, so that the `Expired` and stale arithmetic is fuzzed too.
- R6 `fuzz_entry::receive_signed` MUST pass arbitrary padded plaintext and header fields to the crate-internal `seal_padded` of spec 013-wire-message with a fixed test key, skipping `validate`, and then run `verify` and `open`, so that fuzzing reaches every step after the signature check; the target itself MUST contain no sealing logic.
- R7 `scripts/check_fuzz_targets.sh` MUST fail when a `pub` `parse*`, `decrypt*` or `open*` function of `core` taking `&[u8]`, or a function of `fuzz_entry`, is called by no target file, MUST name each such function, and MUST read a named exclusion list in which every entry carries its reason (AGENTS 21).
- R8 Every target MUST be one call on the fuzzer's bytes with the result ignored: no `unwrap`, no `panic` and no assertion.
- R9 The corpus of each target MUST be seeded from the vectors of `specs/vectors/`, positive and negative alike.
- R10 A nightly CI workflow MUST run the seven targets as a matrix, one job per target, each building its target and running it for 3600 seconds, and each job MUST fail on any crash, timeout, memory-limit hit or build failure.
- R11 A target MUST NOT depend on a clock, on randomness or on the file system: the fuzzer supplies every byte, including the times of R5.
- R12 The fuzz crate MUST add exactly one dependency, `libfuzzer-sys`. Its licence, `(MIT OR Apache-2.0) AND NCSA`, MUST pass `cargo deny` through a licence exception in `deny.toml` scoped to `libfuzzer-sys` alone, with the reason naming this spec.

## Limits

| Item | Range | Out of range |
| --- | --- | --- |
| Targets | the seven of R3; every function of R7 reached | `check_fuzz_targets` fails |
| Nightly run | 3600 s per target, one job each | failure |
| Memory per target | the `cargo-fuzz` default | failure |
| Additional dependencies | `libfuzzer-sys` only | `cargo deny` fails |
| Assertions per target | 0 | T08 fails |

## Interface

```
crates/core/src/fuzz_entry.rs                cfg(fuzzing) only (R2)
crates/core/fuzz/Cargo.toml                  excluded from the workspace (R1)
crates/core/fuzz/fuzz_targets/<target>.rs    one file per target of R3
crates/core/fuzz/corpus/<target>/            seeded from specs/vectors (R9)
crates/core/fuzz/tests/                      s016_* tests that need fuzz_entry
scripts/check_fuzz_targets.sh                the set check of R7, with its exclusion list
.github/workflows/fuzz.yml                   the nightly matrix of R10
```

```rust
// The shape every target keeps: bytes in, one call, result ignored.
fuzz_target!(|data: &[u8]| {
    let _ = fuzz_entry::payload_decode(data);
});
```

`fuzz_entry` holds one thin function per target, taking `&[u8]` and returning nothing. Each one calls the real function with fixed test keys, reads the times of R5 from the input where it needs them, and drops the result. It adds no logic of its own: the only sealing the harness needs, for `receive_signed`, is spec 013-wire-message's own `seal_padded`.

The exclusion list of R7 starts with `Config::export_encrypted` (it takes no external bytes since ADR 0028, and seals rather than parses), `Config::open_encrypted` (not fuzzed past Argon2id, see "Security"; covered by the round-trip test of spec 011-config-format) and the password canonicalisation of spec 011-config-format (a pure string transform covered by its own property test), each with that reason.

## Security

- Fuzzing is the only check in the project that looks for the input nobody imagined. The lints stop the panics we can name; the fuzzer finds the slice, the subtraction and the length that no review saw.
- Seeding from the vectors (R9) matters more than the hours: a random byte string fails at the length check of `docs/spec.md` §4 step 1 and never reaches the AEAD, while a mutated valid blob reaches every step.
- A mutated blob can never get past the signature, so `receive` alone never exercises what happens after authentication. `receive_signed` (R6) signs whatever the fuzzer writes, which is exactly what a malicious member who holds the config can send.
- The `.chatcfg` file is not fuzzed past Argon2id: a mutated file almost never passes the `secretbox` tag, so a fixed-key target would only reach the three header comparisons its own tests already cover. The file is covered by its round-trip test in spec 011-config-format. The round-trip property tests AGENTS 21 asks for belong to the spec that defines each codec (010 padding, 011 config, 012 header, 013 envelope, 014 verification QR, 017 record); this spec adds none.
- The byte-by-byte mutation property test of the envelope, which `docs/spec.md` §10 asks for in phase 1, belongs to spec 013-wire-message, next to its mutation table.
- A crash becomes a test before it becomes a fix: the crashing input is added as a regression case in the owning spec's tests, with the error it must now produce. This is a process rule, carried by the review of the fix, not a requirement a test could check.
- The fuzz crate is outside the workspace (R1) so that its dependencies, which run only on a developer's machine and on the nightly runner, never enter the graph the product ships.

## Public API changes

None. `fuzz_entry` exists only under `--cfg fuzzing`.

## Test cases

- T01 (covers R1): `s016_t01_r01_fuzz_crate_is_isolated`: the workspace manifest excludes `crates/core/fuzz`, and no workspace crate depends on it.
- T02 (covers R2): `s016_t02_r02_fuzz_entry_is_cfg_gated`: `lib.rs` declares `fuzz_entry` only under `cfg(fuzzing)`, the `core` manifest has no feature that enables it, and `[workspace.lints.rust]` declares the `check-cfg` entry.
- T03 (covers R3): `s016_t03_r03_the_seven_targets_exist`: each target of R3 has its file and calls the `fuzz_entry` function of its name.
- T04 (covers R4): `s016_t04_r04_record_schema_uses_every_type`, in `crates/core/fuzz/tests/`: the fuzz-only schema decodes a seed that exercises every type, including a nested record and a list, under both policies.
- T05 (covers R5): `s016_t05_r05_receive_reaches_expired_and_stale`, in `crates/core/fuzz/tests/`: two seeds, one whose times make step 2 return `Expired` and one that `open` classifies as stale.
- T06 (covers R6): `s016_t06_r06_receive_signed_reaches_the_payload`, in `crates/core/fuzz/tests/`: a seed built by the harness reaches `open` and returns an `Opened` value.
- T07 (covers R7): `check_s016_t07_r07_every_parser_is_reached` in `scripts/check_fuzz_targets.sh`, with fixtures: a `pub` parser taking `&[u8]` added with no target fails the script and is named; an exclusion entry with no reason fails it too.
- T08 (covers R8): `s016_t08_r08_targets_are_small`: no target contains `unwrap`, `panic` or an assertion.
- T09 (covers R9): `s016_t09_r09_corpus_is_seeded`: each corpus directory holds at least one file per vector of the spec it fuzzes.
- T10 (covers R10): `s016_t10_r10_nightly_matrix`: the workflow has one matrix entry per target of R3, each building and running for 3600 seconds.
- T11 (covers R11): `s016_t11_r11_targets_are_pure`: no target or `fuzz_entry` function names a clock, a random source or the file system.
- T12 (covers R12): `s016_t12_r12_one_dependency_one_exception`: the fuzz manifest declares only `libfuzzer-sys`, and `deny.toml` carries exactly one licence exception for it, whose reason names this spec.

## Vectors

None of its own. The corpus is seeded from every other spec's vectors (R9).

## Acceptance criterion

`cargo test -p privatechat-core s016_` green; `cargo test --manifest-path crates/core/fuzz/Cargo.toml s016_` green, which builds with `--cfg fuzzing`; `scripts/check_fuzz_targets.sh` green; `cargo deny` green over the fuzz crate; a CI step `RUSTFLAGS="--cfg fuzzing" cargo clippy -p privatechat-core -- -D warnings` green, so `fuzz_entry` is linted like the rest of `core`; and `cargo fuzz run` of each of the seven targets for one hour with no crash, in the nightly matrix. This is the fuzzing half of the phase 1 exit criterion (`docs/spec.md` §10).

## Out of scope

- Fuzzing the `store` and the `server`, which arrive with their phases; each `pub` function of `core` they add for external bytes joins the set of R7 (`docs/spec.md` §9).
- Fuzzing `Channel` and `Session`, which arrive with specs 021-channel-session and 028-session-sans-io and add their own targets.
- Fuzzing past Argon2id, and any round-trip property test: each belongs to the spec that owns the codec.
- Structure-aware fuzzing with `arbitrary` implementations: v1 fuzzes bytes, which is what the network delivers.
- Coverage measurement and corpus minimisation: useful, not a gate.

## Open questions

None. Closed after audit F: one hour per target, run as a matrix of parallel nightly jobs, which respects the six-hour limit of a hosted job and costs nothing on a public repository (016-R9).

## History

- 2026-09-21 in review
- 2026-09-24 revised after audit E (`docs/audit-log.md`): targets over the pure functions of phase 1 through `cfg(fuzzing)`, `receive_signed` and the post-KDF config target, one dependency with a scoped licence exception, lint equality test; open question 016-R3 closed (AGENTS 21 read literally, plus `fuzz_entry`)
- 2026-09-24 revised after audit F (`docs/audit-log.md`): seven targets (post-KDF and seal-then-open dropped), record target over a schema with every type, times from the input, `receive_signed` through `seal_padded`, set check with a named exclusion list in place of a count, nightly matrix, `check-cfg` for `cfg(fuzzing)` and a clippy step in place of the lint-table test; open question 016-R9 closed
- 2026-09-24 documentation review: the round-trip requirement (old R11) dropped, since every round-trip already lives in the spec that owns its codec; R12 and R13 renumbered to R11 and R12; `record_decode` drives the test schema of spec 017 under `cfg(any(test, fuzzing))`; `Config::open_encrypted` added to the exclusion list
