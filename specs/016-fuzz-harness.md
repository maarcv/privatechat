# 016 — Fuzz harness

Status: in review
Phase: 1
Related ADRs: 0012, 0023, 0024
Depends on: 010-primitives-wrapper, 015-test-vectors, 017-record-encoding, 011-config-format, 012-message-keys, 013-wire-message, 014-fingerprint
Blocks: 021-channel-session, 063-beta
Human reviewer: Marc Vilardebó · Accepted on: —

## Context

Every byte the core parses comes from a hostile network or a file that may be corrupt: a blob the server relayed, a config someone scanned or typed, a record read back from disk. The workspace lints already turn most panics on that path into compile errors (AGENTS 4), but only a fuzzer finds the input nobody thought of. AGENTS 21 fixes the rule: every `parse`, `decrypt` and `open_*` has a target in `crates/core/fuzz` and a round-trip property test. This spec adds the check that the number of targets keeps up with the number of functions that take bytes.

Everything phase 1 fuzzes is a pure function (specs 017-record-encoding, 011-config-format, 013-wire-message, 014-fingerprint). No target needs a `Store` or a `Channel`, so this spec closes in phase 1 and blocks spec 021-channel-session instead of waiting for it.

The fuzz crate sits outside the workspace, so it can only call `pub` items of `core`. The crate-internal parsers are reached through a module that exists only when `cargo fuzz` builds: `#[cfg(fuzzing)] pub mod fuzz_entry`. `cargo fuzz` sets `--cfg fuzzing` itself. It is not a Cargo feature, so the product build never contains it.

The phase 1 exit criterion asks for one hour per target without a crash (`docs/spec.md` §10).

## Requirements

- R1 `crates/core/fuzz` MUST be a `cargo-fuzz` crate excluded from the workspace, so that its dependencies never reach `core`, `store` or `server`.
- R2 `core` MUST expose its crate-internal parsers to the fuzz crate only through `#[cfg(fuzzing)] pub mod fuzz_entry`, and that module MUST NOT exist in any build without `--cfg fuzzing`.
- R3 There MUST be at least these nine targets: `record_decode`, `config_parse`, `config_parse_qr`, `config_file_after_kdf`, `payload_decode`, `receive`, `receive_signed`, `seal_then_open` and `verify_qr_parse`.
- R4 `config_file_after_kdf` MUST fuzz the `.chatcfg` path after the Argon2id step, through a `fuzz_entry` hook that takes a fixed key in place of the password, so each run costs microseconds and not 64 MiB.
- R5 `receive_signed` MUST seal and sign arbitrary padded plaintext and arbitrary header fields with a fixed test key, skipping `validate`, and then run `verify` and `open`, so that fuzzing reaches every step after the signature check of `docs/spec.md` §4.
- R6 `scripts/check_fuzz_targets.sh` MUST fail when the number of targets is lower than the number of `pub` functions of `core` that take a `&[u8]` plus the number of functions of `fuzz_entry`, and MUST name the functions with no target.
- R7 Every target MUST be at most one call on the fuzzer's bytes with the result ignored: no `unwrap`, no `panic`, and no assertion, except `seal_then_open`, which MUST carry exactly one assertion, that what it sealed opens to the same payload.
- R8 The corpus of each target MUST be seeded from the vectors of `specs/vectors/`, positive and negative alike.
- R9 A nightly CI job MUST build every target on every run and run each one for 3600 seconds, and MUST fail on any crash, timeout, memory-limit hit or build failure.
- R10 Every encoder and decoder pair MUST have a `proptest` round-trip over the full range of its limits. The pairs are the record, the config as record, QR text and file, the payload, the envelope (`seal` then `verify` and `open`), the padding, and the verification QR.
- R11 The fuzz crate MUST deny the same lints as `[workspace.lints]`, and a test MUST fail when its lint table differs from the workspace table in any entry.
- R12 A target MUST NOT depend on a clock, on randomness or on the file system: the fuzzer supplies every byte, and time enters as a fixed constant.
- R13 The fuzz crate MUST add exactly one dependency, `libfuzzer-sys`. Its licence, `(MIT OR Apache-2.0) AND NCSA`, MUST pass `cargo deny` through a licence exception in `deny.toml` scoped to `libfuzzer-sys` alone, with the reason naming this spec.

## Limits

| Item | Range | Out of range |
| --- | --- | --- |
| Targets | ≥ `pub` functions taking `&[u8]` + `fuzz_entry` functions | `check_fuzz_targets` fails |
| Nightly run | 3600 s per target | failure |
| Memory per target | the `cargo-fuzz` default | failure |
| Additional dependencies | `libfuzzer-sys` only | `cargo deny` fails |
| Assertions per target | 0; 1 in `seal_then_open` | T06 fails |

## Interface

```
crates/core/src/fuzz_entry.rs                cfg(fuzzing) only (R2)
crates/core/fuzz/Cargo.toml                  excluded from the workspace (R1)
crates/core/fuzz/fuzz_targets/<target>.rs    one file per target of R3
crates/core/fuzz/corpus/<target>/            seeded from specs/vectors (R8)
scripts/check_fuzz_targets.sh                the count of R6
.github/workflows/fuzz.yml                   the nightly job of R9
```

```rust
// The shape every target keeps: bytes in, one call, result ignored.
fuzz_target!(|data: &[u8]| {
    let _ = fuzz_entry::payload_decode(data);
});
```

`fuzz_entry` holds one thin function per crate-internal parser, taking `&[u8]` and returning nothing. Each one calls the real function with fixed test keys and a fixed `now`, and drops the result. It adds no logic of its own.

## Security

- Fuzzing is the only check in the project that looks for the input nobody imagined. The lints stop the panics we can name; the fuzzer finds the slice, the subtraction and the length that no review saw.
- Seeding from the vectors (R8) matters more than the hours: a random byte string fails at the length check of `docs/spec.md` §4 step 1 and never reaches the AEAD, while a mutated valid blob reaches every step.
- A mutated blob can never get past the signature, so `receive` alone never exercises what happens after authentication. `receive_signed` (R5) signs whatever the fuzzer writes, which is exactly what a malicious member who holds the config can send.
- `config_file_after_kdf` (R4) exists because Argon2id at 64 MiB makes a direct target of `open_encrypted` useless: a few runs per second, all failing at the tag. The hook is fuzzing-only (R2) and never compiled into the product.
- A crash becomes a test before it becomes a fix: the crashing input is added as a regression case in the owning spec's tests, with the error it must now produce. This is a process rule, carried by the review of the fix, not a requirement a test could check.
- The fuzz crate is outside the workspace (R1) so that its dependencies, which run only on a developer's machine and on the nightly runner, never enter the graph the product ships.

## Public API changes

None. `fuzz_entry` exists only under `--cfg fuzzing`.

## Test cases

- T01 (covers R1): `s016_t01_r01_fuzz_crate_is_isolated`: the workspace manifest excludes `crates/core/fuzz`, and no workspace crate depends on it.
- T02 (covers R2): `s016_t02_r02_fuzz_entry_is_cfg_gated`: `lib.rs` declares `fuzz_entry` only under `cfg(fuzzing)`, and `Cargo.toml` of `core` has no feature that enables it.
- T03 (covers R3): `s016_t03_r03_the_nine_targets_exist`: each target of R3 has its file.
- T04 (covers R4): `s016_t04_r04_config_file_target_skips_the_kdf`: the target calls the fixed-key hook and never `password_key`.
- T05 (covers R5): `s016_t05_r05_receive_signed_reaches_the_payload`: a seed built by the harness reaches `open` and returns an `Opened` value.
- T06 (covers R7): `s016_t06_r07_targets_are_small`: no target contains `unwrap` or `panic`, only `seal_then_open` contains an assertion, and it contains exactly one.
- T07 (covers R6): `check_s016_t07_r06_every_parser_has_a_target` in `scripts/check_fuzz_targets.sh`, with a fixture: a `pub` function taking `&[u8]` added with no target fails the script.
- T08 (covers R8): `s016_t08_r08_corpus_is_seeded`: each corpus directory holds at least one file per vector of the spec it fuzzes.
- T09 (covers R9): `s016_t09_r09_nightly_builds_and_runs`: the workflow builds every target and runs each for 3600 seconds.
- T10 (covers R10): `s016_t10_r10_round_trips`: the seven `proptest` round-trips, each over the full range of its limits.
- T11 (covers R11): `s016_t11_r11_fuzz_lints_match_the_workspace`: the lint table of `crates/core/fuzz/Cargo.toml` equals `[workspace.lints]` entry for entry.
- T12 (covers R12): `s016_t12_r12_targets_are_pure`: no target names a clock, a random source or the file system.
- T13 (covers R13): `s016_t13_r13_one_dependency_one_exception`: the fuzz manifest declares only `libfuzzer-sys`, and `deny.toml` carries exactly one licence exception for it, whose reason names this spec.

## Vectors

None of its own. The corpus is seeded from every other spec's vectors (R8).

## Acceptance criterion

`cargo fuzz run` of each of the nine targets for one hour with no crash, on the machine that runs the nightly job; `scripts/check_fuzz_targets.sh` green; `cargo test -p privatechat-core s016_` green; `cargo deny` green over the fuzz crate. This is the fuzzing half of the phase 1 exit criterion (`docs/spec.md` §10).

## Out of scope

- Fuzzing the `store` and the `server`, which arrive with their phases and carry their own targets.
- Fuzzing `Channel` and `Session`, which arrive with specs 021-channel-session and 028-session-sans-io and add their own targets.
- Structure-aware fuzzing with `arbitrary` implementations: v1 fuzzes bytes, which is what the network delivers.
- Coverage measurement and corpus minimisation: useful, not a gate.

## Open questions

- [ ] 016-R9: one hour per target per night is nine hours of runner time. Confirm it fits the project's CI budget. Lowering it to 15 minutes per target with a weekly long run would need a change to the phase 1 exit criterion of `docs/spec.md` §10, which asks for one hour.

## History

- 2026-09-21 in review
- 2026-09-24 revised after audit E (`docs/audit-log.md`): targets over the pure functions of phase 1 through `cfg(fuzzing)`, `receive_signed` and the post-KDF config target, one dependency with a scoped licence exception, lint equality test; open question 016-R3 closed (AGENTS 21 read literally, plus `fuzz_entry`)
