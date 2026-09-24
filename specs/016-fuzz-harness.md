# 016 — Fuzz harness

Status: in review
Phase: 1
Related ADRs: 0012, 0023, 0027, 0032
Depends on: 010-primitives-wrapper, 015-test-vectors, 017-record-encoding, 011-config-format, 012-message-keys, 013-wire-message, 014-fingerprint
Blocks: 021-channel-session, 063-beta
Human reviewer: Marc Vilardebó · Accepted on: —

## Context

Every byte the core parses comes from a hostile network or a file that may be corrupt: a blob the server relayed, a config someone scanned or typed, a record read back from disk. The workspace lints already turn most panics on that path into compile errors (AGENTS 4), but only a fuzzer finds the input nobody thought of. AGENTS 21 fixes the rule: every function of `core` that reads external bytes is reached by a target in `crates/core/fuzz` and has a round-trip property test, and this spec adds the CI check that keeps it true.

Everything phase 1 fuzzes is a pure function (specs 017-record-encoding, 011-config-format, 013-wire-message, 014-fingerprint). No target needs a `Store` or a `Channel`, so this spec closes in phase 1 and blocks spec 021-channel-session instead of waiting for it.

The fuzz crate sits outside the workspace, so it can only call `pub` items of `core`. The crate-internal parsers are reached through a module that exists only in `core`'s own tests and when `cargo fuzz` builds: `#[cfg(any(test, fuzzing))] pub mod fuzz_entry`. `cargo fuzz` sets `--cfg fuzzing` itself. It is not a Cargo feature, so the product build never contains it, and the tests of this spec run with `cargo test -p privatechat-core`, with no second test harness.

**PR slices.** Two pull requests of at most 400 lines each (AGENTS 14), the spec marked `implemented` after the second: (a) the fuzz crate, `fuzz_entry`, the seven targets, their tests and `scripts/check_fuzz_targets.sh` with the checks of T02, T07 and T10 (R1–R5, R7, R10, R11); (b) the reach check of R6 with its exclusion list, the seed script, `fuzz.yml` and the CI steps (R6, R8, R9, R12).

The phase 1 exit criterion asks for one hour per target without a crash (`docs/spec.md` §10).

## Requirements

- R1 `crates/core/fuzz` MUST be a `cargo-fuzz` crate excluded from the workspace, so that its dependencies never reach `core`, `store` or `server`.
- R2 There MUST be exactly these seven targets, each calling the `fuzz_entry` function of the same name: `record_decode`, `config_parse`, `config_parse_qr`, `payload_decode`, `receive`, `receive_signed` and `verify_qr_parse`.
- R3 `fuzz_entry::record_decode` MUST drive the test schema of spec 017-record-encoding (compiled under `cfg(any(test, fuzzing))` and written like production code, since the test lint relaxations of AGENTS 4 do not apply under `cfg(fuzzing)`): key 0 `u8` mandatory, 1 `u32`, 2 `u64`, 3 `bytes` of at most 64 bytes, 4 `bytes32`, 5 `text` of at most 64 bytes, the whole record at most 512 bytes — every type phase 1 implements — under the unknown-key policy chosen by the first input byte (0 → `Ignore`, any other value → `Reject`).
- R4 `fuzz_entry::receive` MUST read its input as `BE64(received_at) ‖ BE64(now) ‖ blob`, return at once on an input shorter than 16 bytes, and run `verify` and then `Verified::open` of spec 013-wire-message with the `ChannelCtx` of the inputs of the 013 vector `text_k1`, declared once in `proto/envelope/text_k1.rs` (spec 013-wire-message), so that the `Expired` and stale arithmetic is fuzzed too and a seed made from a 013 blob reaches `open`.
- R5 `fuzz_entry::receive_signed` MUST read its input as `BE64(counter) ‖ nonce (24 bytes) ‖ BE64(received_at) ‖ BE64(now) ‖ plaintext`, return at once on an input shorter than 48 bytes, truncate the plaintext to 64 512 bytes and extend it with zero bytes to the next multiple of 1 024 (at least 1 024), and pass it to the crate-internal `seal_padded` of spec 013-wire-message with the `ChannelCtx` of R4 and the `SenderKey` of the `text_k1` seed, skipping `validate`, and then run `verify` and `open`, so that every input reaches the steps after the signature check; the target itself MUST contain no sealing logic.
- R6 `scripts/check_fuzz_targets.sh` MUST fail when a function matched by `pub fn (parse|decrypt|open)\w*\(` with `&[u8]` in its signature, matched across line breaks, in the non-test sources of `core`, or a `pub` function of `fuzz_entry`, is reached by no target — "reached" meaning the function's name followed by `(` appears in `fuzz_entry.rs` or in a `fuzz_targets/*.rs` — MUST name each such function, and MUST read a named exclusion list, a file of `name # reason` lines, in which every entry carries its reason (AGENTS 21).
- R7 Every target MUST be one call on the fuzzer's bytes with the result ignored: no `unwrap`, no `panic` and no assertion; the verdict stays inside `core`, in the `<name>_verdict` function of the Interface, so that the tests of this spec see what an input reached while no crate-internal type crosses into the fuzz crate.
- R8 `scripts/fuzz_seeds.py`, with the Python standard library only, MUST write the corpus of each target from the vectors of `specs/vectors/`, positive and negative alike, in the input layout of R4 and R5 where they apply, from the fields of this table: `record_decode` ← the record of each 017 vector after a policy byte from its `policy`; `config_parse` ← the record of each 011 vector; `config_parse_qr` ← its QR text; `payload_decode` ← the payload record of each 013 vector; `receive` ← each 013 blob with its times; `receive_signed` ← the counter, nonce, times and padded plaintext of each positive 013 vector; `verify_qr_parse` ← each 014 QR, and the nightly workflow MUST run it before each job; the corpus is not committed.
- R9 A nightly CI workflow MUST run the seven targets as a matrix, one job per target; each job MUST install the dated nightly with `rustup toolchain install nightly-YYYY-MM-DD --profile minimal` and `cargo-fuzz` with `cargo install cargo-fuzz`, run `scripts/fuzz_seeds.py`, then build its target with `cargo +nightly-YYYY-MM-DD fuzz build` from `crates/core` (cargo-fuzz looks for `fuzz/` under the working directory) and run it for 3600 seconds; the date is pinned in the workflow, the only place in the repository that uses nightly, and each job MUST fail on any crash, timeout, memory-limit hit or build failure.
- R10 A target MUST NOT depend on a clock, on randomness or on the file system: the fuzzer supplies every byte, including the times of R4.
- R11 The fuzz crate MUST declare exactly one dependency, `libfuzzer-sys`, besides the path dependency on `privatechat-core`, MUST declare `publish = false` and its own `[workspace]` table (as `cargo fuzz init --fuzzing-workspace` writes it), and the root `Cargo.toml` MUST `exclude` it, both being needed for a crate that sits under the workspace member `crates/core`; `crates/core/fuzz/Cargo.lock` is committed after the first build (generated code, outside the AGENTS 14 count); `crates/core/fuzz/.gitignore` MUST list `target/`, `corpus/`, `artifacts/` and `coverage/`.
- R12 The CI workflow MUST run, on every pull request, `scripts/check_fuzz_targets.sh` and `RUSTFLAGS="--cfg fuzzing" cargo clippy -p privatechat-core -- -D warnings`, in steps named `s016_t12_r12_fuzz_targets_reached` and `s016_t12_r12_clippy_under_cfg_fuzzing`, and `.github/CONTRIBUTING.md` MUST list the same commands among the local CI commands (AGENTS 17).

## Limits

| Item | Range | Out of range |
| --- | --- | --- |
| Targets | the seven of R2; every function of R6 reached | `check_fuzz_targets` fails |
| Nightly run | 3600 s per target, one job each | failure |
| Memory per target | the `cargo-fuzz` default | failure |
| Additional dependencies | `libfuzzer-sys` only | T11 fails |
| Assertions per target | 0 | T07 fails |

## Interface

```
crates/core/src/fuzz_entry.rs                cfg(any(test, fuzzing)) only
crates/core/src/fuzz_entry/tests.rs          s016_* tests of R3–R5 and R8
crates/core/src/proto/record/test_schema.rs  gains decode_test_record (R3, R7)
crates/core/fuzz/Cargo.toml                  excluded from the workspace, its own [workspace] table (R1, R11)
crates/core/fuzz/Cargo.lock                  committed, generated (R11)
crates/core/fuzz/.gitignore                  target/, corpus/, artifacts/, coverage/ (R11)
crates/core/fuzz/fuzz_targets/<target>.rs    one file per target of R2, checked by scripts/check_fuzz_targets.sh
scripts/fuzz_seeds.py                        writes crates/core/fuzz/corpus/<target>/ from specs/vectors (R8)
scripts/check_fuzz_targets.sh                the set check of R6, with its exclusion list
.github/workflows/fuzz.yml                   the nightly matrix of R9
```

```rust
// The shape every target keeps: bytes in, one call, result ignored.
fuzz_target!(|data: &[u8]| {
    fuzz_entry::payload_decode(data);   // returns (); the verdict stays inside core (R7)
});
```

`core` exposes its crate-internal parsers to the fuzz crate only through `#[cfg(any(test, fuzzing))] pub mod fuzz_entry`, which exists in no build without `cfg(test)` or `--cfg fuzzing`; it relies on the `check-cfg` entry for `cfg(fuzzing)` that spec 017-record-encoding adds to `[workspace.lints.rust]` (its Interface), which the clippy step of R12 exercises under `-D warnings`. The compiler enforces the gate; it is not a requirement and has no test.

`fuzz_entry` holds one thin `pub fn <target>(data: &[u8])` per target, returning `()`, and, beside it, the `pub(crate)` `<target>_verdict(data: &[u8])` that returns the verdict, `None` for an input too short for its layout: for example `receive_verdict(&[u8]) -> Option<Result<Content, Error>>` and `record_decode_verdict(&[u8]) -> Option<Result<(), Error>>`, which calls `decode_test_record(data, policy) -> Result<(), Error>`, added by this spec to `proto/record/test_schema.rs` of spec 017 and mapping any `RecordError` to `Error::BadPayload`, so that `RecordError` never leaves `proto` (spec 011-config-format, Interface); each `pub` item carries a doc comment. Each one calls the real function with fixed test keys, reads the fields of R4 and R5 from the input where it needs them, and drops the result. The config targets pass `now = 0`, so that no invitation in a seed has expired. It adds no logic of its own: the only sealing the harness needs, for `receive_signed`, is spec 013-wire-message's own `seal_padded`.

The exclusion list of R6 names every function AGENTS 21 covers that no target reaches, each with its reason: `Config::open_encrypted` (not fuzzed past Argon2id, see "Security"; covered by the round-trip test of spec 011-config-format, R24), and the crate-internal `parse_file_header` and `Config::open_file_with_key` of spec 011 (reached only through `open_encrypted`; `open_file_with_key` checks the header with `parse_file_header`, so the R24 round trip and T13 cover both). The script finds `pub` functions by itself; the crate-internal ones are reached through `fuzz_entry` or named here.

## Security

- Fuzzing is the only check in the project that looks for the input nobody imagined. The lints stop the panics we can name; the fuzzer finds the slice, the subtraction and the length that no review saw.
- Seeding from the vectors (R8) matters more than the hours: a random byte string fails at the length check of `docs/spec.md` §4 step 1 and never reaches the AEAD, while a mutated valid blob reaches every step.
- A mutated blob can never get past the signature, so `receive` alone never exercises what happens after authentication. `receive_signed` (R5) signs whatever the fuzzer writes, which is exactly what a malicious member who holds the config can send.
- The `.chatcfg` file is not fuzzed past Argon2id: a mutated file almost never passes the `secretbox` tag, so a fixed-key target would only reach the three header comparisons its own tests already cover. The file is covered by its round-trip test in spec 011-config-format. The round-trip property tests AGENTS 21 asks for belong to the spec that defines each codec (010 padding, 011 config, 012 header, 013 envelope, 014 verification QR, 017 record); this spec adds none.
- The byte-by-byte mutation property test of the envelope, which `docs/spec.md` §10 asks for in phase 1, belongs to spec 013-wire-message, next to its mutation table.
- A crash becomes a test before it becomes a fix: the crashing input is added as a regression case in the owning spec's tests, with the error it must now produce. This is a process rule, carried by the review of the fix, not a requirement a test could check.
- The fuzz crate is outside the workspace (R1) so that its dependencies, which run only on a developer's machine and on the nightly runner, never enter the graph the product ships. Its build-time tree is not audited by `cargo deny`: it compiles only where no secret is held and no shipped artefact is produced.

## Public API changes

None. `fuzz_entry` exists only under `cfg(test)` or `--cfg fuzzing`.

## Test cases

- T01 (covers R1): `s016_t01_r01_fuzz_crate_is_isolated`: the workspace manifest excludes `crates/core/fuzz`, and no workspace crate depends on it.
- T02 (covers R2): `check_s016_t02_r02_the_seven_targets_exist` in `scripts/check_fuzz_targets.sh`, over a glob of `fuzz_targets/*.rs`: each target of R2 has its file and calls the `fuzz_entry` function of its name.
- T03 (covers R3): `s016_t03_r03_record_schema_uses_every_type`: the test schema of spec 017-record-encoding decodes a seed that carries every one of its six fields under both policies. Through `record_decode_verdict`, a seed with an extra unknown key is accepted after the byte 0x00 and gives `BadPayload` after 0x01 and 0xff, and an empty input gives `None`.
- T04 (covers R4): `s016_t04_r04_receive_reaches_expired_and_stale`: through `fuzz_entry::receive_verdict`, the blob of `text_k1` with its own times returns `Message`, with times that fail step 2 returns `Expired`, and with times that make it stale returns `Stale`; an input of 15 bytes returns `None`.
- T05 (covers R5): `s016_t05_r05_receive_signed_always_reaches_open`: a proptest over inputs of 48..=70 000 bytes: `fuzz_entry::receive_signed_verdict` never returns `BadLength`, `WrongChannel` or `BadSignature`, so every input whose times pass step 2 reaches `open`. An input of 47 bytes returns `None`.
- T06 (covers R6): `check_s016_t06_r06_every_parser_is_reached` in `scripts/check_fuzz_targets.sh`, with fixtures: a `pub` parser taking `&[u8]` added with no target fails the script and is named; an exclusion entry with no reason fails it too.
- T07 (covers R7): `check_s016_t07_r07_targets_are_small` in `scripts/check_fuzz_targets.sh`, over `fuzz_targets/*.rs`: no target contains `unwrap`, `panic` or an assertion, and each of the seven is one call of its `fuzz_entry` function.
- T08 (covers R8): `check_s016_t08_r08_corpus_is_seeded` in `scripts/fuzz_seeds.py`: each target's directory gets one file per vector that carries the fields its row of R8 names; and `s016_t08_r08_text_k1_seed_reaches_open`: the seed the script writes for `text_k1`, rebuilt in the test by the layout of R4 from the blob that `seal` gives for the `text_k1` inputs, returns `Message` through `fuzz_entry::receive_verdict`.
- T09 (covers R9): `s016_t09_r09_nightly_matrix`: the workflow has one matrix entry per target of R2, each installing the dated nightly with `rustup toolchain install` and `cargo-fuzz` with `cargo install`, running `fuzz_seeds.py`, then building with the dated nightly and running for 3600 seconds; no other workflow and not `rust-toolchain.toml` names a nightly toolchain.
- T10 (covers R10): `check_s016_t10_r10_targets_are_pure` in `scripts/check_fuzz_targets.sh`: no target or `fuzz_entry` function names a clock, a random source or the file system.
- T11 (covers R11): `s016_t11_r11_one_dependency_own_workspace`: the fuzz manifest declares only `libfuzzer-sys` and the path dependency on `privatechat-core`, `publish = false` and a `[workspace]` table; the root `Cargo.toml` excludes `crates/core/fuzz`; `crates/core/fuzz/Cargo.lock` is committed; `crates/core/fuzz/.gitignore` lists the four paths of R11.
- T12 (covers R12): steps `s016_t12_r12_fuzz_targets_reached` and `s016_t12_r12_clippy_under_cfg_fuzzing` in `.github/workflows/ci.yml`, and the same commands in the local list of `.github/CONTRIBUTING.md`.

## Vectors

None of its own. The corpus is written from every other spec's vectors (R8).

## Acceptance criterion

`cargo test -p privatechat-core s016_` green; the two CI steps of R12 green; and `cargo fuzz run` of each of the seven targets for one hour with no crash, in the nightly matrix. This is the fuzzing half of the phase 1 exit criterion (`docs/spec.md` §10).

## Out of scope

- Fuzzing the `store` and the `server`, which arrive with their phases; each `pub` function of `core` they add for external bytes joins the set of R6 (`docs/spec.md` §9).
- Fuzzing `Channel` and `Session`, which arrive with specs 021-channel-session and 028-session-sans-io and add their own targets.
- Fuzzing past Argon2id, and any round-trip property test: each belongs to the spec that owns the codec.
- Structure-aware fuzzing with `arbitrary` implementations: v1 fuzzes bytes, which is what the network delivers.
- Coverage measurement and corpus minimisation: useful, not a gate.
- `cargo deny` over the fuzz crate: its dependency tree never ships (R1).

## Open questions

None. Closed after audit F: one hour per target, run as a matrix of parallel nightly jobs, which respects the six-hour limit of a hosted job and costs nothing on a public repository (016-R9).

## History

- 2026-09-21 in review
- 2026-09-24 revised after audit E (`docs/audit-log.md`): targets over the pure functions of phase 1 through `cfg(fuzzing)`, `receive_signed` and the post-KDF config target, one dependency with a scoped licence exception, lint equality test; open question 016-R3 closed (AGENTS 21 read literally, plus `fuzz_entry`)
- 2026-09-24 revised after audit F (`docs/audit-log.md`): seven targets (post-KDF and seal-then-open dropped), record target over a schema with every type, times from the input, `receive_signed` through `seal_padded`, set check with a named exclusion list in place of a count, nightly matrix, `check-cfg` for `cfg(fuzzing)` and a clippy step in place of the lint-table test; open question 016-R9 closed
- 2026-09-24 documentation review: the round-trip requirement (old R11) dropped, since every round-trip already lives in the spec that owns its codec; R12 and R13 renumbered to R11 and R12; `record_decode` drives the test schema of spec 017 under `cfg(any(test, fuzzing))`; `Config::open_encrypted` added to the exclusion list
- 2026-09-24 revised after audit H (`docs/audit-log.md`): `fuzz_entry` under `cfg(any(test, fuzzing))` with its tests in `core`; exact input layouts and the fixed keys of `text_k1`; a seed script in place of a committed corpus; the set check counts calls through `fuzz_entry`; a dated nightly only in the fuzz workflow; the CI steps as a requirement; PR slices; round 2: `fuzz_entry` returns its verdict in place of the `_outcome` twins, the `text_k1` inputs shared with spec 013, the `record_decode` seed layout and `now = 0` for the config targets, CI step names; round 3: `allow(private_interfaces)` and example signatures, the seed table, the policy byte, two more exclusions; round 4: `pub` entries return `()` and call crate-internal `_verdict` functions, since crate-internal types cannot cross into the fuzz crate; the `check-cfg` entry moves to spec 017; round 5: `record_decode_verdict` returns `core::Error`, T08 checks the shape of the entries; round 6: `record_decode` through `decode_test_record`, the policy byte and the short input tested, T12 counts the path dependency; round 7: this spec owns `decode_test_record`; round 8: the target sources are read through `FUZZ_TARGETS` in `lib.rs`; round 9: the fuzz manifest carries its licence; round 10: the fuzz targets are checked by the script alone (no `FUZZ_TARGETS`), the manifest and `deny.toml` edits that make `cargo deny` pass, `jobserver` allowed as a build-time wrapper by the human reviewer; round 11: the script lands in slice (a) with the checks its tests need; round 11 and 12: R7 finds `pub` items and the exclusion list names the crate-internal ones no target reaches; round 13: no fuzz lockfile committed, the workspace one copied in CI, a `.gitignore` for the fuzz crate; round 14: the lock-copy check moves from T12 to T10, which lands with the workflows
- 2026-09-24 revised after audit I (`docs/audit-log.md`): no `cargo deny` over the fuzz crate, which reverses H53, H57, H60 and H62: no licence exception, no `jobserver` wrapper, no lockfile copy and no fuzz deny step; the fuzz `Cargo.lock` is committed and the crate has its own `[workspace]` table (I3); the `cfg` gate of `fuzz_entry` and the shape of its entries move to the Interface, the source-scan clauses of the old T02 and T08 dropped (I2); the test schema is the six types phase 1 implements (I4); the reach check of R6 is an operational rule and the nightly installs its toolchain and `cargo-fuzz` (I9); requirements and tests renumbered R1–R12, T01–T12
