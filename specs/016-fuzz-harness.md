# 016 — Fuzz harness

Status: in review
Phase: 1
Related ADRs: 0012, 0015
Depends on: 010-primitives-wrapper, 011-config-format, 013-wire-message, 015-test-vectors
Blocks: 021-channel-session, 063-beta
Human reviewer: Marc Vilardebó · Accepted on: —

## Context

Every byte the core parses comes from a hostile network or a corrupt file: a blob the server relayed, a config someone scanned, a record read back from disk. The workspace lints already make a panic on that path a compile error in most shapes (AGENTS 4), but only a fuzzer finds the input nobody thought of. AGENTS 21 fixes the rule: every `parse`, `decrypt` and `open_*` has a target in `crates/core/fuzz` and a round-trip property test, and this spec adds the check that the number of targets keeps up with the number of functions that take bytes.

The phase 1 exit criterion asks for one hour per target without a crash (`docs/spec.md` §10).

## Requirements

- R1 `crates/core/fuzz` MUST be a `cargo-fuzz` crate excluded from the workspace, so that its dependencies never reach `core`, `store` or `server`.
- R2 There MUST be one target per public or crate-visible function that takes untrusted bytes, and at least these four: `decrypt`, `payload_parse`, `config_parse` and `encrypt_then_decrypt`.
- R3 `scripts/check_fuzz_targets.sh` MUST fail when the number of targets is lower than the number of functions of `core` that take a `&[u8]` from outside, and MUST name the functions with no target.
- R4 Every target MUST be small: bytes in, one call, result ignored, no assertion beyond the absence of a panic, and no `unwrap` of its own.
- R5 The corpus of each target MUST be seeded from the vectors of `specs/vectors/`, positive and negative alike, so that fuzzing starts from inputs that already reach deep into the parser.
- R6 A nightly CI job MUST run each target for one hour and MUST fail the build on any crash, timeout or memory limit hit.
- R7 A crash MUST become a test before it becomes a fix: the crashing input is added as a regression case in the spec's own tests, with the error it must now produce.
- R8 Every encoder and decoder pair MUST have a `proptest` round-trip: the config, the payload, the envelope and the padding, each over the full range of its limits.
- R9 The targets MUST NOT be built with the workspace lints relaxed: the fuzz crate MUST deny the same lints, so that a panic added to a target is a compile error.
- R10 A target MUST NOT depend on a clock, on randomness or on the file system: the fuzzer supplies every byte, and time enters as a fixed value.
- R11 The fuzz crate's dependencies MUST pass `cargo deny check` under the same `deny.toml` as the workspace, with `libfuzzer-sys` and `arbitrary` as the only additions.
- R12 A target that stops compiling MUST fail CI in the same way a test does: the nightly job MUST build every target on every run, even when it has no time to run them all.

## Limits

| Item | Range | Out of range |
| --- | --- | --- |
| Targets | ≥ the functions of `core` taking external bytes | `check_fuzz_targets` fails |
| Nightly run | 3600 s per target | failure |
| Memory per target | the `cargo-fuzz` default | failure |
| Additional dependencies | `libfuzzer-sys`, `arbitrary` | `cargo deny` fails |

## Interface

```
crates/core/fuzz/Cargo.toml                 excluded from the workspace (R1)
crates/core/fuzz/fuzz_targets/decrypt.rs
crates/core/fuzz/fuzz_targets/payload_parse.rs
crates/core/fuzz/fuzz_targets/config_parse.rs
crates/core/fuzz/fuzz_targets/encrypt_then_decrypt.rs
crates/core/fuzz/corpus/<target>/            seeded from specs/vectors (R5)
scripts/check_fuzz_targets.sh                the count of R3
.github/workflows/fuzz.yml                   the nightly job of R6
```

```rust
// The shape every target keeps: bytes in, one call, no assertion.
fuzz_target!(|data: &[u8]| {
    let _ = Config::parse(data, FIXED_NOW);
});
```

## Security

- Fuzzing is the only check in the project that looks for the input nobody imagined. The lints stop the panics we can name; the fuzzer finds the slice, the subtraction and the length that no review saw.
- Seeding from the vectors (R5) matters more than the hours: a random byte string fails at the length check of `docs/spec.md` §4 step 1 and never reaches the AEAD, while a mutated valid blob reaches every step.
- `encrypt_then_decrypt` is the one target that holds a key: it proves that what the core seals it opens, over arbitrary payloads, which is the property a corrupted padding or an off-by-one in the envelope would break.
- R7 exists because a fixed crash with no test comes back: the regression case is what makes the fix permanent.
- The fuzz crate is outside the workspace (R1) so that its dependencies, which are not ours and run only on a developer's machine, never enter the graph the product ships.

## Public API changes

None.

## Test cases

- T01 (covers R1, R11): `s016_t01_r01_fuzz_crate_is_isolated`: the workspace manifest excludes it, and `cargo deny` over its lock file passes with only the two additions.
- T02 (covers R2, R3): `check_s016_t02_r03_every_parser_has_a_target` in `scripts/check_fuzz_targets.sh`, with a fixture: a function added with no target fails the script.
- T03 (covers R4, R9): `s016_t03_r04_targets_are_small`: every target file is at most 20 lines, contains no `unwrap`, no `assert` and no `panic`, and the crate denies the workspace lints.
- T04 (covers R5): `s016_t04_r05_corpus_is_seeded`: each corpus directory holds one file per vector of its spec.
- T05 (covers R6, R12): `s016_t05_r06_nightly_builds_and_runs`: the workflow builds every target and runs each for 3600 seconds.
- T06 (covers R8): `s016_t06_r08_round_trips`: the four `proptest` round-trips, each over the full range of its limits.
- T07 (covers R10): `s016_t07_r10_targets_are_pure`: no target names a clock, a random source or the file system.

R7 has no test of its own: it is a rule about what a pull request must contain, and the pull request template carries it.

## Vectors

None of its own. The corpus is seeded from every other spec's vectors (R5).

## Acceptance criterion

`cargo fuzz run` of each of the four targets for one hour with no crash, on the machine that runs the nightly job; `scripts/check_fuzz_targets.sh` green; the four round-trips green. This is the fuzzing half of the phase 1 exit criterion (`docs/spec.md` §10).

## Out of scope

- Fuzzing the `store` and the `server`, which arrive with their phases and carry their own targets.
- Structure-aware fuzzing with `arbitrary` implementations of `Payload` or `Config`: v1 fuzzes bytes, which is what the network delivers.
- Coverage measurement and corpus minimisation, useful and not a gate.

## Open questions

- [ ] 016-R3: counting "functions that take a `&[u8]` from outside" needs a definition a script can apply. The proposal is every `pub` or `pub(crate)` function of `core` whose signature contains `&[u8]` and which is not in `crypto`, whose inputs are already covered by its own tests. Confirm the exclusion of `crypto`, or accept targets for the primitives too.
- [ ] 016-R6: one hour per target per night is four hours of runner time. Confirm it fits the project's CI budget, or lower it to 15 minutes per target with a weekly long run.

## History

- 2026-09-21 in review
