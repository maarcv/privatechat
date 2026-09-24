# 015 — Test vectors: loader, generator, cross-check and freeze

Status: in review
Phase: 1
Related ADRs: 0012, 0023
Depends on: 010-primitives-wrapper
Blocks: 017-record-encoding, 011-config-format, 012-message-keys, 013-wire-message, 014-fingerprint, 016-fuzz-harness, 040-uniffi
Human reviewer: Marc Vilardebó · Accepted on: —

## Context

Three platforms must produce the same bytes. The only thing that can prove it is a file that the Rust core, and later the Kotlin and Swift bindings, read and check (`docs/spec.md` §9, ADR 0012). The vectors also outlive the code: once frozen, they are what tells a future change that it broke the format (AGENTS 18).

This spec is implemented right after spec 010-primitives-wrapper and before any format spec. It builds the infrastructure only:

- the shared loader;
- the schema check;
- the generator framework;
- the test that keeps committed files equal to what the generator produces;
- the independent reference script.

Each format spec (017, 011, 012, 013, 014) then adds its own generator section and its own `specs/vectors/NNN.json` in its own pull request. That order removes the cycle in which the format specs needed vectors that only this spec could produce.

In plain words: a `derived` vector is a value the core computes. If the core has a bug in a tag or a byte order, the vector freezes the bug. So before freezing, a short Python script that shares no code with the core recomputes every such value from the formulas of `docs/spec.md` §4, and the two must agree.

## Requirements

- R1 Each spec with a format or a derivation MUST have exactly one file `specs/vectors/NNN.json` with the schema of `specs/vectors/README.md`: `spec`, `proto_version` and a `vectors` array of objects with `name`, `kind`, `source`, `origin`, `inputs` and `expected`.
- R2 Every vector MUST declare `source` as `published`, `derived` or `pinned`, and `origin` MUST name it precisely enough for a reader to find it: a document and a section, a formula of `docs/spec.md`, or the library version that produced it.
- R3 Every byte string MUST be lowercase hexadecimal of even length; every integer of at most 32 bits MUST be a JSON number; every 64-bit integer MUST be its big-endian 8 bytes as 16 lowercase hexadecimal characters. Base64, uppercase hexadecimal and a 64-bit JSON number MUST NOT appear.
- R4 A single loader, `crates/core/src/vectors.rs` under `cfg(test)`, MUST read every file with its own JSON reader over `include_str!`, with no dependency, and MUST be shared by the tests of every spec. The loader of spec 010-primitives-wrapper moves into it with the same functions.
- R5 The loader MUST reject, with a failing test and not an empty result, a file that does not match the schema, a missing field, a string that is not valid hexadecimal, and a `proto_version` other than 1.
- R6 The generator, `crates/core/src/vectors/generate.rs`, MUST produce every `derived` and `pinned` vector of specs 017, 011, 012, 013 and 014 from fixed inputs, with no randomness and no clock, so that two runs give byte-identical files.
- R7 The generator MUST be an ignored test, MUST be the only code in `core` that writes a file, and MUST carry `allow(clippy::disallowed_methods, reason = "spec 015")`, which is the single exception of AGENTS 4 and AGENTS 10.
- R8 An always-run test MUST build every generated file in memory and compare it byte for byte with the committed file read through `include_str!`, so that a committed file that no longer matches the generator fails every CI run.
- R9 Spec 010-primitives-wrapper's file and every `published` vector MUST be outside the generator: they are transcribed from their sources and checked, never produced.
- R10 Every spec with vectors MUST have one test that iterates `all("NNN")` and dispatches each vector with a `match` on its name, one arm per vector, whose fallback arm fails the test, so that a vector no test checks cannot exist.
- R11 `scripts/doc_lint.py` MUST fail when a spec marked `implemented` has a "Vectors" section that names a file and that file does not exist.
- R12 `scripts/reference/vectors.py` MUST recompute every BLAKE2b-based `derived` value of specs 017, 011, 012 and 014 using only the Python standard library, reading only the formulas of `docs/spec.md` §4. It MUST NOT import anything from the repository or any third-party package. The values it covers are the record encodings, `channel_id`, `K_msg`, `K_hdr`, `mk`, `fp` and the 12 words.
- R13 A CI step MUST run the reference script and fail when any value it recomputes differs from the committed file.
- R14 The vector files MUST freeze when phase 1 closes. Until then a change needs the `adr-not-needed` label and the reviewer's reason; from then on it needs a `proto_version` change and a new ADR, and `adr-guard` MUST fail a diff touching `specs/vectors/` without one (AGENTS 18).
- R15 A vector MUST NOT carry a secret that is not an input of the algorithm it tests. Every key in a generated vector MUST be a fixed test value of the generator.

## Limits

| Item | Range | Out of range |
| --- | --- | --- |
| Files | one per spec with a format | doc lint fails (R11) |
| `proto_version` | 1 | loader error |
| `kind` | `positive`, `negative` | loader error |
| `source` | `published`, `derived`, `pinned` | loader error |
| Hexadecimal | lowercase, even length | loader error |
| 64-bit integer | exactly 16 hex characters | loader error |
| JSON number | 0..=2^32 − 1 | loader error |

## Interface

```
crates/core/src/vectors.rs             the shared loader, cfg(test)
crates/core/src/vectors/generate.rs    the generator, an ignored test (R7)
crates/core/src/vectors/tests.rs       s015_* tests
scripts/reference/vectors.py           the independent recomputation (R12)
specs/vectors/NNN.json                 one file per spec
```

```rust
pub(crate) struct Vector { /* name, kind, source, origin, inputs, expected */ }

pub(crate) fn load(spec: &str, name: &str) -> Vector;
pub(crate) fn all(spec: &str) -> Vec<Vector>;

impl Vector {
    pub(crate) fn bytes(&self, field: &str) -> Vec<u8>;
    pub(crate) fn array<const N: usize>(&self, field: &str) -> [u8; N];
    pub(crate) fn number(&self, field: &str) -> u64;      // a JSON number, at most 2^32 − 1
    pub(crate) fn u64_hex(&self, field: &str) -> u64;     // 16 hex characters, big-endian
    pub(crate) fn expected_bytes(&self, field: &str) -> Vec<u8>;
    pub(crate) fn expected_text(&self, field: &str) -> &str;
}

/// Each format spec adds one function here; `generate_all` writes their files.
pub(crate) fn generated(spec: &str) -> String;
```

**Reference script.** `crypto_kdf_derive_from_key` is recomputed as libsodium defines it (`crypto_kdf_blake2b_derive_from_key`): BLAKE2b with an empty message, `key` = the master key, `salt` = `subkey_id` as 8 little-endian bytes followed by 8 zero bytes, and `person` = the 8-byte context followed by 8 zero bytes, with the output length of the subkey. Python's `hashlib.blake2b` accepts all four parameters. The unkeyed and keyed hashes of §4 are `hashlib.blake2b(digest_size = 32)` with and without `key`.

XChaCha20, Poly1305, Argon2id and Ed25519 are not recomputed. Spec 010-primitives-wrapper already checks them against published vectors, and the Python standard library does not have them.

## Security

- A vector file is public and lives in a public repository, so R15 is not a formality: a key pasted from a real channel would be a channel published forever.
- The generator is the one place where `core` touches the file system. It is an ignored test, it never runs in CI, and its allow names this spec, so the exception is auditable by grep (AGENTS 10).
- `derived` vectors produced by the implementation under test prove only self-consistency. The reference script (R12) is what turns them into evidence: an error in a tag, a context, a byte order or an input length makes the two disagree before the freeze. `docs/spec.md` §12 ranks exactly this error first among the project's risks.
- `pinned` vectors prove no conformance: they detect a change of library, of build flags or of our own code. Spec 010-primitives-wrapper explains why three of its vectors are pinned, and that reasoning is the only one that justifies the kind.
- Freezing at the end of phase 1 (R14) lets a bug found during phase 1 be fixed without a `proto_version` 2 before version 1 exists. After the freeze, a diff that touches the vectors without an ADR does not merge.

## Public API changes

None. Everything here is test infrastructure and CI.

## Test cases

- T01 (covers R1): `s015_t01_r01_every_file_matches_the_schema`: every file in `specs/vectors/` parses and carries the six fields in every vector.
- T02 (covers R2): `s015_t02_r02_every_vector_declares_its_origin`: `source` is one of the three words and `origin` is not empty.
- T03 (covers R3): `s015_t03_r03_encodings_are_canonical`: every byte string is lowercase hexadecimal of even length, every JSON number is at most 2^32 − 1, and every 64-bit field is 16 hex characters.
- T04 (covers R4): `s015_t04_r04_one_loader`: the source tree has one vector loader, `vectors.rs`, and spec 010-primitives-wrapper's tests read their file through it.
- T05 (covers R5): `s015_t05_r05_loader_rejects_a_broken_file`: fixtures with a missing field, a truncated file, an odd-length hex string and `proto_version` 2 each fail loudly.
- T06 (covers R6): `s015_t06_r06_the_generator_is_deterministic`: generating twice into memory gives identical bytes.
- T07 (covers R7): `s015_t07_r07_only_the_generator_writes`: the sources of `core` contain exactly one allow of `disallowed_methods`, in `generate.rs`, with the reason `spec 015`.
- T08 (covers R8): `s015_t08_r08_committed_files_match_the_generator`: for every generated spec, `generated(spec)` equals the committed file byte for byte.
- T09 (covers R9): `s015_t09_r09_published_vectors_are_not_generated`: no `published` vector and no vector of 010 comes out of the generator.
- T10 (covers R10): `s015_t10_r10_every_spec_dispatches_all_its_vectors`: every spec with a file has a test that calls `all` on it, and a fixture vector with an unknown name makes the dispatch fail.
- T11 (covers R11): `check_s015_t11_r11_implemented_spec_has_its_vectors` in `scripts/doc_lint.py`, with a fixture: an `implemented` spec whose "Vectors" section names a missing file fails the lint.
- T12 (covers R12): `check_s015_t12_r12_reference_script_is_independent`: the script imports only standard-library modules and reproduces the published BLAKE2b test vector of RFC 7693 Appendix A before it checks anything else.
- T13 (covers R13): `s015_t13_r13_ci_runs_the_reference_script`: the CI workflow has a step named with this test id that runs the script against `specs/vectors/`.
- T14 (covers R14): `s015_t14_r14_adr_guard_covers_the_vectors`: the `adr-guard` path list includes `specs/vectors/`.
- T15 (covers R15): `s015_t15_r15_keys_are_generator_constants`: every key-shaped input of a generated vector is one of the fixed test constants declared in `generate.rs`.

## Vectors

This spec has no vectors of its own: it is the spec of the vectors. Its fixtures are the malformed files of T05 and T10, which live beside the tests and are never part of `specs/vectors/`.

## Acceptance criterion

`cargo test -p privatechat-core s015_` green, `python3 scripts/reference/vectors.py` green, and the documentation lint green. Non-automatable criterion: a human confirms that no file carries a key or a password that ever protected anything real.

## Out of scope

- The content of each file, which belongs to the spec that owns the format.
- The Kotlin and Swift readers and the differential test against Rust, which spec 040-uniffi carries from phase 4 on, reading these same files.
- Fuzzing and its corpus, although the vectors are its seed (spec 016-fuzz-harness).
- Recomputing XChaCha20, Poly1305, Argon2id or Ed25519 outside libsodium.

## Open questions

- [ ] 015-R12: the reference script re-implements the record encoding of spec 017-record-encoding in Python, which is a second implementation of our own format. That is the point, but it is also code that must be kept in step with §4. Confirm it belongs in the repository and not only in the reviewer's hands at the freeze.

## History

- 2026-09-21 in review
- 2026-09-24 revised after audit E (`docs/audit-log.md`): implemented before the format specs, always-run comparison with the generator, independent reference script, freeze at the close of phase 1, 64-bit integers as hex, exhaustive dispatch instead of a grep; open questions 015-R5 (exception now in AGENTS 4 and 10) and 015-R7 closed
