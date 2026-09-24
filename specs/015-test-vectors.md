# 015 — Test vectors: loader, generator, cross-check and freeze

Status: in review
Phase: 1
Related ADRs: 0012, 0023
Depends on: 010-primitives-wrapper
Blocks: 017-record-encoding, 011-config-format, 012-message-keys, 013-wire-message, 014-fingerprint, 016-fuzz-harness, 040-uniffi
Human reviewer: Marc Vilardebó · Accepted on: —

## Context

Three platforms must produce the same bytes. The only thing that can prove it is a file that the Rust core, and later the Kotlin and Swift bindings, read and check (`docs/spec.md` §9, ADR 0012). The vectors also outlive the code: once frozen, they are what tells a future change that it broke the format (AGENTS 18).

This spec is implemented right after spec 010-primitives-wrapper and before any format spec, so it delivers the framework only:

- the shared loader and its schema check;
- the generator framework, with an empty registry of sections;
- the always-run test that keeps committed files equal to what the generator produces;
- the skeleton of the independent reference script, with its self-tests.

Each format spec then adds, in its own pull request, its section of the generator, its section of the reference script and its `specs/vectors/NNN.json`: spec 017-record-encoding (record bytes), 011-config-format (config record, `channel_id`, base64url QR, file header layout), 012-message-keys (`K_msg`, `K_hdr`, `mk`, the counter tables), 013-wire-message (payload records, signed range, signatures) and 014-fingerprint (`fp`, word indices, verification QR). That order removes the cycle in which the format specs needed vectors that only this spec could produce.

In plain words: a `derived` vector is a value the core computes. If the core has a bug in a tag or a byte order, the vector freezes the bug. So before freezing, a short Python script that shares no code with the core recomputes every such value from the formulas of `docs/spec.md`, and the two must agree.

## Requirements

- R1 Each spec with a format or a derivation MUST have exactly one file `specs/vectors/NNN.json` with the schema of `specs/vectors/README.md`: `spec`, `proto_version` and a `vectors` array of objects with `name`, `kind`, `source`, `origin`, `inputs` and `expected`.
- R2 Every vector MUST declare `source` as `published`, `derived` or `pinned`, and `origin` MUST name it precisely enough for a reader to find it: a document and a section, a formula of `docs/spec.md`, or the library version that produced it.
- R3 Every byte string MUST be lowercase hexadecimal of even length; every integer of at most 32 bits MUST be a JSON number; every 64-bit integer MUST be its big-endian 8 bytes as 16 lowercase hexadecimal characters. Base64, uppercase hexadecimal and a 64-bit JSON number MUST NOT appear.
- R4 A single loader, `crates/core/src/vectors.rs` under `cfg(test)`, MUST read every file with its own JSON reader over `include_str!`, with no dependency, and MUST be shared by the tests of every spec. The loader of spec 010-primitives-wrapper moves into it and its signatures change: `load(spec, name)` in place of `load(name)`, `all(spec)` in place of `count()`, and `number` returns `u64`.
- R5 The loader MUST reject, with a failing test and not an empty result, a file that does not match the schema, a missing field, a string that is not valid hexadecimal, and a `proto_version` other than 1.
- R6 The generator, `crates/core/src/vectors/generate.rs`, MUST keep a registry of sections, one per format spec, empty when this spec lands, and MUST produce every `derived` and `pinned` vector of each registered section from fixed inputs, with no randomness and no clock, so that two runs give byte-identical files.
- R7 The generator's writing entry point MUST be an ignored test, MUST be the only code in `core` that writes a file, and MUST carry `allow(clippy::disallowed_methods, reason = "spec 015")`, which is the single exception of AGENTS 4 and AGENTS 10.
- R8 An always-run test MUST build every registered section's file in memory and compare it byte for byte with the committed file read through `include_str!`, so that a committed file that no longer matches the generator fails every CI run. A missing committed file fails at compile time.
- R9 Spec 010-primitives-wrapper's file and every `published` vector MUST be outside the generator: they are transcribed from their sources and checked, never produced.
- R10 Every spec with vectors MUST have exactly one test that iterates `all("NNN")` and dispatches each vector with a `match` on its name to the checker of the test it belongs to, whose fallback arm fails the test; that test MUST be the only code that loads the spec's vectors, so no vector is checked twice and none is left unchecked.
- R11 `scripts/reference/vectors.py` MUST use only the Python standard library, MUST NOT import anything from the repository or any third-party package, MUST keep one section per format spec, and MUST first pass its self-tests: the BLAKE2b test vector of RFC 7693 Appendix A and the test vectors of RFC 8032 §7.1 against its Ed25519.
- R12 The reference script MUST carry the reference Ed25519 of RFC 8032 §6, transcribed with the standard library only, and its sections MUST recompute exactly: every `crypto_kdf_derive_from_key` and BLAKE2b value (`channel_id`, `K_msg`, `K_hdr`, `mk`, `fp`); `pk_ch` from its seed; the record bytes of specs 017, 011 and 013; the base64url of specs 011 and 014; the 12 word indices; and every 013 signature, verified over `"privatechat/msg/v1" ‖ blob[0..81 + n]`. It MUST read the word list file and check its SHA-256 against spec 011-config-format. It MUST NOT recompute XChaCha20, Poly1305 or Argon2id outputs, which spec 010-primitives-wrapper checks against published vectors.

## Limits

| Item | Range | Out of range |
| --- | --- | --- |
| Files | one per spec with a format | compile error (R8) |
| `proto_version` | 1 | loader error |
| `kind` | `positive`, `negative` | loader error |
| `source` | `published`, `derived`, `pinned` | loader error |
| Hexadecimal | lowercase, even length | loader error |
| 64-bit integer | exactly 16 hex characters | loader error |
| JSON number | 0..=2^32 − 1 | loader error |

## Interface

```
crates/core/src/vectors.rs             the shared loader, cfg(test)
crates/core/src/vectors/generate.rs    the generator: registry, generated(), generate_all (R6, R7)
crates/core/src/vectors/tests.rs       s015_* tests
scripts/reference/vectors.py           the independent recomputation (R11, R12)
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

/// One entry per format spec; each spec's pull request adds its own.
pub(crate) const SECTIONS: &[(&str, fn() -> String)] = &[];
/// The file of one registered spec, built in memory.
pub(crate) fn generated(spec: &str) -> String;
/// Ignored test: writes every registered file to specs/vectors/ (R7).
fn generate_all();
```

**Reference script.** `crypto_kdf_derive_from_key` is recomputed as libsodium defines it (`crypto_kdf_blake2b_derive_from_key`): BLAKE2b with an empty message, `key` = the master key, `salt` = `subkey_id` as 8 little-endian bytes followed by 8 zero bytes, and `person` = the 8-byte context followed by 8 zero bytes, with the output length of the subkey; this reproduces the `kdf_subkey_0` vector of spec 010-primitives-wrapper. The unkeyed and keyed hashes of §4 are `hashlib.blake2b(digest_size = 32)` with and without `key`. Ed25519 is the RFC 8032 §6 reference code, which is slow and unhardened and is used here only to recompute public values offline.

## Security

- A vector file is public and lives in a public repository: a key pasted from a real channel would be a channel published forever. Every key in a generated vector is a fixed test value declared in the generator, and the human acceptance check below confirms no file carries anything that ever protected something real.
- The generator is the one place where `core` touches the file system. Its writing entry is an ignored test, it never runs in CI, and its allow names this spec, so the exception is auditable by grep (AGENTS 10).
- `derived` vectors produced by the implementation under test prove only self-consistency. The reference script is what turns them into evidence: an error in a tag, a context, a byte order, an input length or the signed range makes the two disagree before the freeze. `docs/spec.md` §12 ranks exactly this error first among the project's risks.
- The reference Ed25519 pins what is signed: an implementation that signed fewer bytes than §4 fixes would produce signatures the script rejects.
- `pinned` vectors prove no conformance: they detect a change of library, of build flags or of our own code. Spec 010-primitives-wrapper explains why three of its vectors are pinned, and that reasoning is the only one that justifies the kind.
- The vectors and the §4 literals freeze together when phase 1 closes, after the reference script has cross-checked them (AGENTS 18, `docs/spec.md` §4). A bug found during phase 1 is fixed without a `proto_version` 2 before version 1 exists; after the freeze, `adr-guard` refuses a diff that touches `specs/vectors/` without an ADR.

## Public API changes

None. Everything here is test infrastructure and CI.

## Test cases

- T01 (covers R1): `s015_t01_r01_every_file_matches_the_schema`: every file in `specs/vectors/` parses and carries the six fields in every vector.
- T02 (covers R2): `s015_t02_r02_every_vector_declares_its_origin`: `source` is one of the three words and `origin` is not empty.
- T03 (covers R3): `s015_t03_r03_encodings_are_canonical`: every byte string is lowercase hexadecimal of even length, every JSON number is at most 2^32 − 1, and every 64-bit field is 16 hex characters.
- T04 (covers R4): `s015_t04_r04_one_loader`: the source tree has one vector loader, `vectors.rs`, and spec 010-primitives-wrapper's tests read their file through it.
- T05 (covers R5): `s015_t05_r05_loader_rejects_a_broken_file`: fixtures with a missing field, a truncated file, an odd-length hex string and `proto_version` 2 each fail loudly.
- T06 (covers R6): `s015_t06_r06_the_generator_is_deterministic`: with a fixture section registered, generating twice into memory gives identical bytes, and the registry of the landed spec is empty.
- T07 (covers R7): `s015_t07_r07_only_the_generator_writes`: the sources of `core` contain exactly one allow of `disallowed_methods`, in `generate.rs`, with the reason `spec 015`.
- T08 (covers R8): `s015_t08_r08_committed_files_match_the_generator`: for every registered section, `generated(spec)` equals the committed file byte for byte; with a fixture section, a changed byte fails.
- T09 (covers R9): `s015_t09_r09_published_vectors_are_not_generated`: no `published` vector and no vector of 010 comes out of any section.
- T10 (covers R10): `s015_t10_r10_one_dispatch_per_spec`: every spec with a file has exactly one test that calls `all` on it and no other test calls `load` on it, and a fixture vector with an unknown name makes the dispatch fail.
- T11 (covers R11): `check_s015_t11_r11_reference_script_is_independent`: the script imports only standard-library modules, and its self-tests reproduce RFC 7693 Appendix A and the RFC 8032 §7.1 vectors before it checks anything else.
- T12 (covers R12): `check_s015_t12_r12_reference_script_covers_its_list`: each section of the script declares the values it recomputes, the union equals the list of R12, and the word-list check fails on a fixture list with one word changed.

## Vectors

This spec has no vectors of its own: it is the spec of the vectors. Its fixtures are the malformed files of T05, the fixture section of T06 and T08, the unknown vector of T10 and the altered word list of T12, which live beside the tests and are never part of `specs/vectors/`.

## Acceptance criterion

`cargo test -p privatechat-core s015_` green, `python3 scripts/reference/vectors.py` green, and the documentation lint green. The CI workflow gains a plain step that runs `python3 scripts/reference/vectors.py` against `specs/vectors/` and fails on any difference. Non-automatable criterion: a human confirms that no file carries a key or a password that ever protected anything real.

## Out of scope

- The content of each file and each section of the generator and of the script, which belong to the spec that owns the format.
- The Kotlin and Swift readers and the differential test against Rust, which spec 040-uniffi carries from phase 4 on, reading these same files.
- Fuzzing and its corpus, although the vectors are its seed (spec 016-fuzz-harness).
- Recomputing XChaCha20, Poly1305 or Argon2id outside libsodium.
- The `adr-guard` rule on `specs/vectors/`, which AGENTS 18 and spec 001-ci already carry.

## Open questions

None. Closed after audit F: the reference script stays in the repository, one section per spec, run in CI (015-R12).

## History

- 2026-09-21 in review
- 2026-09-24 revised after audit E (`docs/audit-log.md`): implemented before the format specs, always-run comparison with the generator, independent reference script, freeze at the close of phase 1, 64-bit integers as hex, exhaustive dispatch instead of a grep; open questions 015-R5 (exception now in AGENTS 4 and 10) and 015-R7 closed
- 2026-09-24 revised after audit F (`docs/audit-log.md`): framework only, each format spec adds its sections; reference Ed25519 of RFC 8032 and the exact list of what the script covers; one dispatch test per spec as the only loader of its vectors; doc-lint, CI-file, `adr-guard` and key-shape requirements dropped as redundant; open question 015-R12 closed
