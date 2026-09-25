# 015 — Test vectors: schema, loader, reference script and freeze

Status: in review
Phase: 1
Related ADRs: 0012, 0023, 0029
Depends on: 010-primitives-wrapper
Blocks: 017-record-encoding, 011-config-format, 012-message-keys, 013-wire-message, 014-fingerprint, 016-fuzz-harness, 020-store-files, 028-session-sans-io, 040-uniffi
Human reviewer: Marc Vilardebó · Accepted on: —

## Context

Three platforms must produce the same bytes. The only thing that can prove it is a file that the Rust core, and later the Kotlin and Swift bindings, read and check (`docs/spec.md` §9, ADR 0012). The vectors also outlive the code: once frozen, they are what tells a future change that it broke the format (AGENTS 18).

This spec is implemented right after spec 010-primitives-wrapper and before any format spec, so it delivers the framework only:

- the shared loader and its schema check;
- `check_all`, the one way a format spec checks its file;
- the skeleton of the independent reference script, which produces the files, with its self-tests;
- the CI step that fails when a committed file is not what the script produces.

Each format spec then adds, in its own pull request, its section of the reference script and its `specs/vectors/NNN.json`: spec 017-record-encoding (record bytes), 011-config-format (config record, `channel_id`, base64url QR), 012-message-keys (`K_msg`, `K_hdr`, `mk`, the sealed header), 013-wire-message (payload records, signed range, signatures) and 014-fingerprint (`fp`, word indices, verification QR). That order removes the cycle in which the format specs needed vectors that only this spec could produce.

**PR slices.** Two pull requests of at most 400 lines each (AGENTS 14), the spec marked `implemented` after the second: (a) the shared loader, its schema check, `check_all` and the move of spec 010's tests onto the loader (R1–R3); (b) the reference script with its self-tests and the CI step (R4–R6). A spec's slices fix the order of its pull requests, not their number: a slice that would exceed 400 lines (AGENTS 14) is split into consecutive pull requests.

In plain words: a `derived` vector is a value computed from the formulas of `docs/spec.md`. A short Python script that shares no code with the core writes every such value into the files; the core then reads the files and must reproduce every value. If the core has a bug in a tag or a byte order, the two disagree before anything is frozen.

## Requirements

- R1 Each spec with a format or a derivation MUST have exactly one file `specs/vectors/NNN.json` with the schema of `specs/vectors/README.md`: `spec`, `proto_version` = 1 and a `vectors` array of objects with `name`, `kind`, `source`, `origin`, `inputs` and `expected`. `source` MUST be `published` (transcribed from a standard), `derived` (written by the reference script from the formulas of `docs/spec.md` §4, or by editing another vector of the same file) or `pinned` (bytes libsodium produced, transcribed once into the script as a literal), and `origin` MUST name it precisely enough for a reader to find it: a document and a section, a formula of `docs/spec.md`, or the library version that produced it. Every byte string MUST be lowercase hexadecimal of even length; every integer of at most 32 bits MUST be a JSON number; every 64-bit integer MUST be its big-endian 8 bytes as 16 lowercase hexadecimal characters; a boolean MUST be `true` or `false`; an absent optional value MUST be a missing field; a list MUST be a JSON array of values under these same rules. Text MUST appear only in the fields `spec`, `name`, `kind`, `source`, `origin`, `error`, `content`, `event`, `policy`, `schema` and `words`. Base64, uppercase hexadecimal, `null` and a 64-bit JSON number MUST NOT appear. The loader MUST fail the test that reads a file breaking any of these rules, never return an empty result.
- R2 A single loader, `crates/core/src/vectors.rs` under `cfg(test)`, MUST read every file with its own JSON reader over `include_str!`, with no dependency, and MUST be shared by the tests of every spec. The loader of spec 010-primitives-wrapper moves into it, and the tests of spec 010 move to its accessors of the Interface; they keep calling `load` by name, since they are implemented and reviewed.
- R3 Every spec with vectors from spec 011 on MUST check them in exactly one test, `sNNN_vectors_dispatch`, which calls `check_all("NNN", entries)` with one entry `(name, checker)` per vector; `check_all` MUST fail the test on a vector with no entry and on an entry with no vector, and MUST be, with the `load` of spec 010's tests, the only way to check a file's vectors, so no vector is checked twice and none is left unchecked.
- R4 `scripts/reference/vectors.py` MUST use only the Python standard library, MUST NOT import anything from the repository or any third-party package (it opens exactly one repository file, `crates/core/src/proto/bip39_english.txt`, relative to its own path, as data for the words of spec 014-fingerprint, and MUST refuse to write anything when that file's SHA-256 differs from the literal of spec 011-config-format R17), MUST keep one section per format spec, and MUST first pass its self-tests: the BLAKE2b test vector of RFC 7693 Appendix A, the test vectors of RFC 8032 §7.1 against its Ed25519, and the XChaCha20 and XChaCha20-Poly1305 vectors of `010.json` against its own ChaCha20 family.
- R5 The reference script MUST carry, transcribed with the standard library only, the reference Ed25519 of RFC 8032 §6 and ChaCha20, HChaCha20 and Poly1305 of RFC 8439 and draft-irtf-cfrg-xchacha, composed as XChaCha20 and XChaCha20-Poly1305 IETF; BLAKE2b and `crypto_kdf_derive_from_key` come from `hashlib`. It MUST write every file `specs/vectors/NNN.json` of specs 011, 012, 013, 014 and 017 from fixed inputs written in the script, with no randomness and no clock, so that two runs give byte-identical files: each `derived` value from the formulas of `docs/spec.md` §4, each `pinned` value as a literal transcribed once with an `origin` naming the library version (`chatcfg_reference` of spec 011-config-format, whose bytes the Rust test of spec 011 produces once from the fixed inputs and which change only with a libsodium bump, spec 010 "Bumping libsodium"). Each format spec's own requirement lists what its section computes. A negative vector's `error` and a positive vector's `content` are verdicts, which the Rust tests check, and the script writes them as its spec says. It MUST NOT implement Argon2id or XSalsa20, which spec 010-primitives-wrapper checks against published vectors. `010.json` and every `published` vector are outside the script: they are transcribed from their sources and checked, never produced.
- R6 The CI workflow MUST run `python3 scripts/reference/vectors.py` and fail when a file under `specs/vectors/` differs from what the script wrote, in a step named `s015_t06_r06_reference_script`, and `.github/CONTRIBUTING.md` MUST list the same command among the local CI commands (AGENTS 17).

## Limits

| Item | Range | Out of range |
| --- | --- | --- |
| Files | one per spec with a format | compile error (`include_str!`, R2) |
| `proto_version` | 1 | loader error |
| `kind` | `positive`, `negative` | loader error |
| `source` | `published`, `derived`, `pinned` | loader error |
| Hexadecimal | lowercase, even length | loader error |
| 64-bit integer | exactly 16 hex characters | loader error |
| JSON number | 0..=2^32 − 1 | loader error |

## Interface

```
crates/core/src/vectors.rs             the shared loader and check_all, cfg(test)
crates/core/src/vectors/tests.rs       s015_* tests
scripts/reference/vectors.py           the independent producer of the files (R4, R5)
specs/vectors/NNN.json                 one file per spec, written by the script for 011–014 and 017
```

```rust
pub(crate) struct Vector { /* name, kind, source, origin, inputs, expected */ }
pub(crate) enum Value { Hex(Vec<u8>), Number(u32), Bool(bool), Text(String), List(Vec<Value>) }

// `mod vectors` is `#[cfg(test)] #[allow(dead_code, reason = "accessors used by specs 011–017")]` until they land.
pub(crate) fn load(spec: &str, name: &str) -> Vector;   // spec 010's tests only (R2, R3): no test outside crypto/tests.rs calls it
pub(crate) type Checker = fn(&Vector);
pub(crate) fn check_all(spec: &str, entries: &[(&str, Checker)]);   // R3
fn all(spec: &str) -> Vec<Vector>;                      // private: check_all and the s015 tests

impl Vector {
    pub(crate) fn name(&self) -> &str;
    pub(crate) fn kind(&self) -> Kind;                   // Positive or Negative
    pub(crate) fn input(&self, field: &str) -> &Value;     // fails the test when absent
    pub(crate) fn expected(&self, field: &str) -> &Value;
    pub(crate) fn has_input(&self, field: &str) -> bool;   // for an optional value
    pub(crate) fn has_expected(&self, field: &str) -> bool;
}

impl Value {
    pub(crate) fn bytes(&self) -> &[u8];
    pub(crate) fn array<const N: usize>(&self) -> [u8; N];
    pub(crate) fn number(&self) -> u32;                  // a JSON number
    pub(crate) fn u64_hex(&self) -> u64;                 // 16 hex characters, big-endian
    pub(crate) fn flag(&self) -> bool;
    pub(crate) fn text(&self) -> &str;                   // only in the text fields of R1
    pub(crate) fn list(&self) -> &[Value];
}
```

There is one loader (R2): spec 010's tests read their file through it and are the only callers of `load`; every later spec reaches its file through `check_all` alone (R3).

**Reference script.** `crypto_kdf_derive_from_key` is computed as libsodium defines it (`crypto_kdf_blake2b_derive_from_key`): BLAKE2b with an empty message, `key` = the master key, `salt` = `subkey_id` as 8 little-endian bytes followed by 8 zero bytes, and `person` = the 8-byte context followed by 8 zero bytes, with the output length of the subkey; this reproduces the `kdf_subkey_0` vector of spec 010-primitives-wrapper. The unkeyed and keyed hashes of §4 are `hashlib.blake2b(digest_size = 32)` with and without `key`. Ed25519 is the RFC 8032 §6 reference code, and the ChaCha20 family a direct transcription of RFC 8439 §2.3–2.8 plus HChaCha20; both are slow and unhardened and are used here only to produce test values offline. They exist so that the composition of §4 — which key, which nonce and which associated data enter each primitive — is written by code that shares nothing with the core; spec 010's published vectors prove only the primitives. The fixed inputs of every vector (keys, nonces, counters, times, bodies) are literals in the script, one block per section.

## Security

- A vector file is public and lives in a public repository: a key pasted from a real channel would be a channel published forever. Every key in a vector the script writes is a fixed test value declared in the script, and the human acceptance check below confirms no file carries anything that ever protected something real.
- `derived` vectors are written by the reference script from the formulas of `docs/spec.md` §4 and reproduced by the core: an error in a tag, a context, a byte order, an input length, the signed range, or the key, nonce or associated data given to the AEAD or the header stream makes the two disagree before the freeze. `docs/spec.md` §12 ranks exactly this error first among the project's risks.
- The reference Ed25519 pins what is signed: an implementation that signed fewer bytes than §4 fixes would produce signatures the script's vectors reject.
- `pinned` vectors prove no conformance: they detect a change of library, of build flags or of our own code. Spec 010-primitives-wrapper explains why three of its vectors are pinned, and that reasoning is the only one that justifies the kind.
- The vectors and the §4 literals freeze together when phase 1 closes, once `cargo test` reproduces every vector the script wrote (AGENTS 18, `docs/spec.md` §4). A bug found during phase 1 is fixed without a `proto_version` 2 before version 1 exists; after the freeze, `adr-guard` refuses a diff that touches `specs/vectors/` without an ADR.

## Public API changes

None. Everything here is test infrastructure and CI.

## Test cases

- T01 (covers R1): `s015_t01_r01_every_committed_file_matches_the_schema`: every file in `specs/vectors/` loads; every vector carries the six fields, `source` is one of the three words, `origin` is not empty, every string outside the text fields is lowercase hexadecimal of even length, no `null` appears, every JSON number is at most 2^32 − 1, every 64-bit field is 16 hex characters and `proto_version` is 1.
- T02 (covers R2): `s015_t02_r02_one_loader_serves_every_spec`: `all(spec)` returns as many vectors as each committed file lists, and spec 010-primitives-wrapper's tests stay green through `load` after the move.
- T03 (covers R3): `s015_t03_r03_check_all_is_exhaustive`: over `010.json`, `check_all` with one entry per vector name passes; with one name left out or one name the file does not hold it fails the test.
- T04 (covers R4): `check_s015_t04_r04_reference_script_is_independent`, a self-check inside `scripts/reference/vectors.py`: the script imports only standard-library modules, and its self-tests reproduce RFC 7693 Appendix A, the RFC 8032 §7.1 vectors and the XChaCha20 vectors of `010.json` before it writes anything.
- T05 (covers R5): `check_s015_t05_r05_script_writes_every_file`, a self-check inside `scripts/reference/vectors.py`: the script writes `011.json`, `012.json`, `013.json`, `014.json` and `017.json`, two runs give byte-identical files (the CI diff of R6 is what observes it against the committed files), and every file it writes loads under R1.
- T06 (covers R6): step `s015_t06_r06_reference_script` in `.github/workflows/ci.yml`, and the same command in the local list of `.github/CONTRIBUTING.md`.

## Vectors

This spec has no vectors of its own: it is the spec of the vectors. Its tests run over the committed files and it has no fixtures.

## Acceptance criterion

`cargo test -p privatechat-core s015_` green, `python3 scripts/reference/vectors.py` green in CI with no difference under `specs/vectors/` (R6), and the documentation lint green. Non-automatable criterion: a human confirms that no file carries a key or a password that ever protected anything real.

## Out of scope

- The content of each file and each section of the script, which belong to the spec that owns the format.
- The Kotlin and Swift readers and the differential test against Rust, which spec 040-uniffi carries from phase 4 on, reading these same files.
- Fuzzing and its corpus, although the vectors are its seed (spec 016-fuzz-harness).
- Producing Argon2id or XSalsa20 outside libsodium, and therefore the sealed `.chatcfg` file, which spec 011-config-format pins by name.
- The `adr-guard` rule on `specs/vectors/`, which AGENTS 18 and spec 001-ci already carry.

## Open questions

None. Closed after audit F: the reference script stays in the repository, one section per spec, run in CI (015-R5).

## History

- 2026-09-21 in review
- 2026-09-24 revised after audit E (`docs/audit-log.md`): implemented before the format specs, always-run comparison with the generator, independent reference script, freeze at the close of phase 1, 64-bit integers as hex, exhaustive dispatch instead of a grep; open questions 015-R5 (exception now in AGENTS 4 and 10) and 015-R7 closed
- 2026-09-24 revised after audit F (`docs/audit-log.md`): framework only, each format spec adds its sections; reference Ed25519 of RFC 8032 and the exact list of what the script covers; one dispatch test per spec as the only loader of its vectors; doc-lint, CI-file, `adr-guard` and key-shape requirements dropped as redundant; open question 015-R12 closed
- 2026-09-24 revised after audit H (`docs/audit-log.md`): PR slices; typed values for booleans, lists and absent fields; spec 010 keeps `load` and is exempt from the dispatch rule; the reference script recomputes the XChaCha20 compositions and every `derived` value not excluded by name, with each format spec owning its list; vectors travel with the slice that tests them (R13); the CI step is a requirement (R14); round 2: `check_all` in place of a free-form dispatch, `kind()` and `has_expected()`, the `content` text field, the slice rule for tests that span slices; round 3: `spec` is a text field, type aliases for the checker and section tables, R9 in slice (b); round 6: one `SOURCES` list for every source-scan test, checked against git in CI; round 7: `SOURCES` in slice (a) and in `lib.rs`, the git pathspec, T15 as a mechanical check; round 8: T13 implementable, the generator may read `all`, verdict fields left to the Rust tests, `dead_code` allow on `mod vectors`; round 9: T13 ignores rustfmt's line breaks; round 13: slices fix the order, not the number of pull requests
- 2026-09-24 revised after audit I (`docs/audit-log.md`): the reference script produces the files and the Rust tests reproduce them; the Rust generator, `SECTIONS`, `generated()`, `generate_all`, the equality test and the `disallowed_methods` allow removed (I1); `pinned` = bytes libsodium produced, transcribed once, `chatcfg_reference` of 011 pinned; the source-scan test and `SOURCES` removed, `one loader` stated in the Interface (I2); `all` no longer read by a generator (I6); the slice requirement and the fixtures removed, schema, source and encoding rules merged into R1, the dispatch test named `sNNN_vectors_dispatch` (I8); requirements and tests renumbered R1–R6, T01–T06
