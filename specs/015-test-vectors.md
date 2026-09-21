# 015 — Test vectors: generation, schema and freeze

Status: in review
Phase: 1
Related ADRs: 0012, 0015
Depends on: 010-primitives-wrapper, 011-config-format, 012-message-keys, 013-wire-message, 014-fingerprint
Blocks: 016-fuzz-harness, 040-uniffi
Human reviewer: Marc Vilardebó · Accepted on: —

## Context

Three platforms must produce the same bytes, and the only thing that can prove it is a file both the Rust core and the Kotlin and Swift bindings read and check (`docs/spec.md` §9, ADR 0012). The vectors also outlive the code: once frozen, they are what tells a future change that it broke the format, which is why regenerating them needs a `proto_version` change and an ADR (AGENTS 18).

Spec 010-primitives-wrapper already wrote a loader and a file by hand. This spec generalises both: who generates the vectors, in what form, what must be true of every entry, and what CI refuses. It owns no protocol rule of its own.

## Requirements

- R1 Each spec with a format or a derivation MUST have exactly one file `specs/vectors/NNN.json`, with the schema of `specs/vectors/README.md`: `spec`, `proto_version` and a `vectors` array of objects with `name`, `kind`, `source`, `origin`, `inputs` and `expected`.
- R2 Every vector MUST declare `source` as `published`, `derived` or `pinned`, and `origin` MUST name it precisely enough for a reader to find it: a document and a section, a formula of `docs/spec.md`, or the library version that produced it.
- R3 Every byte string MUST be lowercase hexadecimal and every integer a JSON number; no field MUST carry base64, uppercase hexadecimal or a number as text.
- R4 A generator MUST produce every `derived` and `pinned` vector from fixed inputs with no randomness and no clock, so that running it twice gives a byte-identical file.
- R5 The generator MUST live inside `core` as an ignored test, MUST be the only place in the crate allowed to write a file, and MUST carry the comment that says so; running the test suite MUST NOT write anything.
- R6 Every negative vector MUST carry the exact `error` its rejection produces and `commits`, which MUST be 0 for every rejection path of `docs/spec.md` §4.
- R7 Every vector of a file MUST be used by at least one test of its spec, and `scripts/check_vectors.sh` MUST fail on a vector no test names.
- R8 `scripts/check_vectors.sh` MUST also fail when a spec marked `implemented` that declares a "Vectors" section has no file, and when a file declares a `proto_version` other than the one `docs/spec.md` §4 fixes.
- R9 A single loader MUST read every file, MUST be shared by the tests of every spec, and MUST reject a file that does not match the schema instead of silently returning nothing.
- R10 Regenerating a file MUST require a `proto_version` change and a new ADR; the `adr-guard` job MUST fail a diff touching `specs/vectors/` without one, unless a human sets the `adr-not-needed` label (AGENTS 18).
- R11 From phase 4 on, the Kotlin and Swift bindings MUST read the same files and assert the same expected values, and their failure MUST block the build (spec 040-uniffi).
- R12 A vector MUST NOT carry a secret that is not itself an input of the algorithm: no `K_ch` of a real channel, no password of a real user, and every key in a file MUST be one this repository generated for the file.

## Limits

| Item | Range | Out of range |
| --- | --- | --- |
| Files | one per spec with a format | `check_vectors` fails |
| `proto_version` | 1 | `check_vectors` fails |
| `kind` | `positive`, `negative` | `check_vectors` fails |
| `source` | `published`, `derived`, `pinned` | `check_vectors` fails |
| Hexadecimal | lowercase, even length | loader error |
| `commits` of a negative vector | 0 | `check_vectors` fails |

## Interface

```
crates/core/src/vectors.rs             the shared loader, cfg(test)
crates/core/src/vectors/generate.rs    the generator, an ignored test
scripts/check_vectors.py               the checks of R7 and R8
scripts/check_vectors.sh               its wrapper, called by CI
specs/vectors/NNN.json                 one file per spec
```

```rust
pub(crate) struct Vector { /* name, kind, source, origin, inputs, expected */ }

pub(crate) fn load(spec: &str, name: &str) -> Vector;
pub(crate) fn all(spec: &str) -> Vec<Vector>;

impl Vector {
    pub(crate) fn bytes(&self, field: &str) -> Vec<u8>;
    pub(crate) fn array<const N: usize>(&self, field: &str) -> [u8; N];
    pub(crate) fn number(&self, field: &str) -> usize;
    pub(crate) fn expected_bytes(&self, field: &str) -> Vec<u8>;
    pub(crate) fn expected_text(&self, field: &str) -> &str;
}
```

The loader of spec 010-primitives-wrapper becomes this one: same functions, one file per spec instead of one file.

## Security

- A vector file is public and lives in a public repository, so R12 is not a formality: a key pasted from a real channel would be a channel published forever.
- The generator writing a file is the one place where `core` touches the file system. It is an ignored test, it never runs in CI, and the allow that lets it compile names this requirement, so the exception is auditable by grep (AGENTS 10).
- `pinned` vectors prove no conformance: they detect a change of library, of build flags or of our own code. Spec 010-primitives-wrapper explains why three of its vectors are pinned, and that reasoning is the only one that justifies the kind.
- Freezing (R10) is what makes a silent format change impossible: a diff that touches the vectors and no ADR does not merge.

## Public API changes

None. Everything here is test infrastructure and CI.

## Test cases

- T01 (covers R1, R3): `s015_t01_r01_every_file_matches_the_schema`: every file in `specs/vectors/` parses, and every byte string is lowercase hexadecimal of even length.
- T02 (covers R2): `s015_t02_r02_every_vector_declares_its_origin`: `source` is one of the three words and `origin` is not empty.
- T03 (covers R4): `s015_t03_r04_the_generator_is_deterministic`: generating twice into memory gives identical bytes.
- T04 (covers R5): `s015_t04_r05_only_the_generator_writes`: the sources of `core` contain one allow of the file-system lint and it is in the generator.
- T05 (covers R6): `s015_t05_r06_negative_vectors_carry_their_error`: every `negative` vector has an `error` and `commits = 0`.
- T06 (covers R7, R8): `check_s015_t06_r07_no_orphan_vectors` in `scripts/check_vectors.py`, with its own fixtures: a vector no test names fails; a spec `implemented` with a "Vectors" section and no file fails.
- T07 (covers R9): `s015_t07_r09_loader_rejects_a_broken_file`: a file with a missing field, a truncated one and one with an odd-length hex string each fail loudly.
- T08 (covers R10): `s015_t08_r10_adr_guard_covers_the_vectors`: the CI job's path list includes `specs/vectors/`.
- T09 (covers R12): `s015_t09_r12_no_foreign_key_in_a_vector`: every key of every file appears in the generator, so nothing was pasted in by hand.

R11 has no test in this phase: it is a Kotlin and Swift test, and spec 040-uniffi carries it.

## Vectors

This spec has no vectors of its own: it is the spec of the vectors. Its fixtures are the malformed files of T07, which live beside the test and are never part of `specs/vectors/`.

## Acceptance criterion

`cargo test -p privatechat-core s015_` and `scripts/check_vectors.sh` green, with the vector files of specs 010 to 014 regenerated by the generator and byte-identical to the ones committed. Non-automatable criterion: a human confirms that no file carries a key or a password that ever protected anything real.

## Out of scope

- The content of each file, which belongs to the spec that owns the format.
- The Kotlin and Swift readers (spec 040-uniffi) and the differential test against Rust.
- Fuzzing and its corpus, although R7 makes the vectors the natural seed (spec 016-fuzz-harness).

## Open questions

- [ ] 015-R5: the generator writes a file from inside `core`, which AGENTS 10 forbids the crate to do. It is an ignored test, it is the only allow of the lint in the crate and CI never runs it, but it is still `std::fs` in a crate whose whole point is not having any. The alternative is a separate workspace crate, which cannot reach the `pub(crate)` derivations the vectors are made of without opening them up. Confirm the exception, or accept a narrower one: a generator that builds the JSON in memory and a shell script that writes it.
- [ ] 015-R7: requiring every vector to be named by a test keeps dead vectors out, but it means the check has to match test source against vector names, which is a grep and not a proof. Confirm it is worth its false negatives.

## History

- 2026-09-21 in review
