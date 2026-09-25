# 017 — Record encoding

Status: in review
Phase: 1
Related ADRs: 0015, 0021, 0023
Depends on: 010-primitives-wrapper, 015-test-vectors
Blocks: 011-config-format, 013-wire-message, 016-fuzz-harness, 020-store-files, 028-session-sans-io, 030-ws-protocol
Human reviewer: Marc Vilardebó · Accepted on: —

## Context

Apart from the envelope, every structure the project writes is a small record with a known schema: the payload, the config, the client-server messages and the local files (`docs/spec.md` §4 "Record encoding"). ADR 0023 replaced CBOR with one encoding of our own, so that `core` needs no third-party parser. The codec adds no dependency: `core` keeps exactly `libsodium-sys-stable` and `zeroize`, which spec 010-primitives-wrapper already pins.

In plain words: a record is a list of fields, and each field is a number that says which field it is, a length, and the bytes of the value. The fields always come in increasing order of their number, and each number has a fixed type that the schema of the record decides. The decoder reads only what the schema expects and rejects anything else, so two implementations can never read one record in two different ways.

This spec implements the six types the two phase 1 records use — `u8`, `u32`, `u64`, `bytes`, `bytesN` and `text` — and the framing rules. `docs/spec.md` §4 defines the full type list of the encoding; `bool`, nested records and `list<T>` arrive with the first schema that needs them (Out of scope).

**PR slices.** Two pull requests of at most 400 lines each (AGENTS 14), the spec marked `implemented` after the second: (a) `Reader`, `RecordError`, the test schema, the `check-cfg` entry and the decoding tests over hand-built bytes (R2–R9, R12); (b) `Writer`, the round trip, `017.json` with its reference-script section, and the dispatch test (R1, R10, R11, R13). `mod proto` carries `#[allow(dead_code, reason = "reached through Device, spec 027-core-api")]`, like `mod crypto` today, and spec 027-core-api removes both.

This spec fixes the codec. Which keys each record has, and which error a failure becomes, belong to the spec that owns the record (011-config-format, 013-wire-message, 020-store-files, 028-session-sans-io, whose frames 030-ws-protocol reuses on the server). The codec is crate-internal: `store` and `server` reach records only through `pub` functions of `core` that specs 020-store-files and 028-session-sans-io define (`docs/spec.md` §9).

## Requirements

- R1 A record MUST be a sequence of zero or more fields, and a field MUST be `key` (1 byte) ‖ `len` (4 bytes, big-endian unsigned) ‖ `value` (`len` bytes), with nothing between fields.
- R2 The decoder MUST check each field in this order, and return the first failure: at least 5 bytes left for `key` and `len`, else `RecordError::Truncated`; `len` no larger than the bytes left, else `RecordError::Truncated`, before anything is allocated or copied; `key` strictly greater than the previous key, else `RecordError::KeyOrder`, which covers duplicates; a key the schema does not name is skipped under `UnknownKeys::Ignore` and returns `RecordError::UnknownKey` under `UnknownKeys::Reject`; and only then the type rules of R3 and R4.
- R3 An integer value MUST be exactly 1 byte for `u8`, 4 for `u32` and 8 for `u64`, big-endian; any other length MUST return `RecordError::Width`.
- R4 A `bytesN` value MUST be exactly `N` bytes (else `RecordError::Width`), a `bytes` value any length up to the maximum the caller gives for that key (else `RecordError::TooLong`), and a `text` value valid UTF-8 up to the caller's maximum (else `RecordError::Utf8` or `RecordError::TooLong`).
- R5 `Reader::end` MUST walk every field left with the loop of R2, so that bytes that do not complete a field return `RecordError::Truncated` and an unknown key returns `RecordError::UnknownKey` under `Reject`; every schema decoder MUST call `end()` on its reader.
- R6 A mandatory key that is absent MUST return `RecordError::Missing`. An optional key that is absent reads as `None`; there is no null marker.
- R7 A `Reader` MUST be built with a policy, `UnknownKeys::Ignore` or `UnknownKeys::Reject`, and MUST apply it to every field it walks, including the ones `end()` walks.
- R8 `Reader::new` MUST return `RecordError::TooLong` for a buffer longer than the maximum its caller gives for the whole record, before reading any field.
- R9 Decoding MUST be typed, one decoder per schema, and MUST NOT build a generic tree of values. A value is never a record and nothing nests, so no decoder recurses on input.
- R10 The writer MUST produce the canonical encoding: keys in increasing order, each integer at its exact width, and no field for an absent optional key. Decoding what the writer produced MUST give back the same values, and, for a reader under `Reject` or a record with no unknown keys, encoding what the decoder accepted MUST give back the same bytes. Under `Ignore` a skipped key is not re-encoded; `docs/spec.md` §4 forbids a later key from changing what the known keys mean.
- R11 `Writer::with_capacity(max)` MUST allocate `max` bytes once, hold them in `zeroize::Zeroizing<Vec<u8>>`, and return `RecordError::TooLong` instead of growing, so that no reallocation leaves an unwiped copy of a secret. It MUST also return `RecordError::KeyOrder` for a key not greater than the previous one, and `RecordError::TooLong` for a value longer than 2^32 − 1 bytes.
- R12 The codec MUST NOT panic, overflow or read out of bounds on any input: every offset and length uses `checked_*` arithmetic and every failure is a `RecordError`.
- R13 This spec MUST add its section to `scripts/reference/vectors.py`, which produces `017.json`: the section encodes the bytes of every positive vector from its values by R1, R3, R4 and R10, appends the extra field of `unknown_key_ignored` by hand (the writer never emits an unknown key, R10), and builds the bytes of every negative vector by hand from the rule it breaks; every vector of this spec is `derived`.

## Limits

| Input | Range | Out of range |
| --- | --- | --- |
| Whole record | 0..=the caller's maximum | `TooLong` |
| Bytes left for a field header | ≥ 5 | `Truncated` |
| `len` of a field | 0..=bytes left in the buffer | `Truncated` |
| `key` | 0..=255, strictly increasing | `KeyOrder` |
| `bytes`, `text` | 0..=the caller's maximum for that key | `TooLong` |
| `bytesN` | exactly N | `Width` |
| `u8`, `u32`, `u64` | exactly 1, 4, 8 bytes | `Width` |
| Writer output | 0..=the capacity given | `TooLong` |

The 4-byte length is wide enough for the largest value any record carries: a sealed blob of 64 673 bytes inside the `outbox` of `state.bin`. The real bound is always the smaller of the buffer and the caller's maximum.

**Test schema.** The tests, the vectors and the fuzz target `record_decode` of spec 016-fuzz-harness decode by one fixed schema that uses every type this spec implements, compiled under `cfg(any(test, fuzzing))` so that both reach it, and so that no path of the codec depends on a later spec to be exercised: 0 `u8` mandatory; 1 `u32`; 2 `u64`; 3 `bytes` (max 64); 4 `bytes32`; 5 `text` (max 64). Every key but 0 is optional, and the whole record is at most 512 bytes. The test schema is written like production code — no `unwrap`, `get` instead of indexing, checked arithmetic — because it also compiles under `cfg(fuzzing)`, where the test relaxations of AGENTS 4 do not apply.

## Interface

```
crates/core/src/proto/record.rs          Writer, Reader, RecordError
crates/core/src/proto/record/tests.rs    s017_* tests
crates/core/src/proto/record/test_schema.rs  the test schema, declared cfg(any(test, fuzzing)); spec 016 adds decode_test_record there
crates/core/fuzz/fuzz_targets/record_decode.rs   spec 016-fuzz-harness
```

```rust
pub(crate) enum RecordError { Truncated, KeyOrder, Width, Utf8, Missing, UnknownKey, TooLong }
pub(crate) enum UnknownKeys { Ignore, Reject }

pub(crate) struct Writer { /* Zeroizing<Vec<u8>> of fixed capacity, last key */ }
impl Writer {
    pub(crate) fn with_capacity(max: usize) -> Writer;
    pub(crate) fn u8(&mut self, key: u8, value: u8) -> Result<(), RecordError>;
    pub(crate) fn u32(&mut self, key: u8, value: u32) -> Result<(), RecordError>;
    pub(crate) fn u64(&mut self, key: u8, value: u64) -> Result<(), RecordError>;
    pub(crate) fn bytes(&mut self, key: u8, value: &[u8]) -> Result<(), RecordError>;
    pub(crate) fn text(&mut self, key: u8, value: &str) -> Result<(), RecordError>;
    pub(crate) fn finish(self) -> Zeroizing<Vec<u8>>;
}

#[must_use]
pub(crate) struct Reader<'a> { /* the buffer, the position, the last key, the policy */ }
impl<'a> Reader<'a> {
    pub(crate) fn new(buf: &'a [u8], max_len: usize, unknown: UnknownKeys) -> Result<Reader<'a>, RecordError>;
    pub(crate) fn u8(&mut self, key: u8) -> Result<Option<u8>, RecordError>;
    pub(crate) fn u32(&mut self, key: u8) -> Result<Option<u32>, RecordError>;
    pub(crate) fn u64(&mut self, key: u8) -> Result<Option<u64>, RecordError>;
    pub(crate) fn bytes(&mut self, key: u8, max: usize) -> Result<Option<&'a [u8]>, RecordError>;
    pub(crate) fn bytes_n<const N: usize>(&mut self, key: u8) -> Result<Option<&'a [u8; N]>, RecordError>;
    pub(crate) fn text(&mut self, key: u8, max: usize) -> Result<Option<&'a str>, RecordError>;
    pub(crate) fn end(self) -> Result<(), RecordError>;
}
```

Keys are read in increasing order. Each getter returns `None` when the key is absent, and the caller turns a `None` for a mandatory key into `RecordError::Missing`. Every getter borrows from the input buffer, so decoding copies nothing: a secret is copied once, by its owner, straight into its `Secret<N>` with `Secret::copy_from` (spec 011-config-format R19). `Reader` carries `#[must_use]`, so a reader that is built and never read or ended is a compiler warning, which the CI turns into an error.

A schema decoder reads its keys in order and may check a value as soon as it is read, before the next key: spec 011-config-format R3 checks the versions after key 1 and spec 013-wire-message R12 checks staleness after key 2, each with the same `Reader` that then reads the rest and calls `end()`.

`s017_vectors_dispatch` calls `vectors::check_all("017", …)` with one entry per vector and is the only code that loads `017.json` (spec 015-test-vectors R3).

`[workspace.lints.rust]` of the root `Cargo.toml` declares `unexpected_cfgs = { level = "warn", check-cfg = ['cfg(fuzzing)'] }`, because this spec is the first to write `cfg(fuzzing)` (the test schema) and the CI builds with `-D warnings`, which fails on an undeclared cfg; spec 016-fuzz-harness relies on it. The compiler enforces it; it is not a requirement.

## Security

- This is the first code that touches most bytes an attacker controls: a decrypted payload, a scanned config, a frame from the server, a file read back from disk. R2 and R12 are the requirements that matter most, and the fuzz target of spec 016-fuzz-harness exists for them.
- One canonical encoding (R2, R3, R5, R10) closes the equivocation that a lax format allows, and no record can hide extra bytes. Under `Ignore` a record can carry a key an older client skips; `docs/spec.md` §4 keeps that from changing what a signed message means to that client.
- A declared length is never trusted before it is compared with the bytes actually present (R2). A 4-byte length of 4 GiB costs the decoder nothing.
- Nothing recurses on input (R9): a value is never a record and nothing nests.
- The writer never grows (R11) because the config record carries `K_ch` and the state record carries `sk_u`: a `Vec` that reallocates frees its old copy without wiping it.
- `store` and `server` never call the codec directly; each `pub` function of `core` that 020 or 028 adds to reach it has its own fuzz target (AGENTS 21).

## Public API changes

None. The codec is `pub(crate)`.

## Test cases

- T01 (covers R1): `s017_t01_r01_field_framing`: the vector `u8_field` encodes and decodes to the exact bytes, and `empty_record` is zero bytes and decodes to `Missing`.
- T02 (covers R2): `s017_t02_r02_field_check_order`: a key lower than the previous one and a repeated key → `KeyOrder`; a field that is both out of order and truncated → `Truncated`; an unknown key out of order → `KeyOrder` under both policies.
- T03 (covers R3): `s017_t03_r03_integer_widths`: a `u32` of 3 and 5 bytes and a `u64` of 7 bytes → `Width`; the maxima of each type round-trip.
- T04 (covers R4): `s017_t04_r04_bytes_and_text_limits`: `bytes32` of 31 and 33 bytes → `Width`; `bytes` and `text` of the maximum accepted and of the maximum plus one → `TooLong`; `text` with the byte 0xff → `Utf8`.
- T05 (covers R5): `s017_t05_r05_end_walks_the_rest`: a valid record plus one byte → `Truncated`; a valid record plus one unknown field → `UnknownKey` under `Reject` and accepted under `Ignore`.
- T06 (covers R6): `s017_t06_r06_missing_and_optional`: an absent optional key gives `None`; an absent key 0 of the test schema → `Missing`.
- T07 (covers R7): `s017_t07_r07_unknown_key_policy`: the same record with an extra key is accepted under `Ignore` and returns `UnknownKey` under `Reject`, whether the extra key is read past or reached by `end()`.
- T08 (covers R8): `s017_t08_r08_whole_record_limit`: a record of 513 bytes against a maximum of 512 → `TooLong` before any field is read; 512 accepted.
- T09 (covers R9): `s017_t09_r09_test_schema_is_typed`: the test schema decodes into its own struct with one field per key; a key 3 whose value happens to be shaped like a record comes back as those bytes, not as a deeper decode.
- T10 (covers R10): `s017_t10_r10_round_trip` proptest over records of the test schema: decode(encode(x)) = x, and encode(decode(b)) = b for every b accepted under `Reject`.
- T11 (covers R11): `s017_t11_r11_writer_never_grows`: `finish` returns `Zeroizing<Vec<u8>>` whose capacity equals the one given; a write past it → `TooLong`; a key not greater than the previous → `KeyOrder`.
- T12 (covers R12): `s017_t12_r12_arbitrary_bytes_never_panic` proptest over arbitrary buffers of up to 4 096 bytes decoded by the test schema under both policies: every call returns `Ok` or a `RecordError`.
- T13 (covers R13): the section is the function `check_s017_t13_r13_section_produces_017_json` of `scripts/reference/vectors.py`; the CI step of spec 015-test-vectors R6 runs the script and fails when its output differs from the committed `017.json`.

## Vectors

`specs/vectors/017.json`, schema of `specs/vectors/README.md`, `proto_version = 1`, produced by the reference script of spec 015-test-vectors (R13). Every vector is `derived`: it follows from R1 to R8 and can be checked by hand. Every vector carries the inputs `schema` (always `"test"`, the test schema above) and `policy` (`"reject"` or `"ignore"`), so that a reader in any language knows how to decode it.

| name | kind | source | origin |
| --- | --- | --- | --- |
| `empty_record` | negative | derived | zero bytes: key 0 is missing → `Missing` |
| `u8_field` | positive | derived | key 0 alone |
| `u32_field`, `u64_field` | positive | derived | key 0 plus one field of each type, at its maximum |
| `bytes_field`, `bytes32_field`, `text_field` | positive | derived | key 0 plus one field of each byte type |
| `unknown_key_ignored` | positive | derived | an extra key 9 under `ignore`, accepted |
| `key_out_of_order`, `duplicate_key` | negative | derived | → `KeyOrder` |
| `u32_wrong_width`, `bytes32_wrong_width` | negative | derived | → `Width` |
| `bytes_too_long`, `text_too_long`, `record_too_long` | negative | derived | a `bytes` of 65 bytes; a `text` of 65 bytes; a record of 513 bytes → `TooLong` |
| `truncated_length`, `length_beyond_buffer`, `extra_byte` | negative | derived | → `Truncated` |
| `invalid_utf8` | negative | derived | → `Utf8` |
| `unknown_key_rejected` | negative | derived | an extra key 9 under `reject` → `UnknownKey` |

## Acceptance criterion

`cargo test -p privatechat-core s017_` green; clippy, `cargo deny` and the documentation lint green; the reference script of spec 015-test-vectors produces `017.json` and its CI step finds no difference. Fuzzing `record_decode` belongs to spec 016-fuzz-harness and to the phase 1 exit. Non-automatable criterion: a second person reads R1 to R8 against `docs/spec.md` §4 "Record encoding" and confirms that the vectors can be written by hand from them.

## Out of scope

- The schema of each record and the error each failure maps to (specs 011-config-format, 013-wire-message, 020-store-files, 030-ws-protocol).
- The `pub` functions through which `store` and `server` reach records (specs 020-store-files, 030-ws-protocol).
- The envelope, which is a fixed layout and not a record (spec 013-wire-message).
- `bool`, nested records and `list<T>`, which `docs/spec.md` §4 defines and no phase 1 record uses: specs 020-store-files and 030-ws-protocol add a type the day their first schema needs it, with its vectors and its fuzz coverage.
- Any self-describing mode, generic value, or tool that prints records without their schema.

## Open questions

None. Decided in audit F (`docs/audit-log.md`):

- 017-R1: the length is 4 bytes for every field. It costs about 10 bytes per payload, which padding to 1 024 bytes absorbs, and about 22 characters in the config QR, and it buys one rule for every record.

## History

- 2026-09-24 in review
- 2026-09-24 revised after audit F (docs/audit-log.md)
- 2026-09-24 documentation review (audit G, `docs/audit-log.md`): the test schema compiled under `cfg(any(test, fuzzing))` for the fuzz target of spec 016
- 2026-09-24 revised after audit H (`docs/audit-log.md`): PR slices and the `dead_code` allow; the test schema in its own file; partial reads defined once (R16); negative vectors for `text` and lists; the vector test only dispatches; round 4: the `check-cfg` entry for `cfg(fuzzing)` (R17); round 6 and 7: `decode_test_record` belongs to spec 016, which depends on `core::Error`; round 9: `unknown_key_ignored` excluded from the script by name
- 2026-09-24 revised after audit I (`docs/audit-log.md`): only the six types phase 1 decodes (`bool`, nested records and `list<T>` leave with their vectors; 020 and 030 add them when needed); no partial-read mode (the in-order reader checks a value as soon as it is read); the reference script of spec 015 produces `017.json` and the Rust tests reproduce it; `#[must_use]` stated in the Interface; the dispatch test is an Interface sentence; the test schema written like production code; requirements and tests renumbered
