# 017 — Record encoding

Status: in review
Phase: 1
Related ADRs: 0015, 0021, 0023
Depends on: 010-primitives-wrapper, 015-test-vectors
Blocks: 011-config-format, 013-wire-message, 016-fuzz-harness, 020-store-files, 030-ws-protocol
Human reviewer: Marc Vilardebó · Accepted on: —

## Context

Apart from the envelope, every structure the project writes is a small record with a known schema: the payload, the config, the client-server messages and the local files (`docs/spec.md` §4 "Record encoding"). ADR 0023 replaced CBOR with one encoding of our own, so that `core` needs no third-party parser and every value has exactly one encoding.

In plain words: a record is a list of fields, and each field is a number that says which field it is, a length, and the bytes of the value. The fields always come in increasing order of their number, and each number has a fixed type that the schema of the record decides. The decoder reads only what the schema expects and rejects anything else, so two implementations can never read one record in two different ways.

This spec fixes the codec. Which keys each record has, and which error a failure becomes, belong to the spec that owns the record (011-config-format, 013-wire-message, 020-store-files, 030-ws-protocol).

## Requirements

- R1 A record MUST be a sequence of zero or more fields, and a field MUST be `key` (1 byte) ‖ `len` (4 bytes, big-endian unsigned) ‖ `value` (`len` bytes), with nothing between fields.
- R2 Within one record the keys MUST be strictly increasing; the decoder MUST return `RecordError::KeyOrder` for a key equal to or lower than the previous one, which covers duplicates.
- R3 An integer value MUST be exactly 1 byte for `u8`, 4 for `u32` and 8 for `u64`, big-endian, and a `bool` MUST be exactly 1 byte of 0x00 or 0x01; any other length or byte MUST return `RecordError::Width`.
- R4 A `bytesN` value MUST be exactly `N` bytes (else `RecordError::Width`), a `bytes` value any length up to the maximum the caller gives for that key (else `RecordError::TooLong`), and a `text` value valid UTF-8 up to the caller's maximum (else `RecordError::Utf8` or `RecordError::TooLong`).
- R5 A nested record MUST be the value of a field, decoded by the schema the caller names, and MUST end exactly at the end of that value.
- R6 A `list<T>` value MUST be a sequence of items, each `len` (4 bytes, big-endian) ‖ item, ending exactly at the end of the value; the caller gives the maximum number of items, and one more MUST return `RecordError::TooLong`.
- R7 A record MUST end exactly at the end of its buffer: `Reader::end` MUST return `RecordError::Trailing` if any byte is left, and every value MUST be consumed whole.
- R8 A mandatory key that is absent MUST return `RecordError::Missing`; an optional key MUST be either present with a valid value or absent, and no value means "null".
- R9 A reader MUST be built with a policy: under `UnknownKeys::Ignore` a key the schema does not name MUST be skipped, and under `UnknownKeys::Reject` it MUST return `RecordError::UnknownKey`; a skipped field MUST still obey R1, R2 and R7.
- R10 A declared `len` larger than the bytes left in the enclosing buffer MUST return `RecordError::Truncated` before anything is allocated or copied, and a buffer that ends inside a `key` or a `len` MUST return `RecordError::Truncated`.
- R11 Decoding MUST be typed, one decoder per schema, and MUST NOT build a generic tree of values; a schema MUST NOT refer to itself, so the depth of nesting is fixed by the schemas and no decoder recurses on input.
- R12 The writer MUST produce the canonical encoding: keys in increasing order, each integer at its exact width, and no field for an absent optional key; decoding what the writer produced MUST give back the same values, and encoding what the decoder accepted MUST give back the same bytes.
- R13 The writer MUST hold its buffer in `zeroize::Zeroizing<Vec<u8>>`, so that a record carrying a secret is wiped when the buffer is dropped.
- R14 The codec MUST NOT panic, overflow or read out of bounds on any input: every offset and length uses `checked_*` arithmetic and every failure is a `RecordError`.
- R15 The codec MUST add no dependency to `core` and MUST live in `crates/core/src/proto/record.rs`, which is the only place in the workspace that frames records.

## Limits

| Input | Range | Out of range |
| --- | --- | --- |
| `key` | 0..=255, strictly increasing | `KeyOrder` |
| `len` of a field | 0..=bytes left in the enclosing buffer | `Truncated` |
| `bytes`, `text` | 0..=the caller's maximum for that key | `TooLong` |
| `bytesN` | exactly N | `Width` |
| `u8`, `u32`, `u64`, `bool` | exactly 1, 4, 8, 1 bytes | `Width` |
| `bool` byte | 0x00 or 0x01 | `Width` |
| Items of a list | 0..=the caller's maximum | `TooLong` |
| Whole record | 0..=the caller's maximum | `TooLong` |

The 4-byte length is wide enough for the largest value any record carries: a sealed blob of 64 673 bytes inside the `outbox` of `state.bin`. The real bound is always the smaller of the buffer and the caller's maximum.

## Interface

```
crates/core/src/proto/record.rs          Writer, Reader, RecordError
crates/core/src/proto/record/tests.rs    s017_* tests
crates/core/fuzz/fuzz_targets/record_decode.rs   spec 016-fuzz-harness
```

```rust
pub(crate) enum RecordError { Truncated, KeyOrder, Width, Utf8, Missing, UnknownKey, Trailing, TooLong }
pub(crate) enum UnknownKeys { Ignore, Reject }

pub(crate) struct Writer { /* Zeroizing<Vec<u8>>, last key */ }
impl Writer {
    pub(crate) fn new() -> Writer;
    pub(crate) fn u8(&mut self, key: u8, value: u8) -> Result<(), RecordError>;
    pub(crate) fn u32(&mut self, key: u8, value: u32) -> Result<(), RecordError>;
    pub(crate) fn u64(&mut self, key: u8, value: u64) -> Result<(), RecordError>;
    pub(crate) fn bool(&mut self, key: u8, value: bool) -> Result<(), RecordError>;
    pub(crate) fn bytes(&mut self, key: u8, value: &[u8]) -> Result<(), RecordError>;
    pub(crate) fn text(&mut self, key: u8, value: &str) -> Result<(), RecordError>;
    pub(crate) fn record(&mut self, key: u8, value: &Writer) -> Result<(), RecordError>;
    pub(crate) fn list(&mut self, key: u8, items: &[&[u8]]) -> Result<(), RecordError>;
    pub(crate) fn finish(self) -> Zeroizing<Vec<u8>>;
}

pub(crate) struct Reader<'a> { /* the buffer, the position, the last key, the policy */ }
impl<'a> Reader<'a> {
    pub(crate) fn new(buf: &'a [u8], max_len: usize, unknown: UnknownKeys) -> Result<Reader<'a>, RecordError>;
    pub(crate) fn u8(&mut self, key: u8) -> Result<Option<u8>, RecordError>;
    pub(crate) fn u32(&mut self, key: u8) -> Result<Option<u32>, RecordError>;
    pub(crate) fn u64(&mut self, key: u8) -> Result<Option<u64>, RecordError>;
    pub(crate) fn bool(&mut self, key: u8) -> Result<Option<bool>, RecordError>;
    pub(crate) fn bytes(&mut self, key: u8, max: usize) -> Result<Option<&'a [u8]>, RecordError>;
    pub(crate) fn bytes_n<const N: usize>(&mut self, key: u8) -> Result<Option<&'a [u8; N]>, RecordError>;
    pub(crate) fn text(&mut self, key: u8, max: usize) -> Result<Option<&'a str>, RecordError>;
    pub(crate) fn record(&mut self, key: u8, unknown: UnknownKeys) -> Result<Option<Reader<'a>>, RecordError>;
    pub(crate) fn list(&mut self, key: u8, max_items: usize) -> Result<Option<Items<'a>>, RecordError>;
    pub(crate) fn end(self) -> Result<(), RecordError>;
}
```

Keys are read in increasing order. Each getter returns `None` when the key is absent, and the caller turns a `None` for a mandatory key into `RecordError::Missing`. Every getter borrows from the input buffer, so decoding copies nothing: a secret is copied once, by its owner, straight into its `Secret<N>`.

## Security

- This is the first code that touches most bytes an attacker controls: a decrypted payload, a scanned config, a frame from the server, a file read back from disk. R10 and R14 are the requirements that matter most, and the fuzz target of spec 016-fuzz-harness exists for them.
- One canonical encoding (R2, R3, R7, R12) closes the equivocation that a lax format allows: a member cannot sign one blob that two versions of the client read as two different messages, and no record can hide extra bytes.
- A declared length is never trusted before it is compared with the bytes actually present (R10). A 4-byte length of 4 GiB costs the decoder nothing.
- Nothing recurses on input (R11): the depth is the depth of the schemas, which are fixed in code.
- The writer wipes its buffer (R13) because the config record carries `K_ch` and the state record carries `sk_u`.

## Public API changes

None. The codec is `pub(crate)`.

## Test cases

- T01 (covers R1): `s017_t01_r01_field_framing`: the vectors `u8_field` and `empty_record` encode and decode to the exact bytes.
- T02 (covers R2): `s017_t02_r02_rejects_keys_out_of_order`: a key lower than the previous one and a repeated key → `KeyOrder`.
- T03 (covers R3): `s017_t03_r03_integer_widths`: a `u32` of 3 and 5 bytes, a `u64` of 7 bytes and a `bool` of 0x02 → `Width`; the maxima of each type round-trip.
- T04 (covers R4): `s017_t04_r04_bytes_and_text_limits`: `bytesN` of N − 1 and N + 1 → `Width`; `bytes` and `text` of the maximum accepted and of the maximum plus one → `TooLong`; `text` with the byte 0xff → `Utf8`.
- T05 (covers R5): `s017_t05_r05_nested_record_ends_exactly`: a nested record with one trailing byte inside its value → `Trailing`.
- T06 (covers R6): `s017_t06_r06_list_items`: a list of the maximum count accepted, one more → `TooLong`, an item whose length overruns the value → `Truncated`.
- T07 (covers R7): `s017_t07_r07_rejects_trailing_bytes`: a valid record plus one byte → `Trailing`.
- T08 (covers R8): `s017_t08_r08_missing_and_optional`: an absent optional key gives `None`; an absent mandatory key → `Missing`.
- T09 (covers R9): `s017_t09_r09_unknown_key_policy`: the same record with an extra key is accepted under `Ignore` and returns `UnknownKey` under `Reject`; an ignored key out of order still fails with `KeyOrder`.
- T10 (covers R10): `s017_t10_r10_length_is_checked_before_use`: a `len` of 0xffffffff in a 10-byte buffer → `Truncated`, and a buffer cut inside a `len` → `Truncated`.
- T11 (covers R11): `s017_t11_r11_no_generic_value`: the module declares no enum of values and no function of the codec calls itself.
- T12 (covers R12): `s017_t12_r12_round_trip` proptest over records of every type with random keys in increasing order: decode(encode(x)) = x and encode(decode(b)) = b.
- T13 (covers R13): `s017_t13_r13_writer_buffer_is_zeroizing`: `Writer::finish` returns `Zeroizing<Vec<u8>>` (a type assertion).
- T14 (covers R14): `s017_t14_r14_arbitrary_bytes_never_panic` proptest over arbitrary buffers of up to 4 096 bytes: every call returns `Ok` or a `RecordError`.
- T15 (covers R15): `s017_t15_r15_no_new_dependency`: the manifest of `core` still declares exactly `libsodium-sys-stable` and `zeroize`.

## Vectors

`specs/vectors/017.json`, schema of `specs/vectors/README.md`, `proto_version = 1`. Every vector is `derived`: it follows from R1 to R10 and can be checked by hand.

| name | kind | source | origin |
| --- | --- | --- | --- |
| `empty_record` | positive | derived | zero fields, zero bytes |
| `u8_field`, `u32_field`, `u64_field`, `bool_field` | positive | derived | one field of each integer type, including the maximum |
| `bytes_field`, `bytes32_field`, `text_field` | positive | derived | one field of each byte type |
| `nested_record`, `list_field` | positive | derived | a record inside a field; a list of three items |
| `key_out_of_order`, `duplicate_key` | negative | derived | → `KeyOrder` |
| `wrong_width` | negative | derived | a `u32` of 3 bytes → `Width` |
| `truncated_length`, `length_beyond_buffer` | negative | derived | → `Truncated` |
| `trailing_byte`, `nested_trailing_byte` | negative | derived | → `Trailing` |
| `invalid_utf8` | negative | derived | → `Utf8` |
| `unknown_key_rejected` | negative | derived | under `Reject` → `UnknownKey` |

## Acceptance criterion

`cargo test -p privatechat-core s017_` green; the fuzz target `record_decode` runs for one hour without a crash (spec 016-fuzz-harness); clippy, `cargo deny` and the documentation lint green. Non-automatable criterion: a second person reads R1 to R10 against `docs/spec.md` §4 "Record encoding" and confirms that the vectors can be written by hand from them.

## Out of scope

- The schema of each record and the error each failure maps to (specs 011-config-format, 013-wire-message, 020-store-files, 030-ws-protocol).
- The envelope, which is a fixed layout and not a record (spec 013-wire-message).
- Any self-describing mode, generic value, or tool that prints records without their schema.

## Open questions

- [ ] 017-R1: the length is 4 bytes for every field, even where 2 would do. It costs 2 bytes per field, around 10 bytes per payload before padding, which padding to 1 024 bytes absorbs, and it buys one rule for every record. Confirm.

## History

- 2026-09-24 in review
