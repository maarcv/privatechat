# 013 — Wire message: envelope, payload and verification

Status: in review
Phase: 1
Related ADRs: 0002, 0005, 0013, 0015, 0016, 0018, 0019
Depends on: 010-primitives-wrapper, 011-config-format, 012-message-keys
Blocks: 014-fingerprint, 015-test-vectors, 016-fuzz-harness, 021-channel-session, 030-ws-protocol
Human reviewer: Marc Vilardebó · Accepted on: —

## Context

This is the format the server stores and every client parses, and the one thing in the project that can never change without a new `proto_version` and an ADR (AGENTS 3). `docs/spec.md` §4 fixes it: a binary envelope of fixed offsets with CBOR only inside the encrypted payload (ADR 0015), a header encrypted under the channel key (ADR 0018), encrypt-then-sign with the sender's Ed25519 key (ADR 0005), and a verification on receive whose order is normative because each step has its own error and the negative vectors tell them apart.

This spec turns that into requirements, the exact byte offsets, the payload grammar and the mutation table. Everything it encrypts and derives comes from specs 010-primitives-wrapper and 012-message-keys; where the result is stored, and in which single commit, is spec 021-channel-session.

## Requirements

- R1 A blob MUST be exactly `proto_version` uint8 at offset 0, `channel_id` 16 bytes at 1, `enc_hdr` 40 bytes at 17, `nonce` 24 bytes at 57, `ciphertext` of `n` bytes at 81, and `signature` 64 bytes at 81 + `n` (`docs/spec.md` §4).
- R2 `proto_version` MUST be 0x01, `n` MUST be 16 + 1024·k with k within 1..=63, and the blob length MUST therefore be 161 + 1024·k, within 1185..=64673 with `(len − 161)` a multiple of 1024.
- R3 The associated data of the AEAD MUST be exactly `blob[0..81]`, the encrypted header included, as it travels.
- R4 The signature MUST be `sign_detached(sk_u, "privatechat/msg/v1" ‖ blob[0..81 + n])`, so it covers the encrypted header and the ciphertext and is verified before anything is decrypted.
- R5 The nonce MUST be 24 bytes from `random_bytes`, drawn once per message, and MUST be the same nonce the header transformation of spec 012-message-keys uses.
- R6 The plaintext payload MUST be a CBOR map with integer keys: 0 `type` uint, mandatory, 0 for `text` and 1 for `key_retired`; 1 `display_name` text of at most 64 bytes of UTF-8 with no character of the Unicode categories Cc and Cf; 2 `sent_at` uint64; 3 `body` bytes.
- R7 `Payload::validate` MUST be the only validation function, MUST be called by both the encrypt and the decrypt path, and MUST return `Error::BadPayload` for a duplicate key, a missing `type`, a value of the wrong CBOR major type, a limit exceeded, a `display_name` present in a `key_retired`, a `body` that is not valid UTF-8 in a `text`, or a `body` that is not empty in a `key_retired`.
- R8 `sent_at` MUST be unix milliseconds rounded down to the minute, and a value that is not a multiple of 60_000 MUST return `Error::BadPayload`.
- R9 A CBOR key the decoder does not know MUST be ignored, so that a later version can add fields without changing `proto_version`; decoding MUST go into a `struct` with `serde` and `recursion_limit = 8`, never into a generic CBOR value.
- R10 The payload MUST be at most 64_511 bytes before padding, and MUST be padded with `pad` to a multiple of 1024 bytes, which makes the padded payload 1024·k with k within 1..=63.
- R11 The payload MUST NOT be compressed, in this version or any other (AGENTS 24).
- R12 Verification on receive MUST run in the order of `docs/spec.md` §4, each condition returning its own error: length, version and channel (`BadLength`, `UnsupportedVersion`, `WrongChannel`), then expiry (`Expired`), then the header is opened, then the retired key and the peer limit (`RetiredKey`, `PeerLimit`), then the counter (`Replay`), then the signature (`BadSignature`), then the AEAD, the unpadding and the payload (`BadSignature`, `BadPadding`, `BadPayload`).
- R13 A blob that fails any check before the AEAD succeeds MUST write nothing to the `Store` except the cursor of `docs/spec.md` §6, and MUST return no data to the caller.
- R14 Once the AEAD has succeeded the message MUST be consumed: the anti-replay state advances, and a failure of unpadding, of CBOR or of `validate` MUST persist the message as `Unreadable`, with no body, instead of discarding it.
- R15 A `key_retired` MUST be signed with the key it retires; one from a public key with no local peer MUST be consumed and discarded without creating a peer (ADR 0016).
- R16 `encrypt` MUST reserve the counter, derive `mk`, seal, and persist the counter and the blob in the outbox in a single commit before returning the blob; if the commit fails it MUST return no blob (`docs/spec.md` §4).
- R17 No error of this spec MUST reach the network or the sender: the variants are local, and the core MUST emit no byte that depends on the result of `decrypt` (`docs/spec.md` §4 "No-oracle rule").
- R18 `mk` MUST be zeroized after the message is sealed or opened, and the decrypted payload MUST NOT be logged, formatted into an error or retained outside the value returned to the caller.

## Limits

| Input | Range | Out of range |
| --- | --- | --- |
| Blob | 1185..=64673 B, `(len − 161) mod 1024 = 0` | `BadLength` |
| `proto_version` | 1 | `UnsupportedVersion` |
| `channel_id` | the channel's own 16 bytes | `WrongChannel` |
| `ciphertext` | 16 + 1024·k, k 1..=63 | `BadLength` |
| Payload before padding | 0..=64 511 B | `BadPayload` |
| Padded payload | 1024·k, k 1..=63 | `BadPadding` |
| `display_name` | 0..=64 B UTF-8, no Cc, no Cf | `BadPayload` |
| `body` of a `text` | valid UTF-8, within the payload limit | `BadPayload` |
| `body` of a `key_retired` | empty | `BadPayload` |
| `sent_at` | multiple of 60 000 | `BadPayload` |
| `type` | 0 or 1 | consumed as `Unreadable` |

An unknown `type` is not out of range: it is a message from a future version, and R14 keeps it.

## Interface

```
crates/core/src/proto/envelope.rs      the fixed offsets, sealing and parsing
crates/core/src/proto/payload.rs       Payload, its CBOR and validate()
crates/core/src/proto/tests.rs         s013_* tests, with the mutation table
crates/core/fuzz/fuzz_targets/         decrypt, payload_parse (spec 016-fuzz-harness)
```

```rust
pub(crate) const VERSION: u8 = 1;
pub(crate) const HEADER_END: usize = 81;
pub(crate) const PAD_BLOCK: usize = 1024;
pub(crate) const MAX_BLOCKS: usize = 63;
pub(crate) const BLOB_OVERHEAD: usize = 161;
pub(crate) const TAG: &[u8] = b"privatechat/msg/v1";

pub struct Payload { pub kind: PayloadKind, pub display_name: Option<String>, pub sent_at: u64, pub body: Vec<u8> }
pub enum PayloadKind { Text, KeyRetired, Unknown(u64) }

pub(crate) struct Envelope<'a> { pub(crate) enc_hdr: &'a [u8; 40], pub(crate) nonce: Nonce, pub(crate) ciphertext: &'a [u8], pub(crate) signature: Signature }

impl<'a> Envelope<'a> {
    /// Checks length, version and channel before it borrows anything (R12).
    pub(crate) fn parse(blob: &'a [u8], channel_id: &[u8; 16]) -> Result<Envelope<'a>, Error>;
}

impl Payload {
    pub(crate) fn validate(&self) -> Result<(), Error>;
    pub(crate) fn encode(&self) -> Result<Vec<u8>, Error>;
    pub(crate) fn decode(bytes: &[u8]) -> Result<Payload, Error>;
}
```

`Envelope` borrows the blob: it is a view over bytes the caller owns, so parsing copies nothing and no partially parsed envelope can outlive its buffer.

## Security

- The order of R12 is a security property, not a convenience: the signature is checked before the AEAD so that a forged blob never reaches the decryption path, and the length before everything so that no offset is ever computed on a buffer too short to hold it.
- Encrypt-then-sign with the sender's key means the server, which holds no key, can verify nothing about a blob's content, and a member who did not write a message cannot produce one that verifies.
- `AAD = blob[0..81]` binds version, channel, encrypted header and nonce to the ciphertext: moving a valid ciphertext to another channel, or replaying it under another header, breaks the tag.
- Every rejection path is silent (R17). The variants exist for the local user interface and for the negative vectors; exposing them to a sender would turn every client into a decryption oracle.
- The payload is never compressed (R11): compressing before encrypting would leak content through the ciphertext length, which is the one thing padding to 1024 bytes exists to hide.
- Secrets: `mk` for the life of one call (R18). The decrypted payload is not a secret of `core`, but it is content: it never reaches a log or an error message (AGENTS 19).

## Public API changes

`Payload`, `PayloadKind` and `Received` become part of the core boundary, as `docs/spec.md` §9 lists them. `Channel::encrypt` and `Channel::decrypt` keep the signatures of §9; spec 027-core-api confirms them and spec 040-uniffi exports them.

## Test cases

- T01 (covers R1, R2): `s013_t01_r01_envelope_offsets` on the reference vector: each field is at the offset the table fixes; `s013_t02_r02_rejects_bad_length` over the table 1184, 1186, 64674, 1185 + 1 and a blob whose `(len − 161)` is not a multiple of 1024 → `BadLength`, each with `commits = 0`.
- T03 (covers R2): `s013_t03_r02_rejects_other_versions`: `blob[0]` of 0x00 and 0x02 → `UnsupportedVersion`.
- T04 (covers R2): `s013_t04_r02_rejects_another_channel`: a `channel_id` of one byte apart → `WrongChannel`.
- T05 (covers R3, R4): `s013_t05_r04_signature_known_answer` on the vector; `s013_t06_r04_signature_covers_everything`: a mutation in any byte of `blob[0..81 + n]` → `BadSignature`.
- T07 (covers R5): `s013_t07_r05_nonce_is_fresh`: two encryptions of the same payload give different nonces and different ciphertexts.
- T08 (covers R6, R7): `s013_t08_r07_payload_validate_table`: a duplicate key, a missing `type`, a `display_name` of 65 bytes, one with U+0009, a `display_name` in a `key_retired`, a `body` that is not UTF-8 in a `text` and a non-empty `body` in a `key_retired` → `BadPayload`.
- T09 (covers R8): `s013_t09_r08_sent_at_is_a_whole_minute`: 60_001 → `BadPayload`; 60_000 and 0 accepted.
- T10 (covers R9): `s013_t10_r09_unknown_keys_are_ignored`: a payload with key 9 decodes and validates.
- T11 (covers R10, R11): `s013_t11_r10_padding_sizes`: payloads of 0, 1, 1023, 64_511 bytes give k of 1, 1, 1 and 63 and blobs of the exact length; 64_512 → `BadPayload`; `s013_t12_r11_no_compression_crate`: the dependency graph carries none of the crates `deny.toml` bans for compression.
- T13 (covers R12): `s013_t13_r12_check_order`: a blob that fails several conditions at once returns the first error of the order, as a table with one case per pair of conditions.
- T14 (covers R13): `s013_t14_r13_rejection_writes_only_the_cursor`: for every rejection above, the `Store` receives one commit carrying the cursor and nothing else.
- T15 (covers R14): `s013_t15_r14_authenticated_is_consumed`: an authentic blob with broken padding, with broken CBOR and with an unknown `type` persists as `Unreadable` and advances `max_counter`.
- T16 (covers R15): `s013_t16_r15_key_retired_from_an_unknown_key`: it is consumed, creates no peer and raises no event.
- T17 (covers R16): `s013_t17_r16_encrypt_commits_before_returning`: with a `FailingStore` that fails at the commit, `encrypt` returns an error, no blob and no advanced counter.
- T18 (covers R17): `s013_t18_r17_no_byte_depends_on_the_verdict`: over the whole rejection table, the bytes the core hands the transport are identical.
- T19 (covers R18): `s013_t19_r18_message_key_is_zeroized_and_nothing_is_logged`: after `decrypt`, the buffer that held `mk` is zero and the tracing subscriber of spec 100-log-test captured no body.
- T20 (covers R1, R12): `s013_t20_r12_mutation_table`: the table below, one flipped byte per region, each expecting its own error and `commits = 0` except the cursor.

## Vectors

`specs/vectors/013.json`, schema of `specs/vectors/README.md`, `proto_version = 1`. Produced by the core and frozen from then on; regenerating them needs a `proto_version` change and an ADR (AGENTS 18).

| name | kind | source | origin |
| --- | --- | --- | --- |
| `text_k1` | positive | derived | a `text` payload padded to one block, with its `mk`, nonce and blob |
| `text_k63` | positive | derived | the largest payload, 64 511 bytes |
| `key_retired` | positive | derived | a `key_retired` of a known key |
| `unknown_type` | positive | derived | `type = 9`, authenticated, kept as `Unreadable` |
| `mutate_version` | negative | derived | `blob[0] = 0x02` → `UnsupportedVersion` |
| `mutate_channel_id` | negative | derived | one byte of `blob[1..17]` → `WrongChannel` |
| `mutate_enc_hdr` | negative | derived | one byte of `blob[17..57]` → `BadSignature` |
| `mutate_nonce` | negative | derived | one byte of `blob[57..81]` → `BadSignature` |
| `mutate_ciphertext` | negative | derived | one byte of `blob[81..81 + n]` → `BadSignature` |
| `mutate_signature` | negative | derived | one byte of the last 64 → `BadSignature` |
| `short_blob`, `long_blob`, `unaligned_blob` | negative | derived | 1184, 64 674 and 1186 bytes → `BadLength` |
| `replayed_counter` | negative | derived | a valid blob at a counter already seen → `Replay` |
| `bad_padding` | negative | derived | an authentic blob whose padding has no marker → `Unreadable` |
| `bad_payload_cbor` | negative | derived | an authentic blob whose CBOR is broken → `Unreadable` |

**Mutation table** (normative, `docs/spec.md` §4 and the template): every region of the envelope, the error a single flipped byte must produce, and the writes it may leave.

| Region | Bytes | Error | Store |
| --- | --- | --- | --- |
| `proto_version` | 0 | `UnsupportedVersion` | cursor only |
| `channel_id` | 1..17 | `WrongChannel` | cursor only |
| `enc_hdr` | 17..57 | `BadSignature` | cursor only |
| `nonce` | 57..81 | `BadSignature` | cursor only |
| `ciphertext` | 81..81 + n | `BadSignature` | cursor only |
| `signature` | last 64 | `BadSignature` | cursor only |
| Length | any | `BadLength` | cursor only |

A mutated `enc_hdr` fails at the signature and not at the header, because the header has no integrity of its own by design (spec 012-message-keys, R5).

## Acceptance criterion

`cargo test -p privatechat-core s013_` green, the mutation table included; `cargo fuzz` targets `decrypt` and `payload_parse` run for one hour without a crash (spec 016-fuzz-harness); clippy, `cargo deny` and the documentation lint green. Non-automatable criterion: a second person reads the offsets of R1 and the order of R12 against `docs/spec.md` §4 and confirms them byte for byte, which is the internal review of `proto` the phase 1 exit criterion asks for.

## Out of scope

- The keys and the header transformation, which are spec 012-message-keys, and the fingerprint, which is spec 014-fingerprint.
- The `Store`, the peers, the TTL and the cursor: this spec says what must be committed and in how many commits, not how (specs 020-store-files, 021-channel-session, 022-peers-tofu, 023-ttl-purge).
- The server's own blob validation, which repeats the length and prefix checks without any key (spec 030-ws-protocol).
- Message quoting, attachments and any field of v1.x or v2 (`docs/spec.md` §12).

## Open questions

- [ ] 013-R8: rejecting a `sent_at` that is not a whole minute makes the rule checkable, but it turns a sloppy sender into an unreadable message for everyone. The alternative is to round it down on receive and accept anything. `docs/spec.md` §4 says the field is rounded, without saying who enforces it; this spec chose the sender. Confirm.
- [ ] 013-R12: the step order puts `RetiredKey` and `PeerLimit` before the signature, so a blob is rejected on the strength of a header that nothing has authenticated yet. It costs nothing and leaks nothing locally, but it means a corrupt header can produce `RetiredKey` instead of `BadSignature`. `docs/spec.md` §4 fixes this order; confirm it is deliberate.
- [ ] 013-R14: `Unreadable` messages occupy a slot in the log and count against the 64 MiB of the channel. Whether they expire by the same TTL as the rest is spec 023-ttl-purge; note it there.

## History

- 2026-09-21 in review
