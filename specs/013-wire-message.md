# 013 — Wire message: envelope, payload and verification

Status: in review
Phase: 1
Related ADRs: 0002, 0005, 0013, 0016, 0018, 0019, 0023, 0024
Depends on: 010-primitives-wrapper, 011-config-format, 012-message-keys, 015-test-vectors, 017-record-encoding
Blocks: 014-fingerprint, 016-fuzz-harness, 021-channel-session, 030-ws-protocol
Human reviewer: Marc Vilardebó · Accepted on: —

## Context

This is the format the server stores and every client parses, and the one thing in the project that can never change without a new `proto_version` and an ADR (AGENTS 3). `docs/spec.md` §4 fixes it: a binary envelope of fixed offsets, a payload in the record encoding of §4 inside the encryption (ADR 0023), a header encrypted under the channel key (ADR 0018), encrypt-then-sign with the sender's Ed25519 key (ADR 0005), and a verification on receive whose order is normative because each step has its own error and the negative vectors tell them apart (ADR 0024).

Every literal of `docs/spec.md` §4 — parameters, domain tags, KDF contexts, offsets and the verification order — freezes when this spec is accepted; changing any of them afterwards needs a new `proto_version` and an ADR.

This spec is pure: it seals a message and verifies and opens a blob, with every input passed in and no state read or written. It covers steps 1–4 and 7 of the verification of §4. Steps 5 and 6 (retired key, peer limit, replay) and step 8 (the single commit) need the peers and the `Store`, so they belong to spec 021-channel-session, which calls `verify`, then its state checks, then `open`, in that order.

**In plain words.** A blob has a visible part and a hidden part. The server sees only the version, the channel it belongs to, the nonce and the size class; the sender and the message number are scrambled with the channel's header key, and the text is encrypted. The first 81 bytes are "associated data": bytes the encryption protects without hiding, so moving a valid ciphertext to another channel or under another header breaks it. The sender signs everything. On receive, the cheap checks come first (length, version, channel, expiry), then the header is unscrambled and the signature checked. Only once the signature has proved who wrote the blob does anything read the sender or the number, and only then is the text decrypted. A message the server kept past its lifetime is recognised by the signed send time inside it and discarded.

## Requirements

- R1 A blob MUST be exactly `proto_version` u8 at offset 0, `channel_id` 16 bytes at 1, `enc_hdr` 40 bytes at 17, `nonce` 24 bytes at 57, `ciphertext` of `n` bytes at 81, and `signature` 64 bytes at 81 + `n` (`docs/spec.md` §4).
- R2 `verify` MUST return `Error::BadLength` for a blob whose length is not 161 + 1024·k with k within 1..=63 (1185..=64673 with `(len − 161)` a multiple of 1024), then `Error::UnsupportedVersion` when `blob[0]` is not 0x01, then `Error::WrongChannel` when `blob[1..17]` is not the `channel_id` it receives.
- R3 The associated data of the AEAD MUST be exactly `blob[0..81]`, the encrypted header included, as it travels.
- R4 The signature MUST be `sign_detached(sk_u, "privatechat/msg/v1" ‖ blob[0..81 + n])`, covering the encrypted header and the ciphertext, and MUST be verified before any state check and before the AEAD is opened.
- R5 `seal` MUST take the 24-byte nonce as a parameter and MUST draw no randomness of its own, and the same nonce MUST be the one the header transformation of spec 012-message-keys uses; the caller (spec 021-channel-session) draws it once per message with `random_bytes`.
- R6 The payload MUST be a record of `docs/spec.md` §4 "Record encoding" with the schema: 0 `type` u8, mandatory, 0 for `text` and 1 for `key_retired`; 1 `display_name` text, optional; 2 `sent_at` u64, mandatory; 3 `body` bytes, mandatory. Unknown keys MUST be ignored, and decoding MUST go through the typed reader of spec 017-record-encoding with the `Ignore` policy, never into a generic tree.
- R7 `Payload::validate` MUST be the only validation function, MUST be called by both `seal` and `open`, and MUST return `Error::BadPayload` for a `PayloadKind::Unknown`, a `sent_at` that is not a multiple of 60 000, a `body` that is not valid UTF-8 in a `text`, a `body` that is not empty in a `key_retired`, a `display_name` in a `key_retired`, a `display_name` longer than 64 bytes or containing a character of the Unicode category Cc, and a payload whose encoding exceeds 64 511 bytes.
- R8 `sent_at` MUST be unix milliseconds rounded down to the minute; the sender rounds it, and a value that is not a multiple of 60 000 fails `validate` (R7).
- R9 On decode, a `display_name` that is not valid UTF-8, is longer than 64 bytes, contains a Cc character or appears in a `key_retired` MUST be dropped (read as absent) before `validate` runs, and MUST NOT make the message unreadable.
- R10 The encoded payload MUST be padded with `pad` to a multiple of 1024 bytes, which makes the padded payload 1024·k with k within 1..=63 and the blob 161 + 1024·k bytes.
- R11 The payload MUST NOT be compressed, in this version or any other (AGENTS 24).
- R12 `verify` MUST run steps 1–4 of `docs/spec.md` §4 in order and return the first failure: length, version and channel (R2); then `Error::Expired` when `min(received_at, now) + ttl_ms < now`; then the header is opened with `K_hdr` and the nonce; then `Error::BadSignature` when the signature does not verify under the opened `sender_pk`. It MUST read no state and have no effect.
- R13 `Verified::open` MUST derive `mk`, open the AEAD and return `Error::BadSignature` if it fails; after that the message is consumed, and it MUST return `Content::Unreadable` when unpadding, decoding or `validate` fails or the `type` is unknown, `Content::Stale` when `sent_at + ttl_ms + 360 000 < min(received_at, now)`, and `Content::Message` otherwise.
- R14 Every time computation of R12 and R13 MUST use `ttl_ms = u64(ttl_seconds) × 1000` and saturating arithmetic, so that no input value of `sent_at`, `received_at` or `now` can overflow.
- R15 The verdicts of this spec MUST NOT carry data: every error MUST be a unit variant with no byte of the blob, the header or the payload, and `verify` and `open` MUST return the verdict only to their caller (`docs/spec.md` §4 "No-oracle rule").
- R16 `Payload` MUST NOT implement `Display`, and its `Debug` MUST NOT print `body` or `display_name`: the decrypted payload is content and never reaches a log or an error (AGENTS 19).
- R17 The version, offsets, sizes, the 360 000 ms margin and the domain tag MUST be named constants next to the code that uses them, equal to the literals of `docs/spec.md` §4, and the tag `privatechat/msg/v1` MUST be exactly 18 bytes.
- R18 `seal` MUST call `validate`, encode, pad, seal the header, encrypt with `mk` and the associated data of R3, and sign, and MUST return a blob that `verify` and `open` accept with the same inputs; given the same inputs it MUST return the same bytes.

## Limits

| Input | Range | Out of range |
| --- | --- | --- |
| Blob | 1185..=64673 B, `(len − 161) mod 1024 = 0` | `BadLength` |
| `proto_version` | 1 | `UnsupportedVersion` |
| `channel_id` | the channel's own 16 bytes | `WrongChannel` |
| `min(received_at, now) + ttl_ms` | ≥ `now` | `Expired` |
| Encoded payload before padding | 0..=64 511 B | `BadPayload` on seal; on receive, not reachable (the blob length bounds it) |
| Padded payload | 1024·k, k 1..=63 | `Unreadable` on receive |
| `display_name` | 0..=64 B UTF-8, no Cc, absent in `key_retired` | `BadPayload` on seal; dropped on receive |
| `body` of a `text` | valid UTF-8 | `BadPayload` on seal; `Unreadable` on receive |
| `body` of a `key_retired` | present and empty | `BadPayload` on seal; `Unreadable` on receive |
| `sent_at` | multiple of 60 000 | `BadPayload` on seal; `Unreadable` on receive |
| `sent_at + ttl_ms + 360 000` | ≥ `min(received_at, now)` | `Stale` |
| `type` | 0 or 1 | `BadPayload` on seal; `Unreadable` on receive |

An unknown `type` on receive is not an attack: it is a message from a future version, consumed and kept as `Unreadable` (`docs/spec.md` §4).

## Interface

```
crates/core/src/proto/envelope.rs      the fixed offsets, seal, verify and open
crates/core/src/proto/payload.rs       Payload, its record schema and validate()
crates/core/src/proto/tests.rs         s013_* tests, with the mutation table
```

```rust
pub(crate) const PROTO_V1: u8 = 0x01;
pub(crate) const HEADER_LEN: usize = 81;
pub(crate) const PAD_BLOCK: usize = 1024;
pub(crate) const MAX_BLOCKS: usize = 63;
pub(crate) const BLOB_OVERHEAD: usize = 161;
pub(crate) const MAX_PAYLOAD: usize = 64_511;
pub(crate) const MAX_DISPLAY_NAME: usize = 64;
pub(crate) const STALE_MARGIN_MS: u64 = 360_000;
pub(crate) const MSG_SIGNATURE_TAG: &[u8; 18] = b"privatechat/msg/v1";

pub(crate) struct Payload { pub(crate) kind: PayloadKind, pub(crate) display_name: Option<String>, pub(crate) sent_at: u64, pub(crate) body: Vec<u8> }
pub(crate) enum PayloadKind { Text, KeyRetired, Unknown(u8) }

impl Payload {
    pub(crate) fn validate(&self) -> Result<(), Error>;
    pub(crate) fn encode(&self) -> Result<Vec<u8>, Error>;
    pub(crate) fn decode(bytes: &[u8]) -> Result<Payload, Error>;   // R6, R9; used by open and by the fuzz target
}

pub(crate) fn seal(keys: &ChannelKeys, sk_u: &Secret<64>, sender_pk: &PublicKey, counter: u64,
                   nonce: &Nonce, channel_id: &ChannelId, payload: &Payload) -> Result<Vec<u8>, Error>;

/// Steps 1–4 of `docs/spec.md` §4. Reads no state (R12).
pub(crate) fn verify<'a>(blob: &'a [u8], channel_id: &ChannelId, keys: &ChannelKeys,
                         received_at: u64, now: u64, ttl_seconds: u32) -> Result<Verified<'a>, Error>;

pub(crate) struct Verified<'a> { /* the borrowed envelope and the opened header */ }

impl<'a> Verified<'a> {
    pub(crate) fn sender_pk(&self) -> &PublicKey;
    pub(crate) fn counter(&self) -> u64;
    /// Step 7. Consumes the message unless the AEAD fails (R13).
    pub(crate) fn open(self, keys: &ChannelKeys, received_at: u64, now: u64, ttl_seconds: u32) -> Result<Opened, Error>;
}

pub(crate) struct Opened { pub(crate) sender_pk: PublicKey, pub(crate) counter: u64, pub(crate) content: Content }
pub(crate) enum Content { Message(Payload), Unreadable, Stale }
```

`Verified` borrows the blob: it is a view over bytes the caller owns, so verifying copies nothing and no partially checked envelope can outlive its buffer. Spec 021-channel-session maps `Content::Stale` to `Error::Expired` after it has advanced the counter.

## Security

- The order of R12 is a security property (ADR 0024): the length comes first so that no offset is ever computed on a buffer too short to hold it, and the signature comes right after the header is opened so that nothing written into an unauthenticated field — a flipped bit of `sender_pk` or `counter` — decides anything. `verify` reads no state at all.
- Encrypt-then-sign with the sender's key means the server, which holds no key, can verify nothing about a blob's content, and a member who did not write a message cannot produce one that verifies.
- `AAD = blob[0..81]` binds version, channel, encrypted header and nonce to the ciphertext: moving a valid ciphertext to another channel, or replaying it under another header, breaks the tag.
- A malicious server can keep a blob past its TTL and hand it over with a fresh `received_at`. The signed `sent_at` catches it (R13): the message is consumed, so it is not retried, and discarded as stale.
- Every rejection is silent (R15). The variants exist for the local caller and for the negative vectors; exposing them to a sender or to the server would turn every client into a decryption oracle. Spec 028-session-sans-io carries the other half of `docs/spec.md` §4: a verdict never surfaces as an `on_frame` error, never changes the connection state and never changes the timing of the next outgoing frame.
- The payload is never compressed (R11): compressing before encrypting would leak content through the ciphertext length, which is the one thing padding to 1024 bytes exists to hide.
- A `display_name` that breaks the rules is dropped rather than failing the message (R9), so two clients of different versions can never disagree on whether a message is readable because of a name.
- Secrets: `mk`, for the life of one call (spec 012-message-keys, R3), and `sk_u`, borrowed by `seal`. The decrypted payload is not a secret of `core`, but it is content: it never reaches a log or an error message (R16, AGENTS 19).

## Public API changes

None directly: every item here is `pub(crate)`. `docs/spec.md` §9 now gives `Channel::encrypt(body, display_name, now)`, which builds the `Payload` inside `core` (the UI cannot build a `key_retired` or choose `sent_at`); spec 021-channel-session implements it and spec 027-core-api confirms it. `Received` is defined there, not here.

## Test cases

- T01 (covers R1): `s013_t01_r01_envelope_offsets` on the vector `text_k1`: each field is at the offset the table fixes.
- T02 (covers R2): `s013_t02_r02_rejects_bad_length` over 1184, 1186, 64674 and 1185 + 1024·64 → `BadLength`; `s013_t03_r02_rejects_other_versions`: `blob[0]` of 0x00 and 0x02 → `UnsupportedVersion`; `s013_t04_r02_rejects_another_channel`: a `channel_id` one byte apart → `WrongChannel`.
- T05 (covers R3): `s013_t05_r03_aad_is_the_first_81_bytes`: opening with any other associated data fails the AEAD.
- T06 (covers R4): `s013_t06_r04_signature_known_answer` on the vector; `s013_t07_r04_signature_before_state_and_aead`: a blob with a valid header and a forged signature returns `BadSignature` without `message_key` being called.
- T08 (covers R5): `s013_t08_r05_seal_uses_the_given_nonce`: the nonce at offset 57 is the one passed, and it also opens the header.
- T09 (covers R6): `s013_t09_r06_payload_schema`: the reference payload encodes to the vector bytes; a payload with key 9 decodes with key 9 ignored; missing `type`, `sent_at` or `body`, a `type` of 2 bytes and keys out of order each fail decoding.
- T10 (covers R7): `s013_t10_r07_validate_table`: each case of R7 → `BadPayload` on `seal`.
- T11 (covers R8): `s013_t11_r08_sent_at_is_a_whole_minute`: 60 001 → `BadPayload` on seal and `Unreadable` on receive; 60 000 and 0 accepted.
- T12 (covers R9): `s013_t12_r09_bad_display_name_is_dropped`: a 65-byte name, one with U+0009, one with invalid UTF-8 and a name in a `key_retired`, all authentic, open as `Message` with no name.
- T13 (covers R10): `s013_t13_r10_padding_sizes`: payloads of 0, 1, 1023 and 64 511 encoded bytes give k of 1, 1, 1 and 63 and blobs of the exact length; 64 512 → `BadPayload`.
- T14 (covers R11): `s013_t14_r11_no_compression_crate`: the dependency graph carries none of the crates `deny.toml` bans for compression.
- T15 (covers R12): `s013_t15_r12_check_order`: a blob that fails several of steps 1–4 at once returns the first, as a table with one case per pair; `verify` takes no state parameter.
- T16 (covers R13): `s013_t16_r13_open_outcomes`: an authentic blob with broken padding, a broken record, an unknown `type` → `Unreadable`; a stale `sent_at` → `Stale`; a ciphertext signed under a wrong `K_msg` → `BadSignature`.
- T17 (covers R14): `s013_t17_r14_time_arithmetic_saturates`: `sent_at`, `received_at` and `now` of 2^64 − 1 and 0 in every combination return a verdict and never panic.
- T18 (covers R15): `s013_t18_r15_verdicts_carry_no_data`: every variant returned by `verify` and `open` is a unit variant.
- T19 (covers R16): `s013_t19_r16_payload_debug_hides_content`: the `Debug` of a payload with a known body and name contains neither.
- T20 (covers R17): `s013_t20_r17_literals`: the constants equal the §4 literals and `MSG_SIGNATURE_TAG` is 18 bytes.
- T21 (covers R18): `s013_t21_r18_seal_round_trip` proptest over every k, both types and names of 0..=64 bytes: `seal` then `verify` then `open` returns the same payload; two calls with the same inputs give the same bytes.
- T22 (covers R1, R2, R12): `s013_t22_r12_mutation_table`: the table below, one flipped byte per region of `text_k1`, each expecting its own error.
- T23 (covers R2, R4, R7, R9, R12, R13): `s013_t23_r12_every_vector_is_checked`: a loop over every vector of `013.json` with one match arm per name and no wildcard (spec 015-test-vectors).

## Vectors

`specs/vectors/013.json`, schema of `specs/vectors/README.md`, `proto_version = 1`. Every 64-bit value (counters, times) is a 16-character big-endian hex string. Receive vectors carry `channel_id`, `K_ch`, `received_at`, `now` and `ttl_seconds`; none needs receiver state. Produced by the generator of spec 015-test-vectors, cross-checked by its reference script where the value is a BLAKE2b computation, and frozen when phase 1 closes (AGENTS 18).

| name | kind | source | origin |
| --- | --- | --- | --- |
| `text_k1` | positive | derived | a `text` payload padded to one block, with its `mk`, nonce and blob → `Message` |
| `text_k63` | positive | derived | the largest payload, 64 511 encoded bytes → `Message` |
| `key_retired` | positive | derived | a `key_retired` → `Message` |
| `unknown_payload_key` | positive | derived | a `text` with key 9 → `Message`, key ignored |
| `unknown_type` | positive | derived | `type = 9`, authentic → `Unreadable` |
| `bad_padding` | positive | derived | authentic, padding with no marker → `Unreadable` |
| `bad_payload_record` | positive | derived | authentic, keys out of order → `Unreadable` |
| `missing_sent_at` | positive | derived | authentic, no key 2 → `Unreadable` |
| `sent_at_not_a_minute` | positive | derived | authentic, `sent_at` = 60 001 → `Unreadable` |
| `display_name_too_long`, `display_name_control`, `display_name_in_key_retired` | positive | derived | authentic → `Message` with no name |
| `stale_sent_at` | positive | derived | `sent_at` older than TTL + 360 000 ms before `received_at` → `Stale` |
| `expired_received_at` | negative | derived | `received_at + ttl_ms < now` → `Expired` |
| `mutate_version` | negative | derived | `blob[0] = 0x02` → `UnsupportedVersion` |
| `mutate_channel_id` | negative | derived | one byte of `blob[1..17]` → `WrongChannel` |
| `mutate_enc_hdr`, `mutate_nonce`, `mutate_ciphertext`, `mutate_signature` | negative | derived | one byte of each region → `BadSignature` |
| `short_blob`, `long_blob`, `unaligned_blob` | negative | derived | 1184, 64 674 and 1186 bytes → `BadLength` |
| `signature_s_plus_l` | negative | derived | a valid signature with S replaced by S + L → `BadSignature` |
| `r_small_order` | negative | derived | a signature whose R is a small-order point → `BadSignature` |
| `pk_identity`, `pk_small_order`, `pk_non_canonical` | negative | derived | that `sender_pk` sealed inside `enc_hdr` under `K_hdr` → `BadSignature` |
| `aead_forged_signed` | negative | derived | a ciphertext sealed under a wrong `K_msg` and validly signed → `BadSignature` |
| `seal_unknown_type`, `seal_sent_at_not_a_minute`, `seal_text_not_utf8`, `seal_key_retired_body`, `seal_key_retired_name`, `seal_name_too_long`, `seal_name_control`, `seal_payload_too_long` | negative | derived | each case of R7 on `seal` → `BadPayload` |

**Mutation table** (normative, `docs/spec.md` §4 and the template): every region of a well-formed blob, and the error a single flipped byte must produce. Because `verify` reads no state (R12), the table holds for any receiver.

| Region | Bytes | Error |
| --- | --- | --- |
| `proto_version` | 0 | `UnsupportedVersion` |
| `channel_id` | 1..17 | `WrongChannel` |
| `enc_hdr` | 17..57 | `BadSignature` |
| `nonce` | 57..81 | `BadSignature` |
| `ciphertext` | 81..81 + n | `BadSignature` |
| `signature` | last 64 | `BadSignature` |
| Length | any | `BadLength` |

A mutated `enc_hdr` or `nonce` fails at the signature, and not at the header, because the header has no integrity of its own by design (spec 012-message-keys, R5) and the signature covers both. A flipped `sender_pk` that happens to be a small-order or non-canonical point is rejected by the same strict verification.

## Acceptance criterion

`cargo test -p privatechat-core s013_` green, the mutation table included; clippy, `cargo deny` and the documentation lint green; the reference script of spec 015-test-vectors agrees with `013.json`. Non-automatable criterion: a second person reads the offsets of R1 and the order of R12 and R13 against `docs/spec.md` §4 and confirms them byte for byte, which is the internal review of `proto` the phase 1 exit criterion asks for.

## Out of scope

- The keys and the header transformation (spec 012-message-keys), the record encoding (spec 017-record-encoding) and the fingerprint (spec 014-fingerprint).
- Steps 5, 6 and 8 of `docs/spec.md` §4 and every write: the retired-key and peer-limit checks, `Replay`, the single commit of message, `max_counter`, peer and cursor, the rule that a rejection commits only the cursor, the persistence of `Unreadable`, the mapping of `Stale` to `Expired`, drawing the nonce and the outbox commit of `encrypt` (specs 021-channel-session, 022-peers-tofu, 026-peer-limits).
- The handling of a `key_retired` — signed by the key it retires, consumed without creating a peer when the key is unknown (ADR 0016) — and one's own `key_retired` (spec 024-key-retired).
- The no-oracle rule at the session level (spec 028-session-sans-io) and the log test (spec 100-log-test).
- The server's own blob validation, which repeats the length and prefix checks without any key (spec 030-ws-protocol).
- Message quoting, attachments and any field of v1.x or v2 (`docs/spec.md` §12).

## Open questions

- [ ] 013-R8: rejecting a `sent_at` that is not a whole minute makes the rule checkable, but it turns a sloppy sender into an unreadable message for everyone. The alternative is to round it down on receive and accept anything. `docs/spec.md` §4 says the field is rounded, without saying who enforces it; this spec chose the sender. Confirm.
- [ ] 013-R13: `Unreadable` messages occupy a slot in the log and count against the 64 MiB of the channel. Whether they expire by the same TTL as the rest is spec 023-ttl-purge; note it there.

## History

- 2026-09-21 in review
- 2026-09-24 revised after audit E (docs/audit-log.md)
