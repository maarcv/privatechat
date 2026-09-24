# 014 — User fingerprint, verification QR and 12 words

Status: in review
Phase: 1
Related ADRs: 0005, 0006, 0007, 0025
Depends on: 010-primitives-wrapper, 011-config-format, 015-test-vectors
Blocks: 016-fuzz-harness, 022-peers-tofu, 055-verify-ui
Human reviewer: Marc Vilardebó · Accepted on: —

## Context

The channel has no member list (ADR 0006). A peer is a public key that has written, and the only way to know it belongs to the person you think is to compare a fingerprint out of band. `docs/spec.md` §4 "User fingerprint" fixes three presentations of the same 32 bytes:

- a QR that two phones scan in person;
- 12 words to read aloud;
- a short identifier of 4 words, which tells peers apart in a list without pretending to verify anything.

This spec fixes the derivation and the three encodings, all as pure functions. The 12 words are 132 bits of the fingerprint read as indices into the English BIP-39 list. They carry no checksum and are not a BIP-39 mnemonic (ADR 0025): nobody types them, two people compare them, so a checksum would buy nothing and would need SHA-256, which the project does not use.

Other specs own the rest:

- the word list itself: spec 011-config-format, which uses it first for the file password;
- what the user interface does with the three presentations, including the partial-match rule: `docs/spec.md` §7 and spec 055-verify-ui;
- how short-identifier collisions between peers are reported: spec 022-peers-tofu;
- the fingerprint of a retired key: spec 025-identity-regen.

In plain words: the fingerprint is a hash of "this key, in this channel". Two people who see the same 12 words, or whose phones accept each other's QR, are looking at the same key.

## Requirements

- R1 The fingerprint MUST be `fp = hash("privatechat/fp/v1" ‖ channel_id ‖ pk_u)`: 32 bytes over exactly 65 bytes of input, which are the 17 ASCII bytes of the tag, the 16 bytes of `channel_id` and the 32 bytes of `pk_u`, with no separator (`docs/spec.md` §4).
- R2 The fingerprint MUST bind the channel: the same `pk_u` in two channels MUST give two different fingerprints.
- R3 The verification QR MUST be the ASCII `verify:v1:` followed by the base64url of `channel_id ‖ pk_u`: 48 bytes that encode to 64 characters, with no padding and no name of any kind.
- R4 Parsing a verification QR MUST return `Error::BadPayload` when the prefix is not `verify:v1:` or the body is not exactly 64 characters of the base64url alphabet, and MUST return `Error::WrongChannel` when the decoded `channel_id` is not the open channel's.
- R5 The 12 words MUST be `words[i] = list[bits(fp, 11·i, 11)]` for `i` in 0..12, where `bits(fp, o, 11)` is the 11-bit big-endian integer starting at bit `o` of `fp`, counted from the most significant bit of `fp[0]`. They use the first 132 bits of `fp`, carry no checksum and MUST NOT be described as a BIP-39 mnemonic (ADR 0025).
- R6 The word list MUST be the one of spec 011-config-format, `crates/core/src/proto/wordlist.rs`, whose BLAKE2b-256 digest `6fefd6b6e47ee66e6bbf8ee322305deebeefb1bd9b24e8618bf126d870175bb7` that spec pins. This spec MUST NOT embed a second copy.
- R7 The short identifier MUST be the first 4 of the 12 words (44 bits) and MUST be output only: 4 words MUST NOT be accepted as input by any function of `core`.
- R8 Every function of this spec MUST be a pure function of its arguments: no clock, no randomness, no state.

## Limits

| Input | Range | Out of range |
| --- | --- | --- |
| Fingerprint input | exactly 65 B | not constructible (types) |
| Domain tag | exactly 17 B | not constructible (constant) |
| QR text | exactly 74 B (`verify:v1:` plus 64 characters) | `BadPayload` |
| QR prefix | exactly `verify:v1:` | `BadPayload` |
| QR body | 64 base64url characters, no padding | `BadPayload` |
| QR `channel_id` | the open channel's | `WrongChannel` |
| Word index | 0..=2047 | not constructible (11 bits) |
| Short identifier | exactly 4 words, output only | not an input anywhere |

## Interface

```
crates/core/src/proto/fingerprint.rs        fp, the QR and the 12 words
crates/core/src/proto/fingerprint/tests.rs  s014_* tests
```

```rust
pub(crate) const FP_TAG: &[u8] = b"privatechat/fp/v1";
pub(crate) const QR_PREFIX: &[u8] = b"verify:v1:";
pub(crate) const WORD_COUNT: usize = 12;
pub(crate) const SHORT_WORD_COUNT: usize = 4;

pub struct Fingerprint { pub words: [String; 12], pub short: [String; 4], pub qr: Vec<u8> }

pub(crate) fn fingerprint(channel_id: &ChannelId, pk_u: &PublicKey) -> Result<[u8; 32], Error>;
pub(crate) fn words(fp: &[u8; 32]) -> [&'static str; 12];
pub(crate) fn short_identifier(words: &[&'static str; 12]) -> [&'static str; 4];
pub(crate) fn verify_qr(channel_id: &ChannelId, pk_u: &PublicKey) -> Vec<u8>;
pub(crate) fn parse_verify_qr(bytes: &[u8], channel_id: &ChannelId) -> Result<PublicKey, Error>;
pub(crate) fn presentation(channel_id: &ChannelId, pk_u: &PublicKey) -> Result<Fingerprint, Error>;
```

`fingerprint` returns `Error::Internal` only when libsodium fails (`CryptoError::InitFailed`); hashing a fixed-size input has no other failure.

The functions are `pub(crate)`. `Fingerprint` is the `Record` of the core boundary (`docs/spec.md` §9) and reaches the UI through `Channel::fingerprint` and the verification screen's call, both of which spec 027-core-api defines. No client re-implements any of the three presentations.

`parse_verify_qr` reuses `Error::BadPayload` for a malformed QR because the §9 enum is the fixed list of the boundary and has no QR variant. Its message is the same to the user, "this is not a verification code of this app". A QR of another channel gets `WrongChannel`, which already means exactly that.

## Security

- The fingerprint is public: it is derived from a public key and a public channel identifier and carries no secret. What it protects is the binding between a key and a person, which is the only thing standing between a member and an impersonation (ADR 0006).
- Binding the channel (R2) stops a fingerprint verified in one channel from being replayed as proof in another.
- The QR compares the full 32-byte `pk_u`. The 12 words carry 132 bits: finding another key with the same 12 words is a second-preimage search of about 2^132 work.
- The short identifier is 44 bits, and a collision can be produced deliberately with enough work. That is why it is output only (R7) and why spec 022-peers-tofu reports a collision instead of resolving it: 44 bits identify, they do not authenticate.
- The QR carries no name on purpose: a name in the QR would be a claim, and the receiver is the one who decides what to call a peer (ADR 0006).
- The words are deliberately not a BIP-39 mnemonic (ADR 0025). No wallet accepts them, so users are never taught to read a valid seed phrase aloud.

## Public API changes

`Fingerprint` and `Channel::fingerprint` are already in `docs/spec.md` §9. This spec adds the `short` field to the record, which §9 already shows. Spec 027-core-api exposes `parse_verify_qr` behind the verification screen's call.

## Test cases

- T01 (covers R1): `s014_t01_r01_fingerprint_known_answer` on the vector; `s014_t02_r01_tag_is_seventeen_bytes`: `FP_TAG.len()` is 17 and the hashed input is 65 bytes.
- T03 (covers R2): `s014_t03_r02_fingerprint_binds_the_channel`: the same `pk_u` in two channels gives two fingerprints.
- T04 (covers R3): `s014_t04_r03_qr_known_answer` on the vector: the prefix, 64 characters, no `=`, and 74 bytes in total.
- T05 (covers R4): `s014_t05_r04_rejects_a_foreign_qr` over a table: a `verify:v2:` prefix, 63 and 65 characters, a `+` and a `/` of standard base64, and a trailing `=` → `BadPayload`; a QR of another channel → `WrongChannel`; a QR round-trip returns the same `pk_u`.
- T06 (covers R5): `s014_t06_r05_words_known_answer` on the vectors, including a fingerprint of all zeros (12 × `abandon`), one of all ones (12 × `zoo`), and one whose bit 131 is set and bit 132 clear, so the boundary of the 132 bits is pinned.
- T07 (covers R6): `s014_t07_r06_uses_the_single_word_list`: the source tree has one copy of the list, the one of spec 011-config-format, and `words` reads it.
- T08 (covers R7): `s014_t08_r07_short_identifier_is_the_first_four`: it equals words 0 to 3, and no function of `core` takes four words.
- T09 (covers R8): `s014_t09_r08_encodings_are_pure`: the same inputs give the same outputs, and no function takes a `now`.

## Vectors

`specs/vectors/014.json`, schema of `specs/vectors/README.md`, `proto_version = 1`. Produced by the generator of spec 015-test-vectors and cross-checked by its reference script before the freeze.

| name | kind | source | origin |
| --- | --- | --- | --- |
| `fingerprint_reference` | positive | derived | `channel_id` and `pk_u` → `fp` (§4) |
| `fingerprint_other_channel` | positive | derived | the same `pk_u`, another channel |
| `words_reference`, `words_zero`, `words_ones`, `words_bit_131` | positive | derived | four fingerprints → their 12 words (§4, ADR 0025) |
| `qr_reference` | positive | derived | `channel_id ‖ pk_u` → the QR bytes |
| `qr_wrong_prefix`, `qr_wrong_length`, `qr_standard_base64`, `qr_padding` | negative | derived | each → `BadPayload` |
| `qr_other_channel` | negative | derived | → `WrongChannel` |

All of these are `derived`: each value follows from the formulas of `docs/spec.md` §4 and the BLAKE2b of spec 010-primitives-wrapper, so `scripts/reference/` recomputes every one of them independently.

## Acceptance criterion

`cargo test -p privatechat-core s014_` green; clippy, `cargo deny` and the documentation lint green. Non-automatable criterion: a human reads the 12 words of `words_reference` against the list and the 132 bits of its `fp`, and confirms the first three indices by hand.

## Out of scope

- The verification screen, the QR camera, the pre-verification flow, the "identifier, not verification" label and the rule that all 12 words must match (`docs/spec.md` §7, spec 055-verify-ui).
- Reporting short-identifier collisions between peers, what is stored about a peer, the labels and the peer limits (specs 022-peers-tofu, 026-peer-limits).
- The fingerprint of one's own retired key, key regeneration and the retirement record (specs 024-key-retired, 025-identity-regen).
- The word list and its digest (spec 011-config-format).
- Any other word list: the English one is the only list of v1 (`docs/spec.md` §12).

## Open questions

- [ ] 014-R6: the list lives in `core`, owned by spec 011-config-format, so the three platforms show the same words and no client carries its own copy. It adds about 13 KB of source, which AGENTS 14 excludes from the PR size. Confirm.
- [ ] 014: `Fingerprint` uses `[String; 12]` and `[String; 4]`, but uniffi records have no fixed-size arrays. Spec 027-core-api and spec 040-uniffi decide whether the boundary carries `Vec<String>` with the length guaranteed by construction. The core keeps the fixed arrays.
- [ ] 014-R4: `parse_verify_qr` accepts any 32 bytes as `pk_u`. Rejecting a non-canonical or small-order key at scan time would stop a pre-verified peer that can never sign, but it needs a key-validity check that spec 010-primitives-wrapper does not expose; today such a key fails later at every signature. Confirm that the later failure is enough.

## History

- 2026-09-21 in review
- 2026-09-24 revised after audit E (`docs/audit-log.md`): 65-byte input, words per ADR 0025 with no SHA-256, UI and peer rules moved to 022, 025 and 055, `WrongChannel` for a QR of another channel
