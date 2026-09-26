# 014 — User fingerprint, verification QR and 12 words

Status: in review
Phase: 1
Related ADRs: 0005, 0006, 0007, 0025, 0028
Depends on: 010-primitives-wrapper, 011-config-format, 015-test-vectors
Blocks: 016-fuzz-harness, 022-peers-tofu, 027-core-api, 055-verify-ui, 040-uniffi
Human reviewer: Marc Vilardebó · Accepted on: —

## Context

The channel has no member list (ADR 0006). A peer is a public key that has written, and the only way to know it belongs to the person you think is to compare a fingerprint out of band. `docs/spec.md` §4 "User fingerprint" fixes three presentations of the same 32 bytes:

- a QR that two phones scan in person;
- 12 words to read aloud;
- a short identifier of 4 words, which tells peers apart in a list without pretending to verify anything.

This spec fixes the derivation and the three encodings, all as functions of their arguments alone. The 12 words are 132 bits of the fingerprint read as indices into the English BIP-39 list. They carry no checksum and are not a BIP-39 mnemonic (ADR 0025): nobody types them, two people compare them, so a checksum would buy nothing and would need SHA-256, which the project does not use.

Other specs own the rest:

- the word list and the strict base64url codec: spec 011-config-format, which uses both first;
- what the user interface does with the three presentations, including the partial-match rule: `docs/spec.md` §7 and spec 055-verify-ui;
- how short-identifier collisions between peers are reported: spec 022-peers-tofu;
- the fingerprint of a retired key, a peer's or one's own old key: spec 022-peers-tofu R12, which computes it for any `pk`.

In plain words: the fingerprint is a hash of "this key, in this channel". Two people who see the same 12 words, or whose phones accept each other's QR, are looking at the same key.

## Requirements

- R1 The fingerprint MUST be `fp = hash("privatechat/fp/v1" ‖ channel_id ‖ pk_u)`: 32 bytes over exactly 65 bytes of input, which are the 17 ASCII bytes of the tag, the 16 bytes of `channel_id` and the 32 bytes of `pk_u`, with no separator (`docs/spec.md` §4).
- R2 The fingerprint MUST bind the channel: the same `pk_u` in two channels MUST give two different fingerprints.
- R3 The verification QR MUST be the ASCII bytes `verify:v1:` followed by the base64url of `channel_id ‖ pk_u`, encoded with the codec of spec 011-config-format (`proto/base64url.rs`): 48 bytes that encode to 64 characters, 74 bytes in total, with no padding and no name of any kind. It MUST cross the boundary as bytes in both directions, never as a `String`, like the config QR (ADR 0028).
- R4 Parsing a verification QR MUST return `Error::BadPayload` when the prefix, compared with `ct_eq`, is not `verify:v1:` or the body is not exactly 64 characters accepted by the strict decoder of spec 011-config-format, and MUST return `Error::WrongChannel` when the decoded `channel_id` is not the open channel's.
- R5 The 12 words MUST be `words[i] = list[bits(fp, 11·i, 11)]` for `i` in 0..12, where `bits(fp, o, 11)` is the 11-bit big-endian integer starting at bit `o` of `fp`, counted from the most significant bit of `fp[0]`. They use the first 132 bits of `fp`, carry no checksum and MUST NOT be described as a BIP-39 mnemonic (ADR 0025).
- R6 The short identifier MUST be the first 4 of the 12 words (44 bits) and MUST be output only: no function of `core` takes it as input.
- R7 This spec MUST add its section to `scripts/reference/vectors.py` of spec 015-test-vectors, which produces `specs/vectors/014.json` from fixed inputs written in the script: `fp` (BLAKE2b through `hashlib`), the 12 word indices, the 12 words looked up in the English BIP-39 list and the verification QR bytes, and the five negative QR vectors as edits of `qr_reference`.
- R8 `presentation(channel_id, pk_u)` MUST return the `Fingerprint` record whose `words`, `short` and `qr` are exactly `words`, `short_identifier` and `verify_qr` of the same inputs, so `words` always holds 12 entries and `short` 4: the lengths of the two `Vec<String>` are guaranteed by `presentation`, the only function that builds a `Fingerprint`.

## Limits

| Input | Range | Out of range |
| --- | --- | --- |
| Fingerprint input | exactly 65 B | not constructible (types) |
| Domain tag | exactly 17 B | not constructible (constant) |
| QR bytes | exactly 74 B (`verify:v1:` plus 64 characters) | `BadPayload` |
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
pub(crate) const FP_TAG: &[u8; 17] = b"privatechat/fp/v1";
pub(crate) const QR_PREFIX: &[u8; 10] = b"verify:v1:";
pub(crate) const WORD_COUNT: usize = 12;
pub(crate) const SHORT_WORD_COUNT: usize = 4;

pub struct Fingerprint { pub words: Vec<String>, pub short: Vec<String>, pub qr: Vec<u8> }   // 12 and 4 entries, by R8

pub(crate) fn fingerprint(channel_id: &ChannelId, pk_u: &PublicKey) -> Result<[u8; 32], Error>;
pub(crate) fn words(fp: &[u8; 32]) -> Result<[&'static str; 12], Error>;   // Internal on the impossible out-of-list index
pub(crate) fn short_identifier(words: &[&'static str; 12]) -> [&'static str; 4];
pub(crate) fn verify_qr(channel_id: &ChannelId, pk_u: &PublicKey) -> Vec<u8>;
pub(crate) fn parse_verify_qr(bytes: &[u8], channel_id: &ChannelId) -> Result<PublicKey, Error>;
pub(crate) fn presentation(channel_id: &ChannelId, pk_u: &PublicKey) -> Result<Fingerprint, Error>;
```

`fingerprint` returns `Error::Internal` only when libsodium fails (`CryptoError::InitFailed`); hashing a fixed-size input has no other failure.

The functions are `pub(crate)`; `Fingerprint` is `pub` with public fields and is built only by `presentation`. It is the `Record` of the core boundary (`docs/spec.md` §9) and reaches the UI through `Channel::fingerprint` and the verification screen's call, both of which spec 022-peers-tofu defines and spec 027-core-api exposes; the same type crosses the uniffi boundary, which has no fixed-size arrays, so its fields are `Vec<String>` with the lengths R8 guarantees. No client re-implements any of the three presentations. No function of `core` takes four words as input (R6).

The word list is the one of spec 011-config-format, `crates/core/src/proto/wordlist.rs`, whose BLAKE2b-256 digest `6fefd6b6e47ee66e6bbf8ee322305deebeefb1bd9b24e8618bf126d870175bb7` that spec pins, and the base64url codec is its `proto/base64url.rs`; this module embeds neither a second copy of the list nor a second codec.

`s014_vectors_dispatch` calls `vectors::check_all("014", …)` with one entry per vector and is the only code that loads `014.json` (spec 015-test-vectors R3).

`parse_verify_qr` reuses `Error::BadPayload` for a malformed QR because the §9 enum is the fixed list of the boundary and has no QR variant. Its message to the user is the same, "this is not a verification code of this app". A QR of another channel gets `WrongChannel`, which already means exactly that.

## Security

- The fingerprint is public: it is derived from a public key and a public channel identifier and carries no secret. What it protects is the binding between a key and a person, which is the only thing standing between a member and an impersonation (ADR 0006).
- Binding the channel (R2) stops a fingerprint verified in one channel from being replayed as proof in another.
- The QR compares the full 32-byte `pk_u`. The 12 words carry 132 bits: finding another key with the same 12 words is a second-preimage search of about 2^132 work.
- The short identifier is 44 bits, and a collision can be produced deliberately with enough work. That is why it is output only (R6) and why spec 022-peers-tofu reports a collision instead of resolving it: 44 bits identify, they do not authenticate.
- The QR carries no name on purpose: a name in the QR would be a claim, and the receiver is the one who decides what to call a peer (ADR 0006).
- `parse_verify_qr` accepts any 32 bytes as `pk_u`. A non-canonical or small-order key cannot produce a signature that libsodium accepts, so a peer pre-verified with one never writes a message; checking it at scan time would need a primitive spec 010-primitives-wrapper does not expose, for no gain.
- The words are deliberately not a BIP-39 mnemonic (ADR 0025). No wallet accepts them, so users are never taught to read a valid seed phrase aloud.

## Public API changes

`Fingerprint`, `Channel::fingerprint` and `Channel::own_fingerprint` are already in `docs/spec.md` §9, `short` field included. `parse_verify_qr` needs a call that takes the scanned bytes, which spec 022-peers-tofu defines as `verify_scanned` and spec 027-core-api exposes.

## Test cases

- T01 (covers R1): `s014_t01_r01_fingerprint_known_answer` on the vector, and `FP_TAG.len()` is 17 and the hashed input is 65 bytes.
- T02 (covers R2): `s014_t02_r02_fingerprint_binds_the_channel`: the same `pk_u` in two channels gives two fingerprints.
- T03 (covers R3): `s014_t03_r03_qr_known_answer` on the vector: the prefix, 64 characters, no `=`, 74 bytes in total; and a proptest over any `channel_id` and `pk_u`: `parse_verify_qr(verify_qr(id, pk), id)` returns the same `pk_u` (AGENTS 21).
- T04 (covers R4): `s014_t04_r04_rejects_a_foreign_qr` over a table: a `verify:v2:` prefix, 63 and 65 characters, a `+` and a `/` of standard base64 and a trailing `=` → `BadPayload`; a QR of another channel → `WrongChannel`.
- T05 (covers R5): `s014_t05_r05_words_known_answer` on the vectors, including a fingerprint of all zeros (12 × `abandon`), one of all ones (12 × `zoo`), and one whose bit 131 is set and bit 132 clear, so the boundary of the 132 bits is pinned.
- T06 (covers R6): `s014_t06_r06_short_identifier_is_the_first_four`: it equals words 0 to 3.
- T07 (covers R7): `check_s014_t07_r07_section_produces_014_json`, the self-check of this spec's section in `scripts/reference/vectors.py`, run by the CI step of spec 015-test-vectors R6: the section writes `014.json` and the file equals the committed one; `cargo test -p privatechat-core s014_` then reproduces every vector through the checkers of the tests above.
- T08 (covers R8): `s014_t08_r08_presentation_matches_its_parts`: for the reference inputs, each field of `presentation` equals the function it comes from, `words.len()` is 12 and `short.len()` is 4.

## Vectors

`specs/vectors/014.json`, schema of `specs/vectors/README.md`, `proto_version = 1`. Produced by this spec's section of the reference script of spec 015-test-vectors from fixed inputs (R7); the Rust tests reproduce them through `check_all`.

| name | kind | source | origin |
| --- | --- | --- | --- |
| `fingerprint_reference` | positive | derived | `channel_id` and `pk_u` → `fp` (§4) |
| `fingerprint_other_channel` | positive | derived | the same `pk_u`, another channel |
| `words_reference`, `words_zero`, `words_ones`, `words_bit_131` | positive | derived | four fingerprints → their 12 word indices and words (§4, ADR 0025) |
| `qr_reference` | positive | derived | `channel_id ‖ pk_u` → the QR bytes |
| `qr_wrong_prefix`, `qr_wrong_length`, `qr_standard_base64`, `qr_padding` | negative | derived | each → `BadPayload` |
| `qr_other_channel` | negative | derived | → `WrongChannel` |

All of these are `derived`: each value follows from the formulas of `docs/spec.md` §4 and the BLAKE2b of spec 010-primitives-wrapper, so the reference script writes every one of them with the Python standard library. The word indices and the words are JSON arrays (`specs/vectors/README.md`). Every vector that carries a `channel_id`, except `fingerprint_other_channel` and `qr_other_channel`, uses the `channel_id` of 011 `config_reference`; `qr_reference` carries the `pk_u` of `fingerprint_reference`, and `words_reference` holds that fingerprint's words, so that Kotlin and Swift reach them through `Device` (spec 040-uniffi R13, R14). No vector tests non-zero final bits: 48 bytes encode to exactly 64 characters with no bits left over, so every accepted 64-character body is canonical by construction.

## Acceptance criterion

`cargo test -p privatechat-core s014_` green; the section of the reference script of spec 015-test-vectors produces `014.json` byte for byte as committed; clippy, `cargo deny` and the documentation lint green. Non-automatable criterion: a human reads the 12 words of `words_reference` against the list and the 132 bits of its `fp`, and confirms the first three indices by hand.

## Out of scope

- The verification screen, the QR camera, the pre-verification flow, the "identifier, not verification" label and the rule that all 12 words must match (`docs/spec.md` §7, spec 055-verify-ui).
- Reporting short-identifier collisions between peers, what is stored about a peer, the labels and the peer limits (specs 022-peers-tofu, 026-peer-limits).
- Key regeneration and the retirement record (specs 024-key-retired, 025-identity-regen); the fingerprint of any retired key is spec 022-peers-tofu R12.
- The word list, its digest and the base64url codec (spec 011-config-format).
- Any other word list: the English one is the only list of v1 (`docs/spec.md` §12).

## Open questions

None. Closed after audit F: the list lives in `core`, owned by spec 011-config-format (now an Interface statement); the boundary carries `Vec<String>` with the length guaranteed by construction, which audit I made the core type itself (R8); a non-canonical or small-order key in a verification QR is left to the later signature failure (014-R4).

## History

- 2026-09-21 in review
- 2026-09-24 revised after audit E (`docs/audit-log.md`): 65-byte input, words per ADR 0025 with no SHA-256, UI and peer rules moved to 022, 025 and 055, `WrongChannel` for a QR of another channel
- 2026-09-24 revised after audit F (`docs/audit-log.md`): base64url codec of 011 reused, verification QR as bytes both ways, purity requirement dropped, generator and reference-script sections and the dispatch test added, open questions closed
- 2026-09-24 revised after audit H (`docs/audit-log.md`): QR round-trip as a proptest, `presentation` as a requirement, prefix compared with `ct_eq`, the impossible final-bits case dropped, the dispatch rule cited as 015 R10; round 4: fixed-size constants for `ct_eq`, `words` returns `Result` under the lints; round 8: the script also checks the words
- 2026-09-24 revised after audit I (`docs/audit-log.md`): `Fingerprint` holds `Vec<String>` fields with lengths guaranteed by `presentation`, one type inside `core` and across uniffi; the reference script produces the vectors and the Rust tests reproduce them, `s014_vectors_dispatch` stated in the Interface; the list-and-codec reuse and the "no input of four words" clause moved to the Interface and their source-scan tests dropped; R6–R9 renumbered R6–R8, T06–T09 renumbered T06–T08
- 2026-09-25 revised after audit J round 12 (`docs/audit-log.md`)
- 2026-09-26 amended by spec 040-uniffi R14 while drafting phase 4: the vectors use the `channel_id` of 011 `config_reference`, so that the bindings reach them through `Device`
