# 014 — User fingerprint, verification QR and 12 words

Status: in review
Phase: 1
Related ADRs: 0005, 0006, 0007
Depends on: 010-primitives-wrapper, 011-config-format, 013-wire-message
Blocks: 015-test-vectors, 022-peers-tofu, 055-verify-ui
Human reviewer: Marc Vilardebó · Accepted on: —

## Context

The channel has no member list (ADR 0006): a peer is a public key that has written, and the only way to know it belongs to the person you think is to compare a fingerprint out of band. `docs/spec.md` §4 "User fingerprint" fixes three presentations of the same 32 bytes: a QR that two phones scan in person, 12 BIP-39 words to read aloud, and a short identifier of 4 words that tells peers apart in a list without pretending to verify anything.

This spec fixes the derivation, the three encodings and the rules that keep the short identifier from being mistaken for verification. What the user interface does with them is `docs/spec.md` §7 and spec 055-verify-ui; what is stored about a peer is spec 022-peers-tofu.

## Requirements

- R1 The fingerprint MUST be `fp = hash("privatechat/fp/v1" ‖ channel_id ‖ pk_u)`, 32 bytes over exactly 18 + 16 + 32 bytes of input, with the tag as ASCII and no separator (`docs/spec.md` §4).
- R2 The fingerprint MUST bind the channel: the same `pk_u` in two channels MUST give two different fingerprints.
- R3 The verification QR MUST be the ASCII `verify:v1:` followed by the base64url of `channel_id ‖ pk_u`, 48 bytes that encode to 64 characters with no padding and no name of any kind.
- R4 Parsing a verification QR MUST return `Error::BadPayload` for a prefix that is not `verify:v1:`, for a body that is not 64 characters of the base64url alphabet, and for a `channel_id` that is not the open channel's.
- R5 The 12 words MUST be the standard BIP-39 mnemonic of `fp[0..16]`: 128 bits of entropy plus a 4-bit checksum, split into 12 groups of 11 bits, each indexing the English list of 2048 words.
- R6 The word list MUST be the official English BIP-39 list, embedded in the crate, and a test MUST pin its digest so that a changed list fails instead of silently renaming everyone.
- R7 The short identifier MUST be the first 4 of those 12 words, MUST always be presented with a label saying it identifies and does not verify, and MUST NOT be usable as an input anywhere: nothing in the core accepts 4 words.
- R8 Manual verification MUST require all 12 words to match; a partial match MUST NOT mark a peer verified (`docs/spec.md` §7).
- R9 Two peers of one channel whose short identifiers collide MUST both be reported as colliding, so that the interface can show the 12 words of each with a warning (`docs/spec.md` §7).
- R10 Every encoding of this spec MUST be a pure function of `channel_id` and `pk_u`: no clock, no randomness, no state.
- R11 The fingerprint of one's own key MUST be available while the channel holds `sk_u` and after it has been retired, because a user reads their own words aloud to be verified.
- R12 `core::crypto` MUST gain `sha256(input: &[u8]) -> Result<[u8; 32], CryptoError>` over `crypto_hash_sha256`, used only for the BIP-39 checksum of R5, and `docs/spec.md` §4 MUST list it with that single use.

## Limits

| Input | Range | Out of range |
| --- | --- | --- |
| Fingerprint input | exactly 66 B | not constructible (types) |
| QR body | exactly 64 base64url characters | `BadPayload` |
| QR prefix | exactly `verify:v1:` | `BadPayload` |
| Words of a mnemonic | exactly 12 | `BadPayload` |
| Word index | 0..=2047 | not constructible (11 bits) |
| Short identifier | exactly 4 words, output only | not an input anywhere |

## Interface

```
crates/core/src/proto/fingerprint.rs        fp, the QR and the mnemonic
crates/core/src/proto/bip39_english.txt     the official list, 2048 lines
crates/core/src/proto/tests.rs              s014_* tests
```

```rust
pub struct Fingerprint { pub words: [String; 12], pub qr: Vec<u8>, pub short: [String; 4] }

pub(crate) fn fingerprint(channel_id: &[u8; 16], sender_pk: &PublicKey) -> Result<[u8; 32], CryptoError>;
pub(crate) fn mnemonic(fingerprint: &[u8; 32]) -> Result<[String; 12], CryptoError>;
pub(crate) fn verify_qr(channel_id: &[u8; 16], sender_pk: &PublicKey) -> Vec<u8>;
pub(crate) fn parse_verify_qr(bytes: &[u8], channel_id: &[u8; 16]) -> Result<PublicKey, Error>;
pub(crate) fn short_identifier(words: &[String; 12]) -> [String; 4];
```

`Fingerprint` is a `Record` at the core boundary (`docs/spec.md` §9): three presentations of the same bytes, so that no client re-implements one of them.

## Security

- The fingerprint is public: it is derived from a public key and a public channel identifier, and it carries no secret. What it protects is the binding between a key and a person, which is the only thing standing between a member and an impersonation (ADR 0006).
- Binding the channel (R2) stops a fingerprint verified in one channel from being replayed as proof in another.
- The short identifier is 44 bits. A collision can be produced deliberately with enough work, which is why it is output only (R7) and why a collision is reported rather than resolved (R9): 44 bits identify, they do not authenticate.
- The QR carries no name on purpose: a name in the QR would be a claim, and the receiver is the one who decides what to call a peer (ADR 0006).
- The mnemonic is standard so that a user can check it with any BIP-39 tool. This is also why the checksum needs SHA-256 (R12): a checksum of our own would produce words no other tool accepts.

## Public API changes

`Fingerprint` and `Channel::fingerprint` are already in `docs/spec.md` §9; this spec adds the `short` field to the record and `parse_verify_qr`, which the verification screen needs. Spec 027-core-api confirms both.

## Test cases

- T01 (covers R1): `s014_t01_r01_fingerprint_known_answer` on the vector.
- T02 (covers R2): `s014_t02_r02_fingerprint_binds_the_channel`: the same `pk_u` in two channels gives two fingerprints.
- T03 (covers R3): `s014_t03_r03_qr_known_answer` on the vector: prefix, 64 characters, no padding, no name.
- T04 (covers R4): `s014_t04_r04_rejects_a_foreign_qr` over a table: a `verify:v2:` prefix, 63 characters, a `+` and a `/` of standard base64, and a QR of another channel → `BadPayload`.
- T05 (covers R5): `s014_t05_r05_mnemonic_known_answer` on the vectors, including a fingerprint of all zeros and one of all ones.
- T06 (covers R5): `s014_t06_r05_mnemonic_matches_bip39`: the checksum of each vector recomputed by hand from the entropy.
- T07 (covers R6): `s014_t07_r06_word_list_is_pinned`: the list has 2048 unique words, sorted, and its digest is the one this spec fixes.
- T08 (covers R7): `s014_t08_r07_short_identifier_is_the_first_four`: it equals words 0 to 3, and no public function accepts four words.
- T09 (covers R8): `s014_t09_r08_partial_match_does_not_verify`: 11 matching words do not verify a peer.
- T10 (covers R9): `s014_t10_r09_collision_is_reported`: two keys whose first four words coincide are both flagged.
- T11 (covers R10): `s014_t11_r10_encodings_are_pure`: the same inputs give the same outputs, and no function takes a `now`.
- T12 (covers R11): `s014_t12_r11_own_fingerprint_survives_retirement`: after `regenerate_identity`, the old key's fingerprint is still computable.
- T13 (covers R12): `s014_t13_r12_sha256_known_answer`: the published SHA-256 vectors of the empty string and of `abc`.

## Vectors

`specs/vectors/014.json`, schema of `specs/vectors/README.md`, `proto_version = 1`.

| name | kind | source | origin |
| --- | --- | --- | --- |
| `fingerprint_reference` | positive | derived | `channel_id` and `pk_u` → `fp` |
| `fingerprint_other_channel` | positive | derived | the same `pk_u`, another channel |
| `mnemonic_reference`, `mnemonic_zero`, `mnemonic_ones` | positive | derived | three fingerprints → their 12 words |
| `qr_reference` | positive | derived | `channel_id ‖ pk_u` → the QR bytes |
| `sha256_empty`, `sha256_abc` | positive | published | FIPS 180-4, the two vectors every implementation carries |
| `qr_wrong_prefix`, `qr_wrong_length`, `qr_standard_base64`, `qr_other_channel` | negative | derived | each → `BadPayload` |

The BIP-39 vectors are `derived` rather than `published` because the published ones map a seed phrase to a seed, which this spec does not do: here the mnemonic is an encoding of 16 bytes and nothing else. T06 checks each one against the algorithm by hand, which is what a published vector would have proved.

## Acceptance criterion

`cargo test -p privatechat-core s014_` green; clippy, `cargo deny` and the documentation lint green. Non-automatable criterion: a human takes the 12 words of `mnemonic_reference`, pastes them into an independent BIP-39 tool and confirms the tool accepts them as a valid mnemonic. If it does not, R5 is not standard and the words are worth nothing outside this app.

## Out of scope

- The verification screen, the QR camera and the pre-verification flow (`docs/spec.md` §7, spec 055-verify-ui).
- What is stored about a peer, the labels, the collision rule of labels and the peer limits (specs 022-peers-tofu, 026-peer-limits).
- Key regeneration and the retirement record (specs 024-key-retired, 025-identity-regen).
- Any other word list: the English one is the only list of v1 (`docs/spec.md` §12).

## Open questions

- [ ] 014-R12: `docs/spec.md` §4 asks for a standard BIP-39 mnemonic, whose checksum is SHA-256 of the entropy, but the primitive table of §4 has no SHA-256 and spec 010-primitives-wrapper put SHA-2 explicitly out of scope. The three ways out: add `crypto_hash_sha256` to the table and to the wrapper, which is what this spec assumes and needs a new ADR and a §4 amendment; use BLAKE2b for the checksum, which makes the words fail in every other BIP-39 tool and empties the word "standard"; or drop the checksum, which does not divide into 12 words. Decide before implementing, because it changes the wrapper of an already implemented spec.
- [ ] 014-R6: embedding the 2048-word list adds about 13 KB of source to `core` and a digest that must be pinned. Confirm that the list lives in `core` and not in each client, which is what keeps the three platforms showing the same words.
- [ ] 014-R9: reporting a collision needs the fingerprints of every peer of the channel, which is up to 550 computations of a hash each time the list is drawn. Spec 022-peers-tofu decides whether the short identifier is stored with the peer or recomputed; note it there.

## History

- 2026-09-21 in review
