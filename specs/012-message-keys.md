# 012 — Message keys and encrypted header

Status: in review
Phase: 1
Related ADRs: 0002, 0013, 0018, 0032
Depends on: 010-primitives-wrapper, 011-config-format, 015-test-vectors
Blocks: 013-wire-message, 016-fuzz-harness, 021-channel-session
Human reviewer: Marc Vilardebó · Accepted on: —

## Context

Three keys hang off `K_ch` and never leave the device: the master message key, the header key and, per message, the key that encrypts it (`docs/spec.md` §4 "Keys", ADR 0013, 0018). This spec fixes those derivations, the 40 plaintext bytes of the header that hides from the server who writes and how much (ADR 0018), and the keystream of 104 bytes that encrypts the header and masks the signature of the envelope (ADR 0032).

It defines pure functions only: bytes in, bytes out. The envelope that carries the header, the two XORs that apply the keystream to it and to the signature, and the verification order are spec 013-wire-message; the counters, the peers and every verdict that reads them are spec 021-channel-session. Keeping the derivations here, with their own vectors, is what lets three platforms agree on a byte before any of them has a `Store`.

**PR slices.** One pull request if it fits in 400 lines (AGENTS 14); otherwise two, in this order: (a) `keys.rs` (R1–R3, R6, R7); (b) `header.rs` (R4, R5), with the `header_sealed` vector. The vectors, the script section and the dispatch arms travel with the slice whose tests read them; the spec is marked `implemented` after the last one.

**In plain words.** Every member holds the same channel key. From it each device derives, with fixed labels, two further keys: one to hide the sender and the message number from the server, and one from which the key of each individual message is computed. The first key produces, for each message, 104 bytes of scrambling: the first 40 hide the sender and the message number, the last 64 hide the sender's signature, so the server sees only scrambled bytes and cannot tell who wrote, how many messages each person has sent, or whether a given person signed a given blob. What is done with the scrambled bytes, and how a receiver checks them, is spec 013-wire-message.

## Requirements

- R1 `K_msg` MUST be `kdf_derive(K_ch, "msgkey__")` and `K_hdr` MUST be `kdf_derive(K_ch, "chhdr___")`, with the contexts as the exact 8 ASCII bytes `docs/spec.md` §4 lists, underscores included.
- R2 The message key MUST be `mk = keyed_hash(K_msg, pk_u ‖ BE64(counter))`, over exactly 40 bytes of input: the 32 of the sender's public key followed by the counter as a big-endian unsigned 64-bit integer.
- R3 `mk` MUST be derived from `K_msg`, never from `K_ch`, and MUST exist only as a local `Secret<32>` of the function that seals or opens one message, so that it is wiped when that function returns.
- R4 The plaintext header MUST be the 40 bytes `sender_pk` ‖ BE64(counter). `header_keystream(keys, nonce)` MUST be the 104 bytes of `stream_xor(K_hdr, nonce)` over zeros, with `nonce` the same 24 bytes the envelope carries: bytes 0..40 are what `enc_hdr` is the header XORed with, and bytes 40..104 are what the signature travels XORed with (ADR 0032). The two XORs are applied by `envelope.rs` of spec 013-wire-message, at seal and, in reverse, at verify.
- R5 Neither decoding a header from 40 bytes nor computing the keystream MUST report an error about the key: a wrong `K_hdr` yields a random public key and a random counter, and the signature of spec 013-wire-message is what rejects it. The only error of this spec is `Error::Internal`, when libsodium fails to initialise.
- R6 `K_msg`, `K_hdr` and `mk` MUST be `Secret<32>`, which introduces no new secret type, and every fallible function of this spec MUST return `core::Error`, with the `CryptoError` of spec 010-primitives-wrapper converted through the single mapping of spec 011-config-format (every variant → `Error::Internal`).
- R7 The two 8-byte contexts MUST be named constants next to the code that uses them, equal byte for byte to the literals of `docs/spec.md` §4 and exactly 8 bytes long; changing any of them MUST require a new `proto_version` and an ADR (AGENTS 3).
- R8 This spec MUST add its section to `scripts/reference/vectors.py` of spec 015-test-vectors, which produces `specs/vectors/012.json` from fixed inputs written in the script: the KDF derivations of `K_msg` and `K_hdr` (BLAKE2b through `hashlib`), the message keys of `message_key_*`, and, for `header_sealed`, `K_hdr`, the 104 bytes of its own XChaCha20 keystream, `enc_hdr` as the header XORed with bytes 0..40 and the masked signature as the signature XORed with bytes 40..104.

## Limits

| Input | Range | Out of range |
| --- | --- | --- |
| Plaintext header | exactly 40 B | not constructible (type) |
| `enc_hdr` | exactly 40 B | not constructible (type) |
| Header keystream | exactly 104 B | not constructible (type) |
| KDF context | exactly 8 B | not constructible (type) |

No input of this spec is variable-length, so nothing here can be too long, and nothing here rejects external bytes.

## Interface

```
crates/core/src/proto/keys.rs              ChannelKeys and message_key
crates/core/src/proto/keys/tests.rs        s012_* tests of R1–R3, R6, R7 and the vector dispatch
crates/core/src/proto/header.rs            the 40-byte header and the keystream of 104 bytes
crates/core/src/proto/header/tests.rs      s012_* tests of R4, R5
```

```rust
pub(crate) const CONTEXT_MESSAGE: KdfContext = KdfContext::new(*b"msgkey__");
pub(crate) const CONTEXT_HEADER: KdfContext = KdfContext::new(*b"chhdr___");
pub(crate) const ENC_HDR_LEN: usize = 40;
pub(crate) const HEADER_STREAM_LEN: usize = 104;   // 40 for the header, 64 for the signature mask (ADR 0032)

pub(crate) struct ChannelKeys { pub(crate) msg: Secret<32>, pub(crate) hdr: Secret<32> }   // read by header.rs and envelope.rs

impl ChannelKeys {
    pub(crate) fn derive(channel_key: &Secret<32>) -> Result<ChannelKeys, Error>;
}

/// Returned by value to the one function that seals or opens a message,
/// which keeps it as a local and drops it before returning (R3).
pub(crate) fn message_key(keys: &ChannelKeys, sender_pk: &PublicKey, counter: u64) -> Result<Secret<32>, Error>;

/// The plaintext header; it holds no key and applies no XOR (R4).
pub(crate) struct Header { pub(crate) sender_pk: PublicKey, pub(crate) counter: u64 }

impl Header {
    pub(crate) fn to_bytes(&self) -> [u8; ENC_HDR_LEN];
    pub(crate) fn from_bytes(bytes: &[u8; ENC_HDR_LEN]) -> Header;   // never fails (R5)
}

/// `stream_xor(K_hdr, nonce)` over zeros: bytes 0..40 for the header, 40..104 for the signature (R4).
pub(crate) fn header_keystream(keys: &ChannelKeys, nonce: &Nonce) -> Result<[u8; HEADER_STREAM_LEN], Error>;
```

Every item of this spec is `pub(crate)`, so none of them reaches a caller outside `core`; `ChannelKeys` is the only type with a `Secret<32>` field, and `message_key` returns its key by value, so `mk` is held in no field (R3). `Header::from_bytes` returns a `Header` and never an error (R5): a wrong key is indistinguishable from a right one until the signature is checked. `header_keystream` fails only with `Internal`, when libsodium fails to initialise. The XOR of the header with bytes 0..40 and of the signature with bytes 40..104 live in `envelope.rs` (spec 013-wire-message R4, R16); this spec computes the keystream and nothing else.

`s012_vectors_dispatch` calls `vectors::check_all("012", …)` with one entry per vector and is the only code that loads `012.json` (spec 015-test-vectors R3).

## Security

- Secrets: `K_msg`, `K_hdr` and `mk`, all `Secret<32>`. `mk` is the shortest-lived of the three: it never outlives the call that seals or opens one message (R3).
- `K_hdr` is shared by every member, so two messages of the same channel that drew the same nonce would expose the XOR of their two headers and of their two signatures. With 24 random bytes per message the probability is negligible, and this is the reason the nonce is 24 bytes and not 12.
- The same nonce protects the header under `K_hdr` and the payload under `mk`. The two keystreams are independent because the keys are, and `mk` changes with every counter, so no pair of messages ever reuses a (key, nonce) pair (`docs/spec.md` §4).
- A header that decodes to a random public key is not an error: making it one would tell whoever holds a blob whether they guessed `K_hdr`, which is the oracle ADR 0018 exists to close.
- Masking the signature with bytes 40..104 of the same keystream (ADR 0032) means that without `K_hdr` the envelope carries nothing that can be tested against a known `pk_u`: the server sees the version, the channel, the nonce, the size and random-looking bytes.
- The header has no integrity of its own: anyone can flip bits of `enc_hdr` without a key. The signature of spec 013-wire-message covers `enc_hdr` as it travels and is verified before anything reads the sender or the counter; every verdict that reads them afterwards is spec 021-channel-session's.

## Public API changes

None at the core boundary: every item of this spec is `pub(crate)`.

## Test cases

- T01 (covers R1): `s012_t01_r01_master_keys_known_answer` on the vector `master_keys`; the two contexts give different keys from the same `K_ch`.
- T02 (covers R2): `s012_t02_r02_message_key_known_answer` on the vectors `message_key_*`.
- T03 (covers R2): `s012_t03_r02_message_key_changes_with_every_input`: a different `pk_u`, or a counter that differs by one, gives a different `mk`.
- T04 (covers R3): `s012_t04_r03_message_key_comes_from_k_msg`: `message_key` equals `keyed_hash(keys.msg, pk_u ‖ BE64(counter))` and differs from the same hash keyed with `K_ch`. `ZeroizeOnDrop` of `Secret` is already proven by spec 010-primitives-wrapper; that `mk` is returned by value and held in no field is the Interface.
- T05 (covers R4): `s012_t05_r04_header_and_mask_known_answer` on the vector `header_sealed`: `ChannelKeys::derive` of its `K_ch` gives its `K_hdr`; the header bytes XORed with bytes 0..40 of `header_keystream` give the exact `enc_hdr`, and the signature XORed with bytes 40..104 gives the exact masked signature.
- T06 (covers R4): `s012_t06_r04_header_bytes_round_trip` proptest over every public key and counter: `to_bytes` is the 32 bytes of `sender_pk` followed by BE64(counter), and `from_bytes` of it gives back the same `Header`.
- T07 (covers R5): `s012_t07_r05_a_wrong_key_decodes_without_error`: a keystream under a different `K_hdr` differs in its 104 bytes, and `Header::from_bytes` of `enc_hdr` XORed with it returns a `Header` and no error.
- T08 (covers R6): `s012_t08_r06_no_new_secret_type`: `SECRET_TYPES` holds exactly the types spec 010-primitives-wrapper registered, and the `Debug` of a `ChannelKeys` derived from a known `K_ch` contains the bytes of neither key.
- T09 (covers R7): `s012_t09_r07_contexts_are_the_literals`: the constants are byte for byte the ones of `docs/spec.md` §4 and each is 8 bytes long.
- T10 (covers R8): `check_s012_t10_r08_section_produces_012_json`, the self-check of this spec's section in `scripts/reference/vectors.py`, run by the CI step of spec 015-test-vectors R6: the section writes `012.json` and the file equals the committed one; `cargo test -p privatechat-core s012_` then reproduces every vector (T01, T02, T05).

## Vectors

`specs/vectors/012.json`, schema of `specs/vectors/README.md`, `proto_version = 1`. Produced by this spec's section of the reference script of spec 015-test-vectors from fixed inputs (R8); the Rust tests reproduce every one of them through `check_all`.

| name | kind | source | origin |
| --- | --- | --- | --- |
| `master_keys` | positive | derived | `K_ch` → `K_msg`, `K_hdr` |
| `message_key_c0`, `message_key_c1`, `message_key_max` | positive | derived | counters 0, 1 and 2^64 − 1 with the same `pk_u` |
| `message_key_other_sender` | positive | derived | the same counter with a different `pk_u` |
| `header_sealed` | positive | derived | the `K_ch` of `master_keys`, 40 plaintext bytes, a signature and a nonce → `K_hdr`, `enc_hdr` and the masked signature |

The vectors of this spec are `derived`: every value follows from the formulas of `docs/spec.md` §4 and the primitives of spec 010-primitives-wrapper. `master_keys` and `message_key_*` are BLAKE2b computations and `header_sealed` an XChaCha20 keystream of 104 bytes, all written by the reference script with the Python standard library. This spec has no negative vector: nothing here rejects external input, and its only error, `Internal`, is libsodium failing to initialise (`specs/vectors/README.md`).

## Acceptance criterion

`cargo test -p privatechat-core s012_` green, together with clippy, `cargo deny` and the documentation lint, and the section of the reference script of spec 015-test-vectors producing `012.json` byte for byte as committed. Non-automatable criterion: a human confirms that the three derivations read here match `docs/spec.md` §4 word for word, because a silent divergence here is two clients that cannot read each other.

## Out of scope

- The envelope, the two XORs that apply the keystream to the header and to the signature, the signature, the payload and the order of the checks on receive (spec 013-wire-message), which also defines `KEY_RETIRED_COUNTER`, `EXPIRY_MARGIN_MS` and `ttl_ms` as their first phase 1 user.
- Anti-replay and every verdict that reads state: `check_counter`, `gap`, `next_send_counter`, `own_key_verdict` and `signature_retention_end`, with `max_counter`, the send counter, the peers, the commit that advances them, the own-key echo and the signature retention (`docs/spec.md` §4; spec 021-channel-session owns those functions, next to the state they read, with specs 022-peers-tofu and 024-key-retired).
- The UI of the anomalous jump and of the key-used-elsewhere alert (`docs/spec.md` §7, the client specs).
- Forward secrecy and the epoch jump, which are v2 (`docs/spec.md` §12, ADR 0004).

## Open questions

None open. The former 012-R11 (the own-key verdict: confirmed on 2026-09-24 in audit F, decided by the signature in audit H, ADR 0029) moved with its function to spec 021-channel-session in audit I.

## History

- 2026-09-21 in review
- 2026-09-24 revised after audit E (docs/audit-log.md)
- 2026-09-24 revised after audit F (docs/audit-log.md)
- 2026-09-24 revised after audit H (`docs/audit-log.md`): the own-key echo is decided by the signature (ADR 0029), one's own key has no `max_counter`; the counter tables become unit tables; `header_sealed` recomputed by the reference script; one dispatch test; round 4: the header keystream is 104 bytes and its last 64 mask the signature (ADR 0032); round 5: the echo compares unmasked signatures, `header_sealed` derives its keys from `K_ch`, T18 checks the keystream buffer; round 6: `KEY_RETIRED_COUNTER` and no gap for a `key_retired` (ADR 0033), the margin and `ttl_ms` defined here for 013, `ChannelKeys` fields readable by `header.rs`; round 7: `ChannelKeys` fields `pub(crate)` for the generator; round 9: no signature kept under a retired key; round 10: PR slices, the keystream buffer rule dropped
- 2026-09-24 revised after audit I (`docs/audit-log.md`): the spec is keys and header only; `check_counter`, `gap`, `next_send_counter`, `own_key_verdict`, `signature_retention_end`, `replay.rs` and the rules for the caller move to spec 021-channel-session, and `KEY_RETIRED_COUNTER`, `EXPIRY_MARGIN_MS` and `ttl_ms` to spec 013-wire-message; one `header_keystream` of 104 bytes replaces `Header::seal`, `Header::open` and `mask_signature`, `Header` is a plain `to_bytes`/`from_bytes`; the reference script produces the vectors and the Rust tests reproduce them, `s012_vectors_dispatch` stated in the Interface; visibility and constructor statements moved from requirements to the Interface and their source-scan tests dropped; one or two PR slices
