# 012 — Message keys, encrypted header and anti-replay

Status: in review
Phase: 1
Related ADRs: 0002, 0013, 0018, 0019
Depends on: 010-primitives-wrapper, 011-config-format
Blocks: 013-wire-message, 015-test-vectors, 021-channel-session, 022-peers-tofu
Human reviewer: Marc Vilardebó · Accepted on: —

## Context

Three keys hang off `K_ch` and never leave the device: the master message key, the header key and, per message, the key that encrypts it (`docs/spec.md` §4 "Keys", ADR 0013, 0018). This spec fixes those derivations, the encrypted header that hides from the server who writes and how much (ADR 0018), and the anti-replay rule that makes a resent blob detectable without a window or a bitmap (ADR 0019).

It defines pure functions and one decision function: bytes in, bytes or a verdict out. Where the counters and the peers are stored, and in which commit they advance, is spec 021-channel-session and spec 022-peers-tofu; the envelope that carries all this is spec 013-wire-message. Keeping the derivations here, with their own vectors, is what lets three platforms agree on a byte before any of them has a `Store`.

## Requirements

- R1 `K_msg` MUST be `kdf_derive(K_ch, "msgkey__")` and `K_hdr` MUST be `kdf_derive(K_ch, "chhdr___")`, with the contexts as the exact 8 ASCII bytes `docs/spec.md` §4 lists, underscores included.
- R2 The message key MUST be `mk = keyed_hash(K_msg, pk_u ‖ BE64(counter))`, over exactly 40 bytes of input: the 32 of the sender's public key followed by the counter as a big-endian unsigned 64-bit integer.
- R3 `mk` MUST be derived from `K_msg`, never from `K_ch`, and MUST be zeroized after the message is encrypted or decrypted, in the same function that derived it.
- R4 The plaintext header MUST be the 40 bytes `sender_pk` ‖ BE64(counter), and `enc_hdr` MUST be that header transformed with `stream_xor(K_hdr, nonce)`, with `nonce` the same 24 bytes the envelope carries.
- R5 Decrypting a header MUST apply `stream_xor` with the same key and nonce to the 40 bytes of `enc_hdr` and MUST NOT report any error of its own: a wrong `K_hdr` yields a random public key and a random counter, and the signature of spec 013-wire-message is what rejects it.
- R6 The anti-replay state per public key MUST be a single `max_counter: Option<u64>`, with no window and no bitmap.
- R7 A counter lower than or equal to `max_counter` MUST be rejected as `Error::Replay`; a counter above it MUST be accepted, and `max_counter` MUST advance to it only after the payload has been authenticated, whatever the payload then turns out to contain.
- R8 The first message of an unknown key MUST be accepted at any counter, and `max_counter` MUST then be that counter.
- R9 The gap reported for a sender MUST be `counter.saturating_sub(max_counter.saturating_add(1))`, and a gap above 2^32 MUST be flagged as an anomalous jump (`docs/spec.md` §4, §7).
- R10 The send counter MUST start at 0, MUST be strictly increasing for each `sk_u`, and reaching 2^64 − 1 MUST return `Error::CounterExhausted` instead of wrapping.
- R11 A message whose `sender_pk` equals one's own `pk_u` and whose counter is at or above one's own send counter MUST raise the `OwnKeyUsedElsewhere` event and MUST move the send counter to `counter + 1`; the echo of one's own message, whose counter is below it, MUST be `Error::Replay` (`docs/spec.md` §4).
- R12 Every derivation of this spec MUST be a pure function of its inputs: no clock, no randomness, no state. The only randomness of a message is its nonce, which spec 013-wire-message draws.
- R13 `K_msg`, `K_hdr` and `mk` MUST live in `Secret<32>`, MUST be listed in `SECRET_TYPES`, and no function of this spec MUST return one of them to a caller outside `core`.
- R14 The 8-byte contexts and the derivation formulas MUST be named constants next to the code that uses them, and changing any of them MUST require a new `proto_version` and an ADR (AGENTS 3).

## Limits

| Input | Range | Out of range |
| --- | --- | --- |
| `counter` | 0..=2^64 − 2 for sending | 2^64 − 1 → `CounterExhausted` |
| `counter` on receive | 0..=2^64 − 1 | `≤ max_counter` → `Replay` |
| Plaintext header | exactly 40 B | not constructible (type) |
| `enc_hdr` | exactly 40 B | not constructible (type) |
| KDF context | exactly 8 B | not constructible (type) |
| Gap flagged as anomalous | > 2^32 | — |

No input of this spec is variable-length, so nothing here can be too long.

## Interface

```
crates/core/src/proto/keys.rs          the three derivations
crates/core/src/proto/header.rs        the 40-byte header, sealed and open
crates/core/src/proto/replay.rs        the anti-replay decision
crates/core/src/proto/tests.rs         s012_* tests
```

```rust
pub(crate) const CONTEXT_MESSAGE: KdfContext = KdfContext::new(*b"msgkey__");
pub(crate) const CONTEXT_HEADER: KdfContext = KdfContext::new(*b"chhdr___");
pub(crate) const HEADER_LEN: usize = 40;

pub(crate) struct Header { pub(crate) sender_pk: PublicKey, pub(crate) counter: u64 }

pub(crate) fn message_master_key(channel_key: &Secret<32>) -> Result<Secret<32>, CryptoError>;
pub(crate) fn header_key(channel_key: &Secret<32>) -> Result<Secret<32>, CryptoError>;
pub(crate) fn message_key(master: &Secret<32>, sender_pk: &PublicKey, counter: u64) -> Result<Secret<32>, CryptoError>;

impl Header {
    pub(crate) fn seal(&self, key: &Secret<32>, nonce: &Nonce) -> Result<[u8; HEADER_LEN], CryptoError>;
    pub(crate) fn open(sealed: &[u8; HEADER_LEN], key: &Secret<32>, nonce: &Nonce) -> Result<Header, CryptoError>;
}

/// `Ok(())` when the counter may be accepted; the caller advances the state
/// only after the payload is authenticated (R7).
pub(crate) fn check_counter(max_counter: Option<u64>, counter: u64) -> Result<(), Error>;
pub(crate) fn gap(max_counter: Option<u64>, counter: u64) -> u64;
```

`Header::open` returns a `Header` and never an error of its own (R5): a wrong key is indistinguishable from a right one until the signature is checked.

## Security

- Secrets: `K_msg`, `K_hdr` and `mk`, all `Secret<32>`. `mk` is the shortest-lived of the three and is zeroized by the function that derived it (R3).
- `K_hdr` is shared by every member, so two messages of the same channel that drew the same nonce would expose the XOR of their two headers. With 24 random bytes per message the probability is negligible, and this is the reason the nonce is 24 bytes and not 12.
- The same nonce protects the header under `K_hdr` and the payload under `mk`. The two keystreams are independent because the keys are, and `mk` changes with every counter, so no pair of messages ever reuses a (key, nonce) pair (`docs/spec.md` §4).
- A header that decrypts to a random public key is not an error: making it one would tell whoever holds a blob whether they guessed `K_hdr`, which is the oracle ADR 0018 exists to close.
- Anti-replay is state, not cryptography: it works because a key lives on one device and the server delivers a total order (ADR 0019). The `Replay` verdict is local and never reaches the network (`docs/spec.md` §4 "No-oracle rule").

## Public API changes

None at the core boundary. `Error::Replay`, `Error::CounterExhausted` and the `OwnKeyUsedElsewhere` event are already in `docs/spec.md` §9; the types of this spec are `pub(crate)`.

## Test cases

- T01 (covers R1): `s012_t01_r01_master_keys_known_answer` on the vectors; the two contexts give different keys from the same `K_ch`.
- T02 (covers R2): `s012_t02_r02_message_key_known_answer` on the vectors; `s012_t03_r02_message_key_changes_with_every_input`: a different `pk_u`, or a counter that differs by one, gives a different `mk`.
- T04 (covers R3): `s012_t04_r03_message_key_is_zeroized`: after the call that used it, the buffer that held `mk` is all zeros.
- T05 (covers R4): `s012_t05_r04_header_known_answer` on the vector: 40 plaintext bytes and a nonce give the exact `enc_hdr`.
- T06 (covers R5): `s012_t06_r05_header_round_trip` proptest over every public key and counter; `s012_t07_r05_a_wrong_key_opens_without_error`: a different `K_hdr` returns a `Header` and no error.
- T08 (covers R6, R7): `s012_t08_r06_replay_table`: for `max_counter` of `None`, 0 and 7, the counters 0, 7, 8 and 2^64 − 1 give the verdict the specification fixes, as a table.
- T09 (covers R8): `s012_t09_r08_first_message_is_accepted_at_any_counter`: `None` with counter 2^63 is accepted.
- T10 (covers R9): `s012_t10_r09_gap_table`, including `max_counter = None`, a gap of 0 and one above 2^32.
- T11 (covers R10): `s012_t11_r10_counter_exhaustion`: sending at 2^64 − 1 → `CounterExhausted` and nothing is sealed.
- T12 (covers R11): `s012_t12_r11_own_key_used_elsewhere`: a counter at and above one's own send counter raises the event and moves the counter; one below is `Replay`.
- T13 (covers R12): `s012_t13_r12_derivations_are_pure`: the same inputs give the same outputs a thousand times, and the functions take no `now`.
- T14 (covers R13): `s012_t14_r13_keys_are_redacted`: the `Debug` of each new secret type is `[REDACTED]` and `SECRET_TYPES` lists them.
- T15 (covers R14): `s012_t15_r14_contexts_are_the_literals`: the constants are byte for byte the ones of `docs/spec.md` §4.

## Vectors

`specs/vectors/012.json`, schema of `specs/vectors/README.md`, `proto_version = 1`. Produced by the core, and from then on frozen (AGENTS 18).

| name | kind | source | origin |
| --- | --- | --- | --- |
| `master_keys` | positive | derived | `K_ch` → `K_msg`, `K_hdr` |
| `message_key_c0`, `message_key_c1`, `message_key_max` | positive | derived | counters 0, 1 and 2^64 − 2 with the same `pk_u` |
| `message_key_other_sender` | positive | derived | the same counter with a different `pk_u` |
| `header_sealed` | positive | derived | 40 plaintext bytes, a nonce and `K_hdr` → `enc_hdr` |
| `replay_table` | negative | derived | the pairs `(max_counter, counter)` of T08 with their verdict and `commits = 0` |

The vectors of this spec are `derived`: every value follows from the formulas of `docs/spec.md` §4 and the primitives of spec 010-primitives-wrapper, so any implementation can recompute them by hand.

## Acceptance criterion

`cargo test -p privatechat-core s012_` green, together with clippy, `cargo deny` and the documentation lint. Non-automatable criterion: a human confirms that the three derivations read here match `docs/spec.md` §4 word for word, because a silent divergence here is two clients that cannot read each other and no test outside the vectors would catch it.

## Out of scope

- The envelope, its signature, the payload and the order of the checks on receive (spec 013-wire-message).
- Where `max_counter`, the send counter and the peers live, and the commit that advances them (specs 021-channel-session, 022-peers-tofu).
- The UI of the anomalous jump and of the key-used-elsewhere alert (`docs/spec.md` §7, the client specs).
- Forward secrecy and the epoch jump, which are v2 (`docs/spec.md` §12, ADR 0004).

## Open questions

- [ ] 012-R7: the state advances after authentication, so a message that is authentic but unreadable — an unknown payload type, broken CBOR — still consumes its counter. This is what `docs/spec.md` §4 fixes, and it is what stops a resend from being retried forever, but it also means a sender who ships a malformed payload burns that counter for every receiver. Confirm.
- [ ] 012-R11: moving one's own send counter to `counter + 1` on detecting the key elsewhere keeps the victim able to write, and it also means two devices with the same key can chase each other upwards without either failing. The alternative, locking the channel read-only at once, is safer and louder. `docs/spec.md` §4 chose the first; confirm against §7 "Key-used-elsewhere alert".

## History

- 2026-09-21 in review
