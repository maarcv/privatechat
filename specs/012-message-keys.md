# 012 — Message keys, encrypted header and anti-replay

Status: in review
Phase: 1
Related ADRs: 0002, 0013, 0018, 0019, 0027
Depends on: 010-primitives-wrapper, 011-config-format, 015-test-vectors
Blocks: 013-wire-message, 016-fuzz-harness, 021-channel-session, 022-peers-tofu
Human reviewer: Marc Vilardebó · Accepted on: —

## Context

Three keys hang off `K_ch` and never leave the device: the master message key, the header key and, per message, the key that encrypts it (`docs/spec.md` §4 "Keys", ADR 0013, 0018). This spec fixes those derivations, the encrypted header that hides from the server who writes and how much (ADR 0018), and the anti-replay rule that makes a resent blob detectable without a window or a bitmap (ADR 0019).

It defines pure functions only: bytes in, bytes or a verdict out. Where the counters and the peers are stored, and in which commit they advance, is spec 021-channel-session and spec 022-peers-tofu; the envelope that carries all this is spec 013-wire-message. Keeping the derivations here, with their own vectors, is what lets three platforms agree on a byte before any of them has a `Store`.

**Rules for the caller.** The decision functions of this spec cannot see how they are called, so three rules of `docs/spec.md` §4 bind their caller, spec 021-channel-session, and are tested there, not here:

- `check_counter`, `gap` and `own_key_verdict` run only on a header whose signature has been verified (step 4, ADR 0027).
- `max_counter` advances to the counter only once the message is consumed and is not stale (step 7); a message opened as `Stale` never advances it.
- `gap` is evaluated only for a message that is consumed and not stale.

**In plain words.** Every member holds the same channel key. From it each device derives, with fixed labels, two further keys: one to hide the sender and the message number from the server, and one from which the key of each individual message is computed. The server sees only scrambled bytes, so it cannot tell who wrote or how many messages each person has sent. Each sender numbers its messages 0, 1, 2… and a receiver remembers the highest number it has accepted from that sender; anything at or below it is a resend and is refused. None of these checks reads a number before the signature of spec 013-wire-message has proved who wrote it, and a message kept past its lifetime moves no number at all (ADR 0027).

## Requirements

- R1 `K_msg` MUST be `kdf_derive(K_ch, "msgkey__")` and `K_hdr` MUST be `kdf_derive(K_ch, "chhdr___")`, with the contexts as the exact 8 ASCII bytes `docs/spec.md` §4 lists, underscores included.
- R2 The message key MUST be `mk = keyed_hash(K_msg, pk_u ‖ BE64(counter))`, over exactly 40 bytes of input: the 32 of the sender's public key followed by the counter as a big-endian unsigned 64-bit integer.
- R3 `mk` MUST be derived from `K_msg`, never from `K_ch`, MUST exist only as a local `Secret<32>` of the function that seals or opens one message, and MUST NOT be stored in a field of any type, so that it is wiped when that function returns.
- R4 The plaintext header MUST be the 40 bytes `sender_pk` ‖ BE64(counter), and `enc_hdr` MUST be that header transformed with `stream_xor(K_hdr, nonce)`, with `nonce` the same 24 bytes the envelope carries.
- R5 Opening a header MUST apply `stream_xor` with the same key and nonce to the 40 bytes of `enc_hdr` and MUST NOT report any error of its own: a wrong `K_hdr` yields a random public key and a random counter, and the signature of spec 013-wire-message is what rejects it.
- R6 The anti-replay state per public key MUST be a single `max_counter: Option<u64>`, with no window and no bitmap.
- R7 `check_counter` MUST return `Error::Replay` for a counter lower than or equal to `max_counter` and `Ok` for a counter above it.
- R8 With `max_counter = None` (an unknown key, or one evicted), `check_counter` MUST accept any counter, including 0 and 2^64 − 1.
- R9 `gap` MUST return `missing = counter.saturating_sub(max_counter + 1)` for `Some(max_counter)`, computed without overflow, and `missing = 0` for `None`; `anomalous` MUST be true exactly when `missing > 2^32`.
- R10 `next_send_counter` MUST return `current + 1` for `current` below 2^64 − 1, and `Error::CounterExhausted` for `current = 2^64 − 1`, instead of wrapping.
- R11 `own_key_verdict(send_counter, counter, stale)` MUST return `OwnKey::Echo` when `counter < send_counter`, which the caller reports as `Error::Replay`; otherwise `OwnKey::UsedElsewhere` with `advance` equal to `Advance::Unchanged` when `stale` is true (the event is raised and no counter moves, ADR 0027), `Advance::To(counter + 1)` for a counter below 2^64 − 1, and `Advance::Exhausted` for `counter = 2^64 − 1` (`docs/spec.md` §4 "Messages from one's own key").
- R12 `K_msg`, `K_hdr` and `mk` MUST be `Secret<32>`, which introduces no new secret type, and every item of this spec MUST be `pub(crate)`, so that none of them can reach a caller outside `core`. Every function of this spec MUST return `core::Error`, with the `CryptoError` of spec 010-primitives-wrapper converted through the single mapping of spec 011-config-format (`InitFailed`, `OutOfMemory`, `TooLong` and `BadLength` → `Error::Internal`).
- R13 The two 8-byte contexts MUST be named constants next to the code that uses them, equal byte for byte to the literals of `docs/spec.md` §4 and exactly 8 bytes long; changing any of them MUST require a new `proto_version` and an ADR (AGENTS 3).
- R14 This spec MUST add its section to the generator `crates/core/src/vectors/generate.rs` and to the reference script `scripts/reference/vectors.py` of spec 015-test-vectors: the KDF derivations of `K_msg` and `K_hdr`, the message keys, and the replay, gap and own-key tables. The script MUST recompute every one of them; `header_sealed` stays covered by the published XChaCha20 vectors of spec 010-primitives-wrapper.

## Limits

| Input | Range | Out of range |
| --- | --- | --- |
| `current` send counter | 0..=2^64 − 2 | 2^64 − 1 → `CounterExhausted` |
| `counter` on receive | 0..=2^64 − 1 | `≤ max_counter` → `Replay` |
| Plaintext header | exactly 40 B | not constructible (type) |
| `enc_hdr` | exactly 40 B | not constructible (type) |
| KDF context | exactly 8 B | not constructible (type) |
| Gap flagged as anomalous | > 2^32 | — |

No input of this spec is variable-length, so nothing here can be too long.

Why 2^32: a sender writing one message every second would need 136 years to move its counter by 2^32. A jump larger than that did not come from normal use; the likeliest cause is someone else writing with the key and a counter chosen by hand.

## Interface

```
crates/core/src/proto/keys.rs              ChannelKeys and message_key
crates/core/src/proto/keys/tests.rs        s012_* tests of R1–R3, R12–R14
crates/core/src/proto/header.rs            the 40-byte header, sealed and opened
crates/core/src/proto/header/tests.rs      s012_* tests of R4, R5
crates/core/src/proto/replay.rs            check_counter, gap, next_send_counter, own_key_verdict
crates/core/src/proto/replay/tests.rs      s012_* tests of R6–R11 and the vector dispatch
```

```rust
pub(crate) const CONTEXT_MESSAGE: KdfContext = KdfContext::new(*b"msgkey__");
pub(crate) const CONTEXT_HEADER: KdfContext = KdfContext::new(*b"chhdr___");
pub(crate) const ENC_HDR_LEN: usize = 40;
pub(crate) const ANOMALOUS_GAP: u64 = 1 << 32;

pub(crate) struct ChannelKeys { msg: Secret<32>, hdr: Secret<32> }

impl ChannelKeys {
    pub(crate) fn derive(channel_key: &Secret<32>) -> Result<ChannelKeys, Error>;
}

/// Returned by value to the one function that seals or opens a message,
/// which keeps it as a local and drops it before returning (R3).
pub(crate) fn message_key(keys: &ChannelKeys, sender_pk: &PublicKey, counter: u64) -> Result<Secret<32>, Error>;

pub(crate) struct Header { pub(crate) sender_pk: PublicKey, pub(crate) counter: u64 }

impl Header {
    pub(crate) fn seal(&self, keys: &ChannelKeys, nonce: &Nonce) -> Result<[u8; ENC_HDR_LEN], Error>;
    pub(crate) fn open(sealed: &[u8; ENC_HDR_LEN], keys: &ChannelKeys, nonce: &Nonce) -> Result<Header, Error>;
}

/// Not the boundary `Gap` record of `docs/spec.md` §9, which spec 021 builds from this.
pub(crate) struct CounterGap { pub(crate) missing: u64, pub(crate) anomalous: bool }
pub(crate) enum OwnKey { Echo, UsedElsewhere { advance: Advance } }
pub(crate) enum Advance { To(u64), Exhausted, Unchanged }

pub(crate) fn check_counter(max_counter: Option<u64>, counter: u64) -> Result<(), Error>;
pub(crate) fn gap(max_counter: Option<u64>, counter: u64) -> CounterGap;
pub(crate) fn next_send_counter(current: u64) -> Result<u64, Error>;
pub(crate) fn own_key_verdict(send_counter: u64, counter: u64, stale: bool) -> OwnKey;
```

`Header::open` returns a `Header` and never an error of its own (R5): a wrong key is indistinguishable from a right one until the signature is checked. Its only possible error is `Internal`, when libsodium fails to initialise.

## Security

- Secrets: `K_msg`, `K_hdr` and `mk`, all `Secret<32>`. `mk` is the shortest-lived of the three: it never outlives the call that seals or opens one message (R3).
- `K_hdr` is shared by every member, so two messages of the same channel that drew the same nonce would expose the XOR of their two headers. With 24 random bytes per message the probability is negligible, and this is the reason the nonce is 24 bytes and not 12.
- The same nonce protects the header under `K_hdr` and the payload under `mk`. The two keystreams are independent because the keys are, and `mk` changes with every counter, so no pair of messages ever reuses a (key, nonce) pair (`docs/spec.md` §4).
- A header that opens to a random public key is not an error: making it one would tell whoever holds a blob whether they guessed `K_hdr`, which is the oracle ADR 0018 exists to close.
- The header has no integrity of its own: anyone can flip bits of `enc_hdr` without a key. This is why every decision function here runs only after the signature has been verified (Context, ADR 0027): a forged counter can neither trigger `Replay` for a real sender, nor raise a false anomalous jump, nor move one's own send counter.
- A thief holding a member's key can sign a message with a counter near 2^64 and a `sent_at` from years ago. Such a message is stale, so it moves no `max_counter` anywhere, and when it reaches the victim `own_key_verdict` still reports it without moving the victim's counter (R11). The thief can neither silence the victim nor stay unnoticed (ADR 0027, audit C5).
- Anti-replay is state, not cryptography: it works because a key lives on one device and the server delivers a total order (ADR 0019). The `Replay` verdict is local and never reaches the network (`docs/spec.md` §4 "No-oracle rule").

## Public API changes

None at the core boundary. `Error::Replay`, `Error::CounterExhausted` and the `OwnKeyUsedElsewhere` event are already in `docs/spec.md` §9; every item of this spec is `pub(crate)`.

## Test cases

- T01 (covers R1): `s012_t01_r01_master_keys_known_answer` on the vector `master_keys`; the two contexts give different keys from the same `K_ch`.
- T02 (covers R2): `s012_t02_r02_message_key_known_answer` on the vectors `message_key_*`.
- T03 (covers R2): `s012_t03_r02_message_key_changes_with_every_input`: a different `pk_u`, or a counter that differs by one, gives a different `mk`.
- T04 (covers R3): `s012_t04_r03_message_key_is_never_stored`: `proto/keys.rs`, `proto/header.rs`, `proto/envelope.rs` and `proto/payload.rs` declare no field of type `Secret<32>` outside `ChannelKeys`, and `message_key` is called only from the seal and open functions of spec 013-wire-message. `ZeroizeOnDrop` of `Secret` is already proven by spec 010-primitives-wrapper.
- T05 (covers R4): `s012_t05_r04_header_known_answer` on the vector `header_sealed`: 40 plaintext bytes and a nonce give the exact `enc_hdr`.
- T06 (covers R5): `s012_t06_r05_header_round_trip` proptest over every public key and counter.
- T07 (covers R5): `s012_t07_r05_a_wrong_key_opens_without_error`: a different `K_hdr` returns a `Header` and no error.
- T08 (covers R6): `s012_t08_r06_state_is_one_option`: `check_counter` and `gap` take `Option<u64>` and nothing else of state.
- T09 (covers R7): `s012_t09_r07_replay_table` on the vector `replay_table`: for `max_counter` of 0 and 7, the counters 0, 7, 8 and 2^64 − 1 give the verdict the specification fixes.
- T10 (covers R8): `s012_t10_r08_unknown_key_accepts_any_counter`: `None` with counters 0, 2^63 and 2^64 − 1 is accepted.
- T11 (covers R9): `s012_t11_r09_gap_table` on the vector `gap_table`: `None`, a gap of 0, a gap of exactly 2^32 (not anomalous), 2^32 + 1 (anomalous), and `max_counter = 2^64 − 1` with no overflow.
- T12 (covers R10): `s012_t12_r10_counter_exhaustion`: 0 → 1, 2^64 − 2 → 2^64 − 1, and 2^64 − 1 → `CounterExhausted`.
- T13 (covers R11): `s012_t13_r11_own_key_verdict_table` on the vector `own_key_table`: a counter below, equal to and above the send counter; `counter = 2^64 − 1` → `Advance::Exhausted`; and every non-echo case with `stale = true` → `Advance::Unchanged`, including `counter = 2^64 − 2`.
- T14 (covers R12): `s012_t14_r12_no_new_secret_type_and_one_error`: `SECRET_TYPES` is unchanged by this spec, no item of `proto/keys.rs`, `proto/header.rs` or `proto/replay.rs` is `pub`, and no function of those files returns `CryptoError`.
- T15 (covers R13): `s012_t15_r13_contexts_are_the_literals`: the constants are byte for byte the ones of `docs/spec.md` §4 and each is 8 bytes long.
- T16 (covers R14): `s012_t16_r14_generator_section`: the generator's section for spec 012 produces `012.json` byte for byte, and the reference script's output for the same section is equal to it.
- T17 (covers R1, R2, R4, R7, R9, R11): `s012_t17_r01_every_vector_is_checked`: the only code that loads `012.json`. It loops over every vector with one match arm per name, each arm calling the checker of its test above, and a fallback arm that fails the test, so an unknown or unused vector fails (spec 015-test-vectors).

## Vectors

`specs/vectors/012.json`, schema of `specs/vectors/README.md`, `proto_version = 1`. Every 64-bit value (counters) is a 16-character big-endian hex string. Produced by the generator of spec 015-test-vectors, cross-checked by its reference script (R14), and frozen when phase 1 closes (AGENTS 18).

| name | kind | source | origin |
| --- | --- | --- | --- |
| `master_keys` | positive | derived | `K_ch` → `K_msg`, `K_hdr` |
| `message_key_c0`, `message_key_c1`, `message_key_max` | positive | derived | counters 0, 1 and 2^64 − 1 with the same `pk_u` |
| `message_key_other_sender` | positive | derived | the same counter with a different `pk_u` |
| `header_sealed` | positive | derived | 40 plaintext bytes, a nonce and `K_hdr` → `enc_hdr` |
| `replay_table` | negative | derived | the pairs `(max_counter, counter)` of T09 with their verdict |
| `gap_table` | positive | derived | the pairs of T11 → `missing`, `anomalous` |
| `own_key_table` | positive | derived | the triples `(send_counter, counter, stale)` of T13 → verdict |

The vectors of this spec are `derived`: every value follows from the formulas of `docs/spec.md` §4 and the primitives of spec 010-primitives-wrapper. `master_keys` and `message_key_*` are BLAKE2b computations and the three tables are plain arithmetic, all recomputed by the reference script with the Python standard library; the header uses XChaCha20, already covered by the published vectors of spec 010-primitives-wrapper.

## Acceptance criterion

`cargo test -p privatechat-core s012_` green, together with clippy, `cargo deny` and the documentation lint, and the reference script of spec 015-test-vectors agreeing with `012.json`. Non-automatable criterion: a human confirms that the three derivations read here match `docs/spec.md` §4 word for word, because a silent divergence here is two clients that cannot read each other.

## Out of scope

- The envelope, its signature, the payload and the order of the checks on receive (spec 013-wire-message).
- The rules for the caller listed in the Context, where `max_counter`, the send counter and the peers live, the commit that advances them, the `OwnKeyUsedElsewhere` event and the read-only state after one's own `key_retired` (specs 021-channel-session, 022-peers-tofu, 024-key-retired).
- The UI of the anomalous jump and of the key-used-elsewhere alert (`docs/spec.md` §7, the client specs).
- Forward secrecy and the epoch jump, which are v2 (`docs/spec.md` §12, ADR 0004).

## Open questions

None open. 012-R11 was confirmed on 2026-09-24 (audit F): on detecting its own key elsewhere, the device raises its send counter and the alert, as `docs/spec.md` §4 says. Locking the channel read-only instead would hand a thief a way to silence the victim, which is what audit C5 closed.

## History

- 2026-09-21 in review
- 2026-09-24 revised after audit E (docs/audit-log.md)
- 2026-09-24 revised after audit F (docs/audit-log.md)
