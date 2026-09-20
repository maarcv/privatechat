# ADR 0018 — Message header encrypted with the channel key

Date: 2026-09-20 · Status: accepted

## Context
With `sender_pk` and `counter` in the clear in the envelope, and `publish` bound to the connection's authenticated subscription (§6), the server obtained for each message `(channel_id, sender_pk, counter, size, time, IP)`: a perfect and permanent pseudonym per member, bound to an IP. It could count writers, see each one's activity and schedule, detect key regenerations (old pk goes quiet, new pk is born with `counter = 0` from the same IP) and censor a specific member. A seized disk contained up to 30 days of this record. The sentence "the server cannot link it to anything" was false (review C, finding C1).

## Decision
The 40 bytes `sender_pk ‖ counter` of the envelope are encrypted with `crypto_stream_xchacha20_xor` under `K_hdr = KDF(K_ch, "chhdr___")`, shared by all members, using the same random `nonce` of the envelope. The blob size does not change; the offsets do not change; the AAD is still `blob[0..81]` as it travels. The receiver decrypts the header in one step and follows the same verification flow (§4). The header has no authentication of its own: the signature covers the whole blob, and a header decrypted with a wrong `K_hdr` yields a random `pk` with which the signature fails.

## Alternatives considered
- Leaving `sender_pk` in the clear and documenting it: zero cost, but the server keeps the pseudonym↔IP record.
- Rotating sender identifier derived from `K_send` and `counter`: the receiver needs a `tag → (peer, counter)` table or a linear search, and an alternative format for the first message of an unknown `pk`. Two formats, more state, more fuzzing.
- Trial decryption per peer: unnecessary, because all members have `K_ch` and a single shared key decrypts the header.

## Consequences
- The server sees `channel_id`, the size class, the time and the connection's IP. It does not know who writes, how many write, or how much. Nor does a seized disk.
- Zero server changes (it did not parse `sender_pk`). It cannot verify the envelope signature, and it does not need to: `publish` is already bound to the subscription.
- One more KDF context (`chhdr___`) and one 40 B `crypto_stream_xchacha20_xor` per message.
- A `nonce` collision under `K_hdr` between two messages of the channel (2^-192) would leak the XOR of two headers; negligible.
- With a fixed home IP the IP is still a noisy pseudonym; with CGNAT or Tor the server no longer has anything per member.
- Affected specs: 012-message-keys, 013-wire-message, 015-test-vectors.
