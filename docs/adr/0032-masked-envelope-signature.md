# ADR 0032 — Mask the envelope signature with the header keystream

Date: 2026-09-24 · Status: accepted

## Context
ADR 0018 encrypts `sender_pk` and `counter` so that the server "does not know who writes, how many write, or how much". The 64-byte Ed25519 signature at the end of the envelope still travels in the clear. `docs/spec.md` §2 treats a member's `pk_u` as public: the verification QR carries it in plain base64url and "is not secret". Audit H (`docs/audit-log.md`, H35) found that whoever holds one member's `pk_u` — from a photographed QR, a screenshot, or a member — can check that signature against every stored and future blob of the channel without any key, and so learn exactly which blobs that member wrote and how many. A server given one QR recovers what ADR 0018 hides.

## Decision
The signature travels masked with the bytes that follow the header in the same keystream: the receiver computes 104 bytes of `crypto_stream_xchacha20(K_hdr, nonce)`, the first 40 open `enc_hdr` and the last 64 unmask the signature, which is then verified exactly as before over the unchanged signed range. The exact layout is `docs/spec.md` §4.

## Alternatives considered
- Documenting the leak and treating the verification QR as sensitive: the QR is shown and scanned in person by design, and any member already holds every `pk_u`; the promise of §2 would depend on nobody ever passing a key along.
- Encrypting the signature with the AEAD: the signature covers the ciphertext, so it cannot sit inside it; a second AEAD adds a tag and a key for no gain.
- A separate KDF context for the mask: the header keystream is already secret to the server and unique per nonce, so a second key adds a derivation and nothing else.

## Consequences
- Without `K_hdr` the envelope carries nothing that can be tested against a known `pk_u`; the server sees the version, the channel, the nonce, the size and random-looking bytes.
- Sizes, offsets, the signed range and the mutation table are unchanged: a flipped signature byte is still `BadSignature`.
- One `stream_xor` of 104 bytes instead of 40 per message. A nonce collision under `K_hdr` (2^-192) would now also leak the XOR of two signatures; negligible, as in ADR 0018.
- The own-key echo of ADR 0029 compares the unmasked signature.
- Extends ADR 0018. Affected specs: 012-message-keys, 013-wire-message, 016-fuzz-harness.
