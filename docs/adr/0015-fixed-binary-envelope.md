# ADR 0015 — Fixed-size binary envelope; CBOR only in the encrypted payload

Date: 2026-09-20 · Status: accepted

## Context
The first version defined the message envelope as "canonical CBOR" and the signature "over all the preceding fields". `ciborium` does not implement the deterministic profile of RFC 8949 §4.2, and "all the preceding fields" admits several serialisations: the signed bytes were not defined and the test vectors would not be reproducible by a third party (finding B2). An envelope with seven fields, six of them fixed-size, does not need CBOR.

## Decision
The envelope is a fixed-offset binary format (`docs/spec.md` §4): `proto_version` (1) ‖ `channel_id` (16) ‖ `enc_hdr` (40: `sender_pk` ‖ `counter` u64 BE, encrypted as per ADR 0018) ‖ `nonce` (24) ‖ `ciphertext` (16 + 1 024·k) ‖ `signature` (64). The AAD is the first 81 bytes; the signature, with a domain tag, covers everything except itself (*encrypt-then-sign*). CBOR remains only inside the encrypted payload and in the client-server protocol messages, where the exact encoding is not relevant to security.

## Alternatives considered
- CBOR with a hand-implemented deterministic profile: more own code on the critical path and no advantage for a fixed-size envelope.
- Protobuf or similar: a new dependency with no need for it.
- *Sign-then-encrypt*: would force decrypting before rejecting, and the receiver must be able to discard cheaply.

## Consequences
- Complete hex test vectors in `specs/vectors/013.json`, verifiable with any libsodium implementation.
- The server can validate the wrapper (length, version, `channel_id`) without parsing anything. It cannot verify the signature (it does not see `sender_pk`), and it does not need to.
- Sizes: minimum blob 1 185 B, maximum 64 673 B; maximum plaintext payload 64 511 B.
- V2 is `proto_version = 2` with its own header; no fields are reserved.
- Affected specs: 013-wire-message, 015-test-vectors, 030-ws-protocol.
