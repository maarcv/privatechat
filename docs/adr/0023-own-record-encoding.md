# ADR 0023 — Fixed binary envelope and an own record encoding; no CBOR

Date: 2026-09-24 · Status: accepted · Supersedes: 0015

## Context
ADR 0015 fixed the envelope as a binary format of fixed offsets and kept CBOR (`ciborium` + `serde`) for the payload, the config, the client-server messages and, through ADR 0021, the local files. Audit E (`docs/audit-log.md` E1) found that the pair adds about nine third-party crates to `core`, which would be the first external code to parse bytes an attacker controls. It does not remove our own code either. `ciborium` accepts tags, indefinite lengths, non-minimal integers and mixed key types, so a strict profile, a hand-written serialiser for integer keys and visitors for byte fields would have to be written on top of it anyway (findings E-B11, E-C14, E-C15, E-C16). Every structure the protocol carries is a small, flat or shallow record with a known schema. None of them needs a general-purpose format.

## Decision
The envelope stays exactly as ADR 0015 fixed it (`docs/spec.md` §4). Every other structure — payload, config, client-server messages, `state.bin`, `messages.log` records and `settings.bin` — is a **record** in the encoding of `docs/spec.md` §4 "Record encoding": a sequence of fields `key` u8 ‖ `len` u32 BE ‖ `value`, keys strictly increasing, each value typed by the schema of its key. Decoding is typed and never builds a generic tree. `core` implements it once (spec 017-record-encoding), with no dependency.

## Alternatives considered
- Keep CBOR with `ciborium` and `serde`: about nine crates, the first external parser on the hostile path, and a strict profile we would still have to write and fuzz ourselves.
- A hand-written CBOR subset: all the grammar of CBOR we do not need (major types, tags, floats, indefinite lengths) in order to call it a standard we would not fully implement.
- Protobuf or similar: a code generator and a runtime crate, for records of four to eight fields.
- A fixed layout for every structure, like the envelope: the payload and the client-server messages need optional fields and room for fields added in v1.x without a `proto_version` change.

## Consequences
- `core` keeps exactly two dependencies, `libsodium-sys-stable` and `zeroize` (spec 010-primitives-wrapper, T25 unchanged). No `serde` or `thiserror` in `core`; its `Error` is written by hand.
- One canonical encoding per value: strictly increasing keys, exact integer widths and no trailing bytes. Two decoders can never disagree on what one record says, and vectors are byte-reproducible by anyone who reads §4.
- The encoding is ours, so it is ours to get right. It is about 150 lines, it has its own spec, fuzz target and round-trip property test (specs 017-record-encoding and 016-fuzz-harness), and its vectors are produced by the independent reference script of spec 015-test-vectors and reproduced by the tests.
- Standard CBOR tools can no longer inspect these bytes. The format is described in full in §4, which is what a reviewer reads instead.
- ADR 0012 ("CBOR payload (`ciborium`)") and ADR 0021 (`CBOR(state)`, `CBOR(record)`) are read with "record encoding of ADR 0023" in place of CBOR. Their other decisions are unchanged.
- Affected specs: 011-config-format, 013-wire-message, 015-test-vectors, 016-fuzz-harness, 017-record-encoding, 020-store-files, 030-ws-protocol.
