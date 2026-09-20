# ADR 0004 — No post-compromise security in v1

Date: 2026-09-19 · Status: accepted

## Context
With ADR 0001 and 0013, whoever obtains `K_ch` can read the whole channel, past and future, indefinitely. V1 has neither cryptographic forward secrecy nor post-compromise security (review B, 2026-09-20).

## Decision
V1 does not attempt to recover security after a config leak nor to protect the messages prior to a leak. The response is the compromise alarm (ADR 0011), key retirement (ADR 0016) and creating a new channel (ADR 0008). This is stated explicitly in the public documentation (`docs/spec.md` §1).

## Alternatives considered
- "Epoch jump" now: each member publishes a signed ephemeral X25519 key; every N messages or days, the new `K_ch` is derived from the old one plus the DHs between active members. Gives FS and PCS at once, but complicates the format and the handling of inactive members. Reserved for v2 (`docs/spec.md` §12).
- Symmetric ratchet without DH: gives neither FS nor PCS in this model (ADR 0003, 0013).

## Consequences
- Maximum simplicity in v1.
- V2 will be `proto_version = 2` with its own header; no fields are reserved in v1 and receivers reject unknown versions.
- To be revisited for v2.
