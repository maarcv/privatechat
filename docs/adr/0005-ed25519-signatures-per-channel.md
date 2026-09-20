# ADR 0005 — Ed25519 signatures per message, with a key per user and per channel

Date: 2026-09-19 · Status: accepted

## Context
With only the channel key, anyone who has it can send messages posing as any name. Authenticity is needed, not just confidentiality.

## Decision
Each user generates an Ed25519 key pair for each channel when importing the config. Each message is signed with this key over all the fields of the envelope. The public key travels in the envelope, encrypted under `K_hdr` (ADR 0018), and serves as the local identity (ADR 0006).

## Alternatives considered
- A global identity key per user: would allow linking the same person across channels, both for the members and for the server.
- MAC with a pairwise shared key (deniability, as Signal does): gives messages that cannot be proven to third parties, but requires a key for each pair of members and complicates the TOFU model.

## Consequences
- Verifiable authenticity: two messages with the same `pk` come from the same device.
- No identity link between channels.
- Messages are non-repudiable: a signature proves that the key holder wrote it. Documented as a known limitation.
