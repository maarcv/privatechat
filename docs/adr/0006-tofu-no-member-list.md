# ADR 0006 — TOFU: no member list in the config

Date: 2026-09-19 · Status: accepted

## Context
The config could include the list of authorised public keys and reject everything that does not come from them.

## Decision
The config carries no members. When a new public key arrives, the client shows it as "unknown"; the user labels it and, optionally, verifies it by comparing the fingerprint over another channel (Trust On First Use). From then on the client guarantees continuity: same key = same label. The rules for presentation, label reuse and limits are in `docs/spec.md` §7.

## Alternatives considered
- Closed list in the config: an intruder with the config would be rejected silently and nobody would notice the leak; a device change would force redistributing the config.

## Consequences
- An intruder who writes becomes visible.
- Moment zero is the weak point: the UI must clearly show the "unverified" state, must not reuse an existing label for an unverified key, and must make QR pre-verification easy.
- Unknowns can be collapsed and muted in bulk to defend against floods; there is a limit with eviction (§7).
