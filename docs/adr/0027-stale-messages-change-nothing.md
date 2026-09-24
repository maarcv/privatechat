# ADR 0027 — Verify the signature before any state; a stale message changes nothing but the cursor

Date: 2026-09-24 · Status: accepted · Supersedes: 0024

## Context
ADR 0024 moved the signature check ahead of every state check. It also discarded, as `Expired`, a consumed message whose signed `sent_at` was older than the TTL plus a margin. Audit F (`docs/audit-log.md`, F1–F4) found three problems in how that rule was written:

- **It silenced a victim.** The stale rule still advanced the sender's `max_counter` but raised no own-key alert. A thief holding a member's key could send one message with `counter = 2^64 − 2` and `sent_at = 0`. Every receiver would consume it silently, and from then on every real message of the victim would be `Replay`, with no alert anywhere. `sent_at` is chosen by the signer, so a stale message is not only something a server produces (F-B1, a regression of audit C5).
- **It ran after `validate`.** A stale message with an unknown `type` or an invalid field became `Unreadable` instead. It was then persisted, and could create a peer and evict another, so a server could still revive expired messages that way (F-B2).
- **Step 2 had no margin for the receiver's clock.** A receiver clock ahead of the server by more than the TTL (61 s in a 60 s channel) rejected every live blob. The cursor then moved past them, so they were lost for good (F-B4).

## Decision
The order of `docs/spec.md` §4 "Verification on receive" stands: length, version and channel; expiry; open header; signature; retired key and peer limit; replay; AEAD. No step before the signature reads state or has any effect.

Both expiry checks carry the same margin of 360 000 ms, which covers the rounding of `sent_at` to the minute plus five minutes of skew:
- Step 2 rejects when `min(received_at, now) + ttl_ms + 360 000 < now`.
- After the AEAD, as soon as the payload frames and `sent_at` can be read, and before the `type` check and `validate`, a message with `sent_at + ttl_ms + 360 000 < min(received_at, now)` is **stale**.

A stale message is discarded as `Expired` and changes nothing but the cursor: no `max_counter`, no peer, no eviction, no send counter. The one exception is a message from one's own key with `counter ≥` send counter, which also persists `OwnKeyUsedElsewhere`, so a stolen key is still reported (widened by ADR 0029 to every message from one's own key this device did not seal).

## Alternatives considered
- ADR 0024 as written: a thief can silence a member with one message.
- Advancing `max_counter` but also raising the own-key alert: the victim would be warned, but every other receiver would still discard the victim's messages until the victim regenerates their key.
- Checking only `received_at`: trusts the server with the one promise it is not trusted with (ADR 0009).

## Consequences
- Nothing an attacker writes into an unauthenticated field decides anything. Every mutated byte of a well-formed blob yields `BadSignature` in `verify`, whatever the receiver's state.
- Replaying a stale blob is harmless: it stays stale, because `now` only grows.
- A message that is authentic, readable and fresh is the only kind that moves `max_counter`, besides an `Unreadable` message that is not stale.
- A sender or receiver clock off by more than five minutes loses messages in channels whose TTL is shorter than the offset (a message left in the `outbox` past its TTL is handled by ADR 0034). The warning of §6 for a `sent_at` more than five minutes off makes the skew visible.
- Affected specs: 013-wire-message, 021-channel-session, 022-peers-tofu, 023-ttl-purge, 026-peer-limits.
