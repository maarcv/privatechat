# ADR 0030 — Treat a message dated more than one TTL in the future as stale

Date: 2026-09-24 · Status: accepted

## Context
ADR 0027 makes a consumed message stale when its signed `sent_at` is older than the TTL plus 360 000 ms, so that a server cannot revive an expired message. It sets no upper bound. Audit H (`docs/audit-log.md`, H7) found that a blob signed with a `sent_at` far in the future — by a sender whose clock runs ahead, or by a thief holding a key — never becomes stale: the server can keep it and hand it with a fresh `received_at` to every new member for as long as the date is ahead, which breaks the promise of §1 that expired messages are deleted by the channel's TTL.

A bound of only five minutes would close that too, but a sender clock ahead of the receiver's by more than five minutes would then lose every message in every channel, silently. ADR 0027 already accepts losses from clock skew only when the skew exceeds the TTL.

## Decision
A consumed message is also stale when `now + ttl_ms + 360 000 < sent_at`, with the receiver's `now` and saturating arithmetic, and is treated exactly as ADR 0027 treats a stale message.

## Alternatives considered
- No upper bound: a server can revive a future-dated blob without limit.
- `sent_at > now + 360 000`: tighter, but any clock more than five minutes off loses all its messages in every channel.
- Using `received_at` for the bound: the server chooses it, and the server is the adversary this rule exists for.

## Consequences
- With `T = ttl_ms + 360 000`, a blob is acceptable only while `now` lies in `[sent_at − T, sent_at + 2T]`: a blob minted with the latest date allowed stays deliverable for at most about three TTLs plus eighteen minutes after it was minted, instead of without limit.
- A signed blob whose `sent_at` cannot be read (broken padding or framing before key 2) is `Unreadable` and never stale, so a server can keep handing it to new members; only a non-conforming signer can produce one, and it carries no content.
- Clock skew loses messages only in the cases ADR 0027 already accepts: an offset larger than the TTL.
- Affected specs: 013-wire-message, 021-channel-session, 023-ttl-purge.
