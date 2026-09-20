# ADR 0014 — TTL bound to the `channel_id` and per-message expiry

Date: 2026-09-20 · Status: accepted

## Context
The server must know when to delete each blob without storing any secret or any channel table. The initial rule ("if different TTLs arrive for the same `pk_ch`, the smallest wins") allowed anyone with the config —member or intruder— to set `ttl = 60 s` and destroy the retention of the whole channel for everyone, for free, indistinguishably and irreversibly (finding B5). Moreover, the implicitly created `channels` table was never deleted.

## Decision
`channel_id = BLAKE2b("privatechat/chid/v1" ‖ pk_ch ‖ BE32(ttl_seconds))[0..16]`. The TTL is part of the channel's identity: a different TTL is a different channel where nobody listens. The server recomputes `channel_id` from the `(pk_ch, ttl_seconds)` received in the signed subscription, checks the range, and for each `publish` stores `expires_at = received_at + ttl_seconds`. There is no channel table; a channel exists while it has unexpired messages or subscribers.

## Alternatives considered
- Per-channel TTL with "the smallest wins": trivial DoS.
- Per-channel TTL with "the first wins": a malicious server can fake a first TTL; clients cannot verify it.
- Per-message TTL according to the publisher's subscription, without binding it to the `channel_id`: avoids the DoS, but lets a member with a modified client keep their messages on the server longer than the channel has agreed.

## Consequences
- No member can change the TTL of an existing channel; changing it means creating a new channel (consistent with ADR 0008).
- The server has only one table, `messages`, with an index on `expires_at`.
- The client keeps enforcing its own expiry (`min(received_at, now_local) + ttl_seconds`), ADR 0009.
- Affected specs: 011-config-format, 031-auth-channel-signature, 032-storage-ttl.
