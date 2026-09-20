# ADR 0010 — Server authentication with a per-channel Ed25519 key pair

Date: 2026-09-19 · Status: accepted

## Context
To subscribe to a channel over WebSocket, something must be proven to the server without creating accounts or revealing user identities. Review A1 (2026-09-19): the proposal preceding this ADR, `HMAC(K_auth, nonce)` with a shared token, was rejected before the repository was created because it forced the server to know and store `K_auth`; it has no ADR of its own.

## Decision
The client derives a **channel** Ed25519 key pair from `K_ch` (`docs/spec.md` §4). On connecting, the server sends a `server_nonce`; the client sends `pk_ch`, `ttl_seconds` and a signature with `sk_ch` over a domain-tagged message that includes the nonce, the `channel_id`, the TTL and the server host name (§6). The server recomputes `channel_id` from `(pk_ch, ttl_seconds)` and verifies the signature.

## Alternatives considered
- HMAC with a shared token: the server has to store a secret per channel and a registration step is needed.
- Authenticating with the user's Ed25519 key: would give the server the full map of which key is in which channels.
- Classic accounts: incompatible with the goal of zero knowledge of identities.

## Consequences
What the signature protects, exactly:
- (a) Whoever lacks the config cannot subscribe (see blobs, size classes, timings) nor publish.
- (b) The server stores no secret and no channel table: self-certifying `channel_id`, zero state, no prior registration; a channel "exists" while it has unexpired messages or subscribers.
- (c) The credential is **not reusable** by whoever sees it: server, TLS proxy, logs or a dump of the server's DB do not allow subscribing. A bearer token derived from `K_ch` would be simpler but would lose this, and would make security depend on the proxy's log discipline.
- (d) `host` inside the signature prevents a server from relaying a subscription to another deployment with the same config.

Other:
- All members share `sk_ch`: the signature proves having the config, not who one is; that is why `publish` is bound to the connection's subscription and there are quotas (§6).
- The client does not send `channel_id` in `subscribe`: the server recomputes it and returns it in `ok`.
- Review C (2026-09-20): replacing it with a bearer token was evaluated and it was kept because of (c) and (d).
