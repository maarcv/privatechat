# ADR 0038 — Allow a plain `ws://` server URL for `.onion` hosts only

Date: 2026-09-25 · Status: accepted

## Context
`docs/spec.md` §1, §2 and §6 promise that a server can be published as a Tor onion service, and `deploy/` is to ship a `torrc` for it (spec 034-docker). But the `server_url` grammar of spec 011-config-format R5 accepts only `wss://`, and a TLS certificate for a `.onion` name comes only from the few authorities that issue them, for a fee. A self-hosted operator cannot use a self-signed one, because the clients validate certificates normally and pin none. In practice, then, `.onion` support would exist only on paper. An onion service already encrypts the connection end to end and authenticates the server: the address is derived from the service's public key. TLS on top adds nothing. The question came up while drafting the phase 3 specs (`docs/audit-log.md`, "Phase 3 drafts", P2).

## Decision
`server_url` also accepts `ws://` ‖ a v3 onion host (56 characters of `a-z2-7`, then `.onion`) ‖ optional `:` port (never 80), and a client opens such a URL with no TLS, always through the SOCKS5 proxy it already requires for every `.onion` host (spec 027-core-api R10).

## Alternatives considered
- Keep `wss://` only and ask the operator to buy a `.onion` certificate: no protocol change, but almost no operator would do it, and the promise of §1 would stay empty.
- Drop the onion service from v1 and reach the public domain through Tor: simpler, but a Tor exit node then sees the server's address, and the operator cannot hide where the server runs.
- Allow `ws://` for any host: this would put plaintext WebSocket on the open network, which the model forbids.

## Consequences
- Spec 011-config-format R5 gains the `ws://` branch, restricted to v3 onion hosts, and R6 `host()` returns the onion host the same way. A `wss://` onion URL stays valid for an operator who has a certificate.
- The plan of spec 027-core-api groups channels by scheme, host and port, and `Route` gains `tls: bool`, so `ws://x.onion` and `wss://x.onion` never share a socket. The clients (specs 050–052) skip TLS only when `tls` is false, and `tls` is false only for a `.onion` host behind the proxy.
- The subscription signature (spec 031-auth-channel-signature) covers the host with no scheme, as before, and `channel_id` does not depend on `server_url`: a config moved to the other scheme names the same channel and the same host. Only the route's `tls` changes, and the two schemes never share a socket.
- The server gets a second listener for the onion service, which carries no client address (specs 033-rate-limit-quotas, 035-server-ops), and `deploy/torrc` maps `HiddenServicePort 80` to it (spec 034-docker).
- `docs/spec.md` §5, §6 and §12 describe the two schemes.
