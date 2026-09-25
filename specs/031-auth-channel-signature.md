# 031 — Subscription authentication with the channel signature

Status: draft
Phase: 3
Related ADRs: 0010, 0014, 0022, 0038
Depends on: 010-primitives-wrapper, 011-config-format, 015-test-vectors, 016-fuzz-harness, 027-core-api, 028-session-sans-io
Blocks: 030-ws-protocol, 033-rate-limit-quotas
Human reviewer: Marc Vilardebó · Accepted on: —

## Context

The server has no accounts (`docs/spec.md` §1). Before it relays or stores anything for a channel, a connection must prove that it holds that channel's config, and the proof must be useless to anyone who sees it: the server, a proxy, a log (ADR 0010). §4 derives the channel's Ed25519 key pair from `K_ch`, and `channel_id` from its public half and the TTL. §6 "Authentication" has the client sign the server's fresh nonce, the `channel_id`, the TTL and the host. The server recomputes `channel_id` from `pk_ch` and `ttl_seconds`, so the identifier certifies itself, and verifies the signature with `core::crypto`. It stores nothing.

Spec 028-session-sans-io R6 already builds the signature on the client. This spec adds the server's side. It adds to `core` one builder of the signed message, which both sides use, and one `pub` verifier for the server. It fixes the nonce's lifetime and the rules for failed attempts, and it writes the vectors both sides reproduce.

**In plain words.** Every member's app can compute the same "channel key pair" from the config. When the server says hello with a random number, the app signs that number together with the channel's id, its message lifetime and the server's name. The server can check the signature with the public half the app sends, and it can check that this public half really gives that channel id. It learns nothing it could reuse: the next connection gets a new random number, so a copied signature is worthless. The server's name is inside the signature, so a signature made for one server cannot be replayed to another.

## Requirements

**The signed message**

- R1 On every new connection, and after every `error{nonce_expired}` (R5), the server MUST send `hello{server_nonce, proto_versions = [1]}` with a nonce from `relay::new_nonce`, which MUST draw 32 bytes with `random_bytes` of spec 010-primitives-wrapper. Only the latest nonce of a connection is valid, and only for 60 000 ms of the server's clock from the moment its `hello` was queued.
- R2 `core` MUST build the signed message in one crate-internal function, `auth_message(server_nonce, channel_id, ttl_seconds, host)`, which returns the 19 ASCII bytes `privatechat/auth/v1` ‖ `server_nonce` (32 bytes) ‖ `channel_id` (16 bytes) ‖ BE32(`ttl_seconds`) ‖ the bytes of `host`. The subscribe of spec 028-session-sans-io R6 MUST sign the output of this function, and this spec MUST amend 028 R6 to say so. The tag MUST be the named constant `AUTH_TAG`, equal to the literal of `docs/spec.md` §4.
- R3 `relay::channel_id(pk_ch, ttl_seconds)` MUST return the `channel_id` of spec 011-config-format R8 through the same function `Config` uses. This spec MUST amend spec 011 so that R8's derivation is that one function, `ChannelId::derive(pk_ch, ttl_seconds)`.
- R4 `relay::verify_subscribe(pk_ch, ttl_seconds, sig, server_nonce, hosts)` MUST return `Error::BadConfig` when `ttl_seconds` is outside 60..=2 592 000 or `hosts` holds no host or more than 8. Otherwise it MUST derive `channel_id` as R3 does and try `verify_detached(pk_ch, auth_message(server_nonce, channel_id, ttl_seconds, host), sig)` of spec 010-primitives-wrapper for each host in order, returning `Ok(channel_id)` at the first success and `Error::BadSignature` when none succeeds.

**The server**

- R5 On a `subscribe`, the server MUST compute `relay::channel_id(pk_ch, ttl_seconds)` to name the channel in its answer. Then, in this order: a nonce older than 60 000 ms MUST get `error{nonce_expired, channel_id}` followed by a new `hello`; a `BadConfig` from `verify_subscribe` MUST get `error{bad_ttl, channel_id}`; a `BadSignature` MUST get `error{bad_auth, channel_id}`. `Ok` hands the channel to spec 030-ws-protocol R7 with `ttl_seconds` and `since`. The rate check of spec 033-rate-limit-quotas runs before all of these.
- R6 A `bad_ttl` or `bad_auth` MUST count as a failed attempt, and a `nonce_expired` or `rate_limited` MUST NOT. After sending the error of the third failed attempt on a connection, the server MUST close it with status 1008.
- R7 A connection with no accepted `subscribe` within 60 000 ms of its first `hello` MUST be closed with status 1008 and no frame. After its first accepted `subscribe`, a connection has no such deadline.
- R8 The server MUST pass as `hosts` the hosts of its configured URLs (spec 035-server-ops), each obtained with `relay::url_host`, which MUST return `Config::host()` of a config with that `server_url` through the grammar of spec 011-config-format R5 (the one URL parser of the workspace), and `Error::BadConfig` for a URL outside it. The server MUST NOT read the host from the `Host` header or from the socket.
- R9 The server MUST keep, per accepted subscription, only `channel_id` and `ttl_seconds`, and MUST NOT keep `pk_ch`, `sig` or an expired nonce past the call that checks them.

**Vectors and fuzzing**

- R10 This spec MUST add its section to `scripts/reference/vectors.py` of spec 015-test-vectors. The section writes `specs/vectors/031.json`: from fixed `K_ch`, TTLs, nonces and URLs, it derives `pk_ch` through the RFC 8032 §6 reference code and `crypto_kdf_derive_from_key`, computes `channel_id`, the host, the message of R2 and its signature, and writes every negative of the table "Vectors" with its error. The Rust tests of this spec reproduce the file on the server path, and those of spec 028 on the client path.
- R11 This spec MUST amend spec 016-fuzz-harness R2 with the target `relay_verify_subscribe`. Its input is `pk_ch` (32) ‖ BE32(`ttl_seconds`) ‖ `sig` (64) ‖ `server_nonce` (32) ‖ host, the host truncated to 250 bytes, and `hosts` is that host followed by `example.org`. Its corpus comes from `031.json`. A proptest MUST check the round trip: for any `K_ch`, any TTL in range, any nonce and any URL of the grammar, `verify_subscribe` of the subscribe that spec 028 R6 builds returns `Ok` with the config's `channel_id`.

## Limits

| Input | Range | Out of range |
| --- | --- | --- |
| `ttl_seconds` | 60..=2 592 000 | `bad_ttl`, a failed attempt |
| `sig` | 64 B that verify under `pk_ch` over R2's message for one configured host | `bad_auth`, a failed attempt |
| `pk_ch` | 32 B; a non-canonical or small-order key fails the verification (spec 010) | `bad_auth`, a failed attempt |
| Nonce age | ≤ 60 000 ms from its `hello` | `nonce_expired` and a new `hello` |
| Failed attempts per connection | ≤ 2 | third → error, then close 1008 |
| First accepted `subscribe` | ≤ 60 000 ms after the first `hello` | close 1008 |
| `hosts` | 1..=8 hosts of the grammar of spec 011 R5 | `BadConfig`; the server does not start (spec 035) |
| Host in the signed message | 1..=250 B (the URL grammar bounds it) | not reachable |

## Interface

```
crates/core/src/proto/auth.rs            AUTH_TAG, auth_message (R2)
crates/core/src/proto/auth/tests.rs      s031_* core tests, 031.json
crates/core/src/relay.rs                 new_nonce, channel_id, verify_subscribe, url_host (R1, R3, R4, R8)
crates/core/fuzz/fuzz_targets/relay_verify_subscribe.rs
crates/server/src/auth.rs                nonce, attempt count and deadline per connection (R1, R5–R7, R9)
crates/server/src/tests/auth.rs          s031_* server tests
scripts/reference/vectors.py             the section of R10
specs/vectors/031.json
```

```rust
pub(crate) const AUTH_TAG: &[u8; 19] = b"privatechat/auth/v1";
pub(crate) fn auth_message(server_nonce: &[u8; 32], channel_id: &ChannelId, ttl_seconds: u32, host: &str) -> Vec<u8>;

impl ChannelId {   // amends spec 011-config-format R8
    pub(crate) fn derive(pk_ch: &PublicKey, ttl_seconds: u32) -> Result<ChannelId, Error>;
}

pub mod relay {   // `pub`, for the server only (spec 027-core-api)
    pub fn new_nonce() -> Result<[u8; 32], Error>;                                   // Internal if libsodium fails
    pub fn channel_id(pk_ch: &[u8; 32], ttl_seconds: u32) -> Result<[u8; 16], Error>;
    pub fn verify_subscribe(pk_ch: &[u8; 32], ttl_seconds: u32, sig: &[u8; 64],
                            server_nonce: &[u8; 32], hosts: &[String]) -> Result<[u8; 16], Error>; // BadConfig, BadSignature
    pub fn url_host(server_url: &str) -> Result<String, Error>;                                       // BadConfig
}

// server, crate-internal
pub(crate) struct AuthState { nonce: [u8; 32], hello_at: u64, first_hello_at: u64, failed: u8, accepted_any: bool }
```

The subscription signature is `sign_detached(sk_ch, auth_message(…))`, computed only by the client (spec 028 R6). The server holds no signing key.

## Security

- The credential binds the nonce, so it cannot be replayed on another connection or after 60 s. It binds `channel_id` and the TTL, so it cannot open another channel or move this one to another TTL (ADR 0014). It binds the host, so a malicious server cannot relay it to another server as a live login.
- `channel_id` certifies itself: the server derives it from `pk_ch` and never takes it from the client.
- Up to 8 hosts means up to 8 signature checks per `subscribe`. The attempt rate of spec 033 (one per second per connection) and the close on the third failure bound that cost.
- Nothing about the credential outlives its check (R9), and spec 035-server-ops keeps it out of the logs. A seized server therefore holds no proof of who subscribed, only the metadata of `docs/spec.md` §2.
- `error{bad_auth}` and `error{bad_ttl}` name the `channel_id` the client sent in effect. They tell the client nothing it does not already know.
- R8 reads the host from the operator's configuration, never from the request. A proxy or a client cannot pick which host is checked.

## Public API changes

- `core` gains `relay::{new_nonce, channel_id, verify_subscribe, url_host}`, `pub` for the server only (spec 027-core-api list and `api_surface.rs`). The bindings do not wrap them.
- Spec 011-config-format R8 is amended to derive `channel_id` through `ChannelId::derive`, and spec 028-session-sans-io R6 to sign the output of `auth_message`. Neither change alters a byte.
- `docs/spec.md` §6, brought up to date when this spec is accepted: the order of the three errors, the failed-attempt count, and the check of the host against every configured URL.

## Test cases

- T01 (covers R1): `s031_t01_r01_nonce_lifetime`: the first frame is a `hello` with 32 random bytes, and two connections get different nonces; a `subscribe` signed with it 59 999 ms later → accepted; 60 001 ms later → `nonce_expired` naming the channel, then a new `hello` with a different nonce; a `subscribe` signed with the old nonce after that → `bad_auth`.
- T02 (covers R2): `s031_t02_r02_auth_message`: `auth_message` of `auth_reference` equals the vector's `message`; `AUTH_TAG` is 19 bytes and equals the §4 literal; the subscribe that spec 028 R6 builds for the vector's config and nonce carries the vector's `sig` (Ed25519 is deterministic).
- T03 (covers R3): `s031_t03_r03_channel_id`: `relay::channel_id` of each positive vector equals its `channel_id` and `Config::channel_id()` of the same config.
- T04 (covers R4): `s031_t04_r04_verify_subscribe`: every positive of `031.json` → `Ok(channel_id)`; `auth_ttl_59` and `auth_ttl_2592001` → `BadConfig` before any signature check; `auth_wrong_host`, `auth_wrong_nonce`, `auth_flipped_sig` and `auth_other_ttl` → `BadSignature`; the host matching only the third of three configured hosts → `Ok`; nine hosts, or none → `BadConfig`.
- T05 (covers R5): `s031_t05_r05_server_answers`: over a socket, a valid `subscribe` → the backlog and `ok`; each negative vector sent as a frame → the error of the table "Vectors" naming the vector's `channel_id`; an expired nonce with a bad signature too → `nonce_expired` (the age is checked first).
- T06 (covers R6): `s031_t06_r06_three_failures_close`: two `bad_auth` and one `nonce_expired` → still open; a third `bad_auth` → the error, then close 1008; `bad_ttl`, `bad_auth`, `bad_ttl` → close after the third.
- T07 (covers R7): `s031_t07_r07_first_subscribe_deadline`: no `subscribe` for 60 001 ms → close 1008 with no frame; an accepted `subscribe` at 30 000 ms, then silence for 10 minutes with pongs answered → still open.
- T08 (covers R8): `s031_t08_r08_hosts_from_config`: configured URLs `wss://chat.example.org` and `ws://<56 chars>.onion` → a signature over either host is accepted; over `chat.example.org:9001` → `bad_auth`; a `Host` header naming another host changes nothing; `url_host` of `wss://h:9001` → `h`, and of `wss://h/` → `BadConfig`.
- T09 (covers R9): `s031_t09_r09_nothing_kept`: after an accepted subscribe, the connection's state holds the `channel_id` and the TTL and no field of 32 or 64 bytes other than the current nonce (a `Debug` of the state, checked against `pk_ch` and `sig` in hex).
- T10 (covers R10): `s031_t10_r10_vectors_reproduced`: every vector of `031.json` is reproduced by `auth_message`, `relay::channel_id` and `verify_subscribe`; the CI step of spec 015 regenerates `031.json` byte for byte.
- T11 (covers R11): `s031_t11_r11_round_trip_and_fuzz`: the proptest of R11; `scripts/check_fuzz_targets.sh` lists `relay_verify_subscribe`; its seeds reach `verify_detached`.

## Vectors

`specs/vectors/031.json`, all `derived`, written by the reference script (R10):

| Name | Kind | Expected |
| --- | --- | --- |
| `auth_reference` | positive | `pk_ch`, `channel_id`, `host`, `message`, `sig` for `wss://chat.example.org`, TTL 86 400 |
| `auth_url_with_port` | positive | the same channel on `wss://chat.example.org:9001`: `host` is `chat.example.org`, and the signature equals `auth_reference`'s |
| `auth_onion_ws` | positive | a `ws://` onion URL (ADR 0038): the host is the onion name |
| `auth_ttl_ends` | positive | TTL 60 and 2 592 000, two different `channel_id`s |
| `auth_wrong_host` | negative | `BadSignature` (`bad_auth`) |
| `auth_wrong_nonce` | negative | `BadSignature` (`bad_auth`) |
| `auth_flipped_sig` | negative | `BadSignature` (`bad_auth`) |
| `auth_other_ttl` | negative | signed for TTL 60, sent with TTL 61 → `BadSignature` (`bad_auth`) |
| `auth_ttl_59`, `auth_ttl_2592001` | negative | `BadConfig` (`bad_ttl`) |

The strict Ed25519 negatives stay in `010.json` and are not repeated.

## Acceptance criterion

`cargo test -p privatechat-core s031_` and `cargo test -p privatechat-server s031_` green; the reference script regenerates `031.json` byte for byte; the `relay_verify_subscribe` target builds and runs nightly; clippy and `scripts/doc_lint.sh` green. The implementation pull request touches `crates/core/src/proto/**` and carries `adr-not-needed` ("implements accepted spec 031, no format change").

## Out of scope

- Building the `subscribe` frame and pacing it (spec 028-session-sans-io R6, R7).
- The one-attempt-per-second rule and the 16-channel cap (spec 033-rate-limit-quotas).
- What happens after an accepted subscribe: backlog, `ok`, publish (spec 030-ws-protocol).
- Reading the configured URLs (spec 035-server-ops).

## Open questions

None.

## History

- 2026-09-25 draft
