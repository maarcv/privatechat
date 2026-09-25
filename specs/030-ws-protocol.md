# 030 — WebSocket protocol: the server's connections, subscriptions, order and fan-out

Status: draft
Phase: 3
Related ADRs: 0010, 0014, 0017, 0020, 0022, 0023, 0038
Depends on: 013-wire-message, 016-fuzz-harness, 027-core-api, 028-session-sans-io, 031-auth-channel-signature, 032-storage-ttl
Blocks: 033-rate-limit-quotas, 035-server-ops
Human reviewer: Marc Vilardebó · Accepted on: —

## Context

The server is a mailbox with a TTL (`docs/spec.md` §6). It stores opaque blobs per `channel_id`, relays them over WebSocket and deletes them. It has no users, validates no content, and knows neither `K_ch` nor any other secret. Spec 028-session-sans-io wrote the client half of the protocol and fixed the frames and the server contract of its R4. This spec is the server half: the HTTP route, the WebSocket connection, the frames the server reads and writes, how a subscription catches up on its backlog before it goes live, and how a published blob becomes an `ack` and a `push` to every subscriber in one total order.

Three neighbours hold the rest. Spec 031-auth-channel-signature checks the `subscribe` frame and owns the nonce. Spec 032-storage-ttl owns the SQLite table, the single writer and the purge. Spec 033-rate-limit-quotas owns every limit of the table "Limits and quotas" in §6. This spec calls them and repeats none of their rules. Configuration, client addresses, logging and shutdown are spec 035-server-ops.

The server touches the protocol only through `pub` functions of `core` (AGENTS 2, `docs/spec.md` §9): `Frame::encode` and `Frame::decode` of spec 028, and the `relay` module that specs 030, 031 and 032 add, each with the items it uses first. It verifies no message signature and decrypts nothing.

**In plain words.** A phone connects, and the server greets it with a random number. The phone proves it holds each channel's config (spec 031). For each channel, the server first sends everything the phone has not seen yet, oldest first, and then says "ok, you are up to date". A message that arrives while that backlog is being sent waits in line until the "ok", so nothing can overtake the backlog. When someone publishes, the server checks only the size and the first bytes of the blob. It stores the blob, says "stored" to the sender and hands the blob to everyone listening on that channel, the sender included. Every listener gets the blobs in the same order. Anything the server cannot follow makes it hang up, and the phone reconnects from where it stopped.

**Implementation order of phase 3.** The specs are numbered by topic and implemented by dependency, as in phase 1: 032-storage-ttl → 031-auth-channel-signature → 030-ws-protocol → 033-rate-limit-quotas → 035-server-ops → 034-docker. The storage and the signature check can be tested alone. This spec needs both. The limits wrap the connection, operation wraps the whole binary, and the image packages the result.

**PR slices** (AGENTS 14): (a) `relay::check_blob` of R2, its property test and fuzz target, and the `deny.toml` entries of R1; (b) the route, the handshake and frame reading (R3–R6); (c) subscriptions, catch-up and disconnect (R7–R10, R15); (d) publish, fan-out and the frames sent (R11–R14).

## Requirements

**Crate and core**

- R1 `deny.toml` MUST allow `sha1` only under the wrappers `axum` and `tungstenite`, and MUST add `tungstenite` to the wrappers of `rand`. The WebSocket handshake of RFC 6455 hashes `Sec-WebSocket-Key` with SHA-1, which protects nothing here, and tungstenite draws client frame masks with `rand`, which the server never sends. No other crate may bring either in.
- R2 The `relay` module of `core` MUST expose `check_blob(blob, channel_id)`, which runs exactly the checks of spec 013-wire-message R2 (length, version, channel) through the same function `verify` calls, and nothing else. This spec MUST amend spec 027-core-api (the items `pub` for `server`) with it, and spec 016-fuzz-harness R2 with the target `relay_check_blob`, whose input is `channel_id` (16 bytes) ‖ blob and whose corpus comes from the blobs of `013.json`.

**Handshake and frames**

- R3 The server MUST answer a WebSocket upgrade only for `GET /`. Any other path or method MUST get HTTP 404 with an empty body, and a request that carries an `Origin` header MUST get HTTP 403 with an empty body (no browser client in v1, ADR 0017). The server MUST negotiate no WebSocket extension and no subprotocol.
- R4 A message or frame longer than 70 000 bytes MUST close the connection with status 1009, and a text message MUST close it with status 1003.
- R5 The server's first frame on every connection MUST be the `hello` of spec 031-auth-channel-signature R1.
- R6 Every binary message MUST be decoded with `Frame::decode`. A decoding failure, or a frame of a type no client sends (`hello`, `ok`, `ack`, `push`, `error`), MUST close the connection with status 1008 and no `error` frame.

**Subscriptions**

- R7 Once spec 031-auth-channel-signature accepts a `subscribe`, the server MUST register the subscription as catching up before it reads any stored blob. It MUST then send as `push`es, in `received_at` order, the channel's stored blobs with `received_at ≥ s` and `expires_at > now`, where `s` is `since`, or 0 when `since` is absent, or `now` when `since > now`. It reads them from spec 032-storage-ttl in pages of 500 and reads the next page only once the socket has taken the previous one. It then sends `ok{channel_id}`, then the held pushes of R8 in order, and only then marks the subscription subscribed.
- R8 While a subscription catches up, every live push of its channel MUST be held for it, in order and unsent. After the backlog, the held pushes whose `received_at` is greater than that of the last backlog push, or all of them when the backlog was empty, MUST be sent after `ok`, and the others dropped as already sent. When a subscription holds more than 256 pushes or more than 4 MiB of blobs, the server MUST close the connection with status 1013 rather than drop one (spec 028-session-sans-io R4: the client resumes from its cursor).
- R9 A `subscribe` for a channel already subscribed or catching up on the same connection MUST, once spec 031 accepts it, change nothing and send nothing.
- R10 Backlog pushes and held pushes MUST NOT count toward the send queue bound of spec 033-rate-limit-quotas. Live pushes of subscribed channels, `ack`s, `error`s and `hello`s count.

**Publish and fan-out**

- R11 A `publish` MUST be refused with `error{not_subscribed}` when its channel is neither subscribed nor catching up on this connection, then with `error{bad_blob}` when `check_blob` fails, then with the error of spec 033 when a limit refuses it, each naming the frame's `channel_id` and `client_ref` and storing nothing. Otherwise the blob MUST go to the writer of spec 032-storage-ttl with the `ttl_seconds` of the subscription.
- R12 Once the writer has committed a blob, the server MUST send `ack{client_ref, server_id, received_at}` on the publishing connection and then a `push` of it to every subscription of its channel on every connection, the publisher's included (the echo of `docs/spec.md` §4). The pushes of one channel MUST reach every connection in `received_at` order, and one connection's `publish`es MUST be stored and acknowledged in the order they arrived (spec 028-session-sans-io R4). A publish the writer refuses MUST get the `error` spec 032 names, with its `channel_id` and `client_ref`.
- R13 The server MUST send only the seven frame types of the table "Frames" of spec 028-session-sans-io. `error.code` MUST be one of the codes of `docs/spec.md` §6, `error.message` MUST be the fixed ASCII text of that code in this spec, and neither may carry a byte that came from a client. The code `unsupported_version` is reserved for a later `proto_version` and MUST NOT be sent in v1.
- R14 For the same fields, every frame the server builds MUST be byte-identical to the server-direction frames of `specs/vectors/028.json`.

**Disconnect**

- R15 When either side closes the connection, or a write to it fails, the server MUST drop the connection's subscriptions, nonce and held pushes at once, and keep nothing about it. A blob whose commit completes after its connection has gone is stored and pushed to the others, with no `ack`.

## Limits

| Input | Range | Out of range |
| --- | --- | --- |
| WebSocket message or frame | 0..=70 000 B, binary | close 1009; a text message, close 1003 |
| Frame content | a frame of spec 028's table that a client sends (`subscribe`, `publish`) | close 1008 |
| `publish.blob` | 1185..=64673 B, `(len − 161) mod 1024 = 0`, `blob[0] = 0x01`, `blob[1..17] = channel_id` | `bad_blob` |
| `subscribe.since` | any u64 | above `now`: read as `now` |
| Backlog page | 500 blobs | next page once the socket has taken this one |
| Held pushes per subscription | ≤ 256 frames and ≤ 4 MiB of blobs | close 1013 |
| `error.message` | the fixed text of its code, ≤ 256 B | not reachable |

## Interface

```
crates/core/src/relay.rs                          check_blob (R2); specs 031 and 032 add their items
crates/core/src/relay/tests.rs                    s030_* core tests
crates/core/fuzz/fuzz_targets/relay_check_blob.rs
crates/server/src/main.rs                         wiring only; spec 035 owns start-up and shutdown
crates/server/src/http.rs                         the route, the Origin and path checks, the upgrade (R3, R4)
crates/server/src/connection.rs                   one task per socket: frames in, frames out, catch-up (R5–R11, R15)
crates/server/src/hub.rs                          subscriptions per channel, held pushes, fan-out in order (R8, R12)
crates/server/src/frames.rs                       the fixed error texts (R13)
crates/server/src/tests/ws.rs                     s030_* server tests, over a real socket
```

```rust
// core, `pub`, for the server only (spec 027-core-api)
pub mod relay {
    pub fn check_blob(blob: &[u8], channel_id: &[u8; 16]) -> Result<(), Error>;   // BadLength, UnsupportedVersion, WrongChannel
}
```

Every time the server reads comes from the `Clock` of spec 032-storage-ttl R14.

The `error.message` texts (R13): `bad_auth` "subscription signature rejected", `nonce_expired` "server nonce expired", `bad_ttl` "ttl out of range", `not_subscribed` "channel not subscribed on this connection", `bad_blob` "blob rejected", `rate_limited` "rate limited", `channel_quota` "channel full", `server_full` "server full".

Dependencies of `privatechat-server` added by this spec, each justified in its pull request (AGENTS 8): `privatechat-core` (path); `tokio` with the features `rt-multi-thread`, `macros`, `net`, `time`, `sync` and `signal`; `axum` with `default-features = false` and the features `ws`, `http1` and `tokio`. Dev-dependency: `tokio-tungstenite` with the feature `connect`, as the test client. Specs 032 and 035 add `rusqlite`, `tracing` and `tracing-subscriber`.

**Tasks.** One `tokio` task per connection. It reads frames, writes frames from its bounded queue, and streams its own backlog pages. The hub is shared state behind one mutex, holding for each `channel_id` its subscriptions and each subscription's held pushes. The writer thread of spec 032 calls the hub after every commit, in commit order, and the hub `try_send`s each push into the queue of each subscribed connection. A full queue marks that connection for closing (spec 033). The writer is the single place where blobs are ordered, so the order of R12 needs no further lock.

## Security

- The server learns what §2 row 1 says and nothing more. It never calls a signature check or a decryption on a blob, and `check_blob` reads only bytes 0..17 and the length.
- R7 and R8 keep the order the cursor of spec 021-channel-session relies on: no live push can reach a client ahead of the backlog it belongs after. Under load, a push is never dropped (a dropped push would be a silent gap). The connection is closed instead, and the client fetches again from its cursor.
- R6 closes on the first malformed frame. A conforming client never sends one (spec 028), so the only cost falls on a client that is not ours, and the server spends no work answering it.
- The echo of R12 is what lets the sender confirm delivery and detect its own key used elsewhere (`docs/spec.md` §4, ADR 0029). A publisher whose connection drops before the `ack` republishes the same `client_ref` (spec 021-channel-session R8). The server stores the second copy under a new `server_id`, and every receiver rejects it by anti-replay. The server keeps no table of `client_ref`s to deduplicate.
- R3 refuses every request that a browser page could send across origins, and serves nothing but the upgrade.
- Memory is bounded per connection by R4, R8 and the queue of spec 033, and in total by the connection cap of spec 033.
- No log line in this spec. Spec 035-server-ops fixes what the server may log.

## Public API changes

- `core` gains `relay::check_blob`, `pub` for the server only. Spec 027-core-api lists it among the items `pub` for the other crates and `crates/core/tests/api_surface.rs` pins it (spec 027 R16). The bindings do not wrap them.
- `docs/spec.md` §6, brought up to date when this spec is accepted: the backlog streamed before `ok` and held live pushes (already decided by spec 028); `error` never carries client data; `unsupported_version` reserved; the route `/` and the 404 and 403 answers.

## Test cases

- T01 (covers R1): a CI step named `s030_t01_r01_deny_wrappers`: `cargo deny --all-features check` green with the server's dependencies, and `cargo tree -i sha1 -e normal` and `cargo tree -i rand -e normal` name no direct dependent other than `axum` and `tungstenite` for `sha1`, and `tungstenite` and `proptest` for `rand`.
- T02 (covers R2): `s030_t02_r02_relay_check_blob`: every positive blob of `013.json` → `Ok`; the length, version and channel negatives of `013.json` → the same error as `verify`; a proptest over blobs from `seal`, one byte flipped in `0..17` → `UnsupportedVersion` or `WrongChannel` by the region of the mutation table of spec 013, and any flip in `17..` → `Ok`; `scripts/check_fuzz_targets.sh` lists `relay_check_blob`.
- T03 (covers R3): `s030_t03_r03_route_and_origin`: `GET /x` → 404, empty body; `POST /` → 404; an upgrade with `Origin: https://example.org` → 403, empty body; a plain upgrade → 101 with no `Sec-WebSocket-Extensions` and no `Sec-WebSocket-Protocol`, even when the request offers `permessage-deflate`.
- T04 (covers R4): `s030_t04_r04_message_size`: a binary message of 70 000 bytes is read; 70 001 → close 1009; a text message → close 1003.
- T05 (covers R5): `s030_t05_r05_hello_first`: the first frame decodes as `hello` with `proto_versions = [1]`.
- T06 (covers R6): `s030_t06_r06_bad_frames_close`: random bytes → close 1008, no `error` frame; a well-formed `push` sent by the client → close 1008; an `ok` → close 1008.
- T07 (covers R7): `s030_t07_r07_backlog_then_ok`: 1 200 stored blobs, a `subscribe` with `since` equal to the `received_at` of the 101st → blobs 101..=1200 in order, then `ok`; `since` absent → all 1 200; `since` a day ahead of the clock → nothing, then `ok`; a blob with `expires_at ≤ now` → not sent; a client that does not read → the server reads no second page until the socket takes the first (the page counter of the test reader stays at 1).
- T08 (covers R8): `s030_t08_r08_held_live_pushes`: during a slow backlog, a second connection publishes 10 blobs → the first connection receives the backlog, `ok`, then the 10 in order, none twice, including the case where a blob was committed between two backlog pages; 257 held pushes → close 1013.
- T09 (covers R9): `s030_t09_r09_second_subscribe_ignored`: subscribing twice to one channel on one connection → one backlog, one `ok`, no second frame.
- T10 (covers R10): `s030_t10_r10_backlog_outside_queue`: a backlog of 20 000 blobs of 64 673 bytes to a slow reader → no close from the send-queue rule; live pushes of another subscribed channel past the bound → close.
- T11 (covers R11): `s030_t11_r11_publish_refusals`: a `publish` on a channel not subscribed → `not_subscribed` naming the `channel_id` and `client_ref`; a blob of 1 184 bytes, of version 2 or of another channel → `bad_blob` naming both; nothing stored in each case.
- T12 (covers R12): `s030_t12_r12_ack_and_fan_out`: three connections on one channel, one publishes → `ack` on the publisher, then a `push` to all three, the publisher included, with the same `server_id` and `received_at`; two publishers interleaving 100 blobs each → every connection sees the same `received_at` order; one connection publishing 50 blobs → 50 `ack`s in the order sent; a writer refusal → its `error` with both fields.
- T13 (covers R13): `s030_t13_r13_frames_sent`: over a run of T07–T12 every frame received decodes as one of the seven types, every `error.message` equals the text of its code, and no `error` carries `unsupported_version`.
- T14 (covers R14): `s030_t14_r14_frames_match_vectors`: the server's encoder, given the fields of each server-direction frame of `028.json`, writes the vector's bytes.
- T15 (covers R15): `s030_t15_r15_disconnect_forgets`: after a client closes, the hub holds no subscription of that connection; a publish whose connection closes before the commit → stored, pushed to the other subscriber, no `ack`.

## Vectors

No new vector file. The server reproduces the server-direction frames of `028.json` (T14), and `check_blob` reproduces the length, version and channel rows of `013.json` (T02).

## Acceptance criterion

`cargo test -p privatechat-core s030_` and `cargo test -p privatechat-server s030_` green; `cargo deny --all-features check`, clippy and `scripts/doc_lint.sh` green; the `relay_check_blob` target builds and runs nightly.

## Out of scope

- The `subscribe` checks, the nonce and the attempt rules (spec 031-auth-channel-signature).
- The table, the writer, `received_at`, the purge and the retention counters (spec 032-storage-ttl).
- Every numeric limit of `docs/spec.md` §6 "Limits and quotas", ping and pong included (spec 033-rate-limit-quotas).
- Configuration, the client address, the onion listener, logging, shutdown and the phase 3 exit test (spec 035-server-ops).
- TLS, which terminates at the reverse proxy (spec 034-docker), and the client side (spec 028-session-sans-io).

## Open questions

None.

## History

- 2026-09-25 draft
