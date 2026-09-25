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

**In plain words.** A phone connects, and the server greets it with a random number. The phone proves it holds each channel's config (spec 031). For each channel, the server first sends everything the phone has not seen yet, oldest first. A message that arrives while that backlog is being sent waits in line behind it, so nothing can overtake the backlog, and once the line is empty the server says "ok, you are up to date". When someone publishes, the server checks only the size and the first bytes of the blob. It stores the blob, says "stored" to the sender and hands the blob to everyone listening on that channel, the sender included. Every listener gets the blobs in the same order. Anything the server cannot follow makes it hang up, and the phone reconnects from where it stopped.

**Implementation order of phase 3.** The specs are numbered by topic and implemented by dependency, as in phase 1: 032-storage-ttl → 031-auth-channel-signature → 030-ws-protocol → 033-rate-limit-quotas → 035-server-ops → 034-docker. The storage is tested through its writer and reader, and the server half of the signature check as a state machine with no socket; this spec puts both on a socket. The limits wrap the connection, operation wraps the whole binary, and the image packages the result.

**PR slices** (AGENTS 14): (a) `relay::check_blob` of R2, its property test and fuzz target, and the `deny.toml` entries of R1; (b) the route, the handshake and frame reading (R3–R6); (c) subscriptions, catch-up and disconnect (R7–R10, R15, R16); (d) publish, fan-out and the frames sent (R11–R14).

## Requirements

**Crate and core**

- R1 `deny.toml` MUST allow `sha1` only under the wrappers `axum` and `tungstenite`, and MUST add `tungstenite` to the wrappers of `rand`. The WebSocket handshake of RFC 6455 hashes `Sec-WebSocket-Key` with SHA-1, which protects nothing here, and tungstenite draws client frame masks with `rand`, which the server never sends. No other crate may bring either in.
- R2 The `relay` module of `core` MUST expose `check_blob(blob, channel_id)`, which runs exactly the checks of spec 013-wire-message R2 (length, version, channel) through the same function `verify` calls, and nothing else. This spec MUST amend spec 027-core-api (the items `pub` for `server`) with it, and spec 016-fuzz-harness R2, R8 and R9 with the target `relay_check_blob`: its input is `channel_id` (16 bytes) ‖ blob, `scripts/fuzz_seeds.py` writes its corpus from the blobs of `013.json` prefixed with their `channel_id`, and the nightly matrix gains its job.

**Handshake and frames**

- R3 The server MUST answer a WebSocket upgrade only for `GET /`. Any other path or method MUST get HTTP 404 with an empty body, and a request that carries an `Origin` header MUST get HTTP 403 with an empty body (no browser client in v1, ADR 0017). The server MUST negotiate no WebSocket extension and no subprotocol.
- R4 A message or frame longer than 70 000 bytes MUST close the connection with status 1009, and a text message MUST close it with status 1003.
- R5 The server's first frame on every connection MUST be the `hello` of spec 031-auth-channel-signature R1.
- R6 Every binary message MUST be decoded with `Frame::decode`. A decoding failure, or a frame of a type no client sends (`hello`, `ok`, `ack`, `push`, `error`), MUST close the connection with status 1008 and no `error` frame.

**Subscriptions**

- R7 Once spec 031-auth-channel-signature accepts a `subscribe`, the server MUST register the subscription as catching up before it reads any stored blob. It MUST then send as `push`es, in `received_at` order, the channel's stored blobs with `received_at ≥ s` and `expires_at > now`, where `now` is `Clock::wall_ms()` and `s` is `since`, or 0 when `since` is absent, or `now` when `since > now`. It reads them from spec 032-storage-ttl in pages of at most 500 blobs and at most 256 KiB (always at least one blob), holding at most one page in memory per connection: the connection task streams its catching-up subscriptions one page at a time, in turn, reads the next page only once the socket has taken the previous one, and before each backlog page and each batch of held pushes writes every frame already in its queue, so that the `ack`s and live pushes of its subscribed channels never wait behind a catch-up. A `read_page` that fails MUST close the connection with status 1011, and the client resumes from its cursor. After the backlog it sends the held pushes of R8 in order, and when none is left, in one step under the hub's lock, it sends `ok{channel_id}` and marks the subscription subscribed, so that from then on its live pushes go straight to the connection's queue.
- R8 While a subscription catches up, every live push of its channel MUST be held for it, in order and unsent. After the backlog, the held pushes whose `received_at` is greater than that of the last backlog push, or all of them when the backlog was empty, MUST be sent before `ok`, and the others dropped as already sent. When the subscriptions of one connection would hold more than 256 pushes or more than 4 MiB of blobs in all, which can happen only before their `ok`, the server MUST end the one of them holding the most bytes, alone, and send `error{rate_limited, channel_id}`. Ending it is decided under the hub's lock: its held pushes are dropped, its backlog stream stops, no further `push` or `ok` of it is written after the error, and the connection forgets it, so that R9 does not apply to the next `subscribe` of that channel. The `error` returns the channel to "not subscribed" at the client and re-queues its `subscribe` from its cursor (spec 028-session-sans-io R16), so that a flooded channel does not take the other channels of the connection down with it.
- R9 A `subscribe` for a channel already subscribed or catching up on the same connection MUST, once spec 031 accepts it, change nothing and send nothing.
- R10 Backlog pushes and held pushes MUST NOT count toward the send queue bound of spec 033-rate-limit-quotas. Live pushes of subscribed channels, `ack`s, `error`s, `hello`s and `ok`s count.

**Publish and fan-out**

- R11 A `publish` MUST be refused with `error{not_subscribed}` when its channel is neither subscribed nor catching up on this connection, then with `error{bad_blob}` when `check_blob` fails, then with the error of spec 033 when a limit refuses it, then with `error{rate_limited}` when `Writer::submit` finds the writer's queue full (spec 032-storage-ttl R4), each naming the frame's `channel_id` and `client_ref`, put in the connection's queue at once, and storing nothing. Otherwise the blob MUST go to the writer of spec 032-storage-ttl with the `ttl_seconds` of the subscription.
- R12 Once the writer has committed a blob, the server MUST put `ack{client_ref, server_id, received_at}` into the publishing connection's queue and then a `push` of it into the queue of every subscription of its channel on every connection, the publisher's included (the echo of `docs/spec.md` §4). Both go through the hub, from the writer's results in the writer's order, so that the `ack` always precedes its echo, the pushes of one channel reach every connection in `received_at` order, and one connection's `publish`es are stored and acknowledged in the order they arrived (spec 028-session-sans-io R4). A publish the writer refuses MUST get, through the same path, the `error` spec 032 names, with its `channel_id` and `client_ref`.
- R13 The server MUST send only the seven frame types of the table "Frames" of spec 028-session-sans-io. `error.code` MUST be one of the codes of `docs/spec.md` §6, `error.message` MUST be the fixed ASCII text of that code in this spec, and neither may carry a byte that came from a client. The code `unsupported_version` is reserved for a later `proto_version` and MUST NOT be sent in v1.
- R14 For the same fields, every frame the server builds MUST be byte-identical to the server-direction frames of `specs/vectors/028.json`.

**Disconnect**

- R15 When either side closes the connection, or a write to it fails, the server MUST drop the connection's subscriptions, nonce and held pushes at once, and keep nothing about it. A blob whose commit completes after its connection has gone is stored and pushed to the others, with no `ack`.
- R16 When a `relay` function returns `Error::Internal` (libsodium failed), the server MUST close the connection with status 1011 and send no other frame for it.

## Limits

| Input | Range | Out of range |
| --- | --- | --- |
| WebSocket message or frame | 0..=70 000 B, binary | close 1009; a text message, close 1003 |
| Frame content | a frame of spec 028's table that a client sends (`subscribe`, `publish`) | close 1008 |
| `publish.blob` | 1185..=64673 B, `(len − 161) mod 1024 = 0`, `blob[0] = 0x01`, `blob[1..17] = channel_id` | `bad_blob` |
| `subscribe.since` | any u64 | above `now`: read as `now` |
| Backlog page | ≤ 500 blobs and ≤ 256 KiB, at least one blob; one in memory per connection | next page once the socket has taken this one |
| Held pushes of one connection, before their `ok` | ≤ 256 frames and ≤ 4 MiB of blobs in all | the subscription holding the most ends with `rate_limited` |
| `error.message` | the fixed text of its code, ≤ 256 B | not reachable |

## Interface

```
crates/core/src/relay.rs                          check_blob (R2); specs 031 and 032 add their items
crates/core/src/relay/tests.rs                    s030_* core tests
crates/core/fuzz/fuzz_targets/relay_check_blob.rs
crates/server/src/main.rs                         wiring only; spec 035 owns start-up and shutdown
crates/server/src/http.rs                         the route, the Origin and path checks, the upgrade (R3, R4)
crates/server/src/connection.rs                   one task per socket: frames in, frames out, catch-up (R5–R11, R15, R16); a `cfg(test)` hook that pauses its socket writes, used by the tests of specs 030, 033 and 035
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

Dependencies of `privatechat-server` added by this spec, each justified in its pull request (AGENTS 8): `privatechat-core` (path); `tokio` with the features `rt-multi-thread`, `macros`, `net`, `time`, `sync` and `signal`; `axum` with `default-features = false` and the features `ws`, `http1` and `tokio`; `tungstenite` with `default-features = false`, at the version `axum` pins, only to recognise `Error::Capacity` behind `axum::Error` and close with 1009 (R4). Dev-dependencies: `tokio-tungstenite` with the feature `connect`, as the test client, and `futures-util` (`default-features = false`, features `sink` and `std`) for its `SinkExt` and `StreamExt`. `tungstenite` and `axum` stay at the versions pinned together: tungstenite 0.30 moves to `rand` 0.10, which brings in the banned `chacha20`. Specs 032 and 035 add `rusqlite`, `tracing` and `tracing-subscriber`.

**Tasks.** One `tokio` task per connection. It reads frames, writes frames from its bounded queue, and streams its own backlog pages. The hub is shared state behind one mutex, holding for each `channel_id` its subscriptions and each subscription's held pushes. The writer thread of spec 032 hands the hub every result of a transaction, stored or refused, in processing order, each carrying the id of the connection it came from and its `client_ref`; the hub puts the `ack` or `error` into that connection's queue and then `try_send`s each push into the queue of each subscribed connection. A full queue marks that connection for closing (spec 033). Each push frame is encoded once and shared (`Bytes`, whose clone is cheap and which `Message::Binary` takes) by every queue and hold it enters, so a blob costs its size once however many subscribers it has; the byte bounds count it per queue. The writer is the single place where blobs are ordered, and the hub the single path to a connection, so the order of R12 needs no further lock.

## Security

- The server learns what §2 row 1 says and nothing more. It never calls a signature check or a decryption on a blob, and `check_blob` reads only bytes 0..17 and the length.
- R7 and R8 keep the order the cursor of spec 021-channel-session relies on: no live push can reach a client ahead of the backlog it belongs after. Under load, a push is never silently dropped (a dropped push would be a silent gap): R8 ends the subscription with an error, spec 033 R5 closes a connection whose queue overflows, and the client fetches again from its cursor.
- R6 closes on the first malformed frame. A conforming client never sends one (spec 028), so the only cost falls on a client that is not ours, and the server spends no work answering it.
- The echo of R12 is what lets the sender confirm delivery and detect its own key used elsewhere (`docs/spec.md` §4, ADR 0029). A publisher whose connection drops before the `ack` republishes the same `client_ref` (spec 021-channel-session R8). The server stores the second copy under a new `server_id`, and every receiver rejects it by anti-replay. The server keeps no table of `client_ref`s to deduplicate.
- An intruder with the config who floods a channel at its limit can keep a member whose link is slower than about twice the flood from ever finishing that channel's catch-up: each subscription is ended at the hold bound and resumed from a cursor rounded down to the minute. That is one more form of "the channel is flooded", whose answer is a new channel (ADR 0008).
- R3 refuses every request that a browser page could send across origins, and serves nothing but the upgrade.
- Memory is bounded per connection by R4, the holds of R8 (4 MiB for all its subscriptions), the one backlog page of R7 (256 KiB) and the queue of spec 033 (4 MiB): about 8.3 MiB, and in total by the connection caps of spec 033 (at the defaults, 5 120 connections, about 42 GiB in the worst case, which `deploy/README.md` states as the memory to plan for, or lower caps). Held and queued pushes share one buffer per blob, so a flood costs its bytes once however many subscribers hold it. There is no server-wide pool that one source could hold: each connection pays for its own page.
- No log line in this spec. Spec 035-server-ops fixes what the server may log.

## Public API changes

- `core` gains `relay::check_blob`, `pub` for the server only. Spec 027-core-api lists it among the items `pub` for the other crates and `crates/core/tests/api_surface.rs` pins it (spec 027 R16). The bindings do not wrap it.
- `docs/spec.md` §6, brought up to date when this spec is accepted: the backlog streamed before `ok` and held live pushes (already decided by spec 028); `error` never carries client data; `unsupported_version` reserved; the route `/` and the 404 and 403 answers; held pushes sent before `ok`, which now closes the catch-up; backlog pages bounded by bytes, one per connection; a flooded subscription ended with `rate_limited` before its `ok` instead of closing the connection.

## Test cases

- T01 (covers R1): a CI step named `s030_t01_r01_deny_wrappers`: `cargo deny --all-features check` green with the server's dependencies, and `cargo tree -i sha1 -e normal` and `cargo tree -i rand -e normal` name no direct dependent other than `axum` and `tungstenite` for `sha1`, and `tungstenite` and `proptest` for `rand`.
- T02 (covers R2): `s030_t02_r02_relay_check_blob`: every positive blob of `013.json` → `Ok`; the length, version and channel negatives of `013.json` → the same error as `verify`; a proptest over blobs from `seal`, one byte flipped in `0..17` → `UnsupportedVersion` or `WrongChannel` by the region of the mutation table of spec 013, and any flip in `17..` → `Ok`; `scripts/check_fuzz_targets.sh` lists `relay_check_blob`, and `scripts/fuzz_seeds.py` writes its corpus.
- T03 (covers R3): `s030_t03_r03_route_and_origin`: `GET /x` → 404, empty body; `POST /` → 404; an upgrade with `Origin: https://example.org` → 403, empty body; a plain upgrade → 101 with no `Sec-WebSocket-Extensions` and no `Sec-WebSocket-Protocol`, even when the request offers `permessage-deflate`.
- T04 (covers R4): `s030_t04_r04_message_size`: a binary message of 70 000 bytes is read; 70 001 → close 1009; a text message → close 1003.
- T05 (covers R5): `s030_t05_r05_hello_first`: the first frame decodes as `hello` with `proto_versions = [1]`.
- T06 (covers R6): `s030_t06_r06_bad_frames_close`: random bytes → close 1008, no `error` frame; a well-formed `push` sent by the client → close 1008; an `ok` → close 1008; over a socket, three `bad_auth` → the third `error`, then close 1008 (spec 031 R6); no accepted `subscribe` for 60 001 ms of the manual clock, moved in steps of 1 000 ms while the client reads and answers pings → close 1008 with no frame (spec 031 R7).
- T07 (covers R7): `s030_t07_r07_backlog_then_ok`, the blobs stored through `Writer::submit` with the channel limits of spec 033 raised: 1 200 stored blobs of 1 185 bytes, a `subscribe` with `since` equal to the `received_at` of the 101st → blobs 101..=1200 in order, then `ok`; `since` absent → all 1 200; `since` a day ahead of the clock → nothing, then `ok`; a blob with `expires_at ≤ now` → not sent; 40 blobs of 64 673 bytes → ten pages of 4 (256 KiB each at most); 300 blobs of 64 673 bytes to a client that connects with a 65 536-byte receive buffer (`TcpSocket::set_recv_buffer_size`) and does not read → the server's `read_page` counter (a `cfg(test)` hook) stays below 75 and unchanged over 500 ms of real time; two subscriptions of one connection catching up at once → their pages alternate and never two are in memory together, and neither is ended however long the other's backlog; a publish on a third, subscribed channel of the same connection during that catch-up → its `ack` and echo arrive before the next backlog page.
- T08 (covers R8): `s030_t08_r08_held_live_pushes`, with the channel limits of spec 033 raised and the catch-up slowed by a `cfg(test)` hook that pauses the connection's socket writes: during a slow backlog, a second connection publishes 10 blobs → the first connection receives the backlog, then the 10 in order, none twice, then `ok`, including the case where a blob was committed between two backlog pages; a 257th held push, and in another run held blobs of 64 673 bytes reaching 4 MiB at the 65th → `rate_limited` naming that channel, and after it no `push` and no `ok` of that channel, the connection still open, a second subscribed channel still receiving pushes, and a new `subscribe` of the ended channel served with a fresh backlog; after `ok`, no subscription is ever ended.
- T09 (covers R9): `s030_t09_r09_second_subscribe_ignored`: subscribing twice to one channel on one connection → one backlog, one `ok`, no second frame.
- T10 (covers R10): `s030_t10_r10_backlog_outside_queue`, stored through `Writer::submit` with the channel limits raised: a backlog of 1 000 blobs of 64 673 bytes (above both queue bounds) to a reader that reads slowly but steadily → no close from the send-queue rule.
- T11 (covers R11): `s030_t11_r11_publish_refusals`: a `publish` on a channel not subscribed → `not_subscribed` naming the `channel_id` and `client_ref`; a blob of 1 184 bytes, of version 2 or of another channel → `bad_blob` naming both; with the writer's queue filled by a test hook → `rate_limited` naming both; nothing stored in each case.
- T12 (covers R12): `s030_t12_r12_ack_and_fan_out`, with the channel limits of spec 033 raised: three connections on one channel, one publishes → `ack` on the publisher, then a `push` to all three, the publisher included, with the same `server_id` and `received_at`; four publishers interleaving 25 blobs each → every connection sees the same `received_at` order; one connection publishing 30 blobs → 30 `ack`s in the order sent, each before its own echo; a writer refusal → its `error` with both fields, in order among the `ack`s.
- T13 (covers R13): `s030_t13_r13_frames_sent`: over a run of T07–T12 every frame received decodes as one of the seven types, every `error.message` equals the text of its code, and no `error` carries `unsupported_version`.
- T14 (covers R14): `s030_t14_r14_frames_match_vectors`: the server's encoder, given the fields of each server-direction frame of `028.json`, writes the vector's bytes.
- T15 (covers R15): `s030_t15_r15_disconnect_forgets`: after a client closes, the hub holds no subscription of that connection; a publish whose connection closes before the commit → stored, pushed to the other subscriber, no `ack`.
- T16 (covers R16): `s030_t16_r16_internal_error_closes`: a `cfg(test)` hook that fails `read_page` during a backlog → close 1011; a hook in the server's wrapper around the `relay` calls, compiled only under `cfg(test)`, that returns `Internal` → close 1011, no `error` frame.

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
- 2026-09-25 revised after audit K round 7 (`docs/audit-log.md`): `futures-util` for the test client; the version pin explained
- 2026-09-25 revised after audit K round 6 (`docs/audit-log.md`): a failed backlog read closes with 1011
- 2026-09-25 revised after audit K round 5 (`docs/audit-log.md`): the write-pause hook for tests; T06's clock steps
- 2026-09-25 revised after audit K round 4 (`docs/audit-log.md`): the hold bound shared by a connection's subscriptions; the queue written before each backlog page; `ok` counted; `tungstenite` for the 1009 close; the memory figure; the flooded-channel residual; T07, T08 and T10 made deterministic
- 2026-09-25 revised after audit K round 3 (`docs/audit-log.md`): the permit pool removed, one page of 256 KiB per connection in turn; held pushes before `ok`, so a subscription can end only before it; the backlog's `now` is the wall reading; tests sized for spec 033's limits
- 2026-09-25 revised after audit K round 2 (`docs/audit-log.md`): one permit per connection, an onion share, a 20 000 ms permit wait and a 30 000 ms page write; ending a subscription stops everything of it under the hub's lock; a full writer queue answered in R11; `Bytes` as the shared buffer; the auth closes tested on a socket
- 2026-09-25 revised after audit K round 1 (`docs/audit-log.md`): pages bounded by bytes and a server-wide permit pool; a flooded subscription ends alone; `ack`, `error` and pushes through the hub in one order; shared push buffers; `Internal` closes 1011; 016 R8 and R9 amended; tests resized
