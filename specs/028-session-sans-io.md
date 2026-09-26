# 028 — Session: the client side of the protocol, sans I/O

Status: draft
Phase: 2
Related ADRs: 0010, 0020, 0022, 0023, 0037
Depends on: 011-config-format, 015-test-vectors, 016-fuzz-harness, 017-record-encoding, 020-store-files, 021-channel-session, 023-ttl-purge, 024-key-retired, 025-identity-regen
Blocks: 027-core-api, 030-ws-protocol, 031-auth-channel-signature, 033-rate-limit-quotas, 035-server-ops
Human reviewer: Marc Vilardebó · Accepted on: —

## Context

The three clients must not implement the protocol three times (ADR 0020). `Session` is the whole client side of `docs/spec.md` §6 for one connection, as a state machine with no I/O: the `Device` of spec 027-core-api owns one `Session` per planned connection (ADR 0037), hands it every frame the UI received on that socket, and returns what it wants written. `Session` parses and builds the frames, answers `hello` with one `subscribe` per channel, feeds `push`es to `Channel::decrypt`, drains each channel's `outbox` into `publish`es and routes `ack`s back.

Since the decision of 2026-09-25 (`docs/spec.md` §6), this spec also fixes the numeric keys of every frame and the order in which the server sends a channel's backlog, because the client needs them first; spec 030-ws-protocol implements the server over the same encoders and decoders, and must honour the server contract of R4. The end-to-end exit test of phase 2 runs over `Device` and is spec 027-core-api's.

**In plain words.** The session is the part that talks to the server, written once for all three apps. When the server says hello with a fresh random number, the session proves, one channel at a time, that it holds each channel's config by signing that number, and asks for everything since the last minute it read. The server sends that backlog in order and then says "ok, you are up to date"; only after that do live messages for the channel arrive. Messages go to their channel; messages waiting to leave go out, at most thirty a minute. If the disk cannot take a message, the session stops reading that channel and asks for a fresh connection once there is room, so nothing is skipped. Whatever the channel thought of a message from someone else — good, forged, expired — never changes what the session sends next.

## Requirements

**Frames**

- R1 Every frame MUST be one record of spec 017-record-encoding, decoded under `UnknownKeys::Ignore`, with key 0 = `type` u8 and the fields of the table "Frames" below; a frame longer than 70 000 bytes, with an unknown `type`, or failing its schema (a text over its limit included) MUST be dropped and MUST produce `Event::Reconnect`.
- R2 `hello.proto_versions` MUST be decoded as a `list<u8>` bounded only by the frame size; a list with no item, with more than 8 items, or without the `proto_version` of the channels (1) MUST produce `Event::UnsupportedServer`, and the session MUST then send nothing until the next `on_connect` (`docs/spec.md` §6 "Version"). `probe_hello` of spec 027-core-api applies this same rule.
- R3 `Frame::encode` and `Frame::decode` MUST be the `pub` functions through which spec 030-ws-protocol reaches the frames without touching the codec (`docs/spec.md` §9), and this spec MUST amend spec 016-fuzz-harness R2, R8 and R9 with two targets seeded from the frames of `028.json`: `frame_decode`, over arbitrary bytes, and `session_on_frame`, which drives a `Session` holding the `text_k1` channel of spec 021-channel-session R29 through a fixed `hello` and `ok` and then reads its input as a sequence of frames, each `len` u16 BE ‖ frame, so that `push`, `ack` and `error` handling are reached.

**Server contract**

- R4 After a `subscribe`, the server MUST send the channel's retained blobs with `received_at ≥ since` (all of them when `since` is absent, `since > now` read as `now`) as `push`es in `received_at` order, written at the pace the socket drains, then the live pushes it held back meanwhile, in order, then `ok`, and MUST NOT send a live `push` of that channel ahead of its backlog; the backlog and the live pushes it holds back do not count toward the send-queue close rule of `docs/spec.md` §6, the server bounding the held pushes of all of a connection's subscriptions together (spec 030-ws-protocol R8) and, when that bound is reached, ending one subscription alone with `error{rate_limited, channel_id}` (R16) and never silently dropping a backlog or held push, so that the client resumes from its cursor. The server stores and acknowledges one connection's `publish`es in the order it receives them (spec 021-channel-session R17 relies on it). On a connection whose `hello` lists `proto_version` 1, the server sends only the frame types of the table "Frames" below; a new type needs a new `proto_version`. The server sends `error{nonce_expired}` only in reply to a `subscribe` signed with an expired nonce, naming that `channel_id`, and never unsolicited. Spec 030-ws-protocol implements all of this.

**Connection**

- R5 `on_connect(now, skip)` and `on_disconnect()` MUST forget every subscription, nonce, queued frame, in-flight and queued `client_ref`, rate count, pause, hold and stall of the connection, and the "no `synced`" stop of R9, keeping the channels and their `write_failed` marks (R10); `on_connect(now)` also sets the reference time of R9's 5 000 ms rule; `skip` names the channels the `Device` refuses to subscribe again (spec 027-core-api R11). Between `on_disconnect` and the next `on_connect`, the session MUST queue nothing.
- R6 On `hello`, the session MUST discard every `subscribe` not yet released, and, for each channel not subscribed, not awaiting `ok`, not refused and not in `skip`, queue, in ascending order of `last + ttl_ms` (R8's `last`, or `created_at + ttl_ms` for a channel with none), so that the channel whose history expires first is released first, a `subscribe` with `pk_ch`, `ttl_seconds`, `sig = sign_detached(sk_ch, "privatechat/auth/v1" ‖ server_nonce ‖ channel_id ‖ BE32(ttl_seconds) ‖ host)` with `host` from spec 011-config-format R6, and `since = cursor − cursor mod 60 000` when the channel has a cursor, absent otherwise; each at least 1 100 ms of `now` after the previous `subscribe` released on this connection, across `hello`s (the first at once when none was released in the last 1 100 ms), released by `on_tick` (`docs/spec.md` §6 "1 authentication attempt/s", with a margin for network jitter).
- R7 A `subscribe` queued in answer to a `hello` that cannot be released within 50 000 ms of that `hello` MUST instead produce `Event::Reconnect`; one queued again after a `rate_limited` (R16) is released however old its nonce, but at most one such `subscribe` signed with a nonce more than 50 000 ms old may be released and unanswered at a time, the others waiting; the server answers it with `nonce_expired` and a fresh `hello` (spec 031-auth-channel-signature R5), after which R6 queues every waiting channel under the new nonce, so that no second stale `subscribe` meets a `hello` it has not seen and gets `bad_auth`; with 16 channels and ticks every 1 000 ms (spec 027-core-api R12), a release lands on every second tick, so the last one leaves after about 31 000 ms. After `on_connect`, and after `error{nonce_expired}`, a `hello` that does not arrive within 50 000 ms MUST produce `Event::Reconnect`.
- R8 When it queues a channel's `subscribe`, the session MUST decide, by the local clock alone, whether the history before it is truncated: with `last = max(cursor, synced_at)` of spec 021-channel-session R20, a `synced_at` later than `now` being ignored, truncated when `last` is absent and `created_at + ttl_ms + 360 000 < now` (`created_at` comes from the creator's clock, hence the margin; a creator more than six minutes behind can still give an importer a needless banner), or `last + ttl_ms < now` (`last` is local, so no margin is needed there, and the server drops a blob one TTL after it arrives); it decides at most once per channel per connection, keeping the first decision until `on_disconnect`; when it is, the session MUST call `Channel::history_truncated(now)` before any `push` of that subscription is decrypted and produce `Event::HistoryTruncated { before: now − ttl_ms }` at once, since it depends on the local clock alone. This spec MUST amend spec 011-config-format with `pub(crate) fn created_at(&self) -> u64`.
- R9 A `push` of a channel that is neither awaiting `ok` nor subscribed, of a channel id the session does not know, and an `ok` of a channel not awaiting one, MUST be ignored. When a channel awaits `ok` and the connection has received no frame at all for 60 000 ms, the session MUST produce `Event::Reconnect`; a long backlog of another channel on the same connection keeps it alive. An `ok` MUST mark the channel subscribed, and, when R8 found no truncation, apply R8's rule once more with the `ok`'s `now` and the `last` R8 captured when it first queued the channel's `subscribe` on this connection, never the cursor the backlog has since moved (a stretch of backlog may have expired while it waited its turn, and a later blob would hide it): truncated → `Channel::history_truncated(now)` and `Event::HistoryTruncated` as R8 says, and no `synced` at this `ok`; otherwise call `Channel::synced(now)` unless the channel dropped a push on this subscription or is stalled (R10); then produce `Event::Subscribed`; while the channel stays subscribed, has dropped nothing and is not stalled (`LogFull` or `write_failed`), every `on_tick` calls `synced(now)` again — except that, on a connection with at least one channel subscribed or awaiting `ok`, any `on_tick` or `on_frame` arriving more than 5 000 ms after the latest of the connection's `on_connect`, `on_tick` and `on_frame` (the frame still processed) (a suspended process or a dead socket) calls no `synced` on this connection any more and produces `Event::Reconnect`, the `ok` of the next connection establishing `synced_at` again; then, unless the channel is paused, it MUST call `Channel::outbox(now, in_flight, stopped)` with the entries in flight or queued, queue a `publish` for each blob it returns and produce `Event::NotDelivered` for each `ClientRef` it reports.

**Traffic**

- R10 On a `push` of a channel awaiting `ok` or subscribed, the session MUST call `decrypt(blob, server_id, received_at, now)`: `Ok(Some(received))` MUST produce `Event::Message`; `Ok(None)` and any error other than `Error::Store` MUST produce no event and no frame, apart from those of R11 and R13. On `Error::Store(e)`, the channel MUST drop the push and every later push of this connection, so that its cursor stays where the lost blob can be fetched again: for `LogFull` it stalls — every later push goes to `check_own_key` of spec 021-channel-session R19 instead of `decrypt`, publishing and acks go on until `check_own_key` returns `true` for any blob, or `own_key_used_elsewhere` became set by the `decrypt` that began the stall, after which the channel is stopped: no ordinary entry sealed with the current key is published on this connection — `outbox` is called with `withhold_current` (spec 021-channel-session R22), so the pending `key_retired` and the entries `under_retired_key` keep leaving and stale entries still expire — until a `regenerate_identity` of it, after which `after_send` produces `Event::Reconnect` and queues nothing, `Event::StorageFailed` is produced once, and when `status().storage_full` is false again on a tick (the `Device` compacts stalled channels, spec 027-core-api R12) the session produces `Event::Reconnect`; for any other `e` the session first hands the same push to `check_own_key` — and when it returns `true` the channel is stopped as in the `LogFull` stall until `on_disconnect` — whose in-memory fallback (spec 021-channel-session R19) keeps the own-key alert when the disk cannot be written, then reports `(channel, e)` in the `failed` list of its `Step`, and the channel stalls as for `LogFull` for the rest of the connection, without that stall's `StorageFailed` or tick `Reconnect`, the `Device` owning both (spec 027-core-api R12, R14); a channel the `Device` marks `write_failed` (spec 027-core-api R14, `Session::set_write_failed(channel, true, false)`) stalls as for `LogFull` — every later push of the connection to `check_own_key`, even when a store error on this connection had already dropped them — without that stall's `StorageFailed` (the `Device` produces it) or the tick's `Reconnect`; clearing the mark does not resume `decrypt` on this connection, which stays stalled, event-free, until `on_disconnect` — except that a channel cleared with `storage_full` true (the value the `Device` read when it cleared the mark) returns to the `LogFull` stall, with its tick `Reconnect` once room returns; the failures of its ack and `outbox` commits while marked (it makes no cursor or `synced` commit, a push sent to `check_own_key` counting as dropped) are reported in `failed` and change nothing else, the blobs `outbox` returns with a `store_error` are published, and any `client_ref` whose `acked` failed with a store error, marked or not, is held, not published again, until `set_write_failed(channel, false, storage_full)` or `on_disconnect`.
- R11 For every `ack` and every `push`, before the call it routes to, the session MUST call `Channel::clock_sample(received_at, now, live)` of spec 021-channel-session R25, `live` only for an `ack` arriving within 5 000 ms of its publish, and for no frame at all on a connection once R9's 5 000 ms gap has tripped, so that held or buffered pushes and queued acks cannot raise a false warning. After every `Channel` call it makes, the session MUST drain `take_outcomes()` (spec 021-channel-session R9, R13, R14, R17, R19) and, for each, remove its `client_ref` from the in-flight set and produce the event of R12 as for an `ack`.
- R12 On `ack`, the session MUST route the `client_ref` to the channel it was published for on this connection, remove it from the in-flight set, call `acked(…, now)`, and produce by the returned `Outcome`: `Delivered` → `Event::Delivered { client_ref, server_id, received_at, expires_at = received_at + ttl_ms }` with the clamped time the `Outcome` carries; `NotDelivered` → `Event::NotDelivered`; `RetirementDelivered` → only the `StatusChanged` of R13; `Ignored` → nothing, and when it names the current copy of a pending `key_retired` (the stored one, or the copy kept in memory for this minute by spec 021-channel-session R22), that entry is held, not published again, until its next re-seal or until the minute of `now` changes (a re-seal handed out from memory by spec 021-channel-session R22 does not end it), so that an `ack` that is always late cannot turn into a publish every tick. An unknown `client_ref` is ignored.
- R13 After every `clock_sample`, `decrypt`, `check_own_key`, `acked`, `outbox` and `on_tick`, when a channel's `status()` differs from before or `take_peers_changed()` (spec 021-channel-session) returns `true`, the session MUST produce `Event::StatusChanged` for it, at most once per channel in one returned step.
- R14 After `Channel::encrypt` or `regenerate_identity` of a subscribed channel that is not paused, and on every `on_tick` for every subscribed channel not paused, the session MUST call `outbox(now, in_flight, stopped)`, `stopped` being the state of R10, with the entries in flight or queued, queue the blobs it returns, and produce `Event::NotDelivered` for each `ClientRef` it reports; on every `on_tick` it MUST call `expire_outbox` for its channels that are not subscribed, and report the same way. An `OutboxStep` whose `store_error` is set, from any `outbox` or `expire_outbox` call of this spec, MUST be reported as `(channel, e)` in `failed` after its blobs are queued, marked or not.
- R15 The session MUST queue at most 30 `publish` frames in any 60 000 ms window of `now` on one connection, holding the rest for a later `on_tick`.
- R16 On `error`, the session MUST first remove the named `client_ref`, if any, from the in-flight set, and then act by `code`: `nonce_expired` → every unreleased `subscribe` is discarded, the named channel is again not subscribed (an unnamed one produces `Event::Reconnect`), and R7's wait for a `hello` starts; `bad_auth` or `bad_ttl` → `Event::SubscribeRefused` for the named channel, which is not subscribed again on this connection, and `Event::Reconnect` when it names none; `channel_quota` → the channel of the named `client_ref`, or the named channel, or else every channel, publishes nothing for 60 000 ms, with one `Event::ChannelFull` per paused channel; `rate_limited` naming a channel and no `client_ref` (a `subscribe` refused, or a subscription the server ended, spec 030-ws-protocol R8) → that channel, when awaiting `ok`, is again not subscribed and its `subscribe` is queued again under R6 and R7, and publishing goes on, and when it is subscribed instead (which a server of spec 030-ws-protocol never causes, since it ends a subscription only before its `ok`) → `Event::Reconnect`; any other `rate_limited` → nothing is published for 60 000 ms; `server_full` → the same, and `Event::ServerFull`; `bad_blob` naming an ordinary entry → `Channel::abandon` and, when it returns `Ok(Some(sent_at))`, `Event::NotDelivered` — a failed `abandon` holding the `client_ref` as a failed `acked` does (R10) — naming a `key_retired` → that entry is held, not published again, until its next re-seal (spec 025-identity-regen R4) or until the minute of `now` changes, as in R12, and naming nothing → `Event::Reconnect`; `not_subscribed` → `Event::Reconnect`; `unsupported_version` → R2's `Event::UnsupportedServer`; any other code → nothing.
- R17 `outgoing()` MUST return the queued frames in order and empty the queue.

**No oracle**

- R18 For two sequences of calls that differ only in the bytes of `push` blobs whose opened `sender_pk` is not one's own, with the log headroom of spec 021-channel-session R18 holding in both, `outgoing()` MUST return the same frames at the same calls, apart from the bytes of `sig`, `client_ref` and the blobs of `publish` (`docs/spec.md` §4 "No-oracle rule"). A blob from one's own key can change what the user may send (spec 021-channel-session R14, spec 024-key-retired R3), and the time a commit takes differs between a consumed and a rejected message; both are outside this property and documented.

## Limits

| Input | Range | Out of range |
| --- | --- | --- |
| Frame | 0..=70 000 B | dropped, `Event::Reconnect` |
| `proto_versions` | 1..=8 items | `Event::UnsupportedServer` |
| `subscribe` spacing | ≥ 1 100 ms; each within 50 000 ms of the `hello` | `Event::Reconnect` |
| Wait for a `hello` after `on_connect` or `nonce_expired` | ≤ 50 000 ms | `Event::Reconnect` |
| Silence while a channel awaits `ok` | ≤ 60 000 ms with no frame on the connection | `Event::Reconnect` |
| Gap between two `on_connect`/`on_tick`/`on_frame` calls on a connection with a channel subscribed or awaiting `ok` | ≤ 5 000 ms | no `synced` on the connection, `Event::Reconnect` (R9) |
| `publish` per 60 000 ms | 0..=30 | held |
| `error.code` | text ≤ 32 B | dropped, `Event::Reconnect` |
| `error.message` | text ≤ 256 B | dropped, `Event::Reconnect` |
| Fuzz input of `session_on_frame` | frames of ≤ 65 535 B each | truncated to whole frames |

**Frames** (key 0 `type`; unknown keys ignored)

| `type` | frame | keys |
| --- | --- | --- |
| 0 | `hello` | 1 `server_nonce` bytes32; 2 `proto_versions` `list<u8>` |
| 1 | `subscribe` | 1 `pk_ch` bytes32; 2 `ttl_seconds` u32; 3 `sig` bytes64; 4 `since` u64, optional |
| 2 | `ok` | 1 `channel_id` bytes16 (sent after the backlog, R4) |
| 3 | `publish` | 1 `channel_id` bytes16; 2 `client_ref` bytes16; 3 `blob` bytes ≤ 64 673 |
| 4 | `ack` | 1 `client_ref` bytes16; 2 `server_id` bytes16; 3 `received_at` u64 |
| 5 | `push` | 1 `channel_id` bytes16; 2 `server_id` bytes16; 3 `received_at` u64; 4 `blob` bytes ≤ 64 673 |
| 6 | `error` | 1 `code` text; 2 `message` text; 3 `channel_id` bytes16, optional; 4 `client_ref` bytes16, optional |

`ok` carries neither `has_more` nor `oldest_retained_at`: the server streams the whole backlog before `ok` (R4), and the client judges truncation by its own clock (R8). `error` names the channel or the publish it answers. A `client_ref` names one `outbox` entry and is reused on every publish of it (spec 021-channel-session R8).

## Interface

```
crates/core/src/session/frames.rs            Frame, encode, decode (R1–R3)
crates/core/src/session/connection.rs        Session, Step, Event, Channels (R5–R18)
crates/core/src/session/connection/tests.rs  s028_* tests
crates/core/src/testing.rs                   MemoryServer, which implements R4 over Frame, with the rest of spec 020's testing module
crates/core/fuzz/fuzz_targets/frame_decode.rs
crates/core/fuzz/fuzz_targets/session_on_frame.rs
```

```rust
pub enum Frame {
    Hello { server_nonce: [u8; 32], proto_versions: Vec<u8> },
    Subscribe { pk_ch: [u8; 32], ttl_seconds: u32, sig: [u8; 64], since: Option<u64> },
    Ok { channel_id: [u8; 16] },
    Publish { channel_id: [u8; 16], client_ref: [u8; 16], blob: Vec<u8> },
    Ack { client_ref: [u8; 16], server_id: [u8; 16], received_at: u64 },
    Push { channel_id: [u8; 16], server_id: [u8; 16], received_at: u64, blob: Vec<u8> },
    Error { code: String, message: String, channel_id: Option<[u8; 16]>, client_ref: Option<[u8; 16]> },
}
impl Frame {
    pub fn encode(&self) -> Result<Vec<u8>, Error>;
    pub fn decode(bytes: &[u8]) -> Result<Frame, Error>;   // BadPayload on any schema failure
}

pub enum Event {
    Subscribed { channel: [u8; 16] }, HistoryTruncated { channel: [u8; 16], before: u64 },
    Message { channel: [u8; 16], received: Received },
    Delivered { channel: [u8; 16], client_ref: ClientRef, server_id: [u8; 16], received_at: u64, expires_at: u64 },
    NotDelivered { channel: [u8; 16], client_ref: ClientRef, sent_at: u64 },   // sent_at lets the client report a row it no longer lists
    StatusChanged { channel: [u8; 16] }, StorageFailed { channel: [u8; 16] },
    SubscribeRefused { channel: [u8; 16] }, ChannelFull { channel: [u8; 16] },
    ServerFull { connection: u64 }, UnsupportedServer { connection: u64 }, Reconnect { connection: u64 },
}

pub(crate) type Channels = Vec<Channel>;   // the Device's open channels, found by channel_id
pub(crate) struct Step { pub(crate) events: Vec<Event>, pub(crate) failed: Vec<([u8; 16], StoreError)> }

pub(crate) struct Session { /* connection id, channel ids, subscriptions, nonce, in-flight map, queue, rate window, pauses, holds, stalls */ }
impl Session {
    pub(crate) fn new(connection: u64, channel_ids: Vec<[u8; 16]>) -> Session;
    pub(crate) fn on_connect(&mut self, now: u64, skip: &[[u8; 16]]);
    pub(crate) fn on_disconnect(&mut self);
    pub(crate) fn on_frame(&mut self, frame: &[u8], channels: &mut Channels, now: u64) -> Step;
    pub(crate) fn on_tick(&mut self, channels: &mut Channels, now: u64) -> Step;
    pub(crate) fn after_send(&mut self, channel_id: [u8; 16], channels: &mut Channels, now: u64) -> Step;
    pub(crate) fn set_write_failed(&mut self, channel_id: [u8; 16], on: bool, storage_full: bool);   // R10, spec 027-core-api R14
    pub(crate) fn outgoing(&mut self) -> Vec<Vec<u8>>;
}
```

A `Step` never fails as a whole: a store failure in one channel goes to `failed` and the session carries on with the others, so no event already produced is lost. `Frame` derives no `PartialEq`; the tests compare encodings.

**PR slices** (AGENTS 14): (a) the frames, their vectors and the `frame_decode` target (R1, R2, R3's first target); (b1) `MemoryServer`, the connection and the subscription (R4–R7); (b2) truncation, `ok` and the `session_on_frame` target (R3's second target, R8, R9); (c1a) traffic, the `LogFull` stall and the stop after an own-key alert (R10's first half); (c1b) the stall after another store error and the `write_failed` mark (R10's second half); (c2) outcomes, acks and status (R11–R14, R17); (d) rate and errors (R15, R16); (e) the no-oracle property (R18). Each test clause lands in the slice that implements the last behaviour it needs; the list above names where each requirement is implemented, and a test that spans slices is completed clause by clause.

## Security

- A half-open socket on an awake device keeps a channel counted as subscribed until the client's ping timeout (specs 050–052), during which `synced` may still advance while nothing arrives; a suspended process is caught by R9's 5 000 ms rule, during the handshake as after it. Documented residual.
- The subscription signature proves having the config, binds the server's nonce, the channel, the TTL and the host, and is useless to whoever sees it (ADR 0010); the host is the config's, never the socket's.
- `since` is rounded down to the minute (R6): the server does not learn the exact last message read. The duplicates it brings are rejected by the channel (spec 021-channel-session R9).
- R4, R8 and R9 together close three holes of streamed history: no live push can move the cursor past an unsent part of the backlog; truncation is decided by the client's clock before the backlog, so a server can neither hide a deletion by claiming everything older expired nor repeat `ok` to reset the gap baseline; and a quiet channel is not flagged as truncated on every reconnect, because `synced_at` records when it was last complete. The cursor itself stays in server time (spec 021-channel-session R20), so a fast device clock skips nothing (spec 021-channel-session R20 leaves the cursor before a push already expired by the local clock).
- R10 never lets the cursor move past a push the channel could not store: once one is dropped, no later push of the connection is decrypted and `synced` is not called, and the connection is renewed from the same cursor when room returns. Meanwhile `check_own_key` keeps the own-key alert working, and the pending `outbox`, including a `key_retired`, still leaves.
- R18 is the session half of the no-oracle rule; its two documented exceptions depend on the user's own key or on local disk timing, not on anything a sender learns from a forged blob.
- No log line (spec 021-channel-session R28).

## Public API changes

- `Frame::encode`, `Frame::decode` and `Event` are `pub`; `Frame` is for the server only, `Event` reaches the clients through `Device` (spec 027-core-api). `Session` is crate-internal.
- `docs/spec.md` §6, brought up to date when this spec is accepted: the frame keys above; the backlog before `ok` (R4); `ok` without `has_more` or `oldest_retained_at`; `error` with optional `channel_id` and `client_ref`; one `client_ref` per `outbox` entry; one `subscribe` every 1 100 ms; the cursor clamped to the local clock and committed on its own at most once a minute, and `synced_at` beside it (spec 021-channel-session R20).

## Test cases

- T01 (covers R1): `s028_t01_r01_frame_schemas`: each frame round-trips; 70 001 bytes, `type` 7, a missing key and a 33-byte `code` → dropped with `Reconnect`; an unknown key is ignored.
- T02 (covers R2): `s028_t02_r02_version_list`: `[1]` → subscribes; `[]`, `[2]` and nine items including 1 → `UnsupportedServer`, and nothing is sent afterwards until `on_connect`.
- T03 (covers R3): `s028_t03_r03_frames_round_trip_and_fuzz`: `encode(decode(encode(f))) = encode(f)` for every frame (proptest); `scripts/check_fuzz_targets.sh` lists both targets; the `session_on_frame` seed of a `push` reaches `decrypt`.
- T04 (covers R4): `s028_t04_r04_memory_server_contract`: `MemoryServer` sends the backlog in order, then a live push published meanwhile, then `ok`, and never that push ahead of the backlog; two `publish`es on one connection are stored and acknowledged in the order sent.
- T05 (covers R5): `s028_t05_r05_reconnect_forgets_connection`: after `on_disconnect`, `on_tick` queues nothing; after `on_connect`, an `ack` of a previous `client_ref` is ignored and the `outbox` is published again after `ok`; a channel in `skip` is not subscribed.
- T06 (covers R6): `s028_t06_r06_subscribe_contents_and_pacing`: the signature verifies over the §6 message with the config's host; `since` of a cursor 90 000 is 60 000; no cursor → no `since`; three channels → subscribes at least 1 100 ms apart; a second `hello` discards the unreleased ones and re-subscribes only channels not subscribed; a 60-second channel among 15 one-day channels → its subscribe released first; a `nonce_expired` and a new `hello` 300 ms after a subscribe was released → the next subscribe released no earlier than 1 100 ms after that one.
- T07 (covers R7): `s028_t07_r07_nonce_window`: 16 channels with ticks every 1 000 ms → all released by about 31 000 ms; a subscribe that would be released 50 001 ms after `hello` → `Reconnect`; `nonce_expired` with no `hello` for 50 001 ms → `Reconnect`; no `hello` within 50 000 ms of `on_connect` → `Reconnect`.
- T08 (covers R8): `s028_t08_r08_truncation_before_backlog`: truncation found → `HistoryTruncated` at once, before any backlog push, and a server that never sends `ok` cannot hide it; a `synced_at` in the future is ignored; a cursor older than `ttl_ms + 360 000` with a backlog of Bob's counters 250–300 over a `max_counter` of 100 → no gap recorded for 250; a new channel created a minute ago → no truncation; an imported channel whose `created_at` is `now − ttl_ms − 300 000`, never synced → no truncation; a `subscribe` queued again after `rate_limited` on the same connection → no second `HistoryTruncated`; a quiet channel whose `synced_at` is recent, after a reopen → no truncation; a 60-second channel last complete 40 s before the `hello`, whose `ok` arrives 30 s later → `HistoryTruncated` at the `ok` and no `synced` there, also when one backlog push dated after the expired stretch arrived before the `ok`.
- T09 (covers R9): `s028_t09_r09_ok`: a second `ok` for a subscribed channel → ignored; a push of an unknown channel id → ignored; `ok` → `Subscribed`, `synced` called, the `outbox` published; no frame on the connection for 60 000 ms while a channel awaits `ok` → `Reconnect`, and a second channel's backlog arriving for 90 000 ms without its `ok` → no `Reconnect`; after a dropped push, `ok` does not call `synced`; a subscribed channel's `synced_at` follows the ticks; subscribed, then a tick 2·`ttl_ms` later → no `synced` commit, `Reconnect`, and `HistoryTruncated` on the next subscribe; after a 2·`ttl_ms` gap, a `push` frame and then a tick → no `synced`, `Reconnect`; `on_disconnect`, then `on_connect` 60 000 ms after the last tick, a tick 500 ms later, then `hello` and `ok` → no `Reconnect`, and `synced` called; a tick 5 000 ms after the previous call → `synced`; 5 001 ms after → `Reconnect`; after the gap, an `ok` on the same connection for a channel awaiting it → subscribed, but no `synced`; a suspension between `subscribe` and `ok`, then a push frame first → `Reconnect`, and the later `ok` calls no `synced`.
- T10 (covers R10): `s028_t10_r10_push_routing_and_stalls`: a valid push → `Message`; a forged one → no event; `Ok(None)` → no event; `LogFull` on the second of three backlog pushes → `StorageFailed` once, the third goes to `check_own_key`, the `ok` does not call `synced`, the cursor is the first push's, and after a purge frees room → `Reconnect`, and the next connection fetches the second and third pushes; a stall with 2 MiB expired ends after the channel's `relieve_headroom` (the step spec 027-core-api R12 runs from the tick, called directly here) and the next `on_tick` → `Reconnect`; once `check_own_key` returns `true`, or when the `decrypt` that began the stall set the flag, no ordinary entry of the current key is published while a pending `key_retired` still is, stale entries expire on the tick with `NotDelivered` and their `sent_at`, an `ok` arriving afterwards publishes nothing of the current key, and a `regenerate_identity` → `Reconnect`; `Io` on a push → `failed` holds the channel, later pushes of the connection are dropped, and the cursor stays; a channel set `write_failed` → later pushes go to `check_own_key`, a foreign own-key push raises the alert, the pending `key_retired` is published, an ack whose commit fails is reported in `failed` and nothing else, and no `Reconnect` from the session, before or after `set_write_failed(false)`; a foreign own-key blob that is the first push after the cursor, with `fail_commits` on → the alert in `status()` and the channel stopped; with the channel marked and a retirement sealed more than a minute before → the `key_retired` published; the mark kept across `on_disconnect` and `on_connect`, a foreign own-key push after the reconnect still raising the alert; an `Io` on a push, then `set_write_failed(true)`, then a foreign own-key push → the alert; after `set_write_failed(false)`, a push on the same connection not decrypted and the cursor unchanged; a failed ack commit → the entry not published again on the next ticks; a marked channel's `synced_at` unchanged; a marked channel with an empty backlog → `ok` does not call `synced`; a late `ack` of a memory-only `key_retired` copy → held until the minute changes, then published once; a marked channel with `storage_full` set, then `set_write_failed(false)` → no `Reconnect` while `storage_full` holds, and `Reconnect` on the first tick after it clears.
- T11 (covers R11): `s028_t11_r11_outcomes`: after a reconnect that lost an `ack`, the echo in the backlog → `Delivered`, and the entry leaves the in-flight set and is not published again; entries removed by a foreign own-key message → `NotDelivered`; an in-time `ack` of entry 6 with entry 5 still queued → `NotDelivered` for 5 in the same step as the `Delivered` for 6; an `ack` read after a suspension that trips R9's gap → no clock sample; every push → a sample with `live` false; after the gap trips, a second push and a later `ack` → no live sample; an `ack` arriving 40 s after its publish in a 60-second channel → a backlog sample.
- T12 (covers R12): `s028_t12_r12_ack_routing`: in-time `ack` → `Delivered` with `server_id`, `received_at` and `expires_at`; late → `NotDelivered`; `Ignored` and an unknown `client_ref` → nothing; a late `ack` of the current retirement → not published again within its minute.
- T13 (covers R13): `s028_t13_r13_status_event`: a stale push from one's own key that raises the event → `StatusChanged`, no other event; an `ack` that delivers the retirement → `StatusChanged`; a stranger's `key_retired` that removes its peer → `StatusChanged`; an ordinary message of a known peer with an unchanged name → no `StatusChanged`; a `send` that changes one's own name → `StatusChanged`; a live `ack` a day off → `StatusChanged`.
- T14 (covers R14): `s028_t14_r14_send_and_tick`: a send while subscribed queues one `publish`; while not subscribed or paused, none; an entry already in flight is not queued twice; a stale entry found on a tick → `NotDelivered`, for an unsubscribed channel of the session too; on an unmarked channel, an `outbox` whose commit fails → its blobs queued and `(channel, Io)` in `failed`; a marked, unsubscribed channel with a stale entry → `NotDelivered` once from memory.
- T15 (covers R15): `s028_t15_r15_publish_rate`: 31 sends in one minute → 30 frames at once, the 31st after the window.
- T16 (covers R16): `s028_t16_r16_error_codes`: one case per code of R16, with and without `client_ref` and `channel_id` where they apply; each named entry leaves the in-flight set; a `bad_blob` of the `key_retired` is not published again within its minute; a `bad_blob` naming nothing → `Reconnect`; a `rate_limited` naming a channel awaiting `ok` and no `client_ref` → that channel subscribed again, also when it arrives 130 s after the `hello` (then `nonce_expired`, a fresh `hello`, and the subscribe under the new nonce, with no `Reconnect`), and two such endings 12 s apart with 20 s of delay on the link → both channels subscribed, neither refused, and a publish on another subscribed channel still queued at once; a `rate_limited` naming a `client_ref` → no publish for 60 000 ms; a `bad_blob` naming an ordinary entry whose `abandon` commit fails (`fail_commits`) → no `NotDelivered`, the channel in `failed`, and the entry not published again until `set_write_failed(false)` or `on_disconnect`.
- T17 (covers R17): `s028_t17_r17_outgoing_drains`: a second call returns nothing.
- T18 (covers R18): `s028_t18_r18_no_oracle` proptest: runs that differ only in the bytes of pushes from peers (valid, forged, expired, replayed) give the same frame sequence.

## Vectors

`specs/vectors/028.json`: one encoded frame of each type, produced by the reference script (`derived`), and one case per schema rule, whose outcome is written in the text field `event` (`specs/vectors/README.md`): `type` 7, a missing mandatory key and a 33-byte `code` → `reconnect`; an `ok` with an unknown key → `accepted`; a `hello` with nine versions, with none and without 1 → `unsupported_server`. Every vector carries the input `frame_type`, the number at key 0 of its frame, so that Kotlin and Swift can check each frame through `probe_hello` (spec 040-uniffi R13, R14). Spec 030-ws-protocol's server reproduces them.

## Acceptance criterion

`cargo test -p privatechat-core s028_` green; the two fuzz targets build and run nightly; clippy and the documentation lint green.

## Out of scope

- The server side of every frame (specs 030–033), apart from the contract of R4.
- The TLS socket, the WebSocket library, ping and pong, backoff and the SOCKS5 connection (the clients, specs 050–052); `Session` sees only whole binary frames.
- Grouping channels into connections, the probe socket, store recovery and the phase 2 exit test (spec 027-core-api).

## Open questions

None.

Decided with the human reviewer on 2026-09-25 (recommendations accepted, `docs/audit-log.md`, Audit J decisions): 028-R4: the backlog before `ok` replaces `has_more` and `oldest_retained_at` of §6.; the recommendation taken: accept; the server holds live pushes of a subscription while it streams that subscription's backlog, which its send queue of §6 already bounds. 028-R16: `error` gains the optional `channel_id` and `client_ref`, so that `channel_quota`, `bad_auth` and `bad_blob` reach the right channel and entry.; the recommendation taken: accept.

Decided on 2026-09-25: the frame keys belong to this spec (`docs/spec.md` §6).

## History

- 2026-09-25 draft
- 2026-09-25 revised after audit J round 1 (`docs/audit-log.md`): driven by `Device`, one `Session` per planned connection; the backlog before `ok` and truncation by the client's clock; one `subscribe` per second and `Reconnect` past the nonce window; stalls on a store failure; the in-flight and queued sets; every error code with its effect; the no-oracle property scoped; the exit test inside `src/` with `MemoryServer`; the 016 amendment; PR slices
- 2026-09-25 revised after audit J round 2: truncation decided when the subscribe is queued, `ok` accepted once, `synced` at `ok`; `on_disconnect`; 1 100 ms pacing and unreleased subscribes discarded; a `LogFull` stall that keeps publishing and ends when room returns; echo acks; `Delivered` with its place; `NotDelivered` on every `outbox` path; refused entries leave the in-flight set; `Event` defined here; the fuzz target driven past `ok`; the exit test over `FailingVault` in fast mode with its own crash criterion
- 2026-09-25 revised after audit J round 3: a dropped push freezes the channel for the connection (no later `decrypt`, no `synced`) and a reconnect fetches it again; `check_own_key` during a stall; `Step` with per-channel failures; truncation by `max(cursor, synced_at)`; `skip` for refused channels; a hold for a refused `key_retired`; the wait for a `hello` after `nonce_expired`; outcomes from `take_outcomes`; `Delivered.expires_at`; the exit test moved to spec 027; the 011 `created_at` amendment
- 2026-09-25 revised after audit J round 4 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 5 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 6 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 7 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 8 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 9 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 10 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 11 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 12 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 17 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 19 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 20 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 21 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 22 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 23 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 24 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 26 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 27 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 28 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 30 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 31 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 32 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 33 (`docs/audit-log.md`)
- 2026-09-25 open questions decided with the human reviewer, recommendations accepted (`docs/audit-log.md`)
- 2026-09-25 amended after audit K round 7 (`docs/audit-log.md`): at most one stale-nonce subscribe outstanding (R7)
- 2026-09-25 amended after audit K round 6 (`docs/audit-log.md`): subscribes released in order of expiry (R6)
- 2026-09-25 amended after audit K round 5 (`docs/audit-log.md`): the check at `ok` uses the `last` captured at the subscribe (R9); the hold bound is per connection (R4)
- 2026-09-25 amended after audit K round 4 (`docs/audit-log.md`): a re-queued subscribe is released past the nonce window (R7); truncation checked again at `ok` (R9)
- 2026-09-25 amended after audit K round 3 (`docs/audit-log.md`): held pushes come before `ok` (R4)
- 2026-09-25 amended after audit K round 2 (`docs/audit-log.md`): the server ends a flooded subscription instead of closing (R4); a `rate_limited` naming a subscribed channel → `Reconnect` (R16)
- 2026-09-25 amended after audit K round 1 (`docs/audit-log.md`): subscribe spacing counts across `hello`s (R6); a `rate_limited` naming a channel and no `client_ref` re-queues that subscribe and does not stop publishing (R16)
- 2026-09-26 amended by spec 040-uniffi R14 while drafting phase 4: every vector carries `frame_type`
