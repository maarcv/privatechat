# 033 — Rate limits and quotas on the server

Status: draft
Phase: 3
Related ADRs: 0008, 0010, 0038
Depends on: 028-session-sans-io, 030-ws-protocol, 031-auth-channel-signature, 032-storage-ttl
Blocks: 035-server-ops
Human reviewer: Marc Vilardebó · Accepted on: —

## Context

Anyone can open a connection, and anyone with a leaked config can write to its channel (`docs/spec.md` §2, rows "Attacker without the config" and "Intruder with the leaked config"). The table "Limits and quotas" of §6 bounds each scope: per connection, per channel across connections, per IP before authentication, and globally. This spec turns every row into a rule with its number, its answer, and the place in the server where it is checked.

Some of these numbers are part of the protocol, because the client of spec 028-session-sans-io paces itself against them: 30 `publish`es per minute (R15), one `subscribe` per 1 100 ms (R6), 16 channels per connection (spec 027-core-api R10). They are constants, the same on every server. The others protect one server's resources, and the operator may change them (spec 035-server-ops). §6 calls all of them "configurable on the server"; this spec narrows that to the second group.

**In plain words.** Each connection may send at most 30 messages a minute and listen to at most 16 channels, and it may try one login per second. Each channel may take at most 120 messages or 4 MiB a minute, and it may hold at most 20 000 messages or 64 MiB. Beyond that, new messages are refused and old ones are kept. Before a connection has logged in, the server remembers its IP address in memory only, and only to stop one address from opening too many connections. After the login, the address is forgotten. A connection that stops answering pings, or cannot keep up with what it is sent, is closed. The phone then reconnects and picks up where it stopped.

**PR slices** (AGENTS 14): (a) the connection rules (R1–R5); (b) the channel rules inside the writer (R6, R7); (c) the IP table, the connection cap and the configurable values (R8–R11).

## Requirements

**Per connection (fixed: the client paces against them)**

- R1 The server MUST refuse a `publish` with `error{rate_limited, channel_id, client_ref}` when 30 `publish`es of the same connection were handed to the writer within the preceding 57 000 ms of its clock. A refused `publish` does not count. The client keeps to 30 in any 60 000 ms (spec 028-session-sans-io R15), and the 3 000 ms difference absorbs network jitter.
- R2 A `subscribe` that arrives less than 1 000 ms after the previous `subscribe` of the same connection MUST get `error{rate_limited, channel_id}`, with `channel_id` from `relay::channel_id`, before any check of spec 031-auth-channel-signature. It is not a failed attempt (spec 031 R6).
- R3 A `subscribe` for a channel not yet subscribed or catching up, on a connection that already holds 16 subscriptions, MUST get `error{rate_limited, channel_id}` and then a close with status 1008, before any check of spec 031.
- R4 The server MUST send a WebSocket ping every 30 000 ms, and close the connection with status 1001 when no pong arrives within 30 000 ms of a ping.
- R5 When a frame counted by spec 030-ws-protocol R10 would take a connection's queue of frames not yet written past 256 frames or 4 MiB, the server MUST close that connection with status 1013 and drop the frame, since the client resumes from its cursor.

**Per channel (configurable)**

- R6 Before inserting a blob, the writer of spec 032-storage-ttl R5 MUST refuse it with `rate_limited` when its channel has had `channel_publish_per_min` blobs inserted within the preceding 60 000 ms, or when those blobs' bytes plus this one would exceed `channel_bytes_per_min`.
- R7 Before inserting a blob, the writer MUST refuse it with `channel_quota` when the counters of spec 032 R11 plus this blob would exceed `channel_max_blobs` blobs or `channel_max_bytes` bytes. Stored blobs are never deleted to make room.

**Per IP, before authentication (configurable)**

- R8 On the main listener, before the WebSocket upgrade, with the client address of spec 035-server-ops R3: the server MUST answer HTTP 429 with an empty body, and not upgrade, when that address already has `ip_unauth_connections` connections open with no accepted `subscribe`, or opened `ip_new_per_min` connections within the preceding 60 000 ms. The same answer applies when the table of addresses holds 65 536 entries and this address is not among them.
- R9 The server MUST keep a client address only in memory, and only while it counts toward R8: in the connection's state until its first accepted `subscribe`, and in the table while an entry counts an open unauthenticated connection or a connection opened within the last 60 000 ms. An entry that counts nothing MUST be removed. Connections on the onion listener (spec 035 R2) carry no address and are outside R8.

**Global (configurable)**

- R10 When `max_connections` connections are open, across both listeners, a new upgrade MUST get HTTP 503 with an empty body.
- R11 The values of R6–R8 and R10 MUST come from the configuration of spec 035-server-ops, with the defaults of the table "Limits". The values of R1–R5 MUST be constants in `limits.rs`.

## Limits

| Scope | Rule | Default | Configurable | Answer |
| --- | --- | --- | --- | --- |
| Connection | `publish`es handed to the writer per 57 000 ms | 30 | no | `rate_limited` |
| Connection | gap between two `subscribe`s | ≥ 1 000 ms | no | `rate_limited` |
| Connection | subscriptions | ≤ 16 | no | `rate_limited`, close 1008 |
| Connection | pong after a ping | ≤ 30 000 ms, ping every 30 000 ms | no | close 1001 |
| Connection | queue of frames not yet written (spec 030 R10) | ≤ 256 frames and ≤ 4 MiB | no | close 1013 |
| Channel | inserts per 60 000 ms | `channel_publish_per_min` = 120 | yes | `rate_limited` |
| Channel | bytes inserted per 60 000 ms | `channel_bytes_per_min` = 4 MiB | yes | `rate_limited` |
| Channel | blobs held | `channel_max_blobs` = 20 000 | yes | `channel_quota` |
| Channel | bytes held | `channel_max_bytes` = 64 MiB | yes | `channel_quota` |
| IP, main listener | open connections with no accepted `subscribe` | `ip_unauth_connections` = 20 | yes | HTTP 429 |
| IP, main listener | new connections per 60 000 ms | `ip_new_per_min` = 60 | yes | HTTP 429 |
| IP table | addresses held | 65 536 | no | HTTP 429 for a new address |
| Global | open connections | `max_connections` = 4 096 | yes | HTTP 503 |
| Global | database size | `max_db_bytes` (spec 032 R8) | yes | `server_full` |

## Interface

```
crates/server/src/limits.rs              the constants of R1–R5, the per-connection windows, the IP table (R1–R5, R8–R10)
crates/server/src/store/writer.rs        the channel windows and quota checks, added to spec 032's writer (R6, R7)
crates/server/src/tests/limits.rs        s033_* tests, with ManualClock
```

```rust
pub(crate) const CONN_PUBLISH_MAX: usize = 30;
pub(crate) const CONN_PUBLISH_WINDOW_MS: u64 = 57_000;
pub(crate) const SUBSCRIBE_GAP_MS: u64 = 1_000;
pub(crate) const MAX_SUBSCRIPTIONS: usize = 16;
pub(crate) const PING_INTERVAL_MS: u64 = 30_000;
pub(crate) const PONG_TIMEOUT_MS: u64 = 30_000;
pub(crate) const SEND_QUEUE_FRAMES: usize = 256;
pub(crate) const SEND_QUEUE_BYTES: usize = 4 * 1024 * 1024;
pub(crate) const IP_TABLE_MAX: usize = 65_536;

pub(crate) struct ChannelLimits { pub(crate) publish_per_min: u32, pub(crate) bytes_per_min: u64,
                                  pub(crate) max_blobs: u32, pub(crate) max_bytes: u64 }
pub(crate) struct IpLimits { pub(crate) unauth_connections: u32, pub(crate) new_per_min: u32 }
pub(crate) struct IpTable { /* Mutex<HashMap<IpAddr, Entry>>, at most IP_TABLE_MAX entries */ }
```

`Writer::spawn` of spec 032 gains a `ChannelLimits` argument. The channel windows live in the writer thread, so the check and the insert happen in one place, in arrival order, with no lock.

## Security

- The channel rules protect the server and the other channels, not the channel itself. An intruder with the config can fill a channel in minutes and keep it full until the TTL (§6). The client shows `channel_quota` as "Channel full: probably flooded. Create a new one" (ADR 0008). The server never evicts old blobs to make room, because eviction would let an intruder erase the members' history.
- R6 and R7 run in the writer, which serialises all inserts. Two connections racing on the same channel cannot both slip under a limit.
- R8 uses the IP only before authentication. After the first accepted `subscribe` the server forgets it (R9), so no stored state links an address to a channel. It still sees the address while the connection is open, as §2 row 1 says. An operator can be compelled to log it (§2); only Tor prevents that.
- The onion listener has no per-IP rule: behind Tor every client shares the same address. Only R1–R7 and R10 bound it, and an operator who fears a flood through Tor can close that listener.
- R2 and R3 run before the signature check of spec 031, so a flood of `subscribe`s costs one BLAKE2b hash each, not up to 8 signature verifications.
- R5 closes a slow reader instead of buffering without limit, and a close never loses a blob: the client resumes from its cursor.

## Public API changes

None in `core`. `docs/spec.md` §6, brought up to date when this spec is accepted: the per-connection values are fixed and the channel, IP and global values are configurable; the server's publish window is 57 000 ms; the per-IP rule applies on the main listener and not on the onion listener (replacing "not applied to connections from `127.0.0.1`", ADR 0038); a full IP table refuses new addresses; the global connection cap and HTTP 503.

## Test cases

- T01 (covers R1): `s033_t01_r01_connection_publish_rate`: 30 publishes at once → 30 `ack`s; a 31st → `rate_limited` naming the `channel_id` and the `client_ref`; 57 001 ms after the first → accepted; a refused publish does not move the window.
- T02 (covers R2): `s033_t02_r02_subscribe_gap`: two subscribes 999 ms apart → the second `rate_limited` with its `channel_id`, and the connection's failed-attempt count unchanged; 1 000 ms apart → both checked.
- T03 (covers R3): `s033_t03_r03_sixteen_channels`: 16 subscriptions accepted; a 17th channel → `rate_limited`, then close 1008; a second subscribe of an already subscribed channel with 16 held → ignored, not closed (spec 030 R9).
- T04 (covers R4): `s033_t04_r04_ping_pong`: a ping arrives every 30 000 ms; a client that stops answering → closed 30 000 ms after the unanswered ping, with status 1001.
- T05 (covers R5): `s033_t05_r05_send_queue`: a subscriber that stops reading while another connection publishes → closed with 1013 once 256 frames or 4 MiB are waiting; its backlog alone never closes it (spec 030 T10).
- T06 (covers R6): `s033_t06_r06_channel_rate`: three connections on one channel, 121 publishes within 60 000 ms → the 121st `rate_limited`; blobs of 64 673 bytes → refused once the next would pass 4 MiB within the window; 60 001 ms later → accepted.
- T07 (covers R7): `s033_t07_r07_channel_quota`: with `channel_max_blobs = 5`, the sixth → `channel_quota`, and the first five still served; after the purge removes two → two more accepted; `channel_max_bytes` behaves the same way on bytes.
- T08 (covers R8): `s033_t08_r08_ip_limits`: 20 unauthenticated connections from one address → the 21st gets 429 and no upgrade; one of them subscribes → a new one is accepted; 60 connections in a minute → the 61st gets 429; a table filled with 65 536 addresses → a new address gets 429, and a known one is still served.
- T09 (covers R9): `s033_t09_r09_ip_forgotten`: after the first accepted subscribe, the connection's state holds no address; 60 001 ms later, with that connection still open, the table has no entry for it; a connection on the onion listener creates no entry.
- T10 (covers R10): `s033_t10_r10_connection_cap`: with `max_connections = 3`, three open connections (two on the main listener, one on the onion listener) → the fourth gets 503; one closes → accepted.
- T11 (covers R11): `s033_t11_r11_configurable_values`: a configuration with `channel_publish_per_min = 10` → the 11th refused; the constants of R1–R5 equal the values of the table "Limits" and of spec 028's pacing (30, 16, 1 000 ms).

## Vectors

None: no format.

## Acceptance criterion

`cargo test -p privatechat-server s033_` green; clippy and `scripts/doc_lint.sh` green.

## Out of scope

- The client's pacing and its reaction to each error (spec 028-session-sans-io R15, R16).
- The database size check (spec 032-storage-ttl R8), which this spec only lists.
- Reading the configuration and deriving the client address (spec 035-server-ops).
- Any rule within a channel against spam from a member: that is the client's (mute unknowns, `docs/spec.md` §7).

## Open questions

None.

## History

- 2026-09-25 draft
