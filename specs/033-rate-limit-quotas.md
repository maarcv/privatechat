# 033 — Rate limits and quotas on the server

Status: draft
Phase: 3
Related ADRs: 0008, 0010, 0038
Depends on: 028-session-sans-io, 030-ws-protocol, 031-auth-channel-signature, 032-storage-ttl
Blocks: 035-server-ops, 041-desktop-bridge
Human reviewer: Marc Vilardebó · Accepted on: —

## Context

Anyone can open a connection, and anyone with a leaked config can write to its channel (`docs/spec.md` §2, rows "Attacker without the config" and "Intruder with the leaked config"). The table "Limits and quotas" of §6 bounds each scope: per connection, per channel across connections, per IP, and globally. This spec turns every row into a rule with its number, its answer, and the place in the server where it is checked.

Some of these numbers are part of the protocol, because the client of spec 028-session-sans-io paces itself against them: 30 `publish`es per minute (R15), one `subscribe` per 1 100 ms (R6), 16 channels per connection (spec 027-core-api R10). They are constants, the same on every server. The others protect one server's resources, and the operator may change them (spec 035-server-ops). §6 calls all of them "configurable on the server"; this spec narrows that to the second group.

**In plain words.** Each connection may send at most 30 messages a minute and listen to at most 16 channels, and it may try one login per second. Each channel may take at most 120 messages or 4 MiB a minute, and it may hold at most 20 000 messages or 64 MiB. Beyond that, new messages are refused and old ones are kept. The server remembers IP addresses in memory only, while a connection is open, to stop one address from opening too many; it never writes them down. The Tor entrance has its own budget, so a flood through Tor cannot lock out everyone else. A connection that stops answering, and makes no progress reading what it is sent, is dropped; the phone reconnects and picks up where it stopped.

**PR slices** (AGENTS 14): (a) the connection rules (R1–R5); (b) the channel rules inside the writer (R6, R7); (c) the IP table, the caps, the budgets and the configurable values (R8–R12).

## Requirements

**Per connection (fixed: the client paces against them)**

- R1 The server MUST refuse a `publish` with `error{rate_limited, channel_id, client_ref}` when 30 `publish`es of the same connection were handed to the writer within the preceding 57 000 ms of its clock. A refused `publish` does not count. The client keeps to 30 in any 60 000 ms (spec 028-session-sans-io R15), and the 3 000 ms difference absorbs network jitter.
- R2 A `subscribe` that arrives less than 1 000 ms after the previous `subscribe` of the same connection MUST get `error{rate_limited, channel_id}`, with `channel_id` from `relay::channel_id`, before any check of spec 031-auth-channel-signature. It is not a failed attempt (spec 031 R6).
- R3 A `subscribe` for a channel not yet subscribed or catching up, on a connection that already holds 16 subscriptions, MUST get `error{rate_limited, channel_id}` and then a close with status 1008, before any check of spec 031.
- R4 The server MUST send a WebSocket ping every 30 000 ms. It MUST close the connection with status 1001 when a ping has waited 30 000 ms, counted from when it was due, with no pong and with no write to the socket other than the ping itself completing in that time. A slow link that keeps taking frames is not closed for a pong stuck behind them.
- R5 When a frame counted by spec 030-ws-protocol R10 would take a connection's queue of frames not yet written past 256 frames or 4 MiB, the server MUST close that connection with status 1013 and drop the frame, since the client resumes from its cursor. A single write or flush to a socket that is still pending 30 000 ms after it started MUST drop the TCP connection with no close frame; progress within the write does not restart that time.

**Per channel (configurable)**

- R6 Before inserting a blob, the writer of spec 032-storage-ttl R5 MUST refuse it with `rate_limited` when its channel has had `channel_publish_per_min` blobs inserted within the preceding 60 000 ms, counting those already inserted by the same transaction (spec 032 R7), or when those blobs' bytes plus this one would exceed `channel_bytes_per_min`.
- R7 Before inserting a blob, the writer MUST refuse it with `channel_quota` when the counters of spec 032 R11, with the blobs already inserted by the same transaction, plus this blob would exceed `channel_max_blobs` blobs or `channel_max_bytes` bytes. Stored blobs are never deleted to make room.

**Per IP and global (configurable)**

- R8 On the main listener, before the WebSocket upgrade, with the client address of spec 035-server-ops R3 in canonical form (`IpAddr::to_canonical`, so that an IPv4-mapped IPv6 address counts as its IPv4 address), counted by its whole IPv4 address, or for IPv6 by its /64 inside the entry of its /48, which also counts the open connections against `ip48_connections` and those with no accepted `subscribe` against `ip48_unauth_connections`, and holds at most `ip48_subnets` /64s (a new /64 past that gets 429): the server MUST answer HTTP 429 with an empty body, and not upgrade, when that address already has `ip_connections` connections open, or `ip_unauth_connections` open with no accepted `subscribe`, or opened `ip_new_per_min` connections within the preceding 60 000 ms. The table holds IPv4 entries and /48 entries, each /64 counted inside its /48 and toward the table's 65 536; a /64 is never counted without its /48. When the table is full, a connection whose IPv4 address or /48 has an entry is still checked against all its bounds, and only one whose IPv4 address or /48 has none is admitted without an entry, bounded by R10 alone.
- R9 The server MUST keep a client address only in memory: in the table, while an entry counts an open connection, a connection opened within the last 60 000 ms or bytes published within the last 60 000 ms (R12), and nowhere else. An entry that counts nothing MUST be removed. Connections on the onion listener (spec 035 R2) carry no address and are outside R8.
- R10 Each listener MUST have its own caps: on the main listener, `max_connections` open and `max_unauth_connections` open with no accepted `subscribe`; on the onion listener, `onion_max_connections` and `max_unauth_connections`. A new upgrade past a cap of its listener MUST get HTTP 503 with an empty body.
- R11 The values of R6–R8, R10 and R12 MUST come from the configuration of spec 035-server-ops, with the defaults of the table "Limits". The values of R1–R5 MUST be constants in `limits.rs`.
- R12 Before a `publish` goes to the writer, the server MUST refuse it with `error{rate_limited, channel_id, client_ref}` when the blobs handed to the writer within the preceding 60 000 ms from connections of the same address (its IPv4 address or IPv6 /64), plus this one, would exceed `ip_bytes_per_min`, or those of its IPv6 /48 would exceed `ip48_bytes_per_min`, or, for a connection of the onion listener, when those of all onion connections would exceed `onion_bytes_per_min`.

## Limits

| Scope | Rule | Default | Configurable | Answer |
| --- | --- | --- | --- | --- |
| Connection | `publish`es handed to the writer per 57 000 ms | 30 | no | `rate_limited` |
| Connection | gap between two `subscribe`s | ≥ 1 000 ms | no | `rate_limited` |
| Connection | subscriptions | ≤ 16 | no | `rate_limited`, close 1008 |
| Connection | pong after a ping, with no write completing | ≤ 30 000 ms, ping every 30 000 ms | no | close 1001 |
| Connection | queue of frames not yet written (spec 030 R10) | ≤ 256 frames and ≤ 4 MiB | no | close 1013 |
| Connection | one pending write or flush | ≤ 30 000 ms | no | TCP dropped |
| Channel | inserts per 60 000 ms | `channel_publish_per_min` = 120 | yes | `rate_limited` |
| Channel | bytes inserted per 60 000 ms | `channel_bytes_per_min` = 4 MiB | yes | `rate_limited` |
| Channel | blobs held | `channel_max_blobs` = 20 000 | yes | `channel_quota` |
| Channel | bytes held | `channel_max_bytes` = 64 MiB | yes | `channel_quota` |
| IP (IPv6 by /64), main listener | open connections | `ip_connections` = 64 | yes | HTTP 429 |
| IP (IPv6 by /64), main listener | open connections with no accepted `subscribe` | `ip_unauth_connections` = 20 | yes | HTTP 429 |
| IP (IPv6 by /64), main listener | new connections per 60 000 ms | `ip_new_per_min` = 60 | yes | HTTP 429 |
| IP (IPv6 by /64), main listener | bytes published per 60 000 ms | `ip_bytes_per_min` = 8 MiB | yes | `rate_limited` |
| IPv6 /48, main listener | bytes published per 60 000 ms | `ip48_bytes_per_min` = 128 MiB | yes | `rate_limited` |
| Onion listener, all connections | bytes published per 60 000 ms | `onion_bytes_per_min` = 32 MiB | yes | `rate_limited` |
| IP table | IPv4 addresses, /48s and /64s held | 65 536 | no | an address with no entry is admitted under R10 only |
| IP table | /64s per /48 | `ip48_subnets` = 256 | yes | HTTP 429 |
| IPv6 /48, main listener | open connections; with no accepted `subscribe` | `ip48_connections` = 256; `ip48_unauth_connections` = 80 | yes | HTTP 429 |
| Main listener | open connections | `max_connections` = 4 096 | yes | HTTP 503 |
| Onion listener | open connections | `onion_max_connections` = 1 024 | yes | HTTP 503 |
| Each listener | open connections with no accepted `subscribe` | `max_unauth_connections` = 1 024 | yes | HTTP 503 |
| Global | live database size | `max_db_bytes` (spec 032 R8) | yes | `server_full` |

## Interface

```
crates/server/src/limits.rs              the constants of R1–R5, the per-connection windows, the IP table, the caps, the ingest budgets (R1–R5, R8–R10, R12)
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
pub(crate) const WRITE_TIMEOUT_MS: u64 = 30_000;
pub(crate) const SEND_QUEUE_FRAMES: usize = 256;
pub(crate) const SEND_QUEUE_BYTES: usize = 4 * 1024 * 1024;
pub(crate) const IP_TABLE_MAX: usize = 65_536;

pub(crate) struct ChannelLimits { pub(crate) publish_per_min: u32, pub(crate) bytes_per_min: u64,
                                  pub(crate) max_blobs: u32, pub(crate) max_bytes: u64 }
pub(crate) struct ConnectionLimits { pub(crate) ip_connections: u32, pub(crate) ip_unauth_connections: u32,
                                     pub(crate) ip_new_per_min: u32, pub(crate) max_connections: u32,
                                     pub(crate) onion_max_connections: u32, pub(crate) max_unauth_connections: u32,
                                     pub(crate) ip_bytes_per_min: u64, pub(crate) onion_bytes_per_min: u64,
                                     pub(crate) ip48_connections: u32, pub(crate) ip48_unauth_connections: u32,
                                     pub(crate) ip48_subnets: u32, pub(crate) ip48_bytes_per_min: u64 }
pub(crate) struct IpTable { /* Mutex<HashMap<IpKey, Entry>>: IPv4 by address, IPv6 by /48 with its /64s inside (≤ `ip48_subnets`), at most IP_TABLE_MAX entries and /64s in all */ }
```

`Writer::spawn` of spec 032 gains a `ChannelLimits` argument. The channel windows live in the writer thread, so the check and the insert happen in one place, in arrival order, with no lock. The ping and write deadlines and every window are measured with `Clock::mono_ms()` and checked by the deadline task of spec 032 R14.

## Security

- The channel rules protect the server and the other channels, not the channel itself. An intruder with the config can fill a channel in minutes and keep it full until the TTL (§6). The client shows `channel_quota` as "Channel full: probably flooded. Create a new one" (ADR 0008). The server never evicts old blobs to make room, because eviction would let an intruder erase the members' history.
- R6 and R7 run in the writer, which serialises all inserts. Two connections racing on the same channel cannot both slip under a limit.
- R8 keeps an address in memory while its connections are open and for a minute after each new one, and never stores or logs it (R9, spec 035 R4). That is what §2 row 1 already says the server sees. An operator can be compelled to log addresses (§2); only Tor prevents that.
- Counting IPv6 by /64 stops one host from rotating through the 2^64 addresses of its own prefix, and the /48 count stops one site or tunnel broker allocation from spreading over its 65 536 /64s. The canonical form stops a dual-stack listener from putting the whole IPv4 internet in one `::/64` bucket. A full table admits new addresses under the listener's caps instead of refusing them, so filling the table does not lock out honest clients.
- No server without accounts can stop a distributed attacker from filling its disk: availability is outside the model (§2 "Outside the model"). R12 makes one address, one /48 or the whole onion listener fill it slowly: at the defaults, one address needs about 17 hours to fill 8 GiB, which gives the operator time to see the totals line of spec 035 and act. The per-channel quota and `max_db_bytes` bound the rest.
- The onion listener has no per-IP rule, because behind Tor every client shares one address. Its own caps (R10) mean a flood through Tor can fill only the onion listener, never the main one; but within it one Tor client can use up `onion_bytes_per_min` and make every other onion user's publishes wait a minute at a time, and fill its connection caps. That is a residual of an address-free listener; `deploy/README.md` names `onion_bytes_per_min` and `onion_max_connections` among the values to raise, and an operator under such a flood can close the onion listener.
- Tor users of a public `wss://` server share their exit's address, and with a proxy every channel is its own connection (spec 027-core-api R10). After a restart, many of them may reconnect at once and meet R8 for a few minutes, and their clients back off. The same holds for many users behind one carrier-grade NAT or office address, where `ip_connections` also bounds how many can be connected at once, and `ip_bytes_per_min` is shared by all of them: one device publishing large blobs at that rate makes the others' publishes wait a minute at a time. Mobile carriers and some ISPs give each device its own /64 out of a /48 shared by many subscribers, so the /48 values bound all of them together: a few devices in such a /48, or more than `ip48_connections` honest connections, keep the rest of it out. `deploy/README.md` names `ip_connections`, `ip_unauth_connections`, `ip_new_per_min`, `ip_bytes_per_min` and the four `ip48_` values as the ones to raise for a server with many Tor, carrier-NAT, carrier-IPv6 or office users (spec 034-docker R7).
- R2 and R3 run before the signature check of spec 031, so a flood of `subscribe`s costs one BLAKE2b hash each, not up to 8 signature verifications.
- R4 and R5 together drop a peer that stops reading within about 60 s, freeing its queue, its holds and its backlog page (spec 030 R7), and never drop a slow peer that is still taking frames, down to a floor: a link that cannot take one 64 673-byte frame in 30 s (about 17 kbit/s) cannot use a channel whose blobs are that large. A close never loses a blob, since the client resumes from its cursor.

## Public API changes

None in `core`. `docs/spec.md` §6, brought up to date when this spec is accepted: the per-connection values are fixed and the channel, IP and global values are configurable; the server's publish window is 57 000 ms; the ping rule counts write progress, and a write stuck for 30 s drops the connection; the per-IP rules count every open connection, key IPv6 by /64 and /48, use the canonical address, add a byte budget per address and one for the onion listener, answer HTTP 429 (not "close"), apply on the main listener and not on the onion listener (replacing "not applied to connections from `127.0.0.1`", ADR 0038); a full IP table admits new addresses under the caps; each listener has its own connection caps, answered with HTTP 503.

## Test cases

- T01 (covers R1): `s033_t01_r01_connection_publish_rate`: 30 publishes at once → 30 `ack`s; a 31st → `rate_limited` naming the `channel_id` and the `client_ref`; 57 001 ms after the first → accepted; a refused publish does not move the window.
- T02 (covers R2): `s033_t02_r02_subscribe_gap`: two subscribes 999 ms apart → the second `rate_limited` with its `channel_id`, and the connection's failed-attempt count unchanged; 1 000 ms apart → both checked.
- T03 (covers R3): `s033_t03_r03_sixteen_channels`: 16 subscriptions accepted; a 17th channel → `rate_limited`, then close 1008; a second subscribe of an already subscribed channel with 16 held → ignored, not closed (spec 030 R9).
- T04 (covers R4): `s033_t04_r04_ping_pong`: a ping arrives every 30 000 ms of the manual clock; a client that stops answering and reading → closed 30 000 ms after the unanswered ping, with status 1001; a client that reads steadily but slowly behind a large backlog and whose pong comes late → not closed.
- T05 (covers R5): `s033_t05_r05_send_queue_and_write_deadline`, with the `cfg(test)` hook of spec 030 that pauses a connection's socket writes (the kernel would otherwise take megabytes first): with the channel limits raised, the clock stopped and a subscriber whose writes are paused, nine publishers of 1 185-byte blobs → 1013 at the 257th waiting frame, and three publishers of 64 673-byte blobs → 1013 past 4 MiB; its backlog alone never closes it (spec 030 T10); a connection whose writes are paused mid-frame → the TCP connection dropped with no close frame 30 000 ms of the monotonic clock after that write began.
- T06 (covers R6): `s033_t06_r06_channel_rate`: three connections on one channel, 121 publishes within 60 000 ms → the 121st `rate_limited`; blobs of 64 673 bytes → refused once the next would pass 4 MiB within the window; 60 001 ms later → accepted.
- T07 (covers R7): `s033_t07_r07_channel_quota`: with `channel_max_blobs = 5`, the sixth → `channel_quota`, also when all six arrive in one transaction, and the first five still served; after the purge removes two → two more accepted; `channel_max_bytes` behaves the same way on bytes.
- T08 (covers R8): `s033_t08_r08_ip_limits`: 20 unauthenticated connections from one address → the 21st gets 429 and no upgrade; one of them subscribes → a new one is accepted; 60 connections in a minute → the 61st gets 429; with `ip_connections = 3`, three subscribed connections → the fourth gets 429; two IPv6 addresses of one /64 share one count; `::ffff:1.2.3.4` and `1.2.3.4` share one count; five /64s of one /48 at `ip_unauth_connections` each → the /48 count refuses past `ip48_unauth_connections` (80), and a configuration with `ip48_unauth_connections = 200` → accepted up to 100; a table filled with 65 536 IPv4 addresses → a new IPv4 address is accepted without an entry, up to `max_unauth_connections`, and a known one is still checked; one /48 cycling through fresh /64s → a 257th /64 gets 429 (`ip48_subnets`), it cannot fill the table, and none of its connections gets past the /48's caps.
- T09 (covers R9): `s033_t09_r09_ip_forgotten`: after every connection of an address closes and 60 001 ms pass, the table has no entry for it; no connection state other than the table holds the address; a connection on the onion listener creates no entry.
- T10 (covers R10): `s033_t10_r10_listener_caps`: with `max_connections = 2` and `onion_max_connections = 1`, two main connections → a third main gets 503, and one onion connection is still accepted; a second onion connection → 503 while the main listener still accepts after one closes; `max_unauth_connections = 2` → the third unauthenticated connection of a listener gets 503.
- T11 (covers R11): `s033_t11_r11_configurable_values`: a configuration with `channel_publish_per_min = 10` → the 11th refused; the constants of R1–R5 equal the values of the table "Limits" and of spec 028's pacing (30, 16), and `SUBSCRIBE_GAP_MS` (1 000) is below spec 028 R6's 1 100 ms.
- T12 (covers R12): `s033_t12_r12_ingest_budgets`: with `ip_bytes_per_min = 200 000`, one address publishing 64 673-byte blobs on two of its own channels over four connections → the fourth blob within 60 000 ms `rate_limited` naming both fields; 60 001 ms later → accepted; two onion connections share `onion_bytes_per_min`.

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
- 2026-09-25 revised after audit K round 7 (`docs/audit-log.md`): the channel checks count the blobs of the same transaction; the onion-budget residual stated
- 2026-09-25 revised after audit K round 6 (`docs/audit-log.md`): the /48 values configurable by name instead of fixed multipliers; the shared carrier /48 stated
- 2026-09-25 revised after audit K round 5 (`docs/audit-log.md`): IPv6 entries per /48 with at most 256 /64s inside; a full table still checks known addresses; the ping's own write does not count as progress; T05 on a write-pause hook
- 2026-09-25 revised after audit K round 4 (`docs/audit-log.md`): a /48 byte budget at sixteen times the /64's; T05 and T11 made exact
- 2026-09-25 revised after audit K round 3 (`docs/audit-log.md`): the /48 count only for open connections; the shared byte budget in the NAT note
- 2026-09-25 revised after audit K round 2 (`docs/audit-log.md`): per-address and onion ingest budgets; IPv6 also by /48; canonical addresses; `ip_connections` 64; the write deadline from the start of a write; deadlines on the monotonic clock; the NAT and slow-link notes
- 2026-09-25 revised after audit K round 1 (`docs/audit-log.md`): the ping rule counts write progress and a stuck write drops the connection; per-IP limits count every open connection and key IPv6 by /64; a full table admits under the caps; each listener has its own caps; the Tor-exit case documented
