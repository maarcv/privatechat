# 032 — Server storage: one SQLite table, one writer, and the TTL purge

Status: draft
Phase: 3
Related ADRs: 0009, 0014, 0022
Depends on: 010-primitives-wrapper, 027-core-api
Blocks: 033-rate-limit-quotas, 035-server-ops
Human reviewer: Marc Vilardebó · Accepted on: —

## Context

The server keeps blobs only until their TTL, and the client does not trust it to delete them (ADR 0009). §6 "Storage" fixes the rest. There is one plain SQLite table, `messages(channel_id, server_id, received_at, expires_at, blob)`, accessed through `rusqlite` with `bundled`, in WAL mode, with one writer that groups inserts into short transactions. Every 60 s a purge deletes what has expired, with `secure_delete` and an incremental vacuum. There are no backups. §6 "Order and time" gives `received_at = max(wall_clock_ms, last_received_at + 1)`, which makes `received_at` unique and strictly increasing, so ordering by it is a total order. The cursor of spec 021-channel-session and the backlog of spec 030-ws-protocol R7 rely on that order.

This spec is that storage, implemented first in phase 3 (see the order in spec 030-ws-protocol's Context): opening and checking the database, the writer thread, the order of `received_at`, the backlog reads, the purge, and the per-channel retention counters that spec 033-rate-limit-quotas checks. The writer is also where the channel limits are applied and where fan-out starts (spec 030 R12), because it is the one place where blobs are ordered.

**In plain words.** All messages go into one table in one file. A single worker writes to it. It collects whatever arrives within 10 ms, saves it in one go, and only then says "stored" and passes the messages on to the listeners. Each message gets a time stamp that is always later than the previous one, even if the server's clock goes backwards or the server restarts, so everyone sees the same order. Every minute the worker deletes what has expired and overwrites the freed space. Nothing is ever copied elsewhere: when the TTL is over, the message is gone from the server.

**PR slices** (AGENTS 14): (a) the clock, `relay::new_server_id`, opening, pragmas, schema and the checks at start-up (R1–R3, R14, R15); (b) the writer, `received_at` and commit handling (R4–R8); (c) reads, the purge, the counters and the crash test (R9–R13).

## Requirements

**The database**

- R1 The database MUST hold one table and two indexes, created on a new file in one transaction together with `PRAGMA user_version = 1`: `messages(server_id BLOB PRIMARY KEY CHECK (length(server_id) = 16), channel_id BLOB NOT NULL CHECK (length(channel_id) = 16), received_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, blob BLOB NOT NULL)`, `messages_by_channel(channel_id, received_at)` and `messages_by_expiry(expires_at)`.
- R2 On a new file, `auto_vacuum = INCREMENTAL` MUST be set before the table is created, and then `journal_mode = WAL`. Every connection MUST set `busy_timeout = 5000`. The writer's connection MUST set `synchronous = NORMAL` and `secure_delete = ON`, and each reader's MUST set `query_only = ON`.
- R3 At start-up the server MUST refuse to run, before it listens, when the file's `user_version` is neither 0 (new) nor 1, when `journal_mode` does not read back as `wal`, when `auto_vacuum` does not read back as 2 (incremental), or when the file cannot be opened for writing (spec 035-server-ops maps each case to an exit code).

**The writer**

- R4 Exactly one OS thread MUST write to the database. It receives requests through a bounded channel of 1 024 entries. A request that finds the channel full MUST be refused with `rate_limited` without waiting.
- R5 The writer MUST take the first waiting request, then every request that arrives within 10 ms of taking it, up to 256, and store them in one transaction, in arrival order. Spec 033-rate-limit-quotas adds its channel checks here, before each insert.
- R6 The writer MUST give each inserted blob `server_id = relay::new_server_id()` (R15), drawn again when it already exists, at most 3 times in all (a fourth collision refuses the request with `server_full`); `received_at = max(clock, last + 1)`; and `expires_at = received_at + u64(ttl_seconds) × 1000`, with checked arithmetic and conversion to SQLite's signed 64-bit integer (an overflow refuses the request with `server_full`). At start-up, `last` MUST be the largest `received_at` in the table, or 0 when it is empty, so that the order survives a restart and a clock set back.
- R7 Only after the transaction has committed may the writer answer its requests and hand the stored blobs, in `received_at` order, to its `on_commit` callback, which spec 030-ws-protocol R12 connects to the hub. When the commit fails, the writer MUST roll back, answer every request of the transaction with `server_full` when SQLite reports `SQLITE_FULL` or `SQLITE_IOERR` of a full disk, and with `rate_limited` otherwise, and go on with the next requests. No database error may panic.
- R8 Before each transaction, when `page_count × page_size` is at least `max_db_bytes` (spec 035-server-ops), the writer MUST refuse every request of that transaction with `server_full` and insert nothing.

**Reads, purge and counters**

- R9 `read_page(channel_id, from, now)` MUST return at most 500 rows `(server_id, received_at, blob)` with that `channel_id`, `received_at ≥ from` and `expires_at > now`, ordered by `received_at`. The next page starts at the last `received_at` + 1. Reads MUST run on a pool of 4 read-only connections off the async threads.
- R10 At start-up before listening, and then every 60 000 ms of the clock, the writer MUST run the purge between two transactions. It repeats `DELETE FROM messages WHERE rowid IN (SELECT rowid FROM messages WHERE expires_at < ?now LIMIT 1000) RETURNING channel_id, length(blob)` until a round deletes fewer than 1 000 rows, then runs `PRAGMA incremental_vacuum(1000)`.
- R11 The writer MUST keep, per `channel_id`, the number and total bytes of the rows in the table. It MUST rebuild them at start-up, after the first purge, with one `GROUP BY channel_id` query, add each insert, subtract each row the purge returns, and drop a channel whose count reaches 0.
- R12 The server MUST NOT copy blobs anywhere: no backup API, no `VACUUM INTO`, no export, and no SQL trace or profile callback.
- R13 A blob whose `ack` was sent MUST still be in the table after the server process is killed with SIGKILL and started again on the same file.

**Clock and identifiers**

- R14 Every time the server reads MUST come from one `Clock`: unix milliseconds of the wall clock in production, a manual clock in tests. `crates/server/src/clock.rs` MUST be the only file that calls `SystemTime::now`, and it allows `clippy::disallowed_methods` there with a reason.
- R15 The `relay` module of `core` MUST expose `new_server_id()`, which draws 16 bytes with `random_bytes` of spec 010-primitives-wrapper, and this spec MUST amend spec 027-core-api (the items `pub` for `server`) with it.

## Limits

| Item | Range | Out of range |
| --- | --- | --- |
| Writer queue | 0..=1 024 requests | `rate_limited` |
| Requests per transaction | 1..=256, gathered for ≤ 10 ms | the rest go to the next transaction |
| `server_id` draws per blob | ≤ 3 | `server_full` |
| `received_at`, `expires_at` | 0..=2^63 − 1 (SQLite INTEGER) | `server_full` |
| Database size | < `max_db_bytes` (spec 035) | `server_full` |
| Backlog page | ≤ 500 rows | next page |
| Purge round | ≤ 1 000 rows, repeated until a round deletes fewer | — |
| Read pool | 4 connections | the next read waits for one |
| `user_version` | 0 or 1 | the server does not start |

## Interface

```
crates/core/src/relay.rs             new_server_id (R15); specs 030 and 031 add their items
crates/server/src/clock.rs           Clock, SystemClock, ManualClock (R14)
crates/server/src/store.rs           open, pragmas, schema and the start-up checks (R1–R3)
crates/server/src/store/writer.rs    the writer thread, batches, received_at, purge, counters (R4–R8, R10, R11)
crates/server/src/store/reader.rs    read_page and the read pool (R9)
crates/server/src/tests/store.rs     s032_* tests, with ManualClock and a temporary directory
crates/server/tests/s032_crash.rs    R13, over a child process
```

```rust
pub mod relay { pub fn new_server_id() -> Result<[u8; 16], Error>; }   // core, `pub` for the server only

pub(crate) trait Clock: Send + Sync { fn now_ms(&self) -> u64; }
pub(crate) struct SystemClock;
pub(crate) struct ManualClock { /* AtomicU64 */ }   // tests only

pub(crate) struct WriteRequest {
    pub(crate) channel_id: [u8; 16], pub(crate) ttl_seconds: u32, pub(crate) blob: Vec<u8>,
    pub(crate) reply: tokio::sync::oneshot::Sender<Result<Stored, Refusal>>,
}
pub(crate) struct Stored { pub(crate) server_id: [u8; 16], pub(crate) received_at: u64 }
pub(crate) enum Refusal { RateLimited, ChannelQuota, ServerFull }   // error codes of docs/spec.md §6
pub(crate) type OnCommit = Box<dyn FnMut(&[([u8; 16], Row)]) + Send>;   // (channel_id, row) in received_at order
pub(crate) struct Row { pub(crate) server_id: [u8; 16], pub(crate) received_at: u64, pub(crate) blob: Vec<u8> }

pub(crate) struct Writer { /* std::sync::mpsc::SyncSender<WriteRequest> */ }
impl Writer {
    pub(crate) fn spawn(db: &Path, clock: Arc<dyn Clock>, on_commit: OnCommit, max_db_bytes: u64) -> Result<Writer, StartError>;
    pub(crate) fn submit(&self, request: WriteRequest) -> Result<(), Refusal>;   // try_send: RateLimited when full
}
pub(crate) async fn read_page(pool: &ReadPool, channel_id: [u8; 16], from: u64, now: u64) -> Result<Vec<Row>, StoreError>;
```

The writer's channel is `std::sync::mpsc::sync_channel(1024)`. `try_send` never blocks an async task, and the writer's `recv_timeout` wakes it for the purge. Dependency added: `rusqlite` with the feature `bundled` (§9), justified in the pull request (AGENTS 8).

## Security

- The table holds only what the server already sees on the wire: `channel_id`, opaque blobs and its own `server_id` and times. The file is not encrypted (§6); disk encryption at rest is the operator's (spec 034-docker, `deploy/README.md`).
- `secure_delete` overwrites the pages of every purged row, and the incremental vacuum gives the space back. Copies outside the file (volume snapshots, the WAL before a checkpoint) are out of the server's reach. `deploy/README.md` says that any snapshot must be kept for at most 60 s, or not taken at all.
- R6 makes `received_at` survive a restart and a clock set back. Without it, a restarted server whose clock runs behind would give new blobs times below the cursors the clients already hold, and those clients would skip them.
- R7 answers only after the commit. An `ack` therefore means the blob is in the WAL, and it survives a process crash (R13). With `synchronous = NORMAL` it may still be lost in a power failure; §6 documents that a crash may lose undelivered messages.
- R8 and R4 turn a full disk or an overloaded writer into `server_full` and `rate_limited`, never into a panic or an unbounded queue.
- No log line in this spec. Spec 035-server-ops fixes what the server may log, and R12 forbids SQL tracing.

## Public API changes

`core` gains `relay::new_server_id`, `pub` for the server only (spec 027-core-api list and `api_surface.rs`). `docs/spec.md` §6, brought up to date when this spec is accepted: `received_at` continues from the largest stored value across restarts; the purge statement uses a sub-select because the bundled SQLite has no `DELETE … LIMIT`; the schema's `user_version`.

## Test cases

- T01 (covers R1): `s032_t01_r01_schema`: a new file has the table, both indexes and `user_version` 1; a 15-byte `channel_id` or `server_id` inserted by hand → constraint error.
- T02 (covers R2): `s032_t02_r02_pragmas`: on the writer's connection, `journal_mode` is `wal`, `auto_vacuum` 2, `synchronous` 1, `secure_delete` 1 and `busy_timeout` 5000; a reader's `query_only` is 1, and an `INSERT` through it fails.
- T03 (covers R3): `s032_t03_r03_start_up_refusals`: `user_version` 2 → refused; a file created with `auto_vacuum = NONE` → refused; a read-only file → refused; in each case no listener is opened.
- T04 (covers R4): `s032_t04_r04_queue_full`: with the writer paused by a test hook, the 1 025th request → `RateLimited` at once, and the first 1 024 are stored after the pause.
- T05 (covers R5): `s032_t05_r05_batches`: 300 requests submitted together → two transactions of 256 and 44, stored in submission order; a request arriving 11 ms after the first → a later transaction.
- T06 (covers R6): `s032_t06_r06_received_at_order`: with the clock stopped, three blobs → `received_at` t, t + 1, t + 2; the clock set back an hour → still increasing; a restart on the same file with the clock a day behind → the next `received_at` is the stored maximum + 1; `expires_at = received_at + ttl_seconds × 1000`; a `new_server_id` hook returning a used id twice → a third draw, stored; four collisions → `ServerFull`.
- T07 (covers R7): `s032_t07_r07_answer_after_commit`: `on_commit` is called after the commit and never before it (a hook between insert and commit sees no call); a commit failing with `SQLITE_FULL` → every request of the batch `ServerFull`, nothing pushed, the next batch stored; a failure with `SQLITE_BUSY` → `RateLimited`.
- T08 (covers R8): `s032_t08_r08_disk_quota`: `max_db_bytes` below the current size → `ServerFull`, nothing inserted; raised again → stored.
- T09 (covers R9): `s032_t09_r09_read_page`: 1 200 rows of one channel and 50 of another → pages of 500, 500 and 200 in order, none of the other channel; a row with `expires_at = now` → not returned; eight concurrent reads → all complete, never more than 4 connections open.
- T10 (covers R10): `s032_t10_r10_purge`: 2 500 expired rows and 10 live ones → after one purge 10 rows remain, in three rounds of 1 000, 1 000 and 500; `freelist_count` drops after the vacuum; the purge runs at start-up before the first connection is accepted, and again 60 000 ms later by the manual clock.
- T11 (covers R11): `s032_t11_r11_counters`: counters equal a `GROUP BY` after inserts and a purge; after a restart they are rebuilt equal; a channel purged to zero rows has no entry.
- T12 (covers R12): a CI step named `s032_t12_r12_no_copy`: `crates/server/src` contains none of `backup`, `VACUUM INTO`, `trace(`, `profile(` in a `rusqlite` call.
- T13 (covers R13): `s032_t13_r13_ack_survives_kill`: a child server process acknowledges a publish and is killed with SIGKILL; a new process on the same file serves that blob in the backlog.
- T14 (covers R14): `s032_t14_r14_one_clock`: a search of `crates/server/src` finds `SystemTime::now` only in `clock.rs`; with a `ManualClock`, `received_at` follows the manual time.
- T15 (covers R15): `s032_t15_r15_server_id`: two calls → two different 16-byte values.

## Vectors

None: the table is internal to the server and no other implementation reads it.

## Acceptance criterion

`cargo test -p privatechat-server s032_` green, the crash test included; clippy, `cargo deny --all-features check` and `scripts/doc_lint.sh` green.

## Out of scope

- The channel limits the writer applies, which spec 033-rate-limit-quotas adds to R5.
- The frames that carry `Stored` and `Refusal` to the client (spec 030-ws-protocol).
- The database path, `max_db_bytes`, the checkpoint at shutdown and the exit codes (spec 035-server-ops).
- Postgres, replication and backups (none in v1, `docs/spec.md` §12).

## Open questions

None.

## History

- 2026-09-25 draft
