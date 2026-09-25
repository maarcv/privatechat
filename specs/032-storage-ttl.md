# 032 — Server storage: one SQLite table, one writer, and the TTL purge

Status: draft
Phase: 3
Related ADRs: 0009, 0014, 0022
Depends on: 010-primitives-wrapper, 027-core-api
Blocks: 030-ws-protocol, 033-rate-limit-quotas, 035-server-ops
Human reviewer: Marc Vilardebó · Accepted on: —

## Context

The server keeps blobs only until their TTL, and the client does not trust it to delete them (ADR 0009). §6 "Storage" fixes the rest. There is one plain SQLite table, `messages(channel_id, server_id, received_at, expires_at, blob)`, accessed through `rusqlite` with `bundled`, in WAL mode, with one writer that groups inserts into short transactions. Every 60 s a purge deletes what has expired, with `secure_delete` and an incremental vacuum. There are no backups. §6 "Order and time" gives `received_at = max(wall_clock_ms, last_received_at + 1)`, which makes `received_at` unique and strictly increasing, so ordering by it is a total order. The cursor of spec 021-channel-session and the backlog of spec 030-ws-protocol R7 rely on that order.

This spec is that storage, implemented first in phase 3 (see the order in spec 030-ws-protocol's Context). It covers opening and checking the database, the writer thread, the order of `received_at`, the backlog reads, the purge, and the per-channel retention counters that spec 033-rate-limit-quotas checks. The writer is also where the channel limits are applied and where fan-out starts (spec 030 R12), because it is the one place where blobs are ordered. Every requirement here is tested through the writer and the reader alone, with no socket.

**In plain words.** All messages go into one table in one file, and a single worker writes to it. It takes whatever is waiting, saves it in one go, and only then says "stored" and passes the messages on to the listeners. Each message gets a time stamp that is always later than the previous one, even if the server's clock goes backwards or the server restarts, so everyone sees the same order. Every minute the worker deletes what has expired, overwrites the freed space and empties the database's side journal, so no expired message stays behind in either file. Nothing is ever copied elsewhere: when the TTL is over, the message is gone from the server.

**PR slices** (AGENTS 14): (a) the clock, `relay::new_server_id`, opening, pragmas, schema and the start-up checks (R1–R3, R14, R15); (b) the writer, `received_at` and commit handling (R4–R8); (c) reads, the purge, the counters and the checks that nothing is left behind (R9–R13).

## Requirements

**The database**

- R1 The database MUST hold two tables and two indexes, created on a new file in one transaction together with `PRAGMA user_version = 1`: `messages(server_id BLOB PRIMARY KEY CHECK (length(server_id) = 16), channel_id BLOB NOT NULL CHECK (length(channel_id) = 16), received_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, blob BLOB NOT NULL)`, `meta(id INTEGER PRIMARY KEY CHECK (id = 0), last_received_at INTEGER NOT NULL)` holding one row, `messages_by_channel(channel_id, received_at)` and `messages_by_expiry(expires_at)`.
- R2 On a new file, `auto_vacuum = INCREMENTAL` MUST be set before the tables are created, and then `journal_mode = WAL`. Every connection MUST set `busy_timeout = 5000` and `temp_store = MEMORY`. The writer's connection MUST set `synchronous = NORMAL`, `secure_delete = ON` and `journal_size_limit = 0`, and each reader's MUST set `query_only = ON`.
- R3 Opening MUST fail with a `StartError` of reason `Database`, naming the cause (`UserVersion`, `JournalMode`, `AutoVacuum` or `Open`), when the file's `user_version` is neither 0 (new) nor 1, when `journal_mode` does not read back as `wal`, when `auto_vacuum` does not read back as 2 (incremental), or when the file cannot be opened for writing. Spec 035-server-ops maps each reason to an exit code and never listens after one.

**The writer**

- R4 Exactly one OS thread MUST write to the database. It receives requests through a bounded channel of 1 024 entries. A request that finds the channel full MUST be refused with `rate_limited` without waiting.
- R5 The writer MUST take the first waiting request and every request already waiting behind it, up to 256, and store them in one transaction, in arrival order. Spec 033-rate-limit-quotas adds its channel checks here, before each insert.
- R6 The writer MUST give each inserted blob `server_id = relay::new_server_id()` (R15), refusing that request alone with `server_full` if a `SELECT` finds that id already stored (a 16-byte random collision, never retried), so that no statement of the transaction fails for it; `received_at = max(wall, last + 1)`; and `expires_at = wall + u64(ttl_seconds) × 1000`, `wall` being `Clock::wall_ms()` at the insert, so that a flood that pushes `received_at` ahead of the clock never keeps a blob past its TTL, with checked arithmetic and conversion to SQLite's signed 64-bit integer (an overflow refuses the request with `server_full`). `last` MUST be read from `meta` when the database is opened, before the start-up purge, and written back in every transaction that inserts, so that the order survives a restart, a clock set back, and a table the purge left empty.
- R7 Only after the transaction has committed may the writer hand its results to its `on_commit` callback, which spec 030-ws-protocol R12 connects to the hub: one result per request, stored or refused, in processing order, each carrying the id of the connection the request came from and its `client_ref`. When any statement of the transaction or its commit fails, the writer MUST roll back if the transaction is still open, report every request of the transaction as refused with `server_full` when SQLite returns `SQLITE_FULL` and with `rate_limited` otherwise, and go on with the next requests. The writer MUST keep, for each transaction, a working copy of `last`, the retention counters of R11 and the channel windows of spec 033, which each insert and each check before it reads and updates; the copy replaces the stored values when the transaction commits and is discarded when it rolls back, so that the blobs of one transaction see each other and a rolled-back one leaves nothing behind. No database error may panic.
- R8 Before each transaction, when `(page_count − freelist_count) × page_size` is at least `max_db_bytes` (spec 035-server-ops), the writer MUST refuse every request of that transaction with `server_full` and insert nothing.

**Reads, purge and counters**

- R9 `read_page(channel_id, from, now)` MUST return, ordered by `received_at`, the rows `(server_id, received_at, blob)` with that `channel_id`, `received_at ≥ from` and `expires_at > now`, stopping at 500 rows or before the row that would take the page past 256 KiB of blobs, whichever comes first, and always returning at least one row when one matches. The next page starts at the last `received_at` + 1. Reads MUST run on a pool of 4 read-only connections off the async threads.
- R10 When the writer starts, before `Writer::spawn` returns, and then every 60 000 ms of the clock, the writer MUST run the purge between two transactions. It repeats `DELETE FROM messages WHERE rowid IN (SELECT rowid FROM messages WHERE expires_at < ?now LIMIT 1000) RETURNING channel_id, length(blob)` until a round deletes fewer than 1 000 rows, then runs `PRAGMA incremental_vacuum(1000)` and `PRAGMA wal_checkpoint(TRUNCATE)`. A checkpoint that returns busy is left to the next purge.
- R11 The writer MUST keep, per `channel_id`, the number and total bytes of the rows in the table. It MUST rebuild them at start-up, after the first purge, with one `GROUP BY channel_id` query, add each insert, subtract each row the purge returns, and drop a channel whose count reaches 0.
- R12 The server MUST NOT copy blobs anywhere: no backup API, no `VACUUM INTO`, no export, and no SQL trace or profile callback.
- R13 After a purge whose checkpoint succeeded, no 64-byte run of a purged blob MUST remain in the database file or in its `-wal` file.

**Clock and identifiers**

- R14 Every time the server reads MUST come from one `Clock` with two readings: `wall_ms()`, unix milliseconds of the wall clock, used only for `received_at`, `expires_at`, the purge's `now` and the backlog read's `now` (spec 030 R7, and R9 of this spec); and `mono_ms()`, milliseconds of a monotonic clock, used for every deadline and window of this spec and of specs 030, 031 and 033 (nonce age, first-subscribe deadline, ping, pong and write deadlines, rate windows, the purge and totals intervals), so that a clock stepped forward or back fires none of them early or late. In tests a `ManualClock` drives both. `crates/server/src/clock.rs` MUST be the only file that calls `SystemTime::now` or `Instant::now`, and it allows `clippy::disallowed_methods` there with a reason. One server-wide deadline task MUST wake every 100 ms of real time and check every connection's deadlines against `mono_ms()`, and the writer's `recv_timeout(100 ms)` checks the purge the same way, so that moving a manual clock fires a deadline at the next wake. The shutdown limit of spec 035 is real time and stays outside `Clock`.
- R15 The `relay` module of `core` MUST expose `new_server_id()`, which draws 16 bytes with `random_bytes` of spec 010-primitives-wrapper, and this spec MUST amend spec 027-core-api (the items `pub` for `server`) with it.

## Limits

| Item | Range | Out of range |
| --- | --- | --- |
| Writer queue | 0..=1 024 requests | `rate_limited` |
| Requests per transaction | 1..=256, those already waiting | the rest go to the next transaction |
| `server_id` | 16 random bytes, new in the table | `server_full`, never retried |
| `received_at`, `expires_at` | 0..=2^63 − 1 (SQLite INTEGER) | `server_full` |
| Live database size, free pages excluded | < `max_db_bytes` (spec 035) | `server_full` |
| Backlog page | ≤ 500 rows and ≤ 256 KiB of blobs, at least one row | next page |
| Purge round | ≤ 1 000 rows, repeated until a round deletes fewer | — |
| Read pool | 4 connections | the next read waits for one |
| Deadline wake | ≤ 100 ms of real time | — |
| `user_version` | 0 or 1 | `StartError` |

## Interface

```
crates/core/src/relay.rs             new_server_id (R15); specs 030 and 031 add their items
crates/server/src/clock.rs           Clock, SystemClock, ManualClock (R14)
crates/server/src/store.rs           open, pragmas, schema and the start-up checks (R1–R3)
crates/server/src/store/writer.rs    the writer thread, batches, received_at, purge, counters (R4–R8, R10, R11)
crates/server/src/store/reader.rs    read_page and the read pool (R9)
crates/server/src/tests/store.rs     s032_* tests, with ManualClock and a temporary directory, no socket
```

```rust
pub mod relay { pub fn new_server_id() -> Result<[u8; 16], Error>; }   // core, `pub` for the server only

pub trait Clock: Send + Sync { fn wall_ms(&self) -> u64; fn mono_ms(&self) -> u64; }   // `pub` through the server's lib.rs (spec 035)
pub struct SystemClock;
pub struct ManualClock { /* AtomicU64 */ }                    // `pub` only under the feature `test-support`

pub(crate) struct WriteRequest {
    pub(crate) connection: u64, pub(crate) client_ref: [u8; 16],
    pub(crate) channel_id: [u8; 16], pub(crate) ttl_seconds: u32, pub(crate) blob: Vec<u8>,
}
pub(crate) enum Refusal { RateLimited, ChannelQuota, ServerFull }   // error codes of docs/spec.md §6
pub(crate) struct Row { pub(crate) server_id: [u8; 16], pub(crate) received_at: u64, pub(crate) blob: Vec<u8> }
pub(crate) struct WriteOutcome { pub(crate) connection: u64, pub(crate) client_ref: [u8; 16],
                            pub(crate) channel_id: [u8; 16], pub(crate) result: Result<Row, Refusal> }
pub(crate) type OnCommit = Box<dyn FnMut(Vec<WriteOutcome>) + Send>;   // processing order

pub(crate) struct Writer { /* std::sync::mpsc::SyncSender<WriteRequest> */ }
impl Writer {
    pub(crate) fn spawn(db: &Path, clock: Arc<dyn Clock>, on_commit: OnCommit, max_db_bytes: u64) -> Result<Writer, StartError>;
    pub(crate) fn submit(&self, request: WriteRequest) -> Result<(), Refusal>;   // try_send: RateLimited when full
    pub(crate) fn finish(self) -> oneshot::Receiver<()>;   // spec 035 R7: answer what is queued, checkpoint, close
}
pub(crate) struct StoreError(rusqlite::Error);   // a failed read; spec 030 R7 closes the connection with 1011
pub(crate) async fn read_page(pool: &ReadPool, channel_id: [u8; 16], from: u64, now: u64) -> Result<Vec<Row>, StoreError>;
```

The writer's channel is `std::sync::mpsc::sync_channel(1024)`. `try_send` never blocks an async task, `try_recv` gathers what is already waiting (R5), and `recv_timeout(100 ms)` wakes the writer for the purge (R14). Dependency added: `rusqlite` with the feature `bundled` (§9), justified in the pull request (AGENTS 8).

## Security

- The table holds only what the server already sees on the wire: `channel_id`, opaque blobs and its own `server_id` and times. The file is not encrypted (§6); disk encryption at rest is the operator's (spec 034-docker, `deploy/README.md`).
- `secure_delete` overwrites the pages of every purged row, the incremental vacuum gives space back, and the truncating checkpoint with `journal_size_limit = 0` empties the WAL, whose old frames would otherwise keep expired blobs past their TTL (R10, R13). A former member holds `K_ch` for ever, so any leftover would be readable. Copies outside the two files are out of the server's reach: volume snapshots, file-system journals, flash remapping, and the disk blocks a truncated WAL gives back without overwriting, which a raw image of the device can still read. R13 proves only what the files hold; the defence for the rest is disk encryption at rest, and `deploy/README.md` says that any snapshot must be kept for at most 60 s, or not taken at all.
- R6 makes `received_at` survive a restart, a clock set back and an empty table. Without it, a restarted server whose clock runs behind would give new blobs times below the cursors the clients already hold, and those clients would skip them.
- R7 reports only after the commit. An `ack` therefore means the blob is in the WAL, and it survives a process crash (spec 035-server-ops R9). With `synchronous = NORMAL` it may still be lost in a power failure; §6 documents that a crash may lose undelivered messages.
- R8 and R4 turn a full disk or an overloaded writer into `server_full` and `rate_limited`, never into a panic or an unbounded queue. R8 counts live pages only, so the space a large expiry frees is usable again at once.
- R9 bounds a page by bytes, so a reader never holds more than 256 KiB of backlog, and spec 030 R7 holds one page per connection.
- The server trusts its host's wall clock. A step of the clock by `d` is a residual, not a protocol failure: forward, the purge deletes up to `d` early and blobs stored meanwhile live up to `d` past their TTL once the clock is corrected; back, `received_at` lags real time by up to `d`, so clients reject messages of channels whose TTL is shorter than `d` as expired and show the clock warning of spec 021-channel-session for up to `d`. `deploy/README.md` asks the operator to run authenticated time synchronisation that slews and never steps the clock (spec 034-docker R7).
- No log line in this spec. Spec 035-server-ops fixes what the server may log, and R12 forbids SQL tracing.

## Public API changes

`core` gains `relay::new_server_id`, `pub` for the server only (spec 027-core-api list and `api_surface.rs`). `docs/spec.md` §6, brought up to date when this spec is accepted: `received_at` continues from the largest value ever stored, kept in `meta`; the writer groups what is already waiting instead of waiting 10 ms; the purge statement uses a sub-select because the bundled SQLite has no `DELETE … LIMIT`, and ends with a truncating checkpoint; the size quota counts live pages; backlog pages are bounded by bytes; the schema's `user_version`.

## Test cases

- T01 (covers R1): `s032_t01_r01_schema`: a new file has both tables, both indexes, `user_version` 1 and one `meta` row; a 15-byte `channel_id` or `server_id` inserted by hand → constraint error; a second `meta` row → constraint error.
- T02 (covers R2): `s032_t02_r02_pragmas`: on the writer's connection, `journal_mode` is `wal`, `auto_vacuum` 2, `synchronous` 1, `secure_delete` 1, `journal_size_limit` 0, `temp_store` 2 and `busy_timeout` 5000; a reader's `query_only` is 1, and an `INSERT` through it fails.
- T03 (covers R3): `s032_t03_r03_start_up_refusals`: `user_version` 2, a file created with `auto_vacuum = NONE`, and a read-only file → `Writer::spawn` returns a `StartError` of reason `Database` naming each cause.
- T04 (covers R4): `s032_t04_r04_queue_full`: with the writer paused by a test hook, the 1 025th request → `RateLimited` at once, and the first 1 024 are stored after the pause.
- T05 (covers R5): `s032_t05_r05_batches`: 300 requests submitted while the writer is paused → on release, two transactions of 256 and 44, stored in submission order; one request submitted to an idle writer → a transaction of one.
- T06 (covers R6): `s032_t06_r06_received_at_order`: with the clock stopped, three blobs in one transaction → `received_at` t, t + 1, t + 2; the clock set back an hour → still increasing; a restart with the clock a day behind → the next `received_at` is the previous maximum + 1; the same after a restart whose start-up purge emptied the table; `expires_at = wall + ttl_seconds × 1000` even when `received_at` runs ahead of the clock; a `new_server_id` hook returning a used id → that request `ServerFull`, the others of the batch stored.
- T07 (covers R7): `s032_t07_r07_report_after_commit`: `on_commit` is called after the commit and never before it (a hook between insert and commit sees no call), with one `WriteOutcome` per request in processing order carrying its connection and `client_ref`; `PRAGMA max_page_count` lowered to force `SQLITE_FULL` → every request of the batch `ServerFull`, the next batch stored once it is raised; a failure with `SQLITE_BUSY` → `RateLimited`; after each failed batch, the counters still equal a `GROUP BY` and the next `received_at` is unchanged.
- T08 (covers R8): `s032_t08_r08_disk_quota`: `max_db_bytes` below the live size → `ServerFull`, nothing inserted; after a purge frees the rows, with the file still as large → stored again.
- T09 (covers R9): `s032_t09_r09_read_page`: 1 200 rows of 1 185 bytes of one channel and 50 of another → pages of 500, 500 and 200 in order, none of the other channel; 40 rows of 64 673 bytes → ten pages of 4; a row with `expires_at = now` → not returned; eight concurrent reads → all complete, never more than 4 connections open.
- T10 (covers R10): `s032_t10_r10_purge`: 2 500 expired rows and 10 live ones → after `Writer::spawn` returns, 10 rows remain, deleted in rounds of 1 000, 1 000 and 500; `freelist_count` drops after the vacuum; the `-wal` file is empty after the checkpoint; the manual clock moved 60 000 ms → a second purge at the next wake.
- T11 (covers R11): `s032_t11_r11_counters`: counters equal a `GROUP BY` after inserts and a purge; after a restart they are rebuilt equal; a channel purged to zero rows has no entry.
- T12 (covers R12): a CI step named `s032_t12_r12_no_copy`: `crates/server/src` contains none of `backup`, `VACUUM INTO`, `trace(`, `profile(` in a `rusqlite` call.
- T13 (covers R13): `s032_t13_r13_nothing_left_behind`: 200 blobs of a known random pattern inserted, expired and purged → no 64-byte run of any of them is found in the database file or the `-wal` file.
- T14 (covers R14): `s032_t14_r14_one_clock`: a search of `crates/server/src` finds `SystemTime::now` and `Instant::now` only in `clock.rs`; with a `ManualClock`, `received_at` follows its wall reading; moving only its monotonic reading 60 000 ms → a purge, observed by polling for up to 5 s of real time with no further clock move; moving only its wall reading an hour forward → no purge and no deadline fired.
- T15 (covers R15): `s032_t15_r15_server_id`: two calls → two different 16-byte values.

## Vectors

None: the table is internal to the server and no other implementation reads it.

## Acceptance criterion

`cargo test -p privatechat-server s032_` green; clippy, `cargo deny --all-features check` and `scripts/doc_lint.sh` green.

## Out of scope

- The channel limits the writer applies, which spec 033-rate-limit-quotas adds to R5.
- The frames that carry a `WriteOutcome` to the client (spec 030-ws-protocol).
- The database path, `max_db_bytes`, the checkpoint at shutdown, the crash test and the exit codes (spec 035-server-ops).
- Postgres, replication and backups (none in v1, `docs/spec.md` §12).

## Open questions

None.

## History

- 2026-09-25 draft
- 2026-09-25 revised after audit K round 7 (`docs/audit-log.md`): a working copy per transaction for `last`, counters and windows
- 2026-09-25 revised after audit K round 6 (`docs/audit-log.md`): a used `server_id` found by `SELECT`; counters, windows and `last` change only on commit; `StoreError`
- 2026-09-25 revised after audit K round 5 (`docs/audit-log.md`): a failure of any statement, not only of the commit, refuses the whole transaction
- 2026-09-25 revised after audit K round 4 (`docs/audit-log.md`): the causes of a database refusal; `Writer::finish`
- 2026-09-25 revised after audit K round 3 (`docs/audit-log.md`): pages of 256 KiB; the backlog read on the wall reading; `Instant::now` checked; the clock-step residual stated
- 2026-09-25 revised after audit K round 2 (`docs/audit-log.md`): `expires_at` from the wall clock, not from `received_at`; `Clock` with a wall and a monotonic reading, deadlines on the monotonic one, one deadline task; `WriteOutcome`; the WAL blocks outside R13's reach stated
- 2026-09-25 revised after audit K round 1 (`docs/audit-log.md`): `last_received_at` kept in `meta`; the batch takes what is waiting, with no 10 ms timer; results with their connection through `on_commit`, no `oneshot`; no `server_id` retry; the quota counts live pages; pages bounded by bytes; a truncating checkpoint after each purge and a test that no purged byte remains; `temp_store = MEMORY`; deadlines checked on a 100 ms wake; the crash test moved to spec 035
