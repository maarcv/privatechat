//! The one writer of the database (spec 032-storage-ttl R4–R8): a thread
//! that takes every request already waiting, up to 256, stores them in one
//! transaction in arrival order, and reports each one only after the commit.
//! It is the one place where blobs are ordered, so `received_at` is given
//! here and nowhere else.

pub(crate) mod purge;
#[cfg(test)]
pub(crate) mod test;

use std::collections::{HashMap, VecDeque};
use std::path::Path;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::JoinHandle;
use std::time::Duration;

use rusqlite::{Connection, ErrorCode, OptionalExtension, Transaction, TransactionBehavior};
use tokio::sync::oneshot;

use self::purge::{Counters, PURGE_INTERVAL_MS, Usage};
use super::{open_writer, refused};
use crate::clock::Clock;
use crate::limits::{CHANNEL_WINDOW_MS, ChannelLimits};
use crate::{DbCause, StartError};

/// Requests waiting for the writer; one more is refused (R4).
pub(crate) const QUEUE_LEN: usize = 1_024;

/// The most requests stored in one transaction (R5).
pub(crate) const MAX_BATCH: usize = 256;

/// How long the writer waits for a request before it looks at its timers
/// (R14).
const WAKE: Duration = Duration::from_millis(100);

/// Milliseconds in a second, for `ttl_seconds` (R6).
const MS_PER_SECOND: u64 = 1_000;

/// One `publish` handed to the writer by a connection (spec 030-ws-protocol R11).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WriteRequest {
    pub(crate) connection: u64,
    pub(crate) client_ref: [u8; 16],
    pub(crate) channel_id: [u8; 16],
    pub(crate) ttl_seconds: u32,
    pub(crate) blob: Vec<u8>,
}

/// Why a request was not stored: the error codes of `docs/spec.md` §6.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refusal {
    RateLimited,
    ChannelQuota,
    ServerFull,
}

/// A stored blob, as a backlog read or a `push` carries it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Row {
    pub(crate) server_id: [u8; 16],
    pub(crate) received_at: u64,
    pub(crate) blob: Vec<u8>,
}

/// What became of one request, for the connection it came from (R7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WriteOutcome {
    pub(crate) connection: u64,
    pub(crate) client_ref: [u8; 16],
    pub(crate) channel_id: [u8; 16],
    pub(crate) result: Result<Row, Refusal>,
}

/// Receives the outcomes of each transaction, in processing order, after
/// its commit (R7).
pub(crate) type OnCommit = Box<dyn FnMut(Vec<WriteOutcome>) + Send>;

/// The handle of the writer thread. Dropping it lets the thread store what
/// is queued and waits for it to close the database.
pub(crate) struct Writer {
    sender: Option<SyncSender<WriteRequest>>,
    thread: Option<JoinHandle<()>>,
}

impl Writer {
    /// Opens the database and starts the writer thread (R1–R4).
    ///
    /// # Errors
    ///
    /// `StartError` of reason `Database` as `open_writer` refuses the file,
    /// or with cause `Open` when `meta` cannot be read or the thread cannot
    /// start.
    pub(crate) fn spawn(
        db: &Path,
        clock: Arc<dyn Clock>,
        on_commit: OnCommit,
        max_db_bytes: u64,
        limits: ChannelLimits,
    ) -> Result<Writer, StartError> {
        Writer::start(db, clock, on_commit, max_db_bytes, limits, Hooks::default())
    }

    fn start(
        db: &Path,
        clock: Arc<dyn Clock>,
        on_commit: OnCommit,
        max_db_bytes: u64,
        limits: ChannelLimits,
        hooks: Hooks,
    ) -> Result<Writer, StartError> {
        let connection = open_writer(db)?;
        // `last` is read before the purge, which may leave the table empty (R6).
        let last = read_last(&connection).map_err(|_| refused(DbCause::Open))?;
        let (sender, receiver) = mpsc::sync_channel(QUEUE_LEN);
        let mut thread = WriterThread {
            connection,
            clock,
            on_commit,
            max_db_bytes,
            limits,
            windows: HashMap::new(),
            last,
            counters: Counters::new(),
            last_purge: 0,
            hooks,
        };
        // The first purge, then the counters of what it left (R10, R11).
        // A failing purge leaves its rows to the next one, as every purge
        // does; the counters below count what stands.
        let _ = thread.purge();
        thread.counters =
            purge::count_all(&thread.connection).map_err(|_| refused(DbCause::Open))?;
        thread
            .hooks
            .after_step(&thread.connection, &thread.counters);
        let handle = std::thread::Builder::new()
            .name("writer".to_owned())
            .spawn(move || thread.run(&receiver))
            .map_err(|_| refused(DbCause::Open))?;
        Ok(Writer {
            sender: Some(sender),
            thread: Some(handle),
        })
    }

    /// Queues `request` without waiting (R4).
    ///
    /// # Errors
    ///
    /// `Refusal::RateLimited` when the queue is full, or the writer is gone.
    pub(crate) fn submit(&self, request: WriteRequest) -> Result<(), Refusal> {
        let sender = self.sender.as_ref().ok_or(Refusal::RateLimited)?;
        sender.try_send(request).map_err(|error| match error {
            TrySendError::Full(_) | TrySendError::Disconnected(_) => Refusal::RateLimited,
        })
    }
}

impl Writer {
    /// Stops taking requests, stores and answers those already queued,
    /// empties the WAL and closes the database; the receiver hears when that
    /// is done (spec 035-server-ops R7).
    pub(crate) fn finish(mut self) -> oneshot::Receiver<()> {
        let (done, finished) = oneshot::channel();
        drop(self.sender.take());
        // Shared with the waiting thread, so that the join still happens here
        // when that thread cannot start: the receiver never hears of an end
        // that has not come.
        let wait = Arc::new(Mutex::new(Some((self.thread.take(), done))));
        let shared = wait.clone();
        let spawned = std::thread::Builder::new()
            .name("writer-finish".to_owned())
            .spawn(move || join_and_tell(&shared));
        if spawned.is_err() {
            join_and_tell(&wait);
        }
        finished
    }
}

impl Drop for Writer {
    fn drop(&mut self) {
        // Closing the queue ends the thread once it has stored what is queued.
        drop(self.sender.take());
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// `(page_count − freelist_count) × page_size` (R8).
fn live_bytes(connection: &Connection) -> Result<u64, rusqlite::Error> {
    let pages = pragma_u64(connection, "page_count")?
        .saturating_sub(pragma_u64(connection, "freelist_count")?);
    Ok(pages.saturating_mul(pragma_u64(connection, "page_size")?))
}

/// A pragma that reads a count, never negative.
fn pragma_u64(connection: &Connection, name: &str) -> Result<u64, rusqlite::Error> {
    let value: i64 = connection.pragma_query_value(None, name, |row| row.get(0))?;
    u64::try_from(value).map_err(|_| rusqlite::Error::IntegralValueOutOfRange(0, value))
}

/// The writer thread and `finish`'s sender, taken by whoever joins first.
type FinishWait = Mutex<Option<(Option<JoinHandle<()>>, oneshot::Sender<()>)>>;

/// Joins the writer thread, if it still has to be, then tells `finish`'s
/// receiver; whoever takes the pair first does it.
fn join_and_tell(wait: &FinishWait) {
    let taken = wait.lock().unwrap_or_else(PoisonError::into_inner).take();
    if let Some((thread, done)) = taken {
        if let Some(thread) = thread {
            let _ = thread.join();
        }
        let _ = done.send(());
    }
}

/// `last_received_at` as stored (R6).
fn read_last(connection: &Connection) -> Result<u64, rusqlite::Error> {
    let last: i64 = connection.query_row(
        "SELECT last_received_at FROM meta WHERE id = 0",
        [],
        |row| row.get(0),
    )?;
    u64::try_from(last).map_err(|_| rusqlite::Error::IntegralValueOutOfRange(0, last))
}

/// What the writer thread owns.
struct WriterThread {
    connection: Connection,
    clock: Arc<dyn Clock>,
    on_commit: OnCommit,
    max_db_bytes: u64,
    /// The limits of a channel (spec 033-rate-limit-quotas R6, R7).
    limits: ChannelLimits,
    /// What each channel inserted within the last `CHANNEL_WINDOW_MS`, as
    /// committed: the monotonic time of each commit and the blobs and bytes
    /// it inserted (spec 033 R6). A channel with none has no entry.
    windows: Windows,
    /// The largest `received_at` ever committed (R6).
    last: u64,
    /// The rows of each channel, as committed (R11).
    counters: Counters,
    /// The monotonic reading of the last purge (R10, R14).
    last_purge: u64,
    hooks: Hooks,
}

impl WriterThread {
    fn run(&mut self, receiver: &Receiver<WriteRequest>) {
        loop {
            self.hooks.wait_while_paused();
            if self.clock.mono_ms().saturating_sub(self.last_purge) >= PURGE_INTERVAL_MS {
                // A purge that fails leaves its rows to the next one.
                let _ = self.purge();
                self.hooks.after_step(&self.connection, &self.counters);
            }
            let first = match receiver.recv_timeout(WAKE) {
                Ok(first) => first,
                Err(RecvTimeoutError::Timeout) => continue,
                Err(RecvTimeoutError::Disconnected) => {
                    // The queue is closed and empty: leave nothing in the WAL.
                    let _ = self.connection.query_row(
                        "PRAGMA wal_checkpoint(TRUNCATE)",
                        [],
                        |_| Ok(()),
                    );
                    return;
                }
            };
            let mut batch = vec![first];
            while batch.len() < MAX_BATCH {
                match receiver.try_recv() {
                    Ok(request) => batch.push(request),
                    Err(_) => break,
                }
            }
            let outcomes = self.store(batch);
            self.hooks.after_step(&self.connection, &self.counters);
            (self.on_commit)(outcomes);
        }
    }

    /// Runs the purge of R10 on the wall clock's `now`. A failure is left
    /// to the next purge; its error is for the log of spec 035-server-ops R4,
    /// which names each database error by its code.
    fn purge(&mut self) -> Result<(), rusqlite::Error> {
        self.last_purge = self.clock.mono_ms();
        let hooks = &mut self.hooks;
        purge::purge(
            &self.connection,
            self.clock.wall_ms(),
            &mut self.counters,
            &mut |rows| hooks.purge_round(rows),
        )
    }

    /// Stores one batch in one transaction and returns its outcomes (R5–R8).
    fn store(&mut self, batch: Vec<WriteRequest>) -> Vec<WriteOutcome> {
        let now = self.clock.mono_ms();
        self.windows.retain(|_, window| {
            while window
                .front()
                .is_some_and(|(at, _)| now.saturating_sub(*at) > CHANNEL_WINDOW_MS)
            {
                window.pop_front();
            }
            !window.is_empty()
        });
        let results = if self.is_full() {
            vec![Err(Refusal::ServerFull); batch.len()]
        } else {
            self.insert_all(&batch)
                .unwrap_or_else(|error| vec![Err(refusal_for(&error)); batch.len()])
        };
        batch
            .into_iter()
            .zip(results)
            .map(|(request, result)| WriteOutcome {
                connection: request.connection,
                client_ref: request.client_ref,
                channel_id: request.channel_id,
                result: result.map(|(server_id, received_at)| Row {
                    server_id,
                    received_at,
                    blob: request.blob,
                }),
            })
            .collect()
    }

    /// Whether the live pages reach `max_db_bytes` (R8). A size that cannot
    /// be read counts as full.
    fn is_full(&self) -> bool {
        live_bytes(&self.connection).map_or(true, |bytes| bytes >= self.max_db_bytes)
    }

    /// Inserts every request of the batch in one transaction, with a working
    /// copy of `last` and of the counters that replaces the stored values
    /// only on commit (R6, R7, R11).
    fn insert_all(&mut self, batch: &[WriteRequest]) -> Result<Vec<Stored>, rusqlite::Error> {
        self.hooks.before_transaction(&self.connection);
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut working = Working {
            last: self.last,
            stored: None,
            added: Counters::new(),
        };
        let mut results = Vec::with_capacity(batch.len());
        for request in batch {
            let refused = refusal(
                &self.limits,
                &self.windows,
                &self.counters,
                &working,
                request,
            );
            let stored = match refused {
                Some(refusal) => Err(refusal),
                None => insert(
                    &transaction,
                    &*self.clock,
                    &mut self.hooks,
                    &mut working,
                    request,
                )?,
            };
            results.push(stored);
        }
        if let Some(stored) = working.stored {
            transaction.execute(
                "UPDATE meta SET last_received_at = ?1 WHERE id = 0",
                [stored],
            )?;
        }
        self.hooks.before_commit(&transaction);
        transaction.commit()?;
        self.last = working.last;
        let now = self.clock.mono_ms();
        for (channel_id, usage) in working.added {
            purge::add(&mut self.counters, channel_id, usage);
            self.windows
                .entry(channel_id)
                .or_default()
                .push_back((now, usage));
        }
        Ok(results)
    }
}

/// The refusal of spec 033-rate-limit-quotas `request` gets before it is
/// inserted, counting what this transaction inserted already: first what
/// its channel holds (R7), which outlasts the window and pauses that channel
/// alone at the client, then its channel's inserts within `CHANNEL_WINDOW_MS`
/// (R6). Stored blobs are never deleted to make room.
fn refusal(
    limits: &ChannelLimits,
    windows: &Windows,
    counters: &Counters,
    working: &Working,
    request: &WriteRequest,
) -> Option<Refusal> {
    let channel_id = request.channel_id;
    let bytes = u64::try_from(request.blob.len()).unwrap_or(u64::MAX);
    let ours = working.added.get(&channel_id).copied();
    let sum = |usages: &mut dyn Iterator<Item = Usage>| {
        usages.fold(Usage::default(), |sum, usage| Usage {
            blobs: sum.blobs.saturating_add(usage.blobs),
            bytes: sum.bytes.saturating_add(usage.bytes),
        })
    };
    let held = sum(&mut counters.get(&channel_id).copied().into_iter().chain(ours));
    if held.blobs >= u64::from(limits.max_blobs)
        || held.bytes.saturating_add(bytes) > limits.max_bytes
    {
        return Some(Refusal::ChannelQuota);
    }
    let window = windows.get(&channel_id).into_iter().flatten();
    let recent = sum(&mut window.map(|(_, usage)| *usage).chain(ours));
    if recent.blobs >= u64::from(limits.publish_per_min)
        || recent.bytes.saturating_add(bytes) > limits.bytes_per_min
    {
        return Some(Refusal::RateLimited);
    }
    None
}

/// What each channel inserted within the window of spec 033 R6: the
/// monotonic time of each commit and what it inserted.
type Windows = HashMap<[u8; 16], VecDeque<(u64, Usage)>>;

/// The `server_id` and `received_at` of a stored request, or its refusal.
type Stored = Result<([u8; 16], u64), Refusal>;

/// The working copy of one transaction (R7): `last`, its value as stored
/// once an insert moved it, and the rows it added to each channel.
struct Working {
    last: u64,
    stored: Option<i64>,
    added: Counters,
}

/// Inserts one request, returning its `server_id` and `received_at`, or
/// the refusal of that request alone (R6). A statement that fails fails the
/// whole transaction.
fn insert(
    transaction: &Transaction<'_>,
    clock: &dyn Clock,
    hooks: &mut Hooks,
    working: &mut Working,
    request: &WriteRequest,
) -> Result<Stored, rusqlite::Error> {
    let wall = clock.wall_ms();
    let Some(times) = times(wall, working.last, request.ttl_seconds) else {
        return Ok(Err(Refusal::ServerFull));
    };
    let Some(server_id) = hooks.server_id() else {
        return Ok(Err(Refusal::ServerFull));
    };
    let used = transaction
        .query_row(
            "SELECT 1 FROM messages WHERE server_id = ?1",
            [&server_id[..]],
            |_| Ok(()),
        )
        .optional()?;
    if used.is_some() {
        return Ok(Err(Refusal::ServerFull));
    }
    transaction
        .execute(
            "INSERT INTO messages(server_id, channel_id, received_at, expires_at, blob) VALUES (?1, ?2, ?3, ?4, ?5)",
            (&server_id[..], &request.channel_id[..], times.received_at, times.expires_at, &request.blob),
        )?;
    working.last = times.received;
    working.stored = Some(times.received_at);
    let bytes = u64::try_from(request.blob.len()).unwrap_or(u64::MAX);
    purge::add(
        &mut working.added,
        request.channel_id,
        Usage { blobs: 1, bytes },
    );
    Ok(Ok((server_id, times.received)))
}

/// The times of one insert, as stored and as reported.
struct Times {
    received: u64,
    received_at: i64,
    expires_at: i64,
}

/// `received_at = max(wall, last + 1)` and `expires_at = wall + ttl_ms`,
/// both within SQLite's signed integer, or `None` (R6).
fn times(wall: u64, last: u64, ttl_seconds: u32) -> Option<Times> {
    let received = wall.max(last.checked_add(1)?);
    let expires = wall.checked_add(u64::from(ttl_seconds).checked_mul(MS_PER_SECOND)?)?;
    Some(Times {
        received,
        received_at: i64::try_from(received).ok()?,
        expires_at: i64::try_from(expires).ok()?,
    })
}

/// The refusal every request of a failed transaction gets (R7).
fn refusal_for(error: &rusqlite::Error) -> Refusal {
    match error.sqlite_error_code() {
        Some(ErrorCode::DiskFull) => Refusal::ServerFull,
        _ => Refusal::RateLimited,
    }
}

/// The points where the tests hold or steer the writer; none in a shipped
/// build.
#[derive(Default)]
struct Hooks {
    #[cfg(test)]
    test: test::Hooks,
}

#[cfg(not(test))]
impl Hooks {
    fn wait_while_paused(&self) {}

    fn before_transaction(&mut self, _: &Connection) {}

    fn before_commit(&mut self, _: &Connection) {}

    fn server_id(&mut self) -> Option<[u8; 16]> {
        privatechat_core::relay::new_server_id().ok()
    }

    fn purge_round(&mut self, _: usize) {}

    fn after_step(&mut self, _: &Connection, _: &Counters) {}
}
