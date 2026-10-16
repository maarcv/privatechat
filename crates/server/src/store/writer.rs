//! The one writer of the database (spec 032-storage-ttl R4–R8): a thread
//! that takes every request already waiting, up to 256, stores them in one
//! transaction in arrival order, and reports each one only after the commit.
//! It is the one place where blobs are ordered, so `received_at` is given
//! here and nowhere else.

use std::path::Path;
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::thread::JoinHandle;
use std::time::Duration;

use rusqlite::{Connection, ErrorCode, OptionalExtension, Transaction, TransactionBehavior};

use super::open_writer;
use crate::clock::Clock;
use crate::{DbCause, StartError, StartReason};

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
    ) -> Result<Writer, StartError> {
        Writer::start(db, clock, on_commit, max_db_bytes, Hooks::default())
    }

    fn start(
        db: &Path,
        clock: Arc<dyn Clock>,
        on_commit: OnCommit,
        max_db_bytes: u64,
        hooks: Hooks,
    ) -> Result<Writer, StartError> {
        let connection = open_writer(db)?;
        let last = read_last(&connection).map_err(|_| refused_open())?;
        let (sender, receiver) = mpsc::sync_channel(QUEUE_LEN);
        let mut thread = WriterThread {
            connection,
            clock,
            on_commit,
            max_db_bytes,
            last,
            hooks,
        };
        let handle = std::thread::Builder::new()
            .name("writer".to_owned())
            .spawn(move || thread.run(&receiver))
            .map_err(|_| refused_open())?;
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

impl Drop for Writer {
    fn drop(&mut self) {
        // Closing the queue ends the thread once it has stored what is queued.
        drop(self.sender.take());
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
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

fn refused_open() -> StartError {
    StartError {
        reason: StartReason::Database(DbCause::Open),
    }
}

/// What the writer thread owns.
struct WriterThread {
    connection: Connection,
    clock: Arc<dyn Clock>,
    on_commit: OnCommit,
    max_db_bytes: u64,
    /// The largest `received_at` ever committed (R6).
    last: u64,
    hooks: Hooks,
}

impl WriterThread {
    fn run(&mut self, receiver: &Receiver<WriteRequest>) {
        loop {
            self.hooks.wait_while_paused();
            let first = match receiver.recv_timeout(WAKE) {
                Ok(first) => first,
                Err(RecvTimeoutError::Timeout) => continue,
                Err(RecvTimeoutError::Disconnected) => return,
            };
            let mut batch = vec![first];
            while batch.len() < MAX_BATCH {
                match receiver.try_recv() {
                    Ok(request) => batch.push(request),
                    Err(_) => break,
                }
            }
            let outcomes = self.store(batch);
            (self.on_commit)(outcomes);
        }
    }

    /// Stores one batch in one transaction and returns its outcomes (R5–R8).
    fn store(&mut self, batch: Vec<WriteRequest>) -> Vec<WriteOutcome> {
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
        let live = || -> Result<u64, rusqlite::Error> {
            let read = |name: &str| -> Result<u64, rusqlite::Error> {
                let value: i64 = self
                    .connection
                    .pragma_query_value(None, name, |row| row.get(0))?;
                u64::try_from(value).map_err(|_| rusqlite::Error::IntegralValueOutOfRange(0, value))
            };
            let pages = read("page_count")?.saturating_sub(read("freelist_count")?);
            Ok(pages.saturating_mul(read("page_size")?))
        };
        live().map_or(true, |bytes| bytes >= self.max_db_bytes)
    }

    /// Inserts every request of the batch in one transaction, with a working
    /// copy of `last` that replaces the stored one only on commit (R6, R7).
    fn insert_all(&mut self, batch: &[WriteRequest]) -> Result<Vec<Stored>, rusqlite::Error> {
        self.hooks.before_transaction(&self.connection);
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut last = Last {
            value: self.last,
            stored: None,
        };
        let mut results = Vec::with_capacity(batch.len());
        for request in batch {
            results.push(insert(
                &transaction,
                &*self.clock,
                &mut self.hooks,
                &mut last,
                request,
            )?);
        }
        if let Some(stored) = last.stored {
            transaction.execute(
                "UPDATE meta SET last_received_at = ?1 WHERE id = 0",
                [stored],
            )?;
        }
        self.hooks.before_commit(&transaction);
        transaction.commit()?;
        self.last = last.value;
        Ok(results)
    }
}

/// The `server_id` and `received_at` of a stored request, or its refusal.
type Stored = Result<([u8; 16], u64), Refusal>;

/// The working copy of `last` of one transaction, and its value as stored
/// once an insert moved it (R6, R7).
struct Last {
    value: u64,
    stored: Option<i64>,
}

/// Inserts one request, returning its `server_id` and `received_at`, or
/// the refusal of that request alone (R6). A statement that fails fails the
/// whole transaction.
fn insert(
    transaction: &Transaction<'_>,
    clock: &dyn Clock,
    hooks: &mut Hooks,
    last: &mut Last,
    request: &WriteRequest,
) -> Result<Stored, rusqlite::Error> {
    let wall = clock.wall_ms();
    let Some(times) = times(wall, last.value, request.ttl_seconds) else {
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
    last.value = times.received;
    last.stored = Some(times.received_at);
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
}

#[cfg(test)]
pub(crate) mod test {
    //! The hooks of the tests: a pause before each batch, a call with the
    //! connection before each transaction and before each commit, and a
    //! source of `server_id`s.

    use std::path::Path;
    use std::sync::{Arc, Condvar, Mutex};

    use rusqlite::Connection;

    use super::{Clock, OnCommit, StartError, Writer};

    /// A pause the test releases.
    #[derive(Default)]
    pub(crate) struct Pause {
        paused: Mutex<bool>,
        released: Condvar,
    }

    impl Pause {
        pub(crate) fn paused() -> Arc<Pause> {
            Arc::new(Pause {
                paused: Mutex::new(true),
                released: Condvar::new(),
            })
        }

        pub(crate) fn release(&self) {
            *self.paused.lock().unwrap() = false;
            self.released.notify_all();
        }
    }

    pub(crate) type ConnectionHook = Box<dyn FnMut(&Connection) + Send>;

    #[derive(Default)]
    pub(crate) struct Hooks {
        pub(crate) pause: Option<Arc<Pause>>,
        pub(crate) before_transaction: Option<ConnectionHook>,
        pub(crate) before_commit: Option<ConnectionHook>,
        pub(crate) server_id: Option<Box<dyn FnMut() -> [u8; 16] + Send>>,
    }

    impl super::Hooks {
        pub(super) fn wait_while_paused(&self) {
            if let Some(pause) = &self.test.pause {
                let mut paused = pause.paused.lock().unwrap();
                while *paused {
                    paused = pause.released.wait(paused).unwrap();
                }
            }
        }

        pub(super) fn before_transaction(&mut self, connection: &Connection) {
            if let Some(hook) = &mut self.test.before_transaction {
                hook(connection);
            }
        }

        pub(super) fn before_commit(&mut self, connection: &Connection) {
            if let Some(hook) = &mut self.test.before_commit {
                hook(connection);
            }
        }

        pub(super) fn server_id(&mut self) -> Option<[u8; 16]> {
            match &mut self.test.server_id {
                Some(next) => Some(next()),
                None => privatechat_core::relay::new_server_id().ok(),
            }
        }
    }

    /// `Writer::spawn` with hooks.
    pub(crate) fn spawn(
        db: &Path,
        clock: Arc<dyn Clock>,
        on_commit: OnCommit,
        max_db_bytes: u64,
        hooks: Hooks,
    ) -> Result<Writer, StartError> {
        Writer::start(
            db,
            clock,
            on_commit,
            max_db_bytes,
            super::Hooks { test: hooks },
        )
    }
}
