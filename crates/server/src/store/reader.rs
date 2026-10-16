//! The backlog reads (spec 032-storage-ttl R9): a pool of read-only
//! connections, used off the async threads, and pages bounded by rows and by
//! bytes so that a reader never holds more than one page of blobs.

use std::path::Path;
use std::sync::{Arc, Condvar, Mutex, PoisonError};

use rusqlite::Connection;

use super::open_reader;
use super::writer::Row;

/// The read-only connections of the pool (R9).
pub(crate) const POOL_SIZE: usize = 4;

/// The most rows of one page (R9).
pub(crate) const PAGE_ROWS: usize = 500;

/// The most blob bytes of one page, unless its one row is larger (R9).
pub(crate) const PAGE_BYTES: usize = 256 * 1024;

/// A failed read; spec 030-ws-protocol R7 closes the connection with 1011.
#[derive(Debug)]
pub(crate) struct StoreError(rusqlite::Error);

/// The pool of read-only connections (R9).
pub(crate) struct ReadPool {
    shared: Arc<Shared>,
}

struct Shared {
    idle: Mutex<Vec<Connection>>,
    returned: Condvar,
    /// The most connections ever out of the pool at once.
    #[cfg(test)]
    most_out: std::sync::atomic::AtomicUsize,
}

impl ReadPool {
    /// Opens the `POOL_SIZE` connections to the database the writer opened.
    ///
    /// # Errors
    ///
    /// `StoreError` when a connection cannot be opened.
    pub(crate) fn open(db: &Path) -> Result<ReadPool, StoreError> {
        let idle = (0..POOL_SIZE)
            .map(|_| open_reader(db))
            .collect::<Result<Vec<_>, _>>()
            .map_err(StoreError)?;
        Ok(ReadPool {
            shared: Arc::new(Shared {
                idle: Mutex::new(idle),
                returned: Condvar::new(),
                #[cfg(test)]
                most_out: std::sync::atomic::AtomicUsize::new(0),
            }),
        })
    }

    /// The most connections that were ever in use at once.
    #[cfg(test)]
    pub(crate) fn most_out(&self) -> usize {
        self.shared
            .most_out
            .load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl Shared {
    /// Takes a connection, waiting for one when all are in use.
    fn take(&self) -> Connection {
        let mut idle = self.idle.lock().unwrap_or_else(PoisonError::into_inner);
        loop {
            if let Some(connection) = idle.pop() {
                #[cfg(test)]
                self.most_out.fetch_max(
                    POOL_SIZE.saturating_sub(idle.len()),
                    std::sync::atomic::Ordering::SeqCst,
                );
                return connection;
            }
            idle = self
                .returned
                .wait(idle)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }

    fn give_back(&self, connection: Connection) {
        self.idle
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(connection);
        self.returned.notify_one();
    }
}

/// The rows of `channel_id` with `received_at ≥ from` and `expires_at > now`,
/// in `received_at` order, up to `PAGE_ROWS` rows and `PAGE_BYTES` of blobs,
/// and at least one row when one matches (R9). The next page starts at the
/// last `received_at` + 1.
///
/// # Errors
///
/// `StoreError` when the read fails.
pub(crate) async fn read_page(
    pool: &ReadPool,
    channel_id: [u8; 16],
    from: u64,
    now: u64,
) -> Result<Vec<Row>, StoreError> {
    let shared = pool.shared.clone();
    let read = tokio::task::spawn_blocking(move || {
        let connection = shared.take();
        let page = query_page(&connection, channel_id, from, now);
        shared.give_back(connection);
        page
    });
    match read.await {
        Ok(page) => page.map_err(StoreError),
        // The closure never panics; a runtime shutting down cancels it.
        Err(_) => Err(StoreError(rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_ABORT),
            None,
        ))),
    }
}

fn query_page(
    connection: &Connection,
    channel_id: [u8; 16],
    from: u64,
    now: u64,
) -> Result<Vec<Row>, rusqlite::Error> {
    // A time past SQLite's integer matches nothing, as it would in u64.
    let (Ok(from), Ok(now)) = (i64::try_from(from), i64::try_from(now)) else {
        return Ok(Vec::new());
    };
    let limit = i64::try_from(PAGE_ROWS).unwrap_or(i64::MAX);
    let mut statement = connection.prepare(
        "SELECT server_id, received_at, blob FROM messages \
         WHERE channel_id = ?1 AND received_at >= ?2 AND expires_at > ?3 \
         ORDER BY received_at LIMIT ?4",
    )?;
    let mut rows = statement.query((&channel_id[..], from, now, limit))?;
    let mut page = Vec::new();
    let mut bytes: usize = 0;
    while let Some(row) = rows.next()? {
        let blob: Vec<u8> = row.get(2)?;
        bytes = bytes.saturating_add(blob.len());
        if bytes > PAGE_BYTES && !page.is_empty() {
            break;
        }
        let received_at: i64 = row.get(1)?;
        page.push(Row {
            server_id: row.get(0)?,
            received_at: u64::try_from(received_at)
                .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(1, received_at))?,
            blob,
        });
    }
    Ok(page)
}
