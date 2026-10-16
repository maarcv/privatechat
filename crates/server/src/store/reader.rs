//! The backlog reads (spec 032-storage-ttl R9): a pool of read-only
//! connections, used off the async threads, and pages bounded by rows and by
//! bytes so that a reader never holds more than one page of blobs.

use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};

use rusqlite::Connection;
use tokio::sync::Semaphore;

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

/// The pool of read-only connections (R9). A read waits for a permit in
/// async code, never on a blocking thread, so a read that is waiting holds
/// no thread and a read dropped while waiting leaves no work behind.
pub(crate) struct ReadPool {
    permits: Arc<Semaphore>,
    idle: Arc<Mutex<Vec<Connection>>>,
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
            permits: Arc::new(Semaphore::new(POOL_SIZE)),
            idle: Arc::new(Mutex::new(idle)),
        })
    }

    /// The permits, for a test that holds them.
    #[cfg(test)]
    pub(crate) fn permits(&self) -> &Arc<Semaphore> {
        &self.permits
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
    // A permit stands for one idle connection, so the pop below finds one.
    let permit = pool
        .permits
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| aborted())?;
    let idle = pool.idle.clone();
    let read = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let connection = idle
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pop()
            .ok_or_else(aborted)?;
        let page = query_page(&connection, channel_id, from, now).map_err(StoreError);
        idle.lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(connection);
        page
    });
    // The closure never panics; a runtime shutting down cancels it.
    read.await.map_err(|_| aborted())?
}

/// A read that did not run: the pool closed, or the runtime shut down.
fn aborted() -> StoreError {
    StoreError(rusqlite::Error::SqliteFailure(
        rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_ABORT),
        None,
    ))
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
