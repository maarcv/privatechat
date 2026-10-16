//! The purge of expired blobs (spec 032-storage-ttl R10, R13) and the
//! per-channel retention counters it keeps right (R11). Both run on the
//! writer's connection, between two transactions.

use std::collections::HashMap;

use rusqlite::Connection;

/// The time between two purges, on the monotonic clock (R10, R14).
pub(crate) const PURGE_INTERVAL_MS: u64 = 60_000;

/// The most rows one purge statement deletes (R10).
pub(crate) const PURGE_ROUND: usize = 1_000;

/// The free pages one purge gives back to the file system (R10).
const VACUUM_PAGES: u32 = 1_000;

/// The rows of one channel in the table (R11).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Usage {
    pub(crate) blobs: u64,
    pub(crate) bytes: u64,
}

/// `Usage` per `channel_id`; a channel with no row has no entry (R11).
pub(crate) type Counters = HashMap<[u8; 16], Usage>;

/// The counters of the whole table, with one `GROUP BY` (R11).
pub(crate) fn count_all(connection: &Connection) -> Result<Counters, rusqlite::Error> {
    let mut statement = connection.prepare(
        "SELECT channel_id, count(*), sum(length(blob)) FROM messages GROUP BY channel_id",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, [u8; 16]>(0)?,
            Usage {
                blobs: unsigned(row, 1)?,
                bytes: unsigned(row, 2)?,
            },
        ))
    })?;
    rows.collect()
}

/// Column `index` of `row`, a count or a length, which is never negative.
fn unsigned(row: &rusqlite::Row<'_>, index: usize) -> Result<u64, rusqlite::Error> {
    let value: i64 = row.get(index)?;
    u64::try_from(value).map_err(|_| rusqlite::Error::IntegralValueOutOfRange(index, value))
}

/// Adds `more` to the entry of `channel_id`.
pub(crate) fn add(counters: &mut Counters, channel_id: [u8; 16], more: Usage) {
    let usage = counters.entry(channel_id).or_default();
    usage.blobs = usage.blobs.saturating_add(more.blobs);
    usage.bytes = usage.bytes.saturating_add(more.bytes);
}

/// Takes one blob of `bytes` off the entry of `channel_id`, dropping the
/// entry when it reaches 0 (R11).
fn subtract(counters: &mut Counters, channel_id: [u8; 16], bytes: u64) {
    if let Some(usage) = counters.get_mut(&channel_id) {
        usage.blobs = usage.blobs.saturating_sub(1);
        usage.bytes = usage.bytes.saturating_sub(bytes);
        if usage.blobs == 0 {
            counters.remove(&channel_id);
        }
    }
}

/// Deletes every row with `expires_at < now` in rounds of at most
/// `PURGE_ROUND`, taking each off the counters, then gives the space back
/// and empties the WAL (R10). Each round is a statement of its own, so a
/// failing one deletes nothing and leaves its rows to the next purge.
/// `on_round` hears how many rows each round deleted.
pub(crate) fn purge(
    connection: &Connection,
    now: u64,
    counters: &mut Counters,
    on_round: &mut dyn FnMut(usize),
) -> Result<(), rusqlite::Error> {
    let deleted = delete_expired(connection, now, counters, on_round);
    // Even after a failed round or a failed vacuum, the rounds before are
    // committed: their WAL frames are emptied now, not a purge later. The
    // checkpoint writes into pages that exist, so a full disk does not stop it.
    let vacuumed = vacuum(connection);
    let checkpointed = checkpoint(connection);
    deleted.and(vacuumed).and(checkpointed)
}

/// The rounds of `DELETE … RETURNING`, until one deletes fewer than
/// `PURGE_ROUND` rows (R10, R11).
fn delete_expired(
    connection: &Connection,
    now: u64,
    counters: &mut Counters,
    on_round: &mut dyn FnMut(usize),
) -> Result<(), rusqlite::Error> {
    let now = i64::try_from(now).unwrap_or(i64::MAX);
    let limit = i64::try_from(PURGE_ROUND).unwrap_or(i64::MAX);
    let mut statement = connection.prepare(
        "DELETE FROM messages WHERE rowid IN \
         (SELECT rowid FROM messages WHERE expires_at < ?1 LIMIT ?2) \
         RETURNING channel_id, length(blob)",
    )?;
    loop {
        let deleted: Vec<([u8; 16], u64)> = statement
            .query_map([now, limit], |row| Ok((row.get(0)?, unsigned(row, 1)?)))?
            .collect::<Result<_, _>>()?;
        for (channel_id, bytes) in &deleted {
            subtract(counters, *channel_id, *bytes);
        }
        on_round(deleted.len());
        if deleted.len() < PURGE_ROUND {
            return Ok(());
        }
    }
}

/// Gives free pages back to the file system (R10).
fn vacuum(connection: &Connection) -> Result<(), rusqlite::Error> {
    let mut vacuum = connection.prepare(&format!("PRAGMA incremental_vacuum({VACUUM_PAGES})"))?;
    let mut steps = vacuum.query([])?;
    while steps.next()?.is_some() {}
    Ok(())
}

/// Empties the WAL into the file (R10, R13).
fn checkpoint(connection: &Connection) -> Result<(), rusqlite::Error> {
    // A checkpoint that finds a reader in the way returns busy, and the next
    // purge tries again (R10).
    connection.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))
}
