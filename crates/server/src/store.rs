//! The blob table (spec 032-storage-ttl, `docs/spec.md` §6 "Storage"):
//! opening the database, its pragmas, its schema and the start-up checks
//! (R1–R3). The writer that inserts and purges, and the reads, are the
//! submodules of the later slices. Nothing here copies a blob anywhere (R12).

pub(crate) mod writer;

use std::path::Path;
use std::time::Duration;

use rusqlite::{Connection, OpenFlags};

use crate::{DbCause, StartError, StartReason};

/// The schema version this server writes and reads (R1, R3).
const USER_VERSION: i64 = 1;

/// `PRAGMA auto_vacuum` reads 2 for `INCREMENTAL` (R2, R3).
const AUTO_VACUUM_INCREMENTAL: i64 = 2;

/// How long a connection waits for a lock before it fails (R2).
const BUSY_TIMEOUT: Duration = Duration::from_millis(5_000);

/// The tables and indexes of a new file and its `meta` row, created in one
/// transaction with `user_version` (R1).
const SCHEMA: &str = "
    CREATE TABLE messages(
        server_id BLOB PRIMARY KEY CHECK (length(server_id) = 16),
        channel_id BLOB NOT NULL CHECK (length(channel_id) = 16),
        received_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        blob BLOB NOT NULL
    );
    CREATE TABLE meta(
        id INTEGER PRIMARY KEY CHECK (id = 0),
        last_received_at INTEGER NOT NULL
    );
    INSERT INTO meta(id, last_received_at) VALUES (0, 0);
    CREATE INDEX messages_by_channel ON messages(channel_id, received_at);
    CREATE INDEX messages_by_expiry ON messages(expires_at);
";

/// Opens the writer's connection to `db`, creating the file when it is new,
/// and checks it (R2, R3).
///
/// # Errors
///
/// `StartError` of reason `Database`, naming the cause: `Open` when the file
/// cannot be opened for writing or a pragma or the schema fails,
/// `UserVersion` for a version other than 0 or 1, `JournalMode` when the
/// journal does not read back as WAL, `AutoVacuum` when the incremental
/// vacuum does not read back.
pub(crate) fn open_writer(db: &Path) -> Result<Connection, StartError> {
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_CREATE
        | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let mut connection =
        Connection::open_with_flags(db, flags).map_err(|_| refused(DbCause::Open))?;
    // SQLite opens a write-protected file read-only without an error.
    if connection
        .is_readonly(rusqlite::MAIN_DB)
        .map_err(|_| refused(DbCause::Open))?
    {
        return Err(refused(DbCause::Open));
    }
    set_common(&connection).map_err(|_| refused(DbCause::Open))?;
    let version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|_| refused(DbCause::Open))?;
    let is_new = match version {
        0 => true,
        USER_VERSION => false,
        _ => return Err(refused(DbCause::UserVersion)),
    };
    // The vacuum mode is fixed when the first table is created, and must be
    // set before the journal turns to WAL (R2); it is read back first, so a
    // file refused for it keeps its journal as it was.
    if is_new {
        connection
            .pragma_update(None, "auto_vacuum", "INCREMENTAL")
            .map_err(|_| refused(DbCause::Open))?;
    }
    check_vacuum(&connection)?;
    if is_new {
        connection
            .pragma_update(None, "journal_mode", "WAL")
            .map_err(|_| refused(DbCause::Open))?;
    }
    check_journal(&connection)?;
    if is_new {
        let transaction = connection
            .transaction()
            .map_err(|_| refused(DbCause::Open))?;
        transaction
            .execute_batch(SCHEMA)
            .map_err(|_| refused(DbCause::Open))?;
        transaction
            .pragma_update(None, "user_version", USER_VERSION)
            .map_err(|_| refused(DbCause::Open))?;
        transaction.commit().map_err(|_| refused(DbCause::Open))?;
    }
    set_writer(&connection).map_err(|_| refused(DbCause::Open))?;
    Ok(connection)
}

/// Opens a read-only connection to the database the writer created (R2, R9).
///
/// # Errors
///
/// The SQLite error when the file cannot be opened or a pragma fails.
pub(crate) fn open_reader(db: &Path) -> Result<Connection, rusqlite::Error> {
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let connection = Connection::open_with_flags(db, flags)?;
    set_common(&connection)?;
    connection.pragma_update(None, "query_only", "ON")?;
    Ok(connection)
}

/// The pragmas of every connection (R2).
fn set_common(connection: &Connection) -> Result<(), rusqlite::Error> {
    connection.busy_timeout(BUSY_TIMEOUT)?;
    connection.pragma_update(None, "temp_store", "MEMORY")
}

/// The pragmas of the writer's connection (R2): `secure_delete` overwrites
/// what the purge deletes, and `journal_size_limit = 0` lets the truncating
/// checkpoint empty the WAL (R10, R13).
fn set_writer(connection: &Connection) -> Result<(), rusqlite::Error> {
    connection.pragma_update(None, "synchronous", "NORMAL")?;
    connection.pragma_update(None, "secure_delete", "ON")?;
    connection.pragma_update(None, "journal_size_limit", 0)
}

/// The vacuum mode, read back (R3).
fn check_vacuum(connection: &Connection) -> Result<(), StartError> {
    let vacuum: i64 = connection
        .pragma_query_value(None, "auto_vacuum", |row| row.get(0))
        .map_err(|_| refused(DbCause::Open))?;
    if vacuum != AUTO_VACUUM_INCREMENTAL {
        return Err(refused(DbCause::AutoVacuum));
    }
    Ok(())
}

/// The journal mode, read back (R3).
fn check_journal(connection: &Connection) -> Result<(), StartError> {
    let journal: String = connection
        .pragma_query_value(None, "journal_mode", |row| row.get(0))
        .map_err(|_| refused(DbCause::Open))?;
    if !journal.eq_ignore_ascii_case("wal") {
        return Err(refused(DbCause::JournalMode));
    }
    Ok(())
}

/// A database refused at start-up for `cause` (R3).
fn refused(cause: DbCause) -> StartError {
    StartError {
        reason: StartReason::Database(cause),
    }
}
