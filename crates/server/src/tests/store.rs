//! Spec 032-storage-ttl: the database, the writer, the reads and the purge,
//! driven through the writer and the reader alone.

mod purge;
mod reader;
pub(super) mod writer;

use std::path::Path;

use rusqlite::Connection;

use super::TestDir;
use crate::clock::{Clock, ManualClock};
use crate::store::{open_reader, open_writer};
use crate::{DbCause, StartError, StartReason};

fn pragma_i64(connection: &Connection, name: &str) -> i64 {
    connection
        .pragma_query_value(None, name, |row| row.get(0))
        .unwrap()
}

/// The cause of a database refused at start-up, or `None` for any other result.
fn cause(result: Result<Connection, StartError>) -> Option<DbCause> {
    match result {
        Err(StartError {
            reason: StartReason::Database(cause),
        }) => Some(cause),
        _ => None,
    }
}

/// The names of the tables and indexes of the schema, sorted.
fn schema_names(connection: &Connection) -> Vec<(String, String)> {
    let mut statement = connection
        .prepare(
            "SELECT type, name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY name",
        )
        .unwrap();
    statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

fn index_columns(connection: &Connection, index: &str) -> Vec<String> {
    let mut statement = connection
        .prepare(&format!(
            "SELECT name FROM pragma_index_info('{index}') ORDER BY seqno"
        ))
        .unwrap();
    statement
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

fn insert(connection: &Connection, server_id: &[u8], channel_id: &[u8]) -> rusqlite::Result<usize> {
    connection.execute(
        "INSERT INTO messages(server_id, channel_id, received_at, expires_at, blob) VALUES (?1, ?2, 1, 2, x'00')",
        (server_id, channel_id),
    )
}

#[test]
fn s032_t01_r01_schema() {
    let dir = TestDir::new("s032_t01");
    let connection = open_writer(&dir.db()).unwrap();
    assert_eq!(
        schema_names(&connection),
        [
            ("table", "messages"),
            ("index", "messages_by_channel"),
            ("index", "messages_by_expiry"),
            ("table", "meta"),
        ]
        .map(|(kind, name)| (kind.to_owned(), name.to_owned()))
    );
    assert_eq!(
        index_columns(&connection, "messages_by_channel"),
        ["channel_id", "received_at"]
    );
    assert_eq!(
        index_columns(&connection, "messages_by_expiry"),
        ["expires_at"]
    );
    assert_eq!(pragma_i64(&connection, "user_version"), 1);
    let meta: (i64, i64, i64) = connection
        .query_row(
            "SELECT count(*), min(id), min(last_received_at) FROM meta",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(meta, (1, 0, 0));

    assert!(insert(&connection, &[1; 16], &[2; 16]).is_ok());
    assert!(
        insert(&connection, &[3; 16], &[2; 15]).is_err(),
        "15-byte channel_id"
    );
    assert!(
        insert(&connection, &[3; 15], &[2; 16]).is_err(),
        "15-byte server_id"
    );
    assert!(
        insert(&connection, &[3; 17], &[2; 16]).is_err(),
        "17-byte server_id"
    );
    assert!(
        insert(&connection, &[3; 16], &[2; 17]).is_err(),
        "17-byte channel_id"
    );
    assert!(
        insert(&connection, &[1; 16], &[2; 16]).is_err(),
        "a server_id twice"
    );
    for (columns, what) in [
        (
            "x'03030303030303030303030303030303', NULL, 1, 2, x'00'",
            "a NULL channel_id",
        ),
        (
            "x'03030303030303030303030303030303', x'02020202020202020202020202020202', 1, 2, NULL",
            "a NULL blob",
        ),
        (
            "x'04040404040404040404040404040404', x'02020202020202020202020202020202', NULL, 2, x'00'",
            "a NULL received_at",
        ),
        (
            "x'05050505050505050505050505050505', x'02020202020202020202020202020202', 1, NULL, x'00'",
            "a NULL expires_at",
        ),
    ] {
        let sql = format!(
            "INSERT INTO messages(server_id, channel_id, received_at, expires_at, blob) VALUES ({columns})"
        );
        assert!(connection.execute(&sql, []).is_err(), "{what}");
    }
    assert!(
        connection
            .execute("INSERT INTO meta(id, last_received_at) VALUES (1, 0)", [])
            .is_err(),
        "a second meta row"
    );
    assert!(
        connection
            .execute("UPDATE meta SET last_received_at = NULL", [])
            .is_err(),
        "a NULL last_received_at"
    );

    // Reopening a file of version 1 keeps it as it is.
    drop(connection);
    let connection = open_writer(&dir.db()).unwrap();
    let rows: i64 = connection
        .query_row("SELECT count(*) FROM messages", [], |row| row.get(0))
        .unwrap();
    assert_eq!(rows, 1);
}

#[test]
fn s032_t02_r02_pragmas() {
    let dir = TestDir::new("s032_t02");
    let writer = open_writer(&dir.db()).unwrap();
    let journal: String = writer
        .pragma_query_value(None, "journal_mode", |row| row.get(0))
        .unwrap();
    assert_eq!(journal, "wal");
    for (name, value) in [
        ("auto_vacuum", 2),
        ("synchronous", 1),
        ("secure_delete", 1),
        ("journal_size_limit", 0),
        ("temp_store", 2),
        ("busy_timeout", 5_000),
        ("query_only", 0),
    ] {
        assert_eq!(pragma_i64(&writer, name), value, "writer {name}");
    }

    let reader = open_reader(&dir.db()).unwrap();
    for (name, value) in [
        ("query_only", 1),
        ("temp_store", 2),
        ("busy_timeout", 5_000),
    ] {
        assert_eq!(pragma_i64(&reader, name), value, "reader {name}");
    }
    assert!(insert(&reader, &[1; 16], &[2; 16]).is_err());
    assert!(insert(&writer, &[1; 16], &[2; 16]).is_ok());

    // The writer's pragmas belong to the connection: a restart sets them again.
    drop((reader, writer));
    let writer = open_writer(&dir.db()).unwrap();
    for (name, value) in [
        ("synchronous", 1),
        ("secure_delete", 1),
        ("journal_size_limit", 0),
    ] {
        assert_eq!(pragma_i64(&writer, name), value, "reopened writer {name}");
    }
}

/// A database at `path` whose `user_version` is `version`, as the server
/// would have left it otherwise.
fn plant_version(path: &Path, version: i64) {
    drop(open_writer(path).unwrap());
    let connection = Connection::open(path).unwrap();
    connection
        .pragma_update(None, "user_version", version)
        .unwrap();
}

#[test]
fn s032_t03_r03_start_up_refusals() {
    let dir = TestDir::new("s032_t03");

    let path = dir.path().join("version2.db");
    plant_version(&path, 2);
    assert_eq!(cause(open_writer(&path)), Some(DbCause::UserVersion));

    // A file of an unknown older layout, with version 0 but a table already.
    let path = dir.path().join("vacuum-none.db");
    let connection = Connection::open(&path).unwrap();
    connection
        .execute_batch("PRAGMA auto_vacuum = NONE; CREATE TABLE other(x);")
        .unwrap();
    drop(connection);
    assert_eq!(cause(open_writer(&path)), Some(DbCause::AutoVacuum));
    // Refused before its journal was switched to WAL.
    let connection = Connection::open(&path).unwrap();
    let journal: String = connection
        .pragma_query_value(None, "journal_mode", |row| row.get(0))
        .unwrap();
    assert_eq!(journal, "delete");
    drop(connection);

    // A new-looking file whose schema fails half way keeps none of it: the
    // tables, the meta row and the version are one transaction.
    let path = dir.path().join("half-schema.db");
    let connection = Connection::open(&path).unwrap();
    connection
        .execute_batch(
            "PRAGMA auto_vacuum = INCREMENTAL; PRAGMA journal_mode = WAL; CREATE TABLE meta(x);",
        )
        .unwrap();
    drop(connection);
    assert_eq!(cause(open_writer(&path)), Some(DbCause::Open));
    let connection = Connection::open(&path).unwrap();
    assert_eq!(
        schema_names(&connection),
        [("table".to_owned(), "meta".to_owned())]
    );
    assert_eq!(pragma_i64(&connection, "user_version"), 0);
    drop(connection);

    // A file of version 1 whose vacuum mode was turned to full.
    let path = dir.path().join("vacuum-full.db");
    drop(open_writer(&path).unwrap());
    let connection = Connection::open(&path).unwrap();
    connection
        .pragma_update(None, "auto_vacuum", "FULL")
        .unwrap();
    assert_eq!(pragma_i64(&connection, "auto_vacuum"), 1);
    drop(connection);
    assert_eq!(cause(open_writer(&path)), Some(DbCause::AutoVacuum));

    // A database with no file has no WAL.
    assert_eq!(
        cause(open_writer(Path::new(":memory:"))),
        Some(DbCause::JournalMode)
    );

    // A file of version 1 whose vacuum mode was turned off.
    let path = dir.path().join("vacuum-off.db");
    drop(open_writer(&path).unwrap());
    let connection = Connection::open(&path).unwrap();
    connection
        .execute_batch("PRAGMA journal_mode = DELETE; PRAGMA auto_vacuum = NONE; VACUUM; PRAGMA journal_mode = WAL;")
        .unwrap();
    drop(connection);
    assert_eq!(cause(open_writer(&path)), Some(DbCause::AutoVacuum));

    let path = dir.path().join("rollback-journal.db");
    drop(open_writer(&path).unwrap());
    let connection = Connection::open(&path).unwrap();
    connection
        .pragma_update(None, "journal_mode", "DELETE")
        .unwrap();
    drop(connection);
    assert_eq!(cause(open_writer(&path)), Some(DbCause::JournalMode));

    let path = dir.path().join("read-only.db");
    drop(open_writer(&path).unwrap());
    let mut permissions = std::fs::metadata(&path).unwrap().permissions();
    permissions.set_readonly(true);
    std::fs::set_permissions(&path, permissions).unwrap();
    assert_eq!(cause(open_writer(&path)), Some(DbCause::Open));

    let path = dir.path().join("missing").join("messages.db");
    assert_eq!(cause(open_writer(&path)), Some(DbCause::Open));

    // A refused path creates no directory.
    assert!(!dir.path().join("missing").exists());
}

/// `needle` in the code of `source`, comments left out.
fn calls(source: &str, needle: &str) -> bool {
    source
        .lines()
        .map(|line| line.split("//").next().unwrap_or_default())
        .any(|code| code.contains(needle))
}

/// Every `.rs` file under `dir`, with its path.
fn sources(dir: &Path) -> Vec<(std::path::PathBuf, String)> {
    let mut found = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            found.extend(sources(&path));
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            let text = std::fs::read_to_string(&path).unwrap();
            found.push((path, text));
        }
    }
    found
}

#[test]
fn s032_t14_r14_one_clock() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    // Spelled in two halves, so that this file does not match itself.
    let needles = [concat!("SystemTime", "::now"), concat!("Instant", "::now")];
    let files = sources(&src);
    assert!(files.len() >= 4, "the sources were not found");
    for (path, text) in files {
        let is_clock = path == src.join("clock.rs");
        for needle in needles {
            assert_eq!(
                calls(&text, needle),
                is_clock,
                "{needle} in {}",
                path.display()
            );
        }
    }

    let clock = ManualClock::new(1_000);
    assert_eq!((clock.wall_ms(), clock.mono_ms()), (1_000, 0));
    clock.advance(500);
    assert_eq!((clock.wall_ms(), clock.mono_ms()), (1_500, 500));
    clock.advance_mono(60_000);
    assert_eq!((clock.wall_ms(), clock.mono_ms()), (1_500, 60_500));
    clock.set_wall(100);
    assert_eq!((clock.wall_ms(), clock.mono_ms()), (100, 60_500));

    // The host's clock: a wall reading of this century, and a monotonic one
    // that counts from its first reading in the process and moves on its own.
    let system = crate::SystemClock;
    let wall = system.wall_ms();
    assert!(wall > 1_700_000_000_000);
    let first = system.mono_ms();
    assert!(first < 60_000, "{first}");
    while system.mono_ms() == first && system.wall_ms() < wall + 1_000 {}
    assert!(system.mono_ms() > first);
}

#[test]
fn s032_t15_r15_server_id() {
    let ids: Vec<[u8; 16]> = (0..64)
        .map(|_| privatechat_core::relay::new_server_id().unwrap())
        .collect();
    // Every byte position is drawn: none keeps one value over 64 ids.
    for position in 0..16 {
        let first = ids[0][position];
        assert!(
            ids.iter().any(|id| id[position] != first),
            "byte {position}"
        );
    }
    let (first, second) = (ids[0], ids[1]);
    assert_ne!(first, [0; 16]);
    // Random, not a counter: two draws share few byte positions.
    let same = first.iter().zip(&second).filter(|(a, b)| a == b).count();
    assert!(same < 8, "{same} equal bytes");
}
