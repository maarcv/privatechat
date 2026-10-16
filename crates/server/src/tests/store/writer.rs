//! Spec 032-storage-ttl, the writer (R4–R8), through `Writer` and the
//! outcomes it reports.

use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rusqlite::Connection;

use super::super::TestDir;
use super::plant_version;
use crate::clock::{Clock, ManualClock};
use crate::store::writer::test::{Hooks, Pause, spawn};
use crate::store::writer::{MAX_BATCH, QUEUE_LEN, Refusal, WriteOutcome, WriteRequest, Writer};
use crate::{DbCause, StartError, StartReason};

/// Far above any test database.
const NO_QUOTA: u64 = 1 << 40;

const T0: u64 = 1_800_000_000_000;

/// A writer under test and the outcomes of its transactions, one `Vec` per
/// transaction.
struct Harness {
    writer: Writer,
    outcomes: Receiver<Vec<WriteOutcome>>,
}

impl Harness {
    fn new(db: &Path, clock: &Arc<ManualClock>, hooks: Hooks) -> Harness {
        Harness::with_quota(db, clock, hooks, NO_QUOTA)
    }

    fn with_quota(db: &Path, clock: &Arc<ManualClock>, hooks: Hooks, max_db_bytes: u64) -> Harness {
        let (sender, outcomes) = mpsc::channel();
        let on_commit = Box::new(move |batch| {
            let _ = sender.send(batch);
        });
        let clock: Arc<dyn Clock> = clock.clone();
        let writer = spawn(db, clock, on_commit, max_db_bytes, hooks).unwrap();
        Harness { writer, outcomes }
    }

    /// The outcomes of the next transaction.
    fn next(&self) -> Vec<WriteOutcome> {
        self.outcomes.recv_timeout(Duration::from_secs(30)).unwrap()
    }

    /// Submits one request and returns its outcome.
    fn store(&self, request: WriteRequest) -> WriteOutcome {
        self.writer.submit(request).unwrap();
        let mut batch = self.next();
        assert_eq!(batch.len(), 1);
        batch.pop().unwrap()
    }
}

/// Request `n` of connection `n % 7`, on channel `[channel; 16]`.
fn request(n: u16, channel: u8, ttl_seconds: u32) -> WriteRequest {
    let mut client_ref = [0; 16];
    client_ref[..2].copy_from_slice(&n.to_be_bytes());
    WriteRequest {
        connection: u64::from(n % 7),
        client_ref,
        channel_id: [channel; 16],
        ttl_seconds,
        blob: vec![channel; 100],
    }
}

fn received_at(outcome: &WriteOutcome) -> u64 {
    outcome.result.as_ref().unwrap().received_at
}

fn count(db: &Path) -> i64 {
    let connection = Connection::open(db).unwrap();
    connection
        .query_row("SELECT count(*) FROM messages", [], |row| row.get(0))
        .unwrap()
}

#[test]
fn s032_t03_r03_spawn_refuses() {
    let dir = TestDir::new("s032_t03_spawn");
    plant_version(&dir.db(), 2);
    let clock = Arc::new(ManualClock::new(T0));
    let refused = spawn(
        &dir.db(),
        clock,
        Box::new(|_| {}),
        NO_QUOTA,
        Hooks::default(),
    );
    assert!(matches!(
        refused,
        Err(StartError {
            reason: StartReason::Database(DbCause::UserVersion)
        })
    ));
}

#[test]
fn s032_t04_r04_queue_full() {
    let dir = TestDir::new("s032_t04");
    let clock = Arc::new(ManualClock::new(T0));
    let pause = Pause::paused();
    let hooks = Hooks {
        pause: Some(pause.clone()),
        ..Hooks::default()
    };
    let harness = Harness::new(&dir.db(), &clock, hooks);
    for n in 0..QUEUE_LEN {
        harness
            .writer
            .submit(request(u16::try_from(n).unwrap(), 1, 60))
            .unwrap();
    }
    // Released before the assertion, so that a failure ends the test
    // instead of leaving the writer paused while the harness drops.
    let refused = harness.writer.submit(request(9_999, 1, 60));
    pause.release();
    assert_eq!(refused, Err(Refusal::RateLimited));
    let mut stored = 0;
    while stored < QUEUE_LEN {
        let batch = harness.next();
        assert!(batch.iter().all(|outcome| outcome.result.is_ok()));
        stored += batch.len();
    }
    assert_eq!(stored, QUEUE_LEN);
    drop(harness);
    assert_eq!(count(&dir.db()), 1_024);
}

#[test]
fn s032_t05_r05_batches() {
    let dir = TestDir::new("s032_t05");
    let clock = Arc::new(ManualClock::new(T0));
    let pause = Pause::paused();
    let hooks = Hooks {
        pause: Some(pause.clone()),
        ..Hooks::default()
    };
    let harness = Harness::new(&dir.db(), &clock, hooks);
    for n in 0..300 {
        harness.writer.submit(request(n, 1, 60)).unwrap();
    }
    pause.release();
    let first = harness.next();
    let second = harness.next();
    assert_eq!((first.len(), second.len()), (MAX_BATCH, 44));
    let all: Vec<WriteOutcome> = first.into_iter().chain(second).collect();
    for (n, outcome) in all.iter().enumerate() {
        let submitted = request(u16::try_from(n).unwrap(), 1, 60);
        assert_eq!(
            (outcome.connection, outcome.client_ref, outcome.channel_id),
            (
                submitted.connection,
                submitted.client_ref,
                submitted.channel_id
            )
        );
    }
    assert!(
        all.windows(2)
            .all(|pair| received_at(&pair[0]) < received_at(&pair[1]))
    );

    // An idle writer, which has woken a few times with nothing to do,
    // stores a lone request at once.
    std::thread::sleep(Duration::from_millis(350));
    let lone = harness.store(request(300, 1, 60));
    assert!(lone.result.is_ok());
}

#[test]
fn s032_t06_r06_received_at_order() {
    let dir = TestDir::new("s032_t06");
    let clock = Arc::new(ManualClock::new(T0));
    let pause = Pause::paused();
    let hooks = Hooks {
        pause: Some(pause.clone()),
        ..Hooks::default()
    };
    let harness = Harness::new(&dir.db(), &clock, hooks);
    for n in 0..3 {
        harness.writer.submit(request(n, 1, 60)).unwrap();
    }
    pause.release();
    let batch = harness.next();
    let times: Vec<u64> = batch.iter().map(received_at).collect();
    assert_eq!(times, [T0, T0 + 1, T0 + 2]);

    // A clock set back an hour: still after the last.
    clock.set_wall(T0 - 3_600_000);
    assert_eq!(received_at(&harness.store(request(3, 1, 60))), T0 + 3);

    // `expires_at` from the wall clock, even with `received_at` ahead of it.
    let expires_at: i64 = Connection::open(dir.db())
        .unwrap()
        .query_row(
            "SELECT expires_at FROM messages WHERE received_at = ?1",
            [i64::try_from(T0 + 3).unwrap()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(expires_at, i64::try_from(T0 - 3_600_000 + 60_000).unwrap());

    // A restart with the clock a day behind continues from the stored maximum.
    drop(harness);
    clock.set_wall(T0 - 86_400_000);
    let harness = Harness::new(&dir.db(), &clock, Hooks::default());
    assert_eq!(received_at(&harness.store(request(4, 1, 60))), T0 + 4);
    drop(harness);

    // A used `server_id` refuses its request alone.
    let ids = Arc::new(Mutex::new(vec![[2; 16], [1; 16], [1; 16]]));
    let source = ids.clone();
    let pause = Pause::paused();
    let hooks = Hooks {
        pause: Some(pause.clone()),
        server_id: Some(Box::new(move || source.lock().unwrap().pop().unwrap())),
        ..Hooks::default()
    };
    let harness = Harness::new(&dir.db(), &clock, hooks);
    for n in 5..8 {
        harness.writer.submit(request(n, 2, 60)).unwrap();
    }
    pause.release();
    let batch = harness.next();
    let results: Vec<_> = batch
        .iter()
        .map(|outcome| outcome.result.clone().map(|row| row.server_id))
        .collect();
    assert_eq!(
        results,
        [Ok([1; 16]), Err(Refusal::ServerFull), Ok([2; 16])]
    );
    assert_eq!(received_at(&batch[2]), T0 + 6);
}

#[test]
fn s032_t06_r06_times_out_of_range() {
    let dir = TestDir::new("s032_t06_range");
    let max = u64::try_from(i64::MAX).unwrap();
    let clock = Arc::new(ManualClock::new(max - 10));
    let harness = Harness::new(&dir.db(), &clock, Hooks::default());
    // `expires_at` past SQLite's integer.
    assert_eq!(
        harness.store(request(0, 1, 1)).result,
        Err(Refusal::ServerFull)
    );
    assert_eq!(received_at(&harness.store(request(1, 1, 0))), max - 10);
    // `received_at` past it.
    clock.set_wall(max + 1);
    assert_eq!(
        harness.store(request(2, 1, 0)).result,
        Err(Refusal::ServerFull)
    );
    drop(harness);
    assert_eq!(count(&dir.db()), 1);
}

#[test]
fn s032_t07_r07_report_after_commit() {
    let dir = TestDir::new("s032_t07");
    let clock = Arc::new(ManualClock::new(T0));
    let reports = Arc::new(AtomicUsize::new(0));
    let seen_before_commit = Arc::new(Mutex::new(Vec::new()));
    let full = Arc::new(AtomicBool::new(false));
    let busy = Arc::new(AtomicBool::new(false));
    let (full_hook, busy_hook) = (full.clone(), busy.clone());
    let (reports_hook, seen) = (reports.clone(), seen_before_commit.clone());
    let pause = Pause::paused();
    pause.release();
    let hooks = Hooks {
        pause: Some(pause.clone()),
        before_transaction: Some(Box::new(move |connection| {
            let pages: i64 = connection
                .pragma_query_value(None, "page_count", |row| row.get(0))
                .unwrap();
            let limit = if full_hook.load(Ordering::SeqCst) {
                pages
            } else {
                1 << 30
            };
            connection
                .pragma_update(None, "max_page_count", limit)
                .unwrap();
            let wait = if busy_hook.load(Ordering::SeqCst) {
                0
            } else {
                5_000
            };
            connection
                .busy_timeout(Duration::from_millis(wait))
                .unwrap();
        })),
        before_commit: Some(Box::new(move |_| {
            seen.lock()
                .unwrap()
                .push(reports_hook.load(Ordering::SeqCst));
        })),
        ..Hooks::default()
    };
    let (sender, outcomes) = mpsc::channel();
    let counter = reports.clone();
    let on_commit = Box::new(move |batch| {
        counter.fetch_add(1, Ordering::SeqCst);
        let _ = sender.send(batch);
    });
    let writer = spawn(&dir.db(), clock.clone(), on_commit, NO_QUOTA, hooks).unwrap();
    let harness = Harness { writer, outcomes };

    let first = harness.store(request(1, 1, 60));
    assert_eq!(
        (first.connection, first.client_ref),
        (1, request(1, 1, 60).client_ref)
    );
    let second = harness.store(request(2, 1, 60));
    assert_eq!(received_at(&second), T0 + 1);
    // Each commit came before its own report and after the previous one.
    assert_eq!(*seen_before_commit.lock().unwrap(), [0, 1]);

    // A full disk refuses the whole batch with `server_full`, the inserts
    // that went in before the failing one included.
    pause.hold();
    let mut big = request(4, 1, 60);
    big.blob = vec![4; 64 * 1024];
    for submitted in [request(3, 1, 60), big, request(5, 1, 60)] {
        harness.writer.submit(submitted).unwrap();
    }
    full.store(true, Ordering::SeqCst);
    pause.release();
    let refused = harness.next();
    assert_eq!(refused.len(), 3);
    assert!(
        refused
            .iter()
            .all(|outcome| outcome.result == Err(Refusal::ServerFull))
    );
    assert_eq!(count(&dir.db()), 2);
    full.store(false, Ordering::SeqCst);
    assert_eq!(received_at(&harness.store(request(6, 1, 60))), T0 + 2);

    // A lock held elsewhere refuses it with `rate_limited`.
    let other = Connection::open(dir.db()).unwrap();
    other.execute_batch("BEGIN IMMEDIATE").unwrap();
    busy.store(true, Ordering::SeqCst);
    pause.hold();
    for n in 7..10 {
        harness.writer.submit(request(n, 1, 60)).unwrap();
    }
    pause.release();
    let refused = harness.next();
    assert_eq!(refused.len(), 3);
    assert!(
        refused
            .iter()
            .all(|outcome| outcome.result == Err(Refusal::RateLimited))
    );
    other.execute_batch("COMMIT").unwrap();
    busy.store(false, Ordering::SeqCst);
    assert_eq!(received_at(&harness.store(request(10, 1, 60))), T0 + 3);

    // Only the committed transactions reached the hook before their commit.
    assert_eq!(*seen_before_commit.lock().unwrap(), [0, 1, 3, 5]);
    drop(harness);
    assert_eq!(count(&dir.db()), 4);
}

#[test]
fn s032_t08_r08_disk_quota() {
    let dir = TestDir::new("s032_t08");
    let clock = Arc::new(ManualClock::new(T0));
    drop(Harness::new(&dir.db(), &clock, Hooks::default()));
    let connection = Connection::open(dir.db()).unwrap();
    let live: i64 = connection
        .query_row(
            "SELECT (page_count - freelist_count) * page_size FROM pragma_page_count, pragma_freelist_count, pragma_page_size",
            [],
            |row| row.get(0),
        )
        .unwrap();
    drop(connection);
    let live = u64::try_from(live).unwrap();

    // At the quota: refused, nothing inserted.
    let harness = Harness::with_quota(&dir.db(), &clock, Hooks::default(), live);
    assert_eq!(
        harness.store(request(1, 1, 60)).result,
        Err(Refusal::ServerFull)
    );
    drop(harness);
    assert_eq!(count(&dir.db()), 0);

    // One byte above it: stored.
    let harness = Harness::with_quota(&dir.db(), &clock, Hooks::default(), live + 1);
    assert!(harness.store(request(2, 1, 60)).result.is_ok());
}

#[test]
fn s032_t14_r14_received_at_follows_the_wall_clock() {
    let dir = TestDir::new("s032_t14_wall");
    let clock = Arc::new(ManualClock::new(T0));
    let harness = Harness::new(&dir.db(), &clock, Hooks::default());
    assert_eq!(received_at(&harness.store(request(1, 1, 60))), T0);
    clock.advance(5_000);
    assert_eq!(received_at(&harness.store(request(2, 1, 60))), T0 + 5_000);
    // The monotonic reading alone moves no `received_at`.
    clock.advance_mono(60_000);
    assert_eq!(received_at(&harness.store(request(3, 1, 60))), T0 + 5_001);
}

/// The live bytes of the database, as R8 counts them.
fn live_bytes(db: &Path) -> u64 {
    let connection = Connection::open(db).unwrap();
    let read = |name: &str| -> u64 {
        let value: i64 = connection
            .pragma_query_value(None, name, |row| row.get(0))
            .unwrap();
        u64::try_from(value).unwrap()
    };
    (read("page_count") - read("freelist_count")) * read("page_size")
}

#[test]
fn s032_t08_r08_free_pages_do_not_count() {
    let dir = TestDir::new("s032_t08_free");
    let clock = Arc::new(ManualClock::new(T0));
    let harness = Harness::new(&dir.db(), &clock, Hooks::default());
    let mut big = request(1, 1, 60);
    big.blob = vec![1; 64 * 1024];
    assert!(harness.store(big).result.is_ok());
    drop(harness);
    let live = live_bytes(&dir.db());
    let harness = Harness::with_quota(&dir.db(), &clock, Hooks::default(), live);
    assert_eq!(
        harness.store(request(2, 1, 60)).result,
        Err(Refusal::ServerFull)
    );
    drop(harness);
    // Rows deleted, the file as large: its free pages do not count.
    let connection = Connection::open(dir.db()).unwrap();
    connection.execute("DELETE FROM messages", []).unwrap();
    drop(connection);
    assert!(live_bytes(&dir.db()) < live);
    let harness = Harness::with_quota(&dir.db(), &clock, Hooks::default(), live);
    assert!(harness.store(request(3, 1, 60)).result.is_ok());
}

#[test]
fn s032_t07_r07_failed_commit_keeps_last() {
    let dir = TestDir::new("s032_t07_commit");
    let clock = Arc::new(ManualClock::new(T0));
    let fail = Arc::new(AtomicBool::new(false));
    let fail_hook = fail.clone();
    let hooks = Hooks {
        before_commit: Some(Box::new(move |connection| {
            if fail_hook.load(Ordering::SeqCst) {
                connection.execute_batch("ROLLBACK").unwrap();
            }
        })),
        ..Hooks::default()
    };
    let harness = Harness::new(&dir.db(), &clock, hooks);
    assert_eq!(received_at(&harness.store(request(1, 1, 60))), T0);
    fail.store(true, Ordering::SeqCst);
    assert_eq!(
        harness.store(request(2, 1, 60)).result,
        Err(Refusal::RateLimited)
    );
    fail.store(false, Ordering::SeqCst);
    assert_eq!(received_at(&harness.store(request(3, 1, 60))), T0 + 1);
    drop(harness);
    assert_eq!(count(&dir.db()), 2);
}
