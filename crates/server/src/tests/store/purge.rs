//! Spec 032-storage-ttl, the purge and the counters (R10, R11, R13), and
//! the clauses of T06, T07, T08 and T14 that need a purge.

use std::collections::HashSet;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rusqlite::Connection;

use super::super::TestDir;
use super::writer::{Harness, T0, count, received_at, request};
use crate::clock::ManualClock;
use crate::store::writer::Refusal;
use crate::store::writer::purge::{Counters, PURGE_INTERVAL_MS, count_all};
use crate::store::writer::test::{Hooks, Pause, StepHook};

/// Waits up to 5 s of real time for `done`.
fn wait_for(mut done: impl FnMut() -> bool) -> bool {
    for _ in 0..500 {
        if done() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    done()
}

/// Inserts `n` rows of `bytes` bytes into channel `[channel; 16]` with
/// `expires_at`, by hand, in one transaction; ids start at `first`.
pub(super) fn plant(db: &Path, channel: u8, n: u32, bytes: usize, expires_at: u64, first: u32) {
    let mut connection = Connection::open(db).unwrap();
    let transaction = connection.transaction().unwrap();
    for k in first..first + n {
        let mut server_id = [0xee; 16];
        server_id[..4].copy_from_slice(&k.to_be_bytes());
        transaction
            .execute(
                "INSERT INTO messages(server_id, channel_id, received_at, expires_at, blob) VALUES (?1, ?2, ?3, ?4, ?5)",
                (
                    &server_id[..],
                    &[channel; 16][..],
                    i64::from(k),
                    i64::try_from(expires_at).unwrap(),
                    vec![channel; bytes],
                ),
            )
            .unwrap();
    }
    transaction.commit().unwrap();
}

fn pragma(db: &Path, name: &str) -> i64 {
    Connection::open(db)
        .unwrap()
        .pragma_query_value(None, name, |row| row.get(0))
        .unwrap()
}

fn wal_len(db: &Path) -> u64 {
    let mut wal = db.as_os_str().to_owned();
    wal.push("-wal");
    std::fs::metadata(wal).map_or(0, |metadata| metadata.len())
}

/// The purge rounds the writer reports.
fn rounds_hook(rounds: &Arc<Mutex<Vec<usize>>>) -> Option<Box<dyn FnMut(usize) + Send>> {
    let rounds = rounds.clone();
    Some(Box::new(move |rows| rounds.lock().unwrap().push(rows)))
}

/// The counters and a fresh `GROUP BY` after each batch and each purge.
fn steps_hook() -> (Option<StepHook>, Receiver<(Counters, Counters)>) {
    let (sender, steps) = mpsc::channel();
    let hook = Box::new(move |connection: &Connection, counters: &Counters| {
        let _ = sender.send((counters.clone(), count_all(connection).unwrap()));
    });
    (Some(hook), steps)
}

fn next_step(steps: &Receiver<(Counters, Counters)>) -> Counters {
    let (counters, grouped) = steps.recv_timeout(Duration::from_secs(30)).unwrap();
    assert_eq!(counters, grouped);
    counters
}

#[test]
fn s032_t10_r10_purge() {
    let dir = TestDir::new("s032_t10");
    let clock = Arc::new(ManualClock::new(T0));
    drop(Harness::new(&dir.db(), &clock, Hooks::default()));
    plant(&dir.db(), 1, 2_500, 1_185, T0 - 1, 0);
    plant(&dir.db(), 1, 10, 1_185, T0 + 3_600_000, 2_500);
    // `expires_at = now` is not yet past: the purge keeps it (R10).
    plant(&dir.db(), 1, 1, 1_185, T0, 2_510);
    let pages = pragma(&dir.db(), "page_count");

    let rounds = Arc::new(Mutex::new(Vec::new()));
    let hooks = Hooks {
        purge_round: rounds_hook(&rounds),
        ..Hooks::default()
    };
    let harness = Harness::new(&dir.db(), &clock, hooks);
    // Purged before `spawn` returned.
    assert_eq!(*rounds.lock().unwrap(), [1_000, 1_000, 500]);
    assert_eq!(count(&dir.db()), 11);
    assert_eq!(pragma(&dir.db(), "freelist_count"), 0);
    assert!(pragma(&dir.db(), "page_count") < pages);
    assert_eq!(wal_len(&dir.db()), 0);

    // The next purge comes 60 000 ms of the monotonic clock later.
    plant(&dir.db(), 2, 5, 1_185, T0 - 1, 3_000);
    clock.advance_mono(PURGE_INTERVAL_MS);
    assert!(wait_for(|| rounds.lock().unwrap().len() == 4));
    // The wall clock has not moved: the row at `T0` is still not past.
    assert_eq!(rounds.lock().unwrap()[3], 5);
    assert_eq!(count(&dir.db()), 11);
    drop(harness);
}

#[test]
fn s032_t14_r14_purge_on_the_monotonic_clock() {
    let dir = TestDir::new("s032_t14_purge");
    let clock = Arc::new(ManualClock::new(T0));
    drop(Harness::new(&dir.db(), &clock, Hooks::default()));
    plant(&dir.db(), 1, 3, 1_185, T0 + 60_000, 0);
    let rounds = Arc::new(Mutex::new(Vec::new()));
    let hooks = Hooks {
        purge_round: rounds_hook(&rounds),
        ..Hooks::default()
    };
    let _harness = Harness::new(&dir.db(), &clock, hooks);
    assert_eq!(*rounds.lock().unwrap(), [0]);

    // The wall clock an hour ahead expires the rows but starts no purge.
    clock.set_wall(T0 + 3_600_000);
    std::thread::sleep(Duration::from_millis(400));
    assert_eq!(rounds.lock().unwrap().len(), 1);
    assert_eq!(count(&dir.db()), 3);

    // The monotonic clock alone starts it, 60 000 ms after the last, at the
    // next wake, and once.
    assert_eq!(PURGE_INTERVAL_MS, 60_000);
    clock.advance_mono(59_999);
    std::thread::sleep(Duration::from_millis(400));
    assert_eq!(rounds.lock().unwrap().len(), 1);
    clock.advance_mono(1);
    assert!(wait_for(|| rounds.lock().unwrap().len() == 2));
    assert_eq!(count(&dir.db()), 0);
    std::thread::sleep(Duration::from_millis(400));
    assert_eq!(rounds.lock().unwrap().len(), 2);
}

#[test]
fn s032_t11_r11_counters() {
    let dir = TestDir::new("s032_t11");
    let clock = Arc::new(ManualClock::new(T0));
    let (after_step, steps) = steps_hook();
    let hooks = Hooks {
        after_step,
        ..Hooks::default()
    };
    let harness = Harness::new(&dir.db(), &clock, hooks);
    assert!(next_step(&steps).is_empty());
    for n in 0..3 {
        harness.store(request(n, 1, 3_600));
        next_step(&steps);
    }
    for n in 3..5 {
        harness.store(request(n, 2, 1));
        next_step(&steps);
    }
    let counters = next_step_now(&harness, &steps);
    assert_eq!(counters.len(), 2);

    // A purge that empties channel 2 drops its entry.
    clock.advance(2_000);
    clock.advance_mono(PURGE_INTERVAL_MS);
    let counters = next_step(&steps);
    assert_eq!(counters.keys().collect::<Vec<_>>(), [&[1; 16]]);
    assert_eq!(
        (counters[&[1; 16]].blobs, counters[&[1; 16]].bytes),
        (4, 400)
    );
    drop(harness);

    // Rebuilt at start-up, equal.
    let (after_step, steps) = steps_hook();
    let hooks = Hooks {
        after_step,
        ..Hooks::default()
    };
    let _harness = Harness::new(&dir.db(), &clock, hooks);
    assert_eq!(next_step(&steps), counters);
}

/// The counters after one more batch, checked against a `GROUP BY`.
fn next_step_now(harness: &Harness, steps: &Receiver<(Counters, Counters)>) -> Counters {
    harness.store(request(99, 1, 3_600));
    next_step(steps)
}

#[test]
fn s032_t07_r07_a_failed_batch_leaves_the_counters() {
    let dir = TestDir::new("s032_t07_counters");
    let clock = Arc::new(ManualClock::new(T0));
    let (after_step, steps) = steps_hook();
    let (busy, full) = (
        Arc::new(AtomicBool::new(false)),
        Arc::new(AtomicBool::new(false)),
    );
    let (busy_hook, full_hook) = (busy.clone(), full.clone());
    let pause = Pause::paused();
    pause.release();
    let hooks = Hooks {
        after_step,
        pause: Some(pause.clone()),
        before_transaction: Some(Box::new(move |connection| {
            let wait = if busy_hook.load(Ordering::SeqCst) {
                0
            } else {
                5_000
            };
            connection
                .busy_timeout(Duration::from_millis(wait))
                .unwrap();
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
        })),
        ..Hooks::default()
    };
    let harness = Harness::new(&dir.db(), &clock, hooks);
    next_step(&steps);
    harness.store(request(0, 1, 60));
    let before = next_step(&steps);

    // A lock held elsewhere: the batch fails before it inserts.
    let other = Connection::open(dir.db()).unwrap();
    other.execute_batch("BEGIN IMMEDIATE").unwrap();
    busy.store(true, Ordering::SeqCst);
    assert_eq!(
        harness.store(request(1, 1, 60)).result,
        Err(Refusal::RateLimited)
    );
    assert_eq!(next_step(&steps), before);
    other.execute_batch("COMMIT").unwrap();
    busy.store(false, Ordering::SeqCst);

    // A full disk: the batch inserts a blob, then fails on the next one.
    pause.hold();
    let mut big = request(3, 1, 60);
    big.blob = vec![1; 64 * 1024];
    for submitted in [request(2, 1, 60), big] {
        harness.writer.submit(submitted).unwrap();
    }
    full.store(true, Ordering::SeqCst);
    pause.release();
    let refused = harness.next();
    assert!(
        refused
            .iter()
            .all(|outcome| outcome.result == Err(Refusal::ServerFull))
    );
    assert_eq!(next_step(&steps), before);
}

#[test]
fn s032_t06_r06_received_at_after_an_emptying_purge() {
    let dir = TestDir::new("s032_t06_purge");
    let clock = Arc::new(ManualClock::new(T0));
    let harness = Harness::new(&dir.db(), &clock, Hooks::default());
    assert_eq!(received_at(&harness.store(request(0, 1, 1))), T0);
    assert_eq!(received_at(&harness.store(request(1, 1, 1))), T0 + 1);
    drop(harness);

    // The start-up purge empties the table, then the clock goes back a day.
    clock.set_wall(T0 + 10_000);
    let harness = Harness::new(&dir.db(), &clock, Hooks::default());
    assert_eq!(count(&dir.db()), 0);
    clock.set_wall(T0 - 86_400_000);
    assert_eq!(received_at(&harness.store(request(2, 1, 60))), T0 + 2);
}

#[test]
fn s032_t08_r08_space_freed_by_a_purge() {
    let dir = TestDir::new("s032_t08_purge");
    let clock = Arc::new(ManualClock::new(T0));
    drop(Harness::new(&dir.db(), &clock, Hooks::default()));
    plant(&dir.db(), 1, 200, 64 * 1024, T0 + 1_000, 0);
    let page_size = pragma(&dir.db(), "page_size");
    let pages = pragma(&dir.db(), "page_count");
    // Between what the file will still hold after the purge's vacuum, which
    // gives back 1 000 pages, and what it holds now: only a quota that counts
    // live pages alone stores again after the purge.
    let quota = u64::try_from((pages - 1_010) * page_size).unwrap();

    let rounds = Arc::new(Mutex::new(Vec::new()));
    let hooks = Hooks {
        purge_round: rounds_hook(&rounds),
        ..Hooks::default()
    };
    let harness = Harness::with_quota(&dir.db(), &clock, hooks, quota);
    assert_eq!(
        harness.store(request(0, 2, 60)).result,
        Err(Refusal::ServerFull)
    );

    clock.advance(2_000);
    clock.advance_mono(PURGE_INTERVAL_MS);
    // The vacuum, after the rounds, gives back 1 000 free pages and no more
    // (and the pointer-map pages that tracked them).
    assert!(wait_for(|| pragma(&dir.db(), "page_count") <= pages - 1_000));
    assert!(pragma(&dir.db(), "page_count") >= pages - 1_010);
    let file = u64::try_from(pragma(&dir.db(), "page_count") * page_size).unwrap();
    assert!(
        file >= quota,
        "the file is still as large: {file} of {quota}"
    );
    assert!(harness.store(request(1, 2, 60)).result.is_ok());
    drop(harness);
    assert_eq!(count(&dir.db()), 1);
}

/// A pseudo-random blob of `len` bytes for `seed`, a pattern no page of the
/// database holds by chance.
fn pattern(seed: u64, len: usize) -> Vec<u8> {
    let mut state = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
    (0..len)
        .map(|_| {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (state >> 56) as u8
        })
        .collect()
}

#[test]
fn s032_t13_r13_nothing_left_behind() {
    let dir = TestDir::new("s032_t13");
    // Pages hold several blobs: the purged ones share pages with those that stay.
    let clock = Arc::new(ManualClock::new(T0));
    let (after_step, steps) = steps_hook();
    let hooks = Hooks {
        after_step,
        ..Hooks::default()
    };
    let harness = Harness::new(&dir.db(), &clock, hooks);
    next_step(&steps);
    let blobs: Vec<Vec<u8>> = (0..200).map(|seed| pattern(seed, 1_185)).collect();
    // One blob in three stays, so that the pages of the purged ones stay in
    // the file around it.
    let stays = |n: usize| n.is_multiple_of(3);
    for (n, blob) in blobs.iter().enumerate() {
        let ttl = if stays(n) { 3_600 } else { 1 };
        let mut submitted = request(u16::try_from(n).unwrap(), 1, ttl);
        submitted.blob = blob.clone();
        assert!(harness.store(submitted).result.is_ok());
        next_step(&steps);
    }

    clock.advance(2_000);
    clock.advance_mono(PURGE_INTERVAL_MS);
    assert_eq!(next_step(&steps)[&[1; 16]].blobs, 67);
    assert_eq!(count(&dir.db()), 67);

    let mut wal = dir.db().into_os_string();
    wal.push("-wal");
    for file in [dir.db().into_os_string(), wal] {
        let bytes = std::fs::read(&file).unwrap_or_default();
        let runs: HashSet<&[u8]> = bytes.windows(64).collect();
        let purged = blobs.iter().enumerate().filter(|(n, _)| !stays(*n));
        for (_, blob) in purged {
            assert!(
                blob.windows(64).all(|run| !runs.contains(run)),
                "a purged run in {file:?}"
            );
        }
    }
    drop(harness);
}

#[test]
fn s032_t07_r07_a_failed_commit_leaves_the_counters() {
    let dir = TestDir::new("s032_t07_commit_counters");
    let clock = Arc::new(ManualClock::new(T0));
    let (after_step, steps) = steps_hook();
    let fail = Arc::new(AtomicBool::new(false));
    let fail_hook = fail.clone();
    let hooks = Hooks {
        after_step,
        before_commit: Some(Box::new(move |connection| {
            if fail_hook.load(Ordering::SeqCst) {
                connection.execute_batch("ROLLBACK").unwrap();
            }
        })),
        ..Hooks::default()
    };
    let harness = Harness::new(&dir.db(), &clock, hooks);
    next_step(&steps);
    harness.store(request(0, 1, 60));
    let before = next_step(&steps);
    fail.store(true, Ordering::SeqCst);
    assert!(harness.store(request(1, 1, 60)).result.is_err());
    assert_eq!(next_step(&steps), before);
}

#[test]
fn s032_t10_r10_a_failed_round_still_vacuums() {
    let dir = TestDir::new("s032_t10_failed_round");
    let clock = Arc::new(ManualClock::new(T0));
    drop(Harness::new(&dir.db(), &clock, Hooks::default()));
    plant(&dir.db(), 1, 2_500, 1_185, T0 - 1, 0);
    // The second round meets a row it cannot delete and fails whole.
    Connection::open(dir.db())
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER refuse BEFORE DELETE ON messages \
             WHEN old.received_at = 1500 BEGIN SELECT RAISE(ABORT, 'no'); END;",
        )
        .unwrap();
    let rounds = Arc::new(Mutex::new(Vec::new()));
    let hooks = Hooks {
        purge_round: rounds_hook(&rounds),
        ..Hooks::default()
    };
    let _harness = Harness::new(&dir.db(), &clock, hooks);
    assert_eq!(*rounds.lock().unwrap(), [1_000]);
    assert_eq!(count(&dir.db()), 1_500);
    // The first round's pages are given back and the WAL emptied anyway.
    assert_eq!(pragma(&dir.db(), "freelist_count"), 0);
    assert_eq!(wal_len(&dir.db()), 0);
}
