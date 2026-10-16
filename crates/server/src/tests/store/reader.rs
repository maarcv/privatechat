//! Spec 032-storage-ttl, the backlog reads (R9).

use std::path::Path;
use std::sync::Arc;

use super::super::TestDir;
use super::purge::plant;
use super::writer::{Harness, T0};
use crate::clock::ManualClock;
use crate::store::reader::{POOL_SIZE, ReadPool, read_page};
use crate::store::writer::test::Hooks;

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
}

/// A database with the schema, its writer stopped.
fn database(dir: &TestDir) {
    let clock = Arc::new(ManualClock::new(T0));
    drop(Harness::new(&dir.db(), &clock, Hooks::default()));
}

/// The sizes of the pages of channel `[channel; 16]` read from 0 to the end,
/// checking that every row is of that channel, in order, with no gap.
/// The planted rows of a channel have consecutive `received_at`.
fn page_sizes(db: &Path, channel: u8, now: u64) -> Vec<usize> {
    let pool = ReadPool::open(db).unwrap();
    let runtime = runtime();
    let mut from = 0;
    let mut next = None;
    let mut sizes = Vec::new();
    loop {
        let page = runtime
            .block_on(read_page(&pool, [channel; 16], from, now))
            .unwrap();
        let Some(last) = page.last() else {
            return sizes;
        };
        for row in &page {
            if let Some(expected) = next {
                assert_eq!(row.received_at, expected);
            }
            next = Some(row.received_at + 1);
            assert!(row.blob.iter().all(|byte| *byte == channel));
        }
        from = last.received_at + 1;
        sizes.push(page.len());
    }
}

#[test]
fn s032_t09_r09_read_page() {
    let dir = TestDir::new("s032_t09");
    database(&dir);
    let alive = T0 + 3_600_000;

    // The row limit: 500 rows of 500 bytes are 250 000 bytes.
    plant(&dir.db(), 1, 1_200, 500, alive, 0);
    plant(&dir.db(), 2, 50, 500, alive, 1_200);
    assert_eq!(page_sizes(&dir.db(), 1, T0), [500, 500, 200]);

    // The byte limit with the smallest blob: 221 × 1 185 = 261 885 bytes.
    plant(&dir.db(), 3, 1_200, 1_185, alive, 2_000);
    let sizes = page_sizes(&dir.db(), 3, T0);
    assert_eq!(sizes, [221, 221, 221, 221, 221, 95]);

    // The largest blob: four of 64 673 bytes per page.
    plant(&dir.db(), 4, 40, 64_673, alive, 4_000);
    assert_eq!(page_sizes(&dir.db(), 4, T0), [4; 10]);

    // A page of exactly 256 KiB: 64 rows of 4 096 bytes.
    plant(&dir.db(), 7, 128, 4_096, alive, 7_000);
    assert_eq!(page_sizes(&dir.db(), 7, T0), [64, 64]);

    // A row larger than a page still comes, alone.
    plant(&dir.db(), 5, 2, 300 * 1024, alive, 5_000);
    assert_eq!(page_sizes(&dir.db(), 5, T0), [1, 1]);

    // `expires_at = now` is expired; one millisecond more is not.
    plant(&dir.db(), 6, 1, 1_185, T0, 6_000);
    assert!(page_sizes(&dir.db(), 6, T0).is_empty());
    assert_eq!(page_sizes(&dir.db(), 6, T0 - 1), [1]);
}

#[test]
fn s032_t09_r09_pool_of_four() {
    assert_eq!(POOL_SIZE, 4);
    let dir = TestDir::new("s032_t09_pool");
    database(&dir);
    plant(&dir.db(), 1, 2_000, 1_185, T0 + 3_600_000, 0);
    let pool = Arc::new(ReadPool::open(&dir.db()).unwrap());
    let runtime = runtime();

    // Eight reads at once all complete.
    let pages = runtime.block_on(async {
        let reads: Vec<_> = (0..8u64)
            .map(|k| {
                let pool = pool.clone();
                tokio::spawn(async move { read_page(&pool, [1; 16], k * 100, T0).await })
            })
            .collect();
        let mut pages = Vec::new();
        for read in reads {
            pages.push(read.await.unwrap().unwrap());
        }
        pages
    });
    assert!(pages.iter().all(|page| page.len() == 221));

    // With the four connections taken, a fifth read waits, and goes on when
    // one comes back.
    runtime.block_on(async {
        let held = pool.permits().clone().acquire_many_owned(4).await.unwrap();
        assert_eq!(pool.permits().available_permits(), 0);
        let waiting = {
            let pool = pool.clone();
            tokio::spawn(async move { read_page(&pool, [1; 16], 0, T0).await })
        };
        for _ in 0..50 {
            tokio::task::yield_now().await;
        }
        assert!(!waiting.is_finished());
        drop(held);
        assert_eq!(waiting.await.unwrap().unwrap().len(), 221);
    });
}

#[test]
fn s032_t09_r09_a_failed_read_gives_its_connection_back() {
    let dir = TestDir::new("s032_t09_failed");
    database(&dir);
    plant(&dir.db(), 1, 1, 1_185, T0 + 3_600_000, 0);
    // A `received_at` that is not an integer: the read of channel 9 fails.
    rusqlite::Connection::open(dir.db())
        .unwrap()
        .execute(
            "INSERT INTO messages VALUES (zeroblob(16), ?1, 'x', ?2, x'00')",
            (&[9u8; 16][..], i64::try_from(T0 + 3_600_000).unwrap()),
        )
        .unwrap();
    let pool = ReadPool::open(&dir.db()).unwrap();
    let runtime = runtime();
    for _ in 0..=POOL_SIZE {
        assert!(runtime.block_on(read_page(&pool, [9; 16], 0, T0)).is_err());
    }
    let page = runtime.block_on(read_page(&pool, [1; 16], 0, T0)).unwrap();
    assert_eq!(page.len(), 1);
}
