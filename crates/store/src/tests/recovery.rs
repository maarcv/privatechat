//! Tests of spec 020 over commit, load, compaction and their recovery:
//! R9–R12, R14, R15, with the crash points and the fault injector.

use std::path::Path;

use privatechat_core::testing::state_for;
use privatechat_core::{Store, StoreError, Vault};

use super::{
    CRASH_STATUS, CRASH_VAR, TestDir, channel_dir, commit, dir_name, id, loaded, open, reopen,
    run_helper,
};
use crate::frame::{self, LOG_HEADER_LEN};
use crate::fs::Io;

/// The variables through which the crash helper learns its directory and
/// what to do.
const DIR_VAR: &str = "PRIVATECHAT_STORE_TEST_DIR";
const STEP_VAR: &str = "PRIVATECHAT_STORE_TEST_STEP";

fn read(path: &Path) -> Vec<u8> {
    std::fs::read(path).expect("read a test file")
}

fn write(path: &Path, bytes: &[u8]) {
    std::fs::write(path, bytes).expect("write a test file")
}

/// The child of the crash tests: loads channel 1 and commits records 1, 2,
/// 3 (`commit`) or compacts at 2 (`compact`), stopping where `CRASH_VAR`
/// says. Returns at once in a normal run.
#[test]
fn s020_t10_r10_crash_helper() {
    let (Ok(path), Ok(step)) = (std::env::var(DIR_VAR), std::env::var(STEP_VAR)) else {
        return;
    };
    let mut data = open(Path::new(&path));
    let mut store = data.create(&id(1)).expect("create");
    let (state, _) = store.load().expect("load").expect("committed");
    match step.as_str() {
        "commit" => commit(store.as_mut(), 1, &[1, 2, 3]).expect("commit"),
        _ => {
            store.compact(&state, 2).expect("compact");
        }
    }
}

/// Runs the crash helper over `path` for `step`, crashing at `point`.
fn crash(path: &Path, step: &str, point: &str) {
    let path = path.to_str().expect("utf-8 path");
    let status = run_helper(
        "tests::recovery::s020_t10_r10_crash_helper",
        &[(DIR_VAR, path), (STEP_VAR, step), (CRASH_VAR, point)],
    );
    assert_eq!(status, Some(CRASH_STATUS), "{step} at {point}");
}

/// A data directory at `path` whose channel 1 committed records 1 and 2.
fn committed_two(path: &Path) {
    let mut data = open(path);
    let mut store = data.create(&id(1)).expect("create");
    commit(store.as_mut(), 1, &[1, 2]).expect("commit");
}

/// Spec 020, R9: an entry read at another place, or repeated, does not load.
#[test]
fn s020_t09_r09_entry_bound_to_place() {
    let dir = TestDir::new("t09");
    committed_two(dir.path());
    let log = channel_dir(dir.path(), 1).join("messages.log");
    let committed = read(&log);
    let first_len = u32::from_be_bytes(committed[9..13].try_into().expect("len")) as usize;
    let first = &committed[9..13 + first_len];
    let second = &committed[13 + first_len..];
    assert_eq!(first.len(), second.len());
    for (what, bytes) in [
        ("swapped", [&committed[..9], second, first].concat()),
        ("repeated", [&committed[..9], first, first].concat()),
    ] {
        write(&log, &bytes);
        assert_eq!(reopen(dir.path(), 1), Err(StoreError::Corrupt), "{what}");
    }
    // The files of channel 1 under the name of channel 2.
    write(&log, &committed);
    let mut data = open(dir.path());
    drop(data.create(&id(2)).expect("create"));
    for file in ["state.bin", "messages.log"] {
        std::fs::copy(
            channel_dir(dir.path(), 1).join(file),
            channel_dir(dir.path(), 2).join(file),
        )
        .expect("copy");
    }
    let mut store = data.create(&id(2)).expect("create");
    assert_eq!(loaded(store.as_mut()), Err(StoreError::Corrupt));
}

/// Spec 020, R10: a crash after the append or before the rename gives the
/// previous commit; stale bytes past the committed end are overwritten.
#[test]
fn s020_t10_r10_commit_order() {
    for point in ["after_append:1", "after_state_tmp:1"] {
        let dir = TestDir::new(&format!("t10-{}", point.replace(':', "-")));
        committed_two(dir.path());
        let log = channel_dir(dir.path(), 1).join("messages.log");
        let before = read(&log).len();
        crash(dir.path(), "commit", point);
        let ((len, _), records) = reopen(dir.path(), 1).expect("load").expect("committed");
        assert_eq!(
            (len, records),
            (u64::try_from(before).unwrap(), vec![1, 2]),
            "{point}"
        );
        assert_eq!(read(&log).len(), before, "{point}");
        assert!(!channel_dir(dir.path(), 1).join("state.bin.tmp").exists());
    }
    let dir = TestDir::new("t10-ok");
    committed_two(dir.path());
    let log = channel_dir(dir.path(), 1).join("messages.log");
    let mut stale = read(&log);
    stale.extend_from_slice(&[0xee; 100]);
    write(&log, &stale);
    let mut data = open(dir.path());
    let mut store = data.create(&id(1)).expect("create");
    commit(store.as_mut(), 1, &[3]).expect("commit over stale bytes");
    drop((store, data));
    let ((len, _), records) = reopen(dir.path(), 1).expect("load").expect("committed");
    assert_eq!(records, vec![1, 2, 3]);
    assert_eq!(read(&log).len() as u64, len);
}

/// What one faulty call left, seen by the store that made it and by a fresh
/// one.
fn check_fault(
    path: &Path,
    k: u32,
    mut store: crate::channel::ChannelFiles,
    previous: &[u64],
    new: &[u64],
) -> (bool, bool) {
    let channel = channel_dir(path, 1);
    let poisoned = matches!(store.load(), Err(StoreError::Io));
    if poisoned {
        assert!(commit(&mut store, 1, &[9]).is_err(), "k={k}");
    } else {
        assert_eq!(
            loaded(&mut store).expect("usable").map(|(_, r)| r),
            Some(previous.to_vec()),
            "k={k}"
        );
    }
    drop(store);
    let after = reopen(path, 1).expect("load").expect("committed").1;
    if poisoned {
        assert!(after == previous || after == new, "k={k}: {after:?}");
    } else {
        assert_eq!(after, previous, "k={k}");
        assert!(!channel.join("state.bin.tmp").exists(), "k={k}");
        assert!(!channel.join("messages.log.new").exists(), "k={k}");
    }
    (!poisoned, poisoned)
}

/// Spec 020, R11: a fault at each system call of a commit and of a
/// compaction: before the state's rename the call fails and nothing changes;
/// at or after it the store is poisoned and a fresh one sees one commit or
/// the other, never a mix.
#[test]
fn s020_t11_r11_failure_and_poison() {
    for compaction in [false, true] {
        let (previous, new): (&[u64], &[u64]) = if compaction {
            (&[1, 2, 3], &[2, 3])
        } else {
            (&[1, 2], &[1, 2, 3])
        };
        let (mut before, mut after) = (false, false);
        for k in 1.. {
            let dir = TestDir::new(&format!("t11-{compaction}-{k}"));
            {
                let mut data = open(dir.path());
                let mut store = data.create(&id(1)).expect("create");
                commit(store.as_mut(), 1, previous).expect("commit");
            }
            let data = open(dir.path());
            let mut store = data
                .store_with(dir_name(1), Io::failing_at(k))
                .expect("store");
            let state = state_for(id(1));
            let result = if compaction {
                store.compact(&state, 2).map(|_| ())
            } else {
                commit(&mut store, 1, &[3])
            };
            if result.is_ok() {
                // Past the last call, or swallowed by a best-effort delete.
                if store.io().calls() < k {
                    break;
                }
                continue;
            }
            drop(data);
            let (failed_before, failed_after) = check_fault(dir.path(), k, store, previous, new);
            before |= failed_before;
            after |= failed_after;
        }
        assert!(before && after, "compaction={compaction}");
    }
}

/// Spec 020, R12: bytes past the committed length are cut, a shorter log or
/// a flipped byte is `Corrupt`, a leftover `state.bin.tmp` is deleted.
#[test]
fn s020_t12_r12_load_checks() {
    let dir = TestDir::new("t12");
    committed_two(dir.path());
    let channel = channel_dir(dir.path(), 1);
    let log = channel.join("messages.log");
    let committed = read(&log);
    write(&log, &[&committed[..], &[0u8; 7]].concat());
    write(&channel.join("state.bin.tmp"), b"leftover");
    let ((len, _), _) = reopen(dir.path(), 1).expect("load").expect("committed");
    assert_eq!(read(&log), committed);
    assert_eq!(len, u64::try_from(committed.len()).unwrap());
    assert!(!channel.join("state.bin.tmp").exists());
    write(&log, &committed[..committed.len() - 1]);
    assert_eq!(reopen(dir.path(), 1), Err(StoreError::Corrupt));
    let mut flipped = committed.clone();
    flipped[LOG_HEADER_LEN + 30] ^= 1;
    write(&log, &flipped);
    assert_eq!(reopen(dir.path(), 1), Err(StoreError::Corrupt));
}

/// Spec 020, R14: a compaction cut after its state is completed; a `.new`
/// left before its state is deleted, even when that fails; generations two
/// apart are `Corrupt`.
#[test]
fn s020_t14_r14_interrupted_compaction() {
    let dir = TestDir::new("t14");
    committed_two(dir.path());
    crash(dir.path(), "compact", "after_compact_state:1");
    let channel = channel_dir(dir.path(), 1);
    let ((_, generation), records) = reopen(dir.path(), 1).expect("load").expect("committed");
    assert_eq!((generation, records), (1, vec![2]));
    assert!(!channel.join("messages.log.new").exists());
    assert_eq!(
        frame::read_log_header(&read(&channel.join("messages.log"))),
        Ok(1)
    );
    // A `.new` of a compaction that never wrote its state.
    write(&channel.join("messages.log.new"), &frame::log_header(2));
    assert!(reopen(dir.path(), 1).expect("load").is_some());
    assert!(!channel.join("messages.log.new").exists());
    // One that cannot be deleted (a directory) does not fail the load.
    std::fs::create_dir_all(channel.join("messages.log.new").join("x")).expect("dir");
    assert!(reopen(dir.path(), 1).expect("load").is_some());
    std::fs::remove_dir_all(channel.join("messages.log.new")).expect("clean");
    // A log whose generation is not the state's nor the one before it.
    let log = channel.join("messages.log");
    let mut apart = read(&log);
    apart[5..9].copy_from_slice(&3u32.to_be_bytes());
    write(&log, &apart);
    assert_eq!(reopen(dir.path(), 1), Err(StoreError::Corrupt));
}

/// Spec 020, R15: the dropped count, the survivors in order at new offsets
/// under generation + 1; nothing to drop writes nothing; the generation is
/// the store's, not the state's.
#[test]
fn s020_t15_r15_compaction() {
    let dir = TestDir::new("t15");
    let mut data = open(dir.path());
    let mut store = data.create(&id(1)).expect("create");
    commit(store.as_mut(), 1, &[1, 5, 2, 7]).expect("commit");
    let (state, _) = store.load().expect("load").expect("committed");
    let channel = channel_dir(dir.path(), 1);
    let files = || {
        (
            read(&channel.join("state.bin")),
            read(&channel.join("messages.log")),
        )
    };
    let untouched = files();
    assert_eq!(store.compact(&state, 1), Ok(0));
    assert_eq!(files(), untouched);
    assert_eq!(store.compact(&state, 3), Ok(2));
    let ((len, generation), records) = loaded(store.as_mut()).expect("load").expect("committed");
    assert_eq!((generation, records), (1, vec![5, 7]));
    assert_eq!(len, store.log_len());
    // A commit and a second compaction, the latter handed the state loaded
    // before the first, which still names generation 0.
    commit(store.as_mut(), 1, &[2]).expect("commit");
    assert_eq!(state.log_position().1, 0);
    assert_eq!(store.compact(&state, 3), Ok(1));
    drop((store, data));
    let ((_, generation), records) = reopen(dir.path(), 1).expect("load").expect("committed");
    assert_eq!((generation, records), (2, vec![5, 7]));
}
