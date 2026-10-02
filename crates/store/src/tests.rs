//! Tests of spec 020-store-files over the files: the data directory, its lock
//! and the I/O module. The crash points and faults they drive exist only under
//! `cfg(test)`, which is why these tests live here and not under `tests/`.

#![allow(
    clippy::disallowed_methods,
    reason = "the one audited place of store I/O"
)]

mod files;
mod golden;
mod recovery;

use std::path::{Path, PathBuf};
use std::process::Command;

use privatechat_core::testing::{batch, record, state_for};
use privatechat_core::{ChannelState, LogRecord, StorageKey, Store, StoreError, Vault};

use crate::DataDir;
use crate::fs::test::{CRASH_STATUS, CRASH_VAR, crash_point};
use crate::fs::{Call, Io};

/// A directory of its own for one test, `temp_dir()/privatechat-<pid>-<name>`,
/// removed when the test ends.
struct TestDir(PathBuf);

impl TestDir {
    fn new(name: &str) -> TestDir {
        let path = std::env::temp_dir().join(format!("privatechat-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        TestDir(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn key() -> StorageKey {
    StorageKey::from_bytes(&mut [7u8; 32])
}

/// The data directory at `path` under the test key. A helper child that
/// another test is starting can hold a copy of the lock for the moment
/// between its fork and its exec, so a `Locked` is retried for a while.
fn open(path: &Path) -> DataDir {
    for _ in 0..200 {
        match DataDir::open(path, key()) {
            Err(StoreError::Locked) => std::thread::sleep(std::time::Duration::from_millis(10)),
            opened => return opened.expect("open the data directory"),
        }
    }
    DataDir::open(path, key()).expect("the data directory stays locked")
}

/// `DataDir::open_with` of a fresh `io`, retried as `open` retries.
fn open_with(path: &Path, io: impl Fn() -> Io) -> Result<DataDir, StoreError> {
    for _ in 0..200 {
        match DataDir::open_with(path, key(), io()) {
            Err(StoreError::Locked) => std::thread::sleep(std::time::Duration::from_millis(10)),
            opened => return opened,
        }
    }
    DataDir::open_with(path, key(), io())
}

/// The channel id of test channel `n`.
fn id(n: u8) -> [u8; 16] {
    [n; 16]
}

/// The directory of test channel `n` under the data directory `path`.
fn channel_dir(path: &Path, n: u8) -> PathBuf {
    path.join("channels").join(crate::hex(&dir_name(n)))
}

/// The directory name of test channel `n` under the test key.
fn dir_name(n: u8) -> privatechat_core::DirName {
    privatechat_core::dir_name(&key(), &id(n)).expect("dir name")
}

/// Commits to `store` a fresh state of channel `n` with one record per
/// `purge_at`.
fn commit(store: &mut dyn Store, n: u8, purge_at: &[u64]) -> Result<(), StoreError> {
    let records: Vec<LogRecord> = purge_at.iter().map(|at| record(*at, 10)).collect();
    store.commit(&batch(state_for(id(n)), records))
}

/// A new channel `n` in `store`: its first commit, which carries no record
/// (R13), then one with a record per `purge_at`.
fn seed(store: &mut dyn Store, n: u8, purge_at: &[u64]) -> Result<(), StoreError> {
    commit(store, n, &[])?;
    commit(store, n, purge_at)
}

/// The `purge_at` of each record, which tells the records of these tests
/// apart.
fn purges(records: &[LogRecord]) -> Vec<u64> {
    records.iter().map(LogRecord::purge_at).collect()
}

/// What a test sees of a `load`: the state's log position and the records'
/// `purge_at`, `None` for a channel never committed.
type Loaded = Result<Option<((u64, u32), Vec<u64>)>, StoreError>;

/// What `load` returns, as the state's log position and the records'
/// `purge_at`.
fn loaded(store: &mut dyn Store) -> Loaded {
    Ok(store
        .load()?
        .map(|(state, records): (ChannelState, Vec<LogRecord>)| {
            (state.log_position(), purges(&records))
        }))
}

/// The store of test channel `n` in a fresh `DataDir` of `path`, loaded.
fn reopen(path: &Path, n: u8) -> Loaded {
    let mut data = open(path);
    let mut store = data.create(&id(n))?;
    loaded(store.as_mut())
}

/// Runs the test `helper` of this binary in a child process with `env`, and
/// returns its exit status.
fn run_helper(helper: &str, env: &[(&str, &str)]) -> Option<i32> {
    let mut child = Command::new(std::env::current_exe().expect("test binary"));
    child.args(["--exact", helper, "--test-threads=1", "--quiet"]);
    for (name, value) in env {
        child.env(name, value);
    }
    child.status().expect("child runs").code()
}

/// The variable through which the lock helper learns which directory to open.
const LOCK_PROBE_VAR: &str = "PRIVATECHAT_STORE_LOCK_PROBE";

/// Exit statuses of the lock helper.
const PROBE_LOCKED: i32 = 87;
const PROBE_OPENED: i32 = 88;

/// The child of `s020_t17_r17_single_process_lock`: opens the data directory
/// the variable names and exits with what it got. Returns at once in a normal
/// run.
#[test]
fn s020_t17_r17_lock_probe_helper() {
    let Ok(path) = std::env::var(LOCK_PROBE_VAR) else {
        return;
    };
    match DataDir::open(Path::new(&path), key()) {
        Err(StoreError::Locked) => std::process::exit(PROBE_LOCKED),
        Ok(_) => std::process::exit(PROBE_OPENED),
        Err(_) => std::process::exit(1),
    }
}

/// Spec 020, R17: `open` creates the directory and `channels/`, and a second
/// `open`, in this process or another, gets `Locked` until the first is
/// dropped.
#[test]
fn s020_t17_r17_single_process_lock() {
    let dir = TestDir::new("t17");
    let path = dir.path().join("nested").join("data");
    let first = open(&path);
    assert!(path.join("channels").is_dir());
    assert!(path.join("LOCK").is_file());
    assert!(matches!(
        DataDir::open(&path, key()),
        Err(StoreError::Locked)
    ));
    let probe = path.to_str().expect("utf-8 path");
    assert_eq!(
        run_helper(
            "tests::s020_t17_r17_lock_probe_helper",
            &[(LOCK_PROBE_VAR, probe)]
        ),
        Some(PROBE_LOCKED)
    );
    // A store keeps the lock after its `DataDir` is gone.
    let mut first = first;
    let store = first.create(&id(1)).expect("create");
    drop(first);
    assert!(matches!(
        DataDir::open(&path, key()),
        Err(StoreError::Locked)
    ));
    assert_eq!(
        run_helper(
            "tests::s020_t17_r17_lock_probe_helper",
            &[(LOCK_PROBE_VAR, probe)]
        ),
        Some(PROBE_LOCKED)
    );
    drop(store);
    drop(open(&path));
    assert_eq!(
        run_helper(
            "tests::s020_t17_r17_lock_probe_helper",
            &[(LOCK_PROBE_VAR, probe)]
        ),
        Some(PROBE_OPENED)
    );
}

/// Spec 020, R17: an existing directory opens as it is, and a failed system
/// call is `Io`, never a panic or a partial lock.
#[test]
fn s020_t17_r17_open_existing_and_failing() {
    let dir = TestDir::new("t17b");
    drop(open(dir.path()));
    drop(open(dir.path()));
    // Every system call of an `open` that creates nothing: the lock file
    // and its lock, whose failure is `Io`, then the cleanup of R19 and R22,
    // whose failure `open` ignores.
    let kinds = open_with(dir.path(), Io::new).expect("probe").io.kinds();
    assert_eq!(kinds, [Call::Lock, Call::Lock, Call::Remove, Call::List]);
    for (k, kind) in (1..).zip(&kinds) {
        let opened = open_with(dir.path(), || Io::failing_at(k));
        if *kind == Call::Lock {
            assert!(matches!(opened, Err(StoreError::Io)), "k={k}");
        } else {
            assert!(opened.is_ok(), "k={k} is best effort");
        }
    }
    drop(open(dir.path()));
}

/// Spec 020, R17: a relative path whose every component is missing is
/// created from the current directory.
#[test]
fn s020_t17_r17_relative_path() {
    let relative = PathBuf::from(format!("privatechat-relative-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&relative);
    let path = relative.join("data");
    drop(open(&path));
    assert!(path.join("channels").is_dir());
    std::fs::remove_dir_all(&relative).expect("clean");
}

/// Spec 020, R26: an I/O failure says `Io` and nothing else, no path.
#[test]
fn s020_t26_r26_io_error_has_no_path() {
    let dir = TestDir::new("t26");
    std::fs::create_dir(dir.path()).expect("test directory");
    let file = dir.path().join("a-file");
    std::fs::write(&file, b"x").expect("file");
    let error = DataDir::open(&file.join("data"), key()).expect_err("under a file");
    assert_eq!(error, StoreError::Io);
    assert_eq!(format!("{error:?}"), "Io");
}

/// Spec 020, R23: the fault injector counts the calls of its own instance, so
/// a fault in one store does not reach another, and fast mode skips and
/// counts every sync.
#[test]
fn s020_t23_r23_faults_and_fast_mode_per_instance() {
    let dir = TestDir::new("t23");
    std::fs::create_dir(dir.path()).expect("test directory");
    let path = dir.path().join("a").join("b");
    // Creating `a`, `b` and `channels`: a create and a parent sync each.
    let created = open_with(&path, Io::fast).expect("fast open");
    assert_eq!(created.io.skipped_syncs(), 3);
    drop(created);
    // The stores a fast directory hands out are fast too.
    let fast = open_with(&path, Io::fast).expect("fast open");
    assert!(fast.store_io().is_fast());
    assert!(!open(&dir.path().join("slow")).store_io().is_fast());
    drop(fast);
    // Each durable step syncs once: a commit its log, its copy and the
    // directory; a compaction its new log, its copy and the directory twice;
    // a destroy the directory of channels; a settings save its copy and
    // the directory.
    let mut fast = open_with(&path, Io::fast).expect("fast open");
    drop(fast.create(&id(1)).expect("create"));
    let mut store = fast.store_with(dir_name(1), Io::fast()).expect("store");
    commit(&mut store, 1, &[]).expect("first commit");
    let first = store.io().skipped_syncs();
    commit(&mut store, 1, &[1, 2]).expect("commit");
    assert_eq!((first, store.io().skipped_syncs() - first), (3, 3));
    let state = state_for(id(1));
    let before = store.io().skipped_syncs();
    assert_eq!(store.compact(&state, 2), Ok(1));
    assert_eq!(store.io().skipped_syncs() - before, 4);
    let before = store.io().skipped_syncs();
    store.destroy().expect("destroy");
    assert_eq!(store.io().skipped_syncs() - before, 1);
    drop(store);
    let before = fast.io.skipped_syncs();
    fast.save_settings(&privatechat_core::testing::settings(
        "wss://example.org",
        1,
        None,
    ))
    .expect("save");
    assert_eq!(fast.io.skipped_syncs() - before, 2);
    drop(fast);
    let other = TestDir::new("t23-other");
    let failing = open_with(other.path(), || Io::failing_at(1));
    assert!(matches!(failing, Err(StoreError::Io)));
    open_with(&path, Io::new).expect("another instance is healthy");
}

/// The child of `s020_t23_r23_crash_points`: passes `after_append` three
/// times. Returns at once in a normal run.
#[test]
fn s020_t23_r23_crash_point_helper() {
    if std::env::var(CRASH_VAR).is_err() {
        return;
    }
    for _ in 0..3 {
        crash_point("after_append");
    }
}

/// Spec 020, R23: `PRIVATECHAT_STORE_CRASH=<point>:<k>` stops the process
/// with status 86 the `k`-th time it passes `<point>`, and at no other point.
#[test]
fn s020_t23_r23_crash_points() {
    let helper = "tests::s020_t23_r23_crash_point_helper";
    assert_eq!(
        run_helper(helper, &[(CRASH_VAR, "after_append:2")]),
        Some(CRASH_STATUS)
    );
    assert_eq!(
        run_helper(helper, &[(CRASH_VAR, "after_append:4")]),
        Some(0)
    );
    assert_eq!(
        run_helper(helper, &[(CRASH_VAR, "after_state_tmp:1")]),
        Some(0)
    );
}
