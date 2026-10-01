//! Tests of spec 020-store-files over the files: the data directory, its lock
//! and the I/O module. The crash points and faults they drive exist only under
//! `cfg(test)`, which is why these tests live here and not under `tests/`.

#![allow(
    clippy::disallowed_methods,
    reason = "the one audited place of store I/O"
)]

use std::path::{Path, PathBuf};
use std::process::Command;

use privatechat_core::{StorageKey, StoreError};

use crate::DataDir;
use crate::fs::Io;
use crate::fs::test::{CRASH_STATUS, CRASH_VAR, crash_point};

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
    let first = DataDir::open(&path, key()).expect("first open");
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
    drop(first);
    let again = DataDir::open(&path, key()).expect("open after drop");
    drop(again);
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
    drop(DataDir::open(dir.path(), key()).expect("create"));
    drop(DataDir::open(dir.path(), key()).expect("reopen"));
    // Every system call of an `open` that creates nothing: the lock file
    // and its lock; each failure is `Io`.
    let calls = {
        let io = Io::new();
        let probe = DataDir::open_with(dir.path(), key(), io).expect("probe");
        probe.io.calls()
    };
    assert_eq!(calls, 2);
    for k in 1..=calls {
        assert!(
            matches!(
                DataDir::open_with(dir.path(), key(), Io::failing_at(k)),
                Err(StoreError::Io)
            ),
            "k={k}"
        );
    }
    DataDir::open(dir.path(), key()).expect("no lock left behind");
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
    let created = DataDir::open_with(&path, key(), Io::fast()).expect("fast open");
    assert_eq!(created.io.skipped_syncs(), 3);
    drop(created);
    let other = TestDir::new("t23-other");
    let failing = DataDir::open_with(other.path(), key(), Io::failing_at(1));
    assert!(matches!(failing, Err(StoreError::Io)));
    DataDir::open_with(&path, key(), Io::new()).expect("another instance is healthy");
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
