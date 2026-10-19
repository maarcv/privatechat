//! Spec 035-server-ops R8 over the built binary: the exit code of each way
//! it can refuse to start.

#![allow(
    clippy::disallowed_methods,
    reason = "the test starts the binary and makes its own directories"
)]
// Tests may relax these four lints to build fixtures (AGENTS 4).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// How long the binary may take to give up on a bad start.
const EXIT_WITHIN: Duration = Duration::from_secs(30);

/// A directory of its own for one test, removed when it ends.
struct TestDir(PathBuf);

impl TestDir {
    fn new(name: &str) -> TestDir {
        let path = std::env::temp_dir().join(format!(
            "privatechat-server-process-{}-{name}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        TestDir(path)
    }

    fn db(&self) -> String {
        self.0.join("messages.db").to_str().unwrap().to_owned()
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The binary with `vars` as its whole environment.
fn start(vars: &[(&str, &str)]) -> Child {
    Command::new(env!("CARGO_BIN_EXE_privatechat-server"))
        .env_clear()
        .envs(vars.iter().copied())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

/// The exit code of `child` and what it wrote to standard error; killed and
/// failed past `EXIT_WITHIN`.
fn exit_code(mut child: Child) -> (i32, String) {
    let start = Instant::now();
    while child.try_wait().unwrap().is_none() {
        if start.elapsed() > EXIT_WITHIN {
            child.kill().unwrap();
        }
        assert!(start.elapsed() <= EXIT_WITHIN, "the binary did not exit");
        std::thread::sleep(Duration::from_millis(20));
    }
    let output = child.wait_with_output().unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    (output.status.code().unwrap(), stderr)
}

#[test]
fn s035_t08_r08_exit_codes_configuration_error() {
    let dir = TestDir::new("config");
    let db = dir.db();
    let child = start(&[
        ("PRIVATECHAT_URLS", "wss://127.0.0.1"),
        ("PRIVATECHAT_DB", &db),
        ("PRIVATECHAT_CHANNEL_MAX_BYTES", "100"),
    ]);
    let (code, stderr) = exit_code(child);
    assert_eq!(code, 2);
    assert!(
        stderr.contains("PRIVATECHAT_CHANNEL_MAX_BYTES"),
        "{stderr:?}"
    );
    assert!(!stderr.contains("100"), "{stderr:?}");
    // Refused before the database is opened.
    assert!(!dir.0.join("messages.db").exists());
    let (code, _) = exit_code(start(&[]));
    assert_eq!(code, 2);
}

#[test]
fn s035_t08_r08_exit_codes_database_refused() {
    let dir = TestDir::new("database");
    let db = dir.db();
    let connection = rusqlite::Connection::open(&db).unwrap();
    connection.pragma_update(None, "user_version", 2).unwrap();
    drop(connection);
    let child = start(&[
        ("PRIVATECHAT_URLS", "wss://127.0.0.1"),
        ("PRIVATECHAT_DB", &db),
        ("PRIVATECHAT_LISTEN", "127.0.0.1:0"),
    ]);
    assert_eq!(exit_code(child).0, 3);
}

#[test]
fn s035_t08_r08_exit_codes_port_in_use() {
    let dir = TestDir::new("bind");
    let db = dir.db();
    let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = taken.local_addr().unwrap().to_string();
    let child = start(&[
        ("PRIVATECHAT_URLS", "wss://127.0.0.1"),
        ("PRIVATECHAT_DB", &db),
        ("PRIVATECHAT_LISTEN", &address),
    ]);
    assert_eq!(exit_code(child).0, 1);
}
