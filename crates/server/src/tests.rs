//! Unit tests of the server, with a `ManualClock` and temporary directories,
//! no socket.

#![allow(
    clippy::disallowed_methods,
    reason = "the tests make and remove their own directories"
)]

mod store;

use std::path::{Path, PathBuf};

/// A directory of its own for one test, `temp_dir()/privatechat-server-<pid>-<name>`,
/// removed when the test ends.
pub(crate) struct TestDir(PathBuf);

impl TestDir {
    pub(crate) fn new(name: &str) -> TestDir {
        let path =
            std::env::temp_dir().join(format!("privatechat-server-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        TestDir(path)
    }

    pub(crate) fn path(&self) -> &Path {
        &self.0
    }

    /// The database file inside the directory.
    pub(crate) fn db(&self) -> PathBuf {
        self.0.join("messages.db")
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
