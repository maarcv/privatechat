//! Local client storage (`docs/spec.md` §8, ADR 0020, 0021).
//!
//! Implements the `Store` trait of `privatechat_core` over two encrypted files
//! per channel with an atomic commit by `rename`. Lives outside `core` because
//! it does I/O. Every system call lives in `fs` (spec 020-store-files R23).

#![forbid(unsafe_code)]
// Tests may relax these four lints to build fixtures; production code never does (AGENTS 4).
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )
)]

mod fs;

#[cfg(test)]
mod tests;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use privatechat_core::{StorageKey, StoreError};

/// The data directory of one device (spec 020-store-files R17): the channel
/// directories under `channels/` and the `LOCK` file that keeps a second
/// process out.
#[derive(Debug)]
pub struct DataDir {
    #[allow(dead_code, reason = "the layout of slice (e2) reads it")]
    path: PathBuf,
    #[allow(dead_code, reason = "the channel stores of slice (e2) share it")]
    key: Arc<StorageKey>,
    /// Held until the `DataDir` and every store it handed out are dropped.
    #[allow(dead_code, reason = "held, never read: dropping it releases the lock")]
    lock: Arc<fs::LockFile>,
    #[allow(dead_code, reason = "the calls of slice (e2) go through it")]
    io: fs::Io,
}

/// The name of the lock file of a data directory (R17).
const LOCK_FILE: &str = "LOCK";

/// The directory of the channel directories (R18).
const CHANNELS_DIR: &str = "channels";

impl DataDir {
    /// Opens the data directory at `path`, creating it and `channels/` when
    /// absent, and takes its lock (R17).
    ///
    /// # Errors
    ///
    /// `Locked` when another holder has the lock, `Io` when a system call
    /// fails.
    pub fn open(path: &Path, key: StorageKey) -> Result<DataDir, StoreError> {
        DataDir::open_with(path, key, fs::Io::new())
    }

    fn open_with(path: &Path, key: StorageKey, io: fs::Io) -> Result<DataDir, StoreError> {
        io.create_dirs(&path.join(CHANNELS_DIR))?;
        let lock = io.lock(&path.join(LOCK_FILE))?;
        Ok(DataDir {
            path: path.to_path_buf(),
            key: Arc::new(key),
            lock: Arc::new(lock),
            io,
        })
    }
}
