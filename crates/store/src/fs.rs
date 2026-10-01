//! Every system call of `store` (spec 020-store-files R23): directories, the
//! `LOCK` file, and, under `cfg(test)`, the fault injector, fast mode and the
//! crash points the recovery tests drive.
//!
//! Each call maps an OS error to `StoreError::Io` at once, so no path or OS
//! detail leaves this module (R26).

#![allow(
    clippy::disallowed_methods,
    reason = "the one audited place of store I/O"
)]

use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::Path;

use privatechat_core::StoreError;

/// The I/O of one `DataDir` or `ChannelFiles`. Under `cfg(test)` it carries
/// that instance's fault and fast mode, counted per instance so that tests in
/// parallel do not interfere.
#[derive(Debug, Default)]
pub(crate) struct Io {
    #[cfg(test)]
    test: test::Hooks,
}

impl Io {
    /// The I/O of a store or data directory outside tests.
    pub(crate) fn new() -> Io {
        Io::default()
    }

    /// Counts one system call, and fails it when it is the injected one.
    fn call(&self) -> Result<(), StoreError> {
        #[cfg(test)]
        self.test.call()?;
        Ok(())
    }

    /// Creates `path` and every missing parent, then `fsync`s the parent of
    /// each directory it created (R17).
    pub(crate) fn create_dirs(&self, path: &Path) -> Result<(), StoreError> {
        let missing: Vec<&Path> = path.ancestors().take_while(|dir| !dir.exists()).collect();
        for dir in missing.into_iter().rev() {
            self.call()?;
            match fs::create_dir(dir) {
                Ok(()) => {}
                // Created meanwhile by someone else: what was asked holds.
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(_) => return Err(StoreError::Io),
            }
            self.sync_dir(parent_of(dir))?;
        }
        Ok(())
    }

    /// `fsync`s a directory, so that the names created, renamed or deleted in
    /// it are durable. Skipped where a directory cannot be opened for it
    /// (R23).
    pub(crate) fn sync_dir(&self, dir: &Path) -> Result<(), StoreError> {
        if cfg!(windows) {
            return Ok(());
        }
        self.call()?;
        let handle = File::open(dir).map_err(|_| StoreError::Io)?;
        self.sync(&handle)
    }

    /// `fsync`s an open file or directory; under fast mode a counted no-op.
    fn sync(&self, file: &File) -> Result<(), StoreError> {
        #[cfg(test)]
        if self.test.skip_sync() {
            return Ok(());
        }
        self.call()?;
        match file.sync_all() {
            Ok(()) => Ok(()),
            // A file system that cannot sync a directory (R23).
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::Unsupported | io::ErrorKind::InvalidInput
                ) =>
            {
                Ok(())
            }
            Err(_) => Err(StoreError::Io),
        }
    }

    /// Opens or creates `path` and takes an exclusive lock on it, held until
    /// the returned file is dropped (R17).
    pub(crate) fn lock(&self, path: &Path) -> Result<LockFile, StoreError> {
        self.call()?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .map_err(|_| StoreError::Io)?;
        self.call()?;
        match file.try_lock() {
            Ok(()) => Ok(LockFile { _file: file }),
            Err(fs::TryLockError::WouldBlock) => Err(StoreError::Locked),
            Err(fs::TryLockError::Error(_)) => Err(StoreError::Io),
        }
    }
}

/// The open `LOCK` file of a data directory; the lock goes with it.
#[derive(Debug)]
pub(crate) struct LockFile {
    _file: File,
}

/// The directory that holds `path`; `.` for a bare name.
fn parent_of(path: &Path) -> &Path {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    }
}

#[cfg(test)]
pub(crate) mod test {
    //! The fault injector, fast mode and crash points (spec 020, "Crash
    //! points and faults"), compiled only under `cfg(test)`.

    use std::cell::Cell;
    use std::collections::HashMap;
    use std::sync::Mutex;

    use privatechat_core::StoreError;

    use super::Io;

    /// The environment variable of a crash test, `<point>:<k>`.
    pub(crate) const CRASH_VAR: &str = "PRIVATECHAT_STORE_CRASH";

    /// The exit status of a process stopped at a crash point.
    pub(crate) const CRASH_STATUS: i32 = 86;

    /// The test hooks of one `Io`.
    #[derive(Debug, Default)]
    pub(crate) struct Hooks {
        /// The 1-based index of the system call that fails, if any.
        fail_at: Option<u32>,
        /// System calls counted so far.
        calls: Cell<u32>,
        /// Fast mode: `sync_all` is skipped and counted.
        fast: bool,
        /// Syncs skipped by fast mode.
        skipped: Cell<u32>,
    }

    impl Hooks {
        pub(super) fn call(&self) -> Result<(), StoreError> {
            let call = self.calls.get().saturating_add(1);
            self.calls.set(call);
            if self.fail_at == Some(call) {
                return Err(StoreError::Io);
            }
            Ok(())
        }

        pub(super) fn skip_sync(&self) -> bool {
            if self.fast {
                self.skipped.set(self.skipped.get().saturating_add(1));
            }
            self.fast
        }
    }

    impl Io {
        /// An `Io` whose `k`-th system call fails with `Io`.
        pub(crate) fn failing_at(k: u32) -> Io {
            Io {
                test: Hooks {
                    fail_at: Some(k),
                    ..Hooks::default()
                },
            }
        }

        /// An `Io` whose `sync_all` is a counted no-op.
        pub(crate) fn fast() -> Io {
            Io {
                test: Hooks {
                    fast: true,
                    ..Hooks::default()
                },
            }
        }

        /// The system calls made so far.
        pub(crate) fn calls(&self) -> u32 {
            self.test.calls.get()
        }

        /// The syncs fast mode skipped.
        pub(crate) fn skipped_syncs(&self) -> u32 {
            self.test.skipped.get()
        }
    }

    /// How many times this process passed each crash point.
    static PASSES: Mutex<Option<HashMap<String, u32>>> = Mutex::new(None);

    /// Exits the process with status 86 the `k`-th time it passes `point`,
    /// when `PRIVATECHAT_STORE_CRASH` is `<point>:<k>`; otherwise returns.
    pub(crate) fn crash_point(point: &str) {
        let Ok(armed) = std::env::var(CRASH_VAR) else {
            return;
        };
        let Some((name, k)) = armed.split_once(':') else {
            return;
        };
        if name != point {
            return;
        }
        let Ok(k) = k.parse::<u32>() else {
            return;
        };
        let mut passes = PASSES
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let count = passes
            .get_or_insert_with(HashMap::new)
            .entry(point.to_owned())
            .or_insert(0);
        *count = count.saturating_add(1);
        if *count == k {
            std::process::exit(CRASH_STATUS);
        }
    }
}
