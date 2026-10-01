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

mod channel;
mod frame;
mod fs;

#[cfg(test)]
mod tests;

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use privatechat_core::{DirName, Settings, StorageKey, Store, StoreError, Vault};

use crate::channel::ChannelFiles;

/// The name of the lock file of a data directory (R17).
const LOCK_FILE: &str = "LOCK";

/// The directory of the channel directories (R18).
const CHANNELS_DIR: &str = "channels";

/// The settings file (R22) and its temporary copy.
const SETTINGS_FILE: &str = "settings.bin";
const SETTINGS_TMP: &str = "settings.bin.tmp";

/// The suffix of a channel directory being deleted (R21).
const LEAVING: &str = ".leaving";

/// What a `DataDir` shares with every store it hands out (R20, R28): the key,
/// the lock, held until the last of them is dropped, and the names of the
/// stores alive.
#[derive(Debug)]
pub(crate) struct Shared {
    channels: PathBuf,
    key: StorageKey,
    /// Held, never read: dropping the last `Arc` releases the lock (R17).
    _lock: fs::LockFile,
    live: Mutex<HashSet<DirName>>,
}

impl Shared {
    /// The directory of the channel `name`.
    pub(crate) fn dir(&self, name: &DirName) -> PathBuf {
        self.channels.join(hex(name))
    }

    /// The directory a `destroy` moves `name` to (R21).
    fn leaving(&self, name: &DirName) -> PathBuf {
        self.channels.join(format!("{}{LEAVING}", hex(name)))
    }

    pub(crate) fn channels(&self) -> &Path {
        &self.channels
    }

    pub(crate) fn key(&self) -> &StorageKey {
        &self.key
    }

    /// Marks `name` alive, or `Locked` when a store of it is (R20).
    fn claim(&self, name: &DirName) -> Result<(), StoreError> {
        let mut live = self.live.lock().unwrap_or_else(PoisonError::into_inner);
        if live.insert(*name) {
            Ok(())
        } else {
            Err(StoreError::Locked)
        }
    }

    /// Marks `name` no longer alive, when its store is dropped (R20).
    pub(crate) fn release(&self, name: &DirName) {
        self.live
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(name);
    }

    fn is_live(&self, name: &DirName) -> bool {
        self.live
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains(name)
    }

    /// Deletes the directory of `name` by R21: a leftover `.leaving` first,
    /// then the rename, which decides; after it, nothing fails the call.
    pub(crate) fn destroy_dir(&self, io: &fs::Io, name: &DirName) -> Result<(), StoreError> {
        let leaving = self.leaving(name);
        io.remove_dir_all(&leaving)?;
        io.rename(&self.dir(name), &leaving)?;
        // Past the rename R19 finishes what fails here.
        let _ = io.sync_dir(&self.channels);
        let _ = io.remove_dir_all(&leaving);
        Ok(())
    }
}

/// The data directory of one device (spec 020-store-files R17): the channel
/// directories under `channels/`, `settings.bin`, and the `LOCK` file that
/// keeps a second process out.
#[derive(Debug)]
pub struct DataDir {
    path: PathBuf,
    shared: Arc<Shared>,
    io: fs::Io,
}

impl DataDir {
    /// Opens the data directory at `path`, creating it and `channels/` when
    /// absent, takes its lock (R17), and deletes what an interrupted delete
    /// or first commit left (R19).
    ///
    /// # Errors
    ///
    /// `Locked` when another holder has the lock, `Io` when a system call
    /// fails.
    pub fn open(path: &Path, key: StorageKey) -> Result<DataDir, StoreError> {
        DataDir::open_with(path, key, fs::Io::new())
    }

    fn open_with(path: &Path, key: StorageKey, io: fs::Io) -> Result<DataDir, StoreError> {
        let channels = path.join(CHANNELS_DIR);
        io.create_dirs(&channels)?;
        let lock = io.lock(&path.join(LOCK_FILE))?;
        let dir = DataDir {
            path: path.to_path_buf(),
            shared: Arc::new(Shared {
                channels,
                key,
                _lock: lock,
                live: Mutex::new(HashSet::new()),
            }),
            io,
        };
        dir.clean_leftovers();
        Ok(dir)
    }

    /// R19, best effort: every `.leaving` directory, and every channel
    /// directory whose first commit never became durable. A failure here
    /// never fails `open`.
    fn clean_leftovers(&self) {
        let Ok(entries) = self.io.list_dir(self.shared.channels()) else {
            return;
        };
        for (entry, is_dir) in entries {
            if !is_dir {
                continue;
            }
            let path = self.shared.channels().join(&entry);
            let leftover = entry.ends_with(LEAVING)
                || (parse_hex(&entry).is_some() && channel::is_unborn(&self.io, &path));
            if leftover {
                let _ = self.io.remove_dir_all(&path);
            }
        }
    }

    /// A store of the channel directory `name`, which the caller has checked
    /// is not alive.
    fn store(&self, name: DirName) -> Result<Box<dyn Store>, StoreError> {
        self.shared.claim(&name)?;
        Ok(Box::new(ChannelFiles::new(
            Arc::clone(&self.shared),
            name,
            fs::Io::new(),
        )))
    }
}

#[cfg(test)]
impl DataDir {
    /// A store of `name` whose system calls go through `io`, so that a test
    /// injects a fault into one commit or compaction.
    fn store_with(&self, name: DirName, io: fs::Io) -> Result<ChannelFiles, StoreError> {
        self.shared.claim(&name)?;
        Ok(ChannelFiles::new(Arc::clone(&self.shared), name, io))
    }
}

impl Vault for DataDir {
    fn list(&mut self) -> Result<Vec<Box<dyn Store>>, StoreError> {
        let names: Vec<DirName> = self
            .io
            .list_dir(self.shared.channels())?
            .into_iter()
            .filter(|(_, is_dir)| *is_dir)
            .filter_map(|(entry, _)| parse_hex(&entry))
            .collect();
        if names.iter().any(|name| self.shared.is_live(name)) {
            return Err(StoreError::Locked);
        }
        names.into_iter().map(|name| self.store(name)).collect()
    }

    fn create(&mut self, channel_id: &[u8; 16]) -> Result<Box<dyn Store>, StoreError> {
        let name = privatechat_core::dir_name(self.shared.key(), channel_id)?;
        if self.shared.is_live(&name) {
            return Err(StoreError::Locked);
        }
        self.io.create_dirs(&self.shared.dir(&name))?;
        self.store(name)
    }

    fn remove(&mut self, name: &DirName) -> Result<(), StoreError> {
        if self.shared.is_live(name) {
            return Err(StoreError::Locked);
        }
        self.shared.destroy_dir(&self.io, name)
    }

    fn dir_name(&self, channel_id: &[u8; 16]) -> Result<DirName, StoreError> {
        privatechat_core::dir_name(self.shared.key(), channel_id)
    }

    fn load_settings(&mut self) -> Result<Option<Settings>, StoreError> {
        let path = self.path.join(SETTINGS_FILE);
        match self
            .io
            .read_limited(&path, privatechat_core::MAX_SETTINGS_FILE)?
        {
            None => Ok(None),
            Some(bytes) => frame::open_settings(&bytes, self.shared.key()).map(Some),
        }
    }

    fn save_settings(&mut self, settings: &Settings) -> Result<(), StoreError> {
        let sealed = settings.seal(self.shared.key())?;
        let tmp = self.path.join(SETTINGS_TMP);
        // R10 step 2 with no log: the copy, its sync, the rename, the
        // directory's sync.
        let written = self
            .io
            .write_synced(&tmp, &frame::frame(frame::SETTINGS_MAGIC, &sealed))
            .and_then(|()| self.io.rename(&tmp, &self.path.join(SETTINGS_FILE)));
        if written.is_err() {
            let _ = self.io.remove_file(&tmp);
        }
        written?;
        self.io.sync_dir(&self.path)
    }
}

/// The 32 lowercase hex characters of a directory name (R18).
fn hex(name: &DirName) -> String {
    name.0.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The directory name of 32 lowercase hex characters, `None` for any other
/// name (R20).
fn parse_hex(entry: &str) -> Option<DirName> {
    let digits = entry.as_bytes();
    if digits.len() != 32 {
        return None;
    }
    let (pairs, _) = digits.as_chunks::<2>();
    let mut name = [0u8; 16];
    for (byte, [high, low]) in name.iter_mut().zip(pairs) {
        *byte = nibble(*high)?.checked_mul(16)?.checked_add(nibble(*low)?)?;
    }
    Some(DirName(name))
}

/// The value of one lowercase hex digit.
fn nibble(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => digit.checked_sub(b'0'),
        b'a'..=b'f' => digit.checked_sub(b'a')?.checked_add(10),
        _ => None,
    }
}
