//! `MemoryStore` and `MemoryVault`: the `Store` and `Vault` of spec 020 over
//! bytes in memory, sealed and opened by the same functions as the files,
//! under a fixed key.
//!
//! Each directory keeps the `nonce ‖ box` of its state and its log laid out
//! as R5 lays out `messages.log`: the 9-byte header, then `len` ‖ `nonce ‖
//! box` per entry, each entry bound to the offset of its `len`. The framing
//! is written out here again, since `core` leaves the files' own to `store`.
//! The doubles are handles over one shared vault, so a test keeps one after
//! giving a store or the vault away.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use crate::storage::{
    ChannelState, DirName, LogRecord, MAX_LOG_LEN, Settings, StorageKey, Store, StoreError, Vault,
    WriteBatch, dir_name,
};

/// The header of `messages.log` (R5): magic, version, generation.
const LOG_MAGIC: &[u8; 4] = b"PLOG";
const LOG_VERSION: u8 = 1;
const LOG_HEADER_LEN: usize = 9;

/// Bytes of an entry's `len`.
const ENTRY_LEN_LEN: usize = 4;

/// The fixed key every double seals under.
fn fixed_key() -> StorageKey {
    StorageKey::from_bytes(&mut [0x42; 32])
}

/// The log header of `generation`.
fn log_header(generation: u32) -> Vec<u8> {
    [&LOG_MAGIC[..], &[LOG_VERSION], &generation.to_be_bytes()].concat()
}

/// The generation of a log whose first 9 bytes are a valid header.
fn log_generation(log: &[u8]) -> Option<u32> {
    let (header, _) = log.split_first_chunk::<LOG_HEADER_LEN>()?;
    let [m0, m1, m2, m3, version, g @ ..] = *header;
    ([m0, m1, m2, m3] == *LOG_MAGIC && version == LOG_VERSION).then(|| u32::from_be_bytes(g))
}

/// Whether a directory with no state holds nothing a commit made durable:
/// its log is absent, short, or a bare header of generation 0 (R13, R19).
fn is_unborn(files: &Files) -> bool {
    files.state.is_none()
        && files.log.as_deref().is_none_or(|log| {
            log_generation(log).is_none_or(|generation| generation == 0)
                && log.len() <= LOG_HEADER_LEN
        })
}

/// The bytes of one channel directory.
#[derive(Default)]
struct Files {
    /// The `nonce ‖ box` of `state.bin`.
    state: Option<Vec<u8>>,
    /// `messages.log`, as R5 lays it out.
    log: Option<Vec<u8>>,
    /// Commits that appended a record or changed the state beyond `cursor`
    /// and `synced_at` (AGENTS 23).
    commits: u32,
    /// Every successful commit (spec 021-channel-session R20).
    all_commits: u32,
}

/// What every handle shares.
#[derive(Default)]
struct Shared {
    dirs: BTreeMap<DirName, Files>,
    /// The `nonce ‖ box` of `settings.bin`.
    settings: Option<Vec<u8>>,
}

/// The vault in memory; `Clone` hands out another handle to the same bytes.
#[derive(Clone, Default)]
pub struct MemoryVault {
    shared: Arc<Mutex<Shared>>,
}

/// One channel's store in memory; `Clone` hands out another handle to it.
#[derive(Clone)]
pub struct MemoryStore {
    shared: Arc<Mutex<Shared>>,
    name: DirName,
}

/// The shared bytes; a test that panicked while holding them leaves them as
/// they were.
fn lock(shared: &Mutex<Shared>) -> MutexGuard<'_, Shared> {
    shared.lock().unwrap_or_else(PoisonError::into_inner)
}

impl MemoryVault {
    /// An empty vault.
    pub fn new() -> MemoryVault {
        MemoryVault::default()
    }

    /// Plants arbitrary bytes as the state and the log of directory `name`,
    /// `None` for a file that is absent.
    pub fn put_raw(&self, name: &DirName, state: Option<&[u8]>, log: Option<&[u8]>) {
        let mut shared = lock(&self.shared);
        let files = shared.dirs.entry(*name).or_default();
        files.state = state.map(<[u8]>::to_vec);
        files.log = log.map(<[u8]>::to_vec);
    }

    /// Plants arbitrary bytes as the `nonce ‖ box` of the settings.
    pub fn put_settings_raw(&self, bytes: &[u8]) {
        lock(&self.shared).settings = Some(bytes.to_vec());
    }

    /// The store of `name` over these bytes.
    fn store(&self, name: DirName) -> MemoryStore {
        MemoryStore {
            shared: Arc::clone(&self.shared),
            name,
        }
    }
}

impl Vault for MemoryVault {
    fn list(&mut self) -> Result<Vec<Box<dyn Store>>, StoreError> {
        let names: Vec<DirName> = lock(&self.shared)
            .dirs
            .iter()
            .filter(|(_, files)| !is_unborn(files))
            .map(|(name, _)| *name)
            .collect();
        Ok(names
            .into_iter()
            .map(|name| Box::new(self.store(name)) as Box<dyn Store>)
            .collect())
    }

    fn create(&mut self, channel_id: &[u8; 16]) -> Result<Box<dyn Store>, StoreError> {
        let name = self.dir_name(channel_id)?;
        lock(&self.shared).dirs.entry(name).or_default();
        Ok(Box::new(self.store(name)))
    }

    fn remove(&mut self, name: &DirName) -> Result<(), StoreError> {
        lock(&self.shared).dirs.remove(name);
        Ok(())
    }

    fn dir_name(&self, channel_id: &[u8; 16]) -> Result<DirName, StoreError> {
        dir_name(&fixed_key(), channel_id)
    }

    fn load_settings(&mut self) -> Result<Option<Settings>, StoreError> {
        let sealed = lock(&self.shared).settings.clone();
        sealed
            .map(|sealed| Settings::open(&fixed_key(), &sealed))
            .transpose()
    }

    fn save_settings(&mut self, settings: &Settings) -> Result<(), StoreError> {
        let sealed = settings.seal(&fixed_key())?;
        lock(&self.shared).settings = Some(sealed);
        Ok(())
    }
}

impl MemoryStore {
    /// A handle to the store of directory `name` of `vault`, for a test that
    /// gave the store itself away.
    pub fn handle(vault: &MemoryVault, name: DirName) -> MemoryStore {
        vault.store(name)
    }

    /// A fresh store over the same bytes, as a reopened directory.
    pub fn reopen(&self) -> MemoryStore {
        self.clone()
    }

    /// The commits of AGENTS 23: those that appended a record or changed the
    /// state beyond `cursor` and `synced_at`.
    pub fn commits(&self) -> u32 {
        self.with_files(|files| files.commits)
    }

    /// Every successful commit.
    pub fn all_commits(&self) -> u32 {
        self.with_files(|files| files.all_commits)
    }

    /// `f` over this directory's files, a directory never created reading as
    /// empty.
    fn with_files<T>(&self, f: impl FnOnce(&Files) -> T) -> T {
        let shared = lock(&self.shared);
        match shared.dirs.get(&self.name) {
            Some(files) => f(files),
            None => f(&Files::default()),
        }
    }

    /// The state and the log as the last commit left them, `None` for a
    /// directory never committed (R12–R14, without the recovery a crash
    /// needs: memory has none).
    fn open(&self) -> Result<Option<(ChannelState, Vec<LogRecord>)>, StoreError> {
        let (state, log) = self.with_files(|files| (files.state.clone(), files.log.clone()));
        let Some(state) = state else {
            let files = Files {
                state: None,
                log,
                ..Files::default()
            };
            return if is_unborn(&files) {
                Ok(None)
            } else {
                Err(StoreError::Corrupt)
            };
        };
        let key = fixed_key();
        let state = ChannelState::open(&key, &self.name, &state)?;
        if dir_name(&key, &state.channel_id())? != self.name {
            return Err(StoreError::Corrupt);
        }
        let (committed_len, generation) = state.log_position();
        let log = log.ok_or(StoreError::Corrupt)?;
        if log_generation(&log) != Some(generation) {
            return Err(StoreError::Corrupt);
        }
        let committed_len = usize::try_from(committed_len).map_err(|_| StoreError::Corrupt)?;
        let committed = log.get(..committed_len).ok_or(StoreError::Corrupt)?;
        let records = entries(committed)?
            .into_iter()
            .map(|(offset, entry)| LogRecord::open(&key, &self.name, entry, generation, offset))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Some((state, records)))
    }

    /// Replaces this directory's files, and counts the commit.
    fn write(&self, state: Vec<u8>, log: Vec<u8>, counted: bool) {
        let mut shared = lock(&self.shared);
        let files = shared.dirs.entry(self.name).or_default();
        files.state = Some(state);
        files.log = Some(log);
        files.all_commits = files.all_commits.saturating_add(1);
        if counted {
            files.commits = files.commits.saturating_add(1);
        }
    }
}

/// Each entry of a log after its header, with the offset of its `len`.
fn entries(log: &[u8]) -> Result<Vec<(u64, &[u8])>, StoreError> {
    let mut rest = log.get(LOG_HEADER_LEN..).ok_or(StoreError::Corrupt)?;
    let mut offset = LOG_HEADER_LEN;
    let mut found = Vec::new();
    while let Some((len, after)) = rest.split_first_chunk::<ENTRY_LEN_LEN>() {
        let len = usize::try_from(u32::from_be_bytes(*len)).map_err(|_| StoreError::Corrupt)?;
        let (entry, after) = after.split_at_checked(len).ok_or(StoreError::Corrupt)?;
        found.push((
            u64::try_from(offset).map_err(|_| StoreError::Corrupt)?,
            entry,
        ));
        offset = offset
            .checked_add(ENTRY_LEN_LEN)
            .and_then(|at| at.checked_add(len))
            .ok_or(StoreError::Corrupt)?;
        rest = after;
    }
    if !rest.is_empty() {
        return Err(StoreError::Corrupt);
    }
    Ok(found)
}

/// Appends `records` to `log`, each sealed for the offset of its `len`.
fn append(
    log: &mut Vec<u8>,
    name: &DirName,
    records: &[LogRecord],
    generation: u32,
) -> Result<(), StoreError> {
    let key = fixed_key();
    for record in records {
        let offset = u64::try_from(log.len()).map_err(|_| StoreError::LogFull)?;
        let sealed = record.seal(&key, name, generation, offset)?;
        let len = u32::try_from(sealed.len()).map_err(|_| StoreError::Corrupt)?;
        log.extend_from_slice(&len.to_be_bytes());
        log.extend_from_slice(&sealed);
    }
    Ok(())
}

/// The length of a log in `u64`.
fn len_of(log: &[u8]) -> Result<u64, StoreError> {
    u64::try_from(log.len()).map_err(|_| StoreError::LogFull)
}

/// Whether the commit of `new` over `old` counts under AGENTS 23: records
/// appended, or a change beyond `cursor` and `synced_at`.
fn counts(
    old: Option<&ChannelState>,
    new: &ChannelState,
    appended: bool,
) -> Result<bool, StoreError> {
    let Some(old) = old else {
        return Ok(true);
    };
    let mut same_clock = new.duplicate()?;
    same_clock.cursor = old.cursor;
    same_clock.synced_at = old.synced_at;
    Ok(appended || !super::state_eq(old, &same_clock))
}

impl Store for MemoryStore {
    fn name(&self) -> &DirName {
        &self.name
    }

    fn load(&mut self) -> Result<Option<(ChannelState, Vec<LogRecord>)>, StoreError> {
        self.open()
    }

    fn commit(&mut self, batch: &WriteBatch) -> Result<(), StoreError> {
        let previous = self.open()?;
        let (mut log, generation) = match &previous {
            Some((state, _)) => {
                let (len, generation) = state.log_position();
                let len = usize::try_from(len).map_err(|_| StoreError::Corrupt)?;
                let log = self
                    .with_files(|files| files.log.clone())
                    .unwrap_or_default();
                (
                    log.get(..len).ok_or(StoreError::Corrupt)?.to_vec(),
                    generation,
                )
            }
            None => (log_header(0), 0),
        };
        append(&mut log, &self.name, batch.records(), generation)?;
        if len_of(&log)? > MAX_LOG_LEN {
            return Err(StoreError::LogFull);
        }
        let state = batch
            .state()
            .seal(&fixed_key(), &self.name, len_of(&log)?, generation)?;
        let old = previous.as_ref().map(|(state, _)| state);
        let counted = counts(old, batch.state(), !batch.records().is_empty())?;
        self.write(state, log, counted);
        Ok(())
    }

    fn compact(&mut self, state: &ChannelState, now: u64) -> Result<u32, StoreError> {
        let Some((_, records)) = self.open()? else {
            return Ok(0);
        };
        let (kept, dropped): (Vec<LogRecord>, Vec<LogRecord>) = records
            .into_iter()
            .partition(|record| record.purge_at() >= now);
        if dropped.is_empty() {
            return Ok(0);
        }
        let (_, generation) = state.log_position();
        let generation = generation.checked_add(1).ok_or(StoreError::Corrupt)?;
        let mut log = log_header(generation);
        append(&mut log, &self.name, &kept, generation)?;
        let sealed = state.seal(&fixed_key(), &self.name, len_of(&log)?, generation)?;
        let mut shared = lock(&self.shared);
        let files = shared.dirs.entry(self.name).or_default();
        files.state = Some(sealed);
        files.log = Some(log);
        u32::try_from(dropped.len()).map_err(|_| StoreError::Corrupt)
    }

    fn log_len(&self) -> u64 {
        let state = self.with_files(|files| files.state.clone());
        state
            .and_then(|state| ChannelState::open(&fixed_key(), &self.name, &state).ok())
            .map_or(0, |state| state.log_position().0)
    }

    fn destroy(&mut self) -> Result<(), StoreError> {
        lock(&self.shared).dirs.remove(&self.name);
        Ok(())
    }
}
