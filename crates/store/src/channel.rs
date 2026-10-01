//! The files of one channel (spec 020-store-files R10–R16, R21):
//! `state.bin`, `messages.log` and their temporary copies, in the directory
//! of R18.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use privatechat_core::{
    ChannelState, DirName, LogRecord, MAX_LOG_LEN, MAX_STATE_FILE, Store, StoreError, WriteBatch,
};

use crate::Shared;
use crate::frame;
use crate::fs::Io;

/// The files of a channel directory.
pub(crate) const STATE_FILE: &str = "state.bin";
pub(crate) const LOG_FILE: &str = "messages.log";
const STATE_TMP: &str = "state.bin.tmp";
const LOG_NEW: &str = "messages.log.new";

/// Whether the channel directory at `dir` holds no `state.bin` and a log
/// that shows a first commit cut before its header was durable (R13, R19).
/// A read that fails counts as not unborn, so nothing is deleted on doubt.
pub(crate) fn is_unborn(io: &Io, dir: &Path) -> bool {
    let Ok(state) = io.read_limited(&dir.join(STATE_FILE), 0) else {
        return false;
    };
    if state.is_some() {
        return false;
    }
    match io.read_limited(&dir.join(LOG_FILE), frame::LOG_HEADER_LEN) {
        Ok(log) => frame::is_unborn_log(log.as_deref()),
        Err(_) => false,
    }
}

/// The store of one channel directory, handed out as `Box<dyn Store>` by a
/// `DataDir` (R20).
#[derive(Debug)]
pub(crate) struct ChannelFiles {
    shared: Arc<Shared>,
    name: DirName,
    io: Io,
    /// Set by a failure at or after a rename; every later call is `Io` (R11).
    poisoned: bool,
    /// The committed length and generation of the last load or write
    /// (R15, R16); `None` before the first.
    position: Option<(u64, u32)>,
}

impl ChannelFiles {
    /// The store of `name`, which the caller has claimed as alive.
    pub(crate) fn new(shared: Arc<Shared>, name: DirName, io: Io) -> ChannelFiles {
        ChannelFiles {
            shared,
            name,
            io,
            poisoned: false,
            position: None,
        }
    }

    fn path(&self, file: &str) -> PathBuf {
        self.shared.dir(&self.name).join(file)
    }

    /// The committed state and log, checked by R12 and R13: `None` for a
    /// channel whose first commit never became durable.
    fn read_committed(&self) -> Result<Option<(ChannelState, Vec<u8>)>, StoreError> {
        let Some(bytes) = self
            .io
            .read_limited(&self.path(STATE_FILE), MAX_STATE_FILE)?
        else {
            let log = self
                .io
                .read_limited(&self.path(LOG_FILE), frame::LOG_HEADER_LEN)?;
            return if frame::is_unborn_log(log.as_deref()) {
                Ok(None)
            } else {
                Err(StoreError::Corrupt)
            };
        };
        let key = self.shared.key();
        let state = frame::open_state(&bytes, key, &self.name)?;
        if privatechat_core::dir_name(key, &state.channel_id())? != self.name {
            return Err(StoreError::Corrupt);
        }
        let (committed_len, generation) = state.log_position();
        let mut log = self.read_log(LOG_FILE)?.ok_or(StoreError::Corrupt)?;
        let found = frame::read_log_header(&log)?;
        if found != generation {
            log = self.finish_compaction(found, generation)?;
        }
        // Best effort: what R14 did not rename is a compaction that never
        // reached its state, and the next one overwrites it.
        let _ = self.io.remove_file(&self.path(LOG_NEW));
        let committed = usize::try_from(committed_len).map_err(|_| StoreError::Corrupt)?;
        if log.len() < committed {
            return Err(StoreError::Corrupt);
        }
        // A commit never writes past the limit (R16): a longer log was
        // written by someone else (R7).
        if u64::try_from(log.len()).map_or(true, |len| len > MAX_LOG_LEN) {
            return Err(StoreError::Corrupt);
        }
        if log.len() > committed {
            // What a commit cut short appended after the committed end.
            self.io.truncate(&self.path(LOG_FILE), committed_len)?;
            log.truncate(committed);
        }
        Ok(Some((state, log)))
    }

    /// A log file of this directory, read up to its limit.
    fn read_log(&self, file: &str) -> Result<Option<Vec<u8>>, StoreError> {
        let limit = usize::try_from(MAX_LOG_LEN).map_err(|_| StoreError::Corrupt)?;
        self.io.read_limited(&self.path(file), limit)
    }

    /// R14: a `state.bin` of generation `g + 1` over a log of `g` is a
    /// compaction cut after its state, which the rename of its
    /// `messages.log.new` completes; any other mismatch is `Corrupt`.
    fn finish_compaction(&self, found: u32, expected: u32) -> Result<Vec<u8>, StoreError> {
        if found.checked_add(1) != Some(expected) {
            return Err(StoreError::Corrupt);
        }
        let new = self.read_log(LOG_NEW)?.ok_or(StoreError::Corrupt)?;
        if frame::read_log_header(&new)? != expected {
            return Err(StoreError::Corrupt);
        }
        self.io.rename(&self.path(LOG_NEW), &self.path(LOG_FILE))?;
        self.io.sync_dir(&self.shared.dir(&self.name))?;
        Ok(new)
    }

    /// Where the next commit appends: the position of the last load or
    /// write, or of the files when this store has done neither; `None` for a
    /// first commit (R13).
    fn committed_position(&self) -> Result<Option<(u64, u32)>, StoreError> {
        if self.position.is_some() {
            return Ok(self.position);
        }
        Ok(self
            .read_committed()?
            .map(|(state, _)| state.log_position()))
    }

    /// R10 step 2: `state.bin.tmp`, its sync, the rename and the directory's
    /// sync. A failure before the rename deletes the copy; at or after it,
    /// poisons the store (R11).
    fn write_state(&mut self, sealed: &[u8]) -> Result<(), StoreError> {
        let tmp = self.path(STATE_TMP);
        let framed = frame::frame(frame::STATE_MAGIC, sealed);
        if let Err(error) = self.io.write_synced(&tmp, &framed) {
            let _ = self.io.remove_file(&tmp);
            return Err(error);
        }
        #[cfg(test)]
        crate::fs::test::crash_point("after_state_tmp");
        let renamed = self
            .io
            .rename(&tmp, &self.path(STATE_FILE))
            .and_then(|()| self.io.sync_dir(&self.shared.dir(&self.name)));
        if renamed.is_err() {
            self.poisoned = true;
        }
        renamed
    }

    /// The I/O of this store, whose calls a test counts.
    #[cfg(test)]
    pub(crate) fn io(&self) -> &Io {
        &self.io
    }

    fn check_usable(&self) -> Result<(), StoreError> {
        if self.poisoned {
            Err(StoreError::Io)
        } else {
            Ok(())
        }
    }
}

impl Store for ChannelFiles {
    fn name(&self) -> &DirName {
        &self.name
    }

    fn load(&mut self) -> Result<Option<(ChannelState, Vec<LogRecord>)>, StoreError> {
        self.check_usable()?;
        // Best effort: the next commit replaces it (R12).
        let _ = self.io.remove_file(&self.path(STATE_TMP));
        let Some((state, log)) = self.read_committed()? else {
            self.position = None;
            return Ok(None);
        };
        let (committed_len, generation) = state.log_position();
        let records = frame::open_entries(&log, self.shared.key(), &self.name, generation)?;
        self.position = Some((committed_len, generation));
        Ok(Some((state, records)))
    }

    fn commit(&mut self, batch: &WriteBatch) -> Result<(), StoreError> {
        self.check_usable()?;
        let key = self.shared.key();
        let header_len = u64::try_from(frame::LOG_HEADER_LEN).map_err(|_| StoreError::Io)?;
        let position = self.committed_position()?;
        if position.is_none() && !batch.records().is_empty() {
            // A first commit is a header and a state, never an entry: a crash
            // between them would leave a log of entries with no state, which
            // R19 keeps and `load` reports as `Corrupt` (R13).
            return Err(StoreError::Corrupt);
        }
        let (base, generation) = position.unwrap_or((header_len, 0));
        let appended = frame::seal_entries(batch.records(), key, &self.name, generation, base)?;
        let end = u64::try_from(appended.len())
            .ok()
            .and_then(|len| base.checked_add(len))
            .ok_or(StoreError::LogFull)?;
        if end > MAX_LOG_LEN {
            return Err(StoreError::LogFull);
        }
        // Sealed before anything is written: a state `seal` refuses writes
        // nothing (R27).
        let sealed = batch.state().seal(key, &self.name, end, generation)?;
        let log = self.path(LOG_FILE);
        if position.is_none() {
            // The first commit: a header of generation 0 alone, durable
            // before the state names it (R13).
            self.io.write_synced(&log, &frame::log_header(0))?;
        }
        if !appended.is_empty() {
            self.io.write_at(&log, base, &appended)?;
            #[cfg(test)]
            crate::fs::test::crash_point("after_append");
        }
        self.write_state(&sealed)?;
        self.position = Some((end, generation));
        Ok(())
    }

    fn compact(&mut self, state: &ChannelState, now: u64) -> Result<u32, StoreError> {
        self.check_usable()?;
        let Some((stored, log)) = self.read_committed()? else {
            return Ok(0);
        };
        // The store's own generation, never the one `state` carries: a state
        // kept in memory does not follow the compactions (R15).
        let (_, generation) = stored.log_position();
        let key = self.shared.key();
        let records = frame::open_entries(&log, key, &self.name, generation)?;
        let before = records.len();
        let kept: Vec<LogRecord> = records
            .into_iter()
            .filter(|record| record.purge_at() >= now)
            .collect();
        // Counted before anything is written, so that nothing fails after
        // the renames.
        let dropped =
            u32::try_from(before.saturating_sub(kept.len())).map_err(|_| StoreError::Corrupt)?;
        if dropped == 0 {
            return Ok(0);
        }
        let next = generation.checked_add(1).ok_or(StoreError::Corrupt)?;
        let header = frame::log_header(next);
        let start = u64::try_from(header.len()).map_err(|_| StoreError::Io)?;
        let entries = frame::seal_entries(&kept, key, &self.name, next, start)?;
        let new_log = [&header[..], &entries[..]].concat();
        let end = u64::try_from(new_log.len()).map_err(|_| StoreError::LogFull)?;
        let sealed = state.seal(key, &self.name, end, next)?;
        let new = self.path(LOG_NEW);
        if let Err(error) = self.io.write_synced(&new, &new_log) {
            let _ = self.io.remove_file(&new);
            return Err(error);
        }
        if let Err(error) = self.write_state(&sealed) {
            // Before the rename of the state the new log is useless; after
            // it, the next load renames it (R11, R14).
            if !self.poisoned {
                let _ = self.io.remove_file(&new);
            }
            return Err(error);
        }
        #[cfg(test)]
        crate::fs::test::crash_point("after_compact_state");
        let renamed = self
            .io
            .rename(&new, &self.path(LOG_FILE))
            .and_then(|()| self.io.sync_dir(&self.shared.dir(&self.name)));
        if renamed.is_err() {
            self.poisoned = true;
        }
        renamed?;
        self.position = Some((end, next));
        Ok(dropped)
    }

    fn log_len(&self) -> u64 {
        self.position.map_or(0, |(len, _)| len)
    }

    fn destroy(&mut self) -> Result<(), StoreError> {
        self.check_usable()?;
        self.shared.destroy_dir(&self.io, &self.name)?;
        self.position = None;
        Ok(())
    }
}

impl Drop for ChannelFiles {
    fn drop(&mut self) {
        self.shared.release(&self.name);
    }
}
