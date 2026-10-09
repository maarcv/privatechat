//! The log headroom of spec 021 R18: room for a maximal entry and a
//! reserve before `encrypt` and `decrypt` append anything, and the one
//! compaction that may restore it, at most every ten minutes.

use super::Channel;
use crate::error::Error;
use crate::session::expiry::ExpiryIndex;
use crate::storage::{LogEntry, MAX_LOG_LEN, StoreError};

/// A maximal log entry with its 4-byte `len` (65 580 bytes) and the
/// reserve of 1 048 576 for the commits that add no message (R18).
pub(super) const HEADROOM: u64 = 1_114_156;

/// The reserve alone, the least a compaction must free.
pub(super) const RESERVE: u64 = 1_048_576;

/// The least time between two compactions of one channel.
const COMPACTION_INTERVAL_MS: u64 = 600_000;

impl Channel {
    /// Compacts the log when what expired before `now` restores the
    /// headroom and the last attempt is ten minutes old (R18): `Ok(true)`
    /// when it compacted, `Ok(false)` when it did not try.
    ///
    /// # Errors
    ///
    /// The compaction's `Store` error, memory left as it was.
    pub(crate) fn relieve_headroom(&mut self, now: u64) -> Result<bool, Error> {
        self.latest_now = Some(now);
        let held_off = self.compaction_held_off(now);
        let excess = self
            .store
            .log_len()
            .saturating_add(HEADROOM)
            .saturating_sub(MAX_LOG_LEN);
        if held_off || self.expiry.expired_bytes(now) < RESERVE.max(excess) {
            return Ok(false);
        }
        self.compact_at(now)?;
        Ok(true)
    }

    /// Whether the last compaction attempt is less than ten minutes before
    /// `now` (R18, spec 023-ttl-purge R5). One recorded later than `now`, by
    /// a clock since set back, holds nothing off, so that the clock does
    /// not hold compactions off until it catches up.
    pub(super) fn compaction_held_off(&self, now: u64) -> bool {
        self.last_compaction
            .is_some_and(|last| last <= now && now.saturating_sub(last) < COMPACTION_INTERVAL_MS)
    }

    /// One compaction attempt at `now`, recorded whether it succeeds or
    /// fails (R18, spec 023-ttl-purge R5), and the records whose `purge_at`
    /// is below `now` dropped from memory after it succeeds: returns the
    /// number of message records dropped.
    ///
    /// # Errors
    ///
    /// The compaction's `Store` error, memory left as it was.
    pub(super) fn compact_at(&mut self, now: u64) -> Result<usize, Error> {
        self.last_compaction = Some(now);
        self.store.compact(&self.state, now)?;
        let messages = self
            .records
            .iter()
            .filter(|record| {
                record.purge_at() < now && matches!(record.entry, LogEntry::Message(_))
            })
            .count();
        self.records.retain(|record| record.purge_at() >= now);
        self.expiry = ExpiryIndex::of(&self.records);
        Ok(messages)
    }

    /// Whether the log has room for a maximal entry and the reserve.
    pub(super) fn has_headroom(&self) -> bool {
        self.store.log_len().saturating_add(HEADROOM) <= MAX_LOG_LEN
    }

    /// The check `encrypt` and `decrypt` make first (R18).
    ///
    /// # Errors
    ///
    /// The compaction's `Store` error when it failed, and otherwise
    /// `Store(LogFull)` while the headroom is missing.
    pub(super) fn check_headroom(&mut self, now: u64) -> Result<(), Error> {
        if !self.has_headroom() {
            self.relieve_headroom(now)?;
        }
        if self.has_headroom() {
            Ok(())
        } else {
            Err(Error::Store(StoreError::LogFull))
        }
    }
}

#[cfg(test)]
impl Channel {
    /// Commits records of `purge_at` until the log is exactly `target`
    /// bytes, for the tests of a full log.
    pub(crate) fn fill_log(&mut self, purge_at: u64, target: u64) {
        // The largest body a log record holds (spec 020-store-files Limits).
        const MAX_BODY: u64 = 64_511;
        let base = crate::testing::record(0, 0).entry_len();
        let mut remaining = target - self.store.log_len();
        let mut records = Vec::new();
        while remaining > 0 {
            let mut len = remaining.min(base + MAX_BODY);
            if remaining > len && remaining - len < base {
                len -= base;
            }
            records.push(crate::testing::record(
                purge_at,
                usize::try_from(len - base).unwrap(),
            ));
            remaining -= len;
        }
        self.commit(self.next_state(), records).unwrap();
    }
}
