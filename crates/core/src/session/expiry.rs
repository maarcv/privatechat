//! The expiry index of spec 021-channel-session R1: the `purge_at` and
//! the entry length of every log record of a channel, ordered by
//! `purge_at`, from which the headroom of R18 knows what a compaction would
//! free without reading a record.

use crate::storage::LogRecord;

/// `(purge_at, entry length)` per record, by `purge_at`.
#[derive(Default)]
pub(crate) struct ExpiryIndex {
    entries: Vec<(u64, u64)>,
}

impl ExpiryIndex {
    /// The index of `records`, built at load.
    pub(crate) fn of(records: &[LogRecord]) -> ExpiryIndex {
        let mut entries: Vec<(u64, u64)> = records
            .iter()
            .map(|record| (record.purge_at(), record.entry_len()))
            .collect();
        entries.sort_by_key(|(purge_at, _)| *purge_at);
        ExpiryIndex { entries }
    }

    /// Adds the records of a commit, a few at a time.
    pub(crate) fn extend(&mut self, records: &[LogRecord]) {
        for record in records {
            let purge_at = record.purge_at();
            let at = self
                .entries
                .partition_point(|(other, _)| *other <= purge_at);
            self.entries.insert(at, (purge_at, record.entry_len()));
        }
    }

    /// The bytes of the records whose `purge_at` is below `now`: what
    /// `Store::compact(state, now)` drops (spec 020-store-files R15).
    pub(crate) fn expired_bytes(&self, now: u64) -> u64 {
        self.entries
            .iter()
            .take_while(|(purge_at, _)| *purge_at < now)
            .fold(0, |sum, (_, len)| sum.saturating_add(*len))
    }

    /// The earliest `purge_at`, `None` for an empty log.
    pub(crate) fn oldest_expiry(&self) -> Option<u64> {
        self.entries.first().map(|(purge_at, _)| *purge_at)
    }
}
