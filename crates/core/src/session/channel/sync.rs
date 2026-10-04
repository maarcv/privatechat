//! The values that move without a message (spec 021 R20): the cursor,
//! `synced_at` and `truncated_at` wait in memory and go with the next
//! commit, and a commit of one of them alone is rate-limited, so that a
//! stream of pushes or ticks cannot make the device write without end.

use super::Channel;
use crate::error::Error;

/// The cursor is committed alone once per minute of its value.
const CURSOR_STEP_MS: u64 = 60_000;

/// `synced_at` is committed alone at most once per hour.
const SYNCED_AT_STEP_MS: u64 = 3_600_000;

impl Channel {
    /// Sets `synced_at = now` (R20), committed when the committed one is
    /// absent, later than `now`, or older than `min(ttl_ms / 2, 1 h)`.
    ///
    /// # Errors
    ///
    /// `Store` when that commit fails; the value still waits in memory.
    pub(crate) fn synced(&mut self, now: u64) -> Result<(), Error> {
        self.latest_now = Some(now);
        self.synced_at = Some(now);
        self.commit_pending(now)
    }

    /// Commits every pending value at once, for the lock of spec
    /// 027-core-api (R20).
    ///
    /// # Errors
    ///
    /// `Store` when the commit fails.
    pub(crate) fn flush(&mut self, now: u64) -> Result<(), Error> {
        self.latest_now = Some(now);
        if self.has_pending() {
            self.commit(self.next_state(), Vec::new())?;
        }
        Ok(())
    }

    /// Commits the in-memory state once, even with nothing pending, to
    /// test that the store can be written (R20, spec 027-core-api R12).
    ///
    /// # Errors
    ///
    /// `Store` when the commit fails.
    pub(crate) fn probe(&mut self, now: u64) -> Result<(), Error> {
        self.latest_now = Some(now);
        self.commit(self.next_state(), Vec::new())
    }

    /// Commits the pending values when the cursor or `synced_at` alone
    /// make a commit due (R20).
    fn commit_pending(&mut self, now: u64) -> Result<(), Error> {
        if self.cursor_due() || self.synced_at_due(now) {
            self.commit(self.next_state(), Vec::new())?;
        }
        Ok(())
    }

    /// Commits the pending values when the cursor's minute changed: the
    /// one commit a rejected push may make (R3, R20).
    pub(super) fn commit_cursor(&mut self) -> Result<(), Error> {
        if self.cursor_due() {
            self.commit(self.next_state(), Vec::new())?;
        }
        Ok(())
    }

    /// A value in memory that the last commit did not write.
    fn has_pending(&self) -> bool {
        self.cursor != self.state.cursor
            || self.synced_at != self.state.synced_at
            || self.truncated_at != self.state.truncated_at
    }

    /// The cursor's minute differs from the committed one's.
    fn cursor_due(&self) -> bool {
        let minute = |cursor: Option<u64>| cursor.map(|v| v.saturating_sub(v % CURSOR_STEP_MS));
        minute(self.cursor) != minute(self.state.cursor)
    }

    /// The committed `synced_at` is absent, ahead of `now`, or older than
    /// the step.
    fn synced_at_due(&self, now: u64) -> bool {
        if self.synced_at == self.state.synced_at {
            return false;
        }
        let step = SYNCED_AT_STEP_MS.min(self.ttl_ms() / 2);
        self.state
            .synced_at
            .is_none_or(|committed| committed > now || now.saturating_sub(committed) > step)
    }
}
