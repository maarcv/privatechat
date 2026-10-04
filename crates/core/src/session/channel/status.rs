//! What a channel reports without committing (spec 021 R25), the device
//! clock sample beside it, and leaving the channel (R27).

use super::{Channel, ChannelStatus, ClockOff, Gap};
use crate::error::Error;
use crate::proto::envelope::EXPIRY_MARGIN_MS;

/// The longest offset a live `ack` may show before this device's clock is
/// called ahead or behind (R25).
const CLOCK_MARGIN_MS: u64 = EXPIRY_MARGIN_MS;

impl Channel {
    /// The cursor, in the server's time (R20).
    pub(crate) fn cursor(&self) -> Option<u64> {
        self.cursor
    }

    /// The local time of the last sync (R20).
    pub(crate) fn synced_at(&self) -> Option<u64> {
        self.synced_at
    }

    /// The flags of R25, from memory alone.
    pub(crate) fn status(&self) -> ChannelStatus {
        ChannelStatus {
            own_key_used_elsewhere: self.state.own_key_used_elsewhere,
            read_only: self.state.read_only,
            retirement_pending: self.state.retiring_seed.is_some(),
            storage_full: !self.has_headroom(),
            ignored_keys: u32::try_from(self.carry.ignored_keys.len()).unwrap_or(u32::MAX),
            // Spec 026-peer-limits sets the two limits.
            unknown_limit_reached: false,
            labelled_limit_reached: false,
            clock_off: self.carry.clock_off != ClockOff::No,
            truncated_before: self.truncated_before(),
        }
    }

    /// The senders with messages missing in this session (R24).
    pub(crate) fn gaps(&self) -> Vec<Gap> {
        self.carry
            .gaps
            .values()
            .filter(|gap| gap.missing > 0)
            .copied()
            .collect()
    }

    /// A sample of the server's time against this device's (R25): `live`
    /// for an `ack` within 5 000 ms of its publish, which sets the flag
    /// when this device is ahead or behind; a backlog sample, legitimately
    /// old, sets it only when it is in the future.
    pub(crate) fn clock_sample(&mut self, received_at: u64, now: u64, live: bool) {
        self.latest_now = Some(now);
        let behind = received_at.saturating_sub(now) > CLOCK_MARGIN_MS;
        // A short TTL cannot absorb this device being as far ahead.
        let ahead_margin = CLOCK_MARGIN_MS.min(self.ttl_ms() / 2);
        let ahead = now.saturating_sub(received_at) > ahead_margin;
        self.carry.clock_off = match (live, self.carry.clock_off) {
            (true, _) if ahead || behind => ClockOff::Live,
            (true, _) => ClockOff::No,
            (false, _) if behind => ClockOff::Backlog(received_at),
            (false, ClockOff::Backlog(setting)) if received_at >= setting => ClockOff::No,
            (false, other) => other,
        };
    }

    /// Deletes the channel's directory (R27); on `Err` the channel stays
    /// usable.
    ///
    /// # Errors
    ///
    /// The store's error.
    pub(crate) fn leave(&mut self) -> Result<(), Error> {
        Ok(self.store.destroy()?)
    }

    /// `truncated_at − ttl_ms` while the banner of a truncation still
    /// applies, or before any timed call (R25); a `truncated_at` later than
    /// the latest `now` is read as that `now` (R24).
    fn truncated_before(&self) -> Option<u64> {
        let truncated_at = self.truncated_at?;
        let ttl = self.ttl_ms();
        let Some(now) = self.latest_now else {
            return Some(truncated_at.saturating_sub(ttl));
        };
        let truncated_at = truncated_at.min(now);
        let shown_until = truncated_at
            .saturating_add(ttl)
            .saturating_add(EXPIRY_MARGIN_MS);
        (shown_until >= now).then(|| truncated_at.saturating_sub(ttl))
    }
}
