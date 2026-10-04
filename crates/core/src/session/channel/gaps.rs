//! The gaps of spec 021 R24: the counters a peer skipped, counted in this
//! session only, so that a deletion by the server shows; and the history
//! truncation, after which a sender away for longer than a TTL counts no
//! gap for the messages that expired meanwhile.

use super::{Channel, Gap};
use crate::storage::state::items::PeerRecord;

/// A single skip above this is anomalous (R24).
const ANOMALOUS_GAP: u64 = 1 << 32;

impl Channel {
    /// The history before `now` may be missing (R24, spec
    /// 028-session-sans-io): `truncated_at = now`, written with the next
    /// commit.
    pub(crate) fn history_truncated(&mut self, now: u64) {
        self.latest_now = Some(now);
        self.truncated_at = Some(now);
    }

    /// The gap a consumed, not stale message of `peer` at `counter`
    /// reveals, its listed time before the clamp to `now` being `listed`
    /// (R11, R24); `None` for none.
    pub(super) fn gap_of(
        &self,
        peer: Option<&PeerRecord>,
        counter: u64,
        listed: u64,
        now: u64,
    ) -> Option<Gap> {
        let peer = peer?;
        let previous = peer.max_counter?;
        let ttl = self.ttl_ms();
        let mut spans_truncation = false;
        // A `truncated_at` ahead of `now` is read as `now`.
        if let Some(truncated_at) = self.truncated_at.map(|at| at.min(now))
            && peer.last_seen < truncated_at.saturating_sub(ttl)
        {
            let window_end = truncated_at.saturating_add(self.accept_window());
            // What expired while the device was away is no deletion.
            if listed <= window_end {
                return None;
            }
            spans_truncation = true;
        }
        let missing = counter.saturating_sub(previous.saturating_add(1));
        (missing > 0).then_some(Gap {
            peer: peer.pk.0,
            missing,
            anomalous: missing > ANOMALOUS_GAP,
            spans_truncation,
        })
    }

    /// Adds a gap to its sender's, after the commit of its message.
    pub(super) fn add_gap(&mut self, gap: Gap) {
        let total = self
            .carry
            .gaps
            .entry(gap.peer)
            .or_insert(Gap { missing: 0, ..gap });
        total.missing = total.missing.saturating_add(gap.missing);
        total.anomalous |= gap.anomalous;
        total.spans_truncation |= gap.spans_truncation;
        self.peers_changed = true;
    }
}
