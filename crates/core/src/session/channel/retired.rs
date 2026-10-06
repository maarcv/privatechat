//! Retired keys (spec 024-key-retired): what a peer's `key_retired` changes
//! (R1, R2) and the manual `retire` (R4). One's own key retired elsewhere
//! (R3) is the own-key event of `own_key.rs`; sending a retirement is spec
//! 025-identity-regen's. Nothing here checks a limit and nothing removes a
//! retired record (R5).

use super::peers::find;
use super::receive::Arrival;
use super::{Channel, PeerId, Received, Sender};
use crate::crypto::PublicKey;
use crate::error::Error;
use crate::proto::envelope::{Content, Opened};
use crate::proto::payload::PayloadKind;
use crate::storage::state::items::PeerRecord;

impl Channel {
    /// Retires `peer` by hand, its label kept (R4); a peer already retired
    /// commits nothing.
    ///
    /// # Errors
    ///
    /// `UnknownPeer` for a key with no record; `Store` when the commit
    /// fails.
    pub(crate) fn retire(&mut self, peer: PeerId, now: u64) -> Result<(), Error> {
        self.latest_now = Some(now);
        let record = self.peer(&PublicKey(peer)).ok_or(Error::UnknownPeer)?;
        if record.retired_at.is_some() {
            return Ok(());
        }
        let mut next = self.next_state();
        if let Some(record) = find(&mut next.peers, &peer) {
            record.retired_at = Some(now);
        }
        self.commit(next, Vec::new())
    }

    /// Consumes a peer's readable, not stale `key_retired` (R1, R2): only a
    /// key the user named or verified becomes a retired record, so that a
    /// stranger can plant none (audit J, J-B1).
    ///
    /// # Errors
    ///
    /// `Store` when the commit fails, the cursor unchanged.
    pub(super) fn consume_retirement(
        &mut self,
        opened: Opened,
        arrival: Arrival,
    ) -> Result<Option<Received>, Error> {
        let pk = opened.sender_pk.0;
        let Some(peer) = self.peer(&opened.sender_pk) else {
            // R2: no record to remove; the cursor alone (spec 021 R20).
            return self.commit_cursor().map(|()| None);
        };
        let trusted = peer.label.is_some() || peer.verified;
        let muted = peer.muted;
        let mut next = self.next_state();
        if trusted {
            let listing = self.listing(opened, arrival, Sender::Peer { pk }, 0);
            if let Some(record) = find(&mut next.peers, &pk) {
                // Step 5 stops a retired key first; R1's "unless already set".
                record.retired_at.get_or_insert(arrival.now);
                spend(record, arrival.now);
            }
            self.commit(next, listing.records)?;
            return Ok(Some(listing.received));
        }
        if muted {
            // Muting stays durable: the key's later blobs are `Replay`.
            if let Some(record) = find(&mut next.peers, &pk) {
                spend(record, arrival.now);
            }
        } else {
            next.peers.retain(|record| record.pk.0 != pk);
        }
        self.commit(next, Vec::new())?;
        // Spec 021 R24: the gap goes with the record.
        if !muted {
            self.carry.gaps.remove(&pk);
        }
        Ok(None)
    }
}

/// A readable, not stale `key_retired`; a stale message's type is never
/// read (spec 013 R12).
pub(super) fn is_key_retired(opened: &Opened) -> bool {
    matches!(&opened.content, Content::Message(payload) if payload.kind == PayloadKind::KeyRetired)
}

/// The last counter taken: every later blob of the key is a replay.
fn spend(record: &mut PeerRecord, now: u64) {
    record.max_counter = Some(u64::MAX);
    record.last_seen = now;
}
