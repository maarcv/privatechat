//! Peer limits (spec 026-peer-limits): the two budgets (R1), the room a
//! new key finds at step 5 (R2), the eviction of a stranger (R3), the
//! admission into the labelled budget (R4), `forget` (R5) and the ignored
//! keys of this session (R6). Only `forget`, the user's call, removes a
//! peer the user named; the eviction touches strangers alone.

use super::{Channel, PeerId};
use crate::crypto::PublicKey;
use crate::error::Error;
use crate::storage::ChannelState;
use crate::storage::state::MAX_PEERS;
use crate::storage::state::items::PeerRecord;

/// The unknown peers a channel keeps (R1, R2).
pub(crate) const MAX_UNKNOWN_PEERS: usize = 50;

/// The labelled, verified or retired peers a label or a verification may
/// fill (R4).
pub(crate) const MAX_LABELLED_PEERS: usize = 500;

/// The distinct ignored keys counted in one session (R6).
pub(crate) const MAX_IGNORED_TRACKED: usize = 1_024;

impl Channel {
    /// Removes the record of `peer`, retired or not, in one commit (R5): a
    /// forgotten key that writes again is a new unknown.
    ///
    /// # Errors
    ///
    /// `UnknownPeer` for a key with no record, committing nothing; `Store`
    /// when the commit fails.
    pub(crate) fn forget(&mut self, peer: PeerId) -> Result<(), Error> {
        if self.peer(&PublicKey(peer)).is_none() {
            return Err(Error::UnknownPeer);
        }
        let mut next = self.next_state();
        next.peers.retain(|record| record.pk.0 != peer);
        self.commit(next, Vec::new())?;
        // Spec 021 R24: the gap goes with the record.
        self.carry.gaps.remove(&peer);
        Ok(())
    }

    /// Whether a key with no record finds room at step 5 (R2): below both
    /// limits, or with a stranger R3 may evict.
    pub(super) fn has_room(&self) -> bool {
        let peers = &self.state.peers;
        let below = unknown_count(peers) < MAX_UNKNOWN_PEERS && peers.len() < MAX_PEERS;
        below || peers.iter().any(is_evictable)
    }

    /// Whether a label or a verification may move an unknown peer into the
    /// labelled budget, or create a verified one (R4): `creates` when the
    /// call adds a record (`verify_scanned` of a new key), which also needs
    /// room under `MAX_PEERS`.
    pub(super) fn admits_labelled(&self, creates: bool) -> bool {
        let peers = &self.state.peers;
        labelled_count(peers) < MAX_LABELLED_PEERS && !(creates && peers.len() >= MAX_PEERS)
    }

    /// Counts `pk` among the keys ignored in this session (R6), up to
    /// [`MAX_IGNORED_TRACKED`].
    pub(super) fn ignore_key(&mut self, pk: PeerId) {
        if self.carry.ignored_keys.len() < MAX_IGNORED_TRACKED {
            self.carry.ignored_keys.insert(pk);
        }
    }

    /// Whether the labelled budget is spent (R6).
    pub(super) fn labelled_limit_reached(&self) -> bool {
        labelled_count(&self.state.peers) >= MAX_LABELLED_PEERS
    }
}

/// Makes room in `next` for a peer a consumed message creates at `now`
/// (R3): at either limit, removes the stranger heard from longest ago that
/// is not muted, ties broken by the smaller key, and returns its key. A
/// `last_seen` later than `now` ranks oldest: only a clock that was ahead
/// left it, and it would otherwise shield a flood for years.
pub(super) fn evict_stranger(next: &mut ChannelState, now: u64) -> Option<PeerId> {
    let full = unknown_count(&next.peers) >= MAX_UNKNOWN_PEERS || next.peers.len() >= MAX_PEERS;
    if !full {
        return None;
    }
    let evicted = next
        .peers
        .iter()
        .filter(|peer| is_evictable(peer))
        .min_by_key(|peer| (peer.last_seen <= now, peer.last_seen, peer.pk.0))
        .map(|peer| peer.pk.0)?;
    next.peers.retain(|peer| peer.pk.0 != evicted);
    Some(evicted)
}

/// §7: a peer with no label, not verified and not retired is unknown,
/// muted or not (R1).
pub(super) fn is_unknown(peer: &PeerRecord) -> bool {
    peer.label.is_none() && !peer.verified && peer.retired_at.is_none()
}

/// An unknown peer R3 may evict: muting stays durable.
fn is_evictable(peer: &PeerRecord) -> bool {
    is_unknown(peer) && !peer.muted
}

fn unknown_count(peers: &[PeerRecord]) -> usize {
    peers.iter().filter(|peer| is_unknown(peer)).count()
}

fn labelled_count(peers: &[PeerRecord]) -> usize {
    peers.iter().filter(|peer| !is_unknown(peer)).count()
}
