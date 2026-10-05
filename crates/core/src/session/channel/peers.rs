//! The peers of spec 022-peers-tofu: the list a client paints with its
//! warnings (R3, R13–R15), the calls that change a peer (R7–R10) and the
//! fingerprints (R12). The record
//! is created and updated on receive (R1, R2, `receive.rs`); retirement is
//! spec 024-key-retired's, and the admission check spec 026-peer-limits'.

use super::{Channel, PeerId};
use crate::crypto::{self, PublicKey};
use crate::error::Error;
use crate::proto::envelope::SenderKey;
use crate::proto::fingerprint::{self, Fingerprint};
use crate::session::names::{name_key, names_collide, shown_name};
use crate::storage::MAX_NAME;
use crate::storage::state::items::PeerRecord;

/// A peer as a client paints it (R3); every name cleaned (R6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Peer {
    /// The peer's `pk_u`.
    pub id: PeerId,
    /// The label one gave the peer.
    pub label: Option<String>,
    /// The name of its last message that carried one.
    pub suggested_name: Option<String>,
    /// Verified by its QR or its 12 words.
    pub verified: bool,
    /// Its messages are not notified.
    pub muted: bool,
    /// When it retired its key (spec 024-key-retired).
    pub retired_at: Option<u64>,
    /// When its first message, or its pre-verification, was committed.
    pub first_seen: u64,
    /// When its latest message was committed.
    pub last_seen: u64,
    /// The 4 words of spec 014-fingerprint.
    pub short: Vec<String>,
    /// For an unknown peer, the first seen peer with a label its suggested
    /// name collides with (R13).
    pub claims_name_of: Option<PeerId>,
    /// An unknown peer suggests one's own display name (R13).
    pub claims_own_name: bool,
    /// Its label collides with another peer's (R14).
    pub label_collides: bool,
    /// Its 4 words equal another peer's or one's own (R15).
    pub short_collides: bool,
}

/// Whether the label of a call is checked against the other peers' labels
/// (R7) or given to a verified target, which may share one (R8, R9).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Target {
    Unverified,
    Verified,
}

impl Channel {
    /// Every peer, in `first_seen` order (R3), with the warnings of
    /// R13–R15; commits nothing.
    ///
    /// # Errors
    ///
    /// `Internal` when a fingerprint cannot be computed.
    pub(crate) fn peers(&self) -> Result<Vec<Peer>, Error> {
        let mut records: Vec<&PeerRecord> = self.state.peers.iter().collect();
        records.sort_by_key(|peer| peer.first_seen);
        let shorts = records
            .iter()
            .map(|peer| Ok(self.fingerprint(peer.pk.0)?.short))
            .collect::<Result<Vec<_>, Error>>()?;
        let own_short = self.own_fingerprint()?.short;
        let own_name = self.state.own_display_name.as_deref();
        let peers = records.iter().zip(&shorts).map(|(peer, short)| {
            let suggested = suggested_name(peer);
            // §7: a peer with no label that is not retired is unknown.
            let unknown = peer.label.is_none() && peer.retired_at.is_none();
            let claimed = suggested.filter(|_| unknown);
            Peer {
                id: peer.pk.0,
                label: peer.label.as_deref().and_then(shown_name),
                suggested_name: suggested.and_then(shown_name),
                verified: peer.verified,
                muted: peer.muted,
                retired_at: peer.retired_at,
                first_seen: peer.first_seen,
                last_seen: peer.last_seen,
                short: short.clone(),
                claims_name_of: claimed.and_then(|name| first_holder(&records, name)),
                claims_own_name: claimed
                    .zip(own_name)
                    .is_some_and(|(name, own)| names_collide(name, own)),
                label_collides: peer
                    .label
                    .as_deref()
                    .is_some_and(|label| label_held_by_other(&records, &peer.pk, label)),
                short_collides: *short == own_short
                    || records
                        .iter()
                        .zip(&shorts)
                        .any(|(other, words)| other.pk.0 != peer.pk.0 && words == short),
            }
        });
        Ok(peers.collect())
    }

    /// Gives `peer` the label `name` (R7).
    ///
    /// # Errors
    ///
    /// In this order: `UnknownPeer`; `BadPayload` for an invalid name;
    /// `LabelInUse` when another peer that is not retired holds a colliding
    /// label and `peer` is not verified; `PeerLimit` from spec
    /// 026-peer-limits; `Store` when the commit fails.
    pub(crate) fn label(&mut self, peer: PeerId, name: &str, now: u64) -> Result<(), Error> {
        let record = self.peer_record(&peer)?;
        let target = if record.verified {
            Target::Verified
        } else {
            Target::Unverified
        };
        self.check_label(&peer, name, target, now)?;
        let mut next = self.next_state();
        if let Some(record) = find(&mut next.peers, &peer) {
            record.label = Some(name.to_owned());
        }
        self.commit(next, Vec::new())
    }

    /// Marks `peer` verified, its label kept, or `label` given to a peer
    /// with none (R8).
    ///
    /// # Errors
    ///
    /// `UnknownPeer`; `BadPayload` when the peer has no label and `label`
    /// is `None` or invalid; `PeerLimit` from spec 026-peer-limits; `Store`
    /// when the commit fails.
    pub(crate) fn verify(
        &mut self,
        peer: PeerId,
        label: Option<&str>,
        now: u64,
    ) -> Result<(), Error> {
        let has_label = self.peer_record(&peer)?.label.is_some();
        let given = if has_label {
            None
        } else {
            let name = label.ok_or(Error::BadPayload)?;
            self.check_label(&peer, name, Target::Verified, now)?;
            Some(name)
        };
        let mut next = self.next_state();
        if let Some(record) = find(&mut next.peers, &peer) {
            record.verified = true;
            if let Some(name) = given {
                record.label = Some(name.to_owned());
            }
        }
        self.commit(next, Vec::new())
    }

    /// Verifies the key of a scanned QR, creating its record when it has
    /// none (R9): pre-verification before its first message.
    ///
    /// # Errors
    ///
    /// `BadPayload` and `WrongChannel` of `parse_verify_qr`; `OwnKey` for
    /// one's own current or old key; the label errors of R7 and `PeerLimit`
    /// when the label is written; `Store` when the commit fails.
    pub(crate) fn verify_scanned(
        &mut self,
        qr: &[u8],
        label: &str,
        now: u64,
    ) -> Result<PeerId, Error> {
        let pk = fingerprint::parse_verify_qr(qr, self.config.id())?;
        if self.is_own_key(&pk)? {
            return Err(Error::OwnKey);
        }
        let has_label = self.peer(&pk).is_some_and(|peer| peer.label.is_some());
        if !has_label {
            self.check_label(&pk.0, label, Target::Verified, now)?;
        }
        let mut next = self.next_state();
        if let Some(record) = find(&mut next.peers, &pk.0) {
            record.verified = true;
            if !has_label {
                record.label = Some(label.to_owned());
            }
        } else {
            next.peers.push(PeerRecord {
                pk,
                label: Some(label.to_owned()),
                verified: true,
                muted: false,
                retired_at: None,
                first_seen: now,
                last_seen: now,
                max_counter: None,
                last_display_name: None,
            });
        }
        self.commit(next, Vec::new())?;
        Ok(pk.0)
    }

    /// Mutes or unmutes `peer` (R10); the same value commits nothing.
    ///
    /// # Errors
    ///
    /// `UnknownPeer`; `Store` when the commit fails.
    pub(crate) fn mute(&mut self, peer: PeerId, muted: bool) -> Result<(), Error> {
        if self.peer_record(&peer)?.muted == muted {
            return Ok(());
        }
        let mut next = self.next_state();
        if let Some(record) = find(&mut next.peers, &peer) {
            record.muted = muted;
        }
        self.commit(next, Vec::new())
    }

    /// The fingerprint of any key in this channel, with or without a
    /// record (R12).
    ///
    /// # Errors
    ///
    /// `Internal` when libsodium fails.
    pub(crate) fn fingerprint(&self, peer: PeerId) -> Result<Fingerprint, Error> {
        fingerprint::presentation(self.config.id(), &PublicKey(peer))
    }

    /// The fingerprint of one's own `pk_u` (R12).
    ///
    /// # Errors
    ///
    /// `Internal` when libsodium fails.
    pub(crate) fn own_fingerprint(&self) -> Result<Fingerprint, Error> {
        let own = SenderKey::from_seed(&self.state.identity_seed)?;
        fingerprint::presentation(self.config.id(), own.public())
    }

    /// The record of `peer`, or `UnknownPeer`.
    fn peer_record(&self, peer: &PeerId) -> Result<&PeerRecord, Error> {
        self.peer(&PublicKey(*peer)).ok_or(Error::UnknownPeer)
    }

    /// One's own `pk_u` or one of `own_old_keys`, never a peer (R9).
    fn is_own_key(&self, pk: &PublicKey) -> Result<bool, Error> {
        let own = SenderKey::from_seed(&self.state.identity_seed)?;
        Ok(crypto::ct_eq(&pk.0, &own.public().0)
            || self.state.own_old_keys.iter().any(|old| old.pk.0 == pk.0))
    }

    /// The label rules of R7 after `UnknownPeer`, in order: the name, the
    /// collision unless the target is verified, then the admission.
    fn check_label(
        &self,
        peer: &PeerId,
        name: &str,
        target: Target,
        now: u64,
    ) -> Result<(), Error> {
        let valid = !name.is_empty()
            && name.len() <= MAX_NAME
            && !name.chars().any(char::is_control)
            && !name_key(name).is_empty();
        if !valid {
            return Err(Error::BadPayload);
        }
        // A label held by a retired peer is free: the user retires the old
        // key to give its label to the new one (spec 024-key-retired).
        let in_use = self.state.peers.iter().any(|other| {
            other.pk.0 != *peer
                && other.retired_at.is_none()
                && other
                    .label
                    .as_deref()
                    .is_some_and(|label| names_collide(label, name))
        });
        if in_use && target == Target::Unverified {
            return Err(Error::LabelInUse);
        }
        if !self.admits(peer, now) {
            return Err(Error::PeerLimit);
        }
        Ok(())
    }

    /// Whether a label or a verification may move `peer` into the labelled
    /// budget: spec 026-peer-limits R4 decides, and until it does every
    /// call finds room.
    fn admits(&self, _peer: &PeerId, _now: u64) -> bool {
        true
    }
}

/// The name of the peer's last message that carried one, as sent.
fn suggested_name(peer: &PeerRecord) -> Option<&str> {
    let name = peer.last_display_name.as_deref()?;
    core::str::from_utf8(name).ok()
}

/// The first of `records` (in `first_seen` order) whose label collides with
/// `name`: labelled, verified or retired, since an impostor appears when a
/// key is retired (R13).
fn first_holder(records: &[&PeerRecord], name: &str) -> Option<PeerId> {
    records
        .iter()
        .find(|other| {
            other
                .label
                .as_deref()
                .is_some_and(|label| names_collide(label, name))
        })
        .map(|other| other.pk.0)
}

/// Whether a peer other than `pk` holds a label colliding with `label`,
/// retired peers included (R14).
fn label_held_by_other(records: &[&PeerRecord], pk: &PublicKey, label: &str) -> bool {
    records.iter().any(|other| {
        other.pk.0 != pk.0
            && other
                .label
                .as_deref()
                .is_some_and(|held| names_collide(held, label))
    })
}

/// The record of `peer` in a state being built.
fn find<'a>(peers: &'a mut [PeerRecord], peer: &PeerId) -> Option<&'a mut PeerRecord> {
    peers.iter_mut().find(|record| record.pk.0 == *peer)
}
