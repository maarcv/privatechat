//! Messages from one's own key (spec 021 R13–R15, ADR 0029): an echo is
//! told by the signature this device kept, never by a counter, and any
//! other blob of one's own key that a member could still accept raises the
//! alert that someone else holds the key.

use super::receive::Arrival;
use super::{Channel, ClientRef, Received, Sender};
use crate::crypto::{self, PublicKey};
use crate::error::Error;
use crate::proto::envelope::{self, ChannelCtx, EXPIRY_MARGIN_MS, Opened, SenderKey, Verified};
use crate::proto::payload::PayloadKind;
use crate::storage::{ChannelState, LogEntry, LogRecord, StoreError};

impl Channel {
    /// Step 6 and on for a blob from one's own `pk_u` (R9, R13, R14).
    ///
    /// # Errors
    ///
    /// `Replay` for an echo or a repeated counter, committing nothing;
    /// `Expired` for a message no member accepts any more, with no event,
    /// and for a stale one with the event; `Store` when the commit fails.
    pub(super) fn receive_own(
        &mut self,
        verified: Verified<'_>,
        arrival: Arrival,
    ) -> Result<Option<Received>, Error> {
        if self.is_echo(verified.signature()) {
            return Err(Error::Replay);
        }
        // A republished foreign blob, whose alert is already set.
        if self.has_seen_pair(verified.sender_pk(), verified.counter()) {
            return Err(Error::Replay);
        }
        let opened = verified.open()?;
        if self.past_window(opened.sent_at, arrival.now) {
            return Err(Error::Expired);
        }
        let stale = matches!(opened.content, envelope::Content::Stale);
        let mut next = self.next_state();
        let mut records = Vec::new();
        let removed = self.own_key_changes(&mut next, &mut records, &opened, arrival.now);
        // A stale blob writes no seen record, so a server could push it
        // again and again: it commits only what it changes (R3, R14).
        if stale && !self.event_changes(&next, &removed) {
            return Err(Error::Expired);
        }
        let mut received = None;
        if !stale {
            let sender = Sender::OwnKeyElsewhere {
                pk: opened.sender_pk.0,
            };
            let listing = self.listing(opened, arrival, sender, EXPIRY_MARGIN_MS);
            records.extend(listing.records);
            received = Some(listing.received);
        }
        self.commit(next, records)?;
        self.queue_not_delivered(&removed);
        received.map(Some).ok_or(Error::Expired)
    }

    /// Step 5 for a blob of the key being retired (R9, spec
    /// 025-identity-regen): one that is not the sealed copy of one of its
    /// own entries comes from a thief, and the entries it overtook go.
    ///
    /// # Errors
    ///
    /// `RetiredKey`, after that commit; `Store` when it fails.
    pub(super) fn overtaken_by_thief(
        &mut self,
        verified: Verified<'_>,
        now: u64,
    ) -> Result<Option<Received>, Error> {
        // Step 5 decides: a blob of this key whose AEAD does not open is
        // `RetiredKey` like any other.
        let opened = match self.open_unless_sealed_here(verified) {
            Err(Error::BadSignature) => None,
            other => other?,
        };
        if let Some(opened) = opened {
            let mut next = self.next_state();
            let mut records = Vec::new();
            let removed = self.thief_removal(&mut next, &mut records, &opened, now);
            if !removed.is_empty() {
                self.commit(next, records)?;
                self.queue_not_delivered(&removed);
            }
        }
        Err(Error::RetiredKey)
    }

    /// The own-key check of R19, which needs no room for a message: for a
    /// blob of one's own key that is no echo and that a member could still
    /// accept, the changes of R14 without the record and the cursor; for a
    /// thief's blob of the key being retired, the removal of R9. `true`
    /// for every such blob of one's own key, set already or not.
    ///
    /// # Errors
    ///
    /// `Internal` for a `LogFull`, which the reserve of R18 rules out;
    /// `Store` for any other failed commit, nothing kept in memory.
    pub(crate) fn check_own_key(
        &mut self,
        blob: &[u8],
        received_at: u64,
        now: u64,
    ) -> Result<bool, Error> {
        self.latest_now = Some(now);
        let ctx = ChannelCtx::from_config(&self.config)?;
        let verified = match envelope::verify(blob, &ctx, received_at, now) {
            Ok(verified) => verified,
            // A libsodium failure is no verdict on the blob.
            Err(Error::Internal) => return Err(Error::Internal),
            Err(_) => return Ok(false),
        };
        let sender = *verified.sender_pk();
        let own = SenderKey::from_seed(&self.state.identity_seed)?;
        let is_own = crypto::ct_eq(&sender.0, &own.public().0);
        let opened = if is_own {
            if self.is_echo(verified.signature()) {
                return Ok(false);
            }
            verified.open().map(Some)
        } else if self.is_retiring(&sender)? {
            self.open_unless_sealed_here(verified)
        } else {
            return Ok(false);
        };
        let opened = match opened {
            Ok(Some(opened)) => opened,
            Ok(None) | Err(Error::BadSignature) => return Ok(false),
            Err(error) => return Err(error),
        };
        if is_own && self.past_window(opened.sent_at, now) {
            return Ok(false);
        }
        let mut next = self.next_state();
        // No cursor: the push is fetched again once there is room.
        next.cursor = self.state.cursor;
        let mut records = Vec::new();
        let removed = if is_own {
            self.own_key_changes(&mut next, &mut records, &opened, now)
        } else {
            self.thief_removal(&mut next, &mut records, &opened, now)
        };
        if self.event_changes(&next, &removed) {
            self.commit(next, records).map_err(|error| match error {
                Error::Store(StoreError::LogFull) => Error::Internal,
                other => other,
            })?;
            self.queue_not_delivered(&removed);
        }
        Ok(is_own)
    }

    /// Opens a blob of the key being retired, unless it is the sealed copy
    /// of one of its own entries (`None`).
    fn open_unless_sealed_here(&self, verified: Verified<'_>) -> Result<Option<Opened>, Error> {
        let signature = verified.signature();
        let sealed_here = self
            .state
            .outbox
            .iter()
            .any(|entry| crypto::ct_eq(&entry.signature.0, signature));
        if sealed_here {
            return Ok(None);
        }
        verified.open().map(Some)
    }

    /// The removal a thief's blob of the key being retired causes while a
    /// member could still accept it: the old key's ordinary entries at or
    /// below its counter, since receivers that took it reject them; never
    /// the pending `key_retired`. As for one's own key (R14), a blob no
    /// member accepts any more, or none could yet, overtakes nothing.
    fn thief_removal(
        &self,
        next: &mut ChannelState,
        records: &mut Vec<LogRecord>,
        opened: &Opened,
        now: u64,
    ) -> Vec<(ClientRef, u64)> {
        if self.past_window(opened.sent_at, now) || !self.within_reach(opened.sent_at, now) {
            return Vec::new();
        }
        self.remove_entries(next, records, |entry| {
            entry.under_retired_key && entry.counter <= opened.counter
        })
    }

    /// The key whose `key_retired` is pending (spec 025-identity-regen).
    ///
    /// # Errors
    ///
    /// `Internal` when libsodium fails.
    pub(super) fn is_retiring(&self, pk: &PublicKey) -> Result<bool, Error> {
        let Some(seed) = &self.state.retiring_seed else {
            return Ok(false);
        };
        let old = SenderKey::from_seed(seed)?;
        Ok(crypto::ct_eq(&old.public().0, &pk.0))
    }

    /// Whether a member could still accept a message dated `sent_at`: the
    /// latest date a copy the server keeps for one TTL could be accepted by
    /// a member whose clock is off by the margin, or no readable date
    /// (R14).
    pub(super) fn within_reach(&self, sent_at: Option<u64>, now: u64) -> bool {
        let window = self.accept_window();
        let reach = now.saturating_add(window.saturating_mul(2));
        sent_at.is_none_or(|sent_at| sent_at <= reach)
    }

    /// Whether the own-key changes of `next` change the committed state.
    fn event_changes(&self, next: &ChannelState, removed: &[(ClientRef, u64)]) -> bool {
        !removed.is_empty()
            || next.own_key_used_elsewhere != self.state.own_key_used_elsewhere
            || next.send_counter != self.state.send_counter
            || next.read_only != self.state.read_only
    }

    /// The signature of a kept-signature record or of an `outbox` entry,
    /// under `ct_eq`, whatever key sealed it (R13, R15).
    fn is_echo(&self, signature: &[u8; 64]) -> bool {
        let kept = self.records.iter().any(|record| {
            matches!(&record.entry, LogEntry::KeptSignature { signature: kept, .. }
                if crypto::ct_eq(&kept.0, signature))
        });
        kept || self
            .state
            .outbox
            .iter()
            .any(|entry| crypto::ct_eq(&entry.signature.0, signature))
    }

    /// The changes of the own-key event (R14), which R19 commits too:
    /// the flag; when the message is not stale, the send counter past its
    /// counter and, for a `key_retired`, `read_only` (spec 024-key-retired
    /// R3); and while a member could still accept it, the removal of the
    /// ordinary entries it overtook, since every receiver that took it
    /// rejects them. Returns the removed entries.
    pub(super) fn own_key_changes(
        &self,
        next: &mut ChannelState,
        records: &mut Vec<LogRecord>,
        opened: &Opened,
        now: u64,
    ) -> Vec<(ClientRef, u64)> {
        next.own_key_used_elsewhere = true;
        let key_retired = matches!(&opened.content,
            envelope::Content::Message(payload) if payload.kind == PayloadKind::KeyRetired);
        if !matches!(opened.content, envelope::Content::Stale) {
            if opened.counter >= next.send_counter {
                // `2^64 − 1` stays: the counter is exhausted.
                next.send_counter = opened.counter.saturating_add(1);
            }
            next.read_only |= key_retired;
        }
        if !self.within_reach(opened.sent_at, now) {
            return Vec::new();
        }
        self.remove_entries(next, records, |entry| {
            !entry.under_retired_key && (key_retired || entry.counter <= opened.counter)
        })
    }
}
