//! The receive pipeline of spec 021 R9–R12 and the cursor it moves (R3,
//! R20): the headroom, the checks of spec 013 that need no state, the
//! questions that need state (`docs/spec.md` §4 steps 5 and 6), then
//! `open`, and at most one commit.

use zeroize::Zeroizing;

use super::{Channel, MessageContent, Received, Sender};
use crate::crypto::{self, PublicKey};
use crate::error::Error;
use crate::proto::envelope::{self, ChannelCtx, EXPIRY_MARGIN_MS, Opened, SenderKey};
use crate::proto::payload::PayloadKind;
use crate::storage::state::items::PeerRecord;
use crate::storage::{ChannelState, Content, LogEntry, LogRecord, Message};

impl Channel {
    /// Checks and, when it passes, consumes one pushed blob (R9–R12):
    /// `Ok(Some)` when it appended a message record, `Ok(None)` when it
    /// consumed the blob without one.
    ///
    /// # Errors
    ///
    /// The first failure of R9, in its order, committing nothing but the
    /// cursor of R20; `Expired` for a stale message (R10); `Store` with the
    /// cursor unchanged when a commit fails.
    pub(crate) fn decrypt(
        &mut self,
        blob: &[u8],
        server_id: [u8; 16],
        received_at: u64,
        now: u64,
    ) -> Result<Option<Received>, Error> {
        self.latest_now = Some(now);
        // R18 first: it reads only the log length, which no blob changes.
        self.check_headroom(now)?;
        let previous = self.cursor;
        // R20: a push the server would not hold if the clocks agreed leaves
        // the cursor where a corrected clock fetches it again.
        if received_at.saturating_add(self.ttl_ms()) >= now {
            let pushed = received_at.min(now);
            self.cursor = Some(previous.map_or(pushed, |cursor| cursor.max(pushed)));
        }
        let result = match self.receive(blob, server_id, received_at, now) {
            Err(Error::Store(error)) => Err(Error::Store(error)),
            // A rejection commits the cursor alone, and only when due.
            other => self.commit_pending(now).and(other),
        };
        if matches!(result, Err(Error::Store(_))) {
            self.cursor = previous;
        }
        result
    }

    /// Steps 1–7 of `docs/spec.md` §4 in order (R9).
    fn receive(
        &mut self,
        blob: &[u8],
        server_id: [u8; 16],
        received_at: u64,
        now: u64,
    ) -> Result<Option<Received>, Error> {
        let ctx = ChannelCtx::from_config(&self.config)?;
        // Steps 1–4: nothing reads the state before the signature has
        // proved the header (ADR 0027).
        let verified = envelope::verify(blob, &ctx, received_at, now)?;
        let sender = *verified.sender_pk();
        let own = SenderKey::from_seed(&self.state.identity_seed)?;
        let is_own = crypto::ct_eq(&sender.0, &own.public().0);
        // Step 5.
        if self.is_retired(&sender) {
            return Err(Error::RetiredKey);
        }
        if !is_own && self.peer(&sender).is_none() && !self.has_room_for(&sender) {
            return Err(Error::PeerLimit);
        }
        // Step 6.
        if self.has_seen_server_id(&server_id) {
            return Err(Error::Replay);
        }
        if is_own {
            return self.receive_own(verified, server_id, received_at, now);
        }
        let counter = verified.counter();
        let max_counter = self.peer(&sender).and_then(|peer| peer.max_counter);
        if self.has_seen_pair(&sender, counter) || max_counter.is_some_and(|max| counter <= max) {
            return Err(Error::Replay);
        }
        let opened = verified.open()?;
        self.consume(opened, server_id, received_at, now)
    }

    /// R10–R12 for a peer's message that `open` read.
    fn consume(
        &mut self,
        opened: Opened,
        server_id: [u8; 16],
        received_at: u64,
        now: u64,
    ) -> Result<Option<Received>, Error> {
        let ttl = self.ttl_ms();
        let sent_at = opened.sent_at;
        // R10: a life measured from the signed `sent_at` (ADR 0044).
        let past_window = sent_at.is_some_and(|sent_at| {
            sent_at.saturating_add(ttl).saturating_add(EXPIRY_MARGIN_MS) < now
        });
        if matches!(opened.content, envelope::Content::Stale) || past_window {
            return Err(Error::Expired);
        }
        // A message that would expire before it is shown is not consumed.
        let shown_from = sent_at.unwrap_or(received_at).min(now);
        let expires_at = shown_from.saturating_add(ttl);
        if expires_at < now {
            return Err(Error::Expired);
        }
        // R11: never later than its arrival, never earlier than its signed
        // `sent_at` minus the margin.
        let listed_at = sent_at
            .map_or(received_at, |sent_at| {
                received_at.max(sent_at.saturating_sub(EXPIRY_MARGIN_MS))
            })
            .min(now);
        let (content, stored, name) = contents(opened.content)?;
        let sender = opened.sender_pk;
        let counter = opened.counter;
        let message = LogRecord {
            purge_at: expires_at,
            entry: LogEntry::Message(Message {
                server_id: Some(server_id),
                received_at: listed_at,
                sender_pk: sender,
                counter,
                content: stored,
                display_name: name.clone().map(|name| Zeroizing::new(name.into_bytes())),
                sent_at,
                own_client_ref: None,
            }),
        };
        // R26: the seen record outlives every moment a copy could still be
        // accepted.
        let seen = LogRecord {
            purge_at: sent_at.map_or(expires_at, |sent_at| sent_at.saturating_add(ttl)),
            entry: LogEntry::Seen {
                server_id,
                sender_pk: sender,
                counter,
            },
        };
        let mut next = self.next_state();
        let key_retired = content == MessageContent::KeyRetired;
        update_peer(&mut next, &sender, counter, name, key_retired, now);
        self.commit(next, vec![message, seen])?;
        Ok(Some(Received {
            server_id,
            sender: Sender::Peer { pk: sender.0 },
            received_at: listed_at,
            sent_at,
            expires_at,
            content,
        }))
    }

    /// The peer record of `pk`, looked up by its public identifier
    /// (AGENTS 22).
    pub(super) fn peer(&self, pk: &PublicKey) -> Option<&PeerRecord> {
        self.state.peers.iter().find(|peer| peer.pk.0 == pk.0)
    }

    /// A retired peer, or one of one's own old keys (step 5).
    fn is_retired(&self, pk: &PublicKey) -> bool {
        self.peer(pk).is_some_and(|peer| peer.retired_at.is_some())
            || self.state.own_old_keys.iter().any(|old| old.pk.0 == pk.0)
    }

    /// Whether an unknown key finds room: spec 026-peer-limits R2 decides,
    /// and until it does every unknown does.
    fn has_room_for(&self, _pk: &PublicKey) -> bool {
        true
    }

    /// A retained message or seen record with this `server_id` (step 6).
    pub(super) fn has_seen_server_id(&self, id: &[u8; 16]) -> bool {
        self.records.iter().any(|record| match &record.entry {
            LogEntry::Message(message) => message.server_id == Some(*id),
            LogEntry::Seen { server_id, .. } => server_id == id,
            _ => false,
        })
    }

    /// A retained seen record of this sender and counter (step 6).
    pub(super) fn has_seen_pair(&self, pk: &PublicKey, counter: u64) -> bool {
        self.records.iter().any(|record| {
            matches!(&record.entry, LogEntry::Seen { sender_pk, counter: seen, .. }
                if sender_pk.0 == pk.0 && *seen == counter)
        })
    }
}

/// What a consumed message holds: for `Received`, for the log record, and
/// its name.
fn contents(opened: envelope::Content) -> Result<(MessageContent, Content, Option<String>), Error> {
    let envelope::Content::Message(payload) = opened else {
        return Ok((MessageContent::Unreadable, Content::Unreadable, None));
    };
    Ok(match payload.kind {
        PayloadKind::Text => {
            // `validate` proved the body UTF-8.
            let body = String::from_utf8(payload.body).map_err(|_| Error::BadPayload)?;
            let content = MessageContent::Text {
                body: body.clone(),
                display_name: payload.display_name.clone(),
            };
            (
                content,
                Content::Text(Zeroizing::new(body.into_bytes())),
                payload.display_name,
            )
        }
        PayloadKind::KeyRetired => (MessageContent::KeyRetired, Content::KeyRetired, None),
        PayloadKind::Unknown(_) => (MessageContent::Unreadable, Content::Unreadable, None),
    })
}

/// The peer as spec 022-peers-tofu R1 and R2 create or update it, with
/// `max_counter = counter` (R11). A `key_retired` creates no record: spec
/// 024-key-retired says what it changes.
fn update_peer(
    next: &mut ChannelState,
    pk: &PublicKey,
    counter: u64,
    name: Option<String>,
    key_retired: bool,
    now: u64,
) {
    let name = name.map(|name| Zeroizing::new(name.into_bytes()));
    if let Some(peer) = next.peers.iter_mut().find(|peer| peer.pk.0 == pk.0) {
        peer.last_seen = now;
        peer.max_counter = Some(counter);
        if name.is_some() {
            peer.last_display_name = name;
        }
    } else if !key_retired {
        next.peers.push(PeerRecord {
            pk: *pk,
            label: None,
            verified: false,
            muted: false,
            retired_at: None,
            first_seen: now,
            last_seen: now,
            max_counter: Some(counter),
            last_display_name: name,
        });
    }
}
