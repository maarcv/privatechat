//! Sending (spec 021 R7, R8, R33): the counter is committed with the
//! sealed copy before the blob can leave (`docs/spec.md` §4 "Send
//! counter"), and the blob leaves only through `outbox()`.

use zeroize::Zeroizing;

use super::{Channel, ClientRef};
use crate::crypto::{self, Nonce, Signature};
use crate::error::Error;
use crate::proto::envelope::{self, ChannelCtx, SenderKey};
use crate::proto::payload::{Payload, PayloadKind};
use crate::storage::state::MAX_OUTBOX;
use crate::storage::state::items::{OutboxEntry, OutboxKind};
use crate::storage::{Content, LogEntry, LogRecord, Message, StoreError};

/// The ordinary entries an `outbox` holds; its last slot is kept for a
/// `key_retired` (spec 020-store-files).
const MAX_ORDINARY_OUTBOX: usize = MAX_OUTBOX - 1;

/// A send counter with no value left (spec 020-store-files).
const EXHAUSTED: u64 = u64::MAX;

/// `sent_at` is a whole minute (spec 013-wire-message R8).
const MINUTE_MS: u64 = 60_000;

/// The whole minute of `now`, a blob's `sent_at` (spec 013-wire-message
/// R8).
pub(super) fn minute_of(now: u64) -> u64 {
    now.saturating_sub(now % MINUTE_MS)
}

impl Channel {
    /// Seals `body` with the next counter and commits the counter, the
    /// `outbox` entry and one's own log record in one commit (R7, R8).
    /// `display_name`: `Some("")` clears the stored name, `None` keeps it.
    ///
    /// # Errors
    ///
    /// In this order, each committing nothing: `RetiredKey` for a
    /// read-only channel, `CounterExhausted`, `Store(OutboxFull)` with 31
    /// ordinary entries, the headroom's errors (R18), `BadPayload` for a
    /// body or a name the payload refuses; then `Internal` when libsodium
    /// fails and `Store` when the commit does.
    pub(crate) fn encrypt(
        &mut self,
        body: &str,
        display_name: Option<&str>,
        now: u64,
    ) -> Result<ClientRef, Error> {
        self.latest_now = Some(now);
        if self.state.read_only {
            return Err(Error::RetiredKey);
        }
        let counter = self.state.send_counter;
        if counter == EXHAUSTED {
            return Err(Error::CounterExhausted);
        }
        if self.ordinary_outbox().count() >= MAX_ORDINARY_OUTBOX {
            return Err(Error::Store(StoreError::OutboxFull));
        }
        self.check_headroom(now)?;
        let display_name = match display_name {
            Some("") => None,
            Some(name) => Some(name.to_owned()),
            None => self.state.own_display_name.clone(),
        };
        let payload = Payload {
            kind: PayloadKind::Text,
            display_name,
            sent_at: minute_of(now),
            body: body.as_bytes().to_vec(),
        };
        let sender = SenderKey::from_seed(&self.state.identity_seed)?;
        let nonce = Nonce(crypto::random_bytes()?);
        let ctx = ChannelCtx::from_config(&self.config)?;
        let sealed = envelope::seal(&ctx, &sender, counter, &nonce, &payload)?;
        let client_ref = ClientRef {
            bytes: crypto::random_bytes()?,
        };
        let mut next = self.next_state();
        next.send_counter = counter.saturating_add(1);
        next.own_display_name.clone_from(&payload.display_name);
        next.outbox.push(OutboxEntry {
            client_ref: client_ref.bytes,
            kind: OutboxKind::Text,
            sent_at: payload.sent_at,
            blob: sealed.blob,
            signature: Signature(sealed.signature),
            under_retired_key: false,
            counter,
        });
        let record = LogRecord {
            purge_at: self.own_purge_at(payload.sent_at),
            entry: LogEntry::Message(Message {
                server_id: None,
                received_at: now,
                sender_pk: *sender.public(),
                counter,
                content: Content::Text(Zeroizing::new(payload.body)),
                display_name: payload
                    .display_name
                    .map(|name| Zeroizing::new(name.into_bytes())),
                sent_at: Some(payload.sent_at),
                own_client_ref: Some(client_ref.bytes),
            }),
        };
        self.commit(next, vec![record])?;
        Ok(client_ref)
    }

    /// The current send counter (R33).
    pub(crate) fn send_counter(&self) -> u64 {
        self.state.send_counter
    }

    /// The `ClientRef` of the ordinary `outbox` entry sealed with
    /// `counter`, if it is still waiting (R33).
    pub(crate) fn outbox_ref(&self, counter: u64) -> Option<ClientRef> {
        self.ordinary_outbox()
            .find(|entry| entry.counter == counter)
            .map(ClientRef::of)
    }
}
