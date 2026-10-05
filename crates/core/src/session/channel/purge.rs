//! The message list of spec 023-ttl-purge (R1–R3, R7): every message
//! still on screen, in the order of its display time, with one's own
//! folded with its fate.

use core::fmt;
use std::collections::BTreeMap;

use super::peers::Claimable;
use super::{Channel, ClientRef, MessageContent, PeerId, Sender, key_prefix};
use crate::crypto::PublicKey;
use crate::error::Error;
use crate::proto::envelope::SenderKey;
use crate::session::names::shown_name;
use crate::storage::{Content, LogEntry, LogRecord, Message as Stored};

/// The margin and the grace minute of spec 021-channel-session R22 beyond
/// one TTL: after them, a pending message can no longer be acknowledged.
const PENDING_FOR_MS: u64 = 420_000;

/// The fate of one's own message (R3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Delivery {
    /// Not acknowledged yet, and still in time to be.
    Pending,
    /// Stored by the server in time for receivers to show it.
    Delivered,
    /// Not stored, or not in time.
    NotDelivered,
}

/// The sender of a message that has no peer record, presented as an
/// unknown one (R3). Its `Debug` shows the 4-byte prefix of a key.
#[derive(Clone, PartialEq, Eq)]
pub struct Stranger {
    /// The 4 words of spec 014-fingerprint.
    pub short: Vec<String>,
    /// The first seen peer whose label the message's name collides with
    /// (spec 022-peers-tofu R13).
    pub claims_name_of: Option<PeerId>,
    /// The message's name collides with one's own.
    pub claims_own_name: bool,
}

impl fmt::Debug for Stranger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Stranger")
            .field("short", &self.short)
            .field(
                "claims_name_of",
                &self.claims_name_of.as_ref().map(key_prefix),
            )
            .field("claims_own_name", &self.claims_own_name)
            .finish()
    }
}

/// A message as a client paints it (R3); its `Debug` hides the content.
#[derive(Debug, PartialEq, Eq)]
pub struct Message {
    /// The server's identifier, once known.
    pub server_id: Option<[u8; 16]>,
    /// For one's own message, the identifier of its `outbox` entry.
    pub client_ref: Option<ClientRef>,
    /// Who sent it.
    pub sender: Sender,
    /// Its display time, by which the list is ordered (R2).
    pub received_at: u64,
    /// The signed send time, when it could be read.
    pub sent_at: Option<u64>,
    /// When it leaves the screen (R1).
    pub expires_at: u64,
    /// What it holds, its name cleaned (spec 022-peers-tofu R6).
    pub content: MessageContent,
    /// For one's own message, its fate.
    pub delivery: Option<Delivery>,
    /// For a sender with no peer record.
    pub stranger: Option<Stranger>,
}

/// What a delivery record says of one's own message.
#[derive(Clone, Copy)]
enum Fate {
    Acked {
        server_id: [u8; 16],
        received_at: u64,
    },
    NotDelivered,
}

/// What a row is built against, read once per call.
struct Context<'a> {
    now: u64,
    ttl_ms: u64,
    /// One's own current `pk_u` and old keys (R3).
    own_keys: Vec<[u8; 32]>,
    fates: BTreeMap<[u8; 16], Fate>,
    claimable: Option<&'a Claimable>,
}

impl Channel {
    /// Every message whose display expiry is not below `now`, in display
    /// order with ties in log order (R1–R3); commits nothing.
    ///
    /// # Errors
    ///
    /// `Internal` when libsodium fails.
    pub(crate) fn messages(&self, now: u64) -> Result<Vec<Message>, Error> {
        let claimable = self.claimable();
        let context = Context {
            claimable: Some(&claimable),
            fates: self.fates(),
            ..self.context(now)?
        };
        let mut rows = Vec::new();
        for (purge_at, stored) in self.stored_messages() {
            if let Some(row) = self.row(stored, purge_at, &context)? {
                rows.push(row);
            }
        }
        // Stable: the records are in log order.
        rows.sort_by_key(|row| row.received_at);
        Ok(rows)
    }

    /// The row of one's own message with `client_ref`, built without the
    /// rest of the list, while it is listed (R7).
    pub(crate) fn message(&self, client_ref: ClientRef, now: u64) -> Option<Message> {
        let context = Context {
            fates: self.fates(),
            ..self.context(now).ok()?
        };
        let (purge_at, stored) = self
            .stored_messages()
            .find(|(_, stored)| stored.own_client_ref == Some(client_ref.bytes))?;
        // An own row computes no stranger, so it cannot fail.
        self.row(stored, purge_at, &context).ok().flatten()
    }

    /// The message records of the log, with their `purge_at`.
    fn stored_messages(&self) -> impl Iterator<Item = (u64, &Stored)> {
        self.records
            .iter()
            .filter_map(|record| match &record.entry {
                LogEntry::Message(stored) => Some((record.purge_at(), stored)),
                _ => None,
            })
    }

    /// The fate of every own message a delivery record names.
    fn fates(&self) -> BTreeMap<[u8; 16], Fate> {
        self.records.iter().filter_map(LogRecord::fate).collect()
    }

    /// The parts of a `Context` that every call reads.
    fn context(&self, now: u64) -> Result<Context<'static>, Error> {
        let own = SenderKey::from_seed(&self.state.identity_seed)?;
        let old = self.state.own_old_keys.iter().map(|old| old.pk.0);
        Ok(Context {
            now,
            ttl_ms: self.ttl_ms(),
            own_keys: core::iter::once(own.public().0).chain(old).collect(),
            fates: BTreeMap::new(),
            claimable: None,
        })
    }

    /// The row of `stored`, or `None` once its display expiry is below
    /// `now` (R1, R3).
    fn row(
        &self,
        stored: &Stored,
        purge_at: u64,
        context: &Context<'_>,
    ) -> Result<Option<Message>, Error> {
        let pk = stored.sender_pk.0;
        let own_client_ref = stored.own_client_ref.map(|bytes| ClientRef { bytes });
        // Public keys, compared as lookups (AGENTS 22).
        let sender = if own_client_ref.is_some() {
            Sender::Own
        } else if context.own_keys.contains(&pk) {
            Sender::OwnKeyElsewhere { pk }
        } else {
            Sender::Peer { pk }
        };
        let mut row = Message {
            server_id: stored.server_id,
            client_ref: own_client_ref,
            sender,
            received_at: stored.received_at,
            sent_at: stored.sent_at,
            expires_at: purge_at,
            content: content_of(stored),
            delivery: None,
            stranger: None,
        };
        if let Some(client_ref) = own_client_ref {
            Channel::fold_fate(&mut row, context.fates.get(&client_ref.bytes), context);
        }
        if row.expires_at < context.now {
            return Ok(None);
        }
        if let (Sender::Peer { pk }, Some(claimable)) = (sender, context.claimable)
            && self.peer(&PublicKey(pk)).is_none()
        {
            row.stranger = Some(self.stranger(pk, stored, claimable)?);
        }
        Ok(Some(row))
    }

    /// Folds one's own message with its delivery record (R1–R3): delivered,
    /// it is listed at its `ack` and leaves the screen one TTL after its
    /// `sent_at` (ADR 0044); otherwise it stays, as failed, until its
    /// `purge_at`.
    fn fold_fate(row: &mut Message, fate: Option<&Fate>, context: &Context<'_>) {
        let sent_at = row.sent_at.unwrap_or(row.received_at);
        row.delivery = Some(match fate {
            Some(Fate::Acked {
                server_id,
                received_at,
            }) => {
                row.server_id = Some(*server_id);
                row.received_at = *received_at;
                row.expires_at = sent_at.saturating_add(context.ttl_ms);
                Delivery::Delivered
            }
            Some(Fate::NotDelivered) => Delivery::NotDelivered,
            None => {
                let window = context.ttl_ms.saturating_add(PENDING_FOR_MS);
                if sent_at.saturating_add(window) < context.now {
                    Delivery::NotDelivered
                } else {
                    Delivery::Pending
                }
            }
        });
    }

    /// The short identifier and claims of a sender with no record (R3).
    fn stranger(
        &self,
        pk: PeerId,
        stored: &Stored,
        claimable: &Claimable,
    ) -> Result<Stranger, Error> {
        let name = stored
            .display_name
            .as_deref()
            .and_then(|name| core::str::from_utf8(name).ok());
        let (claims_name_of, claims_own_name) =
            name.map_or((None, false), |name| claimable.claims(name));
        Ok(Stranger {
            short: self.short(&PublicKey(pk))?.map(str::to_owned).to_vec(),
            claims_name_of,
            claims_own_name,
        })
    }
}

impl LogRecord {
    /// The own message a delivery record names, and its fate.
    fn fate(&self) -> Option<([u8; 16], Fate)> {
        match self.entry {
            LogEntry::Acked {
                server_id,
                received_at,
                client_ref,
            } => Some((
                client_ref,
                Fate::Acked {
                    server_id,
                    received_at,
                },
            )),
            LogEntry::NotDelivered { client_ref } => Some((client_ref, Fate::NotDelivered)),
            _ => None,
        }
    }
}

/// What a stored message holds, as a client reads it; a body that is not
/// UTF-8, which `validate` makes impossible, reads as unreadable.
fn content_of(stored: &Stored) -> MessageContent {
    match &stored.content {
        Content::Text(body) => match core::str::from_utf8(body) {
            Ok(body) => MessageContent::Text {
                body: body.to_owned(),
                display_name: stored
                    .display_name
                    .as_deref()
                    .and_then(|name| core::str::from_utf8(name).ok())
                    .and_then(shown_name),
            },
            Err(_) => MessageContent::Unreadable,
        },
        Content::KeyRetired => MessageContent::KeyRetired,
        Content::Unreadable => MessageContent::Unreadable,
    }
}
