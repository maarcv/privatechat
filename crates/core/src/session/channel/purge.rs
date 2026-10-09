//! The message list of spec 023-ttl-purge (R1–R3, R7): every message
//! still on screen, in the order of its display time, with one's own
//! folded with its fate; and the purge that removes expired records from
//! the disk, and when it is due (R4, R5).

use core::fmt;
use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};

use super::peers::Claimable;
use super::{ACK_GRACE_MS, Channel, ClientRef, MessageContent, PeerId, Sender, key_prefix};
use crate::crypto::PublicKey;
use crate::error::Error;
use crate::proto::envelope::SenderKey;
use crate::session::names::shown_name;
use crate::storage::{Content, LogEntry, LogRecord, Message as Stored};

/// A rewrite of the log is due once expired records take this fraction of
/// it, the inverse of a quarter (R5).
const DUE_FRACTION: u64 = 4;

/// Or once the oldest expired record expired this long ago (R5).
const DUE_AFTER_MS: u64 = 86_400_000;

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
/// unknown one (R3). Its `Debug` shows the claims alone, a key by its
/// 4-byte prefix: the 4 words are 44 bits of the key's fingerprint.
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
            .field(
                "claims_name_of",
                &self.claims_name_of.as_ref().map(|pk| key_prefix(pk)),
            )
            .field("claims_own_name", &self.claims_own_name)
            .finish_non_exhaustive()
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
    /// With the log position of the acked record, where a delivered row
    /// stands among rows of the same display time (R2).
    Acked {
        server_id: [u8; 16],
        received_at: u64,
        position: usize,
    },
    NotDelivered,
}

/// What a row is built against, read once per call.
struct Context {
    now: u64,
    ttl_ms: u64,
    /// How long after its `sent_at` a pending message can still be
    /// acknowledged: one TTL, the margin and the grace minute of spec
    /// 021-channel-session R22.
    pending_for: u64,
    /// One's own current `pk_u` and old keys (R3); an own row needs none.
    own_keys: BTreeSet<PeerId>,
    fates: BTreeMap<[u8; 16], Fate>,
}

impl Channel {
    /// Every message whose display expiry is not below `now`, in display
    /// order with ties in log order (R1–R3); commits nothing.
    ///
    /// # Errors
    ///
    /// `Internal` when libsodium fails.
    pub(crate) fn messages(&self, now: u64) -> Result<Vec<Message>, Error> {
        let own = SenderKey::from_seed(&self.state.identity_seed)?;
        let old = self.state.own_old_keys.iter().map(|old| old.pk.0);
        let context = Context {
            own_keys: core::iter::once(own.public().0).chain(old).collect(),
            fates: self.fates().collect(),
            ..self.context(now)
        };
        let claimable = self.claimable();
        let known: BTreeSet<PeerId> = self.state.peers.iter().map(|peer| peer.pk.0).collect();
        // One fingerprint per stranger, however many rows it has.
        let mut shorts: BTreeMap<PeerId, Vec<String>> = BTreeMap::new();
        let mut rows = Vec::new();
        for (position, purge_at, stored) in self.stored_messages() {
            let Some((position, mut row)) = row(stored, purge_at, position, &context) else {
                continue;
            };
            if let Sender::Peer { pk } = row.sender
                && !known.contains(&pk)
            {
                let short = match shorts.entry(pk) {
                    Entry::Occupied(entry) => entry.get().clone(),
                    Entry::Vacant(entry) => {
                        let short = self.short(&PublicKey(pk))?.map(str::to_owned).to_vec();
                        entry.insert(short).clone()
                    }
                };
                row.stranger = Some(stranger(short, stored, &claimable));
            }
            rows.push((position, row));
        }
        rows.sort_by_key(|(position, row)| (row.received_at, *position));
        Ok(rows.into_iter().map(|(_, row)| row).collect())
    }

    /// The row of one's own message with `client_ref`, from its record and
    /// its one delivery record alone, while it is listed (R7). It cannot
    /// fail: an own row needs no key and computes no stranger.
    pub(crate) fn message(&self, client_ref: ClientRef, now: u64) -> Option<Message> {
        let (position, purge_at, stored) = self
            .stored_messages()
            .find(|(_, _, stored)| stored.own_client_ref == Some(client_ref.bytes))?;
        let context = Context {
            fates: self
                .fates()
                .filter(|(named, _)| *named == client_ref.bytes)
                .collect(),
            ..self.context(now)
        };
        row(stored, purge_at, position, &context).map(|(_, row)| row)
    }

    /// Removes every record whose `purge_at` is below `now` from the disk
    /// and from memory, whatever the amount expired, and returns the number
    /// of message records removed (R4); with nothing expired, it touches
    /// no store.
    ///
    /// # Errors
    ///
    /// The compaction's `Store` error, memory left as it was and the
    /// attempt recorded (spec 020-store-files R11).
    pub(crate) fn purge_expired(&mut self, now: u64) -> Result<u32, Error> {
        self.latest_now = Some(now);
        if self
            .expiry
            .oldest_expiry()
            .is_none_or(|oldest| oldest >= now)
        {
            return Ok(0);
        }
        let removed = self.compact_at(now)?;
        Ok(u32::try_from(removed).unwrap_or(u32::MAX))
    }

    /// Whether `purge_expired` is due (R5): expired records take a quarter
    /// of the log or the oldest expired a day ago, and the last compaction
    /// attempt is ten minutes old, so that a rewrite frees at least a
    /// quarter of what it writes and a failing one is retried at most every
    /// ten minutes. An attempt recorded later than `now` holds nothing off.
    pub(crate) fn purge_due(&self, now: u64) -> bool {
        let held_off = self.compaction_held_off(now);
        let expired = self.expiry.expired_bytes(now);
        let quarter = expired.saturating_mul(DUE_FRACTION) >= self.store.log_len();
        let day_old = self
            .expiry
            .oldest_expiry()
            .is_some_and(|oldest| oldest.saturating_add(DUE_AFTER_MS) < now);
        !held_off && (quarter || day_old)
    }

    /// The message records of the log, with their log position and
    /// `purge_at`.
    fn stored_messages(&self) -> impl Iterator<Item = (usize, u64, &Stored)> {
        self.records
            .iter()
            .enumerate()
            .filter_map(|(position, record)| match &record.entry {
                LogEntry::Message(stored) => Some((position, record.purge_at(), stored)),
                _ => None,
            })
    }

    /// The fate of every own message a delivery record names.
    fn fates(&self) -> impl Iterator<Item = ([u8; 16], Fate)> {
        self.records
            .iter()
            .enumerate()
            .filter_map(|(position, record)| record.fate(position))
    }

    /// A `Context` with no own key and no fate, what an own row needs
    /// beside its fate.
    fn context(&self, now: u64) -> Context {
        Context {
            now,
            ttl_ms: self.ttl_ms(),
            pending_for: self.accept_window().saturating_add(ACK_GRACE_MS),
            own_keys: BTreeSet::new(),
            fates: BTreeMap::new(),
        }
    }
}

impl LogRecord {
    /// The own message a delivery record at `position` names, and its fate.
    fn fate(&self, position: usize) -> Option<([u8; 16], Fate)> {
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
                    position,
                },
            )),
            LogEntry::NotDelivered { client_ref } => Some((client_ref, Fate::NotDelivered)),
            _ => None,
        }
    }
}

/// The row of `stored`, at log `position`, or `None` once its display
/// expiry is below `now` (R1, R3), with the position it is ordered by among
/// rows of the same display time (R2); a stranger is the caller's.
fn row(
    stored: &Stored,
    purge_at: u64,
    position: usize,
    context: &Context,
) -> Option<(usize, Message)> {
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
    let fate = own_client_ref.and_then(|client_ref| context.fates.get(&client_ref.bytes));
    if own_client_ref.is_some() {
        fold_fate(&mut row, fate, context);
    }
    // A delivered row stands where its `ack` was written.
    let position = match fate {
        Some(Fate::Acked { position, .. }) => *position,
        _ => position,
    };
    (row.expires_at >= context.now).then_some((position, row))
}

/// Folds one's own message with its delivery record (R1–R3): delivered, it
/// is listed at its `ack` and leaves the screen one TTL after its
/// `sent_at` (ADR 0044); otherwise it stays, as failed, until its
/// `purge_at`.
fn fold_fate(row: &mut Message, fate: Option<&Fate>, context: &Context) {
    let sent_at = row.sent_at.unwrap_or(row.received_at);
    row.delivery = Some(match fate {
        Some(Fate::Acked {
            server_id,
            received_at,
            ..
        }) => {
            row.server_id = Some(*server_id);
            row.received_at = *received_at;
            row.expires_at = sent_at.saturating_add(context.ttl_ms);
            Delivery::Delivered
        }
        Some(Fate::NotDelivered) => Delivery::NotDelivered,
        None => {
            if sent_at.saturating_add(context.pending_for) < context.now {
                Delivery::NotDelivered
            } else {
                Delivery::Pending
            }
        }
    });
}

/// The sender of `stored`, which has no record, with its 4 words and the
/// claims of its name (R3).
fn stranger(short: Vec<String>, stored: &Stored, claimable: &Claimable) -> Stranger {
    let name = stored
        .display_name
        .as_deref()
        .and_then(|name| core::str::from_utf8(name).ok());
    let (claims_name_of, claims_own_name) =
        name.map_or((None, false), |name| claimable.claims(name));
    Stranger {
        short,
        claims_name_of,
        claims_own_name,
    }
}

/// What a stored message holds, as a client reads it; a body that is not
/// UTF-8, which `validate` makes impossible, reads as unreadable.
pub(super) fn content_of(stored: &Stored) -> MessageContent {
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
