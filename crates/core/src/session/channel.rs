//! One channel on this device (spec 021-channel-session): the state and the
//! log records of the last commit, the in-session values beside them, and
//! the one commit every change goes through (R1, R2, AGENTS 23).
//!
//! Sending, receiving, the `outbox` and the reads are the later slices of
//! spec 021; the peers, the message list, retirement, regeneration and the
//! peer limits are specs 022–026's.

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

use super::expiry::ExpiryIndex;
use crate::crypto::{self, Secret};
use crate::error::Error;
use crate::proto::config::Config;
use crate::proto::envelope::{EXPIRY_MARGIN_MS, ttl_ms};
use crate::storage::state::items::{OutboxEntry, OutboxKind};
use crate::storage::{ChannelState, DirName, LogRecord, Store, StoreError, WriteBatch};

mod headroom;
mod outbox;
mod own_key;
mod receive;
mod send;
mod status;
mod sync;

#[cfg(test)]
mod tests;

/// The minute of grace an entry in flight gets for its `ack` (R22).
const ACK_GRACE_MS: u64 = 60_000;

/// A peer's `pk_u` (`docs/spec.md` §9); used by specs 022–027.
pub type PeerId = [u8; 32];

/// The identifier of one `outbox` entry, used for every publish of it
/// (R8): public, compared as a map key (AGENTS 22).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ClientRef {
    /// 16 bytes from `random_bytes`.
    pub bytes: [u8; 16],
}

/// Who sent a message (R12, spec 023-ttl-purge).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sender {
    /// Another member.
    Peer {
        /// The sender's `pk_u`.
        pk: PeerId,
    },
    /// This device.
    Own,
    /// One's own key, sealed on another device (R14).
    OwnKeyElsewhere {
        /// One's own `pk_u`.
        pk: PeerId,
    },
}

/// What a received message holds (R12). No `Display`, and a `Debug` that
/// names the variant alone: it is content (AGENTS 19).
#[derive(PartialEq, Eq)]
pub enum MessageContent {
    /// A text and the name it was signed with.
    Text {
        /// The text.
        body: String,
        /// The sender's name, when it gave one.
        display_name: Option<String>,
    },
    /// The sender retired its key (spec 024-key-retired).
    KeyRetired,
    /// A message this version cannot read.
    Unreadable,
}

/// A message `decrypt` consumed and listed (R12); its `Debug` hides the
/// content.
#[derive(Debug, PartialEq, Eq)]
pub struct Received {
    /// The server's identifier.
    pub server_id: [u8; 16],
    /// Who sent it.
    pub sender: Sender,
    /// The time it is listed at (R11).
    pub received_at: u64,
    /// The signed send time, when it could be read.
    pub sent_at: Option<u64>,
    /// When it leaves the screen (R26).
    pub expires_at: u64,
    /// What it holds.
    pub content: MessageContent,
}

impl fmt::Debug for MessageContent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            MessageContent::Text { .. } => "Text([REDACTED])",
            MessageContent::KeyRetired => "KeyRetired",
            MessageContent::Unreadable => "Unreadable",
        })
    }
}

/// What became of a message this device sent (R16, R17, R22).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AckOutcome {
    /// The server stored it in time for receivers to show it.
    Delivered,
    /// It was not stored, or not in time: it failed.
    NotDelivered,
    /// The `key_retired` was stored (spec 025-identity-regen).
    RetirementDelivered,
    /// An `ack` for no current `outbox` entry.
    Ignored,
}

/// The outcome of one entry and its times, from which spec
/// 028-session-sans-io builds its event (R17).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Outcome {
    pub(crate) client_ref: ClientRef,
    pub(crate) outcome: AckOutcome,
    /// The server's identifier of an acknowledged message.
    pub(crate) server_id: Option<[u8; 16]>,
    /// The time an `ack` is listed at, clamped (R17).
    pub(crate) received_at: Option<u64>,
    /// `None` only for an unknown `client_ref`.
    pub(crate) sent_at: Option<u64>,
}

/// What `outbox` hands out and what it removed (R22).
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct OutboxStep {
    /// The entries to publish, in `outbox` order.
    pub(crate) publish: Vec<(ClientRef, Vec<u8>)>,
    /// The entries removed as not delivered, with their `sent_at`.
    pub(crate) not_delivered: Vec<(ClientRef, u64)>,
}

/// The messages missing from one sender in this session (R24).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Gap {
    /// The sender.
    pub peer: PeerId,
    /// How many counters were skipped.
    pub missing: u64,
    /// A single skip above `2^32`.
    pub anomalous: bool,
    /// Counted across a truncation of the history.
    pub spans_truncation: bool,
}

/// The in-session values a reopen of the same channel keeps (R1, spec
/// 027-core-api R14): read from the dropped `Channel` and copied onto the
/// new one, committing nothing.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct SessionCarry {
    /// Per sender, keyed by its public key (AGENTS 22).
    gaps: BTreeMap<PeerId, Gap>,
    /// The ignored keys of spec 026-peer-limits R6.
    ignored_keys: BTreeSet<PeerId>,
    /// The device-clock warning of R25.
    clock_off: ClockOff,
}

/// Whether the device clock looks off, and which kind of sample said so
/// (R25): a backlog sample clears only a flag a backlog sample set.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum ClockOff {
    #[default]
    No,
    /// Set by a live sample.
    Live,
    /// Set by a backlog sample with this `received_at`.
    Backlog(u64),
}

/// What a client shows about a channel (R25).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChannelStatus {
    /// Another device used one's own key (R14).
    pub own_key_used_elsewhere: bool,
    /// One's own key was retired elsewhere (spec 024-key-retired).
    pub read_only: bool,
    /// A `key_retired` is pending (spec 025-identity-regen R6).
    pub retirement_pending: bool,
    /// The log headroom of R18 is missing.
    pub storage_full: bool,
    /// Distinct keys refused or evicted in this session (spec
    /// 026-peer-limits R6).
    pub ignored_keys: u32,
    /// A new key would be refused (spec 026-peer-limits R6).
    pub unknown_limit_reached: bool,
    /// The labelled budget is spent (spec 026-peer-limits R6).
    pub labelled_limit_reached: bool,
    /// The device clock differs from the server's (R25).
    pub clock_off: bool,
    /// Messages before this time may be missing (R24, R25).
    pub truncated_before: Option<u64>,
}

/// One channel and its store. It implements neither `Clone` nor `Debug`:
/// its state holds the channel key and one's own seed.
pub(crate) struct Channel {
    store: Box<dyn Store>,
    /// Decoded once from `state.config`.
    config: Config,
    /// The state of the last successful commit.
    state: ChannelState,
    /// The log records of the last successful commit, in log order.
    records: Vec<LogRecord>,
    /// `(purge_at, entry length)` of `records` (R1).
    expiry: ExpiryIndex,
    /// The cursor, `synced_at` and `truncated_at` as they stand, committed
    /// or not; every commit writes them (R20, R24).
    cursor: Option<u64>,
    synced_at: Option<u64>,
    truncated_at: Option<u64>,
    carry: SessionCarry,
    /// The outcomes queued for `take_outcomes` (R1).
    outcomes: Vec<Outcome>,
    /// The `now` of the last compaction attempt (R18).
    last_compaction: Option<u64>,
    /// The `now` of the latest call that took one (R25).
    latest_now: Option<u64>,
}

impl Channel {
    /// The channel of `config` in `store`: the stored one, and `false`, when
    /// the store holds it, or a new one with a fresh identity, and `true`
    /// (R4, R5).
    ///
    /// # Errors
    ///
    /// `ConfigMismatch` for a stored channel of another `channel_id` or
    /// another server; `Internal` when libsodium fails; the errors of
    /// [`Channel::open_stored`] for a stored channel and `Store` for a
    /// failed first commit.
    pub(crate) fn create(
        config: &Config,
        mut store: Box<dyn Store>,
    ) -> Result<(Channel, bool), Error> {
        if let Some(loaded) = store.load()? {
            let channel = Channel::loaded(store, loaded)?;
            // `docs/spec.md` §5: a channel has one server, whichever config
            // names it first.
            let same = crypto::ct_eq(&channel.state.channel_id, &config.channel_id())
                && channel.config.server_url() == config.server_url();
            if !same {
                return Err(Error::ConfigMismatch);
            }
            return Ok((channel, false));
        }
        let batch = WriteBatch::new(first_state(config)?, Vec::new());
        store.commit(&batch)?;
        let (state, records) = batch.into_parts();
        Ok((
            Channel::new(store, config.duplicate(), state, records),
            true,
        ))
    }

    /// The channel `store` holds (R6).
    ///
    /// # Errors
    ///
    /// `Store(Corrupt)` for an empty store or a stored config that does not
    /// decode, `Store(UnsupportedVersion)` for one of a newer app, and any
    /// error of the load.
    pub(crate) fn open_stored(mut store: Box<dyn Store>) -> Result<Channel, Error> {
        let loaded = store.load()?.ok_or(Error::Store(StoreError::Corrupt))?;
        Channel::loaded(store, loaded)
    }

    /// The stored config (R6).
    pub(crate) fn config(&self) -> &Config {
        &self.config
    }

    /// The store's directory (R6).
    pub(crate) fn dir_name(&self) -> &DirName {
        self.store.name()
    }

    /// The gaps, ignored keys and `clock_off` of this session, read before
    /// the channel is dropped (R1).
    pub(crate) fn session_carry(&self) -> SessionCarry {
        self.carry.clone()
    }

    /// Takes on the values of a dropped instance of this channel, over the
    /// reset of the load (R1).
    pub(crate) fn carry_session(&mut self, carry: SessionCarry) {
        self.carry = carry;
    }

    /// A channel over what `store` loaded, its config decoded once (R6).
    fn loaded(
        store: Box<dyn Store>,
        (state, records): (ChannelState, Vec<LogRecord>),
    ) -> Result<Channel, Error> {
        // A stored config has no `invite_expires_at` (R4), so `now` is not read.
        let config = Config::parse(&state.config, 0).map_err(|error| match error {
            Error::UnsupportedVersion => Error::Store(StoreError::UnsupportedVersion),
            _ => Error::Store(StoreError::Corrupt),
        })?;
        Ok(Channel::new(store, config, state, records))
    }

    /// A channel of a committed state, with the in-session values of a
    /// fresh load (R1).
    fn new(
        store: Box<dyn Store>,
        config: Config,
        state: ChannelState,
        records: Vec<LogRecord>,
    ) -> Channel {
        Channel {
            expiry: ExpiryIndex::of(&records),
            cursor: state.cursor,
            synced_at: state.synced_at,
            truncated_at: state.truncated_at,
            store,
            config,
            state,
            records,
            carry: SessionCarry::default(),
            outcomes: Vec::new(),
            last_compaction: None,
            latest_now: None,
        }
    }

    /// A copy of the committed state carrying the in-session values every
    /// commit writes: the base of every batch (R2, R20).
    fn next_state(&self) -> ChannelState {
        let mut state = self.state.duplicate();
        state.cursor = self.cursor;
        state.synced_at = self.synced_at;
        state.truncated_at = self.truncated_at;
        state
    }

    /// `ttl_ms` of the channel (R21).
    fn ttl_ms(&self) -> u64 {
        ttl_ms(self.config.ttl_seconds())
    }

    /// The `purge_at` of one's own message, and of its acked or
    /// not-delivered record (R26): reported not delivered at the latest
    /// moment R22 allows, it stays visible as failed one more TTL.
    fn own_purge_at(&self, sent_at: u64) -> u64 {
        sent_at
            .saturating_add(self.ttl_ms().saturating_mul(2))
            .saturating_add(EXPIRY_MARGIN_MS)
            .saturating_add(ACK_GRACE_MS)
    }

    /// The `outbox` entries that are not the `key_retired`.
    fn ordinary_outbox(&self) -> impl Iterator<Item = &OutboxEntry> {
        self.state
            .outbox
            .iter()
            .filter(|entry| entry.kind == OutboxKind::Text)
    }

    /// Commits `state` and `records` once and moves them into memory only
    /// after `Ok`; on `Err` memory keeps the previous copy (R2).
    fn commit(&mut self, state: ChannelState, records: Vec<LogRecord>) -> Result<(), Error> {
        let batch = WriteBatch::new(state, records);
        self.store.commit(&batch)?;
        let (state, records) = batch.into_parts();
        self.expiry.extend(&records);
        self.records.extend(records);
        self.state = state;
        Ok(())
    }
}

/// The first state of a new channel (R4): a fresh identity, nothing sent or
/// seen, and the config without `invite_expires_at`.
fn first_state(config: &Config) -> Result<ChannelState, Error> {
    Ok(ChannelState {
        channel_id: config.channel_id(),
        config: config.record(None)?,
        identity_seed: Secret::random()?,
        identity_epoch: 0,
        send_counter: 0,
        cursor: None,
        own_display_name: None,
        local_name: None,
        peers: Vec::new(),
        outbox: Vec::new(),
        retiring_seed: None,
        own_old_keys: Vec::new(),
        own_key_used_elsewhere: false,
        read_only: false,
        log_committed_len: 0,
        log_generation: 0,
        synced_at: None,
        truncated_at: None,
    })
}
