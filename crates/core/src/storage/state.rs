//! The state record of `state.bin` (spec 020, "State record"): everything of
//! a channel that is not a message, decoded under `Reject` and written at its
//! exact length. The store sets the log position (R10); every other field
//! belongs to the spec named in the schema.

use zeroize::Zeroizing;

use self::items::{
    MAX_OLD_KEY, MAX_OUTBOX_ENTRY, MAX_PEER_RECORD, OldKey, OutboxEntry, PeerRecord,
};
use super::{
    DirName, ID_LEN, KEY_LEN, MAX_NAME, StorageKey, StoreError, open_box, required, seal_box,
    store_key, within,
};
use crate::crypto::Secret;
use crate::proto::config;
use crate::proto::record::{
    BOOL_LEN, Reader, U8_LEN, U32_LEN, U64_LEN, UnknownKeys, Writer, list_len, record_len,
};

pub(crate) mod items;

#[cfg(test)]
pub(super) mod tests;

/// The version of the state and log schemas, key 0 (R8).
const STATE_VERSION: u8 = 1;

/// The largest state record (Limits): 2.25 MiB.
pub(crate) const MAX_STATE_RECORD: usize = 2_359_296;

/// The most peers of a channel (spec 026-peer-limits).
pub(crate) const MAX_PEERS: usize = 550;

/// The most `outbox` entries: 31 ordinary ones and a slot kept for a
/// `key_retired` (spec 025-identity-regen).
pub(crate) const MAX_OUTBOX: usize = 32;

/// The most of one's own old keys (spec 025-identity-regen).
pub(crate) const MAX_OLD_KEYS: usize = 16;

/// The keys of the state record, in order.
const KEY_STATE_VERSION: u8 = 0;
const KEY_CHANNEL_ID: u8 = 1;
const KEY_CONFIG: u8 = 2;
const KEY_IDENTITY_SEED: u8 = 3;
const KEY_IDENTITY_EPOCH: u8 = 4;
const KEY_SEND_COUNTER: u8 = 5;
const KEY_CURSOR: u8 = 6;
const KEY_OWN_DISPLAY_NAME: u8 = 7;
const KEY_LOCAL_NAME: u8 = 8;
const KEY_PEERS: u8 = 9;
const KEY_OUTBOX: u8 = 10;
const KEY_RETIRING_SEED: u8 = 11;
const KEY_OWN_OLD_KEYS: u8 = 12;
const KEY_OWN_KEY_USED_ELSEWHERE: u8 = 13;
const KEY_READ_ONLY: u8 = 14;
const KEY_LOG_COMMITTED_LEN: u8 = 15;
const KEY_LOG_GENERATION: u8 = 16;
const KEY_SYNCED_AT: u8 = 17;
const KEY_TRUNCATED_AT: u8 = 18;

/// The state of one channel. It implements neither `Clone` nor `Debug`: it
/// holds the channel key inside `config` and one's own seeds, and
/// [`ChannelState::duplicate`] is its one deep copy.
pub struct ChannelState {
    pub(crate) channel_id: [u8; ID_LEN],
    /// The config record of spec 011-config-format without key 6; it holds
    /// `K_ch`.
    pub(crate) config: Zeroizing<Vec<u8>>,
    pub(crate) identity_seed: Secret<KEY_LEN>,
    pub(crate) identity_epoch: u32,
    /// `2^64 − 1` means exhausted.
    pub(crate) send_counter: u64,
    pub(crate) cursor: Option<u64>,
    pub(crate) own_display_name: Option<String>,
    pub(crate) local_name: Option<String>,
    pub(crate) peers: Vec<PeerRecord>,
    pub(crate) outbox: Vec<OutboxEntry>,
    pub(crate) retiring_seed: Option<Secret<KEY_LEN>>,
    pub(crate) own_old_keys: Vec<OldKey>,
    pub(crate) own_key_used_elsewhere: bool,
    pub(crate) read_only: bool,
    /// Set by the store at each seal (R10).
    pub(crate) log_committed_len: u64,
    /// Set by the store at each seal (R10).
    pub(crate) log_generation: u32,
    pub(crate) synced_at: Option<u64>,
    pub(crate) truncated_at: Option<u64>,
}

impl ChannelState {
    /// Opens the `nonce ‖ box` of a `state.bin` of directory `name`, which
    /// `store` has taken out of its framing (R4, R7).
    ///
    /// # Errors
    ///
    /// `Corrupt` for fewer than 40 bytes, a box that does not open under this
    /// directory's key, or a record that breaks the schema;
    /// `UnsupportedVersion` for a newer `state_version` (R8).
    pub fn open(
        key: &StorageKey,
        name: &DirName,
        sealed: &[u8],
    ) -> Result<ChannelState, StoreError> {
        let record = open_box(&store_key(key, name)?, sealed)?;
        ChannelState::decode(&record)
    }

    /// Seals the state of directory `name` as `nonce ‖ box`, with the log
    /// position the store gives (R4, R10).
    ///
    /// # Errors
    ///
    /// `OutboxFull` and `Corrupt` as [`ChannelState::encode`] (R27), and
    /// `Corrupt` when libsodium fails.
    pub fn seal(
        &self,
        key: &StorageKey,
        name: &DirName,
        log_len: u64,
        generation: u32,
    ) -> Result<Vec<u8>, StoreError> {
        let record = self.encode(log_len, generation)?;
        seal_box(&store_key(key, name)?, &record)
    }

    /// The committed length and the generation of the log, as the store
    /// last sealed them (R10).
    pub fn log_position(&self) -> (u64, u32) {
        (self.log_committed_len, self.log_generation)
    }

    /// The channel this state belongs to, which names its directory (R12,
    /// R18).
    pub fn channel_id(&self) -> [u8; ID_LEN] {
        self.channel_id
    }

    /// The one deep copy of a state, its secrets through
    /// `Secret::copy_from`.
    pub(crate) fn duplicate(&self) -> ChannelState {
        ChannelState {
            channel_id: self.channel_id,
            config: Zeroizing::new(self.config.to_vec()),
            identity_seed: Secret::copy_from(self.identity_seed.expose()),
            identity_epoch: self.identity_epoch,
            send_counter: self.send_counter,
            cursor: self.cursor,
            own_display_name: self.own_display_name.clone(),
            local_name: self.local_name.clone(),
            peers: self.peers.clone(),
            outbox: self.outbox.clone(),
            retiring_seed: self
                .retiring_seed
                .as_ref()
                .map(|seed| Secret::copy_from(seed.expose())),
            own_old_keys: self.own_old_keys.clone(),
            own_key_used_elsewhere: self.own_key_used_elsewhere,
            read_only: self.read_only,
            log_committed_len: self.log_committed_len,
            log_generation: self.log_generation,
            synced_at: self.synced_at,
            truncated_at: self.truncated_at,
        }
    }

    /// Decodes a state record under `Reject`, key 0 first (R8).
    ///
    /// # Errors
    ///
    /// `UnsupportedVersion` for a `state_version` other than 1, before any
    /// other key is read; `Corrupt` for any other break of the schema.
    pub(crate) fn decode(buf: &[u8]) -> Result<ChannelState, StoreError> {
        let mut reader = Reader::new(buf, MAX_STATE_RECORD, UnknownKeys::Reject)?;
        if required(reader.u8(KEY_STATE_VERSION))? != STATE_VERSION {
            return Err(StoreError::UnsupportedVersion);
        }
        let state = ChannelState {
            channel_id: *required(reader.bytes_n(KEY_CHANNEL_ID))?,
            config: Zeroizing::new(
                required(reader.bytes(KEY_CONFIG, config::MAX_RECORD))?.to_vec(),
            ),
            identity_seed: Secret::copy_from(required(reader.bytes_n(KEY_IDENTITY_SEED))?),
            identity_epoch: required(reader.u32(KEY_IDENTITY_EPOCH))?,
            send_counter: required(reader.u64(KEY_SEND_COUNTER))?,
            cursor: reader.u64(KEY_CURSOR)?,
            own_display_name: reader
                .text(KEY_OWN_DISPLAY_NAME, MAX_NAME)?
                .map(str::to_owned),
            local_name: reader.text(KEY_LOCAL_NAME, MAX_NAME)?.map(str::to_owned),
            peers: required(reader.list(
                KEY_PEERS,
                MAX_PEERS,
                MAX_PEER_RECORD,
                PeerRecord::decode,
            ))?,
            outbox: required(reader.list(
                KEY_OUTBOX,
                MAX_OUTBOX,
                MAX_OUTBOX_ENTRY,
                OutboxEntry::decode,
            ))?,
            retiring_seed: reader.bytes_n(KEY_RETIRING_SEED)?.map(Secret::copy_from),
            own_old_keys: required(reader.list(
                KEY_OWN_OLD_KEYS,
                MAX_OLD_KEYS,
                MAX_OLD_KEY,
                OldKey::decode,
            ))?,
            own_key_used_elsewhere: required(reader.bool(KEY_OWN_KEY_USED_ELSEWHERE))?,
            read_only: required(reader.bool(KEY_READ_ONLY))?,
            log_committed_len: required(reader.u64(KEY_LOG_COMMITTED_LEN))?,
            log_generation: required(reader.u32(KEY_LOG_GENERATION))?,
            synced_at: reader.u64(KEY_SYNCED_AT)?,
            truncated_at: reader.u64(KEY_TRUNCATED_AT)?,
        };
        reader.end()?;
        Ok(state)
    }

    /// Encodes the state record at its exact length (R25), with the log
    /// position the store gives (R10).
    ///
    /// # Errors
    ///
    /// `OutboxFull` for more than [`MAX_OUTBOX`] entries; `Corrupt` for any
    /// other value beyond the Limits table (R27).
    pub(crate) fn encode(
        &self,
        log_len: u64,
        generation: u32,
    ) -> Result<Zeroizing<Vec<u8>>, StoreError> {
        self.check_limits()?;
        let peers = encode_all(&self.peers, PeerRecord::encode)?;
        let outbox = encode_all(&self.outbox, OutboxEntry::encode)?;
        let own_old_keys = encode_all(&self.own_old_keys, OldKey::encode)?;
        let lens = |items: &[Zeroizing<Vec<u8>>]| list_len(items.iter().map(|item| item.len()));
        let len = record_len(&[
            Some(U8_LEN),
            Some(ID_LEN),
            Some(self.config.len()),
            Some(KEY_LEN),
            Some(U32_LEN),
            Some(U64_LEN),
            self.cursor.map(|_| U64_LEN),
            self.own_display_name.as_ref().map(String::len),
            self.local_name.as_ref().map(String::len),
            Some(lens(&peers)),
            Some(lens(&outbox)),
            self.retiring_seed.as_ref().map(|_| KEY_LEN),
            Some(lens(&own_old_keys)),
            Some(BOOL_LEN),
            Some(BOOL_LEN),
            Some(U64_LEN),
            Some(U32_LEN),
            self.synced_at.map(|_| U64_LEN),
            self.truncated_at.map(|_| U64_LEN),
        ]);
        within(len, MAX_STATE_RECORD)?;
        let mut writer = Writer::with_capacity(len);
        writer.u8(KEY_STATE_VERSION, STATE_VERSION)?;
        writer.bytes(KEY_CHANNEL_ID, &self.channel_id)?;
        writer.bytes(KEY_CONFIG, &self.config)?;
        writer.bytes(KEY_IDENTITY_SEED, self.identity_seed.expose())?;
        writer.u32(KEY_IDENTITY_EPOCH, self.identity_epoch)?;
        writer.u64(KEY_SEND_COUNTER, self.send_counter)?;
        if let Some(cursor) = self.cursor {
            writer.u64(KEY_CURSOR, cursor)?;
        }
        if let Some(name) = &self.own_display_name {
            writer.text(KEY_OWN_DISPLAY_NAME, name)?;
        }
        if let Some(name) = &self.local_name {
            writer.text(KEY_LOCAL_NAME, name)?;
        }
        writer.list(KEY_PEERS, &peers)?;
        writer.list(KEY_OUTBOX, &outbox)?;
        if let Some(seed) = &self.retiring_seed {
            writer.bytes(KEY_RETIRING_SEED, seed.expose())?;
        }
        writer.list(KEY_OWN_OLD_KEYS, &own_old_keys)?;
        writer.bool(KEY_OWN_KEY_USED_ELSEWHERE, self.own_key_used_elsewhere)?;
        writer.bool(KEY_READ_ONLY, self.read_only)?;
        writer.u64(KEY_LOG_COMMITTED_LEN, log_len)?;
        writer.u32(KEY_LOG_GENERATION, generation)?;
        if let Some(synced_at) = self.synced_at {
            writer.u64(KEY_SYNCED_AT, synced_at)?;
        }
        if let Some(truncated_at) = self.truncated_at {
            writer.u64(KEY_TRUNCATED_AT, truncated_at)?;
        }
        Ok(writer.finish())
    }
}

impl ChannelState {
    /// The bounds of the Limits table on the state's own fields and list
    /// counts, which `open` applies too (R27); each item checks its own.
    fn check_limits(&self) -> Result<(), StoreError> {
        if self.outbox.len() > MAX_OUTBOX {
            return Err(StoreError::OutboxFull);
        }
        within(self.peers.len(), MAX_PEERS)?;
        within(self.own_old_keys.len(), MAX_OLD_KEYS)?;
        within(self.config.len(), config::MAX_RECORD)?;
        let name_len = |name: &Option<String>| name.as_ref().map_or(0, String::len);
        within(name_len(&self.own_display_name), MAX_NAME)?;
        within(name_len(&self.local_name), MAX_NAME)
    }
}

/// Each item encoded on its own, for the list that holds it.
fn encode_all<T>(
    items: &[T],
    encode: fn(&T) -> Result<Zeroizing<Vec<u8>>, StoreError>,
) -> Result<Vec<Zeroizing<Vec<u8>>>, StoreError> {
    items.iter().map(encode).collect()
}
