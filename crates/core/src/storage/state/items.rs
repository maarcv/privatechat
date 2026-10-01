//! The items of the three lists of the state record (spec 020, "State
//! record"): a peer, an `outbox` entry and one's own old key. Each is a
//! record of its own schema, decoded under `Reject` and written at its exact
//! length; what the fields mean belongs to specs 021, 022 and 025.

use zeroize::Zeroizing;

use super::super::{ID_LEN, KEY_LEN, MAX_NAME, SIGNATURE_LEN, StoreError, required, within};
use crate::crypto::{PublicKey, Signature};
use crate::proto::envelope::BLOB_OVERHEAD;
use crate::proto::payload::{MAX_BLOCKS, PAD_BLOCK};
use crate::proto::record::{
    BOOL_LEN, FIELD_HEADER_LEN, Reader, U8_LEN, U64_LEN, UnknownKeys, Writer, record_len,
};

/// The largest sealed blob, of 63 padding blocks (spec 013-wire-message):
/// 64 673 bytes.
pub(crate) const MAX_BLOB: usize = BLOB_OVERHEAD + PAD_BLOCK * MAX_BLOCKS;

/// The largest peer record: every field present at its maximum.
pub(crate) const MAX_PEER_RECORD: usize =
    9 * FIELD_HEADER_LEN + KEY_LEN + MAX_NAME + 2 * BOOL_LEN + 4 * U64_LEN + MAX_NAME;

/// The largest `outbox` entry.
pub(crate) const MAX_OUTBOX_ENTRY: usize = 7 * FIELD_HEADER_LEN
    + ID_LEN
    + U8_LEN
    + U64_LEN
    + MAX_BLOB
    + SIGNATURE_LEN
    + BOOL_LEN
    + U64_LEN;

/// The largest old-key record.
pub(crate) const MAX_OLD_KEY: usize = 2 * FIELD_HEADER_LEN + KEY_LEN + U64_LEN;

/// One peer of the channel (spec 022-peers-tofu).
#[derive(Clone)]
pub(crate) struct PeerRecord {
    /// Key 0, the peer's public key.
    pub(crate) pk: PublicKey,
    /// Key 1, the label one gave the peer.
    pub(crate) label: Option<String>,
    /// Key 2.
    pub(crate) verified: bool,
    /// Key 3.
    pub(crate) muted: bool,
    /// Key 4, when the peer retired its key.
    pub(crate) retired_at: Option<u64>,
    /// Key 5.
    pub(crate) first_seen: u64,
    /// Key 6.
    pub(crate) last_seen: u64,
    /// Key 7, the highest counter received from the peer.
    pub(crate) max_counter: Option<u64>,
    /// Key 8, the display name of the peer's last message, as sent.
    pub(crate) last_display_name: Option<Vec<u8>>,
}

impl PeerRecord {
    /// Decodes one peer record under `Reject`.
    ///
    /// # Errors
    ///
    /// `Corrupt` for any record that breaks the schema.
    pub(crate) fn decode(buf: &[u8]) -> Result<PeerRecord, StoreError> {
        let mut reader = Reader::new(buf, MAX_PEER_RECORD, UnknownKeys::Reject)?;
        let peer = PeerRecord {
            pk: PublicKey(*required(reader.bytes_n::<KEY_LEN>(0))?),
            label: reader.text(1, MAX_NAME)?.map(str::to_owned),
            verified: required(reader.bool(2))?,
            muted: required(reader.bool(3))?,
            retired_at: reader.u64(4)?,
            first_seen: required(reader.u64(5))?,
            last_seen: required(reader.u64(6))?,
            max_counter: reader.u64(7)?,
            last_display_name: reader.bytes(8, MAX_NAME)?.map(<[u8]>::to_vec),
        };
        reader.end()?;
        Ok(peer)
    }

    /// The exact length of [`PeerRecord::encode`]'s output.
    pub(crate) fn encoded_len(&self) -> usize {
        record_len(&[
            Some(KEY_LEN),
            self.label.as_ref().map(String::len),
            Some(BOOL_LEN),
            Some(BOOL_LEN),
            self.retired_at.map(|_| U64_LEN),
            Some(U64_LEN),
            Some(U64_LEN),
            self.max_counter.map(|_| U64_LEN),
            self.last_display_name.as_ref().map(Vec::len),
        ])
    }

    /// Encodes the record at its exact length (R25).
    ///
    /// # Errors
    ///
    /// `Corrupt` for a name above [`MAX_NAME`] (R27).
    pub(crate) fn encode(&self) -> Result<Zeroizing<Vec<u8>>, StoreError> {
        within(self.label.as_ref().map_or(0, String::len), MAX_NAME)?;
        within(
            self.last_display_name.as_ref().map_or(0, Vec::len),
            MAX_NAME,
        )?;
        let mut writer = Writer::with_capacity(self.encoded_len());
        writer.bytes(0, &self.pk.0)?;
        if let Some(label) = &self.label {
            writer.text(1, label)?;
        }
        writer.bool(2, self.verified)?;
        writer.bool(3, self.muted)?;
        if let Some(retired_at) = self.retired_at {
            writer.u64(4, retired_at)?;
        }
        writer.u64(5, self.first_seen)?;
        writer.u64(6, self.last_seen)?;
        if let Some(max_counter) = self.max_counter {
            writer.u64(7, max_counter)?;
        }
        if let Some(name) = &self.last_display_name {
            writer.bytes(8, name)?;
        }
        Ok(writer.finish())
    }
}

/// What an `outbox` entry carries (key 1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OutboxKind {
    /// 0, a text message.
    Text,
    /// 1, the `key_retired` of spec 025-identity-regen.
    KeyRetired,
}

impl OutboxKind {
    /// The kind of key 1.
    ///
    /// # Errors
    ///
    /// `Corrupt` for a byte other than 0 and 1.
    fn from_byte(byte: u8) -> Result<OutboxKind, StoreError> {
        match byte {
            0 => Ok(OutboxKind::Text),
            1 => Ok(OutboxKind::KeyRetired),
            _ => Err(StoreError::Corrupt),
        }
    }

    /// Key 1 of this kind.
    fn to_byte(self) -> u8 {
        match self {
            OutboxKind::Text => 0,
            OutboxKind::KeyRetired => 1,
        }
    }
}

/// One sealed message waiting to leave (spec 021-channel-session).
#[derive(Clone)]
pub(crate) struct OutboxEntry {
    /// Key 0.
    pub(crate) client_ref: [u8; ID_LEN],
    /// Key 1.
    pub(crate) kind: OutboxKind,
    /// Key 2.
    pub(crate) sent_at: u64,
    /// Key 3, the sealed blob, at most [`MAX_BLOB`] bytes.
    pub(crate) blob: Vec<u8>,
    /// Key 4, the unmasked signature (spec 013-wire-message R20).
    pub(crate) signature: Signature,
    /// Key 5.
    pub(crate) under_retired_key: bool,
    /// Key 6.
    pub(crate) counter: u64,
}

impl OutboxEntry {
    /// Decodes one `outbox` entry under `Reject`.
    ///
    /// # Errors
    ///
    /// `Corrupt` for any entry that breaks the schema, a `kind` other than 0
    /// and 1 included.
    pub(crate) fn decode(buf: &[u8]) -> Result<OutboxEntry, StoreError> {
        let mut reader = Reader::new(buf, MAX_OUTBOX_ENTRY, UnknownKeys::Reject)?;
        let entry = OutboxEntry {
            client_ref: *required(reader.bytes_n(0))?,
            kind: OutboxKind::from_byte(required(reader.u8(1))?)?,
            sent_at: required(reader.u64(2))?,
            blob: required(reader.bytes(3, MAX_BLOB))?.to_vec(),
            signature: Signature(*required(reader.bytes_n(4))?),
            under_retired_key: required(reader.bool(5))?,
            counter: required(reader.u64(6))?,
        };
        reader.end()?;
        Ok(entry)
    }

    /// The exact length of [`OutboxEntry::encode`]'s output.
    pub(crate) fn encoded_len(&self) -> usize {
        record_len(&[
            Some(ID_LEN),
            Some(U8_LEN),
            Some(U64_LEN),
            Some(self.blob.len()),
            Some(SIGNATURE_LEN),
            Some(BOOL_LEN),
            Some(U64_LEN),
        ])
    }

    /// Encodes the entry at its exact length (R25).
    ///
    /// # Errors
    ///
    /// `Corrupt` for a blob above [`MAX_BLOB`] (R27).
    pub(crate) fn encode(&self) -> Result<Zeroizing<Vec<u8>>, StoreError> {
        within(self.blob.len(), MAX_BLOB)?;
        let mut writer = Writer::with_capacity(self.encoded_len());
        writer.bytes(0, &self.client_ref)?;
        writer.u8(1, self.kind.to_byte())?;
        writer.u64(2, self.sent_at)?;
        writer.bytes(3, &self.blob)?;
        writer.bytes(4, &self.signature.0)?;
        writer.bool(5, self.under_retired_key)?;
        writer.u64(6, self.counter)?;
        Ok(writer.finish())
    }
}

/// One of one's own retired keys (spec 025-identity-regen).
#[derive(Clone)]
pub(crate) struct OldKey {
    /// Key 0.
    pub(crate) pk: PublicKey,
    /// Key 1.
    pub(crate) retired_at: u64,
}

impl OldKey {
    /// Decodes one old-key record under `Reject`.
    ///
    /// # Errors
    ///
    /// `Corrupt` for any record that breaks the schema.
    pub(crate) fn decode(buf: &[u8]) -> Result<OldKey, StoreError> {
        let mut reader = Reader::new(buf, MAX_OLD_KEY, UnknownKeys::Reject)?;
        let old_key = OldKey {
            pk: PublicKey(*required(reader.bytes_n(0))?),
            retired_at: required(reader.u64(1))?,
        };
        reader.end()?;
        Ok(old_key)
    }

    /// The exact length of [`OldKey::encode`]'s output.
    pub(crate) fn encoded_len(&self) -> usize {
        MAX_OLD_KEY
    }

    /// Encodes the record at its exact length (R25).
    ///
    /// # Errors
    ///
    /// None in practice: every field has a fixed width.
    pub(crate) fn encode(&self) -> Result<Zeroizing<Vec<u8>>, StoreError> {
        let mut writer = Writer::with_capacity(self.encoded_len());
        writer.bytes(0, &self.pk.0)?;
        writer.u64(1, self.retired_at)?;
        Ok(writer.finish())
    }
}
