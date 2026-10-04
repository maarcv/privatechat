//! The log record of `messages.log` (spec 020, "Log record"): one entry of
//! the message journal, bound to its file generation and its byte offset
//! (R9, ADR 0035). Key 0 fixes which other keys a record has, so each kind is
//! its own variant and a record of one kind cannot carry another's fields.

use zeroize::Zeroizing;

use super::{
    DirName, ENTRY_LEN_LEN, ID_LEN, KEY_LEN, MAX_NAME, MIN_SEALED, SIGNATURE_LEN, StorageKey,
    StoreError, open_box, required, seal_box, store_key, within,
};
use crate::crypto::{PublicKey, Signature};
use crate::proto::payload::MAX_PAYLOAD;
use crate::proto::record::{
    BOOL_LEN, Reader, RecordError, U8_LEN, U32_LEN, U64_LEN, UnknownKeys, Writer, record_len,
};

#[cfg(test)]
pub(super) mod tests;

/// The largest log record (Limits).
pub(crate) const MAX_LOG_RECORD: usize = 65_536;

/// The keys of the log record, in order.
const KEY_KIND: u8 = 0;
const KEY_GENERATION: u8 = 1;
const KEY_OFFSET: u8 = 2;
const KEY_PURGE_AT: u8 = 3;
const KEY_SERVER_ID: u8 = 4;
const KEY_RECEIVED_AT: u8 = 5;
const KEY_SENDER_PK: u8 = 6;
const KEY_COUNTER: u8 = 7;
const KEY_CONTENT: u8 = 8;
const KEY_DISPLAY_NAME: u8 = 9;
const KEY_SENT_AT: u8 = 10;
const KEY_BODY: u8 = 11;
const KEY_OWN: u8 = 12;
const KEY_CLIENT_REF: u8 = 13;
const KEY_SIGNATURE: u8 = 14;
const KEY_EPOCH: u8 = 15;

/// One record of the log, less the generation and offset that `open` checks
/// and `seal` writes from their parameters. It implements neither `Clone`
/// nor `Debug`: a message holds its plaintext body.
pub struct LogRecord {
    /// Key 3, when the record may be dropped (spec 021-channel-session R26).
    pub(crate) purge_at: u64,
    /// Key 0 and the keys it allows.
    pub(crate) entry: LogEntry,
}

/// What a log record is, key 0: 0 message, 1 acked, 2 not delivered, 3 kept
/// signature, 4 seen.
pub(crate) enum LogEntry {
    Message(Message),
    Acked {
        server_id: [u8; 16],
        received_at: u64,
        client_ref: [u8; 16],
    },
    NotDelivered {
        client_ref: [u8; 16],
    },
    KeptSignature {
        sent_at: u64,
        client_ref: [u8; 16],
        signature: Signature,
        /// The `identity_epoch` it was sealed under.
        epoch: u32,
    },
    Seen {
        server_id: [u8; 16],
        sender_pk: PublicKey,
        counter: u64,
    },
}

/// A message, received or one's own.
pub(crate) struct Message {
    /// Absent for one's own before its `ack`.
    pub(crate) server_id: Option<[u8; 16]>,
    pub(crate) received_at: u64,
    pub(crate) sender_pk: PublicKey,
    pub(crate) counter: u64,
    /// Key 8, with key 11 for a text.
    pub(crate) content: Content,
    /// Wiped on drop like the body: whatever comes out of a sealed log
    /// record is.
    pub(crate) display_name: Option<Zeroizing<Vec<u8>>>,
    /// Absent when `open` read none.
    pub(crate) sent_at: Option<u64>,
    /// Key 12 and, when it is true, key 13: a message sealed by this device
    /// carries its `client_ref`.
    pub(crate) own_client_ref: Option<[u8; 16]>,
}

/// Key 8 of a message: 0 text with its body, 1 `key_retired`, 2 unreadable.
pub(crate) enum Content {
    Text(Zeroizing<Vec<u8>>),
    KeyRetired,
    Unreadable,
}

impl LogRecord {
    /// When the record may be dropped, which compaction reads (R15).
    pub fn purge_at(&self) -> u64 {
        self.purge_at
    }

    /// Opens the `nonce ‖ box` of one log entry of directory `name`, read at
    /// `offset` of a file of `generation` (R5, R9).
    ///
    /// # Errors
    ///
    /// `Corrupt` for fewer than 40 bytes, a box that does not open under this
    /// directory's key, a record that breaks the schema, or one written for
    /// another generation or offset.
    pub fn open(
        key: &StorageKey,
        name: &DirName,
        entry: &[u8],
        generation: u32,
        offset: u64,
    ) -> Result<LogRecord, StoreError> {
        let record = open_box(&store_key(key, name)?, entry)?;
        let (record, written_generation, written_offset) = LogRecord::decode(&record)?;
        if (written_generation, written_offset) != (generation, offset) {
            return Err(StoreError::Corrupt);
        }
        Ok(record)
    }

    /// Seals the record as `nonce ‖ box` for `offset` of a file of
    /// `generation` of directory `name` (R5, R9).
    ///
    /// # Errors
    ///
    /// `Corrupt` for a value beyond the Limits table, or when libsodium
    /// fails.
    pub fn seal(
        &self,
        key: &StorageKey,
        name: &DirName,
        generation: u32,
        offset: u64,
    ) -> Result<Vec<u8>, StoreError> {
        let record = self.encode(generation, offset)?;
        seal_box(&store_key(key, name)?, &record)
    }

    /// Decodes a log record under `Reject`, with the generation and offset
    /// it names.
    ///
    /// # Errors
    ///
    /// `Corrupt` for any break of the schema: an unknown kind, a key its kind
    /// does not allow, a mandatory key missing, a text without its body or a
    /// body on anything else, or an own message without its `client_ref`.
    pub(crate) fn decode(buf: &[u8]) -> Result<(LogRecord, u32, u64), StoreError> {
        let mut reader = Reader::new(buf, MAX_LOG_RECORD, UnknownKeys::Reject)?;
        let kind = required(reader.u8(KEY_KIND))?;
        let generation = required(reader.u32(KEY_GENERATION))?;
        let offset = required(reader.u64(KEY_OFFSET))?;
        let purge_at = required(reader.u64(KEY_PURGE_AT))?;
        let entry = match kind {
            0 => LogEntry::Message(Message::decode(&mut reader)?),
            1 => LogEntry::Acked {
                server_id: *required(reader.bytes_n(KEY_SERVER_ID))?,
                received_at: required(reader.u64(KEY_RECEIVED_AT))?,
                client_ref: *required(reader.bytes_n(KEY_CLIENT_REF))?,
            },
            2 => LogEntry::NotDelivered {
                client_ref: *required(reader.bytes_n(KEY_CLIENT_REF))?,
            },
            3 => LogEntry::KeptSignature {
                sent_at: required(reader.u64(KEY_SENT_AT))?,
                client_ref: *required(reader.bytes_n(KEY_CLIENT_REF))?,
                signature: Signature(*required(reader.bytes_n(KEY_SIGNATURE))?),
                epoch: required(reader.u32(KEY_EPOCH))?,
            },
            4 => LogEntry::Seen {
                server_id: *required(reader.bytes_n(KEY_SERVER_ID))?,
                sender_pk: PublicKey(*required(reader.bytes_n(KEY_SENDER_PK))?),
                counter: required(reader.u64(KEY_COUNTER))?,
            },
            _ => return Err(StoreError::Corrupt),
        };
        reader.end()?;
        Ok((LogRecord { purge_at, entry }, generation, offset))
    }

    /// Encodes the record at its exact length (R25) for `offset` of a file of
    /// `generation`.
    ///
    /// # Errors
    ///
    /// `Corrupt` for a display name above 64 bytes or a body above 64 511.
    pub(crate) fn encode(
        &self,
        generation: u32,
        offset: u64,
    ) -> Result<Zeroizing<Vec<u8>>, StoreError> {
        if let LogEntry::Message(message) = &self.entry {
            message.check()?;
        }
        let mut writer = Writer::with_capacity(self.encoded_len());
        writer.u8(KEY_KIND, self.kind())?;
        writer.u32(KEY_GENERATION, generation)?;
        writer.u64(KEY_OFFSET, offset)?;
        writer.u64(KEY_PURGE_AT, self.purge_at)?;
        match &self.entry {
            LogEntry::Message(message) => message.encode(&mut writer)?,
            LogEntry::Acked {
                server_id,
                received_at,
                client_ref,
            } => {
                writer.bytes(KEY_SERVER_ID, server_id)?;
                writer.u64(KEY_RECEIVED_AT, *received_at)?;
                writer.bytes(KEY_CLIENT_REF, client_ref)?;
            }
            LogEntry::NotDelivered { client_ref } => writer.bytes(KEY_CLIENT_REF, client_ref)?,
            LogEntry::KeptSignature {
                sent_at,
                client_ref,
                signature,
                epoch,
            } => {
                writer.u64(KEY_SENT_AT, *sent_at)?;
                writer.bytes(KEY_CLIENT_REF, client_ref)?;
                writer.bytes(KEY_SIGNATURE, &signature.0)?;
                writer.u32(KEY_EPOCH, *epoch)?;
            }
            LogEntry::Seen {
                server_id,
                sender_pk,
                counter,
            } => {
                writer.bytes(KEY_SERVER_ID, server_id)?;
                writer.bytes(KEY_SENDER_PK, &sender_pk.0)?;
                writer.u64(KEY_COUNTER, *counter)?;
            }
        }
        Ok(writer.finish())
    }

    /// The bytes this record takes in `messages.log`: its `len`, the nonce,
    /// the record and the tag (R5), whatever its generation and offset,
    /// which are fixed-width. Spec 021-channel-session counts with it what a
    /// compaction would free.
    pub(crate) fn entry_len(&self) -> u64 {
        let len = ENTRY_LEN_LEN
            .saturating_add(MIN_SEALED)
            .saturating_add(self.encoded_len());
        u64::try_from(len).unwrap_or(u64::MAX)
    }

    /// The exact length of [`LogRecord::encode`]'s output: the four keys
    /// every record has, then those of its kind.
    fn encoded_len(&self) -> usize {
        let head = record_len(&[Some(U8_LEN), Some(U32_LEN), Some(U64_LEN), Some(U64_LEN)]);
        let entry = match &self.entry {
            LogEntry::Message(message) => record_len(&message.value_lens()),
            LogEntry::Acked { .. } => record_len(&[Some(ID_LEN), Some(U64_LEN), Some(ID_LEN)]),
            LogEntry::NotDelivered { .. } => record_len(&[Some(ID_LEN)]),
            LogEntry::KeptSignature { .. } => record_len(&[
                Some(U64_LEN),
                Some(ID_LEN),
                Some(SIGNATURE_LEN),
                Some(U32_LEN),
            ]),
            LogEntry::Seen { .. } => record_len(&[Some(ID_LEN), Some(KEY_LEN), Some(U64_LEN)]),
        };
        head.saturating_add(entry)
    }

    /// Key 0 of the record.
    fn kind(&self) -> u8 {
        match self.entry {
            LogEntry::Message(_) => 0,
            LogEntry::Acked { .. } => 1,
            LogEntry::NotDelivered { .. } => 2,
            LogEntry::KeptSignature { .. } => 3,
            LogEntry::Seen { .. } => 4,
        }
    }
}

impl Content {
    /// Key 8 of this content.
    fn to_byte(&self) -> u8 {
        match self {
            Content::Text(_) => 0,
            Content::KeyRetired => 1,
            Content::Unreadable => 2,
        }
    }
}

impl Message {
    /// Keys 4 to 13 of a message, after the four every record has.
    fn decode(reader: &mut Reader<'_>) -> Result<Message, StoreError> {
        let server_id = reader.bytes_n(KEY_SERVER_ID)?.copied();
        let received_at = required(reader.u64(KEY_RECEIVED_AT))?;
        let sender_pk = PublicKey(*required(reader.bytes_n(KEY_SENDER_PK))?);
        let counter = required(reader.u64(KEY_COUNTER))?;
        let content = required(reader.u8(KEY_CONTENT))?;
        let display_name = reader
            .bytes(KEY_DISPLAY_NAME, MAX_NAME)?
            .map(|name| Zeroizing::new(name.to_vec()));
        let sent_at = reader.u64(KEY_SENT_AT)?;
        let body = reader.bytes(KEY_BODY, MAX_PAYLOAD)?;
        let content = match (content, body) {
            (0, Some(body)) => Content::Text(Zeroizing::new(body.to_vec())),
            (1, None) => Content::KeyRetired,
            (2, None) => Content::Unreadable,
            _ => return Err(StoreError::Corrupt),
        };
        let own_client_ref = match (
            required(reader.bool(KEY_OWN))?,
            reader.bytes_n(KEY_CLIENT_REF)?,
        ) {
            (true, Some(client_ref)) => Some(*client_ref),
            (false, None) => None,
            _ => return Err(StoreError::Corrupt),
        };
        Ok(Message {
            server_id,
            received_at,
            sender_pk,
            counter,
            content,
            display_name,
            sent_at,
            own_client_ref,
        })
    }

    /// `Corrupt` for a value open would refuse (R27).
    fn check(&self) -> Result<(), StoreError> {
        within(
            self.display_name.as_ref().map_or(0, |name| name.len()),
            MAX_NAME,
        )?;
        match &self.content {
            Content::Text(body) => within(body.len(), MAX_PAYLOAD),
            Content::KeyRetired | Content::Unreadable => Ok(()),
        }
    }

    /// The value lengths of keys 4 to 13.
    fn value_lens(&self) -> [Option<usize>; 10] {
        let body = match &self.content {
            Content::Text(body) => Some(body.len()),
            Content::KeyRetired | Content::Unreadable => None,
        };
        [
            self.server_id.map(|_| ID_LEN),
            Some(U64_LEN),
            Some(KEY_LEN),
            Some(U64_LEN),
            Some(U8_LEN),
            self.display_name.as_ref().map(|name| name.len()),
            self.sent_at.map(|_| U64_LEN),
            body,
            Some(BOOL_LEN),
            self.own_client_ref.map(|_| ID_LEN),
        ]
    }

    /// Writes keys 4 to 13.
    fn encode(&self, writer: &mut Writer) -> Result<(), RecordError> {
        if let Some(server_id) = &self.server_id {
            writer.bytes(KEY_SERVER_ID, server_id)?;
        }
        writer.u64(KEY_RECEIVED_AT, self.received_at)?;
        writer.bytes(KEY_SENDER_PK, &self.sender_pk.0)?;
        writer.u64(KEY_COUNTER, self.counter)?;
        writer.u8(KEY_CONTENT, self.content.to_byte())?;
        if let Some(name) = &self.display_name {
            writer.bytes(KEY_DISPLAY_NAME, name)?;
        }
        if let Some(sent_at) = self.sent_at {
            writer.u64(KEY_SENT_AT, sent_at)?;
        }
        if let Content::Text(body) = &self.content {
            writer.bytes(KEY_BODY, body)?;
        }
        writer.bool(KEY_OWN, self.own_client_ref.is_some())?;
        if let Some(client_ref) = &self.own_client_ref {
            writer.bytes(KEY_CLIENT_REF, client_ref)?;
        }
        Ok(())
    }
}
