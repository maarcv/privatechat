//! The frames of `docs/spec.md` §6: one record of spec 017-record-encoding
//! each, unknown keys ignored, key 0 the frame's `type` (spec
//! 028-session-sans-io R1–R3, the table "Frames").
//!
//! `Frame::encode` and `Frame::decode` are the one codec of the frames, for
//! the `Session` of spec 028 and for the server of spec 030-ws-protocol. The
//! version rule of R2 is [`is_supported`]: a `hello` that breaks it decodes,
//! and the session, not the codec, refuses it.

use crate::Error;
use crate::proto::config::VERSION as PROTO_VERSION;
use crate::proto::envelope::MAX_BLOB;
use crate::proto::record::{
    Reader, RecordError, U8_LEN, U32_LEN, U64_LEN, UnknownKeys, Writer, list_len, record_len,
};

#[cfg(test)]
mod tests;

/// The largest frame (R1).
pub(crate) const MAX_FRAME: usize = 70_000;

/// The most items of `hello.proto_versions` the session accepts (R2).
pub(crate) const MAX_PROTO_VERSIONS: usize = 8;

/// The largest `error.code`, in bytes of UTF-8 (R1).
pub(crate) const MAX_ERROR_CODE: usize = 32;

/// The largest `error.message`, in bytes of UTF-8 (R1).
pub(crate) const MAX_ERROR_MESSAGE: usize = 256;

/// The `error.code`s of R16 that the session and the test server name.
pub(crate) const CODE_NONCE_EXPIRED: &str = "nonce_expired";
pub(crate) const CODE_BAD_AUTH: &str = "bad_auth";
pub(crate) const CODE_NOT_SUBSCRIBED: &str = "not_subscribed";

/// The values of key 0, `type` (the table "Frames").
const TYPE_HELLO: u8 = 0;
const TYPE_SUBSCRIBE: u8 = 1;
const TYPE_OK: u8 = 2;
const TYPE_PUBLISH: u8 = 3;
const TYPE_ACK: u8 = 4;
const TYPE_PUSH: u8 = 5;
const TYPE_ERROR: u8 = 6;

/// Key 0 of every frame.
const KEY_TYPE: u8 = 0;

/// The width of one `proto_versions` item, a `u8`.
const VERSION_ITEM_LEN: usize = 1;

/// One frame of the protocol, with the fields of the table "Frames". It
/// derives no `PartialEq`: the tests compare encodings.
#[derive(Debug)]
pub enum Frame {
    /// Server → client, first on every connection.
    Hello {
        /// The fresh nonce every `subscribe` of the connection signs.
        server_nonce: [u8; 32],
        /// The protocol versions the server speaks (R2).
        proto_versions: Vec<u8>,
    },
    /// Client → server, one per channel.
    Subscribe {
        /// The channel's public key.
        pk_ch: [u8; 32],
        /// The channel's TTL.
        ttl_seconds: u32,
        /// The channel's signature over the server's nonce (R6).
        sig: [u8; 64],
        /// The cursor rounded down to the minute; absent for all.
        since: Option<u64>,
    },
    /// Server → client, after a channel's backlog (R4).
    Ok {
        /// The channel now subscribed.
        channel_id: [u8; 16],
    },
    /// Client → server, one sealed blob.
    Publish {
        /// The channel to store it in.
        channel_id: [u8; 16],
        /// The `outbox` entry it carries.
        client_ref: [u8; 16],
        /// The sealed message.
        blob: Vec<u8>,
    },
    /// Server → client, a `publish` stored.
    Ack {
        /// The `client_ref` of the `publish`.
        client_ref: [u8; 16],
        /// The server's name for the stored blob.
        server_id: [u8; 16],
        /// When the server stored it, by its clock.
        received_at: u64,
    },
    /// Server → client, a stored blob.
    Push {
        /// The channel it was stored in.
        channel_id: [u8; 16],
        /// The server's name for the blob.
        server_id: [u8; 16],
        /// When the server stored it, by its clock.
        received_at: u64,
        /// The sealed message.
        blob: Vec<u8>,
    },
    /// Server → client, naming the channel or the publish it answers.
    Error {
        /// What failed (R16).
        code: String,
        /// Free text; the session acts on `code` alone.
        message: String,
        /// The channel it answers.
        channel_id: Option<[u8; 16]>,
        /// The `publish` it answers.
        client_ref: Option<[u8; 16]>,
    },
}

impl Frame {
    /// The canonical record of the frame (spec 017 R10).
    ///
    /// # Errors
    ///
    /// `BadPayload` for a field `decode` would refuse: a blob above 64 673
    /// bytes, a `code` above 32 bytes or a `message` above 256, or a frame
    /// above 70 000 bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// use privatechat_core::Frame;
    ///
    /// let ok = Frame::Ok { channel_id: [7; 16] };
    /// let bytes = ok.encode()?;
    /// assert!(matches!(Frame::decode(&bytes)?, Frame::Ok { channel_id: [7, ..] }));
    /// # Ok::<(), privatechat_core::Error>(())
    /// ```
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let len = self.encoded_len();
        if len > MAX_FRAME {
            return Err(Error::BadPayload);
        }
        // Allocated at the frame's length, so that neither the writer nor a
        // queue of small frames holds 70 000 bytes each (spec 020 R25).
        let mut writer = Writer::with_capacity(len);
        writer.u8(KEY_TYPE, self.type_byte()).map_err(bad_payload)?;
        self.write_fields(&mut writer).map_err(bad_payload)?;
        // A frame is ciphertext and public fields: it leaves the wiping buffer.
        Ok(core::mem::take(&mut *writer.finish()))
    }

    /// The bytes `encode` writes; saturating, so a frame past `usize` is
    /// above `MAX_FRAME` too.
    fn encoded_len(&self) -> usize {
        let id = Some(16);
        let values = match self {
            Frame::Hello { proto_versions, .. } => vec![
                Some(32),
                Some(list_len(proto_versions.iter().map(|_| VERSION_ITEM_LEN))),
            ],
            Frame::Subscribe { since, .. } => {
                vec![Some(32), Some(U32_LEN), Some(64), since.map(|_| U64_LEN)]
            }
            Frame::Ok { .. } => vec![id],
            Frame::Publish { blob, .. } => vec![id, id, Some(blob.len())],
            Frame::Ack { .. } => vec![id, id, Some(U64_LEN)],
            Frame::Push { blob, .. } => vec![id, id, Some(U64_LEN), Some(blob.len())],
            Frame::Error {
                code,
                message,
                channel_id,
                client_ref,
            } => vec![
                Some(code.len()),
                Some(message.len()),
                channel_id.map(|_| 16),
                client_ref.map(|_| 16),
            ],
        };
        record_len(&[Some(U8_LEN)]).saturating_add(record_len(&values))
    }

    /// The frame of a record, under `UnknownKeys::Ignore` (R1).
    ///
    /// # Errors
    ///
    /// `BadPayload` for a record above 70 000 bytes, an unknown `type`, a
    /// mandatory key absent, a value of the wrong width or above its bound
    /// (a `text` included), or a framing failure of spec 017.
    pub fn decode(bytes: &[u8]) -> Result<Frame, Error> {
        let mut reader = Reader::new(bytes, MAX_FRAME, UnknownKeys::Ignore).map_err(bad_payload)?;
        let frame = match required(reader.u8(KEY_TYPE))? {
            TYPE_HELLO => Frame::Hello {
                server_nonce: *required(reader.bytes_n(1))?,
                proto_versions: required(reader.list(2, MAX_FRAME, VERSION_ITEM_LEN, version))?,
            },
            TYPE_SUBSCRIBE => Frame::Subscribe {
                pk_ch: *required(reader.bytes_n(1))?,
                ttl_seconds: required(reader.u32(2))?,
                sig: *required(reader.bytes_n(3))?,
                since: reader.u64(4).map_err(bad_payload)?,
            },
            TYPE_OK => Frame::Ok {
                channel_id: *required(reader.bytes_n(1))?,
            },
            TYPE_PUBLISH => Frame::Publish {
                channel_id: *required(reader.bytes_n(1))?,
                client_ref: *required(reader.bytes_n(2))?,
                blob: required(reader.bytes(3, MAX_BLOB))?.to_vec(),
            },
            TYPE_ACK => Frame::Ack {
                client_ref: *required(reader.bytes_n(1))?,
                server_id: *required(reader.bytes_n(2))?,
                received_at: required(reader.u64(3))?,
            },
            TYPE_PUSH => Frame::Push {
                channel_id: *required(reader.bytes_n(1))?,
                server_id: *required(reader.bytes_n(2))?,
                received_at: required(reader.u64(3))?,
                blob: required(reader.bytes(4, MAX_BLOB))?.to_vec(),
            },
            TYPE_ERROR => Frame::Error {
                code: required(reader.text(1, MAX_ERROR_CODE))?.to_owned(),
                message: required(reader.text(2, MAX_ERROR_MESSAGE))?.to_owned(),
                channel_id: reader.bytes_n(3).map_err(bad_payload)?.copied(),
                client_ref: reader.bytes_n(4).map_err(bad_payload)?.copied(),
            },
            _ => return Err(Error::BadPayload),
        };
        reader.end().map_err(bad_payload)?;
        Ok(frame)
    }

    /// The value of key 0.
    fn type_byte(&self) -> u8 {
        match self {
            Frame::Hello { .. } => TYPE_HELLO,
            Frame::Subscribe { .. } => TYPE_SUBSCRIBE,
            Frame::Ok { .. } => TYPE_OK,
            Frame::Publish { .. } => TYPE_PUBLISH,
            Frame::Ack { .. } => TYPE_ACK,
            Frame::Push { .. } => TYPE_PUSH,
            Frame::Error { .. } => TYPE_ERROR,
        }
    }

    /// Keys 1 and up, in order, each checked against the bound `decode`
    /// applies, so that `encode` never writes a frame `decode` refuses.
    fn write_fields(&self, writer: &mut Writer) -> Result<(), RecordError> {
        match self {
            Frame::Hello {
                server_nonce,
                proto_versions,
            } => {
                writer.bytes(1, server_nonce)?;
                let items: Vec<[u8; 1]> = proto_versions.iter().map(|v| [*v]).collect();
                writer.list(2, &items)
            }
            Frame::Subscribe {
                pk_ch,
                ttl_seconds,
                sig,
                since,
            } => {
                writer.bytes(1, pk_ch)?;
                writer.u32(2, *ttl_seconds)?;
                writer.bytes(3, sig)?;
                since.map_or(Ok(()), |since| writer.u64(4, since))
            }
            Frame::Ok { channel_id } => writer.bytes(1, channel_id),
            Frame::Publish {
                channel_id,
                client_ref,
                blob,
            } => {
                writer.bytes(1, channel_id)?;
                writer.bytes(2, client_ref)?;
                writer.bytes(3, bounded(blob, MAX_BLOB)?)
            }
            Frame::Ack {
                client_ref,
                server_id,
                received_at,
            } => {
                writer.bytes(1, client_ref)?;
                writer.bytes(2, server_id)?;
                writer.u64(3, *received_at)
            }
            Frame::Push {
                channel_id,
                server_id,
                received_at,
                blob,
            } => {
                writer.bytes(1, channel_id)?;
                writer.bytes(2, server_id)?;
                writer.u64(3, *received_at)?;
                writer.bytes(4, bounded(blob, MAX_BLOB)?)
            }
            Frame::Error {
                code,
                message,
                channel_id,
                client_ref,
            } => {
                writer.bytes(1, bounded(code.as_bytes(), MAX_ERROR_CODE)?)?;
                writer.bytes(2, bounded(message.as_bytes(), MAX_ERROR_MESSAGE)?)?;
                channel_id.map_or(Ok(()), |id| writer.bytes(3, &id))?;
                client_ref.map_or(Ok(()), |id| writer.bytes(4, &id))
            }
        }
    }
}

/// The version rule of R2 over a decoded `hello.proto_versions`: 1 to 8
/// items, one of them the `proto_version` of the channels.
pub(crate) fn is_supported(proto_versions: &[u8]) -> bool {
    // An empty list holds no version, so `contains` refuses it too.
    proto_versions.len() <= MAX_PROTO_VERSIONS && proto_versions.contains(&PROTO_VERSION)
}

/// One item of `proto_versions`; the reader has bounded it to one byte, so
/// only an empty item fails here.
fn version(item: &[u8]) -> Result<u8, RecordError> {
    match item {
        [version] => Ok(*version),
        _ => Err(RecordError::Width),
    }
}

/// `value` when it is at most `max` bytes.
fn bounded(value: &[u8], max: usize) -> Result<&[u8], RecordError> {
    if value.len() > max {
        Err(RecordError::TooLong)
    } else {
        Ok(value)
    }
}

/// A mandatory key: absent or malformed, the record is not a frame (R1).
fn required<T>(value: Result<Option<T>, RecordError>) -> Result<T, Error> {
    value.map_err(bad_payload)?.ok_or(Error::BadPayload)
}

/// Every `RecordError` of a frame is `BadPayload` (the Interface).
fn bad_payload(_: RecordError) -> Error {
    Error::BadPayload
}
