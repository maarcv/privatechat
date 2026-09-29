//! The plaintext payload of `docs/spec.md` §4: a record of spec
//! 017-record-encoding with unknown keys ignored, then padded to 1 024-byte
//! blocks (spec 013-wire-message R6–R10, R14).
//!
//! `validate` is the one validation both sides run. Decoding is split at key
//! 2, `sent_at`, so that the stale check of `open` (R12) can run after
//! `sent_at` is read and before anything later in the record decides the
//! verdict. The envelope around the padded payload is `envelope.rs`.

use core::fmt;

use super::record::{Reader, RecordError, UnknownKeys, Writer};
use crate::Error;

#[cfg(test)]
mod tests;

/// The padding block (`docs/spec.md` §4, R10).
pub(crate) const PAD_BLOCK: usize = 1_024;

/// The most blocks a padded payload may take (R10).
pub(crate) const MAX_BLOCKS: usize = 63;

/// The largest encoded payload before padding: `sodium_pad` adds at least
/// one byte, so 63 blocks hold one byte less (R7).
pub(crate) const MAX_PAYLOAD: usize = 64_511;

/// The largest `display_name`, in bytes of UTF-8 (R7, R9).
pub(crate) const MAX_DISPLAY_NAME: usize = 64;

/// `sent_at` is rounded down to the minute (R8).
const MINUTE_MS: u64 = 60_000;

/// The keys of the payload record, `docs/spec.md` §4 (R6).
const KEY_TYPE: u8 = 0;
const KEY_DISPLAY_NAME: u8 = 1;
const KEY_SENT_AT: u8 = 2;
const KEY_BODY: u8 = 3;

/// The values of `type` (R6).
const TYPE_TEXT: u8 = 0;
const TYPE_KEY_RETIRED: u8 = 1;

/// Bytes of a field before its value: key and length (spec 017 R1).
const FIELD_HEADER_LEN: usize = 5;

/// The bytes every payload has: `type` (5 + 1), `sent_at` (5 + 8) and the
/// field header of `body` (5).
const FIXED_LEN: usize = 24;

/// What a payload is; any other `type` is a message of a later version.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PayloadKind {
    Text,
    KeyRetired,
    Unknown(u8),
}

impl PayloadKind {
    fn from_byte(byte: u8) -> PayloadKind {
        match byte {
            TYPE_TEXT => PayloadKind::Text,
            TYPE_KEY_RETIRED => PayloadKind::KeyRetired,
            other => PayloadKind::Unknown(other),
        }
    }

    fn to_byte(self) -> u8 {
        match self {
            PayloadKind::Text => TYPE_TEXT,
            PayloadKind::KeyRetired => TYPE_KEY_RETIRED,
            PayloadKind::Unknown(other) => other,
        }
    }
}

/// A decrypted message. Its `Debug` hides `body` and `display_name`, which
/// are content (R14); it has no `Display`.
#[derive(PartialEq, Eq)]
pub(crate) struct Payload {
    pub(crate) kind: PayloadKind,
    pub(crate) display_name: Option<String>,
    pub(crate) sent_at: u64,
    pub(crate) body: Vec<u8>,
}

impl fmt::Debug for Payload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let display_name = self.display_name.as_ref().map(|_| "[REDACTED]");
        f.debug_struct("Payload")
            .field("kind", &self.kind)
            .field("display_name", &display_name)
            .field("sent_at", &self.sent_at)
            .field("body", &format_args!("[REDACTED]"))
            .finish()
    }
}

impl Payload {
    /// The one validation of a payload, on both sides (R7, R8).
    ///
    /// # Errors
    ///
    /// `BadPayload` for an unknown `type`, a `sent_at` that is not a whole
    /// minute, a `text` body that is not UTF-8, a `key_retired` with a body
    /// or a name, a name above 64 bytes or with a Cc character, and an
    /// encoding above 64 511 bytes.
    pub(crate) fn validate(&self) -> Result<(), Error> {
        let kind_ok = match self.kind {
            PayloadKind::Text => core::str::from_utf8(&self.body).is_ok(),
            PayloadKind::KeyRetired => self.body.is_empty() && self.display_name.is_none(),
            PayloadKind::Unknown(_) => false,
        };
        let name_ok = self.display_name.as_deref().is_none_or(is_valid_name);
        let len_ok = self.encoded_len().is_some_and(|len| len <= MAX_PAYLOAD);
        if kind_ok && name_ok && len_ok && self.sent_at.is_multiple_of(MINUTE_MS) {
            Ok(())
        } else {
            Err(Error::BadPayload)
        }
    }

    /// The canonical record of R6, with no validation of its content: `seal`
    /// validates first.
    ///
    /// # Errors
    ///
    /// `BadPayload` for an encoding above 64 511 bytes.
    pub(crate) fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut writer = Writer::with_capacity(MAX_PAYLOAD);
        writer
            .u8(KEY_TYPE, self.kind.to_byte())
            .map_err(bad_payload)?;
        if let Some(name) = &self.display_name {
            writer.text(KEY_DISPLAY_NAME, name).map_err(bad_payload)?;
        }
        writer.u64(KEY_SENT_AT, self.sent_at).map_err(bad_payload)?;
        writer.bytes(KEY_BODY, &self.body).map_err(bad_payload)?;
        // The payload is content, not a key: it leaves the wiping buffer.
        Ok(core::mem::take(&mut *writer.finish()))
    }

    /// The record of R6 with its name filtered by R9, and no validation:
    /// `open` runs `validate` after the stale check.
    ///
    /// # Errors
    ///
    /// `BadPayload` for a record that breaks the framing of spec 017, a
    /// field of the wrong width, or a missing `type`, `sent_at` or `body`.
    pub(crate) fn decode(bytes: &[u8]) -> Result<Payload, Error> {
        PayloadHead::read(bytes)?.finish()
    }

    /// The bytes `encode` writes, or `None` past `usize`.
    fn encoded_len(&self) -> Option<usize> {
        let name = self
            .display_name
            .as_ref()
            .map_or(Some(0), |name| name.len().checked_add(FIELD_HEADER_LEN))?;
        FIXED_LEN.checked_add(name)?.checked_add(self.body.len())
    }
}

/// A payload read up to and including `sent_at`, the point where `open`
/// runs the stale check (R12).
pub(crate) struct PayloadHead<'a> {
    reader: Reader<'a>,
    kind: Option<u8>,
    display_name: Option<&'a [u8]>,
    pub(crate) sent_at: u64,
}

impl<'a> PayloadHead<'a> {
    /// Keys 0 to 2, in order.
    ///
    /// # Errors
    ///
    /// `BadPayload` for a framing or width failure before `sent_at`, or a
    /// `sent_at` that is absent. An absent `type` fails in `finish`, after
    /// the stale check.
    pub(crate) fn read(bytes: &'a [u8]) -> Result<PayloadHead<'a>, Error> {
        let mut reader =
            Reader::new(bytes, MAX_PAYLOAD, UnknownKeys::Ignore).map_err(bad_payload)?;
        let kind = reader.u8(KEY_TYPE).map_err(bad_payload)?;
        let display_name = reader
            .bytes(KEY_DISPLAY_NAME, MAX_PAYLOAD)
            .map_err(bad_payload)?;
        let sent_at = required(reader.u64(KEY_SENT_AT))?;
        Ok(PayloadHead {
            reader,
            kind,
            display_name,
            sent_at,
        })
    }

    /// The rest of the record, and the name dropped when it breaks R9.
    ///
    /// # Errors
    ///
    /// `BadPayload` for a missing `type` or `body`, or a framing failure
    /// after `sent_at`.
    pub(crate) fn finish(mut self) -> Result<Payload, Error> {
        let body = required(self.reader.bytes(KEY_BODY, MAX_PAYLOAD))?;
        self.reader.end().map_err(bad_payload)?;
        let kind = PayloadKind::from_byte(self.kind.ok_or(Error::BadPayload)?);
        // R9: a bad name is a suggestion to ignore, never a reason to lose
        // the message, so two versions never disagree on readability.
        let display_name = self
            .display_name
            .filter(|_| kind != PayloadKind::KeyRetired)
            .and_then(|name| core::str::from_utf8(name).ok())
            .filter(|name| is_valid_name(name))
            .map(str::to_owned);
        Ok(Payload {
            kind,
            display_name,
            sent_at: self.sent_at,
            body: body.to_vec(),
        })
    }
}

/// At most 64 bytes and no Cc character (R7, R9); `char::is_control` is
/// exactly the general category Cc.
fn is_valid_name(name: &str) -> bool {
    name.len() <= MAX_DISPLAY_NAME && !name.chars().any(char::is_control)
}

/// A mandatory key: absent or malformed, the record is not a payload (R6).
fn required<T>(value: Result<Option<T>, RecordError>) -> Result<T, Error> {
    value.map_err(bad_payload)?.ok_or(Error::BadPayload)
}

/// Every `RecordError` of a payload is `BadPayload` (R6).
fn bad_payload(_: RecordError) -> Error {
    Error::BadPayload
}
