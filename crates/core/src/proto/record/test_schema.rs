//! The fixed schema that the tests, the vectors and the fuzz target
//! `record_decode` of spec 016 decode by (spec 017, "Test schema"). It uses
//! every type the codec implements, so no path of the codec waits for a later
//! spec to be exercised. It is written like production code because it also
//! compiles under `cfg(fuzzing)`, where the test relaxations of AGENTS 4 do
//! not apply.

use zeroize::Zeroizing;

use super::{Reader, RecordError, UnknownKeys, Writer};
use crate::Error;

/// The largest record of the test schema.
pub(crate) const MAX_RECORD: usize = 512;

/// The largest value of key 3 (`bytes`).
pub(crate) const MAX_BYTES: usize = 64;

/// The largest value of key 5 (`text`).
pub(crate) const MAX_TEXT: usize = 64;

/// One record of the test schema, one field per key. Every key but 0 is
/// optional.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct TestRecord<'a> {
    /// Key 0, `u8`, mandatory.
    pub(crate) small: u8,
    /// Key 1, `u32`.
    pub(crate) medium: Option<u32>,
    /// Key 2, `u64`.
    pub(crate) large: Option<u64>,
    /// Key 3, `bytes` of at most [`MAX_BYTES`].
    pub(crate) bytes: Option<&'a [u8]>,
    /// Key 4, `bytes32`.
    pub(crate) bytes32: Option<&'a [u8; 32]>,
    /// Key 5, `text` of at most [`MAX_TEXT`].
    pub(crate) text: Option<&'a str>,
}

impl<'a> TestRecord<'a> {
    /// Decodes `buf` by the test schema under `unknown`.
    pub(crate) fn decode(buf: &'a [u8], unknown: UnknownKeys) -> Result<Self, RecordError> {
        let mut reader = Reader::new(buf, MAX_RECORD, unknown)?;
        let record = TestRecord {
            small: reader.u8(0)?.ok_or(RecordError::Missing)?,
            medium: reader.u32(1)?,
            large: reader.u64(2)?,
            bytes: reader.bytes(3, MAX_BYTES)?,
            bytes32: reader.bytes_n::<32>(4)?,
            text: reader.text(5, MAX_TEXT)?,
        };
        reader.end()?;
        Ok(record)
    }

    /// Encodes the record by the test schema (R10).
    pub(crate) fn encode(&self) -> Result<Zeroizing<Vec<u8>>, RecordError> {
        let mut writer = Writer::with_capacity(MAX_RECORD);
        writer.u8(0, self.small)?;
        if let Some(value) = self.medium {
            writer.u32(1, value)?;
        }
        if let Some(value) = self.large {
            writer.u64(2, value)?;
        }
        if let Some(value) = self.bytes {
            writer.bytes(3, value)?;
        }
        if let Some(value) = self.bytes32 {
            writer.bytes(4, value)?;
        }
        if let Some(value) = self.text {
            writer.text(5, value)?;
        }
        Ok(writer.finish())
    }
}

/// The verdict of the test schema on `buf`, for the fuzz target
/// `record_decode` of spec 016-fuzz-harness: every `RecordError` is
/// `BadPayload`, so that `RecordError` never leaves `proto`.
pub(crate) fn decode_test_record(buf: &[u8], unknown: UnknownKeys) -> Result<(), Error> {
    TestRecord::decode(buf, unknown)
        .map(|_| ())
        .map_err(|_| Error::BadPayload)
}
