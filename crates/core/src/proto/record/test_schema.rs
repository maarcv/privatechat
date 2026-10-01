//! The fixed schemas that the tests, the vectors and the fuzz target
//! `record_decode` of spec 016 decode by: spec 017's "Test schema" and, next
//! to it, the schema of the codec vectors of spec 020-store-files, which uses
//! the types that spec adds. Between them every type of the codec is used, so
//! no path of the codec waits for a later spec to be exercised. They are
//! written like production code because they also compile under
//! `cfg(fuzzing)`, where the test relaxations of AGENTS 4 do not apply.

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

/// The largest record of the schema of spec 020's codec vectors: a nested
/// test record at its maximum and a full list fit with room to spare.
pub(crate) const MAX_TYPES_RECORD: usize = 1024;

/// The most items of key 3 of that schema (`list<u64>`).
pub(crate) const MAX_NUMBERS: usize = 4;

/// Bytes of one `u64` item.
const NUMBER_LEN: usize = 8;

/// One record of the schema of spec 020's codec vectors ("Vectors"). Every
/// key but 0 is optional.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct TypesRecord<'a> {
    /// Key 0, `u8`, mandatory.
    pub(crate) small: u8,
    /// Key 1, `bool`.
    pub(crate) flag: Option<bool>,
    /// Key 2, a nested record of the test schema of spec 017.
    pub(crate) nested: Option<TestRecord<'a>>,
    /// Key 3, `list<u64>` of at most [`MAX_NUMBERS`] items.
    pub(crate) numbers: Option<Vec<u64>>,
}

impl<'a> TypesRecord<'a> {
    /// Decodes `buf` under `unknown`, which the nested record follows too.
    pub(crate) fn decode(buf: &'a [u8], unknown: UnknownKeys) -> Result<Self, RecordError> {
        let mut reader = Reader::new(buf, MAX_TYPES_RECORD, unknown)?;
        let record = TypesRecord {
            small: reader.u8(0)?.ok_or(RecordError::Missing)?,
            flag: reader.bool(1)?,
            nested: reader.record(2, |value| TestRecord::decode(value, unknown))?,
            numbers: reader.list(3, MAX_NUMBERS, NUMBER_LEN, |item| {
                let item = item.try_into().map_err(|_| RecordError::Width)?;
                Ok(u64::from_be_bytes(item))
            })?,
        };
        reader.end()?;
        Ok(record)
    }

    /// Encodes the record (017 R10).
    pub(crate) fn encode(&self) -> Result<Zeroizing<Vec<u8>>, RecordError> {
        let mut writer = Writer::with_capacity(MAX_TYPES_RECORD);
        writer.u8(0, self.small)?;
        if let Some(value) = self.flag {
            writer.bool(1, value)?;
        }
        if let Some(value) = &self.nested {
            writer.bytes(2, &value.encode()?)?;
        }
        if let Some(value) = &self.numbers {
            let items: Vec<[u8; NUMBER_LEN]> = value.iter().map(|n| n.to_be_bytes()).collect();
            writer.list(3, &items)?;
        }
        Ok(writer.finish())
    }
}

/// The verdict of the test schema on `buf`, for the fuzz target
/// `record_decode` of spec 016-fuzz-harness: every `RecordError` is
/// `BadPayload`, so that `RecordError` does not leave the core's decoders
/// (spec 011-config-format, Interface).
pub(crate) fn decode_test_record(buf: &[u8], unknown: UnknownKeys) -> Result<(), Error> {
    TestRecord::decode(buf, unknown)
        .map(|_| ())
        .map_err(|_| Error::BadPayload)
}
