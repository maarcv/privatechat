//! The record encoding of `docs/spec.md` §4 (ADR 0023, spec 017-record-encoding).
//!
//! A record is a sequence of fields `key` (1 byte) ‖ `len` (4 bytes, big-endian)
//! ‖ `value`, in strictly increasing key order. The decoder is typed: each
//! schema reads its keys in order through a [`Reader`] and checks every value
//! against the type the schema gives it, so there is no generic tree of values
//! and nothing recurses on input (R9). Which keys a record has, and which error
//! a failure becomes, belong to the spec that owns the record.

#[cfg(test)]
mod tests;

#[cfg(any(test, fuzzing))]
pub(crate) mod test_schema;

/// Bytes of a field before its value: the key and the length (R1).
const FIELD_HEADER_LEN: usize = 5;

/// Why a record was rejected, one variant per rule of spec 017.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RecordError {
    /// Fewer bytes than a field header, or a length beyond the buffer (R2, R5).
    Truncated,
    /// A key not greater than the previous one, duplicates included (R2).
    KeyOrder,
    /// An integer or `bytesN` value of the wrong length (R3, R4).
    Width,
    /// A `text` value that is not UTF-8 (R4).
    Utf8,
    /// A mandatory key that is absent (R6).
    Missing,
    /// A key the schema does not name, under [`UnknownKeys::Reject`] (R7).
    UnknownKey,
    /// A record, value or writer output above its maximum (R4, R8, R11).
    TooLong,
}

/// What a reader does with a key the schema does not name (R7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum UnknownKeys {
    Ignore,
    Reject,
}

/// One field as it sits in the buffer, framing checked, value not yet typed.
struct Field<'a> {
    key: u8,
    value: &'a [u8],
}

/// Reads one record by its schema: keys in increasing order, each getter
/// returning `None` for an absent key and borrowing the value from the buffer.
#[must_use]
pub(crate) struct Reader<'a> {
    rest: &'a [u8],
    last_key: Option<u8>,
    /// A field already framed whose key is above the one last asked for.
    pending: Option<Field<'a>>,
    unknown: UnknownKeys,
}

impl<'a> Reader<'a> {
    /// A reader over `buf`, which must be at most `max_len` bytes (R8).
    pub(crate) fn new(
        buf: &'a [u8],
        max_len: usize,
        unknown: UnknownKeys,
    ) -> Result<Reader<'a>, RecordError> {
        if buf.len() > max_len {
            return Err(RecordError::TooLong);
        }
        Ok(Reader {
            rest: buf,
            last_key: None,
            pending: None,
            unknown,
        })
    }

    pub(crate) fn u8(&mut self, key: u8) -> Result<Option<u8>, RecordError> {
        self.fixed(key).map(|value| value.map(u8::from_be_bytes))
    }

    pub(crate) fn u32(&mut self, key: u8) -> Result<Option<u32>, RecordError> {
        self.fixed(key).map(|value| value.map(u32::from_be_bytes))
    }

    pub(crate) fn u64(&mut self, key: u8) -> Result<Option<u64>, RecordError> {
        self.fixed(key).map(|value| value.map(u64::from_be_bytes))
    }

    /// A value of any length up to `max` (R4).
    pub(crate) fn bytes(&mut self, key: u8, max: usize) -> Result<Option<&'a [u8]>, RecordError> {
        match self.field(key)? {
            Some(value) if value.len() > max => Err(RecordError::TooLong),
            value => Ok(value),
        }
    }

    /// A value of exactly `N` bytes (R4).
    pub(crate) fn bytes_n<const N: usize>(
        &mut self,
        key: u8,
    ) -> Result<Option<&'a [u8; N]>, RecordError> {
        self.field(key)?
            .map(|value| value.try_into().map_err(|_| RecordError::Width))
            .transpose()
    }

    /// UTF-8 of at most `max` bytes (R4). The length is checked first, so an
    /// oversized value is never walked.
    pub(crate) fn text(&mut self, key: u8, max: usize) -> Result<Option<&'a str>, RecordError> {
        self.bytes(key, max)?
            .map(|value| core::str::from_utf8(value).map_err(|_| RecordError::Utf8))
            .transpose()
    }

    /// Walks every field left, so that no record can hide trailing bytes or,
    /// under `Reject`, a key the schema never asked for (R5).
    pub(crate) fn end(mut self) -> Result<(), RecordError> {
        while self.next_field()?.is_some() {
            self.skip_unknown()?;
        }
        Ok(())
    }

    /// An integer value, exactly as wide as its type (R3).
    fn fixed<const N: usize>(&mut self, key: u8) -> Result<Option<[u8; N]>, RecordError> {
        Ok(self.bytes_n::<N>(key)?.copied())
    }

    /// The value of `key`, skipping the unknown keys below it by the policy.
    fn field(&mut self, key: u8) -> Result<Option<&'a [u8]>, RecordError> {
        while let Some(field) = self.next_field()? {
            match field.key.cmp(&key) {
                core::cmp::Ordering::Less => self.skip_unknown()?,
                core::cmp::Ordering::Equal => return Ok(Some(field.value)),
                core::cmp::Ordering::Greater => {
                    self.pending = Some(field);
                    return Ok(None);
                }
            }
        }
        Ok(None)
    }

    /// Frames the next field with the checks of R2, in their order: header,
    /// length against the bytes present, then key order.
    fn next_field(&mut self) -> Result<Option<Field<'a>>, RecordError> {
        if let Some(field) = self.pending.take() {
            return Ok(Some(field));
        }
        if self.rest.is_empty() {
            return Ok(None);
        }
        let (header, rest) = self
            .rest
            .split_first_chunk::<FIELD_HEADER_LEN>()
            .ok_or(RecordError::Truncated)?;
        let [key, len @ ..] = *header;
        let len = usize::try_from(u32::from_be_bytes(len)).map_err(|_| RecordError::Truncated)?;
        let (value, rest) = rest.split_at_checked(len).ok_or(RecordError::Truncated)?;
        if self.last_key.is_some_and(|last| key <= last) {
            return Err(RecordError::KeyOrder);
        }
        self.last_key = Some(key);
        self.rest = rest;
        Ok(Some(Field { key, value }))
    }

    fn skip_unknown(&self) -> Result<(), RecordError> {
        match self.unknown {
            UnknownKeys::Ignore => Ok(()),
            UnknownKeys::Reject => Err(RecordError::UnknownKey),
        }
    }
}
