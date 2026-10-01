//! The record encoding of `docs/spec.md` §4 (ADR 0023, spec 017-record-encoding).
//!
//! A record is a sequence of fields `key` (1 byte) ‖ `len` (4 bytes, big-endian)
//! ‖ `value`, in strictly increasing key order. The decoder is typed: each
//! schema reads its keys in order through a [`Reader`] and checks every value
//! against the type the schema gives it, so there is no generic tree of values
//! (R9). A nested record or a list item is decoded by the decoder of its own
//! named schema, and no schema is recursive, so the depth of a decode is fixed
//! by the schemas, never by the input (spec 020-store-files R1). Which keys a
//! record has, and which error a failure becomes, belong to the spec that owns
//! the record.

use core::cmp::Ordering;

use zeroize::Zeroizing;

#[cfg(test)]
mod tests;

#[cfg(any(test, fuzzing))]
pub(crate) mod test_schema;

/// Bytes of a field before its value: the key and the length (R1).
pub(crate) const FIELD_HEADER_LEN: usize = 5;

/// Bytes of a list item before its value: the length (spec 020 R1).
pub(crate) const ITEM_HEADER_LEN: usize = 4;

/// The encoded length of a record whose present fields have these value
/// lengths (R1), for a writer allocated at its exact size (spec 020 R25).
/// Saturating: every caller checks each value's bound first, so it never
/// saturates, and a writer given a wrong length refuses with `TooLong`.
pub(crate) fn record_len(values: &[Option<usize>]) -> usize {
    values.iter().flatten().fold(0, |sum, len| {
        sum.saturating_add(FIELD_HEADER_LEN).saturating_add(*len)
    })
}

/// The encoded length of a `list<T>` value of items of these lengths (spec
/// 020 R1), saturating as [`record_len`].
pub(crate) fn list_len(items: impl IntoIterator<Item = usize>) -> usize {
    items.into_iter().fold(0, |sum, len| {
        sum.saturating_add(ITEM_HEADER_LEN).saturating_add(len)
    })
}

/// Why a record was rejected, one variant per rule of spec 017.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RecordError {
    /// Fewer bytes than a field header, or a length beyond the buffer (R2, R5).
    Truncated,
    /// A key not greater than the previous one, duplicates included (R2), or
    /// a schema that writes or asks for its keys out of order (R11, Interface).
    KeyOrder,
    /// An integer, `bool` or `bytesN` value of the wrong length, or a `bool`
    /// other than 0x00 and 0x01 (R3, R4, spec 020 R1).
    Width,
    /// A `text` value that is not UTF-8 (R4).
    Utf8,
    /// A mandatory key that is absent (R6).
    Missing,
    /// A key the schema does not name, under [`UnknownKeys::Reject`] (R7).
    UnknownKey,
    /// A record, value, list or writer output above its maximum (R4, R8,
    /// R11, spec 020 R1).
    TooLong,
}

/// What a reader does with a key the schema does not name (R7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum UnknownKeys {
    Ignore,
    Reject,
}

/// Writes one record in its canonical encoding (R10) into a buffer allocated
/// once, which never grows (R11).
pub(crate) struct Writer {
    buf: Zeroizing<Vec<u8>>,
    max: usize,
    last_key: Option<u8>,
}

impl Writer {
    /// A writer of at most `max` bytes, all allocated here: a `Vec` that grew
    /// would free its old copy of a secret without wiping it (R11). `max` is a
    /// constant of the schema, never input.
    pub(crate) fn with_capacity(max: usize) -> Writer {
        Writer {
            buf: Zeroizing::new(Vec::with_capacity(max)),
            max,
            last_key: None,
        }
    }

    /// A `u8` value, 1 byte (R3). Errors as [`Writer::bytes`].
    pub(crate) fn u8(&mut self, key: u8, value: u8) -> Result<(), RecordError> {
        self.bytes(key, &value.to_be_bytes())
    }

    /// A `u32` value, 4 bytes big-endian (R3). Errors as [`Writer::bytes`].
    pub(crate) fn u32(&mut self, key: u8, value: u32) -> Result<(), RecordError> {
        self.bytes(key, &value.to_be_bytes())
    }

    /// A `u64` value, 8 bytes big-endian (R3). Errors as [`Writer::bytes`].
    pub(crate) fn u64(&mut self, key: u8, value: u64) -> Result<(), RecordError> {
        self.bytes(key, &value.to_be_bytes())
    }

    /// A `bool` value, 1 byte, 0x00 or 0x01 (spec 020 R1). Errors as
    /// [`Writer::bytes`].
    pub(crate) fn bool(&mut self, key: u8, value: bool) -> Result<(), RecordError> {
        self.bytes(key, &[u8::from(value)])
    }

    /// A `list<T>` value: each item `len` (4 bytes, big-endian) ‖ item, in the
    /// order given (spec 020 R1). The count and the item bounds are the
    /// schema's to check before it writes.
    ///
    /// # Errors
    ///
    /// As [`Writer::bytes`], with `TooLong` also for an item above 2^32 − 1
    /// bytes. A failed write leaves the writer as it was.
    pub(crate) fn list<I: AsRef<[u8]>>(&mut self, key: u8, items: &[I]) -> Result<(), RecordError> {
        let value_len = items.iter().try_fold(0usize, |sum, item| {
            ITEM_HEADER_LEN
                .checked_add(item.as_ref().len())
                .and_then(|item_len| sum.checked_add(item_len))
                .ok_or(RecordError::TooLong)
        })?;
        self.field_header(key, value_len)?;
        for item in items {
            let item = item.as_ref();
            let len = u32::try_from(item.len()).map_err(|_| RecordError::TooLong)?;
            self.buf.extend_from_slice(&len.to_be_bytes());
            self.buf.extend_from_slice(item);
        }
        Ok(())
    }

    /// A `bytes` or `bytesN` value, the schema knowing which, or a nested
    /// record, the encoding of its own schema (spec 020 R1).
    ///
    /// # Errors
    ///
    /// `KeyOrder` for a key not greater than the last one written, `TooLong`
    /// for a field past the capacity or a value above 2^32 − 1 bytes (R11). A
    /// failed write leaves the writer as it was.
    pub(crate) fn bytes(&mut self, key: u8, value: &[u8]) -> Result<(), RecordError> {
        self.field_header(key, value.len())?;
        self.buf.extend_from_slice(value);
        Ok(())
    }

    /// A `text` value, its UTF-8 bytes. Errors as [`Writer::bytes`].
    pub(crate) fn text(&mut self, key: u8, value: &str) -> Result<(), RecordError> {
        self.bytes(key, value.as_bytes())
    }

    /// The record written so far.
    pub(crate) fn finish(self) -> Zeroizing<Vec<u8>> {
        self.buf
    }

    /// Checks a field of `value_len` bytes against the key order and the
    /// capacity, then writes its key and length; the caller writes exactly
    /// `value_len` bytes after it. Nothing is written on an error.
    fn field_header(&mut self, key: u8, value_len: usize) -> Result<(), RecordError> {
        if self.last_key.is_some_and(|last| key <= last) {
            return Err(RecordError::KeyOrder);
        }
        let len = u32::try_from(value_len).map_err(|_| RecordError::TooLong)?;
        let end = FIELD_HEADER_LEN
            .checked_add(value_len)
            .and_then(|field_len| field_len.checked_add(self.buf.len()))
            .ok_or(RecordError::TooLong)?;
        if end > self.max {
            return Err(RecordError::TooLong);
        }
        self.buf.push(key);
        self.buf.extend_from_slice(&len.to_be_bytes());
        self.last_key = Some(key);
        Ok(())
    }
}

/// The items of a `list<T>` value, each framed as `len` ‖ item and bounded by
/// `max_item_len` (spec 020 R1); the iterator stops after the first error.
struct Items<'a> {
    rest: &'a [u8],
    max_item_len: usize,
}

impl<'a> Iterator for Items<'a> {
    type Item = Result<&'a [u8], RecordError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.rest.is_empty() {
            return None;
        }
        let item = self.frame();
        if item.is_err() {
            self.rest = &[];
        }
        Some(item)
    }
}

impl<'a> Items<'a> {
    /// The next item: header, length against the bytes present, then the
    /// bound, in the order of R2 for fields.
    fn frame(&mut self) -> Result<&'a [u8], RecordError> {
        let (header, rest) = self
            .rest
            .split_first_chunk::<ITEM_HEADER_LEN>()
            .ok_or(RecordError::Truncated)?;
        let len =
            usize::try_from(u32::from_be_bytes(*header)).map_err(|_| RecordError::Truncated)?;
        let (item, rest) = rest.split_at_checked(len).ok_or(RecordError::Truncated)?;
        if len > self.max_item_len {
            return Err(RecordError::TooLong);
        }
        self.rest = rest;
        Ok(item)
    }
}

/// One field as it sits in the buffer, framing checked, value not yet typed.
struct Field<'a> {
    key: u8,
    value: &'a [u8],
}

/// Reads one record by its schema: keys in increasing order, each getter
/// returning `None` for an absent key and borrowing the value from the buffer.
///
/// A getter frames fields only until it meets its key or a greater one, so a
/// schema can check a value before the next field is looked at (specs 011 R3,
/// 013 R12), and an absent key is decided by the first greater key or the end.
#[must_use]
pub(crate) struct Reader<'a> {
    rest: &'a [u8],
    last_key: Option<u8>,
    /// The key last asked for; a schema that asks out of order gets
    /// `KeyOrder` instead of a silent `None`.
    last_asked: Option<u8>,
    /// A field already framed whose key is above the one last asked for.
    pending: Option<Field<'a>>,
    unknown: UnknownKeys,
}

impl<'a> Reader<'a> {
    /// A reader over `buf`, which must be at most `max_len` bytes (R8).
    ///
    /// # Errors
    ///
    /// `TooLong` for a longer buffer, before any field is framed.
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
            last_asked: None,
            pending: None,
            unknown,
        })
    }

    /// A `u8` value, exactly 1 byte (R3). Errors as [`Reader::bytes_n`].
    pub(crate) fn u8(&mut self, key: u8) -> Result<Option<u8>, RecordError> {
        Ok(self.bytes_n(key)?.copied().map(u8::from_be_bytes))
    }

    /// A `u32` value, exactly 4 bytes big-endian (R3). Errors as
    /// [`Reader::bytes_n`].
    pub(crate) fn u32(&mut self, key: u8) -> Result<Option<u32>, RecordError> {
        Ok(self.bytes_n(key)?.copied().map(u32::from_be_bytes))
    }

    /// A `u64` value, exactly 8 bytes big-endian (R3). Errors as
    /// [`Reader::bytes_n`].
    pub(crate) fn u64(&mut self, key: u8) -> Result<Option<u64>, RecordError> {
        Ok(self.bytes_n(key)?.copied().map(u64::from_be_bytes))
    }

    /// A `bool` value, exactly 1 byte, 0x00 or 0x01 (spec 020 R1).
    ///
    /// # Errors
    ///
    /// The errors of [`Reader::bytes_n`], then `Width` for any other byte.
    pub(crate) fn bool(&mut self, key: u8) -> Result<Option<bool>, RecordError> {
        self.bytes_n::<1>(key)?
            .map(|[value]| match value {
                0x00 => Ok(false),
                0x01 => Ok(true),
                _ => Err(RecordError::Width),
            })
            .transpose()
    }

    /// A nested record, decoded by `decode`, the decoder of its own schema,
    /// which checks its own maximum length and calls its own `end` (spec 020
    /// R1). The decoder may return the error of the spec that owns the
    /// schema, into which the codec's own errors convert.
    ///
    /// # Errors
    ///
    /// The framing errors of [`Reader::bytes`], then whatever `decode` returns.
    pub(crate) fn record<T, E: From<RecordError>>(
        &mut self,
        key: u8,
        decode: impl FnOnce(&'a [u8]) -> Result<T, E>,
    ) -> Result<Option<T>, E> {
        self.field(key)?.map(decode).transpose()
    }

    /// A `list<T>` value of at most `max_items` items of at most
    /// `max_item_len` bytes each, every item decoded by `decode` (spec 020
    /// R1). The items are framed and counted before the first is decoded, so
    /// the list is allocated once at its exact length and never grows. The
    /// errors are as in [`Reader::record`].
    ///
    /// # Errors
    ///
    /// The framing errors of [`Reader::bytes`]; then, item by item, `Truncated`
    /// for bytes that do not complete an item header or an item, `TooLong` for
    /// an item above `max_item_len` or one item past `max_items`; then
    /// whatever `decode` returns.
    pub(crate) fn list<T, E: From<RecordError>>(
        &mut self,
        key: u8,
        max_items: usize,
        max_item_len: usize,
        mut decode: impl FnMut(&'a [u8]) -> Result<T, E>,
    ) -> Result<Option<Vec<T>>, E> {
        let Some(value) = self.field(key)? else {
            return Ok(None);
        };
        let items = || Items {
            rest: value,
            max_item_len,
        };
        let mut count = 0usize;
        for item in items() {
            item?;
            if count >= max_items {
                return Err(RecordError::TooLong.into());
            }
            count = count.checked_add(1).ok_or(RecordError::TooLong)?;
        }
        let mut list = Vec::with_capacity(count);
        for item in items() {
            list.push(decode(item?)?);
        }
        Ok(Some(list))
    }

    /// A value of any length up to `max` (R4).
    ///
    /// # Errors
    ///
    /// The framing errors of R2 for this field or any skipped before it
    /// (`Truncated`, `KeyOrder`, `UnknownKey` under `Reject`), `KeyOrder` for a
    /// key not greater than the one last asked for, then `TooLong` above `max`.
    pub(crate) fn bytes(&mut self, key: u8, max: usize) -> Result<Option<&'a [u8]>, RecordError> {
        match self.field(key)? {
            Some(value) if value.len() > max => Err(RecordError::TooLong),
            value => Ok(value),
        }
    }

    /// A value of exactly `N` bytes (R4).
    ///
    /// # Errors
    ///
    /// The errors of [`Reader::bytes`] before the value, then `Width`.
    pub(crate) fn bytes_n<const N: usize>(
        &mut self,
        key: u8,
    ) -> Result<Option<&'a [u8; N]>, RecordError> {
        self.field(key)?
            .map(|value| value.try_into().map_err(|_| RecordError::Width))
            .transpose()
    }

    /// UTF-8 of at most `max` bytes (R4).
    ///
    /// # Errors
    ///
    /// The errors of [`Reader::bytes`], then `Utf8`: the length comes first, so
    /// an oversized value is never walked.
    pub(crate) fn text(&mut self, key: u8, max: usize) -> Result<Option<&'a str>, RecordError> {
        self.bytes(key, max)?
            .map(|value| core::str::from_utf8(value).map_err(|_| RecordError::Utf8))
            .transpose()
    }

    /// Walks every field left, so that no record can hide trailing bytes or,
    /// under `Reject`, a key the schema never asked for (R5).
    ///
    /// # Errors
    ///
    /// The framing errors of R2 for any field left, and `UnknownKey` for any
    /// of them under `Reject`.
    pub(crate) fn end(mut self) -> Result<(), RecordError> {
        while self.next_field()?.is_some() {
            self.unknown_key()?;
        }
        Ok(())
    }

    /// The value of `key`, skipping the unknown keys below it by the policy.
    fn field(&mut self, key: u8) -> Result<Option<&'a [u8]>, RecordError> {
        if self.last_asked.is_some_and(|last| key <= last) {
            return Err(RecordError::KeyOrder);
        }
        self.last_asked = Some(key);
        while let Some(field) = self.next_field()? {
            match field.key.cmp(&key) {
                Ordering::Less => self.unknown_key()?,
                Ordering::Equal => return Ok(Some(field.value)),
                Ordering::Greater => {
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

    /// The policy's verdict on a key the schema does not name (R7).
    fn unknown_key(&self) -> Result<(), RecordError> {
        match self.unknown {
            UnknownKeys::Ignore => Ok(()),
            UnknownKeys::Reject => Err(RecordError::UnknownKey),
        }
    }
}
