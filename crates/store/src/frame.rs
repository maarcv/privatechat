//! The plaintext framing of the files (spec 020-store-files R4, R5, R7): the
//! magic and version of `state.bin` and `settings.bin`, the log header and
//! the `len` before each entry. It carries no secret; everything inside the
//! box is `core`'s.

use privatechat_core::{
    ChannelState, DirName, LogRecord, MAX_LOG_ENTRY, MAX_SETTINGS_FILE, MAX_STATE_FILE, Settings,
    StorageKey, StoreError,
};

/// The magic of `state.bin` (R4).
pub(crate) const STATE_MAGIC: [u8; 4] = *b"PSTA";

/// The magic of `settings.bin` (R4).
pub(crate) const SETTINGS_MAGIC: [u8; 4] = *b"PSET";

/// The magic of `messages.log` (R5).
pub(crate) const LOG_MAGIC: [u8; 4] = *b"PLOG";

/// The `store_version` this store writes and reads (R4, R5).
pub(crate) const STORE_VERSION: u8 = 1;

/// The shortest `state.bin` or `settings.bin`: magic, version, nonce and an
/// empty record's tag (R7).
pub(crate) const MIN_FILE: usize = 45;

/// The log header: magic, version and `generation` u32 BE (R5).
pub(crate) const LOG_HEADER_LEN: usize = 9;

/// The `len` u32 BE before each log entry (R5).
const ENTRY_LEN_LEN: usize = 4;

/// The shortest log entry: a nonce and an empty record's tag (R7).
const MIN_ENTRY: usize = 40;

/// Magic and version, before the `nonce ‖ box` of `state.bin` and
/// `settings.bin`.
const FILE_HEADER_LEN: usize = 5;

/// `magic ‖ store_version ‖ sealed`, the bytes of `state.bin` or
/// `settings.bin` (R4).
pub(crate) fn frame(magic: [u8; 4], sealed: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(FILE_HEADER_LEN.saturating_add(sealed.len()));
    bytes.extend_from_slice(&magic);
    bytes.push(STORE_VERSION);
    bytes.extend_from_slice(sealed);
    bytes
}

/// Opens a framed file in the order of R7: its minimum size, its magic, its
/// version (a version other than 1 whose box still opens as version 1 is a
/// forged header, so `Corrupt`), its size limit, and then `open` of `core`,
/// which checks the box and the record.
fn open_framed<T>(
    bytes: &[u8],
    magic: [u8; 4],
    limit: usize,
    open: impl Fn(&[u8]) -> Result<T, StoreError>,
) -> Result<T, StoreError> {
    if bytes.len() < MIN_FILE {
        return Err(StoreError::Corrupt);
    }
    let (header, sealed) = bytes
        .split_first_chunk::<FILE_HEADER_LEN>()
        .ok_or(StoreError::Corrupt)?;
    let (found, version) = header.split_at(4);
    if found != magic {
        return Err(StoreError::Corrupt);
    }
    if version != [STORE_VERSION] {
        return match open(sealed) {
            Ok(_) => Err(StoreError::Corrupt),
            Err(_) => Err(StoreError::UnsupportedVersion),
        };
    }
    if bytes.len() > limit {
        return Err(StoreError::Corrupt);
    }
    open(sealed)
}

/// The state of a `state.bin` of the directory `name` (R7).
pub(crate) fn open_state(
    bytes: &[u8],
    key: &StorageKey,
    name: &DirName,
) -> Result<ChannelState, StoreError> {
    open_framed(bytes, STATE_MAGIC, MAX_STATE_FILE, |sealed| {
        ChannelState::open(key, name, sealed)
    })
}

/// The settings of a `settings.bin` (R7).
pub(crate) fn open_settings(bytes: &[u8], key: &StorageKey) -> Result<Settings, StoreError> {
    open_framed(bytes, SETTINGS_MAGIC, MAX_SETTINGS_FILE, |sealed| {
        Settings::open(key, sealed)
    })
}

/// The 9-byte header of a log of `generation` (R5).
pub(crate) fn log_header(generation: u32) -> [u8; LOG_HEADER_LEN] {
    let mut header = [0u8; LOG_HEADER_LEN];
    let (start, rest) = header.split_at_mut(4);
    start.copy_from_slice(&LOG_MAGIC);
    let (version, number) = rest.split_at_mut(1);
    version.copy_from_slice(&[STORE_VERSION]);
    number.copy_from_slice(&generation.to_be_bytes());
    header
}

/// The `generation` of a log, or `Corrupt` for a log shorter than its
/// header, with another magic, or of another version: a log schema change
/// raises `state_version`, never the log's own byte (R7).
pub(crate) fn read_log_header(bytes: &[u8]) -> Result<u32, StoreError> {
    let (header, _) = bytes
        .split_first_chunk::<LOG_HEADER_LEN>()
        .ok_or(StoreError::Corrupt)?;
    let (start, rest) = header.split_at(4);
    let (version, number) = rest.split_at(1);
    if start != LOG_MAGIC || version != [STORE_VERSION] {
        return Err(StoreError::Corrupt);
    }
    let number: [u8; 4] = number.try_into().map_err(|_| StoreError::Corrupt)?;
    Ok(u32::from_be_bytes(number))
}

/// Whether the log of a directory without `state.bin` shows a first commit
/// cut before its header was durable (R13, R19): absent, shorter than its
/// header, or a header alone that is not one of a generation ≥ 1. A longer
/// log holds entries, and a lost `state.bin` is reported, not erased.
pub(crate) fn is_unborn_log(log: Option<&[u8]>) -> bool {
    match log {
        None => true,
        Some(bytes) if bytes.len() < LOG_HEADER_LEN => true,
        Some(bytes) if bytes.len() == LOG_HEADER_LEN => {
            !matches!(read_log_header(bytes), Ok(generation) if generation >= 1)
        }
        Some(_) => false,
    }
}

/// `records` sealed and framed as log entries from the byte `at` of a log of
/// `generation`: each `len` ‖ `nonce ‖ box`, sealed for the offset of its
/// `len` (R5, R9).
pub(crate) fn seal_entries(
    records: &[LogRecord],
    key: &StorageKey,
    name: &DirName,
    generation: u32,
    at: u64,
) -> Result<Vec<u8>, StoreError> {
    let prefix = u64::try_from(ENTRY_LEN_LEN).map_err(|_| StoreError::LogFull)?;
    let mut bytes = Vec::new();
    let mut offset = at;
    for record in records {
        let sealed = record.seal(key, name, generation, offset)?;
        let len = u32::try_from(sealed.len()).map_err(|_| StoreError::Corrupt)?;
        bytes.extend_from_slice(&len.to_be_bytes());
        bytes.extend_from_slice(&sealed);
        offset = offset
            .checked_add(u64::from(len))
            .and_then(|end| end.checked_add(prefix))
            .ok_or(StoreError::LogFull)?;
    }
    Ok(bytes)
}

/// Every record of `log`, a log cut to its committed length whose header
/// carries `generation`: each entry's `len` within 40..=65 576, the entry
/// whole inside the log, and its box opened for its own offset (R7, R9).
pub(crate) fn open_entries(
    log: &[u8],
    key: &StorageKey,
    name: &DirName,
    generation: u32,
) -> Result<Vec<LogRecord>, StoreError> {
    let mut rest = log.get(LOG_HEADER_LEN..).ok_or(StoreError::Corrupt)?;
    let mut offset = LOG_HEADER_LEN;
    let mut records = Vec::new();
    while !rest.is_empty() {
        let (len, after) = rest
            .split_first_chunk::<ENTRY_LEN_LEN>()
            .ok_or(StoreError::Corrupt)?;
        let len = usize::try_from(u32::from_be_bytes(*len)).map_err(|_| StoreError::Corrupt)?;
        if !(MIN_ENTRY..=MAX_LOG_ENTRY).contains(&len) {
            return Err(StoreError::Corrupt);
        }
        let (entry, after) = after.split_at_checked(len).ok_or(StoreError::Corrupt)?;
        let at = u64::try_from(offset).map_err(|_| StoreError::Corrupt)?;
        records.push(LogRecord::open(key, name, entry, generation, at)?);
        offset = offset
            .checked_add(ENTRY_LEN_LEN)
            .and_then(|end| end.checked_add(len))
            .ok_or(StoreError::Corrupt)?;
        rest = after;
    }
    Ok(records)
}
