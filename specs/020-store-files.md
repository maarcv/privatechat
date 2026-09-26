# 020 — Store files: encrypted state and log with atomic commit

Status: draft
Phase: 2
Related ADRs: 0019, 0020, 0021, 0023, 0029, 0034, 0035
Depends on: 010-primitives-wrapper, 011-config-format, 015-test-vectors, 016-fuzz-harness, 017-record-encoding
Blocks: 021-channel-session, 023-ttl-purge, 027-core-api, 028-session-sans-io, 040-uniffi, 041-desktop-bridge
Human reviewer: Marc Vilardebó · Accepted on: —

## Context

The client keeps no database (ADR 0021). Per channel there are two files: a small `state.bin` rewritten whole on every commit, and an append-only `messages.log`. The app settings live in a third file of the same kind. One `Store` in Rust serves the three platforms (ADR 0020), and every change to a channel goes through its single write operation, `commit` (AGENTS 23). ADR 0035 binds each log entry to its channel, its file generation and its offset, and names each channel directory by a keyed hash.

This spec fixes the bytes on disk, the commit and recovery protocol, the data directory, the limits that bound the files, and the split between `core` and the `store` crate. What each state field means, and when it changes, belongs to the spec that changes it: 021-channel-session (identity, counters, cursor, `outbox`, own-key signatures, `purge_at`), 022-peers-tofu (peers), 023-ttl-purge (compaction and the message list), 024-key-retired and 025-identity-regen (retirement), 026-peer-limits (peer counts), 027-core-api (the `Device` that owns the data directory).

**In plain words.** Each channel is a folder with two locked boxes. The small box holds everything that is not a message: the channel key, one's own key, the counters, the list of people and the messages waiting to leave. It is small, so every change writes a complete new copy next to the old one and then swaps the names in one step, which the file system guarantees is all or nothing. The big box is a journal of messages: new entries are only ever added at the end, each one sealed on its own and stamped with where it belongs. The small box remembers how long the journal was at the last swap, so if the phone dies halfway through adding entries, whatever sits after that length is cut off when the channel is opened again. Once in a while the journal is copied without the expired entries and swapped the same way. Each folder has its own key, derived from the device key and the folder's name, so nothing can be moved from one folder to another.

**Split of the code.**

- `core` owns every byte that is encrypted or encoded: the `Store` and `Vault` traits, `WriteBatch`, `ChannelState`, `LogRecord`, `Settings`, `StorageKey`, `StoreError`, the record schemas and the `pub` functions that seal and open each file kind. The codec and `core::crypto` stay crate-internal (`docs/spec.md` §9); these functions are the only way `store` reaches them.
- `store` owns every system call: the data directory, the `LOCK` file, reads, appends, `fsync`, `rename`, truncation and deletion, and the plaintext framing of the files — the magic and version bytes of `state.bin` and `settings.bin`, the log header of R5 and the 4-byte `len` before each entry — which carries no secret; on a `store_version` other than 1 of `state.bin` or `settings.bin` it calls the file kind's `open` of `core` and returns `Corrupt` when that returns `Ok`, else `UnsupportedVersion`, and for `messages.log` returns `Corrupt` when the `state.bin` it loads with opened as version 1 (R7, R12). It never encodes a record field or touches libsodium on its own; what `ChannelState`, `LogRecord` and `Settings` take in `open` and return from `seal` is `nonce ‖ box` alone. R4, R5 and R7 are split accordingly: `store` writes and checks the framing (minimum sizes 45 for `state.bin` and `settings.bin` and 9 for `messages.log`, magic, version, size limit), and `core` checks the rest (at least 40 bytes, the box, the record).

AGENTS 23 says every state write goes through `commit`; `compact` (R15) is the one other writer of `state.bin`, and it writes only the new log position of a state it was handed, never a change of meaning.

## Requirements

**Record codec and primitives**

- R1 This spec MUST add to spec 017-record-encoding the three types `docs/spec.md` §4 lists and phase 1 left out, both in `Reader` and in `Writer`: `bool` (exactly 1 byte, 0x00 or 0x01, else `RecordError::Width`); a nested record (the value is a record of a named schema, decoded by that schema's own decoder with its own maximum length and its own `end()`); and `list<T>` (zero or more items, each `len` u32 BE ‖ item, with a maximum item count and a maximum item length given by the caller, else `RecordError::TooLong`, and bytes that do not complete an item `RecordError::Truncated`). It MUST amend 017-R9 and 017's Security line "a value is never a record and nothing nests" to "no schema is recursive", 017's sentence on the largest value to the `outbox` list of this spec (a value of at most 2 073 920 bytes, within the 4-byte length), and 017's Security line on fuzz targets to allow a sealed `open` whose decoder is fuzzed on its own (R29); and it MUST amend spec 011-config-format's sentence "`RecordError` does not leave `proto`" to "`RecordError` does not leave the core's decoders; every `pub` function returns `Error` or `StoreError`".
- R2 This spec MUST amend spec 010-primitives-wrapper so that `secretbox_open` returns `Zeroizing<Vec<u8>>`, and its R16 and T25 so that `core` may declare the feature `test-support`, which enables nothing outside the module `testing`; and it MUST amend the sentences of the rust skill it contradicts ("No feature flags in `core`", "no `Send` bounds to think about", and "no `Arc<Mutex<_>>` in `core`", which the `testing` module needs).

**Keys and file formats**

- R3 Every file MUST be sealed with a key derived from `K_db` and never with `K_db` itself: the state and log of a channel with `K_store = keyed_hash(K_db, "privatechat/store/v1" ‖ name)`, where `name` is the 16-byte directory hash of R18, and the settings with `K_settings = keyed_hash(K_db, "privatechat/settings/v1")`, each derived into a `Secret<32>` at each seal and open and dropped after it.
- R4 `state.bin` MUST be `"PSTA"` ‖ `store_version` u8 = 1 ‖ `nonce` 24 bytes ‖ `secretbox_seal(K_store, nonce, state record)`; `settings.bin` MUST be `"PSET"` ‖ 1 ‖ `nonce` ‖ `secretbox_seal(K_settings, nonce, settings record)`; each write draws a fresh nonce with `random_bytes`.
- R5 `messages.log` MUST be `"PLOG"` ‖ `store_version` u8 = 1 ‖ `generation` u32 BE, a 9-byte header, followed by zero or more entries, each `len` u32 BE ‖ `nonce` 24 bytes ‖ `secretbox_seal(K_store, nonce, log record)`, where `len` counts the nonce and the box; `core` produces and opens the `nonce ‖ box` of each entry, and `store` writes the header and each `len`.
- R6 `store` MUST read at most the limit of the Limits table plus one byte of every file, allocating nothing beyond it, and leave the verdict on a larger file to the order of R7.
- R7 Opening any file MUST check, in this order: at least the minimum size of its kind (45 bytes for `state.bin` and `settings.bin`, 9 for `messages.log`, 40 for a log entry), else `Corrupt`; the magic, else `Corrupt`; `store_version` = 1, else `StoreError::UnsupportedVersion` — except that for `state.bin` and `settings.bin`, when `ChannelState::open` (or `Settings::open`) of its `nonce ‖ box` returns `Ok`, the header was forged outside the box and the result is `Corrupt`, any error of that open leaving `UnsupportedVersion` (a newer app that raises `store_version` MUST also change what the box holds so that it does not open as version 1); a `messages.log` header whose version is not 1 next to a `state.bin` that opened as version 1 gives `Corrupt`, since a log schema change raises `state_version` (R8), never the log's own byte; the size limit, else `Corrupt`; the box, where any failure is `Corrupt`; the record, where any `RecordError` is `Corrupt`.
- R8 Before the full decode, key 0 of the state and settings records (`state_version`, `settings_version`) MUST be read and, when it is not 1, give `UnsupportedVersion`; any later change to the state, log or settings schemas MUST raise key 0 (`state_version` for a state or log change, `settings_version` for a settings change), `store_version` being raised only together with a change to what the box holds (R7), so that an older app reports `UnsupportedVersion` for a newer app's data, not `Corrupt`. The state record MUST be decoded under `UnknownKeys::Reject` with the schema "State record" below; the settings record the same with the schema "Settings record", whose `default_server_url` and `socks5_proxy` MUST satisfy the grammars of Limits and whose `lock_timeout_seconds` MUST be within 0..=86 400, else `Corrupt`; `Settings::seal` MUST refuse with `Corrupt` any value `open` would refuse.
- R9 Every log record MUST be decoded under `UnknownKeys::Reject` with the schema "Log record" below and MUST carry the `generation` of its file and its own byte `offset`; a record whose `generation` or `offset` differs from where it was read MUST return `Corrupt`. Because a channel's files are sealed under its own `K_store` (R3), an entry or a state of another directory does not open.

**Commit and recovery**

- R10 `commit(batch: &WriteBatch)` MUST run these steps and return `Ok` only after the last one: (1) if the batch appends records, truncate `messages.log` to its committed end, write the records there and `fsync` the file; (2) write the state record, with `log_committed_len` and `log_generation` set by the store to the new end and the current generation, to `state.bin.tmp`, `fsync` it, `rename` it over `state.bin`, and `fsync` the directory. A commit with no appended records MUST skip step 1.
- R11 A `commit` or `compact` that fails before the `rename` of its state MUST return the `StoreError` of that step and leave the files so that the next `load` returns the previous commit, deleting, best effort, each of `state.bin.tmp` and `messages.log.new` it wrote, so that a compaction failing on a full disk does not keep the space it took (a leftover of a crash is deleted by R12 and R14). A failure at or after that `rename` MUST poison the store: every later call returns `StoreError::Io` until the store is dropped and opened again with `Vault::create`, whose `load` then decides which commit stands.
- R12 `load` MUST delete a leftover `state.bin.tmp` (best effort: a failed deletion is ignored, since the next commit replaces it), read `state.bin`, check that the stored `channel_id` gives this directory's name under R18, else `Corrupt`, apply R14, check that the `generation` of `messages.log` equals `log_generation`, truncate the log to `log_committed_len` when it is longer and `fsync` it, return `Corrupt` when it is shorter, and open every entry up to `log_committed_len` by R7 and R9, returning `Corrupt` for any entry that fails.
- R13 `load` of a directory without `state.bin` whose `messages.log` is absent, shorter than 9 bytes, or 9 bytes that are not a valid header of a generation ≥ 1 (a first commit cut before its header was durable), MUST return `Ok(None)`; the first commit of a channel MUST write `messages.log` with the header of generation 0 and no entry, `fsync` it, and then write `state.bin` by R10 step 2.
- R14 When `state.bin` names generation `g + 1` and `messages.log` carries `g`, `load` MUST rename a `messages.log.new` of generation `g + 1` over `messages.log`; any other mismatch MUST return `Corrupt`; and any `messages.log.new` this rule does not rename MUST be deleted, best effort (a failed deletion is ignored, since the next compaction overwrites it).
- R15 `compact(state, now)` MUST write `messages.log.new` with the header of generation `log_generation + 1` and every committed record whose `purge_at` is not below `now`, re-sealed with a fresh nonce at its new offset and its new generation, `fsync` it; then write `state` by R10 step 2 with the new generation and length; then `rename` `messages.log.new` over `messages.log` and `fsync` the directory; and return the number of records dropped. With nothing to drop it MUST write nothing and return 0.
- R16 A commit whose appended records would take `messages.log` beyond 67 108 864 bytes MUST write nothing and return `StoreError::LogFull`; `log_len()` MUST return the committed length, so that spec 021-channel-session can keep its headroom.

**Data directory**

- R17 `DataDir::open(path, key)` MUST create `path` and `path/channels/` if they are absent, `fsync`ing each parent after creating a directory, take an exclusive lock with `File::try_lock` on `path/LOCK`, held until the `DataDir` and every store it handed out are dropped, and return `StoreError::Locked` when another holder has it.
- R18 A channel directory MUST be `path/channels/<name>`, where `name` is the lowercase hex of the first 16 bytes of `keyed_hash(K_db, "privatechat/dir/v1" ‖ channel_id)`.
- R19 `DataDir::open` MUST delete, best effort (a failed deletion is ignored and never fails `open`), under `channels/`, every directory ending in `.leaving`, and every directory without `state.bin` whose `messages.log` is absent, shorter than 9 bytes, or 9 bytes that are not a valid header of a generation ≥ 1; a directory without `state.bin` whose log holds entries is listed by R20, and its `load` returns `Corrupt`, so that a lost `state.bin` is reported instead of silently erasing a channel.
- R20 `Vault::list()` MUST return one store per directory under `channels/` left by R19, ignoring any entry that is not a directory or whose name is not 32 lowercase hex characters; `Vault::create(channel_id)` MUST return the store of that channel, creating its directory when absent and then `fsync`ing `channels/`; and either MUST return `StoreError::Locked` for a directory whose store is still alive, so that no two stores ever write one directory: `DataDir` and its stores share a set of live names, from which a `ChannelFiles` removes its own when it is dropped.
- R21 `destroy(&mut self)` MUST delete a leftover `<name>.leaving` first, then rename the channel directory to `<name>.leaving`, `fsync` `channels/`, and then delete it; a failure before the rename MUST return the error and leave the store usable, and a failure after it MUST return `Ok`, R19 finishing the deletion at the next open. `Vault::remove(name)` MUST do the same for the directory of a store that could not be loaded, named by `Store::name()`, and `Vault::dir_name(channel_id)` MUST return the name of R18.
- R22 `Vault::load_settings()` MUST return `Ok(None)` when `settings.bin` is absent, and `Vault::save_settings` MUST write it by R10 step 2 with no log.
- R23 Every system call of `store` MUST live in `crates/store/src/fs.rs`; `scripts/check_store_io.sh` MUST fail when one of the words `std::fs`, `std::io::Write`, `OpenOptions`, `File` or `std::process`, matched on word boundaries on code lines with comments stripped, appears in any other non-test source of `store`, and the CI MUST run it; `fs.rs` and the store's test module carry `#[allow(clippy::disallowed_methods, reason = "the one audited place of store I/O")]`. Under `cfg(windows)`, where a directory cannot be opened for `fsync`, and on any platform where the directory `fsync` fails with `io::ErrorKind::Unsupported` or `InvalidInput`, the directory `fsync` MUST be skipped and nothing else changes; a CI job on macOS runs T10.

**Types**

- R24 `StorageKey::from_bytes(bytes: &mut [u8; 32])` MUST copy `K_db` into a `Secret<32>` and fill `bytes` with zeros before returning; `StorageKey` MUST be added to `SECRET_TYPES` of spec 010-primitives-wrapper.
- R25 Every buffer that holds a plaintext record MUST be a `Zeroizing<Vec<u8>>`: each writer computes the exact encoded length of its record first (`encoded_len`) and calls `Writer::with_capacity` with it, so the buffer never grows and no 2.25 MiB buffer is wiped for a small state; the plaintext `secretbox_open` returns is already `Zeroizing` (R2).
- R26 `StoreError` MUST have exactly the unit variants `Io`, `Locked`, `Corrupt`, `UnsupportedVersion`, `LogFull` and `OutboxFull`, and MUST NOT carry an OS error, a path or any byte of a file; `core::Error` MUST gain the variant `Store(StoreError)`.
- R27 `ChannelState::seal` MUST return `StoreError::OutboxFull` for more than 32 `outbox` entries and `Corrupt` for any other value beyond the Limits table, so that the store never writes a file it would refuse to read.
- R28 `Store` and `Vault` MUST be `Send`, and `ChannelFiles` MUST share the lock and the key with its `DataDir` through `Arc`, so that the `Device` of spec 027-core-api can live behind a `Mutex` in the bindings.
- R29 This spec MUST amend spec 016-fuzz-harness R2, R8 and R9 with the targets `state_decode`, `log_record_decode` and `settings_decode` over the plaintext decoders, seeded from the records of `020.json`; the three sealed `open` functions are counted as reached by name by the check of 016-R6, and their decoders are the fuzzed part. Every record kind MUST have a round-trip property test (AGENTS 21).
- R30 This spec MUST add its section to `scripts/reference/vectors.py`, which produces `020.json`: the encoding of each codec type of R1, one reference state, log and settings record in plaintext, and the negatives of the Vectors table. The sealed files have no vector: no platform other than Rust reads them.

## Limits

| Item | Range | Out of range |
| --- | --- | --- |
| `state.bin` | 45..=2 359 341 B (29 B of magic, version and nonce; a record of at most 2 359 296 B; a 16-byte tag) | `Corrupt` |
| State record | 0..=2 359 296 B | `Corrupt` on open; `seal` refuses (R27) |
| `outbox` entries | 0..=32; ordinary entries 0..=31, one slot kept for a `key_retired` (spec 025-identity-regen) | `OutboxFull` |
| Peers | 0..=550 (spec 026-peer-limits) | `Corrupt` |
| One's own old keys | 0..=16 (spec 025-identity-regen) | `Corrupt` |
| `label`, `own_display_name`, `local_name`, `last_display_name`, a log `display_name` | 0..=`MAX_NAME` (64) B | `Corrupt` |
| `messages.log` | 9..=67 108 864 B | `LogFull` on commit; `Corrupt` on open |
| Log entry `len` | 40..=65 576 (nonce 24, tag 16, record ≤ 65 536) | `Corrupt` |
| Log record | 0..=65 536 B | `Corrupt` |
| `settings.bin` | 45..=1 069 B | `Corrupt` |
| Settings record | 0..=1 024 B | `Corrupt` |
| `default_server_url` | the grammar of spec 011-config-format R5 | `Corrupt` |
| `socks5_proxy` | host by the grammar of spec 011-config-format R5 ‖ `:` ‖ port 1..=65535 with no leading zero, at most 256 B | `Corrupt` |
| `lock_timeout_seconds` | 0..=86 400; 0 means lock on app switch | `Corrupt` |

The state record bound is the sum of its maxima — the config of at most 512 B, 550 peer records of at most 243 B, 32 `outbox` entries of at most 64 810 B, 16 old keys of 54 B, and the fixed fields — about 2.21 MB, rounded up to 2.25 MiB; T27 builds the largest state and checks that it seals and opens.

**State record** (`Reject`)

| key | field | type | owner |
| --- | --- | --- | --- |
| 0 | `state_version` | u8 = 1 | this spec |
| 1 | `channel_id` | bytes16 | this spec (R12) |
| 2 | `config` | bytes ≤ 512, the config record of spec 011-config-format without key 6 | 021-channel-session |
| 3 | `identity_seed` | bytes32 | 021-channel-session |
| 4 | `identity_epoch` | u32, raised by each regeneration | 025-identity-regen |
| 5 | `send_counter` | u64; `2^64 − 1` means exhausted | 021-channel-session |
| 6 | `cursor` | u64, optional | 021-channel-session |
| 7 | `own_display_name` | text ≤ 64, optional | 021-channel-session |
| 8 | `local_name` | text ≤ 64, optional | 027-core-api |
| 9 | `peers` | list of peer records, ≤ 550 | 022-peers-tofu |
| 10 | `outbox` | list of `outbox` entries, ≤ 32 | 021-channel-session |
| 11 | `retiring_seed` | bytes32, optional | 025-identity-regen |
| 12 | `own_old_keys` | list of old-key records, ≤ 16 | 025-identity-regen |
| 13 | `own_key_used_elsewhere` | bool | 021-channel-session |
| 14 | `read_only` | bool | 024-key-retired |
| 15 | `log_committed_len` | u64 | this spec (R10) |
| 16 | `log_generation` | u32 | this spec (R10) |
| 17 | `synced_at` | u64, optional, local time | 021-channel-session |
| 18 | `truncated_at` | u64, optional, local time | 021-channel-session |

Peer record: 0 `pk` bytes32; 1 `label` text ≤ 64, optional; 2 `verified` bool; 3 `muted` bool; 4 `retired_at` u64, optional; 5 `first_seen` u64; 6 `last_seen` u64; 7 `max_counter` u64, optional; 8 `last_display_name` bytes ≤ 64, optional.

`outbox` entry: 0 `client_ref` bytes16; 1 `kind` u8 (0 `text`, 1 `key_retired`); 2 `sent_at` u64; 3 `blob` bytes ≤ 64 673; 4 `signature` bytes64, unmasked (spec 013-wire-message R20); 5 `under_retired_key` bool; 6 `counter` u64.

Old-key record: 0 `pk` bytes32; 1 `retired_at` u64.

**Log record** (`Reject`; key 0 fixes which other keys are allowed, each mandatory unless marked optional)

| key | field | type | kinds |
| --- | --- | --- | --- |
| 0 | `kind` | u8: 0 message, 1 acked, 2 not delivered, 3 kept signature, 4 seen | all |
| 1 | `generation` | u32 | all (R9) |
| 2 | `offset` | u64 | all (R9) |
| 3 | `purge_at` | u64 (spec 021-channel-session R26) | all |
| 4 | `server_id` | bytes16 | message (optional: absent for one's own before its `ack`), acked, seen |
| 5 | `received_at` | u64 | message, acked |
| 6 | `sender_pk` | bytes32 | message, seen |
| 7 | `counter` | u64 | message, seen |
| 8 | `content` | u8: 0 text, 1 key_retired, 2 unreadable | message |
| 9 | `display_name` | bytes ≤ 64, optional | message |
| 10 | `sent_at` | u64 | message (optional: absent when `open` read none), kept signature |
| 11 | `body` | bytes ≤ 64 511, optional | message (present for text) |
| 12 | `own` | bool, sealed by this device | message |
| 13 | `client_ref` | bytes16 | message (optional: present when `own`), acked, not delivered, kept signature |
| 14 | `signature` | bytes64 | kept signature |
| 15 | `epoch` | u32, the `identity_epoch` it was sealed under | kept signature |

**Settings record**: 0 `settings_version` u8 = 1; 1 `default_server_url` text ≤ 256; 2 `lock_timeout_seconds` u32; 3 `socks5_proxy` text ≤ 256, optional.

## Interface

```
crates/core/src/storage.rs                 Store, Vault, WriteBatch, StorageKey, StoreError
crates/core/src/storage/state.rs           the state record and its seal/open
crates/core/src/storage/log.rs             the log record and its seal/open
crates/core/src/storage/settings.rs        the settings record and its seal/open
crates/core/src/storage/tests.rs           s020_* tests of the records
crates/core/src/testing.rs                 MemoryStore, MemoryVault, FailingStore, state_eq; cfg(any(test, fuzzing, feature = "test-support"))
crates/store/src/lib.rs                    DataDir, ChannelFiles
crates/store/src/fs.rs                     every system call (R23), the crash points and the fault injector
crates/store/src/tests.rs                  s020_* tests of the files
scripts/check_store_io.sh                  R23
```

```rust
// core
pub enum StoreError { Io, Locked, Corrupt, UnsupportedVersion, LogFull, OutboxFull }

pub struct StorageKey { /* Secret<32> */ }
impl StorageKey { pub fn from_bytes(bytes: &mut [u8; 32]) -> StorageKey; }

pub struct DirName(pub [u8; 16]);                  // the directory hash of R18
pub struct Settings { /* default_server_url, lock_timeout_seconds, socks5_proxy; pub(crate) */ }
pub struct ChannelState { /* the fields of the state record, pub(crate) */ }
pub struct LogRecord { /* the fields of the log record except generation and offset, which open checks and seal writes from their parameters; pub(crate) */ }
pub(crate) const MAX_NAME: usize = 64;          // every stored name; specs 021, 022 and 027 use it
pub struct WriteBatch { /* the new ChannelState, the records to append */ }

pub trait Store: Send {
    fn name(&self) -> &DirName;
    fn load(&mut self) -> Result<Option<(ChannelState, Vec<LogRecord>)>, StoreError>;  // R12–R14
    fn commit(&mut self, batch: &WriteBatch) -> Result<(), StoreError>;               // R10, R11, R16
    fn compact(&mut self, state: &ChannelState, now: u64) -> Result<u32, StoreError>; // R15
    fn log_len(&self) -> u64;                                                         // R16
    fn destroy(&mut self) -> Result<(), StoreError>;                                  // R21
}
pub trait Vault: Send {
    fn list(&mut self) -> Result<Vec<Box<dyn Store>>, StoreError>;                    // R20
    fn create(&mut self, channel_id: &[u8; 16]) -> Result<Box<dyn Store>, StoreError>;
    fn remove(&mut self, name: &DirName) -> Result<(), StoreError>;                   // R21
    fn dir_name(&self, channel_id: &[u8; 16]) -> Result<DirName, StoreError>;          // R18
    fn load_settings(&mut self) -> Result<Option<Settings>, StoreError>;              // R22
    fn save_settings(&mut self, settings: &Settings) -> Result<(), StoreError>;
}

impl ChannelState {
    pub fn open(key: &StorageKey, name: &DirName, sealed: &[u8]) -> Result<ChannelState, StoreError>;   // nonce ‖ box
    pub fn seal(&self, key: &StorageKey, name: &DirName, log_len: u64, generation: u32) -> Result<Vec<u8>, StoreError>;
    pub fn log_position(&self) -> (u64, u32);
    pub fn channel_id(&self) -> [u8; 16];
}
impl LogRecord {
    pub fn open(key: &StorageKey, name: &DirName, entry: &[u8], generation: u32, offset: u64) -> Result<LogRecord, StoreError>;
    pub fn seal(&self, key: &StorageKey, name: &DirName, generation: u32, offset: u64) -> Result<Vec<u8>, StoreError>;
    pub fn purge_at(&self) -> u64;
}
impl ChannelState { pub(crate) fn duplicate(&self) -> Result<ChannelState, StoreError>; }   // the one deep copy, secrets through Secret::copy_from
impl WriteBatch {
    pub fn state(&self) -> &ChannelState;
    pub fn records(&self) -> &[LogRecord];
}
impl Settings {
    pub fn open(key: &StorageKey, sealed: &[u8]) -> Result<Settings, StoreError>;   // nonce ‖ box
    pub fn seal(&self, key: &StorageKey) -> Result<Vec<u8>, StoreError>;
}
pub fn dir_name(key: &StorageKey, channel_id: &[u8; 16]) -> Result<DirName, StoreError>;   // R18

// store
pub struct DataDir { /* path, Arc of the fs::LockFile and the StorageKey, the live names */ }
impl DataDir { pub fn open(path: &Path, key: StorageKey) -> Result<DataDir, StoreError>; }
impl Vault for DataDir { /* R19–R22 */ }
pub(crate) struct ChannelFiles { /* directory, Arc of the key and lock, poisoned flag */ }   // handed out as Box<dyn Store>
impl Store for ChannelFiles { /* R10–R16, R21 */ }
```

`WriteBatch` is built only inside `core` (spec 021-channel-session) and is committed by reference, so that `Channel` moves its parts into memory after `Ok` and can retry after `LogFull` (spec 023-ttl-purge); the store keeps no copy of the state. `ChannelState`, `LogRecord` and `WriteBatch` implement neither `Clone` nor `Debug`; `ChannelState::duplicate`, declared here, is the one deep copy, through `Secret::copy_from`.

The `testing` module compiles under `cfg(any(test, fuzzing, feature = "test-support"))`, where the test relaxations of AGENTS 4 do not apply, so it is written like production code; `store` enables `test-support` only in its dev-dependency, and `store` has `privatechat-core` as its only dependency. Its doubles are handles over shared state (`Arc<Mutex<_>>`, which R2's rust-skill amendment allows in this module only), so that a test keeps a handle after giving a store or a vault away:

- `MemoryStore` and `MemoryVault`, `Clone`, which seal and open through the same functions with a fixed key; `reopen()` gives a fresh store over the same bytes; `commits()` counts the commits that append a record or change the state beyond `cursor` and `synced_at` (the count of AGENTS 23), and `all_commits()` every successful commit, for the rate rules of spec 021-channel-session R20; `log_len()` counts bytes as R5 lays them out (9-byte header, then 4 + `len` per entry); `list` skips, and `load` returns `Ok(None)` for, a store with no state whose log is absent or short as R13 and R19 say, as they do; `put_raw(name, state_bytes, log_bytes)` and `put_settings_raw(bytes)` plant arbitrary bytes; `commit` applies R16 and returns `LogFull` for a log that would pass 67 108 864 bytes.
- `Faults`, a `Clone` handle shared by the test and the doubles, which counts calls from the moment a fault is armed, across every store sharing the handle: `fail_at(n)` fails the *n*-th `commit`, `compact` or `destroy` with `Io` before touching the store; `poison_after(n)` lets the *n*-th call through and then returns `Io` for it and for every later call of that one store instance, as a store poisoned after its rename (R11), while stores handed out afterwards are healthy; `fail_compactions(on)` fails every `compact` with `Io` before touching the store while on, leaving commits alone, and `fail_commits(on)` does the same for every `commit`, leaving loads and compactions alone; `fail_create(on)`, `fail_remove(on)`, `fail_list(on)`, `fail_load_settings(on)` and `fail_save_settings(on)` fail those `Vault` calls while on, `fail_create_at(n)` only the *n*-th `create`; `last_committed(&DirName)` returns a duplicate of the last state let through.
- `FailingStore`, which wraps a `Box<dyn Store>` with a `Faults` handle, and `FailingVault`, which wraps a `Box<dyn Vault>` and every store it hands out.
- The builders `state_for(channel_id)`, `record(purge_at, body_len)` and `batch(state, records)`, with which the `store` tests commit chosen content.
- `state_eq` and `records_eq`, which compare two states and two record lists field by field, with `ct_eq` for the secrets, `state_eq` ignoring the store's own `log_committed_len` and `log_generation`.

**Crash points and faults.** All of it exists under `cfg(test)` only, in `fs.rs`, and the tests that use it live in `crates/store/src/tests.rs` and its submodules, never under `crates/store/tests/`, so that `cfg(test)` applies.

- Faults: a `cfg(test)` field of each `ChannelFiles` and `DataDir`, set by a `cfg(test)` constructor, makes that instance's *k*-th system call return an I/O error; it is counted per instance, so tests running in parallel do not interfere.
- Fast mode: a second `cfg(test)` field makes `sync_all` a counted no-op; a process that exits keeps the page cache, so the crash tests lose nothing, and the 10 000-message test of spec 027-core-api uses it.
- Crash points: the environment variable `PRIVATECHAT_STORE_CRASH`, read as `<point>:<k>`, makes the process exit with status 86 (`std::process::exit`) the *k*-th time it passes `<point>`: `after_append` (R10 between steps 1 and 2), `after_state_tmp` (before the rename), `after_compact_state` (R15 before the log rename). A crash test runs `std::env::current_exe()` as a child with `--exact <helper test> --test-threads=1`, the crash variable and the data directory in the child's environment (set with `Command::env`, never `set_var`), waits for status 86, and checks the files it then reopens; the helper test returns at once when the variable is absent, so the normal run does not repeat its work. Every store test works in `std::env::temp_dir()/privatechat-<pid>-<test name>`, removed at its end.

`mod storage` carries `#[allow(dead_code, reason = "reached through Device, spec 027-core-api")]` until spec 027 removes it.

**PR slices** (AGENTS 14): (a) the codec types of R1 and the amendments of R2; (b1) the peer, `outbox` and old-key sub-records; (b2) the state record codec, `duplicate` and `StoreError` (R8 for it, R26, its part of R30); (b3) `StorageKey`, `DirName`, the derived keys and the sealing of the state (R3, R24, R27, core's halves of R4 and R7); (c) the log and settings records (core's half of R5, R9, R4 and R8 for settings); (d1) the traits and `WriteBatch` (R25, R28); (d2a) `testing/compare.rs` and `testing/builders.rs`; (d2b) `testing/memory.rs`; (d2c) `testing/faults.rs` with `FailingStore` and `FailingVault`; (d3) the fuzz targets and round-trip properties (R29); (e1) `fs.rs` with the faults, fast mode and crash points, the lock and the IO script (R17, R23); (e2) `DataDir`, the layout, the file framing and the `Vault` impl (R6, R18–R22, store's halves of R4, R5 and R7); (f) commit, load and recovery (R10–R13, R16, T11's commit half, T19's load half); (g) compaction and its recovery (R14, R15, and T11's compaction half). Each test clause lands in the slice that implements the last behaviour it needs; the list above names where each requirement is implemented, and a test that spans slices is completed clause by clause.

## Security

- `K_db` protects everything on disk; its loss erases all local data by design (`docs/spec.md` §8). `StorageKey` is the only type that holds it, it enters once and zeroes its input (R24), and no function returns it. Every file is sealed under a key derived for its purpose (R3), so no box of one channel, or of the settings, opens as another.
- Nothing in a file is trusted before its box opens: the size checks of R6 and R7 come before any allocation, and `Corrupt` carries no detail. A corrupt channel is reported by `Device` (spec 027-core-api), which lets the user remove it and import it again from a fresh invitation (ADR 0021, `docs/spec.md` §1).
- `generation`, `offset` and the per-directory key bind every entry to one place in one file of one channel (R9, ADR 0035). Someone who can write the disk but has no `K_db` can still roll both files back to an earlier commit, or delete `settings.bin`: a rollback resets counters and cursor, and a deleted settings file resets the proxy. Spec 027-core-api reports a missing settings file when channels exist, so the user notices; the rollback is documented, inside the desktop model's "any process of the user can read the files" (`docs/spec.md` §1) and excluded by the mobile sandbox.
- The channel directory name is a keyed hash (R18): a forensic copy without `K_db` sees how many channels exist and their sizes, not which `channel_id`s.
- `state.bin` is not padded: its size tells a forensic copy roughly how many peers and pending messages a channel has.
- Deleting a message is physical, by compaction (R15), and does not resist older copies of the flash (`docs/spec.md` §2).
- A failed `fsync` is not retried (R11): on Linux a retry can report success for data already lost, so the store stops and the next open decides.
- `store` logs nothing; `StoreError` carries no path.

## Public API changes

- `core::Error` gains `Store(StoreError)`, as `docs/spec.md` §9 announces.
- The `Store` trait of §9 changes: `load` returns an `Option`, `commit` takes the batch by reference, `compact` takes the state, and `name`, `log_len` and `destroy` are new; `Vault` is new, and `Settings::load(store)` of §9 becomes `Vault::load_settings`. None of these crosses to the clients: spec 027-core-api exposes only `Device`.

## Test cases

- T01 (covers R1): `s020_t01_r01_new_codec_types`: `bool` 0x00 and 0x01 round-trip, 0x02 and a 2-byte value → `Width`; a nested record decodes with its own schema and a trailing byte inside it → `Truncated`; a list at its maximum count round-trips, one more → `TooLong`, an item cut short → `Truncated`; the `Writer` produces each of them.
- T02 (covers R2): `s020_t02_r02_amended_wrapper`: `secretbox_open` returns `Zeroizing<Vec<u8>>` (a type assertion); `s010_t25` accepts the `test-support` feature and still refuses a third dependency declared by this spec.
- T03 (covers R3): `s020_t03_r03_derived_keys`: the state of directory A does not open under the name of directory B, nor as settings.
- T04 (covers R4): `s020_t04_r04_file_layouts`: in `core`, two seals of the same state differ in their 24-byte nonce and open to the same record; in `store`, the files begin with `PSTA` or `PSET` and version 1.
- T05 (covers R5): `s020_t05_r05_log_layout`: three entries after the 9-byte header, each `len` equal to nonce plus box.
- T06 (covers R6): `s020_t06_r06_size_before_read`: a `state.bin` one byte over the limit → `Corrupt`, and the read buffer never exceeds limit + 1.
- T07 (covers R7): `s020_t07_r07_open_check_order`: in `store`, 44 bytes, a wrong magic, a `state.bin` of version 2 whose box does not open as version 1, and a file over the limit → `Corrupt`, `Corrupt`, `UnsupportedVersion`, `Corrupt`, with the version checked before the size, an 8-byte log next to a `state.bin` → `Corrupt`, a version-1 `state.bin` or `settings.bin` with its header byte changed to 2 → `Corrupt`, and a version-1 log with its header byte changed to 2 next to a version-1 `state.bin` → `Corrupt`; in `core`, 39 bytes, a flipped box byte and a box holding a broken record → `Corrupt`.
- T08 (covers R8): `s020_t08_r08_state_and_settings_schemas`: an unknown key in either → `Corrupt`; a `default_server_url` with a path, a proxy with port 0 and a `lock_timeout_seconds` of 86 401 → `Corrupt`; `Settings::seal` of a `lock_timeout_seconds` of 86 401 → `Corrupt`; a state record with `state_version` 2 and an unknown key, and settings with `settings_version` 2 → `UnsupportedVersion`.
- T09 (covers R9): `s020_t09_r09_entry_bound_to_place`: an entry opened at another offset or generation → `Corrupt`; swapping two entries or repeating one → `load` returns `Corrupt`; an entry of another directory does not open.
- T10 (covers R10): `s020_t10_r10_commit_order`: `after_append:1` → reopening gives the previous state and a log truncated to its length; `after_state_tmp:1` → the previous state; a successful commit gives the new state and log; stale bytes after the committed end are overwritten, not appended after.
- T11 (covers R11): `s020_t11_r11_failure_and_poison`: with the fault at every *k* of one commit and one compaction: before the state rename, the call fails, the store stays usable and reopening gives the previous commit; at or after it, every later call → `Io`, and reopening gives the previous or the new commit, never a mix; a fault while writing `messages.log.new` → the file is gone after the call returns; a fault after `state.bin.tmp` is written and before its rename, in a commit and in a compaction → neither `state.bin.tmp` nor `messages.log.new` remains.
- T12 (covers R12): `s020_t12_r12_load_checks`: extra bytes after `log_committed_len` are cut; a shorter log → `Corrupt`; a flipped byte inside the committed length → `Corrupt`; a leftover `state.bin.tmp` is deleted.
- T13 (covers R13): `s020_t13_r13_first_commit`: a new directory → `None`; no `state.bin` and a 0-byte or 5-byte log, a 9-byte log of generation 0, or 9 bytes with a wrong magic → `None`, in the real store and in `MemoryStore`; after the first commit, a 9-byte log of generation 0.
- T14 (covers R14): `s020_t14_r14_interrupted_compaction`: `after_compact_state:1` → reopening completes the rename; a `.new` left by a crash before the state write is deleted; generations two apart → `Corrupt`; a stray `messages.log.new` whose deletion fails → `load` still succeeds.
- T15 (covers R15): `s020_t15_r15_compaction`: records below and above `now` → the dropped count, the survivors in order at new offsets, generation + 1; nothing to drop → byte-identical files.
- T16 (covers R16): `s020_t16_r16_log_full`: an append past 67 108 864 bytes → `LogFull`, files byte-identical; `log_len` equals the committed length after each commit.
- T17 (covers R17): `s020_t17_r17_single_process_lock`: a second `DataDir::open`, from another process too → `Locked`; after every handle is dropped it succeeds.
- T18 (covers R18): `s020_t18_r18_directory_name_is_keyed`: 32 hex characters, different under two keys, not containing the `channel_id` hex.
- T19 (covers R19): `s020_t19_r19_open_cleans_leftovers`: a directory without `state.bin` and with a generation-0 header-only or 5-byte log, and a `.leaving` directory, are gone after `DataDir::open`; a header-only log of generation 1 without `state.bin` → listed, loads as `Corrupt`; a directory without `state.bin` whose log holds entries is listed and loads as `Corrupt`; a `.leaving` directory whose deletion fails → `DataDir::open` succeeds and `list` skips it.
- T20 (covers R20): `s020_t20_r20_one_store_per_directory`: `list` after three channels gives three stores; `create` of an id already listed and alive → `Locked`; after dropping it, `create` succeeds; a stray file and a directory named `backup` under `channels/` are ignored.
- T21 (covers R21): `s020_t21_r21_destroy_and_remove`: after `destroy` the directory is gone; a fault before the rename → the error and a usable store; a fault after it → `Ok`, and R19 removes the `.leaving` directory; `remove` of a corrupt directory deletes it; `dir_name` equals R18; a second `destroy` of a re-created channel whose earlier `.leaving` was left behind succeeds.
- T22 (covers R22): `s020_t22_r22_settings_file`: absent → `None`; saved and loaded → equal.
- T23 (covers R23): `s020_t23_r23_io_in_one_module`: `scripts/check_store_io.sh` fails on a fixture that calls `std::fs::rename` outside `fs.rs` and passes on the crate.
- T24 (covers R24): `s020_t24_r24_storage_key_zeroes_input`: the input array is zeros after `from_bytes`; the redacted-`Debug` test of spec 010 covers `StorageKey`.
- T25 (covers R25): `s020_t25_r25_plaintext_buffers`: for a small and a maximal state, the writer's buffer capacity equals the encoded length and does not grow.
- T26 (covers R26): `s020_t26_r26_store_error_has_no_data`: each variant's `Debug` is its name; an `Io` from a missing file carries no path.
- T27 (covers R27): `s020_t27_r27_seal_refuses_what_open_refuses`: 33 entries → `OutboxFull`; 551 peers, 17 old keys, a 65-byte label → `Corrupt`; the largest state seals, is at most 2 359 296 bytes and opens.
- T28 (covers R28): `s020_t28_r28_send`: a compile-time assertion that `DataDir`, `ChannelFiles` and `Box<dyn Store>` are `Send`.
- T29 (covers R29): `s020_t29_r29_records_round_trip`: property tests over valid states, log records of each kind and settings: `open(seal(x))` gives `x` under `state_eq`; the three decoders never panic on arbitrary bytes.
- T30 (covers R30): `check_s020_t30_r30_section_produces_020_json`, run by the CI step of spec 015-test-vectors; `cargo test` reproduces every vector.

## Vectors

`specs/vectors/020.json`, every vector `derived` by the reference script from R1 and the schemas above. The codec vectors use a test schema declared next to spec 017's: 0 `u8` mandatory, 1 `bool`, 2 a nested record of the 017 test schema, 3 `list<u64>` of at most 4 items.

| name | kind | source | origin |
| --- | --- | --- | --- |
| `bool_true`, `bool_false` | positive | derived | one `bool` field |
| `bool_two` | negative | derived | value 0x02 → `Width` |
| `nested_record` | positive | derived | one nested record |
| `list_two_items`, `list_empty` | positive | derived | a `list<u64>` of two items and of none |
| `list_item_truncated` | negative | derived | an item `len` beyond the value → `Truncated` |
| `list_too_many` | negative | derived | one item over the maximum → `TooLong` |
| `state_reference`, `log_message_reference`, `log_kept_signature_reference`, `log_seen_reference`, `settings_reference` | positive | derived | one plaintext record of each schema with fixed values |
| `state_unknown_key`, `log_unknown_key`, `settings_bad_url` | negative | derived | a state record with key 19; a message log record with key 16; settings with a URL path → `Corrupt` |

## Acceptance criterion

`cargo test -p privatechat-core s020_` and `cargo test -p privatechat-store s020_` green, crash and fault tests included; `scripts/check_store_io.sh`, clippy, `cargo deny` and the documentation lint green; the reference script produces `020.json` as committed. Non-automatable: a second person reads R10–R15 and convinces themselves that every interruption leaves either the previous commit or the new one.

## Out of scope

- What each state field means and when it changes (specs 021–027); which records a purge drops (spec 023-ttl-purge).
- `DEFAULT_SERVER_URL` (spec 000-repo-layout) and the settings API (spec 027-core-api); what `lock_timeout_seconds` does on each platform (spec 053-device-security).
- Wrapping and unwrapping `K_db` (specs 040-uniffi, 041-desktop-bridge, 053-device-security); backup exclusion flags (spec 053-device-security).
- Per-channel keys for cryptographic deletion (`docs/spec.md` §12, v2).

## Open questions

None.

Decided with the human reviewer on 2026-09-25 (recommendations accepted, `docs/audit-log.md`, Audit J decisions): 020-R10: every commit rewrites `state.bin`, about 132 KiB with a full peer list and an empty `outbox`, up to 2.25 MiB with 32 large blobs waiting; spec 021-channel-session writes a cursor-only commit at most once a minute.; the recommendation taken: accept.

Decided on 2026-09-25: 020-R5, R9 and R18 (log header, generation and offset, keyed directory name) refine ADR 0021 in ADR 0035.

## History

- 2026-09-25 draft
- 2026-09-25 revised after audit J round 1 (`docs/audit-log.md`): per-directory and settings keys, commit by reference, `compact` takes the state, poisoning after a late failure, `Vault` with one live store per directory, `Send`, sizes checked before reading, crash points with a count and a fault injector inside `src/`, the 010 and 016 amendments, the IO-module script, more PR slices
- 2026-09-25 revised after audit J round 2 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 3 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 4 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 5 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 6 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 7 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 8 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 9 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 10 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 12 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 15 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 16 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 17 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 18 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 19 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 26 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 28 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 29 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 30 (`docs/audit-log.md`)
- 2026-09-25 open questions decided with the human reviewer, recommendations accepted (`docs/audit-log.md`)
