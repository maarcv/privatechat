//! Tests of the log headroom for `encrypt` (R18) and of the expiry index
//! after a compaction (R1), over logs filled to the byte.

use super::{SERVER, config_on, fill, new_channel, new_store};
use crate::Error;
use crate::session::channel::Channel;
use crate::storage::{ENTRY_LEN_LEN, MAX_LOG_ENTRY, StoreError};
use crate::testing::{FailingStore, Faults, MemoryStore, record};

const NOW: u64 = 1_790_000_000_000;
const EXPIRED: u64 = NOW - 1;
const LIVE: u64 = NOW + 36_000_000;
const FULL: u64 = 67_108_864;
const HEADROOM: u64 = 1_114_156;
const MIB: u64 = 1_048_576;

/// A channel whose log has `expired` bytes that expired before `NOW` and
/// is `len` bytes long, the rest live; with a handle and its faults.
fn filled(expired: u64, len: u64) -> (Channel, MemoryStore, Faults) {
    let (store, handle) = new_store();
    let faults = Faults::new();
    let failing = Box::new(FailingStore::new(store, faults.clone()));
    let (mut channel, _) = Channel::create(&config_on(SERVER), failing).unwrap();
    let start = channel.store.log_len();
    fill(&mut channel, EXPIRED, start + expired);
    fill(&mut channel, LIVE, len);
    (channel, handle, faults)
}

/// Spec 021, R18: the headroom is a maximal entry with its `len` and a
/// reserve of one mebibyte.
#[test]
fn s021_t18_r18_headroom_constants() {
    let max_entry = u64::try_from(MAX_LOG_ENTRY + ENTRY_LEN_LEN).unwrap();
    assert_eq!(max_entry, 65_580);
    assert_eq!(HEADROOM, max_entry + MIB);
    let (mut channel, _) = new_channel();
    fill(&mut channel, LIVE, FULL - HEADROOM);
    assert!(channel.encrypt("fits", None, NOW).is_ok());
}

/// Spec 021, R18: a live log within the headroom refuses `encrypt` and
/// `decrypt` with no compaction, no commit and the cursor unchanged; so
/// does one with only 100 expired bytes.
#[test]
fn s021_t18_r18_headroom_live_log() {
    for expired in [0, record(0, 0).entry_len()] {
        let (mut channel, handle, _) = filled(expired, FULL - HEADROOM + 1);
        let commits = handle.commits();
        let result = channel.encrypt("hi", None, NOW);
        assert_eq!(result, Err(Error::Store(StoreError::LogFull)));
        // `decrypt` refuses before reading a byte of the blob.
        let result = channel.decrypt(&[], [1; 16], NOW, NOW);
        assert_eq!(result, Err(Error::Store(StoreError::LogFull)));
        assert_eq!(channel.cursor(), None);
        assert_eq!(handle.commits(), commits);
        assert_eq!(channel.store.log_len(), FULL - HEADROOM + 1);
        assert_eq!(channel.relieve_headroom(NOW), Ok(false));
    }
}

/// Spec 021, R18 and R1: one mebibyte expired restores the room of a log
/// one byte past the headroom; the compaction goes through
/// `Store::compact`, the call succeeds and the index is rebuilt.
#[test]
fn s021_t18_r18_compaction_restores_room() {
    let (mut channel, _, _) = filled(MIB, FULL - HEADROOM + 1);
    let live = channel
        .records
        .iter()
        .filter(|r| r.purge_at == LIVE)
        .count();
    assert_eq!(channel.expiry.expired_bytes(NOW), MIB);
    channel.encrypt("hi", None, NOW).unwrap();
    assert!(channel.store.log_len() < FULL - HEADROOM);
    assert_eq!(channel.records.len(), live + 1);
    assert_eq!(channel.expiry.expired_bytes(NOW), 0);
    // One's own message now expires first.
    let own = channel.records.last().unwrap().purge_at;
    assert!(own < LIVE);
    assert_eq!(channel.expiry.oldest_expiry(), Some(own));
}

/// Spec 021, R18: a log at its limit with exactly one mebibyte expired is
/// not compacted, since that would not restore the room.
#[test]
fn s021_t18_r18_exact_mebibyte_at_full_log() {
    let (mut channel, _, _) = filled(MIB, FULL);
    let result = channel.encrypt("hi", None, NOW);
    assert_eq!(result, Err(Error::Store(StoreError::LogFull)));
    assert_eq!(channel.relieve_headroom(NOW), Ok(false));
    assert_eq!(channel.store.log_len(), FULL);
}

/// Spec 021, R18 and R32: a failed compaction is returned with memory
/// unchanged, holds off the next attempt for ten minutes, and a reopened
/// channel compacts at once.
#[test]
fn s021_t18_r18_failed_compaction() {
    let (mut channel, handle, faults) = filled(MIB, FULL - HEADROOM + 1);
    let records = channel.records.len();
    faults.fail_compactions(true);
    let result = channel.encrypt("hi", None, NOW);
    assert_eq!(result, Err(Error::Store(StoreError::Io)));
    assert_eq!(channel.records.len(), records);
    assert_eq!(channel.expiry.expired_bytes(NOW), MIB);
    // Faults still on: an attempt would be `Io`.
    let result = channel.decrypt(&[], [1; 16], NOW + 599_999, NOW + 599_999);
    assert_eq!(result, Err(Error::Store(StoreError::LogFull)));
    assert_eq!(channel.relieve_headroom(NOW + 599_999), Ok(false));
    let result = channel.relieve_headroom(NOW + 600_000);
    assert_eq!(result, Err(Error::Store(StoreError::Io)));
    drop(channel);
    faults.fail_compactions(false);
    let mut reopened = Channel::open_stored(Box::new(handle.reopen())).unwrap();
    assert_eq!(reopened.relieve_headroom(NOW + 600_001), Ok(true));
}

/// Spec 021, R18: a clock set back resets the time of the last compaction
/// to `now`, from which the ten minutes run.
#[test]
fn s021_t18_r18_clock_set_back() {
    let (mut channel, _, _) = filled(MIB, FULL - HEADROOM + 1);
    assert_eq!(channel.relieve_headroom(NOW), Ok(true));
    let back = NOW - 1_000_000;
    let start = channel.store.log_len();
    fill(&mut channel, back - 1, start + MIB);
    fill(&mut channel, LIVE, FULL - HEADROOM + 1);
    assert_eq!(channel.relieve_headroom(back), Ok(false));
    assert_eq!(channel.relieve_headroom(back + 599_999), Ok(false));
    assert_eq!(channel.relieve_headroom(back + 600_000), Ok(true));
}
