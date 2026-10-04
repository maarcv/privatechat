//! Tests of the own-key check under a full log (R19) and of the reserve of
//! R18 it relies on.

use super::{fill, receiver, retiring, seal, text_from};
use crate::Error;
use crate::proto::envelope;
use crate::proto::payload::{Payload, PayloadKind};
use crate::session::channel::{Channel, ClientRef};
use crate::storage::{LogEntry, StoreError};
use crate::testing::{Faults, MemoryStore};

/// A whole minute.
const NOW: u64 = 1_790_000_040_000;
const HOUR_MS: u64 = 3_600_000;
const MARGIN_MS: u64 = 360_000;
const LIVE: u64 = NOW + 36_000_000;
const FULL: u64 = 67_108_864;
const HEADROOM: u64 = 1_114_156;

/// A text sealed with this channel's own key elsewhere.
fn own_text(channel: &Channel, counter: u64, sent_at: u64) -> Vec<u8> {
    text_from(
        channel,
        *channel.state.identity_seed.expose(),
        counter,
        sent_at,
    )
}

/// A `key_retired` sealed with this channel's own key elsewhere.
fn own_key_retired(channel: &Channel, sent_at: u64) -> Vec<u8> {
    let payload = Payload {
        kind: PayloadKind::KeyRetired,
        display_name: None,
        sent_at,
        body: Vec::new(),
    };
    let seed = *channel.state.identity_seed.expose();
    seal(channel, seed, |ctx, sender, nonce| {
        envelope::seal(ctx, sender, u64::MAX, nonce, &payload)
    })
}

/// A one-hour channel with entries 10 and 11 and a log one byte past the
/// headroom, all live.
fn stalled() -> (Channel, MemoryStore, Faults, Vec<ClientRef>) {
    let (mut channel, handle, faults) = receiver(3_600);
    let mut next = channel.next_state();
    next.send_counter = 10;
    channel.commit(next, Vec::new()).unwrap();
    let entries = (0..2)
        .map(|_| channel.encrypt("mine", None, NOW).unwrap())
        .collect();
    fill(&mut channel, LIVE, FULL - HEADROOM + 1);
    (channel, handle, faults, entries)
}

/// The counters still in the `outbox`.
fn counters(channel: &Channel) -> Vec<u64> {
    channel
        .state
        .outbox
        .iter()
        .map(|entry| entry.counter)
        .collect()
}

/// Spec 021, R19: under a full log, a foreign blob of one's own key raises
/// the alert in one commit with no message record and no cursor, bumps the
/// counter and removes the overtaken entries with their records.
#[test]
fn s021_t19_r19_own_key_under_full_log() {
    let (mut channel, handle, _, entries) = stalled();
    let records = channel.records.len();
    let commits = handle.commits();
    let foreign = own_text(&channel, 12, NOW);
    let result = channel.decrypt(&foreign, [1; 16], NOW, NOW);
    assert_eq!(result, Err(Error::Store(StoreError::LogFull)));
    assert!(channel.status().own_key_used_elsewhere);
    assert_eq!(channel.send_counter(), 13);
    assert!(channel.state.outbox.is_empty());
    assert_eq!(handle.commits(), commits + 1);
    assert_eq!(channel.cursor(), None);
    let new = &channel.records[records..];
    assert_eq!(new.len(), 4);
    assert!(!new.iter().any(|r| matches!(r.entry, LogEntry::Message(_))));
    let removed: Vec<ClientRef> = channel
        .take_outcomes()
        .iter()
        .map(|o| o.client_ref)
        .collect();
    assert_eq!(removed, entries);
    // A second foreign blob: `true`, the counter past it, the flag as it was.
    let second = own_text(&channel, 20, NOW);
    assert_eq!(channel.check_own_key(&second, NOW, NOW), Ok(true));
    assert_eq!(channel.send_counter(), 21);

    // Planted exactly full: the removal cannot be written.
    let (mut channel, handle, _, _) = stalled();
    fill(&mut channel, LIVE, FULL);
    let commits = handle.commits();
    let foreign = own_text(&channel, 12, NOW);
    assert_eq!(
        channel.check_own_key(&foreign, NOW, NOW),
        Err(Error::Internal)
    );
    assert_eq!(handle.commits(), commits);
}

/// Spec 021, R18 and R19: the reserve holds the worst case a stall can
/// add — 31 ordinary entries and a pending `key_retired`, each acked or
/// removed with its records — and the own-key commit after it.
#[test]
fn s021_t19_r19_reserve_bound() {
    let (mut channel, _, _) = receiver(3_600);
    let entries: Vec<ClientRef> = (0..31)
        .map(|_| channel.encrypt("mine", None, NOW).unwrap())
        .collect();
    super::plant_retirement(&mut channel);
    fill(&mut channel, LIVE, FULL - HEADROOM + 1);
    for (n, entry) in entries.iter().enumerate().rev() {
        let server_id = [u8::try_from(n).unwrap(); 16];
        channel.acked(*entry, server_id, NOW, NOW).unwrap();
    }
    let foreign = text_from(&channel, [0x99; 32], 40, NOW);
    assert_eq!(channel.check_own_key(&foreign, NOW, NOW), Ok(true));
    assert!(channel.store.log_len() <= FULL);
}

/// Spec 021, R19: the verdicts by date and kind under a full log.
#[test]
fn s021_t19_r19_verdicts() {
    // Dated `ttl_ms + 420 000` ahead: the event and the removal, no bump.
    let (mut channel, _, _, _) = stalled();
    let ahead = own_text(&channel, 12, NOW + HOUR_MS + 420_000);
    assert_eq!(channel.check_own_key(&ahead, NOW, NOW), Ok(true));
    assert_eq!((channel.send_counter(), counters(&channel)), (12, vec![]));

    // A fresh `key_retired`: every entry, and `read_only`.
    let (mut channel, _, _, _) = stalled();
    let retired = own_key_retired(&channel, NOW);
    assert_eq!(channel.check_own_key(&retired, NOW, NOW), Ok(true));
    assert!(counters(&channel).is_empty() && channel.status().read_only);

    // A stale one within reach: every entry, but no `read_only`.
    let (mut channel, _, _, _) = stalled();
    let retired = own_key_retired(&channel, NOW + HOUR_MS + 420_000);
    assert_eq!(channel.check_own_key(&retired, NOW, NOW), Ok(true));
    assert!(counters(&channel).is_empty() && !channel.status().read_only);
    assert!(channel.status().own_key_used_elsewhere);

    // A genuine blob of this device replayed after its kept signature was
    // purged: no member accepts it any more, so no alert.
    let (mut channel, handle, _) = receiver(3_600);
    let sent = channel.encrypt("old", None, NOW).unwrap();
    let blob = channel.state.outbox[0].blob.clone();
    channel.acked(sent, [1; 16], NOW, NOW).unwrap();
    let later = NOW + 2 * (HOUR_MS + MARGIN_MS) + 60_000;
    channel.store.compact(&channel.state, later).unwrap();
    let mut channel = super::reopened(&handle);
    let commits = handle.commits();
    assert_eq!(channel.check_own_key(&blob, later, later), Ok(false));
    assert!(!channel.status().own_key_used_elsewhere);
    assert_eq!(handle.commits(), commits);
}

/// Spec 021, R19: the thief of the key being retired under a full log, and
/// a failed commit that keeps nothing in memory.
#[test]
fn s021_t19_r19_retiring_and_failures() {
    for sent_at in [NOW, NOW + HOUR_MS + 420_000] {
        let (mut channel, _, _, old_seed, _) = retiring();
        fill(&mut channel, LIVE, FULL - HEADROOM + 1);
        let thief = text_from(&channel, old_seed, 1_000, sent_at);
        assert_eq!(channel.check_own_key(&thief, NOW, NOW), Ok(false));
        assert_eq!(counters(&channel), [u64::MAX], "{sent_at}");
    }
    let (mut channel, _, faults, old_seed, _) = retiring();
    let thief = text_from(&channel, old_seed, 1_000, NOW);
    faults.fail_commits(true);
    let result = channel.check_own_key(&thief, NOW, NOW);
    assert_eq!(result, Err(Error::Store(StoreError::Io)));
    assert_eq!(counters(&channel), [300, 301, u64::MAX]);

    let (mut channel, _, faults, _) = stalled();
    let foreign = own_text(&channel, 12, NOW);
    faults.fail_commits(true);
    let result = channel.check_own_key(&foreign, NOW, NOW);
    assert_eq!(result, Err(Error::Store(StoreError::Io)));
    assert!(!channel.status().own_key_used_elsewhere);
    assert_eq!(counters(&channel), [10, 11]);
    faults.fail_commits(false);
    assert_eq!(channel.check_own_key(&foreign, NOW, NOW), Ok(true));
    assert!(channel.status().own_key_used_elsewhere);
    assert!(counters(&channel).is_empty());
}
