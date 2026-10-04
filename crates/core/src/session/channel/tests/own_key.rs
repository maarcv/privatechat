//! Tests of messages from one's own key: R13, R14, and the own-key clauses
//! of R9, R10 and R26.

use super::{receiver, reopened, seal, sid, text_from};
use crate::Error;
use crate::proto::envelope;
use crate::session::channel::{AckOutcome, Channel, ClientRef, Sender};
use crate::storage::LogEntry;
use crate::testing::MemoryStore;

/// A whole minute.
const NOW: u64 = 1_790_000_040_000;
const HOUR_MS: u64 = 3_600_000;
const MARGIN_MS: u64 = 360_000;

/// A text sealed with this channel's own key elsewhere.
fn own_text(channel: &Channel, counter: u64, sent_at: u64) -> Vec<u8> {
    text_from(
        channel,
        *channel.state.identity_seed.expose(),
        counter,
        sent_at,
    )
}

/// A one-hour channel whose next counter is `first`, with `count`
/// entries sealed at `NOW`.
fn with_entries(first: u64, count: u64) -> (Channel, MemoryStore, Vec<ClientRef>) {
    let (mut channel, handle, _) = receiver(3_600);
    let mut next = channel.next_state();
    next.send_counter = first;
    channel.commit(next, Vec::new()).unwrap();
    let entries = (0..count)
        .map(|_| channel.encrypt("mine", None, NOW).unwrap())
        .collect();
    (channel, handle, entries)
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

/// Spec 021, R13: an echo is `Replay` with no commit, before and after its
/// `ack`, after a lost `ack`, after it failed and after a foreign message
/// removed it; a blob of one's own key at the same counter with another
/// signature is no echo.
#[test]
fn s021_t13_r13_echo_by_signature() {
    let (mut channel, handle, entries) = with_entries(0, 1);
    let blob = channel.state.outbox[0].blob.clone();
    let commits = handle.commits();
    assert_eq!(channel.decrypt(&blob, sid(1), NOW, NOW), Err(Error::Replay));
    // The `ack` was lost: the echo acknowledges nothing.
    assert!(channel.take_outcomes().is_empty());
    let step = channel.outbox(NOW, &[], false).unwrap();
    assert_eq!(step.publish, [(entries[0], blob.clone())]);
    let outcome = channel.acked(entries[0], sid(2), NOW, NOW).unwrap();
    assert_eq!(outcome.outcome, AckOutcome::Delivered);
    assert_eq!(channel.decrypt(&blob, sid(3), NOW, NOW), Err(Error::Replay));
    assert_eq!(handle.commits(), commits + 1);

    let (mut channel, handle, entries) = with_entries(0, 1);
    let blob = channel.state.outbox[0].blob.clone();
    channel.abandon(entries[0]).unwrap();
    let commits = handle.commits();
    assert_eq!(channel.decrypt(&blob, sid(1), NOW, NOW), Err(Error::Replay));
    assert_eq!(handle.commits(), commits);
    assert!(
        !channel
            .records
            .iter()
            .any(|r| matches!(r.entry, LogEntry::Acked { .. }))
    );

    let (mut channel, _, _) = with_entries(0, 1);
    let blob = channel.state.outbox[0].blob.clone();
    // Same counter, another signature: someone else holds the key.
    let foreign = own_text(&channel, 0, NOW);
    assert!(
        channel
            .decrypt(&foreign, sid(1), NOW, NOW)
            .unwrap()
            .is_some()
    );
    assert!(channel.state.outbox.is_empty());
    assert_eq!(channel.decrypt(&blob, sid(2), NOW, NOW), Err(Error::Replay));
}

/// Spec 021, R14: the verdicts by `sent_at`, the counter bump and the
/// removal of the entries a foreign message overtook.
#[test]
fn s021_t14_r14_own_key_verdicts() {
    // Older than one TTL and the margin: no event, no commit.
    let (mut channel, handle, _) = with_entries(10, 3);
    let commits = handle.commits();
    let old = own_text(&channel, 11, NOW - HOUR_MS - MARGIN_MS - 60_000);
    assert_eq!(channel.decrypt(&old, sid(1), NOW, NOW), Err(Error::Expired));
    assert!(!channel.status().own_key_used_elsewhere);
    assert_eq!(handle.commits(), commits);

    // (sent_at, counter) → event, `send_counter` after, counters kept.
    let cases: [(u64, u64, u64, &[u64]); 5] = [
        // Dated `ttl_ms + 420 000` ahead: stale, still within reach.
        (NOW + HOUR_MS + 420_000, 11, 13, &[12]),
        (NOW, 20, 21, &[]),
        (NOW, u64::MAX, u64::MAX, &[]),
        (NOW + 2 * HOUR_MS + 780_000, 11, 13, &[10, 11, 12]),
        (NOW + 2 * HOUR_MS + 660_000, 11, 13, &[12]),
    ];
    for (sent_at, counter, send_counter, kept) in cases {
        let (mut channel, handle, _) = with_entries(10, 3);
        let blob = own_text(&channel, counter, sent_at);
        let _ = channel.decrypt(&blob, sid(1), NOW, NOW);
        let label = format!("{sent_at} {counter}");
        assert!(channel.status().own_key_used_elsewhere, "{label}");
        assert_eq!(channel.send_counter(), send_counter, "{label}");
        assert_eq!(counters(&channel), kept, "{label}");
        assert!(reopened(&handle).status().own_key_used_elsewhere);
    }

    // No readable `sent_at`: the event, and the overtaken entries removed.
    let (mut channel, _, entries) = with_entries(10, 3);
    let seed = *channel.state.identity_seed.expose();
    let garbage = seal(&channel, seed, |ctx, sender, nonce| {
        envelope::seal_padded(ctx, sender, 11, nonce, &[0; 1_024])
    });
    let received = channel
        .decrypt(&garbage, sid(1), NOW, NOW)
        .unwrap()
        .unwrap();
    assert!(matches!(received.sender, Sender::OwnKeyElsewhere { .. }));
    assert_eq!(counters(&channel), [12]);
    let outcomes = channel.take_outcomes();
    let removed: Vec<ClientRef> = outcomes.iter().map(|o| o.client_ref).collect();
    assert_eq!(removed, entries[..2]);
    assert!(
        outcomes
            .iter()
            .all(|o| o.outcome == AckOutcome::NotDelivered)
    );

    // A fresh foreign message: listed, its sender one's own key elsewhere,
    // and the entries `under_retired_key` never removed.
    let (mut channel, _, _) = with_entries(10, 3);
    let mut next = channel.next_state();
    next.outbox[0].under_retired_key = true;
    channel.commit(next, Vec::new()).unwrap();
    let blob = own_text(&channel, 11, NOW);
    let received = channel.decrypt(&blob, sid(1), NOW, NOW).unwrap().unwrap();
    let own_pk = envelope::SenderKey::from_seed(&channel.state.identity_seed).unwrap();
    assert!(
        received.sender
            == Sender::OwnKeyElsewhere {
                pk: own_pk.public().0
            }
    );
    assert_eq!(counters(&channel), [10, 12]);
    assert!(channel.state.peers.is_empty());
}

/// Spec 021, R9, R10 and R26 for one's own key: a republished foreign blob
/// is `Replay` with no second record, also after a purge within reach, and
/// a message a peer's would be `Expired` for raises the event instead.
#[test]
fn s021_t09_r09_own_key_clauses() {
    let (mut channel, handle, _) = receiver(3_600);
    let foreign = own_text(&channel, 5, NOW);
    channel.decrypt(&foreign, sid(1), NOW, NOW).unwrap();
    let records = channel.records.len();
    assert_eq!(
        channel.decrypt(&foreign, sid(2), NOW, NOW),
        Err(Error::Replay)
    );
    assert_eq!(channel.records.len(), records);

    // The message record goes at `now + ttl_ms`, its seen record lasts
    // the margin longer.
    channel
        .store
        .compact(&channel.state, NOW + HOUR_MS + 1)
        .unwrap();
    let mut channel = reopened(&handle);
    assert_eq!(channel.records.len(), 1);
    let later = NOW + HOUR_MS + 300_000;
    assert_eq!(
        channel.decrypt(&foreign, sid(3), later, later),
        Err(Error::Replay)
    );
    assert_eq!(channel.records.len(), 1);

    let (mut channel, _, _) = receiver(3_600);
    let late = own_text(&channel, 1, NOW - HOUR_MS - 60_000);
    assert!(channel.decrypt(&late, sid(1), NOW, NOW).unwrap().is_some());
    assert!(channel.status().own_key_used_elsewhere);
}
