//! Tests of the gaps and the truncation (R24), the peers-changed flag of
//! R1, and the retiring-key clause of R9.

use super::{receiver, reopened, retiring, sid, text_from};
use crate::Error;
use crate::crypto::Secret;
use crate::proto::envelope::SenderKey;
use crate::proto::payload::{Payload, PayloadKind};
use crate::session::channel::{AckOutcome, Channel, ClientRef, Gap};
use crate::storage::StoreError;

/// A whole minute.
const NOW: u64 = 1_790_000_040_000;
const HOUR_MS: u64 = 3_600_000;
const DAY_MS: u64 = 86_400_000;
const ANN: [u8; 32] = [0x41; 32];
const BOB: [u8; 32] = [0x42; 32];

/// `pk_u` of `seed`.
fn pk(seed: [u8; 32]) -> [u8; 32] {
    SenderKey::from_seed(&Secret::from_bytes(seed))
        .unwrap()
        .public()
        .0
}

/// Delivers a fresh text of `seed` at `counter`, sent and received at `at`.
fn deliver(channel: &mut Channel, seed: [u8; 32], counter: u64, at: u64) {
    let blob = text_from(channel, seed, counter, at);
    // A `server_id` of its own per sender and counter.
    let mut id = [seed[0]; 16];
    id[8..].copy_from_slice(&counter.to_be_bytes());
    channel.decrypt(&blob, id, at, at).unwrap();
}

/// Spec 021, R24 and R25: the skipped counters per sender, anomalous above
/// `2^32`, none for a `key_retired`, none across a truncation for a sender
/// away longer than a TTL, and `spans_truncation` a month later.
#[test]
fn s021_t24_r24_gaps() {
    let (mut channel, _, _) = receiver(3_600);
    for counter in [0, 1, 5] {
        deliver(&mut channel, ANN, counter, NOW);
    }
    let gap = |peer, missing, anomalous, spans_truncation| Gap {
        peer,
        missing,
        anomalous,
        spans_truncation,
    };
    assert_eq!(channel.gaps(), [gap(pk(ANN), 3, false, false)]);
    deliver(&mut channel, BOB, 0, NOW);
    deliver(&mut channel, BOB, (1 << 32) + 1, NOW);
    let bob = |channel: &Channel| channel.gaps().into_iter().find(|g| g.peer == pk(BOB));
    assert_eq!(bob(&channel), Some(gap(pk(BOB), 1 << 32, false, false)));
    deliver(&mut channel, BOB, (1 << 33) + 3, NOW);
    assert_eq!(
        bob(&channel),
        Some(gap(pk(BOB), (1 << 32) * 2 + 1, true, false))
    );
    // A `key_retired` counts for no gap.
    let retired = Payload {
        kind: PayloadKind::KeyRetired,
        display_name: None,
        sent_at: NOW,
        body: Vec::new(),
    };
    let blob = super::seal(&channel, ANN, |ctx, sender, nonce| {
        crate::proto::envelope::seal(ctx, sender, u64::MAX, nonce, &retired)
    });
    channel.decrypt(&blob, sid(200), NOW, NOW).unwrap();
    let ann = channel.gaps().into_iter().find(|g| g.peer == pk(ANN));
    assert_eq!(ann, Some(gap(pk(ANN), 3, false, false)));

    // Both last seen at `NOW`; the history truncated two hours later.
    let (mut channel, handle, _) = receiver(3_600);
    deliver(&mut channel, ANN, 0, NOW);
    deliver(&mut channel, BOB, 0, NOW);
    let truncated_at = NOW + 2 * HOUR_MS;
    channel.history_truncated(truncated_at);
    assert_eq!(
        channel.status().truncated_before,
        Some(truncated_at - HOUR_MS)
    );
    channel.flush(truncated_at).unwrap();
    let mut channel = reopened(&handle);
    deliver(&mut channel, ANN, 9, truncated_at + 1_800_000);
    assert!(channel.gaps().is_empty());
    deliver(&mut channel, BOB, 9, truncated_at + 30 * DAY_MS);
    assert_eq!(channel.gaps(), [gap(pk(BOB), 8, false, true)]);
    assert_eq!(channel.status().truncated_before, None);
}

/// Spec 021, R1: the peers-changed flag is set at load, by a new peer, by
/// one's own new name and by a new gap, cleared by `take_peers_changed`,
/// and left clear by an ordinary message of a known peer.
#[test]
fn s021_t01_r01_peers_changed() {
    let (mut channel, handle, _) = receiver(3_600);
    assert!(channel.take_peers_changed());
    assert!(!channel.take_peers_changed());
    deliver(&mut channel, ANN, 0, NOW);
    assert!(channel.take_peers_changed());
    deliver(&mut channel, ANN, 1, NOW);
    assert!(!channel.take_peers_changed());
    channel.encrypt("hi", None, NOW).unwrap();
    assert!(!channel.take_peers_changed());
    channel.encrypt("hi", Some("Me"), NOW).unwrap();
    assert!(channel.take_peers_changed());
    deliver(&mut channel, ANN, 5, NOW);
    assert!(channel.take_peers_changed());
    drop(channel);
    assert!(reopened(&handle).take_peers_changed());
}

/// Spec 021, R9: a thief's blob of the key being retired is `RetiredKey`
/// and removes the old key's entries it overtook while a member could
/// accept it, never the pending `key_retired`; a failed commit removes
/// nothing and leaves the cursor, and the blob pushed again removes them.
#[test]
fn s021_t09_r09_retiring_key() {
    for (sent_at, removed) in [
        (NOW, true),
        (NOW + HOUR_MS + 420_000, true),
        (NOW - HOUR_MS - 780_000, false),
    ] {
        let (mut channel, _, _, old_seed, entries) = retiring();
        let thief = text_from(&channel, old_seed, 301, sent_at);
        assert_eq!(
            channel.decrypt(&thief, sid(1), NOW, NOW),
            Err(Error::RetiredKey)
        );
        let left: Vec<u64> = channel.state.outbox.iter().map(|e| e.counter).collect();
        let outcomes = channel.take_outcomes();
        if removed {
            assert_eq!(left, [u64::MAX], "{sent_at}");
            let gone: Vec<ClientRef> = outcomes.iter().map(|o| o.client_ref).collect();
            assert_eq!(gone, entries);
            assert!(
                outcomes
                    .iter()
                    .all(|o| o.outcome == AckOutcome::NotDelivered)
            );
        } else {
            assert_eq!(left, [300, 301, u64::MAX], "{sent_at}");
            assert!(outcomes.is_empty());
        }
    }

    // The echo of a superseded `key_retired` copy keeps the pending one.
    let (mut channel, _, _, old_seed, _) = retiring();
    let retired = Payload {
        kind: PayloadKind::KeyRetired,
        display_name: None,
        sent_at: NOW,
        body: Vec::new(),
    };
    let copy = super::seal(&channel, old_seed, |ctx, sender, nonce| {
        crate::proto::envelope::seal(ctx, sender, u64::MAX, nonce, &retired)
    });
    assert_eq!(
        channel.decrypt(&copy, sid(1), NOW, NOW),
        Err(Error::RetiredKey)
    );
    assert_eq!(channel.state.outbox.len(), 1);
    assert!(channel.status().retirement_pending);

    let (mut channel, _, faults, old_seed, entries) = retiring();
    let thief = text_from(&channel, old_seed, 301, NOW);
    faults.fail_commits(true);
    let result = channel.decrypt(&thief, sid(1), NOW, NOW);
    assert_eq!(result, Err(Error::Store(StoreError::Io)));
    assert_eq!(channel.cursor(), None);
    assert_eq!(channel.state.outbox.len(), 3);
    faults.fail_commits(false);
    assert_eq!(
        channel.decrypt(&thief, sid(1), NOW, NOW),
        Err(Error::RetiredKey)
    );
    let gone: Vec<ClientRef> = channel
        .take_outcomes()
        .iter()
        .map(|o| o.client_ref)
        .collect();
    assert_eq!(gone, entries);
}
