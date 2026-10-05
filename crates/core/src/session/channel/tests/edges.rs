//! The edges and branches audit AD's hand mutants reached and no test
//! held: each test names the requirement whose clause it pins.

use super::{
    FULL, HEADROOM, HOUR_MS, LIVE, MARGIN_MS, NOW, counters, fill, own_text, pk_of, receiver,
    reopened, retiring, sealed, sid, text_from,
};
use crate::Error;
use crate::crypto::PublicKey;
use crate::proto::payload::PayloadKind;
use crate::session::channel::{AckOutcome, Channel, ClientRef};
use crate::storage::StoreError;
use crate::storage::state::items::PeerRecord;
use crate::testing::record;

const ANN: [u8; 32] = [0x41; 32];
const BOB: [u8; 32] = [0x42; 32];

/// Delivers a text of `seed` at `counter`, sent and received at `at`.
fn deliver(channel: &mut Channel, seed: [u8; 32], counter: u64, at: u64, name: Option<&str>) {
    let blob = sealed(channel, seed, counter, at, PayloadKind::Text, name);
    let mut id = [seed[0]; 16];
    id[8..].copy_from_slice(&counter.to_be_bytes());
    channel.decrypt(&blob, id, at, at).unwrap().unwrap();
}

/// An unknown peer record of `seed`.
fn peer(seed: [u8; 32]) -> PeerRecord {
    PeerRecord {
        pk: PublicKey(pk_of(seed)),
        label: None,
        verified: false,
        muted: false,
        retired_at: None,
        first_seen: NOW,
        last_seen: NOW,
        max_counter: None,
        last_display_name: None,
    }
}

/// Spec 021, R9: a counter equal to `max_counter` with no seen record is
/// `Replay`; with a retirement pending, the device's own sealed copy of an
/// old-key entry, a retired peer and an old key that is not being retired
/// remove nothing, and a thief removes no entry of the current key.
#[test]
fn s021_t09_r09_edges() {
    let (mut channel, _, _) = receiver(3_600);
    let mut next = channel.next_state();
    next.peers.push(PeerRecord {
        max_counter: Some(5),
        ..peer(ANN)
    });
    channel.commit(next, Vec::new()).unwrap();
    let equal = text_from(&channel, ANN, 5, NOW);
    assert_eq!(
        channel.decrypt(&equal, sid(1), NOW, NOW),
        Err(Error::Replay)
    );

    let (mut channel, _, _, _, entries) = retiring();
    let own = channel
        .state
        .outbox
        .iter()
        .find(|e| e.client_ref == entries[1].bytes);
    let own = own.unwrap().blob.clone();
    assert_eq!(
        channel.decrypt(&own, sid(1), NOW, NOW),
        Err(Error::RetiredKey)
    );
    assert_eq!(counters(&channel), [300, 301, u64::MAX]);
    assert!(channel.take_outcomes().is_empty());

    let (mut channel, _, _, _, _) = retiring();
    let mut next = channel.next_state();
    next.peers.push(PeerRecord {
        retired_at: Some(NOW),
        ..peer(BOB)
    });
    channel.commit(next, Vec::new()).unwrap();
    let retired = text_from(&channel, BOB, 400, NOW);
    assert_eq!(
        channel.decrypt(&retired, sid(1), NOW, NOW),
        Err(Error::RetiredKey)
    );
    assert_eq!(counters(&channel), [300, 301, u64::MAX]);

    let (mut channel, _, _, old_seed, _) = retiring();
    channel.encrypt("current key", None, NOW).unwrap();
    let thief = text_from(&channel, old_seed, 1_000, NOW);
    assert_eq!(
        channel.decrypt(&thief, sid(1), NOW, NOW),
        Err(Error::RetiredKey)
    );
    assert_eq!(counters(&channel), [u64::MAX, 302]);
}

/// Spec 021, R10 and R11: a message dated exactly one TTL back is still
/// shown; an unknown's `key_retired` creates no peer; a message with no
/// name keeps the last one, and every message moves `last_seen`.
#[test]
fn s021_t11_r11_edges() {
    let (mut channel, _, _) = receiver(3_600);
    let edge = text_from(&channel, ANN, 1, NOW - HOUR_MS);
    assert!(channel.decrypt(&edge, sid(1), NOW, NOW).unwrap().is_some());

    let (mut channel, _, _) = receiver(3_600);
    let retired = sealed(&channel, ANN, u64::MAX, NOW, PayloadKind::KeyRetired, None);
    channel.decrypt(&retired, sid(1), NOW, NOW).unwrap();
    assert!(channel.state.peers.is_empty());

    let (mut channel, _, _) = receiver(3_600);
    deliver(&mut channel, ANN, 0, NOW, Some("Bea"));
    deliver(&mut channel, ANN, 1, NOW + 60_000, None);
    let peer = &channel.state.peers[0];
    assert_eq!(
        peer.last_display_name.as_deref().map(|n| &n[..]),
        Some(&b"Bea"[..])
    );
    assert_eq!(peer.last_seen, NOW + 60_000);
}

/// Spec 021, R1: a peer's new name and a commit of its `retired_at` set the
/// peers-changed flag.
#[test]
fn s021_t01_r01_peers_changed_edges() {
    let (mut channel, _, _) = receiver(3_600);
    deliver(&mut channel, ANN, 0, NOW, Some("Bea"));
    channel.take_peers_changed();
    deliver(&mut channel, ANN, 1, NOW, Some("Cy"));
    assert!(channel.take_peers_changed());
    let mut next = channel.next_state();
    next.peers[0].retired_at = Some(NOW);
    channel.commit(next, Vec::new()).unwrap();
    assert!(channel.take_peers_changed());
}

/// Spec 021, R24: the edges of the truncation window, and
/// `spans_truncation` kept on a sender's total.
#[test]
fn s021_t24_r24_truncation_edges() {
    // Last seen exactly at `truncated_at − ttl_ms`: not away.
    let (mut channel, _, _) = receiver(3_600);
    deliver(&mut channel, ANN, 0, NOW, None);
    channel.history_truncated(NOW + HOUR_MS);
    deliver(&mut channel, ANN, 5, NOW + HOUR_MS + 60_000, None);
    assert_eq!(channel.gaps()[0].missing, 4);

    // Away, and listed exactly at `truncated_at + ttl_ms + 360 000`.
    let (mut channel, _, _) = receiver(3_600);
    deliver(&mut channel, ANN, 0, NOW, None);
    let truncated_at = NOW + HOUR_MS + 60_000;
    channel.history_truncated(truncated_at);
    deliver(
        &mut channel,
        ANN,
        5,
        truncated_at + HOUR_MS + MARGIN_MS,
        None,
    );
    assert!(channel.gaps().is_empty());

    // A plain gap, then one across a truncation.
    let (mut channel, _, _) = receiver(3_600);
    deliver(&mut channel, ANN, 0, NOW, None);
    deliver(&mut channel, ANN, 3, NOW, None);
    channel.history_truncated(NOW + 2 * HOUR_MS);
    deliver(&mut channel, ANN, 9, NOW + 30 * 86_400_000, None);
    let gap = channel.gaps()[0];
    assert_eq!((gap.missing, gap.spans_truncation), (7, true));
}

/// Spec 021, R18: a compaction at a record's own `purge_at` keeps it in
/// memory as on disk.
#[test]
fn s021_t18_r18_compaction_at_purge_at() {
    let (mut channel, handle, _) = receiver(3_600);
    let start = channel.store.log_len();
    fill(&mut channel, NOW - 1, start + 1_048_576);
    let at_now = channel.store.log_len() + record(0, 0).entry_len();
    fill(&mut channel, NOW, at_now);
    fill(&mut channel, LIVE, FULL - HEADROOM + 1);
    assert_eq!(channel.relieve_headroom(NOW), Ok(true));
    assert_eq!(channel.records.len(), reopened(&handle).records.len());
}

/// Spec 021, R7, R16 and R33: a pending `key_retired` takes none of the 31
/// ordinary slots, has no `outbox_ref`, and its `ack` is spec 025's.
#[test]
fn s021_t16_r16_key_retired_entry() {
    let (mut channel, _, _, _, _) = retiring();
    assert_eq!(channel.outbox_ref(u64::MAX), None);
    let outcome = channel
        .acked(ClientRef { bytes: [0xee; 16] }, sid(1), NOW, NOW)
        .unwrap();
    assert_eq!(outcome.outcome, AckOutcome::Ignored);
    for _ in 0..29 {
        channel.encrypt("more", None, NOW).unwrap();
    }
    let full = channel.encrypt("one too many", None, NOW);
    assert_eq!(full, Err(Error::Store(StoreError::OutboxFull)));
    assert!(counters(&channel).contains(&u64::MAX));
}

/// Spec 021, R20: `flush` commits a `synced_at` that was not due.
#[test]
fn s021_t20_r20_flush_synced_at() {
    let (mut channel, handle, _) = receiver(3_600);
    channel.synced(NOW).unwrap();
    channel.synced(NOW + 1_000).unwrap();
    let all = handle.all_commits();
    channel.flush(NOW + 1_000).unwrap();
    assert_eq!(handle.all_commits(), all + 1);
    assert_eq!(reopened(&handle).synced_at(), Some(NOW + 1_000));
}

/// Spec 021, R14 and R19: with 50 muted unknowns a foreign blob of one's
/// own key still raises the event (no room check applies to it); under a
/// full log, a `key_retired` that changes only `read_only` commits it.
#[test]
fn s021_t14_r14_own_key_edges() {
    let (mut channel, _, _) = receiver(3_600);
    let mut next = channel.next_state();
    for n in 0..50u8 {
        next.peers.push(PeerRecord {
            muted: true,
            ..peer([n; 32])
        });
    }
    channel.commit(next, Vec::new()).unwrap();
    let foreign = own_text(&channel, 3, NOW);
    assert!(
        channel
            .decrypt(&foreign, sid(1), NOW, NOW)
            .unwrap()
            .is_some()
    );
    assert!(channel.status().own_key_used_elsewhere);
    assert_eq!(channel.state.peers.len(), 50);

    let (mut channel, handle, _) = receiver(3_600);
    let mut next = channel.next_state();
    next.send_counter = 12;
    next.own_key_used_elsewhere = true;
    channel.commit(next, Vec::new()).unwrap();
    fill(&mut channel, LIVE, FULL - HEADROOM + 1);
    let seed = *channel.state.identity_seed.expose();
    let retired = sealed(&channel, seed, 5, NOW, PayloadKind::KeyRetired, None);
    assert_eq!(channel.check_own_key(&retired, NOW, NOW), Ok(true));
    assert!(reopened(&handle).status().read_only);
}
