//! Tests of spec 025-identity-regen: the regeneration commit, the old
//! key's `key_retired` and the list of one's old keys.

use super::{FULL, HOUR_MS, LIVE, MARGIN_MS, NOW, fill, pk_of, receiver, reopened, sealed, sid};
use crate::Error;
use crate::crypto::PublicKey;
use crate::proto::envelope::{self, ChannelCtx, Content, KEY_RETIRED_COUNTER};
use crate::proto::payload::PayloadKind;
use crate::session::channel::{AckOutcome, Channel, ClientRef, OldKey};
use crate::storage::state::items::{self, OutboxKind, PeerRecord};
use crate::storage::state::{MAX_OLD_KEYS, MAX_OUTBOX, MAX_PEERS};
use crate::storage::{LogEntry, StoreError};
use crate::testing::state_eq;

/// One's current seed.
fn own_seed(channel: &Channel) -> [u8; 32] {
    *channel.state.identity_seed.expose()
}

/// The sender and counter of a blob this channel sealed.
fn sealed_by(channel: &Channel, blob: &[u8]) -> ([u8; 32], u64) {
    let ctx = ChannelCtx::from_config(channel.config()).unwrap();
    let verified = envelope::verify(blob, &ctx, NOW, NOW).unwrap();
    (verified.sender_pk().0, verified.counter())
}

/// The `outbox` entry kept for the `key_retired`.
fn retirement_entry(channel: &Channel) -> &items::OutboxEntry {
    channel
        .state
        .outbox
        .iter()
        .find(|entry| entry.kind == OutboxKind::KeyRetired)
        .unwrap()
}

/// Plants one's old keys retired at `retired_at`, in that order.
fn plant_old_keys(channel: &mut Channel, retired_at: &[u64]) {
    let mut next = channel.next_state();
    next.own_old_keys = retired_at
        .iter()
        .zip(0u8..)
        .map(|(&retired_at, n)| items::OldKey {
            pk: PublicKey(pk_of([0x60 + n; 32])),
            retired_at,
        })
        .collect();
    channel.commit(next, Vec::new()).unwrap();
}

/// Spec 025, R1: one commit with no record gives a fresh key, epoch + 1,
/// counter 0, the own-key event and `read_only` cleared and the old key
/// among one's old keys; the entries left from before are marked and a
/// later `encrypt` is not; no peer limit refuses it, and a second call
/// while the retirement is pending is `RetirementPending`.
#[test]
fn s025_t01_r01_regeneration_commit() {
    let (mut channel, handle, _) = receiver(3_600);
    channel.encrypt("before", None, NOW).unwrap();
    let mut next = channel.next_state();
    next.own_key_used_elsewhere = true;
    next.read_only = true;
    next.send_counter = 7;
    next.peers = (0..MAX_PEERS)
        .map(|n| PeerRecord {
            pk: PublicKey(pk_of(
                u32::try_from(n)
                    .unwrap()
                    .to_le_bytes()
                    .repeat(8)
                    .try_into()
                    .unwrap(),
            )),
            label: None,
            verified: false,
            muted: false,
            retired_at: None,
            first_seen: NOW,
            last_seen: NOW,
            max_counter: Some(0),
            last_display_name: None,
        })
        .collect();
    channel.commit(next, Vec::new()).unwrap();
    let old_seed = own_seed(&channel);
    let (epoch, commits, log_len) = (
        channel.state.identity_epoch,
        handle.all_commits(),
        channel.store.log_len(),
    );

    channel.regenerate_identity(NOW + 5).unwrap();
    assert_eq!(handle.all_commits(), commits + 1);
    assert_eq!(channel.store.log_len(), log_len);
    assert_ne!(own_seed(&channel), old_seed);
    assert_eq!(channel.state.identity_epoch, epoch + 1);
    assert_eq!(channel.send_counter(), 0);
    let status = channel.status();
    assert!(!status.own_key_used_elsewhere && !status.read_only);
    assert_eq!(
        channel.own_old_keys(),
        [OldKey {
            pk: pk_of(old_seed),
            retired_at: NOW + 5,
        }]
    );
    let marks: Vec<(OutboxKind, bool)> = channel
        .state
        .outbox
        .iter()
        .map(|entry| (entry.kind, entry.under_retired_key))
        .collect();
    assert_eq!(
        marks,
        [(OutboxKind::Text, true), (OutboxKind::KeyRetired, true)]
    );
    channel.encrypt("after", None, NOW).unwrap();
    assert!(!channel.state.outbox.last().unwrap().under_retired_key);
    assert!(state_eq(&reopened(&handle).state, &channel.state));

    let commits = handle.all_commits();
    assert_eq!(
        channel.regenerate_identity(NOW + 6),
        Err(Error::RetirementPending)
    );
    assert_eq!(handle.all_commits(), commits);
}

/// Spec 025, R1: with sixteen old keys, the first whose blobs no member
/// accepts any more is dropped, in the order of regeneration even when a
/// clock set back dated a later one earlier; else the first.
#[test]
fn s025_t01_r01_seventeenth_old_key() {
    let window = HOUR_MS + MARGIN_MS;
    let gone = NOW - 2 * window - 1;
    let edge = NOW - 2 * window;
    let mut all_live = vec![edge; MAX_OLD_KEYS];
    all_live[0] = NOW - HOUR_MS;
    let mut one_gone = vec![NOW - HOUR_MS; MAX_OLD_KEYS];
    one_gone[5] = gone;
    one_gone[9] = gone - 1;
    for (planted, dropped) in [(all_live, 0), (one_gone, 5)] {
        let (mut channel, _, _) = receiver(3_600);
        plant_old_keys(&mut channel, &planted);
        let old_pk = pk_of(own_seed(&channel));
        let mut expected: Vec<[u8; 32]> = channel.own_old_keys().iter().map(|old| old.pk).collect();
        expected.remove(dropped);
        expected.push(old_pk);
        channel.regenerate_identity(NOW).unwrap();
        let kept: Vec<[u8; 32]> = channel.own_old_keys().iter().map(|old| old.pk).collect();
        assert_eq!(kept, expected, "dropped {dropped}");
    }
}

/// Spec 025, R1: a full log does not refuse it, since it appends no
/// record; after one's own key was retired elsewhere on a full log, the new
/// key is neither read-only nor exhausted, and raises no alert.
#[test]
fn s025_t01_r01_full_log() {
    let (mut channel, _, _) = receiver(3_600);
    fill(&mut channel, LIVE, FULL);
    channel.regenerate_identity(NOW).unwrap();
    assert!(channel.status().retirement_pending);

    let (mut channel, _, _) = receiver(3_600);
    fill(&mut channel, LIVE, FULL);
    let seed = own_seed(&channel);
    let retired = sealed(&channel, seed, u64::MAX, NOW, PayloadKind::KeyRetired, None);
    assert_eq!(
        channel.decrypt(&retired, sid(1), NOW, NOW),
        Err(Error::Store(StoreError::LogFull))
    );
    assert!(channel.status().read_only);
    channel.regenerate_identity(NOW).unwrap();
    let status = channel.status();
    assert!(!status.read_only && !status.own_key_used_elsewhere);
    assert_eq!(channel.send_counter(), 0);
    assert_eq!(channel.store.log_len(), FULL);
}

/// Spec 025, R2: the entry is the old key's `key_retired` at counter
/// `2^64 − 1`, dated at the minute, and it fits beside 31 ordinary
/// entries in the slot kept for it.
#[test]
fn s025_t02_r02_retirement_sealed() {
    let (mut channel, _, _) = receiver(3_600);
    for _ in 1..MAX_OUTBOX {
        channel.encrypt("old", None, NOW).unwrap();
    }
    let old_pk = pk_of(own_seed(&channel));
    channel.regenerate_identity(NOW + 59_999).unwrap();
    assert_eq!(channel.state.outbox.len(), MAX_OUTBOX);
    let entry = retirement_entry(&channel);
    assert_eq!(
        channel.state.outbox.last().unwrap().kind,
        OutboxKind::KeyRetired
    );
    assert!(entry.under_retired_key);
    assert_eq!(entry.counter, KEY_RETIRED_COUNTER);
    assert_eq!(entry.sent_at, NOW);
    assert_eq!(sealed_by(&channel, &entry.blob), (old_pk, u64::MAX));
    let ctx = ChannelCtx::from_config(channel.config()).unwrap();
    let verified = envelope::verify(&entry.blob, &ctx, NOW, NOW).unwrap();
    assert_eq!(verified.signature(), &entry.signature.0);
    let opened = verified.open().unwrap();
    assert_eq!(opened.sent_at, Some(NOW));
    assert!(
        matches!(opened.content, Content::Message(payload) if payload.kind == PayloadKind::KeyRetired)
    );
}

/// Spec 025, R3: echoes of the old key's blobs, waiting or acknowledged
/// before the regeneration, are `RetiredKey` with no own-key event and
/// commit nothing, before and after a reopen.
#[test]
fn s025_t03_r03_old_echoes_are_retired() {
    let (mut channel, handle, _) = receiver(3_600);
    let acked = channel.encrypt("acked", None, NOW).unwrap();
    channel.encrypt("waiting", None, NOW).unwrap();
    let echoes: Vec<Vec<u8>> = channel
        .state
        .outbox
        .iter()
        .map(|entry| entry.blob.clone())
        .collect();
    channel.acked(acked, sid(9), NOW, NOW).unwrap();
    channel.regenerate_identity(NOW).unwrap();
    let mut before = channel.state.duplicate();
    for round in 0..2 {
        for (n, echo) in (1u8..).zip(&echoes) {
            let commits = handle.commits();
            assert_eq!(
                channel.decrypt(echo, sid(n + 10 * round), NOW, NOW),
                Err(Error::RetiredKey)
            );
            assert_eq!(handle.commits(), commits);
            assert!(!channel.status().own_key_used_elsewhere);
            assert!(channel.take_outcomes().is_empty());
        }
        // A rejection commits the cursor alone (AGENTS 23).
        before.cursor = channel.state.cursor;
        assert!(state_eq(&channel.state, &before));
        channel = reopened(&handle);
    }
}

/// Spec 025, R6: `retirement_pending` follows the old seed, across a
/// reopen, and `own_old_keys` lists the old key with its time.
#[test]
fn s025_t06_r06_pending_flag_and_old_keys() {
    let (mut channel, handle, _) = receiver(3_600);
    assert!(!channel.status().retirement_pending);
    assert!(channel.own_old_keys().is_empty());
    let old_pk = pk_of(own_seed(&channel));
    channel.regenerate_identity(NOW + 1).unwrap();
    assert!(channel.status().retirement_pending);
    let channel = reopened(&handle);
    assert!(channel.status().retirement_pending);
    assert_eq!(
        channel.own_old_keys(),
        [OldKey {
            pk: old_pk,
            retired_at: NOW + 1,
        }]
    );
}

/// Spec 025, R7: after a regeneration every ordinary `encrypt` is sealed
/// with the new key and listed under it; the old seed is held only as the
/// one for the `key_retired`.
#[test]
fn s025_t07_r07_old_key_only_for_retirement() {
    let (mut channel, _, _) = receiver(3_600);
    let old_seed = own_seed(&channel);
    channel.regenerate_identity(NOW).unwrap();
    let new_pk = pk_of(own_seed(&channel));
    for counter in 0..3 {
        channel.encrypt("new", None, NOW).unwrap();
        let entry = channel.state.outbox.last().unwrap();
        assert_eq!(sealed_by(&channel, &entry.blob), (new_pk, counter));
        let listed = channel
            .records
            .iter()
            .rev()
            .find_map(|record| match &record.entry {
                LogEntry::Message(message) => Some(message.sender_pk.0),
                _ => None,
            });
        assert_eq!(listed, Some(new_pk));
    }
    let retiring = channel.state.retiring_seed.as_ref().unwrap();
    assert_eq!(*retiring.expose(), old_seed);
    let entry = retirement_entry(&channel);
    assert_eq!(
        sealed_by(&channel, &entry.blob),
        (pk_of(old_seed), u64::MAX)
    );
}

/// Spec 025, R8: a regeneration whose commit fails leaves the state in
/// memory and on reopening as it was, the old key current.
#[test]
fn s025_t08_r08_failing_store() {
    let (mut channel, handle, faults) = receiver(3_600);
    channel.encrypt("old", None, NOW).unwrap();
    let before = channel.state.duplicate();
    faults.fail_commits(true);
    assert_eq!(
        channel.regenerate_identity(NOW),
        Err(Error::Store(StoreError::Io))
    );
    assert!(state_eq(&channel.state, &before));
    assert!(state_eq(&reopened(&handle).state, &before));
    assert!(!channel.status().retirement_pending);
    faults.fail_commits(false);
    channel.regenerate_identity(NOW).unwrap();
}

/// The `client_ref` of the pending `key_retired`.
fn retirement_ref(channel: &Channel) -> ClientRef {
    ClientRef::of(retirement_entry(channel))
}

/// The `client_ref`s `outbox` hands out at `now`.
fn handed_out(channel: &mut Channel, now: u64, in_flight: &[ClientRef]) -> Vec<ClientRef> {
    let step = channel.outbox(now, in_flight, false).unwrap();
    step.publish
        .iter()
        .map(|(client_ref, _)| *client_ref)
        .collect()
}

/// A regeneration at `NOW` whose retirement the server stored at `NOW`.
fn delivered(channel: &mut Channel) {
    channel.regenerate_identity(NOW).unwrap();
    let outcome = channel
        .acked(retirement_ref(channel), sid(7), NOW, NOW)
        .unwrap();
    assert_eq!(outcome.outcome, AckOutcome::RetirementDelivered);
}

/// Spec 025, R1 with R4 and R5: once a retirement is delivered no entry
/// of the first old key is left, so a second regeneration marks only the
/// second old key's.
#[test]
fn s025_t01_r01_second_regeneration() {
    let (mut channel, _, _) = receiver(3_600);
    let first = channel.encrypt("first key", None, NOW).unwrap();
    channel.regenerate_identity(NOW).unwrap();
    assert_eq!(handed_out(&mut channel, NOW, &[]), [first]);
    channel.acked(first, sid(1), NOW, NOW).unwrap();
    let retirement = retirement_ref(&channel);
    assert_eq!(handed_out(&mut channel, NOW, &[]), [retirement]);
    channel.acked(retirement, sid(2), NOW, NOW).unwrap();
    channel.encrypt("second key", None, NOW).unwrap();
    let second_pk = pk_of(own_seed(&channel));
    channel.regenerate_identity(NOW).unwrap();
    for entry in &channel.state.outbox {
        assert!(entry.under_retired_key);
        assert_eq!(sealed_by(&channel, &entry.blob).0, second_pk);
    }
    assert_eq!(channel.state.outbox.len(), 2);
}

/// Spec 025, R2 with R4: the `key_retired` is handed out only after the
/// last of 31 entries of the old key leaves the `outbox`.
#[test]
fn s025_t02_r02_retirement_after_old_entries() {
    let (mut channel, _, _) = receiver(3_600);
    let old: Vec<ClientRef> = (1..MAX_OUTBOX)
        .map(|_| channel.encrypt("old", None, NOW).unwrap())
        .collect();
    channel.regenerate_identity(NOW).unwrap();
    let retirement = retirement_ref(&channel);
    assert_eq!(handed_out(&mut channel, NOW, &[]), old);
    assert_eq!(
        channel.outbox(NOW, &[], true).unwrap().publish.len(),
        old.len()
    );
    let (last, earlier) = old.split_last().unwrap();
    for client_ref in earlier {
        channel.abandon(*client_ref).unwrap();
    }
    assert_eq!(handed_out(&mut channel, NOW, &[]), [*last]);
    channel.acked(*last, sid(1), NOW, NOW).unwrap();
    assert_eq!(handed_out(&mut channel, NOW, &[]), [retirement]);
}

/// Spec 025, R4: re-sealed in place when the minute of `now` differs, in
/// either direction, never in flight, never by `expire_outbox`; a
/// superseded copy's echo removes nothing; a failed commit hands out
/// nothing and keeps the stored copy.
#[test]
fn s025_t04_r04_reseal() {
    let (mut channel, handle, faults) = receiver(3_600);
    channel.regenerate_identity(NOW).unwrap();
    let current = channel.encrypt("new key", None, NOW).unwrap();
    let first = retirement_entry(&channel).blob.clone();
    let commits = handle.all_commits();
    let step = channel.outbox(NOW + 59_999, &[], false).unwrap();
    assert_eq!(step.publish[0].1, first);
    assert_eq!(handle.all_commits(), commits);

    let superseded = retirement_ref(&channel);
    let step = channel.outbox(NOW + 60_000, &[], false).unwrap();
    assert_eq!(handle.all_commits(), commits + 1);
    let entry = &channel.state.outbox[0];
    assert_eq!(entry.kind, OutboxKind::KeyRetired);
    assert_eq!(entry.sent_at, NOW + 60_000);
    assert_ne!(entry.blob[..], first[..]);
    assert_ne!(ClientRef::of(entry), superseded);
    assert_eq!(step.publish[0], (ClientRef::of(entry), entry.blob.clone()));
    assert!(state_eq(&reopened(&handle).state, &channel.state));

    // Earlier, as after a clock set back, and in flight: none of them.
    channel.outbox(NOW - HOUR_MS, &[], true).unwrap();
    assert_eq!(retirement_entry(&channel).sent_at, NOW - HOUR_MS);
    let in_flight = retirement_ref(&channel);
    let commits = handle.all_commits();
    let step = channel.outbox(NOW, &[in_flight], false).unwrap();
    assert_eq!(step.publish.len(), 1);
    assert_eq!(retirement_ref(&channel), in_flight);
    channel.expire_outbox(NOW + 2 * 60_000, &[]).unwrap();
    assert_eq!(retirement_ref(&channel), in_flight);
    assert_eq!(handle.all_commits(), commits);

    let commits = handle.commits();
    assert_eq!(
        channel.decrypt(&first, sid(3), NOW, NOW),
        Err(Error::RetiredKey)
    );
    assert_eq!(handle.commits(), commits);
    assert_eq!(channel.outbox_ref(0), Some(current));
    assert!(channel.take_outcomes().is_empty());
    assert!(!channel.status().own_key_used_elsewhere);

    let before = channel.state.duplicate();
    faults.fail_commits(true);
    assert_eq!(
        channel.outbox(NOW + 2 * 60_000, &[], false),
        Err(Error::Store(StoreError::Io))
    );
    assert!(state_eq(&channel.state, &before));
    assert!(state_eq(&reopened(&handle).state, &before));
}

/// Spec 025, R5: an `ack` of the current copy stored within one window of
/// its `sent_at` removes the entry and the old seed, keeping no
/// signature; a late or early one, or one of a previous copy, is
/// `Ignored` and commits nothing.
#[test]
fn s025_t05_r05_ack_erases_old_key() {
    let window = HOUR_MS + MARGIN_MS;
    for (received_at, delivered) in [
        (NOW, true),
        (NOW + window, true),
        (NOW - window, true),
        (NOW + window + 1, false),
        (NOW - window - 1, false),
    ] {
        let (mut channel, handle, _) = receiver(3_600);
        channel.regenerate_identity(NOW).unwrap();
        let retirement = retirement_ref(&channel);
        let (commits, records) = (handle.all_commits(), channel.records.len());
        let outcome = channel
            .acked(retirement, sid(1), received_at, NOW + window + 1)
            .unwrap();
        assert_eq!(channel.records.len(), records);
        if delivered {
            assert_eq!(outcome.outcome, AckOutcome::RetirementDelivered);
            assert_eq!(outcome.sent_at, Some(NOW));
            assert!(channel.state.outbox.is_empty());
            assert!(channel.state.retiring_seed.is_none());
            assert_eq!(handle.all_commits(), commits + 1);
        } else {
            assert_eq!(outcome.outcome, AckOutcome::Ignored, "{received_at}");
            assert!(channel.state.retiring_seed.is_some());
            assert_eq!(channel.state.outbox.len(), 1);
            assert_eq!(handle.all_commits(), commits);
        }
    }

    let (mut channel, handle, _) = receiver(3_600);
    channel.regenerate_identity(NOW).unwrap();
    let previous = retirement_ref(&channel);
    channel.outbox(NOW + 60_000, &[], false).unwrap();
    let commits = handle.all_commits();
    let outcome = channel.acked(previous, sid(1), NOW, NOW).unwrap();
    assert_eq!(outcome.outcome, AckOutcome::Ignored);
    assert_eq!(handle.all_commits(), commits);
    assert!(channel.status().retirement_pending);
}

/// Spec 025, R6: the flag is false again after the delivery, also on
/// reopening.
#[test]
fn s025_t06_r06_flag_cleared_by_delivery() {
    let (mut channel, handle, _) = receiver(3_600);
    delivered(&mut channel);
    assert!(!channel.status().retirement_pending);
    assert!(!reopened(&handle).status().retirement_pending);
    assert_eq!(channel.own_old_keys().len(), 1);
}

/// Spec 025, R7: the state the delivery writes holds no old seed.
#[test]
fn s025_t07_r07_delivery_drops_old_seed() {
    let (mut channel, handle, _) = receiver(3_600);
    delivered(&mut channel);
    let reopened = reopened(&handle);
    assert!(reopened.state.retiring_seed.is_none());
    assert!(reopened.state.outbox.is_empty());
}

/// Spec 025, R8: a delivering `ack` whose commit fails leaves the state in
/// memory and on reopening as it was.
#[test]
fn s025_t08_r08_failing_ack() {
    let (mut channel, handle, faults) = receiver(3_600);
    channel.regenerate_identity(NOW).unwrap();
    let before = channel.state.duplicate();
    faults.fail_commits(true);
    let result = channel.acked(retirement_ref(&channel), sid(1), NOW, NOW);
    assert_eq!(result, Err(Error::Store(StoreError::Io)));
    assert!(state_eq(&channel.state, &before));
    assert!(state_eq(&reopened(&handle).state, &before));
}
