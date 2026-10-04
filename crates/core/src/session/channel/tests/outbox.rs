//! Tests of the `outbox` after sealing: R15–R17, R22, R23, R31 and their
//! clauses of R32.

use super::{
    HOUR_MS, MARGIN_MS, NOW, SERVER, config_on, config_with, failing_channel, new_channel, reopened,
};
use crate::Error;
use crate::crypto::Signature;
use crate::session::channel::{AckOutcome, Channel, ClientRef, Outcome};
use crate::storage::state::items::{OutboxEntry, OutboxKind};
use crate::storage::{LogEntry, LogRecord, StoreError};
use crate::testing::state_eq;

const SERVER_ID: [u8; 16] = [0x5e; 16];

/// A pending `key_retired`, planted as spec 025-identity-regen would.
fn key_retired() -> OutboxEntry {
    OutboxEntry {
        client_ref: [0xee; 16],
        kind: OutboxKind::KeyRetired,
        sent_at: NOW,
        blob: vec![1; 10],
        signature: Signature([2; 64]),
        under_retired_key: false,
        counter: u64::MAX,
    }
}

/// Plants the `key_retired` and marks the entries of `retired` as sealed
/// under the key being retired, in one commit.
fn mark_retiring(channel: &mut Channel, retired: &[ClientRef]) {
    let mut next = channel.next_state();
    for entry in &mut next.outbox {
        entry.under_retired_key = retired.contains(&ClientRef::of(entry));
    }
    next.outbox.push(key_retired());
    channel.commit(next, Vec::new()).unwrap();
}

fn is_kept_signature(record: &LogRecord) -> bool {
    matches!(record.entry, LogEntry::KeptSignature { .. })
}

fn is_not_delivered(record: &LogRecord, client_ref: ClientRef) -> bool {
    matches!(record.entry, LogEntry::NotDelivered { client_ref: c } if c == client_ref.bytes)
}

/// Spec 021, R16: an `ack` for no entry is `Ignored`, with no commit.
#[test]
fn s021_t16_r16_unknown_ack() {
    let (mut channel, handle) = new_channel();
    let unknown = ClientRef { bytes: [9; 16] };
    let outcome = channel.acked(unknown, SERVER_ID, NOW, NOW).unwrap();
    assert_eq!(outcome.outcome, AckOutcome::Ignored);
    assert_eq!(outcome.sent_at, None);
    assert_eq!(handle.all_commits(), 1);
}

/// Spec 021, R17: in time → `Delivered` with an acked record at the
/// clamped time, a lower entry removed as not delivered; out of time or
/// dated beyond the margin → `NotDelivered` and a not-delivered record.
#[test]
fn s021_t17_r17_acked() {
    let (mut channel, _) = new_channel();
    let lower = channel.encrypt("lower", None, NOW).unwrap();
    let upper = channel.encrypt("upper", None, NOW).unwrap();
    let outcome = channel
        .acked(upper, SERVER_ID, NOW + 1_000, NOW + 2_000)
        .unwrap();
    let expected = Outcome {
        client_ref: upper,
        outcome: AckOutcome::Delivered,
        server_id: Some(SERVER_ID),
        received_at: Some(NOW + 1_000),
        sent_at: Some(NOW),
    };
    assert_eq!(outcome, expected);
    assert!(channel.state.outbox.is_empty());
    let outcomes = channel.take_outcomes();
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0].client_ref, lower);
    assert_eq!(outcomes[0].outcome, AckOutcome::NotDelivered);
    assert_eq!(outcomes[0].sent_at, Some(NOW));
    assert!(channel.take_outcomes().is_empty());
    let new: Vec<&LogRecord> = channel.records.iter().skip(2).collect();
    assert!(is_kept_signature(new[0]) && is_kept_signature(new[1]));
    assert!(is_not_delivered(new[2], lower));
    assert!(matches!(
        new[3].entry,
        LogEntry::Acked { server_id: SERVER_ID, received_at: r, client_ref: c }
            if r == NOW + 1_000 && c == upper.bytes
    ));

    // (TTL, the `ack`'s `received_at`, `now`) → outcome and listed time.
    let cases: [(u32, u64, u64, AckOutcome, u64); 9] = [
        (
            3_600,
            NOW + 50_000,
            NOW + 10_000,
            AckOutcome::Delivered,
            NOW + 10_000,
        ),
        (
            3_600,
            NOW - HOUR_MS,
            NOW + 1,
            AckOutcome::Delivered,
            NOW - MARGIN_MS,
        ),
        (
            60,
            NOW - 30_000,
            NOW + 61_000,
            AckOutcome::NotDelivered,
            NOW - 30_000,
        ),
        (
            60,
            NOW - 30_000,
            NOW + 31_000,
            AckOutcome::Delivered,
            NOW - 30_000,
        ),
        (
            60,
            NOW + 600_000,
            NOW + 1_000,
            AckOutcome::NotDelivered,
            NOW + 1_000,
        ),
        (
            60,
            NOW + 86_400_000,
            NOW + 1_000,
            AckOutcome::NotDelivered,
            NOW + 1_000,
        ),
        (
            60,
            NOW - 86_400_000,
            NOW + 1_000,
            AckOutcome::NotDelivered,
            NOW - MARGIN_MS,
        ),
        (
            3_600,
            NOW + HOUR_MS + MARGIN_MS + 1,
            NOW + 1_000,
            AckOutcome::NotDelivered,
            NOW + 1_000,
        ),
        (
            3_600,
            NOW + HOUR_MS + MARGIN_MS,
            NOW + HOUR_MS,
            AckOutcome::Delivered,
            NOW + HOUR_MS,
        ),
    ];
    for (ttl, received_at, now, outcome, listed_at) in cases {
        let (mut channel, _, _) = failing_channel(&config_with(ttl));
        let sent = channel.encrypt("hi", None, NOW).unwrap();
        let result = channel.acked(sent, SERVER_ID, received_at, now).unwrap();
        assert_eq!(result.outcome, outcome, "{ttl} {received_at} {now}");
        assert_eq!(
            result.received_at,
            Some(listed_at),
            "{ttl} {received_at} {now}"
        );
        let last = channel.records.last().unwrap();
        match outcome {
            AckOutcome::Delivered => assert!(
                matches!(last.entry, LogEntry::Acked { received_at: r, .. } if r == listed_at)
            ),
            _ => assert!(is_not_delivered(last, sent)),
        }
    }
}

/// Spec 021, R15 and R26: an acknowledged entry's signature moves to a
/// kept record that lasts `sent_at + 2·(ttl_ms + 360 000)`, an entry
/// `under_retired_key` too; acked and not-delivered records take the
/// `purge_at` of their message.
#[test]
fn s021_t15_r15_signature_retention() {
    let (mut channel, _) = new_channel();
    let first = channel.encrypt("one", None, NOW).unwrap();
    let signature = channel.state.outbox[0].signature;
    let second = channel.encrypt("two", None, NOW).unwrap();
    mark_retiring(&mut channel, &[second]);
    let before = channel.records.len();
    channel.acked(first, SERVER_ID, NOW, NOW).unwrap();
    channel.acked(second, [1; 16], NOW, NOW).unwrap();
    let new: Vec<&LogRecord> = channel.records.iter().skip(before).collect();
    let kept = NOW + 2 * (HOUR_MS + MARGIN_MS);
    let message = NOW + 2 * HOUR_MS + 420_000;
    assert_eq!(new.len(), 4);
    assert!(
        matches!(new[0].entry, LogEntry::KeptSignature { signature: s, sent_at: NOW, .. } if s == signature)
    );
    assert!(is_kept_signature(new[2]));
    for record in [new[0], new[2]] {
        assert_eq!(record.purge_at, kept);
    }
    for record in [new[1], new[3]] {
        assert_eq!(record.purge_at, message);
    }
    // The pending `key_retired` is spec 025's.
    assert_eq!(channel.state.outbox.len(), 1);
}

/// Spec 021, R22: stale entries are removed and reported, one in flight a
/// minute later; the others are handed out in order, only the retirement's
/// with `withhold_current`; nothing to remove commits nothing.
#[test]
fn s021_t22_r22_outbox() {
    let (mut channel, handle) = new_channel();
    let stale = channel.encrypt("stale", None, NOW).unwrap();
    let in_flight = channel.encrypt("in flight", None, NOW).unwrap();
    let later = NOW + 600_000;
    let fresh: Vec<ClientRef> = (0..3)
        .map(|_| channel.encrypt("fresh", None, later).unwrap())
        .collect();
    let commits = handle.all_commits();
    let step = channel.outbox(NOW + 1, &[in_flight], false).unwrap();
    assert!(step.not_delivered.is_empty());
    assert_eq!(handle.all_commits(), commits);
    let order: Vec<ClientRef> = step.publish.iter().map(|(c, _)| *c).collect();
    assert_eq!(order, [&[stale][..], &fresh].concat());
    assert_eq!(step.publish[0].1, channel.state.outbox[0].blob);

    let past = NOW + HOUR_MS + MARGIN_MS + 1;
    let step = channel.outbox(past, &[in_flight], false).unwrap();
    assert_eq!(step.not_delivered, [(stale, NOW)]);
    let order: Vec<ClientRef> = step.publish.iter().map(|(c, _)| *c).collect();
    assert_eq!(order, fresh);
    let step = channel.outbox(past + 59_999, &[in_flight], false).unwrap();
    assert!(step.not_delivered.is_empty());
    let step = channel.outbox(past + 60_000, &[in_flight], false).unwrap();
    assert_eq!(step.not_delivered, [(in_flight, NOW)]);
    assert!(channel.take_outcomes().is_empty());
    assert_eq!(reopened(&handle).state.outbox.len(), 3);

    mark_retiring(&mut channel, &[fresh[1]]);
    let step = channel.outbox(later, &[], true).unwrap();
    let order: Vec<ClientRef> = step.publish.iter().map(|(c, _)| *c).collect();
    assert_eq!(order, [fresh[1], ClientRef { bytes: [0xee; 16] }]);
}

/// Spec 021, R23: `expire_outbox` removes a stale ordinary entry, hands
/// out nothing and leaves the pending `key_retired` as it is.
#[test]
fn s021_t23_r23_expire_outbox() {
    let (mut channel, _) = new_channel();
    let stale = channel.encrypt("stale", None, NOW).unwrap();
    mark_retiring(&mut channel, &[]);
    let step = channel.expire_outbox(NOW + 2 * HOUR_MS, &[]).unwrap();
    assert!(step.publish.is_empty());
    assert_eq!(step.not_delivered, [(stale, NOW)]);
    assert_eq!(channel.state.outbox.len(), 1);
    assert_eq!(channel.state.outbox[0].blob, key_retired().blob);
}

/// Spec 021, R31: an ordinary entry is removed with its kept signature and
/// a not-delivered record; a `key_retired` or an unknown one commit
/// nothing.
#[test]
fn s021_t31_r31_abandon() {
    let (mut channel, handle) = new_channel();
    let sent = channel.encrypt("refused", None, NOW).unwrap();
    mark_retiring(&mut channel, &[]);
    assert_eq!(channel.abandon(sent), Ok(Some(NOW)));
    let new: Vec<&LogRecord> = channel.records.iter().skip(1).collect();
    assert!(is_kept_signature(new[0]) && is_not_delivered(new[1], sent));
    let commits = handle.all_commits();
    for client_ref in [ClientRef { bytes: [0xee; 16] }, sent] {
        assert_eq!(channel.abandon(client_ref), Ok(None));
    }
    assert_eq!(handle.all_commits(), commits);
    assert_eq!(channel.state.outbox.len(), 1);
}

/// Spec 021, R32: `acked`, `outbox`, `expire_outbox` and `abandon` under a
/// failing commit leave memory and the reopened state as before, and hand
/// nothing out.
#[test]
fn s021_t32_r32_failing_outbox_methods() {
    let (mut channel, handle, faults) = failing_channel(&config_on(SERVER));
    let first = channel.encrypt("one", None, NOW).unwrap();
    let second = channel.encrypt("two", None, NOW).unwrap();
    let before = channel.state.duplicate();
    faults.fail_commits(true);
    let io = Err(Error::Store(StoreError::Io));
    let past = NOW + 2 * HOUR_MS;
    assert_eq!(channel.acked(second, SERVER_ID, NOW, NOW).map(|_| ()), io);
    assert_eq!(channel.outbox(past, &[], false).map(|_| ()), io);
    assert_eq!(channel.expire_outbox(past, &[]).map(|_| ()), io);
    assert_eq!(channel.abandon(first).map(|_| ()), io);
    assert!(channel.take_outcomes().is_empty());
    assert!(state_eq(&channel.state, &before));
    assert!(state_eq(&reopened(&handle).state, &before));
    assert_eq!(channel.records.len(), 2);
}

/// Spec 021, R17 and R22: an `ack` removes the lower entries of its own
/// key only; an entry not in flight goes one millisecond after `sent_at +
/// ttl_ms + 360 000`, not at it.
#[test]
fn s021_t17_r17_same_key_and_edges() {
    let (mut channel, _) = new_channel();
    let old = channel.encrypt("old key", None, NOW).unwrap();
    mark_retiring(&mut channel, &[old]);
    let current = channel.encrypt("current key", None, NOW).unwrap();
    channel.acked(current, SERVER_ID, NOW, NOW).unwrap();
    let left: Vec<ClientRef> = channel.state.outbox.iter().map(ClientRef::of).collect();
    assert_eq!(left, [old, ClientRef { bytes: [0xee; 16] }]);

    let (mut channel, _) = new_channel();
    let sent = channel.encrypt("edge", None, NOW).unwrap();
    let edge = NOW + HOUR_MS + MARGIN_MS;
    assert!(
        channel
            .outbox(edge, &[], false)
            .unwrap()
            .not_delivered
            .is_empty()
    );
    let step = channel.outbox(edge + 1, &[], false).unwrap();
    assert_eq!(step.not_delivered, [(sent, NOW)]);
}
