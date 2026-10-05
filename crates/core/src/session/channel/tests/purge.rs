//! Tests of spec 023-ttl-purge: the message list (R1–R3, R7) and the
//! purge (R4–R6).

use super::{DAY_MS, HOUR_MS, MARGIN_MS, NOW, fill, own_text, pk_of, receiver, reopened, sealed};
use crate::crypto::Signature;
use crate::crypto::{PublicKey, Secret};
use crate::error::Error;
use crate::proto::payload::PayloadKind;
use crate::session::channel::purge::{Delivery, Message};
use crate::session::channel::{AckOutcome, Channel, ClientRef, MessageContent, Sender};
use crate::storage::state::items::OldKey;
use crate::storage::{LogEntry, LogRecord, StoreError};
use crate::testing::{MemoryStore, record, state_eq};

const ANN: [u8; 32] = [0x41; 32];
const BOB: [u8; 32] = [0x42; 32];
const MINUTE_MS: u64 = 60_000;
const WEEK_S: u32 = 604_800;

/// Delivers a text of `seed` at `counter`, signed at `sent_at`, pushed with
/// `received_at` and opened at `now`.
fn push(
    channel: &mut Channel,
    seed: [u8; 32],
    counter: u64,
    (sent_at, received_at, now): (u64, u64, u64),
    name: Option<&str>,
) {
    let blob = sealed(channel, seed, counter, sent_at, PayloadKind::Text, name);
    let mut server_id = [seed[0]; 16];
    server_id[8..].copy_from_slice(&counter.to_be_bytes());
    channel.decrypt(&blob, server_id, received_at, now).unwrap();
}

/// The listed row of `client_ref`.
fn own_row(channel: &Channel, client_ref: ClientRef, now: u64) -> Option<Message> {
    let rows = channel.messages(now).unwrap();
    rows.into_iter()
        .find(|row| row.client_ref == Some(client_ref))
}

/// The display times of the listed rows, in list order.
fn times(channel: &Channel, now: u64) -> Vec<u64> {
    channel
        .messages(now)
        .unwrap()
        .iter()
        .map(|row| row.received_at)
        .collect()
}

/// Spec 023, R1: a peer's message leaves the list at its display expiry,
/// before any compaction; one's own stays as failed until its `purge_at`,
/// and once delivered until one TTL after its `sent_at`.
#[test]
fn s023_t01_r01_display_expiry() {
    let (mut channel, handle, _) = receiver(60);
    // Received half a minute after it was signed: its life runs from
    // `sent_at` all the same.
    push(
        &mut channel,
        ANN,
        0,
        (NOW, NOW + 30_000, NOW + 30_000),
        None,
    );
    // Written offline at 12:00:59: `sent_at` is 12:00:00.
    let client_ref = channel.encrypt("mine", None, NOW + 59_000).unwrap();
    let commits = handle.all_commits();
    assert_eq!(channel.messages(NOW + MINUTE_MS).unwrap().len(), 2);
    let rows = channel.messages(NOW + MINUTE_MS + 1).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].sender, Sender::Own);
    assert_eq!(channel.records.len(), 3, "hidden, not compacted");

    let purge_at = NOW + 540_000;
    let pending = own_row(&channel, client_ref, NOW + 480_000).unwrap();
    assert_eq!(pending.delivery, Some(Delivery::Pending));
    assert_eq!(pending.expires_at, purge_at);
    let late = own_row(&channel, client_ref, NOW + 480_001).unwrap();
    assert_eq!(late.delivery, Some(Delivery::NotDelivered));
    assert_eq!(handle.all_commits(), commits);
    channel.expire_outbox(NOW + 480_001, &[]).unwrap();
    assert!(channel.state.outbox.is_empty());
    let failed = own_row(&channel, client_ref, purge_at).unwrap();
    assert_eq!(failed.delivery, Some(Delivery::NotDelivered));
    assert!(own_row(&channel, client_ref, purge_at + 1).is_none());

    let (mut channel, handle, _) = receiver(60);
    let client_ref = channel.encrypt("mine", None, NOW + 59_000).unwrap();
    let outcome = channel.acked(client_ref, [7; 16], NOW + 59_000, NOW + 59_000);
    assert_eq!(outcome.unwrap().outcome, AckOutcome::Delivered);
    let commits = handle.all_commits();
    let delivered = own_row(&channel, client_ref, NOW + MINUTE_MS).unwrap();
    assert_eq!(delivered.expires_at, NOW + MINUTE_MS);
    assert!(own_row(&channel, client_ref, NOW + MINUTE_MS + 1).is_none());
    assert_eq!(handle.all_commits(), commits);
}

/// Spec 023, R2: the list follows the display time, which neither a future
/// `sent_at` nor a server's `received_at` can push to an end.
#[test]
fn s023_t02_r02_order() {
    let (mut channel, _, _) = receiver(3_600);
    push(
        &mut channel,
        ANN,
        0,
        (NOW, NOW + 40_000, NOW + 40_000),
        None,
    );
    let mine = channel.encrypt("mine", None, NOW + 50_000).unwrap();
    assert_eq!(times(&channel, NOW + 50_000), [NOW + 40_000, NOW + 50_000]);
    channel
        .acked(mine, [7; 16], NOW + 55_000, NOW + 55_000)
        .unwrap();
    assert_eq!(times(&channel, NOW + 55_000), [NOW + 40_000, NOW + 55_000]);
    // Dated a TTL ahead by its signer: listed at its arrival.
    let ahead = NOW + 3_600_000;
    push(
        &mut channel,
        BOB,
        0,
        (ahead, NOW + 60_000, NOW + 60_000),
        None,
    );
    push(
        &mut channel,
        BOB,
        1,
        (NOW, NOW + 70_000, NOW + 70_000),
        None,
    );
    let rows = channel.messages(NOW + 70_000).unwrap();
    let listed: Vec<(Option<u64>, u64)> = rows.iter().map(|r| (r.sent_at, r.received_at)).collect();
    assert_eq!(listed[2], (Some(ahead), NOW + 60_000));
    assert_eq!(listed[3], (Some(NOW), NOW + 70_000));

    let (mut channel, _, _) = receiver(WEEK_S);
    // Dated six days back by the server: listed at `sent_at` minus the margin.
    let now = NOW + 1_000;
    push(&mut channel, ANN, 0, (NOW, NOW - 6 * DAY_MS, now), None);
    // Acked a day ahead: listed at the `ack`; a TTL back: at the margin.
    let ahead = channel.encrypt("ahead", None, now).unwrap();
    channel
        .acked(ahead, [7; 16], NOW + DAY_MS, now + 1)
        .unwrap();
    let back = channel.encrypt("back", None, now + 2).unwrap();
    channel
        .acked(back, [8; 16], NOW - 7 * DAY_MS, now + 3)
        .unwrap();
    let rows = channel.messages(now + 3).unwrap();
    let margin = NOW - MARGIN_MS;
    let order: Vec<(Option<ClientRef>, u64)> =
        rows.iter().map(|r| (r.client_ref, r.received_at)).collect();
    assert_eq!(
        order,
        [(None, margin), (Some(back), margin), (Some(ahead), now + 1)]
    );
    assert!(
        rows.iter()
            .all(|row| row.delivery != Some(Delivery::NotDelivered))
    );

    // A tie: one's own message, sealed before a peer's but acked after it,
    // stands after it, where the client moved it at its `ack`.
    let (mut channel, handle, _) = receiver(3_600);
    let mine = channel.encrypt("mine", None, NOW).unwrap();
    push(&mut channel, ANN, 0, (NOW, NOW - 400_000, NOW), None);
    channel.acked(mine, [7; 16], NOW - 400_000, NOW).unwrap();
    // A peer's message logged after the `ack`, at the same time, after it.
    push(&mut channel, BOB, 0, (NOW, NOW - 400_000, NOW), None);
    let rows = channel.messages(NOW).unwrap();
    let order: Vec<(Option<ClientRef>, u64)> =
        rows.iter().map(|r| (r.client_ref, r.received_at)).collect();
    assert_eq!(
        order,
        [
            (None, NOW - MARGIN_MS),
            (Some(mine), NOW - MARGIN_MS),
            (None, NOW - MARGIN_MS)
        ]
    );
    assert_eq!(rows[2].sender, Sender::Peer { pk: pk_of(BOB) });
    // The same after a reload, and after a compaction drops other records.
    assert_eq!(reopened(&handle).messages(NOW), channel.messages(NOW));
    channel
        .commit(channel.next_state(), vec![record(NOW - 10, 10)])
        .unwrap();
    assert_eq!(channel.purge_expired(NOW), Ok(1));
    assert_eq!(channel.messages(NOW).unwrap(), rows);
}

/// Spec 023, R3: the fields of each kind of row.
#[test]
fn s023_t03_r03_message_fields() {
    let (mut channel, _, _) = receiver(3_600);
    let mine = channel.encrypt("mine", Some("Me"), NOW).unwrap();
    let row = own_row(&channel, mine, NOW).unwrap();
    assert_eq!(row.sender, Sender::Own);
    assert_eq!(row.delivery, Some(Delivery::Pending));
    assert_eq!(row.server_id, None);
    assert_eq!(row.expires_at, NOW + 2 * HOUR_MS + 420_000);
    assert_eq!(row.stranger, None);
    channel.acked(mine, [7; 16], NOW, NOW).unwrap();
    let row = own_row(&channel, mine, NOW).unwrap();
    assert_eq!(row.delivery, Some(Delivery::Delivered));
    assert_eq!(row.server_id, Some([7; 16]));
    let late = channel.encrypt("late", None, NOW).unwrap();
    let after = NOW + HOUR_MS + 1;
    let outcome = channel.acked(late, [8; 16], NOW, after).unwrap();
    assert_eq!(outcome.outcome, AckOutcome::NotDelivered);
    let row = own_row(&channel, late, after).unwrap();
    assert_eq!(row.delivery, Some(Delivery::NotDelivered));
    assert_eq!(row.server_id, None);

    push(&mut channel, ANN, 0, (NOW, NOW, NOW), Some("Ann\u{202E}"));
    let rows = channel.messages(NOW).unwrap();
    let ann = rows
        .iter()
        .find(|r| r.sender == Sender::Peer { pk: pk_of(ANN) })
        .unwrap();
    let expected = MessageContent::Text {
        body: "hi".to_owned(),
        display_name: Some("Ann".to_owned()),
    };
    assert_eq!(ann.content, expected);
    assert_eq!((ann.delivery, &ann.stranger), (None, &None));

    // One's own key sealed elsewhere, and still so once it is an old key.
    let own = pk_of(*channel.state.identity_seed.expose());
    let blob = own_text(&channel, 50, NOW);
    channel.decrypt(&blob, [9; 16], NOW, NOW).unwrap();
    let elsewhere = |channel: &Channel| {
        let rows = channel.messages(NOW).unwrap();
        rows.into_iter()
            .find(|r| r.server_id == Some([9; 16]))
            .unwrap()
    };
    let row = elsewhere(&channel);
    assert_eq!(
        (row.sender, row.delivery),
        (Sender::OwnKeyElsewhere { pk: own }, None)
    );
    let mut next = channel.next_state();
    next.own_old_keys.push(OldKey {
        pk: PublicKey(own),
        retired_at: NOW,
    });
    next.identity_seed = Secret::from_bytes([0x99; 32]);
    channel.commit(next, Vec::new()).unwrap();
    assert_eq!(
        elsewhere(&channel).sender,
        Sender::OwnKeyElsewhere { pk: own }
    );

    // A sender whose record is gone is a stranger, claims included.
    push(&mut channel, BOB, 0, (NOW, NOW, NOW), Some("ALICE"));
    push(&mut channel, BOB, 1, (NOW, NOW, NOW), Some("ALICE"));
    channel.label(pk_of(ANN), "Alice", NOW).unwrap();
    let mut next = channel.next_state();
    next.peers.retain(|peer| peer.pk.0 != pk_of(BOB));
    channel.commit(next, Vec::new()).unwrap();
    let rows = channel.messages(NOW).unwrap();
    let bob = rows
        .iter()
        .find(|r| r.sender == Sender::Peer { pk: pk_of(BOB) })
        .unwrap();
    let stranger = bob.stranger.as_ref().unwrap();
    // Every row of the sender carries its 4 words, computed once.
    let rows_of_bob: Vec<&Message> = rows
        .iter()
        .filter(|r| r.sender == Sender::Peer { pk: pk_of(BOB) })
        .collect();
    assert_eq!(rows_of_bob.len(), 2);
    assert_eq!(rows_of_bob[1].stranger.as_ref(), Some(stranger));
    assert_eq!(stranger.short.len(), 4);
    assert_eq!(stranger.claims_name_of, Some(pk_of(ANN)));
    assert!(!stranger.claims_own_name);
    assert_eq!(
        stranger.short,
        channel.fingerprint(pk_of(BOB)).unwrap().short
    );
    let ann = rows
        .iter()
        .find(|r| r.sender == Sender::Peer { pk: pk_of(ANN) })
        .unwrap();
    assert_eq!(ann.stranger, None);

    // A stranger claiming one's own name; a `key_retired` is listed as such.
    let cat = [0x43; 32];
    let mut next = channel.next_state();
    next.own_display_name = Some("Me".to_owned());
    channel.commit(next, Vec::new()).unwrap();
    push(&mut channel, cat, 0, (NOW, NOW, NOW), Some("ME"));
    let retired = sealed(&channel, cat, 1, NOW, PayloadKind::KeyRetired, None);
    channel.decrypt(&retired, [0x44; 16], NOW, NOW).unwrap();
    let mut next = channel.next_state();
    next.peers.retain(|peer| peer.pk.0 != pk_of(cat));
    channel.commit(next, Vec::new()).unwrap();
    let rows = channel.messages(NOW).unwrap();
    let from_cat: Vec<&Message> = rows
        .iter()
        .filter(|r| r.sender == Sender::Peer { pk: pk_of(cat) })
        .collect();
    assert_eq!(from_cat.len(), 2);
    assert!(from_cat[0].stranger.as_ref().unwrap().claims_own_name);
    assert_eq!(from_cat[1].content, MessageContent::KeyRetired);
}

/// Spec 023, R7: the one own row equals its row of the list.
#[test]
fn s023_t07_r07_single_message() {
    let (mut channel, _, _) = receiver(3_600);
    push(&mut channel, ANN, 0, (NOW, NOW, NOW), None);
    let mine = channel.encrypt("mine", None, NOW).unwrap();
    assert_eq!(channel.message(mine, NOW), own_row(&channel, mine, NOW));
    assert!(channel.message(mine, NOW).is_some());
    channel.acked(mine, [7; 16], NOW, NOW).unwrap();
    assert_eq!(channel.message(mine, NOW), own_row(&channel, mine, NOW));
    assert!(channel.message(mine, NOW).is_some());
    assert_eq!(channel.message(ClientRef { bytes: [3; 16] }, NOW), None);
    assert_eq!(channel.message(mine, NOW + HOUR_MS + 1), None);
}

/// A kept signature that may be dropped from `purge_at` on.
fn kept_signature(purge_at: u64) -> LogRecord {
    LogRecord {
        purge_at,
        entry: LogEntry::KeptSignature {
            sent_at: purge_at,
            client_ref: [5; 16],
            signature: Signature([6; 64]),
            epoch: 0,
        },
    }
}

/// Commits `records` to `channel`.
fn plant(channel: &mut Channel, records: Vec<LogRecord>) {
    channel.commit(channel.next_state(), records).unwrap();
}

/// The `purge_at` of every record a reopened store holds.
fn stored_purge_ats(handle: &MemoryStore) -> Vec<u64> {
    reopened(handle)
        .records
        .iter()
        .map(LogRecord::purge_at)
        .collect()
}

/// Spec 023, R4: the purge drops every expired record and counts the
/// messages alone, not the kept signatures or delivery records; with nothing expired it calls no compaction.
#[test]
fn s023_t04_r04_purge_counts_messages() {
    let (mut channel, handle, faults) = receiver(3_600);
    let expired = vec![
        record(NOW, 10),
        kept_signature(NOW),
        record(NOW + 1, 10),
        kept_signature(NOW + 1),
        record(NOW + 2, 10),
        LogRecord {
            purge_at: NOW + 2,
            entry: LogEntry::NotDelivered {
                client_ref: [5; 16],
            },
        },
    ];
    plant(&mut channel, expired);
    plant(
        &mut channel,
        vec![record(NOW + 3, 10), kept_signature(NOW + 3)],
    );
    assert_eq!(channel.purge_expired(NOW + 3), Ok(3));
    assert_eq!(stored_purge_ats(&handle), [NOW + 3, NOW + 3]);
    assert_eq!(channel.records.len(), 2);
    assert_eq!(
        channel.messages(NOW + 3),
        reopened(&handle).messages(NOW + 3)
    );
    assert_eq!(channel.messages(NOW + 3).unwrap().len(), 1);
    // Nothing expired: a failing compaction is never reached.
    faults.fail_compactions(true);
    assert_eq!(channel.purge_expired(NOW + 3), Ok(0));
    let (mut empty, _, faults) = receiver(3_600);
    faults.fail_compactions(true);
    assert_eq!(empty.purge_expired(NOW), Ok(0));

    // Both compaction calls take a `now` and may commit, so they record it
    // for the truncation banner of spec 021-channel-session R1 and R25.
    let late = NOW + 2 * DAY_MS;
    for headroom in [false, true] {
        let (mut channel, handle, _) = receiver(3_600);
        let mut next = channel.next_state();
        next.truncated_at = Some(NOW);
        channel.commit(next, Vec::new()).unwrap();
        let mut channel = reopened(&handle);
        assert!(channel.status().truncated_before.is_some());
        if headroom {
            assert_eq!(channel.relieve_headroom(late), Ok(false));
        } else {
            assert_eq!(channel.purge_expired(late), Ok(0));
        }
        assert_eq!(channel.status().truncated_before, None, "{headroom}");
    }
}

/// Spec 023, R5: opening never compacts; the purge is due at a quarter of
/// the log or a day after the oldest expiry, and not within ten minutes of
/// the last attempt, failed or not, unless that attempt is in the future.
#[test]
fn s023_t05_r05_open_does_not_purge() {
    let (mut channel, handle, _) = receiver(3_600);
    plant(&mut channel, vec![record(NOW, 30_000), record(NOW, 100)]);
    drop(channel);
    let commits = handle.all_commits();
    let before = stored_purge_ats(&handle);
    let channel = reopened(&handle);
    assert_eq!(stored_purge_ats(&handle), before, "no compaction at open");
    assert_eq!(handle.all_commits(), commits);
    assert_eq!(channel.records.len(), 2);
    assert!(channel.messages(NOW + 1).unwrap().is_empty());

    // A quarter of the log: a large live record and small expired ones.
    let (mut channel, _, _) = receiver(3_600);
    plant(&mut channel, vec![record(NOW + 2 * DAY_MS, 30_000)]);
    let mut crossed = false;
    for step in 0..40 {
        plant(&mut channel, vec![record(NOW, 1_000)]);
        let expired = channel.expiry.expired_bytes(NOW + 1);
        let quarter = expired * 4 >= channel.store.log_len();
        assert_eq!(channel.purge_due(NOW + 1), quarter, "step {step}");
        crossed |= quarter;
    }
    assert!(crossed);
    // Exactly a quarter is due; nothing expired never is, the log holding
    // its header.
    let (mut channel, _, _) = receiver(3_600);
    assert!(!channel.purge_due(NOW + DAY_MS * 2));
    let header = channel.store.log_len();
    let small = record(NOW, 1_000).entry_len();
    let base = record(NOW, 0).entry_len();
    let live = usize::try_from(3 * small - header - base).unwrap();
    plant(
        &mut channel,
        vec![record(NOW + 2 * DAY_MS, live), record(NOW, 1_000)],
    );
    assert_eq!(channel.store.log_len(), 4 * small);
    assert!(
        !channel.purge_due(NOW),
        "a `purge_at` of `now` has not expired"
    );
    assert!(channel.purge_due(NOW + 1));
    let (mut channel, _, _) = receiver(3_600);
    plant(
        &mut channel,
        vec![record(NOW + 2 * DAY_MS, live + 1), record(NOW, 1_000)],
    );
    assert!(!channel.purge_due(NOW + 1));
    // A day after the oldest expiry, however little expired.
    let (mut channel, _, _) = receiver(3_600);
    plant(
        &mut channel,
        vec![record(NOW + 2 * DAY_MS, 30_000), record(NOW, 10)],
    );
    assert!(!channel.purge_due(NOW + DAY_MS));
    assert!(channel.purge_due(NOW + DAY_MS + 1));

    // A failed purge holds the next one off for ten minutes, and the
    // headroom's compaction too.
    let (mut channel, _, faults) = receiver(3_600);
    fill(&mut channel, NOW, 3_000_000);
    let t = NOW + 2 * DAY_MS;
    faults.fail_compactions(true);
    assert_eq!(channel.purge_expired(t), Err(Error::Store(StoreError::Io)));
    assert!(!channel.purge_due(t));
    assert!(!channel.purge_due(t + 599_999));
    assert_eq!(channel.relieve_headroom(t + 599_999), Ok(false));
    assert!(channel.purge_due(t + 600_000));
    // An attempt recorded later than `now` holds nothing off.
    assert!(channel.purge_due(t - DAY_MS));
    assert_eq!(
        channel.relieve_headroom(t + 600_000),
        Err(Error::Store(StoreError::Io))
    );
    assert!(!channel.purge_due(t + 1_199_999));
    assert!(channel.purge_due(t + 1_200_000));
    faults.fail_compactions(false);
    assert_eq!(channel.relieve_headroom(t + 1_200_000), Ok(true));
}

/// Spec 023, R6: a failed compaction leaves memory as it was, and the
/// store before or after it, never a mix.
#[test]
fn s023_t06_r06_failed_compaction() {
    let records = || vec![record(NOW, 10), kept_signature(NOW), record(NOW + 5, 10)];
    for poisoned in [false, true] {
        let (mut channel, handle, faults) = receiver(3_600);
        plant(&mut channel, records());
        let state = channel.state.duplicate();
        if poisoned {
            // The compaction is written, then the store fails.
            faults.poison_after(1);
        } else {
            faults.fail_compactions(true);
        }
        let result = channel.purge_expired(NOW + 1);
        assert_eq!(result, Err(Error::Store(StoreError::Io)), "{poisoned}");
        assert_eq!(channel.records.len(), 3);
        assert!(state_eq(&channel.state, &state));
        let stored = stored_purge_ats(&handle);
        let expected = if poisoned {
            vec![NOW + 5]
        } else {
            vec![NOW, NOW, NOW + 5]
        };
        assert_eq!(stored, expected, "{poisoned}");
        assert!(state_eq(&reopened(&handle).state, &state));
    }
}
