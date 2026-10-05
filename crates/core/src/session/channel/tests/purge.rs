//! Tests of spec 023-ttl-purge: the message list (R1–R3, R7).

use super::{NOW, own_text, pk_of, receiver, sealed};
use crate::crypto::{PublicKey, Secret};
use crate::proto::envelope::EXPIRY_MARGIN_MS;
use crate::proto::payload::PayloadKind;
use crate::session::channel::purge::{Delivery, Message};
use crate::session::channel::{AckOutcome, Channel, ClientRef, MessageContent, Sender};
use crate::storage::state::items::OldKey;
use crate::testing::MemoryStore;

const ANN: [u8; 32] = [0x41; 32];
const BOB: [u8; 32] = [0x42; 32];
const MINUTE_MS: u64 = 60_000;
const DAY_MS: u64 = 86_400_000;
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

/// Asserts that reading the list committed nothing.
fn no_commit(handle: &MemoryStore, commits: u32) {
    assert_eq!(handle.all_commits(), commits);
}

/// Spec 023, R1: a peer's message leaves the list at its display expiry,
/// before any compaction; one's own stays as failed until its `purge_at`,
/// and once delivered until one TTL after its `sent_at`.
#[test]
fn s023_t01_r01_display_expiry() {
    let (mut channel, handle, _) = receiver(60);
    push(&mut channel, ANN, 0, (NOW, NOW, NOW), None);
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
    no_commit(&handle, commits);
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
    no_commit(&handle, commits);
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
    let margin = NOW - EXPIRY_MARGIN_MS;
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
    assert_eq!(row.expires_at, channel.own_purge_at(NOW));
    assert_eq!(row.stranger, None);
    channel.acked(mine, [7; 16], NOW, NOW).unwrap();
    let row = own_row(&channel, mine, NOW).unwrap();
    assert_eq!(row.delivery, Some(Delivery::Delivered));
    assert_eq!(row.server_id, Some([7; 16]));
    let late = channel.encrypt("late", None, NOW).unwrap();
    let after = NOW + 3_600_001;
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
    assert_eq!(channel.message(ClientRef { bytes: [3; 16] }, NOW), None);
    assert_eq!(channel.message(mine, NOW + 3_600_001), None);
}
