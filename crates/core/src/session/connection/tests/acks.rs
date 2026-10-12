//! Tests of spec 028 R11–R13 and R17: an `ack` routed to its channel, the
//! clock samples, the outcomes a channel queued, the hold on a late
//! `key_retired` copy, `Event::StatusChanged`, and the freeze after a
//! failed `acked` (R10).

use super::traffic::{alice, greeted, member, published, push, sealed, thief_of};
use super::{DAY, T0, channel, connected, hello, ids, ok, reconnect};
use crate::session::channel::ClientRef;
use crate::session::connection::{Channels, Event, Session};
use crate::session::frames::Frame;
use crate::storage::StoreError;

/// One hour, by which a clock sample is off.
const HOUR: u64 = 3_600_000;

/// A one-day channel's TTL in ms.
const DAY_MS: u64 = 86_400_000;

/// The `ack` of `client_ref` as server message `n`, stored at
/// `received_at`.
fn ack(client_ref: ClientRef, n: u8, received_at: u64) -> Vec<u8> {
    Frame::Ack {
        client_ref: client_ref.bytes,
        server_id: [n; 16],
        received_at,
    }
    .encode()
    .unwrap()
}

/// A session over `channels` whose first channel had its `ok` at `now`,
/// its `outbox` published.
fn subscribed(channels: &mut Channels, now: u64) -> Session {
    let mut session = connected(channels, now);
    session.on_frame(&hello(1, &[1]), channels, now);
    session.on_frame(&ok(ids(channels)[0]), channels, now);
    session
}

/// The `publish`es written, with their blobs.
fn publishes(session: &mut Session) -> Vec<(ClientRef, Vec<u8>)> {
    session
        .outgoing()
        .iter()
        .filter_map(|frame| match Frame::decode(frame).unwrap() {
            Frame::Publish {
                client_ref, blob, ..
            } => Some((ClientRef { bytes: client_ref }, blob)),
            _ => None,
        })
        .collect()
}

/// Spec 028, R12: an in-time `ack` → `Delivered` with its `server_id`,
/// `received_at` and `expires_at`; a late one → `NotDelivered`; a second
/// `ack` of it and an unknown `client_ref` → nothing.
#[test]
fn s028_t12_r12_ack_routing() {
    let (mut channels, _, _) = alice();
    let id = ids(&channels)[0];
    let on_time = channels[0].encrypt("on time", None, T0).unwrap();
    let late = channels[0].encrypt("late", None, T0).unwrap();
    let mut session = subscribed(&mut channels, T0);
    assert_eq!(published(&mut session), [on_time, late]);

    let step = session.on_frame(&ack(on_time, 1, T0 + 200), &mut channels, T0 + 300);
    let delivered = Event::Delivered {
        channel: id,
        client_ref: on_time,
        server_id: [1; 16],
        received_at: T0 + 200,
        expires_at: T0 + 200 + DAY_MS,
    };
    assert_eq!(step.events, [delivered]);
    assert!(step.failed.is_empty());
    assert!(format!("{:?}", step.events).starts_with("[Delivered("));
    // Stored two days after it was sealed: past every receiver's window.
    let step = session.on_frame(&ack(late, 2, T0 + 2 * DAY_MS), &mut channels, T0 + 400);
    let not_delivered = Event::NotDelivered {
        channel: id,
        client_ref: late,
        sent_at: T0,
    };
    // The live sample, two days off, raises the clock warning (R11, R13).
    let status = Event::StatusChanged { channel: id };
    assert_eq!(step.events, [not_delivered, status]);
    for frame in [
        ack(on_time, 3, T0 + 500),
        ack(ClientRef { bytes: [9; 16] }, 4, T0),
    ] {
        let step = session.on_frame(&frame, &mut channels, T0 + 500);
        assert!(step.events.is_empty() && step.failed.is_empty());
    }
    // Answered: neither is published again.
    session.on_tick(&mut channels, T0 + 1_500);
    assert_eq!(published(&mut session), []);
}

/// Spec 028, R12: the `ack` of the current `key_retired` copy stored too
/// late → `Ignored`, the copy held, not published again within its
/// minute; the next minute re-seals it and publishes the new copy.
#[test]
fn s028_t12_r12_late_retirement_held() {
    let (mut channels, _, _) = alice();
    channels[0].regenerate_identity(T0).unwrap();
    let mut session = subscribed(&mut channels, T0);
    let copy = published(&mut session);
    assert_eq!(copy.len(), 1);

    let step = session.on_frame(&ack(copy[0], 1, T0 + 2 * DAY_MS), &mut channels, T0 + 1_000);
    // No outcome: only the live sample, two days off, shows (R11, R13).
    let id = ids(&channels)[0];
    assert_eq!(step.events, [Event::StatusChanged { channel: id }]);
    assert!(channels[0].status().retirement_pending);
    let mut now = T0 + 1_000;
    while now < T0 + 59_000 {
        now += 1_000;
        session.on_tick(&mut channels, now);
        assert_eq!(published(&mut session), [], "{now}");
    }
    session.on_tick(&mut channels, T0 + 60_000);
    let next = published(&mut session);
    assert_eq!(next.len(), 1);
    assert_ne!(next[0], copy[0]);
}

/// Spec 028, R11: after a reconnect that lost an `ack`, the echo in the
/// backlog → no event, the entry published again under its `client_ref`,
/// and its `ack` → `Delivered`.
#[test]
fn s028_t11_r11_lost_ack_echo() {
    let (mut channels, _, _) = alice();
    let id = ids(&channels)[0];
    let sent = channels[0].encrypt("hi", None, T0).unwrap();
    let mut session = subscribed(&mut channels, T0);
    let [(client_ref, blob)] = publishes(&mut session).try_into().unwrap();
    assert_eq!(client_ref, sent);

    session.on_disconnect();
    session.on_connect(T0 + 1_000, &[]);
    session.on_frame(&hello(2, &[1]), &mut channels, T0 + 1_000);
    session.outgoing();
    let step = session.on_frame(&push(id, 1, &blob), &mut channels, T0 + 1_100);
    assert!(step.events.is_empty(), "{:?}", step.events);
    session.on_frame(&ok(id), &mut channels, T0 + 1_200);
    assert_eq!(published(&mut session), [sent]);
    let step = session.on_frame(&ack(sent, 1, T0 + 1), &mut channels, T0 + 1_300);
    assert!(matches!(step.events[..], [Event::Delivered { client_ref, .. }] if client_ref == sent));
}

/// Spec 028, R11: an in-time `ack` of the second entry with the first
/// still in flight → `NotDelivered` for the first in the same step, which
/// leaves the in-flight set; a thief's message of one's own key → the
/// entry it overtakes `NotDelivered`.
#[test]
fn s028_t11_r11_outcomes() {
    let (mut channels, handle, _) = alice();
    let id = ids(&channels)[0];
    let first = channels[0].encrypt("five", None, T0).unwrap();
    let second = channels[0].encrypt("six", None, T0).unwrap();
    let mut session = subscribed(&mut channels, T0);
    assert_eq!(published(&mut session), [first, second]);

    let step = session.on_frame(&ack(second, 1, T0 + 100), &mut channels, T0 + 200);
    assert!(matches!(
        step.events[..],
        [
            Event::Delivered { client_ref: d, .. },
            Event::NotDelivered { client_ref: n, sent_at: T0, .. },
        ] if d == second && n == first
    ));
    // The first left the in-flight set: its late `ack` is unknown.
    let step = session.on_frame(&ack(first, 2, T0 + 100), &mut channels, T0 + 300);
    assert!(step.events.is_empty());

    let mut thief = thief_of(&handle);
    let mut overtaken = Vec::new();
    for text in ["a", "b", "c"] {
        overtaken.push(channels[0].encrypt(text, None, T0 + 400).unwrap());
    }
    session.after_send(id, &mut channels, T0 + 400);
    session.outgoing();
    // The thief's counters 1–3 overtake the entries of counters 3 and up
    // to its own: one is overtaken here.
    let theirs = sealed(&mut thief, "x");
    let step = session.on_frame(&push(id, 3, &theirs), &mut channels, T0 + 500);
    let removed: Vec<ClientRef> = step
        .events
        .iter()
        .filter_map(|event| match event {
            Event::NotDelivered { client_ref, .. } => Some(*client_ref),
            _ => None,
        })
        .collect();
    assert!(!removed.is_empty(), "{:?}", step.events);
    assert!(removed.iter().all(|removed| overtaken.contains(removed)));
    assert!(step.events.contains(&Event::StatusChanged { channel: id }));
}

/// Spec 028, R11: every push is a backlog sample; an `ack` within
/// 5 000 ms of its publish is a live one; an `ack` 40 s after its publish
/// in a 60-second channel, and any `ack` once R9's gap tripped, are
/// backlog samples.
#[test]
fn s028_t11_r11_clock_samples() {
    // A push stored an hour in the device's future sets the warning, as
    // a backlog sample may; the warning shows (R13).
    let (mut channels, _, _) = alice();
    let id = ids(&channels)[0];
    let mut session = greeted(&mut channels);
    let junk = Frame::Push {
        channel_id: id,
        server_id: [1; 16],
        received_at: T0 + HOUR,
        blob: vec![0; 8],
    };
    let step = session.on_frame(&junk.encode().unwrap(), &mut channels, T0 + 100);
    assert!(channels[0].status().clock_off);
    assert_eq!(step.events, [Event::StatusChanged { channel: id }]);

    // A live `ack` an hour behind the device sets it.
    let (mut channels, _, _) = alice();
    let sent = channels[0].encrypt("hi", None, T0).unwrap();
    let mut session = subscribed(&mut channels, T0);
    session.outgoing();
    let step = session.on_frame(&ack(sent, 1, T0 + 5_000 - HOUR), &mut channels, T0 + 5_000);
    assert!(channels[0].status().clock_off);
    assert!(step.events.contains(&Event::StatusChanged {
        channel: ids(&channels)[0]
    }));

    // Read after a suspension that trips the gap: not live.
    let (mut channels, _, _) = alice();
    let sent = channels[0].encrypt("hi", None, T0).unwrap();
    let mut session = subscribed(&mut channels, T0);
    session.outgoing();
    let step = session.on_frame(&ack(sent, 1, T0), &mut channels, T0 + HOUR);
    assert!(step.events.contains(&reconnect()));
    assert!(!channels[0].status().clock_off);
    // After the gap, an `ack` within 5 000 ms of its publish is not live
    // either.
    let later = channels[0].encrypt("later", None, T0 + HOUR).unwrap();
    session.after_send(ids(&channels)[0], &mut channels, T0 + HOUR);
    assert_eq!(published(&mut session), [later]);
    session.on_frame(&ack(later, 2, T0), &mut channels, T0 + HOUR + 1_000);
    assert!(!channels[0].status().clock_off);

    // A 60-second channel whose `ack` comes 40 s late, an off of 40 s past
    // its 30 s margin: a backlog sample, no warning.
    let mut channels = vec![channel(2, 60, T0)];
    let sent = channels[0].encrypt("hi", None, T0).unwrap();
    let mut session = subscribed(&mut channels, T0);
    session.outgoing();
    for at in (1..40).map(|second| T0 + second * 1_000) {
        session.on_tick(&mut channels, at);
    }
    session.on_frame(&ack(sent, 1, T0), &mut channels, T0 + 40_000);
    assert!(!channels[0].status().clock_off);
}

/// Spec 028, R13: a stale push of one's own key that raises the alert →
/// `StatusChanged` alone; an ordinary message of a known peer with its
/// name unchanged → none; a stranger's `key_retired` that removes its
/// peer → `StatusChanged`; an `ack` that delivers the retirement →
/// `StatusChanged`; a send that changes one's own name → `StatusChanged`.
#[test]
fn s028_t13_r13_status_event() {
    let (mut channels, handle, _) = alice();
    let id = ids(&channels)[0];
    // Dated a TTL and 420 000 ms ahead: stale, yet within reach of the
    // own-key check (spec 021-channel-session R14).
    let mut thief = thief_of(&handle);
    thief.encrypt("x", None, T0 + DAY_MS + 420_000).unwrap();
    let step = thief.outbox(T0 + DAY_MS + 420_000, &[], false).unwrap();
    let theirs = step.publish[0].1.clone();
    // Bob's messages, stored, so that his retirement leaves after them.
    let mut bob = member(&channels[0]);
    let refs = ["one", "two"].map(|text| bob.encrypt(text, None, T0).unwrap());
    let [(_, first), (_, second)]: [_; 2] = bob
        .outbox(T0, &[], false)
        .unwrap()
        .publish
        .try_into()
        .unwrap();
    for (n, client_ref) in (1..).zip(refs) {
        bob.acked(client_ref, [n; 16], T0, T0).unwrap();
    }
    bob.regenerate_identity(T0).unwrap();
    let retired = bob.outbox(T0, &[], false).unwrap().publish[0].1.clone();
    let mut session = subscribed(&mut channels, T0);
    let status = Event::StatusChanged { channel: id };

    let step = session.on_frame(&push(id, 1, &theirs), &mut channels, T0 + 100);
    assert!(channels[0].status().own_key_used_elsewhere);
    assert_eq!(step.events, [status]);

    let (mut channels, _, _) = alice();
    let mut session = subscribed(&mut channels, T0);
    let step = session.on_frame(&push(id, 1, &first), &mut channels, T0 + 100);
    assert!(step.events.contains(&Event::StatusChanged { channel: id }));
    let step = session.on_frame(&push(id, 2, &second), &mut channels, T0 + 200);
    assert!(
        matches!(step.events[..], [Event::Message { .. }]),
        "{:?}",
        step.events
    );
    let step = session.on_frame(&push(id, 3, &retired), &mut channels, T0 + 300);
    assert_eq!(step.events, [Event::StatusChanged { channel: id }]);

    // One's own retirement delivered.
    channels[0].regenerate_identity(T0 + 400).unwrap();
    session.after_send(id, &mut channels, T0 + 400);
    let [copy] = published(&mut session).try_into().unwrap();
    let step = session.on_frame(&ack(copy, 4, T0 + 400), &mut channels, T0 + 500);
    assert!(!channels[0].status().retirement_pending);
    assert_eq!(step.events, [Event::StatusChanged { channel: id }]);

    // One's own name, sent for the first time.
    channels[0]
        .encrypt("hello", Some("Alice"), T0 + 600)
        .unwrap();
    let step = session.after_send(id, &mut channels, T0 + 600);
    assert_eq!(step.events, [Event::StatusChanged { channel: id }]);
    channels[0]
        .encrypt("again", Some("Alice"), T0 + 700)
        .unwrap();
    assert!(
        session
            .after_send(id, &mut channels, T0 + 700)
            .events
            .is_empty()
    );
}

/// Spec 028, R10: an `acked` whose commit fails → the channel in `failed`
/// and frozen: a later push neither decrypted nor checked, nothing
/// published, and the `ack` of a frozen channel dropped, its entry
/// published again on the next connection.
#[test]
fn s028_t10_r10_acked_failure_freezes() {
    let (mut channels, handle, faults) = alice();
    let id = ids(&channels)[0];
    let first = channels[0].encrypt("one", None, T0).unwrap();
    let second = channels[0].encrypt("two", None, T0).unwrap();
    let mut bob = member(&channels[0]);
    let hi = sealed(&mut bob, "hi");
    let mut session = subscribed(&mut channels, T0);
    assert_eq!(published(&mut session), [first, second]);

    faults.fail_commits(true);
    let step = session.on_frame(&ack(first, 1, T0 + 100), &mut channels, T0 + 200);
    faults.fail_commits(false);
    assert_eq!(step.failed, [(id, StoreError::Io)]);
    assert!(step.events.is_empty());
    channels[0].encrypt("three", None, T0 + 200).unwrap();
    let commits = handle.all_commits();
    let step = session.on_frame(&ack(second, 2, T0 + 100), &mut channels, T0 + 300);
    assert!(step.events.is_empty() && step.failed.is_empty());
    let step = session.on_frame(&push(id, 3, &hi), &mut channels, T0 + 400);
    assert!(step.events.is_empty());
    session.after_send(id, &mut channels, T0 + 500);
    session.on_tick(&mut channels, T0 + 1_000);
    assert_eq!(published(&mut session), []);
    assert_eq!(handle.all_commits(), commits);
    assert_eq!(channels[0].cursor(), None);

    session.on_disconnect();
    session.on_connect(T0 + 2_000, &[]);
    session.on_frame(&hello(2, &[1]), &mut channels, T0 + 2_000);
    session.outgoing();
    session.on_frame(&ok(id), &mut channels, T0 + 2_100);
    let again = published(&mut session);
    assert!(again.contains(&first) && again.contains(&second));
}

/// Spec 028, R17: `outgoing` returns the queued frames in order and
/// empties the queue.
#[test]
fn s028_t17_r17_outgoing_drains() {
    let mut channels: Channels = vec![channel(1, DAY, T0)];
    let first = channels[0].encrypt("one", None, T0).unwrap();
    let second = channels[0].encrypt("two", None, T0).unwrap();
    let mut session = subscribed(&mut channels, T0);
    let frames = session.outgoing();
    let kinds: Vec<String> = frames
        .iter()
        .map(|frame| match Frame::decode(frame).unwrap() {
            Frame::Subscribe { .. } => "subscribe".to_owned(),
            Frame::Publish { client_ref, .. } => format!("{:?}", ClientRef { bytes: client_ref }),
            _ => "other".to_owned(),
        })
        .collect();
    assert_eq!(
        kinds,
        [
            "subscribe".to_owned(),
            format!("{first:?}"),
            format!("{second:?}")
        ]
    );
    assert!(session.outgoing().is_empty());
}
