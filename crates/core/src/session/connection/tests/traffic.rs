//! Tests of spec 028 R10: a `push` routed to `decrypt`, the `LogFull`
//! stall, the stop after one's own key is used elsewhere, and the freeze
//! after another store error.

use super::{DAY, T0, channel, connected, hello, ids, ok, reconnect};
use crate::session::channel::{Channel, ClientRef, key_prefix};
use crate::session::connection::{Channels, Event, Session};
use crate::session::frames::Frame;
use crate::storage::{MAX_LOG_LEN, StoreError, Vault};
use crate::testing::{FailingStore, Faults, MemoryStore, MemoryVault};

/// The log length past which `decrypt` refuses with `LogFull` (spec
/// 021-channel-session R18).
const ROOM: u64 = MAX_LOG_LEN - 1_114_156;

/// When the records that fill a log expire.
const FILL_EXPIRES: u64 = T0 + 5_000;

/// A one-day channel of key 1 over a store that fails on demand, a handle
/// to its bytes, and its faults.
fn alice() -> (Channels, MemoryStore, Faults) {
    let faults = Faults::new();
    let mut vault = MemoryVault::new();
    let template = channel(1, DAY, T0);
    let config = template.config();
    let store = vault.create(&config.channel_id()).unwrap();
    let handle = MemoryStore::handle(&vault, *store.name());
    let failing = Box::new(FailingStore::new(store, faults.clone()));
    let (channel, _) = Channel::create(config, failing).unwrap();
    (vec![channel], handle, faults)
}

/// Another member of `channel`'s channel, with a key of its own.
fn member(channel: &Channel) -> Channel {
    let config = channel.config();
    let store = MemoryVault::new().create(&config.channel_id()).unwrap();
    Channel::create(config, store).unwrap().0
}

/// A device holding a copy of the channel behind `handle`, its key
/// included: a thief of one's key.
fn thief_of(handle: &MemoryStore) -> Channel {
    Channel::open_stored(Box::new(handle.copy())).unwrap()
}

/// The blob `sender` seals for `text` at `T0`.
fn sealed(sender: &mut Channel, text: &str) -> Vec<u8> {
    let client_ref = sender.encrypt(text, None, T0).unwrap();
    let step = sender.outbox(T0, &[], false).unwrap();
    let (_, blob) = step
        .publish
        .into_iter()
        .find(|(entry, _)| *entry == client_ref)
        .unwrap();
    blob
}

/// The `push` of `blob` to `channel_id` as server message `n`, stored at
/// `T0 + n`.
fn push(channel_id: [u8; 16], n: u8, blob: &[u8]) -> Vec<u8> {
    Frame::Push {
        channel_id,
        server_id: [n; 16],
        received_at: T0 + u64::from(n),
        blob: blob.to_vec(),
    }
    .encode()
    .unwrap()
}

/// A session over `channels` that had the `hello` at `T0`.
fn greeted(channels: &mut Channels) -> Session {
    let mut session = connected(channels, T0);
    session.on_frame(&hello(1, &[1]), channels, T0);
    session.outgoing();
    session
}

/// The client refs of the `publish`es written.
fn published(session: &mut Session) -> Vec<ClientRef> {
    session
        .outgoing()
        .iter()
        .filter_map(|frame| match Frame::decode(frame).unwrap() {
            Frame::Publish { client_ref, .. } => Some(ClientRef { bytes: client_ref }),
            _ => None,
        })
        .collect()
}

/// Whether `events` hold exactly one message, with `server_id` `[n; 16]`.
fn is_message(events: &[Event], n: u8) -> bool {
    matches!(events, [Event::Message { received, .. }] if received.server_id == [n; 16])
}

/// Spec 028, R10: a valid push → `Message`; a forged one and a consumed
/// `key_retired` (`Ok(None)`) → no event; a push before the channel's
/// `subscribe` is released → not decrypted.
#[test]
fn s028_t10_r10_push_routing() {
    let (mut channels, _, _) = alice();
    let id = ids(&channels)[0];
    let mut bob = member(&channels[0]);
    let hi = sealed(&mut bob, "hi");
    let mut carol = member(&channels[0]);
    carol.regenerate_identity(T0).unwrap();
    let retired = carol.outbox(T0, &[], false).unwrap().publish[0].1.clone();
    let mut forged = sealed(&mut bob, "again");
    *forged.last_mut().unwrap() ^= 1;

    let mut session = connected(&channels, T0);
    // Not yet subscribing: ignored, the cursor unmoved.
    let step = session.on_frame(&push(id, 1, &hi), &mut channels, T0);
    assert!(step.events.is_empty());
    assert_eq!(channels[0].cursor(), None);
    session.on_frame(&hello(1, &[1]), &mut channels, T0);
    // Awaiting `ok`: the backlog is decrypted.
    let step = session.on_frame(&push(id, 1, &hi), &mut channels, T0 + 1);
    assert!(is_message(&step.events, 1), "{:?}", step.events);
    assert_eq!(
        format!("{:?}", step.events),
        format!("[Message({})]", key_prefix(&id))
    );
    for (n, blob) in [(2, &forged), (3, &retired)] {
        let step = session.on_frame(&push(id, n, blob), &mut channels, T0 + 3);
        assert!(step.events.is_empty(), "{n}: {:?}", step.events);
        assert!(step.failed.is_empty());
    }
    assert_eq!(channels[0].cursor(), Some(T0 + 3));
}

/// Spec 028, R10: `LogFull` on the second of three backlog pushes →
/// `StorageFailed` once, the third goes to `check_own_key`, the `ok` and
/// the ticks call no `synced`, the cursor is the first push's; room
/// regained → `Reconnect` on the next tick, and the next connection
/// fetches the second and third pushes.
#[test]
fn s028_t10_r10_log_full_stall() {
    let (mut channels, _, _) = alice();
    let id = ids(&channels)[0];
    let mut bob = member(&channels[0]);
    let blobs: Vec<Vec<u8>> = ["one", "two", "three"]
        .into_iter()
        .map(|text| sealed(&mut bob, text))
        .collect();
    let mine = channels[0].encrypt("mine", None, T0).unwrap();
    channels[0].fill_log(FILL_EXPIRES, ROOM);
    let mut session = greeted(&mut channels);

    let step = session.on_frame(&push(id, 1, &blobs[0]), &mut channels, T0 + 100);
    assert!(is_message(&step.events, 1));
    let step = session.on_frame(&push(id, 2, &blobs[1]), &mut channels, T0 + 200);
    assert_eq!(step.events, [Event::StorageFailed { channel: id }]);
    assert_eq!(
        format!("{:?}", step.events[0]),
        format!("StorageFailed({})", key_prefix(&id))
    );
    let step = session.on_frame(&push(id, 3, &blobs[2]), &mut channels, T0 + 300);
    assert!(step.events.is_empty() && step.failed.is_empty());
    let step = session.on_frame(&ok(id), &mut channels, T0 + 400);
    assert_eq!(step.events, [Event::Subscribed { channel: id }]);
    // A stall with no own-key alert publishes on.
    assert_eq!(published(&mut session), [mine]);
    let mut now = T0 + 400;
    while now < FILL_EXPIRES + 1_000 {
        now += 1_000;
        assert!(session.on_tick(&mut channels, now).events.is_empty());
    }
    assert_eq!(channels[0].synced_at(), None);
    assert_eq!(channels[0].cursor(), Some(T0 + 1));
    // The `Device` compacts the stalled channel (spec 027-core-api R12).
    assert_eq!(channels[0].relieve_headroom(now), Ok(true));
    assert!(!channels[0].status().storage_full);
    // A tick that does not hand the channel over asks nothing.
    assert!(
        session
            .on_tick(&mut Vec::new(), now + 500)
            .events
            .is_empty()
    );
    assert_eq!(
        session.on_tick(&mut channels, now + 1_000).events,
        [reconnect()]
    );
    // Asked once: a close reported late gets no second one.
    assert!(
        session
            .on_tick(&mut channels, now + 1_500)
            .events
            .is_empty()
    );

    session.on_disconnect();
    session.on_connect(now + 2_000, &[]);
    session.on_frame(&hello(2, &[1]), &mut channels, now + 2_000);
    for n in [2, 3] {
        let step = session.on_frame(
            &push(id, n, &blobs[usize::from(n) - 1]),
            &mut channels,
            now + 2_100,
        );
        assert!(is_message(&step.events, n), "{n}: {:?}", step.events);
    }
}

/// Spec 028, R10: a thief's push of one's own key during a `LogFull`
/// stall stops the current key's entries while the pending `key_retired`
/// still leaves, the `ok` after it included.
#[test]
fn s028_t10_r10_own_key_stops_publishing() {
    let (mut channels, handle, _) = alice();
    let id = ids(&channels)[0];
    channels[0].regenerate_identity(T0).unwrap();
    let mut thief = thief_of(&handle);
    // The thief's counter overtakes the first entry alone (spec
    // 021-channel-session R14).
    channels[0].encrypt("overtaken", None, T0).unwrap();
    let mine = channels[0].encrypt("mine", None, T0).unwrap();
    // The thief's device is its own: sealing writes nothing of Alice's.
    let before = handle.all_commits();
    let theirs = sealed(&mut thief, "x");
    assert_eq!(handle.all_commits(), before);
    let mut bob = member(&channels[0]);
    let hi = sealed(&mut bob, "hi");
    channels[0].fill_log(FILL_EXPIRES, ROOM + 1);
    let mut session = greeted(&mut channels);

    let step = session.on_frame(&push(id, 1, &hi), &mut channels, T0 + 100);
    assert_eq!(step.events, [Event::StorageFailed { channel: id }]);
    assert!(!channels[0].status().own_key_used_elsewhere);
    let step = session.on_frame(&push(id, 2, &theirs), &mut channels, T0 + 200);
    assert!(step.events.is_empty());
    assert!(channels[0].status().own_key_used_elsewhere);
    session.on_frame(&ok(id), &mut channels, T0 + 300);
    let refs = published(&mut session);
    // The `key_retired` alone.
    assert_eq!(refs.len(), 1);
    assert_ne!(refs[0], mine);
    assert_eq!(channels[0].outbox_ref(1), Some(mine));
    // `after_send` stops it too, the `key_retired` being in flight, and
    // no `Reconnect` before a regeneration.
    let step = session.after_send(id, &mut channels, T0 + 400);
    assert!(step.events.is_empty());
    assert_eq!(published(&mut session), []);
}

/// Spec 028, R10: the `decrypt` that begins a stall and sets the own-key
/// flag stops the current key's entries; `regenerate_identity` then →
/// `Reconnect` from `after_send`, nothing queued.
#[test]
fn s028_t10_r10_stall_alert_then_regeneration() {
    let (mut channels, handle, _) = alice();
    let id = ids(&channels)[0];
    let mut thief = thief_of(&handle);
    channels[0].encrypt("first", None, T0).unwrap();
    channels[0].encrypt("second", None, T0).unwrap();
    let theirs = sealed(&mut thief, "x");
    channels[0].fill_log(FILL_EXPIRES, ROOM + 1);
    let mut session = greeted(&mut channels);

    let step = session.on_frame(&push(id, 1, &theirs), &mut channels, T0 + 100);
    assert_eq!(step.events, [Event::StorageFailed { channel: id }]);
    assert!(channels[0].status().own_key_used_elsewhere);
    session.on_frame(&ok(id), &mut channels, T0 + 200);
    assert_eq!(published(&mut session), []);
    channels[0].regenerate_identity(T0 + 300).unwrap();
    let step = session.after_send(id, &mut channels, T0 + 300);
    assert_eq!(step.events, [reconnect()]);
    assert!(session.outgoing().is_empty());
}

/// Spec 028, R10: `Io` on a push → the channel in `failed`, later pushes
/// neither decrypted nor checked, the cursor unmoved, and the `ok` calls
/// neither `synced` nor `outbox`; a `LogFull` stall whose `check_own_key`
/// fails → frozen, with no `Reconnect` once room returns.
#[test]
fn s028_t10_r10_store_error_freezes() {
    let (mut channels, handle, faults) = alice();
    let id = ids(&channels)[0];
    let mut thief = thief_of(&handle);
    let theirs = sealed(&mut thief, "x");
    channels[0].encrypt("mine", None, T0).unwrap();
    let mut bob = member(&channels[0]);
    let blobs = [sealed(&mut bob, "one"), sealed(&mut bob, "two")];
    let mut session = greeted(&mut channels);

    faults.fail_commits(true);
    let step = session.on_frame(&push(id, 1, &blobs[0]), &mut channels, T0 + 100);
    faults.fail_commits(false);
    assert!(step.events.is_empty());
    assert_eq!(step.failed, [(id, StoreError::Io)]);
    for (n, blob) in [(2, &blobs[1]), (3, &theirs)] {
        let step = session.on_frame(&push(id, n, blob), &mut channels, T0 + 200);
        assert!(step.events.is_empty() && step.failed.is_empty());
    }
    assert_eq!(channels[0].cursor(), None);
    assert!(!channels[0].status().own_key_used_elsewhere);
    let step = session.on_frame(&ok(id), &mut channels, T0 + 300);
    assert_eq!(step.events, [Event::Subscribed { channel: id }]);
    assert_eq!(channels[0].synced_at(), None);
    assert_eq!(published(&mut session), []);
    session.on_tick(&mut channels, T0 + 1_300);
    assert_eq!(channels[0].synced_at(), None);

    // A `LogFull` stall, then a failed own-key check.
    let (mut channels, handle, faults) = alice();
    let id = ids(&channels)[0];
    let mut thief = thief_of(&handle);
    let theirs = [sealed(&mut thief, "x"), sealed(&mut thief, "y")];
    let mut bob = member(&channels[0]);
    let hi = sealed(&mut bob, "hi");
    channels[0].fill_log(FILL_EXPIRES, ROOM + 1);
    let mut session = greeted(&mut channels);
    session.on_frame(&push(id, 1, &hi), &mut channels, T0 + 100);
    faults.fail_commits(true);
    let step = session.on_frame(&push(id, 2, &theirs[0]), &mut channels, T0 + 200);
    faults.fail_commits(false);
    assert_eq!(step.failed, [(id, StoreError::Io)]);
    session.on_frame(&push(id, 3, &theirs[1]), &mut channels, T0 + 300);
    assert!(!channels[0].status().own_key_used_elsewhere);
    let mut now = T0 + 300;
    while now < FILL_EXPIRES + 1_000 {
        now += 1_000;
        session.on_tick(&mut channels, now);
    }
    assert_eq!(channels[0].relieve_headroom(now), Ok(true));
    assert!(
        session
            .on_tick(&mut channels, now + 1_000)
            .events
            .is_empty()
    );
}

/// Spec 028, R10: with the own-key flag already set by an earlier push, a
/// thief's push that begins the `LogFull` stall stops the current key's
/// entries, as it would one push later.
#[test]
fn s028_t10_r10_stall_with_flag_already_set() {
    let (mut channels, handle, _) = alice();
    let id = ids(&channels)[0];
    let mut thief = thief_of(&handle);
    for text in ["one", "two", "three"] {
        channels[0].encrypt(text, None, T0).unwrap();
    }
    let theirs = [sealed(&mut thief, "x"), sealed(&mut thief, "y")];
    let mut session = greeted(&mut channels);
    session.on_frame(&push(id, 1, &theirs[0]), &mut channels, T0 + 100);
    assert!(channels[0].status().own_key_used_elsewhere);
    channels[0].fill_log(FILL_EXPIRES, ROOM + 1);

    let step = session.on_frame(&push(id, 2, &theirs[1]), &mut channels, T0 + 200);
    assert_eq!(step.events, [Event::StorageFailed { channel: id }]);
    let waiting = channels[0].outbox_ref(2).unwrap();
    session.on_frame(&ok(id), &mut channels, T0 + 300);
    assert!(!published(&mut session).contains(&waiting));
}

/// Spec 028, R10 and R9: a channel frozen before its `ok`, whose `ok`
/// finds the history truncated → `HistoryTruncated`, with no commit, no
/// `synced` and no `outbox`.
#[test]
fn s028_t10_r10_frozen_ok_records_truncation() {
    let (mut channels, handle, faults) = alice();
    let id = ids(&channels)[0];
    let at = T0 + 86_400_000 + 360_000;
    channels[0].encrypt("mine", None, at - 1_000).unwrap();
    let mut session = connected(&channels, at);
    let step = session.on_frame(&hello(1, &[1]), &mut channels, at);
    assert_eq!(step.events, []);
    session.outgoing();
    faults.fail_commits(true);
    let push = Frame::Push {
        channel_id: id,
        server_id: [1; 16],
        received_at: at,
        blob: vec![0; 8],
    };
    let step = session.on_frame(&push.encode().unwrap(), &mut channels, at + 100);
    faults.fail_commits(false);
    assert_eq!(step.failed, [(id, StoreError::Io)]);
    let commits = handle.all_commits();
    let late = at + 1_000;
    let step = session.on_frame(&ok(id), &mut channels, late);
    assert_eq!(
        step.events,
        [
            Event::HistoryTruncated {
                channel: id,
                before: late - 86_400_000,
            },
            Event::Subscribed { channel: id },
        ]
    );
    assert_eq!(handle.all_commits(), commits);
    assert_eq!(channels[0].synced_at(), None);
    assert_eq!(published(&mut session), []);
}

/// Spec 028, R14: `after_send` publishes a send of a subscribed channel
/// once, an entry in flight not again, and nothing for a channel awaiting
/// `ok` or after `on_disconnect`.
#[test]
fn s028_t14_r14_send() {
    let (mut channels, _, _) = alice();
    let id = ids(&channels)[0];
    let mut session = greeted(&mut channels);
    let early = channels[0].encrypt("early", None, T0).unwrap();
    assert!(session.after_send(id, &mut channels, T0).events.is_empty());
    assert!(
        session
            .after_send([9; 16], &mut channels, T0)
            .events
            .is_empty()
    );
    assert_eq!(published(&mut session), []);
    session.on_frame(&ok(id), &mut channels, T0 + 100);
    assert_eq!(published(&mut session), [early]);
    let sent = channels[0].encrypt("hi", None, T0 + 200).unwrap();
    session.after_send(id, &mut channels, T0 + 200);
    assert_eq!(published(&mut session), [sent]);
    session.after_send(id, &mut channels, T0 + 250);
    assert_eq!(published(&mut session), []);

    session.on_disconnect();
    channels[0].encrypt("offline", None, T0 + 300).unwrap();
    session.after_send(id, &mut channels, T0 + 300);
    assert_eq!(published(&mut session), []);
}

/// Spec 028, R10: `after_send` on a channel frozen by an `Io` push
/// publishes nothing and commits nothing.
#[test]
fn s028_t10_r10_after_send_frozen() {
    let (mut channels, handle, faults) = alice();
    let id = ids(&channels)[0];
    let mut session = greeted(&mut channels);
    session.on_frame(&ok(id), &mut channels, T0 + 500);
    session.outgoing();
    faults.fail_commits(true);
    let bad = Frame::Push {
        channel_id: id,
        server_id: [1; 16],
        received_at: T0 + 600,
        blob: vec![0; 8],
    };
    let step = session.on_frame(&bad.encode().unwrap(), &mut channels, T0 + 600);
    faults.fail_commits(false);
    assert_eq!(step.failed, [(id, StoreError::Io)]);
    channels[0].encrypt("frozen", None, T0 + 700).unwrap();
    let commits = handle.all_commits();
    let step = session.after_send(id, &mut channels, T0 + 700);
    assert!(step.events.is_empty() && step.failed.is_empty());
    assert_eq!(handle.all_commits(), commits);
    assert_eq!(published(&mut session), []);
}

/// Spec 028, R10: a stall that stops after its tick asked for a new
/// connection does not ask again.
#[test]
fn s028_t10_r10_stop_after_reconnect_asked() {
    let (mut channels, handle, _) = alice();
    let id = ids(&channels)[0];
    let mut thief = thief_of(&handle);
    let theirs = sealed(&mut thief, "x");
    let mut bob = member(&channels[0]);
    let hi = sealed(&mut bob, "hi");
    channels[0].fill_log(FILL_EXPIRES, ROOM + 1);
    let mut session = greeted(&mut channels);
    session.on_frame(&push(id, 1, &hi), &mut channels, T0 + 100);
    let mut now = T0 + 100;
    while now < FILL_EXPIRES + 1_000 {
        now += 1_000;
        session.on_tick(&mut channels, now);
    }
    channels[0].relieve_headroom(now).unwrap();
    assert_eq!(
        session.on_tick(&mut channels, now + 500).events,
        [reconnect()]
    );
    session.on_frame(&push(id, 2, &theirs), &mut channels, now + 600);
    assert!(channels[0].status().own_key_used_elsewhere);
    assert!(
        session
            .on_tick(&mut channels, now + 1_000)
            .events
            .is_empty()
    );
}

/// Spec 028, R10: once stopped, a second theft of the new key on the same
/// connection keeps the stop of the first, so a regeneration still asks
/// for a new connection.
#[test]
fn s028_t10_r10_second_theft_after_regeneration() {
    let (mut channels, handle, _) = alice();
    let id = ids(&channels)[0];
    let mut thief = thief_of(&handle);
    let theirs = sealed(&mut thief, "x");
    channels[0].fill_log(FILL_EXPIRES, ROOM + 1);
    let mut session = greeted(&mut channels);
    session.on_frame(&push(id, 1, &theirs), &mut channels, T0 + 100);
    session.on_frame(&ok(id), &mut channels, T0 + 200);
    channels[0].regenerate_identity(T0 + 300).unwrap();
    // The device is copied again, with its new key.
    let mut again = thief_of(&handle);
    again.relieve_headroom(FILL_EXPIRES + 1).unwrap();
    let client_ref = again.encrypt("y", None, FILL_EXPIRES + 1).unwrap();
    let step = again.outbox(FILL_EXPIRES + 1, &[], false).unwrap();
    let (_, blob) = step
        .publish
        .into_iter()
        .find(|(entry, _)| *entry == client_ref)
        .unwrap();
    let frame = Frame::Push {
        channel_id: id,
        server_id: [2; 16],
        received_at: T0 + 400,
        blob,
    };
    session.on_frame(&frame.encode().unwrap(), &mut channels, T0 + 400);
    let step = session.after_send(id, &mut channels, T0 + 500);
    assert_eq!(step.events, [reconnect()]);
}

/// Spec 028, R14 and R10: an `outbox` whose commit fails → nothing
/// queued, `(channel, Io)` in `failed` and the channel frozen: a later
/// push is not decrypted and `after_send` publishes nothing.
#[test]
fn s028_t14_r14_outbox_failure_freezes() {
    let (mut channels, handle, faults) = alice();
    let id = ids(&channels)[0];
    channels[0].encrypt("stale", None, T0).unwrap();
    let mut bob = member(&channels[0]);
    let hi = sealed(&mut bob, "hi");
    let late = T0 + 86_400_000 + 361_000;
    let mut session = connected(&channels, late);
    session.on_frame(&hello(1, &[1]), &mut channels, late);
    session.outgoing();

    faults.fail_commits(true);
    let step = session.on_frame(&ok(id), &mut channels, late + 100);
    faults.fail_commits(false);
    // The `synced` after the truncation, then the `outbox`.
    assert_eq!(step.failed, [(id, StoreError::Io), (id, StoreError::Io)]);
    assert!(
        !step
            .events
            .iter()
            .any(|event| matches!(event, Event::NotDelivered { .. }))
    );
    assert_eq!(published(&mut session), []);
    let commits = handle.all_commits();
    let step = session.on_frame(&push(id, 1, &hi), &mut channels, late + 200);
    assert!(step.events.is_empty() && step.failed.is_empty());
    channels[0].encrypt("after", None, late + 300).unwrap();
    let after = handle.all_commits();
    assert_eq!(after, commits + 1);
    let step = session.after_send(id, &mut channels, late + 300);
    assert!(step.events.is_empty() && step.failed.is_empty());
    assert_eq!(handle.all_commits(), after);
    assert_eq!(published(&mut session), []);
}

/// Spec 028, R10: a channel set `write_failed` → pushes dropped with no
/// call to the channel, a foreign own-key push raising no alert, nothing
/// published, no `synced` at its `ok` or on a tick, and no `Reconnect`;
/// the mark kept across `on_disconnect` and `on_connect`; once cleared, a
/// push on the same connection still not decrypted.
#[test]
fn s028_t10_r10_write_failed_mark() {
    let (mut channels, handle, _) = alice();
    let id = ids(&channels)[0];
    let mut thief = thief_of(&handle);
    let theirs = sealed(&mut thief, "x");
    let mut bob = member(&channels[0]);
    let hi = sealed(&mut bob, "hi");
    channels[0].encrypt("mine", None, T0).unwrap();
    let mut session = greeted(&mut channels);
    session.set_write_failed(&channels[0], true, false);
    let commits = handle.all_commits();

    for (n, blob) in [(1, &hi), (2, &theirs)] {
        let step = session.on_frame(&push(id, n, blob), &mut channels, T0 + 100);
        assert!(step.events.is_empty() && step.failed.is_empty());
    }
    let step = session.on_frame(&ok(id), &mut channels, T0 + 200);
    assert_eq!(step.events, [Event::Subscribed { channel: id }]);
    assert!(
        session
            .after_send(id, &mut channels, T0 + 300)
            .events
            .is_empty()
    );
    assert!(session.on_tick(&mut channels, T0 + 1_200).events.is_empty());
    assert_eq!(published(&mut session), []);
    assert_eq!(handle.all_commits(), commits);
    assert_eq!(channels[0].cursor(), None);
    assert_eq!(channels[0].synced_at(), None);
    assert!(!channels[0].status().own_key_used_elsewhere);

    // A new connection: still frozen, an empty backlog's `ok` calling no
    // `synced` either.
    session.on_disconnect();
    session.on_connect(T0 + 2_000, &[]);
    session.on_frame(&hello(2, &[1]), &mut channels, T0 + 2_000);
    session.outgoing();
    let step = session.on_frame(&ok(id), &mut channels, T0 + 2_100);
    assert_eq!(step.events, [Event::Subscribed { channel: id }]);
    assert_eq!(channels[0].synced_at(), None);
    session.on_frame(&push(id, 1, &hi), &mut channels, T0 + 2_200);
    assert_eq!(published(&mut session), []);
    assert_eq!(handle.all_commits(), commits);

    // Cleared: frozen until the connection ends, with no `Reconnect`.
    session.set_write_failed(&channels[0], false, false);
    let step = session.on_frame(&push(id, 2, &theirs), &mut channels, T0 + 2_300);
    assert!(step.events.is_empty());
    assert!(
        session
            .after_send(id, &mut channels, T0 + 2_400)
            .events
            .is_empty()
    );
    assert!(session.on_tick(&mut channels, T0 + 3_000).events.is_empty());
    assert_eq!(published(&mut session), []);
    assert_eq!(handle.all_commits(), commits);
    assert_eq!(channels[0].cursor(), None);
    assert!(!channels[0].status().own_key_used_elsewhere);

    // The next connection decrypts again.
    session.on_disconnect();
    session.on_connect(T0 + 4_000, &[]);
    session.on_frame(&hello(3, &[1]), &mut channels, T0 + 4_000);
    // Clearing a channel not marked changes nothing.
    session.set_write_failed(&channels[0], false, false);
    let step = session.on_frame(&push(id, 1, &hi), &mut channels, T0 + 4_100);
    assert!(is_message(&step.events, 1), "{:?}", step.events);
}

/// Spec 028, R10: a channel marked in a `LogFull` stall is frozen — its
/// own-key check no longer called and no `Reconnect` when room returns;
/// cleared with `storage_full` → back in the stall, no `Reconnect` while
/// the log is full, one on the first tick after room returns.
#[test]
fn s028_t10_r10_write_failed_storage_full() {
    let (mut channels, handle, _) = alice();
    let id = ids(&channels)[0];
    let mut thief = thief_of(&handle);
    let theirs = sealed(&mut thief, "x");
    let mut bob = member(&channels[0]);
    let hi = sealed(&mut bob, "hi");
    let mine = channels[0].encrypt("mine", None, T0).unwrap();
    channels[0].fill_log(FILL_EXPIRES, ROOM + 1);
    let mut session = greeted(&mut channels);
    session.on_frame(&push(id, 1, &hi), &mut channels, T0 + 100);
    assert!(channels[0].status().storage_full);
    session.set_write_failed(&channels[0], true, false);
    session.on_frame(&push(id, 2, &theirs), &mut channels, T0 + 200);
    assert!(!channels[0].status().own_key_used_elsewhere);

    session.set_write_failed(&channels[0], false, true);
    // No own-key alert: the stall begun at the clearing publishes on.
    session.on_frame(&ok(id), &mut channels, T0 + 200);
    assert_eq!(published(&mut session), [mine]);
    let mut now = T0 + 200;
    while now < FILL_EXPIRES + 1_000 {
        now += 1_000;
        assert!(session.on_tick(&mut channels, now).events.is_empty());
    }
    assert_eq!(channels[0].relieve_headroom(now), Ok(true));
    assert_eq!(
        session.on_tick(&mut channels, now + 1_000).events,
        [reconnect()]
    );

    // Marked again in the stall: no `Reconnect` once room returns.
    let (mut channels, _, _) = alice();
    channels[0].fill_log(FILL_EXPIRES, ROOM + 1);
    let mut session = greeted(&mut channels);
    session.on_frame(&push(id, 1, &hi), &mut channels, T0 + 100);
    session.set_write_failed(&channels[0], true, false);
    let mut now = T0 + 100;
    while now < FILL_EXPIRES + 1_000 {
        now += 1_000;
        session.on_tick(&mut channels, now);
    }
    assert_eq!(channels[0].relieve_headroom(now), Ok(true));
    assert!(
        session
            .on_tick(&mut channels, now + 1_000)
            .events
            .is_empty()
    );
}

/// Spec 028, R10: a mark cleared with `storage_full` while the own-key
/// flag is set begins a stopped stall: no ordinary entry of the current
/// key is published, and a regeneration → `Reconnect`.
#[test]
fn s028_t10_r10_write_failed_cleared_stopped() {
    let (mut channels, handle, _) = alice();
    let id = ids(&channels)[0];
    let mut thief = thief_of(&handle);
    let theirs = sealed(&mut thief, "x");
    let mut session = greeted(&mut channels);
    session.on_frame(&push(id, 1, &theirs), &mut channels, T0 + 100);
    assert!(channels[0].status().own_key_used_elsewhere);
    session.on_frame(&ok(id), &mut channels, T0 + 200);
    session.outgoing();
    session.set_write_failed(&channels[0], true, false);
    session.set_write_failed(&channels[0], false, true);

    let mine = channels[0].encrypt("mine", None, T0 + 300).unwrap();
    assert!(
        session
            .after_send(id, &mut channels, T0 + 300)
            .events
            .is_empty()
    );
    assert!(!published(&mut session).contains(&mine));
    channels[0].regenerate_identity(T0 + 400).unwrap();
    assert_eq!(
        session.after_send(id, &mut channels, T0 + 400).events,
        [reconnect()]
    );
}
