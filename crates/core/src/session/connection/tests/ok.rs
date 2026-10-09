//! Tests of spec 028 R9: what an `ok` and the ticks after it call, the
//! silence before an `ok`, and the 5 000 ms gap between calls.

use super::{DAY, T0, channel, connected, hello, ids, ok, reconnect};
use crate::session::channel::Channel;
use crate::session::connection::{Channels, Event, Session};
use crate::session::frames::Frame;
use crate::storage::{StoreError, Vault};
use crate::testing::{FailingStore, Faults, MemoryVault};

/// A minute-long channel.
const MINUTE: u32 = 60;

/// A well-formed `push` of `channel_id` at `received_at`, whose blob no
/// channel opens.
fn push(channel_id: [u8; 16], received_at: u64) -> Vec<u8> {
    Frame::Push {
        channel_id,
        server_id: [1; 16],
        received_at,
        blob: vec![0; 8],
    }
    .encode()
    .unwrap()
}

/// Ticks every 1 000 ms after `from` up to `to`, gathering the events.
fn ticks(session: &mut Session, channels: &mut Channels, from: u64, to: u64) -> Vec<Event> {
    let mut events = Vec::new();
    let mut now = from + 1_000;
    while now <= to {
        events.extend(session.on_tick(channels, now).events);
        now += 1_000;
    }
    events
}

/// A session over `channels` whose first channel had its `ok` at `now`.
fn subscribed(channels: &mut Channels, now: u64) -> Session {
    let mut session = connected(channels, now);
    session.on_frame(&hello(1, &[1]), channels, now);
    session.on_frame(&ok(ids(channels)[0]), channels, now);
    session.outgoing();
    session
}

/// The client refs of the `publish`es written.
fn published(session: &mut Session) -> Vec<[u8; 16]> {
    session
        .outgoing()
        .iter()
        .filter_map(|frame| match Frame::decode(frame).unwrap() {
            Frame::Publish { client_ref, .. } => Some(client_ref),
            _ => None,
        })
        .collect()
}

/// Spec 028, R9: `ok` → `Subscribed`, `synced` called and the `outbox`
/// published once on the connection; the ticks of a subscribed channel
/// call `synced`; a stale entry found at the `ok` → `NotDelivered`.
#[test]
fn s028_t09_r09_ok_syncs_and_publishes() {
    let mut channels = vec![channel(1, DAY, T0)];
    let id = ids(&channels)[0];
    let sent = channels[0].encrypt("hi", None, T0).unwrap();
    let mut session = connected(&channels, T0);
    session.on_frame(&hello(1, &[1]), &mut channels, T0);
    session.outgoing();
    let step = session.on_frame(&ok(id), &mut channels, T0 + 500);
    assert_eq!(step.events, [Event::Subscribed { channel: id }]);
    assert!(step.failed.is_empty());
    assert_eq!(channels[0].synced_at(), Some(T0 + 500));
    assert_eq!(published(&mut session), [sent.bytes]);
    // The ticks sync it.
    for at in [T0 + 1_500, T0 + 2_500] {
        assert!(session.on_tick(&mut channels, at).events.is_empty());
        assert_eq!(channels[0].synced_at(), Some(at));
    }
    // A new connection publishes it again after its `ok`.
    session.on_disconnect();
    session.on_connect(T0 + 3_000, &[]);
    session.on_frame(&hello(2, &[1]), &mut channels, T0 + 3_000);
    session.outgoing();
    session.on_frame(&ok(id), &mut channels, T0 + 3_100);
    assert_eq!(published(&mut session), [sent.bytes]);

    // An entry sealed in a one-minute channel and stale at the `ok`.
    let mut channels = vec![channel(2, MINUTE, T0)];
    let id = ids(&channels)[0];
    let stale = channels[0].encrypt("hi", None, T0).unwrap();
    let later = T0 + 500_000;
    let mut session = connected(&channels, later);
    session.on_frame(&hello(1, &[1]), &mut channels, later);
    let step = session.on_frame(&ok(id), &mut channels, later);
    // The truncation was found at the `hello` (R8), and the `ok` syncs.
    assert_eq!(channels[0].synced_at(), Some(later));
    assert_eq!(
        step.events,
        [
            Event::Subscribed { channel: id },
            Event::NotDelivered {
                channel: id,
                client_ref: stale,
                sent_at: T0,
            },
        ]
    );
}

/// A channel of `ttl_seconds` over a store that fails on demand.
fn failing_channel(byte: u8, ttl_seconds: u32) -> (Channels, Faults) {
    let faults = Faults::new();
    let mut vault = MemoryVault::new();
    let template = channel(byte, ttl_seconds, T0);
    let config = template.config();
    let store = vault.create(&config.channel_id()).unwrap();
    let failing = Box::new(FailingStore::new(store, faults.clone()));
    let (channel, _) = Channel::create(config, failing).unwrap();
    (vec![channel], faults)
}

/// Spec 028, R9: a store failure of `synced` at the `ok` goes to `failed`
/// and the `outbox` still leaves; one of `outbox` goes to `failed` with
/// nothing published.
#[test]
fn s028_t09_r09_ok_store_failure_reported() {
    // `synced` alone fails: its first commit is due, the `outbox` commits
    // nothing.
    let (mut channels, faults) = failing_channel(3, DAY);
    let id = ids(&channels)[0];
    let sent = channels[0].encrypt("hi", None, T0).unwrap();
    let mut session = connected(&channels, T0);
    session.on_frame(&hello(1, &[1]), &mut channels, T0);
    session.outgoing();
    faults.fail_commits(true);
    let step = session.on_frame(&ok(id), &mut channels, T0 + 100);
    assert_eq!(step.failed, [(id, StoreError::Io)]);
    assert_eq!(published(&mut session), [sent.bytes]);
    // And on a tick.
    let step = session.on_tick(&mut channels, T0 + 1_100);
    assert_eq!(step.failed, [(id, StoreError::Io)]);

    // `outbox` alone fails: a stale entry to remove beside a fresh one, and
    // a `synced_at` committed too recently to commit again.
    let (mut channels, faults) = failing_channel(4, MINUTE);
    let id = ids(&channels)[0];
    let later = T0 + 500_000;
    channels[0].encrypt("old", None, T0).unwrap();
    channels[0].encrypt("new", None, later - 1_000).unwrap();
    channels[0].synced(later - 500).unwrap();
    let mut session = connected(&channels, later);
    session.on_frame(&hello(1, &[1]), &mut channels, later);
    session.outgoing();
    faults.fail_commits(true);
    let step = session.on_frame(&ok(id), &mut channels, later);
    assert_eq!(step.failed, [(id, StoreError::Io)]);
    assert!(session.outgoing().is_empty());
}

/// Spec 028, R9: with a channel awaiting `ok`, 60 000 ms with no frame →
/// `Reconnect`, and any frame keeps the connection alive; a last frame
/// later than `now` counts as long past.
#[test]
fn s028_t09_r09_silence_before_ok() {
    let mut channels = vec![channel(1, DAY, T0), channel(2, DAY, T0)];
    let [first, second] = [ids(&channels)[0], ids(&channels)[1]];
    let mut session = connected(&channels, T0);
    session.on_frame(&hello(1, &[1]), &mut channels, T0);
    assert!(ticks(&mut session, &mut channels, T0, T0 + 60_000).is_empty());
    let step = session.on_tick(&mut channels, T0 + 60_001);
    assert_eq!(step.events, [reconnect()]);

    // The first channel's backlog arrives for 90 s while the second awaits
    // its `ok` too: no `Reconnect`.
    let mut session = connected(&channels, T0);
    session.on_frame(&hello(1, &[1]), &mut channels, T0);
    let mut now = T0;
    while now < T0 + 90_000 {
        now += 1_000;
        let step = session.on_frame(&push(first, T0), &mut channels, now);
        assert!(step.events.is_empty());
        assert!(session.on_tick(&mut channels, now).events.is_empty());
    }
    let step = session.on_frame(&ok(second), &mut channels, now);
    assert_eq!(step.events, [Event::Subscribed { channel: second }]);

    // A frame recorded after `now`: the clock was set back. The first tick
    // also trips the gap between calls (R9); the second, later than that
    // tick, only the silence.
    let mut session = connected(&channels, T0);
    session.on_frame(&hello(1, &[1]), &mut channels, T0);
    session.on_frame(&push([0xee; 16], T0), &mut channels, T0 + 10);
    let step = session.on_tick(&mut channels, T0);
    assert_eq!(step.events, [reconnect()]);
    let step = session.on_tick(&mut channels, T0 + 5);
    assert_eq!(step.events, [reconnect()]);
}

/// Spec 028, R9: a call more than 5 000 ms after the previous one, with a
/// channel subscribed or awaiting `ok`, stops `synced` on the connection
/// with one `Reconnect`, the frame still processed; a new connection syncs
/// again.
#[test]
fn s028_t09_r09_gap_between_calls() {
    // 5 000 ms → `synced`; 5 001 ms → `Reconnect`, and no `synced` after.
    let mut channels = vec![channel(1, DAY, T0)];
    let mut session = subscribed(&mut channels, T0);
    assert!(session.on_tick(&mut channels, T0 + 5_000).events.is_empty());
    assert_eq!(channels[0].synced_at(), Some(T0 + 5_000));
    let step = session.on_tick(&mut channels, T0 + 10_001);
    assert_eq!(step.events, [reconnect()]);
    assert!(
        session
            .on_tick(&mut channels, T0 + 11_000)
            .events
            .is_empty()
    );
    assert_eq!(channels[0].synced_at(), Some(T0 + 5_000));
    // A second gap on the stopped connection: no second `Reconnect`.
    assert!(
        session
            .on_tick(&mut channels, T0 + 20_000)
            .events
            .is_empty()
    );

    // A one-minute channel subscribed, then a tick two TTLs later: no
    // `synced`, `Reconnect`, and the next connection finds the truncation.
    let mut channels = vec![channel(2, MINUTE, T0)];
    let id = ids(&channels)[0];
    let mut session = subscribed(&mut channels, T0);
    let later = T0 + 120_000;
    let step = session.on_tick(&mut channels, later);
    assert_eq!(step.events, [reconnect()]);
    assert_eq!(channels[0].synced_at(), Some(T0));
    session.on_disconnect();
    session.on_connect(later, &[]);
    let step = session.on_frame(&hello(2, &[1]), &mut channels, later);
    let before = later - 60_000;
    assert_eq!(
        step.events,
        [Event::HistoryTruncated {
            channel: id,
            before
        }]
    );

    // The same gap seen first by a `push` frame, then a tick.
    let mut channels = vec![channel(3, MINUTE, T0)];
    let id = ids(&channels)[0];
    let mut session = subscribed(&mut channels, T0);
    let step = session.on_frame(&push(id, later), &mut channels, later);
    assert_eq!(step.events, [reconnect()]);
    assert!(
        session
            .on_tick(&mut channels, later + 1_000)
            .events
            .is_empty()
    );
    assert_eq!(channels[0].synced_at(), Some(T0));

    // `on_connect` sets the reference: 60 s after the last tick, a tick
    // 500 ms later, then `hello` and `ok` → `synced`, no `Reconnect`.
    let mut channels = vec![channel(4, DAY, T0)];
    let id = ids(&channels)[0];
    let mut session = subscribed(&mut channels, T0);
    session.on_disconnect();
    session.on_connect(T0 + 60_000, &[]);
    assert!(
        session
            .on_tick(&mut channels, T0 + 60_500)
            .events
            .is_empty()
    );
    session.on_frame(&hello(2, &[1]), &mut channels, T0 + 61_000);
    let step = session.on_frame(&ok(id), &mut channels, T0 + 61_000);
    assert_eq!(step.events, [Event::Subscribed { channel: id }]);
    assert_eq!(channels[0].synced_at(), Some(T0 + 61_000));

    // A suspension between `subscribe` and `ok`, seen first by a push
    // frame: `Reconnect`, and the `ok` after it, on the same connection,
    // marks the channel subscribed with no `synced`.
    let mut channels = vec![channel(5, DAY, T0)];
    let id = ids(&channels)[0];
    let mut session = connected(&channels, T0);
    session.on_frame(&hello(1, &[1]), &mut channels, T0);
    let step = session.on_frame(&push(id, T0), &mut channels, T0 + 5_001);
    assert_eq!(step.events, [reconnect()]);
    let step = session.on_frame(&ok(id), &mut channels, T0 + 5_100);
    assert_eq!(step.events, [Event::Subscribed { channel: id }]);
    assert_eq!(channels[0].synced_at(), None);

    // The previous call later than `now`: the clock was set back.
    let mut channels = vec![channel(6, DAY, T0)];
    let mut session = subscribed(&mut channels, T0);
    let step = session.on_tick(&mut channels, T0 - 1);
    assert_eq!(step.events, [reconnect()]);
    assert_eq!(channels[0].synced_at(), Some(T0));

    // With no channel subscribed or awaiting `ok`, a gap is no `Reconnect`.
    let mut channels = vec![channel(7, DAY, T0)];
    let mut session = connected(&channels, T0);
    assert!(
        session
            .on_tick(&mut channels, T0 + 20_000)
            .events
            .is_empty()
    );
}
