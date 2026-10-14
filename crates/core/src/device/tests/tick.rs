//! Tests of the connections, the tick and `flush` (spec 027-core-api R11,
//! R12, R24, and R14 for the sessions and the probes).

use super::dispatch::{PEER, id, opened, with_peer};
use super::{Fixture, NOW, config};
use crate::Error;
use crate::device::Device;
use crate::session::connection::Event;
use crate::session::frames::Frame;
use crate::storage::{Store, StoreError};
use crate::testing::{MemoryServer, record, settings};

const HOST: &str = "example.org";
const MINUTE: u64 = 60_000;
const TEN_MINUTES: u64 = 600_000;

/// Connects every plan of `device` to `server` and exchanges frames until
/// both are quiet, at `now`; returns the events.
fn pump(device: &mut Device, server: &mut MemoryServer, now: u64) -> Vec<Event> {
    let mut events = Vec::new();
    for _ in 0..50 {
        let mut moved = false;
        for plan in device.connections() {
            for frame in device.outgoing(plan.id) {
                server.receive(plan.id, &frame, now);
                moved = true;
            }
            for frame in server.read(plan.id, 100) {
                events.extend(device.on_frame(plan.id, &frame, now));
                moved = true;
            }
        }
        if !moved {
            break;
        }
    }
    events
}

/// Opens a socket for every plan of `device`.
fn connect_all(device: &mut Device, server: &mut MemoryServer, now: u64) {
    for plan in device.connections() {
        server.connect(plan.id, now);
        device.on_connect(plan.id, now);
    }
}

/// Ticks every second from `from` to `to`, pumping frames, and returns the
/// events.
fn run(device: &mut Device, server: &mut MemoryServer, from: u64, to: u64) -> Vec<Event> {
    let mut events = Vec::new();
    let mut now = from;
    while now <= to {
        events.extend(device.on_tick(now));
        events.extend(pump(device, server, now));
        now += 1_000;
    }
    events
}

/// Whether `events` holds a `Subscribed` for `channel`.
fn subscribed(events: &[Event], channel: [u8; 16]) -> bool {
    events.contains(&Event::Subscribed { channel })
}

/// A device with saved settings and the channels of keys `1..=n`.
fn with_channels(n: u8) -> (Fixture, Device) {
    let fixture = Fixture::new();
    fixture.save_settings(&settings("wss://example.org", 30, None));
    for k in 1..=n {
        fixture.plant_channel(k, Vec::new());
    }
    let device = fixture.open().unwrap();
    (fixture, device)
}

/// Spec 027, R11: frames reach the right session; an `id` not in the plan
/// gets no event and no frame.
#[test]
fn s027_t11_r11_routing() {
    let (_fixture, mut device) = with_channels(1);
    let mut server = MemoryServer::new(&[HOST]);
    let plan = device.connections()[0].id;
    let unknown = plan + 100;
    device.on_connect(unknown, NOW);
    assert!(device.outgoing(unknown).is_empty());
    let hello = Frame::Hello {
        server_nonce: [9; 32],
        proto_versions: vec![1],
    }
    .encode()
    .unwrap();
    assert!(device.on_frame(unknown, &hello, NOW).is_empty());
    device.on_disconnect(unknown);

    connect_all(&mut device, &mut server, NOW);
    let events = run(&mut device, &mut server, NOW, NOW + 5_000);
    assert!(subscribed(&events, config(1).channel_id()));
}

/// Spec 027, R11: a channel the server refuses with `bad_auth` is not
/// subscribed on the next connection of the same plan, and a plan whose
/// channels were all refused leaves the plan.
#[test]
fn s027_t11_r11_refused_channels() {
    let (_fixture, mut device) = with_channels(1);
    // A server configured for another host refuses every signature.
    let mut server = MemoryServer::new(&["other.example.org"]);
    let plan = device.connections()[0].id;
    connect_all(&mut device, &mut server, NOW);
    let events = run(&mut device, &mut server, NOW, NOW + 3_000);
    let channel = config(1).channel_id();
    assert!(events.contains(&Event::SubscribeRefused { channel }));
    assert!(device.connections().is_empty());
    device.on_disconnect(plan);
    server.disconnect(plan);
    server.connect(plan, NOW + 4_000);
    device.on_connect(plan, NOW + 4_000);
    pump(&mut device, &mut server, NOW + 4_000);
    run(&mut device, &mut server, NOW + 4_000, NOW + 8_000);
    assert!(device.outgoing(plan).is_empty());
}

/// Spec 027, R12: 16 channels ticked every second are all subscribed.
#[test]
fn s027_t12_r12_sixteen_channels_subscribe() {
    let (_fixture, mut device) = with_channels(16);
    let mut server = MemoryServer::new(&[HOST]);
    assert_eq!(device.connections().len(), 1);
    connect_all(&mut device, &mut server, NOW);
    let events = run(&mut device, &mut server, NOW, NOW + 30_000);
    for k in 1..=16 {
        assert!(subscribed(&events, config(k).channel_id()), "{k}");
    }
}

/// Spec 027, R12: a stale entry of a channel with no connected session
/// leaves its `outbox` as `NotDelivered` from `on_tick`.
#[test]
fn s027_t12_r12_stale_entry_without_a_connection() {
    let (_fixture, mut device) = opened();
    let id = id();
    let sent = device.send(id, "hello", None, NOW).unwrap();
    device.on_tick(NOW + 1_000);
    // One TTL and the margin past its minute (spec 021-channel-session R22).
    let late = NOW + 3_600_000 + 7 * MINUTE;
    let events = device.on_tick(late);
    assert!(events.contains(&Event::NotDelivered {
        channel: id,
        client_ref: sent.client_ref,
        sent_at: sent.message.sent_at.unwrap(),
    }));
    assert!(
        !device
            .on_tick(late + 1_000)
            .iter()
            .any(|event| matches!(event, Event::NotDelivered { .. }))
    );
}

/// Spec 027, R12, R14: a channel with no connection reports
/// `StatusChanged` from the first tick, its peers flag starting set, and
/// none from the second; a successful `mute` reports it from the next.
#[test]
fn s027_t12_r12_status_without_a_connection() {
    let (_fixture, mut device) = opened();
    let id = id();
    assert!(
        device
            .on_tick(NOW)
            .contains(&Event::StatusChanged { channel: id })
    );
    assert!(device.on_tick(NOW + 1_000).is_empty());
    device.mute(id, PEER, true).unwrap();
    assert_eq!(
        device.on_tick(NOW + 2_000),
        [Event::StatusChanged { channel: id }]
    );
}

/// Spec 027, R12: one compaction a tick: two channels due for a purge are
/// purged on two ticks.
#[test]
fn s027_t12_r12_one_compaction_a_tick() {
    let fixture = Fixture::new();
    fixture.save_settings(&settings("wss://example.org", 30, None));
    let a = fixture.plant_channel(1, vec![record(NOW + 1_000, 1_000)]);
    let b = fixture.plant_channel(2, vec![record(NOW + 1_000, 1_000)]);
    let mut device = fixture.open().unwrap();
    let len = |dir| crate::testing::MemoryStore::handle(&fixture.vault, dir).log_len();
    let (len_a, len_b) = (len(a), len(b));
    device.on_tick(NOW + 2_000);
    let shrunk = usize::from(len(a) < len_a) + usize::from(len(b) < len_b);
    assert_eq!(shrunk, 1);
    device.on_tick(NOW + 3_000);
    assert!(len(a) < len_a && len(b) < len_b);
}

/// Marks channel 1 of `device` `write_failed` through a failing `mute`.
fn mark(fixture: &Fixture, device: &mut Device) {
    fixture.faults.fail_at(1);
    assert!(device.mute(id(), PEER, true).is_err());
    device.on_tick(NOW);
}

/// Spec 027, R12, R14: the probe a minute later clears the mark with
/// `StatusChanged`, and no `Reconnect` without a connection; one that
/// fails waits ten minutes, with no event.
#[test]
fn s027_t14_r14_probe() {
    let (fixture, mut device) = opened();
    let id = id();
    mark(&fixture, &mut device);
    assert!(device.on_tick(NOW + MINUTE - 1_000).is_empty());
    fixture.faults.fail_commits(true);
    assert!(device.on_tick(NOW + MINUTE).is_empty());
    assert!(device.channels()[0].write_failed);
    assert!(
        device
            .on_tick(NOW + MINUTE + TEN_MINUTES - 1_000)
            .is_empty()
    );
    fixture.faults.fail_commits(false);
    assert_eq!(
        device.on_tick(NOW + MINUTE + TEN_MINUTES),
        [Event::StatusChanged { channel: id }]
    );
    assert!(!device.channels()[0].write_failed);
}

/// Spec 027, R12, R14: a probe that clears a channel whose connection is
/// connected asks for a new connection, so that the pushes it held come
/// again.
#[test]
fn s027_t14_r14_probe_reconnects() {
    let (fixture, mut device) = opened();
    let mut server = MemoryServer::new(&[HOST]);
    connect_all(&mut device, &mut server, NOW);
    run(&mut device, &mut server, NOW, NOW + 3_000);
    let plan = device.connections()[0].id;
    fixture.faults.fail_at(1);
    assert!(device.mute(id(), PEER, true).is_err());
    let events = device.on_tick(NOW + 4_000 + MINUTE);
    assert!(events.contains(&Event::StatusChanged { channel: id() }));
    assert!(events.contains(&Event::Reconnect { connection: plan }));
}

/// Spec 027, R12: a probe time more than ten minutes ahead, after a clock
/// set back, is due at the next tick.
#[test]
fn s027_t14_r14_probe_after_a_clock_set_back() {
    let (fixture, mut device) = opened();
    mark(&fixture, &mut device);
    let events = device.on_tick(NOW - TEN_MINUTES);
    assert!(events.contains(&Event::StatusChanged { channel: id() }));
    assert!(!device.channels()[0].write_failed);
}

/// Spec 027, R12: a `send` that returns `Ok` on a marked channel, or a
/// `leave` of another channel, makes the probe due at the next tick; a
/// `label` that returns `Ok` does not.
#[test]
fn s027_t14_r14_probe_made_due() {
    let (fixture, mut device) = opened();
    let id = id();
    mark(&fixture, &mut device);
    device.label(id, PEER, "ann", NOW + 1_000).unwrap();
    device.on_tick(NOW + 2_000);
    assert!(device.channels()[0].write_failed);
    device.send(id, "hi", None, NOW + 3_000).unwrap();
    assert!(
        device
            .on_tick(NOW + 4_000)
            .contains(&Event::StatusChanged { channel: id })
    );
    assert!(!device.channels()[0].write_failed);

    let (fixture, _) = with_peer();
    fixture.plant_channel(2, Vec::new());
    let mut device = fixture.open().unwrap();
    device.on_tick(NOW);
    mark(&fixture, &mut device);
    device.leave(config(2).channel_id()).unwrap();
    assert!(
        device
            .on_tick(NOW + 1_000)
            .contains(&Event::StatusChanged { channel: id })
    );
}

/// Spec 027, R12, R14: within ten minutes of a clearing a new failure
/// waits ten minutes for its first probe, and a `send` does not make it
/// due; a clearing recorded later than `now` counts as older.
#[test]
fn s027_t14_r14_after_a_recent_clearing() {
    let (fixture, mut device) = opened();
    let id = id();
    mark(&fixture, &mut device);
    device.on_tick(NOW + MINUTE);
    assert!(!device.channels()[0].write_failed);
    fixture.faults.fail_at(1);
    device.on_tick(NOW + MINUTE + 1_000);
    assert!(device.mute(id, PEER, true).is_err());
    assert_eq!(
        super::first_probe_at(&device),
        Some(NOW + MINUTE + 1_000 + TEN_MINUTES)
    );
    device.send(id, "hi", None, NOW + MINUTE + 2_000).unwrap();
    assert_eq!(
        device.on_tick(NOW + 2 * MINUTE + 3_000),
        [Event::StorageFailed { channel: id }]
    );
    assert!(device.channels()[0].write_failed);

    // A clearing at `NOW + MINUTE`, then the clock set back.
    let (fixture, mut device) = opened();
    mark(&fixture, &mut device);
    device.on_tick(NOW + MINUTE);
    device.on_tick(NOW - TEN_MINUTES);
    fixture.faults.fail_at(1);
    assert!(device.mute(id, PEER, true).is_err());
    assert_eq!(
        super::first_probe_at(&device),
        Some(NOW - TEN_MINUTES + MINUTE)
    );
}

/// Spec 027, R12, R14: one probe a tick, and a probe whose reopen fails
/// moves the channel to `broken` with `StorageFailed`.
#[test]
fn s027_t14_r14_one_probe_a_tick() {
    let (fixture, _) = with_peer();
    fixture.plant_channel(2, Vec::new());
    let mut device = fixture.open().unwrap();
    device.on_tick(NOW);
    fixture.faults.fail_at(1);
    assert!(device.mute(id(), PEER, true).is_err());
    fixture.faults.fail_at(1);
    assert!(device.rename_channel(config(2).channel_id(), "x").is_err());
    let events = device.on_tick(NOW + MINUTE);
    let cleared = events
        .iter()
        .filter(|event| matches!(event, Event::StatusChanged { .. }))
        .count();
    assert_eq!(cleared, 1);
    let marked = device.channels().iter().filter(|c| c.write_failed).count();
    assert_eq!(marked, 1);

    fixture.faults.fail_create(true);
    let events = device.on_tick(NOW + MINUTE + 1_000);
    assert_eq!(events.len(), 1);
    assert!(matches!(events[0], Event::StorageFailed { .. }));
    assert_eq!(device.channels().len(), 1);
    assert_eq!(device.status().broken.len(), 1);
}

/// Spec 027, R14: a marked channel with no connection and an entry going
/// stale reports nothing and reopens nothing until the probe clears the
/// mark, then `NotDelivered` once.
#[test]
fn s027_t14_r14_marked_channel_expires_nothing() {
    let (fixture, mut device) = opened();
    let id = id();
    let sent = device.send(id, "hello", None, NOW).unwrap();
    device.on_tick(NOW);
    fixture.faults.fail_at(1);
    assert!(device.mute(id, PEER, true).is_err());
    assert_eq!(
        device.on_tick(NOW + 1_000),
        [Event::StorageFailed { channel: id }]
    );
    let late = NOW + 3_600_000 + 7 * MINUTE;
    fixture.faults.fail_commits(true);
    // The probe at `late` fails: nothing expires, no event.
    assert_eq!(device.on_tick(late), []);
    fixture.faults.fail_commits(false);
    let events = device.on_tick(late + TEN_MINUTES);
    let not_delivered = Event::NotDelivered {
        channel: id,
        client_ref: sent.client_ref,
        sent_at: sent.message.sent_at.unwrap(),
    };
    assert!(events.contains(&Event::StatusChanged { channel: id }));
    let events = device.on_tick(late + TEN_MINUTES + 1_000);
    assert_eq!(
        events
            .iter()
            .filter(|event| **event == not_delivered)
            .count(),
        1
    );
}

/// Spec 027, R14: a store poisoned during `on_frame` → `StorageFailed`
/// and no `Reconnect` in its result, the channel `write_failed`.
#[test]
fn s027_t14_r14_session_failure() {
    let (fixture, mut device) = opened();
    let mut server = MemoryServer::new(&[HOST]);
    let id = id();
    connect_all(&mut device, &mut server, NOW);
    run(&mut device, &mut server, NOW, NOW + 3_000);
    // The `ack` of a publish commits; poison that commit.
    device.send(id, "hello", None, NOW + 4_000).unwrap();
    let plan = device.connections()[0].id;
    for frame in device.outgoing(plan) {
        server.receive(plan, &frame, NOW + 4_000);
    }
    fixture.faults.poison_after(1);
    let mut events = Vec::new();
    for frame in server.read(plan, 100) {
        events.extend(device.on_frame(plan, &frame, NOW + 4_000));
    }
    assert!(events.contains(&Event::StorageFailed { channel: id }));
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, Event::Reconnect { .. }))
    );
    assert!(device.channels()[0].write_failed);
}

/// Spec 027, R14: a marked channel whose run gets a new plan `id` is held
/// in the new session too.
#[test]
fn s027_t14_r14_new_session_holds_the_mark() {
    let (fixture, mut device) = opened();
    mark(&fixture, &mut device);
    device
        .import_qr(&config(2).export_qr(NOW).unwrap(), false, NOW)
        .unwrap();
    let plan = device.connections()[0].clone();
    assert_eq!(plan.channels.len(), 2);
    let mut server = MemoryServer::new(&[HOST]);
    connect_all(&mut device, &mut server, NOW + 1_000);
    let events = run(&mut device, &mut server, NOW + 1_000, NOW + 5_000);
    assert!(subscribed(&events, config(2).channel_id()));
    // Frozen: the marked channel publishes nothing.
    device.send(id(), "held", None, NOW + 6_000).unwrap();
    assert!(device.outgoing(plan.id).is_empty());
}

/// Spec 027, R24: a quiet channel synced at `now` and flushed keeps its
/// `synced_at`; one channel failing its `flush` → that error, the others
/// flushed.
#[test]
fn s027_t24_r24_flush() {
    let (fixture, mut device) = with_channels(2);
    let mut server = MemoryServer::new(&[HOST]);
    connect_all(&mut device, &mut server, NOW);
    run(&mut device, &mut server, NOW, NOW + 5_000);
    let later = NOW + 30 * MINUTE;
    run(&mut device, &mut server, later, later);
    device.flush(later).unwrap();
    drop(device);
    let device = fixture.open().unwrap();
    for channel in &device.channels {
        assert!(channel.synced_at().is_some_and(|at| at >= NOW));
    }

    let (fixture, mut device) = with_channels(2);
    device.on_tick(NOW);
    let mut server = MemoryServer::new(&[HOST]);
    connect_all(&mut device, &mut server, NOW);
    run(&mut device, &mut server, NOW, NOW + 5_000);
    fixture.faults.fail_at(1);
    assert_eq!(
        device.flush(NOW + 30 * MINUTE),
        Err(Error::Store(StoreError::Io))
    );
}
