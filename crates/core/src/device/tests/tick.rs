//! Tests of the connections, the tick and `flush` (spec 027-core-api R11,
//! R12, R24, and R14 for the sessions and the probes).

use super::dispatch::{PEER, id, opened, with_peer};
use super::{Fixture, NOW, config};
use crate::Error;
use crate::device::Device;
use crate::session::connection::Event;
use crate::storage::{Store, StoreError};
use crate::testing::{MemoryServer, record, settings};

pub(super) const HOST: &str = "example.org";
pub(super) const MINUTE: u64 = 60_000;
pub(super) const TEN_MINUTES: u64 = 600_000;

/// Connects every plan of `device` to `server` and exchanges frames until
/// both are quiet, at `now`; returns the events.
pub(super) fn pump(device: &mut Device, server: &mut MemoryServer, now: u64) -> Vec<Event> {
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
pub(super) fn connect_all(device: &mut Device, server: &mut MemoryServer, now: u64) {
    for plan in device.connections() {
        server.connect(plan.id, now);
        device.on_connect(plan.id, now);
    }
}

/// Ticks every second from `from` to `to`, pumping frames, and returns the
/// events.
pub(super) fn run(
    device: &mut Device,
    server: &mut MemoryServer,
    from: u64,
    to: u64,
) -> Vec<Event> {
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
pub(super) fn subscribed(events: &[Event], channel: [u8; 16]) -> bool {
    events.contains(&Event::Subscribed { channel })
}

/// A device with saved settings and the channels of keys `1..=n`.
pub(super) fn with_channels(n: u8) -> (Fixture, Device) {
    let fixture = Fixture::new();
    fixture.save_settings(&settings("wss://example.org", 30, None));
    for k in 1..=n {
        fixture.plant_channel(k, Vec::new());
    }
    let device = fixture.open().unwrap();
    (fixture, device)
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
fn s027_t14_r14_status_without_a_connection() {
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
pub(super) fn mark(fixture: &Fixture, device: &mut Device) {
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

/// Spec 027, R14: a failure queued before a tick whose probe clears it
/// comes first, so that `StorageFailed` never follows its own clearing.
#[test]
fn s027_t14_r14_queued_failure_before_its_clearing() {
    let (fixture, mut device) = opened();
    let id = id();
    fixture.faults.fail_at(1);
    assert!(device.mute(id, PEER, true).is_err());
    let events = device.on_tick(NOW + MINUTE);
    let failed = events
        .iter()
        .position(|event| *event == Event::StorageFailed { channel: id });
    let cleared = events
        .iter()
        .rposition(|event| *event == Event::StatusChanged { channel: id });
    assert!(
        failed.is_some() && cleared.is_some() && failed < cleared,
        "{events:?}"
    );
    assert!(!device.channels()[0].write_failed);
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
fn s027_t12_r12_one_probe_a_tick() {
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

/// Spec 027, R24: a quiet channel synced at `now` and flushed, reopened a
/// TTL later minus a minute, shows no `HistoryTruncated`; without the
/// `flush` it would.
#[test]
fn s027_t24_r24_flush() {
    let lock = NOW + 20 * MINUTE;
    let back = lock + 3_600_000 - MINUTE;
    for flushed in [true, false] {
        let (fixture, mut device) = with_channels(1);
        let mut server = MemoryServer::new(&[HOST]);
        connect_all(&mut device, &mut server, NOW);
        run(&mut device, &mut server, NOW, lock);
        if flushed {
            device.flush(lock).unwrap();
        }
        drop(device);
        let mut device = fixture.open().unwrap();
        let mut server = MemoryServer::new(&[HOST]);
        connect_all(&mut device, &mut server, back);
        let events = run(&mut device, &mut server, back, back + 5_000);
        let truncated = events
            .iter()
            .any(|event| matches!(event, Event::HistoryTruncated { .. }));
        assert_eq!(truncated, !flushed);
    }
}

/// Spec 027, R24: one channel failing its `flush` → that error, and the
/// other channel flushed.
#[test]
fn s027_t24_r24_flush_with_a_failure() {
    let (fixture, mut device) = with_channels(2);
    let mut server = MemoryServer::new(&[HOST]);
    connect_all(&mut device, &mut server, NOW);
    let lock = NOW + 20 * MINUTE;
    run(&mut device, &mut server, NOW, lock);
    fixture.faults.fail_at(1);
    assert_eq!(device.flush(lock), Err(Error::Store(StoreError::Io)));
    drop(device);
    let device = fixture.open().unwrap();
    let synced: Vec<Option<u64>> = device
        .channels
        .iter()
        .map(crate::session::channel::Channel::synced_at)
        .collect();
    assert!(synced.contains(&Some(lock)), "{synced:?}");
    assert!(synced.iter().any(|at| *at != Some(lock)), "{synced:?}");
}

/// Spec 027, R12: the periodic purge runs at a quarter of the log, and not
/// below it before a day after the oldest expiry.
#[test]
fn s027_t12_r12_periodic_purge() {
    let fixture = Fixture::new();
    fixture.save_settings(&settings("wss://example.org", 30, None));
    let quarter = fixture.plant_channel(
        1,
        vec![
            record(NOW + 1_000, 1_000),
            record(NOW + 10 * 86_400_000, 100),
        ],
    );
    let below = fixture.plant_channel(
        2,
        vec![
            record(NOW + 1_000, 10),
            record(NOW + 10 * 86_400_000, 10_000),
        ],
    );
    let mut device = fixture.open().unwrap();
    let len = |dir| crate::testing::MemoryStore::handle(&fixture.vault, dir).log_len();
    let (quarter_len, below_len) = (len(quarter), len(below));
    device.on_tick(NOW + 2_000);
    device.on_tick(NOW + 3_000);
    assert!(len(quarter) < quarter_len);
    assert_eq!(len(below), below_len);
    device.on_tick(NOW + 1_000 + 86_400_000);
    assert_eq!(len(below), below_len);
    device.on_tick(NOW + 2_000 + 86_400_000);
    assert!(len(below) < below_len);
}

/// Spec 027, R12: a stale entry of a channel refused on its connection
/// leaves as `NotDelivered` from `on_tick`.
#[test]
fn s027_t12_r12_stale_entry_of_a_refused_channel() {
    let (_fixture, mut device) = opened();
    let mut server = MemoryServer::new(&["other.example.org"]);
    let id = id();
    connect_all(&mut device, &mut server, NOW);
    run(&mut device, &mut server, NOW, NOW + 3_000);
    let sent = device.send(id, "hello", None, NOW + 4_000).unwrap();
    let late = NOW + 4_000 + 3_600_000 + 7 * MINUTE;
    let events = device.on_tick(late);
    assert!(events.contains(&Event::NotDelivered {
        channel: id,
        client_ref: sent.client_ref,
        sent_at: sent.message.sent_at.unwrap(),
    }));
}

/// Spec 027, R15: a compaction failing on the tick, with commits working,
/// marks the channel until the probe a minute later clears it, with no
/// second attempt before; the probe then asks for no `Reconnect` without a
/// connection.
#[test]
fn s027_t15_r15_compaction_failing_on_the_tick() {
    let fixture = Fixture::new();
    fixture.save_settings(&settings("wss://example.org", 30, None));
    let dir = fixture.plant_channel(1, vec![record(NOW + 1_000, 1_000)]);
    let mut device = fixture.open().unwrap();
    device.on_tick(NOW);
    fixture.faults.fail_compactions(true);
    let id = config(1).channel_id();
    let events = device.on_tick(NOW + 2_000);
    assert!(events.contains(&Event::StorageFailed { channel: id }));
    assert!(device.channels()[0].write_failed);
    fixture.faults.fail_compactions(false);
    let handle = crate::testing::MemoryStore::handle(&fixture.vault, dir);
    let len = handle.log_len();
    device.on_tick(NOW + 3_000);
    assert_eq!(handle.log_len(), len);
    let events = device.on_tick(NOW + 2_000 + MINUTE);
    assert!(events.contains(&Event::StatusChanged { channel: id }));
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, Event::Reconnect { .. }))
    );
    assert!(!device.channels()[0].write_failed);
}

/// A log one byte into the headroom of spec 021-channel-session R18.
pub(super) const FULL_LOG: u64 = crate::storage::MAX_LOG_LEN - 1_114_156 + 1;

/// Spec 027, R12, R14: a probe that clears a channel whose socket has
/// closed asks for no `Reconnect`.
#[test]
fn s027_t14_r14_probe_after_disconnect_no_reconnect() {
    let (fixture, mut device) = opened();
    let mut server = MemoryServer::new(&[HOST]);
    connect_all(&mut device, &mut server, NOW);
    run(&mut device, &mut server, NOW, NOW + 3_000);
    let plan = device.connections()[0].id;
    device.on_disconnect(plan);
    server.disconnect(plan);
    fixture.faults.fail_at(1);
    assert!(device.mute(id(), PEER, true).is_err());
    let events = device.on_tick(NOW + 4_000 + MINUTE);
    assert!(events.contains(&Event::StatusChanged { channel: id() }));
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, Event::Reconnect { .. }))
    );
}

/// Spec 027, R9: `regenerate_identity` on a connected channel calls
/// `after_send`, so that the `key_retired` is published at once.
#[test]
fn s027_t09_r09_regenerate_identity_after_send() {
    let (_fixture, mut device) = opened();
    let mut server = MemoryServer::new(&[HOST]);
    connect_all(&mut device, &mut server, NOW);
    run(&mut device, &mut server, NOW, NOW + 3_000);
    let plan = device.connections()[0].id;
    device.regenerate_identity(id(), NOW + 4_000).unwrap();
    assert!(!device.outgoing(plan).is_empty());
}

/// Spec 027, R12: a `send` that a reopen saved on a channel not marked
/// before it does not make the new mark's probe due.
#[test]
fn s027_t14_r14_send_marking_keeps_its_first_probe() {
    let (fixture, mut device) = opened();
    fixture.faults.poison_after(1);
    device.send(id(), "hello", None, NOW + 1_000).unwrap();
    assert_eq!(super::first_probe_at(&device), Some(NOW + 1_000 + MINUTE));
}

/// Spec 027, R12, R14: a clearing exactly ten minutes old is no longer
/// recent; a probe exactly ten minutes ahead is not due yet.
#[test]
fn s027_t14_r14_ten_minute_boundaries() {
    let (fixture, mut device) = opened();
    mark(&fixture, &mut device);
    device.on_tick(NOW + MINUTE);
    assert!(!device.channels()[0].write_failed);
    device.on_tick(NOW + MINUTE + TEN_MINUTES);
    fixture.faults.fail_at(1);
    assert!(device.mute(id(), PEER, true).is_err());
    assert_eq!(
        super::first_probe_at(&device),
        Some(NOW + MINUTE + TEN_MINUTES + MINUTE)
    );

    let (fixture, mut device) = opened();
    mark(&fixture, &mut device);
    device.on_tick(NOW + MINUTE);
    device.on_tick(NOW + MINUTE + 1_000);
    fixture.faults.fail_at(1);
    assert!(device.mute(id(), PEER, true).is_err());
    let events = device.on_tick(NOW + MINUTE + 1_000);
    assert!(!events.contains(&Event::StatusChanged { channel: id() }));
    assert!(device.channels()[0].write_failed);
}

/// Spec 027, R14: a channel marked on a session that already exists is
/// frozen there: nothing it sends is published.
#[test]
fn s027_t14_r14_mark_freezes_the_current_session() {
    let (fixture, mut device) = opened();
    let mut server = MemoryServer::new(&[HOST]);
    connect_all(&mut device, &mut server, NOW);
    run(&mut device, &mut server, NOW, NOW + 3_000);
    let plan = device.connections()[0].id;
    fixture.faults.fail_at(1);
    assert!(device.mute(id(), PEER, true).is_err());
    device.send(id(), "held", None, NOW + 4_000).unwrap();
    assert!(device.outgoing(plan).is_empty());
}

/// Spec 027, R14: a tick failure whose reopen fails breaks that channel
/// and marks no other.
#[test]
fn s027_t14_r14_failed_reopen_marks_no_other_channel() {
    let fixture = Fixture::new();
    fixture.save_settings(&settings("wss://example.org", 30, None));
    // Both due, so that the channel the tick purges first is the one at
    // the first position, whichever the listing put there.
    fixture.plant_channel(1, vec![record(NOW + 1_000, 1_000)]);
    fixture.plant_channel(2, vec![record(NOW + 1_000, 1_000)]);
    let mut device = fixture.open().unwrap();
    let first = device.channels()[0].id;
    fixture.faults.fail_at(1);
    fixture.faults.fail_create(true);
    let events = device.on_tick(NOW + 2_000);
    assert!(events.contains(&Event::StorageFailed { channel: first }));
    assert_eq!(device.status().broken.len(), 1);
    assert_eq!(device.channels().len(), 1);
    assert!(!device.channels()[0].write_failed);
}

/// Spec 027, R14, R15: the tick purges no marked channel until its probe
/// clears the mark.
#[test]
fn s027_t15_r15_no_purge_while_marked() {
    let fixture = Fixture::new();
    fixture.save_settings(&settings("wss://example.org", 30, None));
    let dir = fixture.plant_channel(1, vec![record(NOW + 1_000, 1_000)]);
    let mut device = fixture.open().unwrap();
    let handle = crate::testing::MemoryStore::handle(&fixture.vault, dir);
    fixture.faults.fail_at(1);
    assert!(device.rename_channel(id(), "x").is_err());
    let len = handle.log_len();
    device.on_tick(NOW + 2_000);
    assert_eq!(handle.log_len(), len);
}

/// Spec 027, R12: the tick relieves a log within its headroom.
#[test]
fn s027_t12_r12_tick_relieves_headroom() {
    let (fixture, mut device) = opened();
    let dir = *device.channels[0].dir_name();
    device.channels[0].fill_log(NOW + 1_000, 2 * 1_048_576);
    device.channels[0].fill_log(NOW + 36_000_000, FULL_LOG);
    assert!(device.channels()[0].status.storage_full);
    let handle = crate::testing::MemoryStore::handle(&fixture.vault, dir);
    device.on_tick(NOW + 2_000);
    assert!(handle.log_len() < FULL_LOG);
}

/// Spec 027, R14, R15: the tick relieves no marked channel.
#[test]
fn s027_t15_r15_no_relief_while_marked() {
    let (fixture, mut device) = opened();
    fixture.faults.fail_at(1);
    assert!(device.mute(id(), PEER, true).is_err());
    let dir = *device.channels[0].dir_name();
    device.channels[0].fill_log(NOW + 1_000, 2 * 1_048_576);
    device.channels[0].fill_log(NOW + 36_000_000, FULL_LOG);
    let handle = crate::testing::MemoryStore::handle(&fixture.vault, dir);
    device.on_tick(NOW + 2_000);
    assert_eq!(handle.log_len(), FULL_LOG);
}

/// Spec 027, R12: a probe that clears a connected channel whose log is
/// full asks for no `Reconnect`.
#[test]
fn s027_t14_r14_probe_storage_full_no_reconnect() {
    let (fixture, mut device) = opened();
    let mut server = MemoryServer::new(&[HOST]);
    connect_all(&mut device, &mut server, NOW);
    run(&mut device, &mut server, NOW, NOW + 3_000);
    fixture.faults.fail_at(1);
    assert!(device.mute(id(), PEER, true).is_err());
    device.channels[0].fill_log(NOW + 36_000_000, FULL_LOG);
    // Ticks every second, so that no call gap (spec 028 R9) asks for one.
    let events = run(&mut device, &mut server, NOW + 4_000, NOW + 4_000 + MINUTE);
    assert!(events.contains(&Event::StatusChanged { channel: id() }));
    assert!(!device.channels()[0].write_failed);
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, Event::Reconnect { .. }))
    );
}

/// Spec 027, R12: the probe itself asks for the `Reconnect`, with the
/// client ticking every second, so that no call gap asks for it.
#[test]
fn s027_t14_r14_probe_reconnects_without_a_gap() {
    let (fixture, mut device) = opened();
    let mut server = MemoryServer::new(&[HOST]);
    connect_all(&mut device, &mut server, NOW);
    run(&mut device, &mut server, NOW, NOW + 3_000);
    let plan = device.connections()[0].id;
    fixture.faults.fail_at(1);
    assert!(device.mute(id(), PEER, true).is_err());
    let events = run(&mut device, &mut server, NOW + 4_000, NOW + 4_000 + MINUTE);
    assert!(events.contains(&Event::StatusChanged { channel: id() }));
    assert!(events.contains(&Event::Reconnect { connection: plan }));
}

/// Spec 027, R12: after a probe clears the mark and the socket is
/// reopened, the channel publishes again on the same plan.
#[test]
fn s027_t14_r14_cleared_channel_publishes_again() {
    let (fixture, mut device) = opened();
    let mut server = MemoryServer::new(&[HOST]);
    connect_all(&mut device, &mut server, NOW);
    run(&mut device, &mut server, NOW, NOW + 3_000);
    let plan = device.connections()[0].id;
    fixture.faults.fail_at(1);
    assert!(device.mute(id(), PEER, true).is_err());
    let events = device.on_tick(NOW + 4_000 + MINUTE);
    assert!(events.contains(&Event::Reconnect { connection: plan }));
    device.on_disconnect(plan);
    server.disconnect(plan);
    let later = NOW + 5_000 + MINUTE;
    connect_all(&mut device, &mut server, later);
    run(&mut device, &mut server, later, later + 3_000);
    device.send(id(), "back", None, later + 4_000).unwrap();
    pump(&mut device, &mut server, later + 4_000);
    assert!(!server.stored(&id()).is_empty());
}

/// Spec 027, R24: a channel whose `flush` fails does not stop the next
/// one from being flushed.
#[test]
fn s027_t24_r24_flush_attempts_every_channel() {
    let fixture = Fixture::new();
    fixture.save_settings(&settings("wss://example.org", 30, None));
    let dirs = [
        fixture.plant_channel(1, Vec::new()),
        fixture.plant_channel(2, Vec::new()),
    ];
    let mut device = fixture.open().unwrap();
    let mut server = MemoryServer::new(&[HOST]);
    connect_all(&mut device, &mut server, NOW);
    run(&mut device, &mut server, NOW, NOW + 5_000);
    let commits =
        || dirs.map(|dir| crate::testing::MemoryStore::handle(&fixture.vault, dir).all_commits());
    let before = commits();
    fixture.faults.fail_at(1);
    assert!(device.flush(NOW + 30 * MINUTE).is_err());
    let after = commits();
    let flushed = (0..2).filter(|&k| after[k] > before[k]).count();
    assert_eq!(flushed, 1);
}

/// Spec 027, R12: the tick leaves the `outbox` of a connected channel to
/// its session: an entry in flight, published and not yet acked, is not
/// expired by the `Device`.
#[test]
fn s027_t12_r12_connected_outbox_left_to_its_session() {
    let (_fixture, mut device) = opened();
    let mut server = MemoryServer::new(&[HOST]);
    connect_all(&mut device, &mut server, NOW);
    run(&mut device, &mut server, NOW, NOW + 3_000);
    device.send(id(), "hello", None, NOW + 4_000).unwrap();
    let late = NOW + 3_600_000 + 7 * MINUTE;
    let mut events = Vec::new();
    let mut now = NOW + 5_000;
    while now <= late {
        events.extend(device.on_tick(now));
        now += 1_000;
    }
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, Event::NotDelivered { .. })),
        "{events:?}"
    );
}

/// Spec 027, R12: a full channel whose relief cannot act holds back no
/// other full channel's relief.
#[test]
fn s027_t12_r12_relief_skips_a_channel_it_cannot_relieve() {
    let (fixture, _) = with_peer();
    fixture.plant_channel(2, Vec::new());
    let mut device = fixture.open().unwrap();
    device.channels[0].fill_log(NOW + 36_000_000, FULL_LOG);
    device.channels[1].fill_log(NOW + 1_000, 2 * 1_048_576);
    device.channels[1].fill_log(NOW + 36_000_000, FULL_LOG);
    assert!(
        device
            .channels()
            .iter()
            .all(|info| info.status.storage_full)
    );
    let second = *device.channels[1].dir_name();
    let handle = crate::testing::MemoryStore::handle(&fixture.vault, second);
    device.on_tick(NOW + 2_000);
    assert!(handle.log_len() < FULL_LOG);
}

/// Spec 027, R12, R15: a relief that fails is the tick's one compaction:
/// no other full channel is relieved on that tick.
#[test]
fn s027_t12_r12_failed_relief_is_the_ticks_compaction() {
    let (fixture, _) = with_peer();
    fixture.plant_channel(2, Vec::new());
    let mut device = fixture.open().unwrap();
    for channel in &mut device.channels {
        channel.fill_log(NOW + 1_000, 2 * 1_048_576);
        channel.fill_log(NOW + 36_000_000, FULL_LOG);
    }
    fixture.faults.fail_compactions(true);
    let events = device.on_tick(NOW + 2_000);
    let failed = events
        .iter()
        .filter(|event| matches!(event, Event::StorageFailed { .. }))
        .count();
    assert_eq!(failed, 1, "{events:?}");
    let marked = device.channels().iter().filter(|c| c.write_failed).count();
    assert_eq!(marked, 1);
}

/// Spec 027, R12: the tick relieves no channel whose log has its
/// headroom, whatever has expired below a due purge.
#[test]
fn s027_t12_r12_no_relief_with_headroom() {
    let (fixture, mut device) = opened();
    let dir = *device.channels[0].dir_name();
    device.channels[0].fill_log(NOW + 1_000, 2 * 1_048_576);
    device.channels[0].fill_log(NOW + 36_000_000, 16 * 1_048_576);
    assert!(!device.channels()[0].status.storage_full);
    let handle = crate::testing::MemoryStore::handle(&fixture.vault, dir);
    device.on_tick(NOW + 2_000);
    assert_eq!(handle.log_len(), 16 * 1_048_576);
}

/// Spec 027, R12, R14: a probe that clears a connected channel whose log
/// is full leaves it waiting for room, and the `Reconnect` comes once the
/// tick has relieved the log.
#[test]
fn s027_t14_r14_probe_storage_full_reconnects_once_relieved() {
    let (fixture, mut device) = opened();
    let mut server = MemoryServer::new(&[HOST]);
    connect_all(&mut device, &mut server, NOW);
    run(&mut device, &mut server, NOW, NOW + 3_000);
    let plan = device.connections()[0].id;
    fixture.faults.fail_at(1);
    assert!(device.mute(id(), PEER, true).is_err());
    device.channels[0].fill_log(NOW + 1_000, 2 * 1_048_576);
    device.channels[0].fill_log(NOW + 36_000_000, FULL_LOG);
    let events = run(&mut device, &mut server, NOW + 4_000, NOW + 8_000 + MINUTE);
    assert!(events.contains(&Event::StatusChanged { channel: id() }));
    assert!(!device.channels()[0].status.storage_full);
    assert!(events.contains(&Event::Reconnect { connection: plan }));
}

/// Spec 027, R12, R14: a compaction that changes no status reports
/// nothing.
#[test]
fn s027_t12_r12_purge_without_a_status_change_is_silent() {
    let fixture = Fixture::new();
    fixture.save_settings(&settings("wss://example.org", 30, None));
    let dir = fixture.plant_channel(1, vec![record(NOW + 1_000, 1_000)]);
    let mut device = fixture.open().unwrap();
    device.on_tick(NOW);
    let handle = crate::testing::MemoryStore::handle(&fixture.vault, dir);
    let len = handle.log_len();
    assert_eq!(device.on_tick(NOW + 2_000), []);
    assert!(handle.log_len() < len);
}

/// Spec 027, R14: a probe whose reopen fails drops the mark with the
/// channel, so that the channel imported again is not `write_failed`.
#[test]
fn s027_t14_r14_broken_by_a_probe_forgets_its_mark() {
    let (fixture, mut device) = opened();
    mark(&fixture, &mut device);
    fixture.faults.fail_create(true);
    assert_eq!(
        device.on_tick(NOW + MINUTE),
        [Event::StorageFailed { channel: id() }]
    );
    fixture.faults.fail_create(false);
    device
        .import_qr(&config(1).export_qr(NOW).unwrap(), false, NOW + MINUTE)
        .unwrap();
    assert!(!device.channels()[0].write_failed);
}

/// Spec 027, R14: a channel broken by a failed reopen forgets its
/// clearing: imported again from `broken`, a new failure waits one minute
/// for its first probe, not ten.
#[test]
fn s027_t14_r14_broken_by_a_reopen_forgets_its_clearing() {
    let (fixture, mut device) = opened();
    mark(&fixture, &mut device);
    device.on_tick(NOW + MINUTE);
    assert!(!device.channels()[0].write_failed);
    fixture.faults.fail_create(true);
    fixture.faults.fail_at(1);
    assert!(device.rename_channel(id(), "x").is_err());
    assert!(device.channels().is_empty());
    fixture.faults.fail_create(false);
    device
        .import_qr(&config(1).export_qr(NOW).unwrap(), false, NOW + MINUTE)
        .unwrap();
    device.on_tick(NOW + MINUTE + 1_000);
    fixture.faults.fail_at(1);
    assert!(device.rename_channel(id(), "y").is_err());
    assert_eq!(
        super::first_probe_at(&device),
        Some(NOW + 2 * MINUTE + 1_000)
    );
}

/// Spec 027, R14: a channel left forgets its mark and its clearing: once
/// imported again it is not `write_failed`, and a new failure waits one
/// minute for its first probe.
#[test]
fn s027_t14_r14_leave_forgets_mark_and_clearing() {
    let (fixture, mut device) = opened();
    mark(&fixture, &mut device);
    device.leave(id()).unwrap();
    device
        .import_qr(&config(1).export_qr(NOW).unwrap(), false, NOW)
        .unwrap();
    assert!(!device.channels()[0].write_failed);

    let (fixture, mut device) = opened();
    mark(&fixture, &mut device);
    device.on_tick(NOW + MINUTE);
    assert!(!device.channels()[0].write_failed);
    device.leave(id()).unwrap();
    device
        .import_qr(&config(1).export_qr(NOW).unwrap(), false, NOW + MINUTE)
        .unwrap();
    device.on_tick(NOW + MINUTE + 1_000);
    fixture.faults.fail_at(1);
    assert!(device.rename_channel(id(), "x").is_err());
    assert_eq!(
        super::first_probe_at(&device),
        Some(NOW + 2 * MINUTE + 1_000)
    );
}

/// Spec 027, R3, R12: a `remove_broken` makes the probe due at the next
/// tick.
#[test]
fn s027_t03_r03_remove_broken_makes_the_probe_due() {
    let (fixture, _) = with_peer();
    let corrupt = fixture.plant_corrupt(9);
    let mut device = fixture.open().unwrap();
    mark(&fixture, &mut device);
    device.remove_broken(&corrupt.to_hex()).unwrap();
    assert_eq!(
        device.on_tick(NOW + 1_000),
        [Event::StatusChanged { channel: id() }]
    );
    assert!(!device.channels()[0].write_failed);
}
