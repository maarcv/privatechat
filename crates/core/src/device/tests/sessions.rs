//! Tests of the store recovery through the sessions and the tick (spec
//! 027-core-api R8, R9, R12, R14 and R15 with a connection).

use super::dispatch::{PEER, id, opened, with_peer};
use super::tick::{FULL_LOG, HOST, MINUTE, connect_all, run};
use super::{Fixture, NOW};
use crate::device::Device;
use crate::session::connection::Event;
use crate::storage::{Store, StoreError};
use crate::testing::{MemoryServer, MemoryStore, record, settings};

/// A channel subscribed on `server` from `NOW` to `NOW + 3 s`.
fn subscribed(server: &mut MemoryServer) -> (Fixture, Device) {
    let (fixture, mut device) = opened();
    connect_all(&mut device, server, NOW);
    run(&mut device, server, NOW, NOW + 3_000);
    (fixture, device)
}

/// Marks channel 1 through a store poisoned by the commit of a session's
/// `ack`, and returns the step's events.
fn mark_by_an_ack(fixture: &Fixture, device: &mut Device, server: &mut MemoryServer) -> Vec<Event> {
    device.send(id(), "hello", None, NOW + 4_000).unwrap();
    let plan = device.connections()[0].id;
    for frame in device.outgoing(plan) {
        server.receive(plan, &frame, NOW + 4_000);
    }
    fixture.faults.poison_after(1);
    let mut events = Vec::new();
    for frame in server.read(plan, 100) {
        events.extend(device.on_frame(plan, &frame, NOW + 4_000));
    }
    events
}

/// Spec 027, R8: a channel marked by a session's commit is left at once,
/// and one whose `destroy` keeps failing returns the error and stays
/// listed.
#[test]
fn s027_t08_r08_leave_a_channel_marked_by_a_session() {
    let mut server = MemoryServer::new(&[HOST]);
    let (fixture, mut device) = subscribed(&mut server);
    mark_by_an_ack(&fixture, &mut device, &mut server);
    assert!(device.channels()[0].write_failed);
    fixture.faults.fail_destroys(true);
    assert_eq!(device.leave(id()), Err(crate::Error::Store(StoreError::Io)));
    assert_eq!(device.channels().len(), 1);
    fixture.faults.fail_destroys(false);
    device.leave(id()).unwrap();
    assert!(device.channels().is_empty());
}

/// Spec 027, R9: a `send` whose `outbox` step fails after `encrypt` → `Ok`,
/// with `StorageFailed` among its events.
#[test]
fn s027_t09_r09_send_whose_outbox_step_fails() {
    let mut server = MemoryServer::new(&[HOST]);
    let (fixture, mut device) = subscribed(&mut server);
    let plan = device.connections()[0].id;
    // A first entry in flight that is never acknowledged.
    device.send(id(), "first", None, NOW + 4_000).unwrap();
    assert!(!device.outgoing(plan).is_empty());
    // Past its TTL, the margin and the grace, the next `send`'s `outbox`
    // removes it in a commit of its own, which fails.
    let late = NOW + 4_000 + 3_600_000 + 8 * MINUTE;
    fixture.faults.poison_after(2);
    let sent = device.send(id(), "second", None, late).unwrap();
    assert!(
        sent.events
            .contains(&Event::StorageFailed { channel: id() })
    );
    assert!(device.channels()[0].write_failed);
}

/// Spec 027, R12: a pending retirement of a channel with no connection is
/// not sealed again by the tick.
#[test]
fn s027_t12_r12_retirement_not_resealed_on_the_tick() {
    let (fixture, mut device) = opened();
    device.regenerate_identity(id(), NOW).unwrap();
    device.on_tick(NOW);
    let dir = *device.channels[0].dir_name();
    let handle = MemoryStore::handle(&fixture.vault, dir);
    let commits = handle.all_commits();
    for minute in 1..=5 {
        device.on_tick(NOW + minute * MINUTE);
    }
    assert_eq!(handle.all_commits(), commits);
    assert!(device.channel_status(id()).unwrap().retirement_pending);
}

/// Spec 027, R12: a stale entry of a channel whose socket closed leaves
/// as `NotDelivered` from `on_tick`.
#[test]
fn s027_t12_r12_stale_entry_after_a_disconnect() {
    let mut server = MemoryServer::new(&[HOST]);
    let (_fixture, mut device) = subscribed(&mut server);
    let plan = device.connections()[0].id;
    device.on_disconnect(plan);
    let sent = device.send(id(), "hello", None, NOW + 4_000).unwrap();
    let late = NOW + 4_000 + 3_600_000 + 7 * MINUTE;
    let events = device.on_tick(late);
    assert!(events.contains(&Event::NotDelivered {
        channel: id(),
        client_ref: sent.client_ref,
        sent_at: sent.message.sent_at.unwrap(),
    }));
}

/// A second device holding channel 1 of `fixture` with the same identity,
/// as a copy of the data directory restored elsewhere.
fn twin_of(fixture: &Fixture) -> Device {
    let dir = crate::storage::Vault::dir_name(&fixture.vault.clone(), &id()).unwrap();
    let (state, log) = fixture.vault.get_raw(&dir);
    let twin = Fixture::new();
    twin.save_settings(&settings("wss://example.org", 30, None));
    twin.vault.put_raw(&dir, state.as_deref(), log.as_deref());
    twin.open().unwrap()
}

/// Has `twin` publish one message on `server`, on a socket numbered apart,
/// between `from` and `from + 6 s`.
fn twin_sends(twin: &mut Device, server: &mut MemoryServer, from: u64) {
    let plan = twin.connections()[0].id;
    let socket = 1_000;
    server.connect(socket, from);
    twin.on_connect(plan, from);
    for now in (from..from + 6_000).step_by(1_000) {
        twin.on_tick(now);
        for _ in 0..5 {
            for frame in twin.outgoing(plan) {
                server.receive(socket, &frame, now);
            }
            for frame in server.read(socket, 100) {
                twin.on_frame(plan, &frame, now);
            }
        }
        if now == from + 2_000 {
            twin.send(id(), "from the twin", None, now).unwrap();
        }
    }
}

/// Spec 027, R9: a `regenerate_identity` on a connected channel whose
/// publishing the session stopped after an own-key alert, its log full,
/// returns the `Reconnect` of its connection (spec 028-session-sans-io
/// R10).
#[test]
fn s027_t09_r09_regeneration_after_an_alert_reconnects() {
    let (fixture, _) = with_peer();
    let mut device = fixture.open().unwrap();
    let mut other = twin_of(&fixture);
    let mut server = MemoryServer::new(&[HOST]);
    connect_all(&mut device, &mut server, NOW);
    run(&mut device, &mut server, NOW, NOW + 3_000);
    device.channels[0].fill_log(NOW + 36_000_000, FULL_LOG);
    twin_sends(&mut other, &mut server, NOW + 4_000);
    run(&mut device, &mut server, NOW + 4_000, NOW + 10_000);
    assert!(device.channel_status(id()).unwrap().own_key_used_elsewhere);
    let plan = device.connections()[0].id;
    let events = device.regenerate_identity(id(), NOW + 11_000).unwrap();
    assert!(events.contains(&Event::Reconnect { connection: plan }));
}

/// Spec 027, R14: under `fail_commits`, a push of one's own key from
/// another device raises no alert while the channel is marked; once the
/// probe clears the mark and the client reconnects, the push comes again
/// and raises it.
#[test]
fn s027_t14_r14_own_key_push_on_a_marked_channel() {
    let (fixture, _) = with_peer();
    let mut device = fixture.open().unwrap();
    let mut other = twin_of(&fixture);
    let mut server = MemoryServer::new(&[HOST]);
    connect_all(&mut device, &mut server, NOW);
    run(&mut device, &mut server, NOW, NOW + 3_000);
    fixture.faults.fail_commits(true);
    assert!(device.mute(id(), PEER, true).is_err());
    twin_sends(&mut other, &mut server, NOW + 4_000);
    run(&mut device, &mut server, NOW + 4_000, NOW + 10_000);
    assert!(!device.channel_status(id()).unwrap().own_key_used_elsewhere);

    fixture.faults.fail_commits(false);
    let events = run(&mut device, &mut server, NOW + 11_000, NOW + 4_000 + MINUTE);
    let mine = device.connections()[0].id;
    assert!(events.contains(&Event::Reconnect { connection: mine }));
    device.on_disconnect(mine);
    server.disconnect(mine);
    connect_all(&mut device, &mut server, NOW + 5_000 + MINUTE);
    run(
        &mut device,
        &mut server,
        NOW + 5_000 + MINUTE,
        NOW + 10_000 + MINUTE,
    );
    assert!(device.channel_status(id()).unwrap().own_key_used_elsewhere);
}

/// Spec 027, R15: a relief poisoned after its rename reopens onto the
/// compacted log, and the probe a minute later clears the mark.
#[test]
fn s027_t15_r15_relief_poisoned_after_its_rename() {
    let (fixture, mut device) = opened();
    let dir = *device.channels[0].dir_name();
    device.channels[0].fill_log(NOW + 1_000, 2 * 1_048_576);
    device.channels[0].fill_log(NOW + 36_000_000, FULL_LOG);
    device.on_tick(NOW);
    let handle = MemoryStore::handle(&fixture.vault, dir);
    fixture.faults.poison_after(1);
    let events = device.on_tick(NOW + 2_000);
    assert!(events.contains(&Event::StorageFailed { channel: id() }));
    assert!(device.channels()[0].write_failed);
    assert!(handle.log_len() < FULL_LOG);
    assert!(!device.channels()[0].status.storage_full);
    let events = device.on_tick(NOW + 2_000 + MINUTE);
    assert!(events.contains(&Event::StatusChanged { channel: id() }));
    assert!(!device.channels()[0].write_failed);
}

/// Spec 027, R15: a compaction failing on the tick of a connected channel
/// is cleared by the probe with `Reconnect`.
#[test]
fn s027_t15_r15_compaction_failing_with_a_connection() {
    let fixture = Fixture::new();
    fixture.save_settings(&settings("wss://example.org", 30, None));
    fixture.plant_channel(1, vec![record(NOW + 1_000, 1_000)]);
    let mut device = fixture.open().unwrap();
    let mut server = MemoryServer::new(&[HOST]);
    // The purge waits for its records to expire, after the subscription.
    connect_all(&mut device, &mut server, NOW - 5_000);
    run(&mut device, &mut server, NOW - 5_000, NOW);
    fixture.faults.fail_compactions(true);
    let events = run(&mut device, &mut server, NOW + 1_000, NOW + 2_000);
    assert!(events.contains(&Event::StorageFailed { channel: id() }));
    fixture.faults.fail_compactions(false);
    let plan = device.connections()[0].id;
    let events = run(&mut device, &mut server, NOW + 3_000, NOW + 3_000 + MINUTE);
    assert!(events.contains(&Event::Reconnect { connection: plan }));
    assert!(!device.channels()[0].write_failed);
}
