//! Tests of the recovery of a failed store through the direct calls (spec
//! 027-core-api R14, R15, and R8 for a `write_failed` channel).

use super::dispatch::{PEER, id, opened, with_peer};
use super::{DAY_MS, Fixture, NOW, config};
use crate::Error;
use crate::session::connection::Event;
use crate::storage::{Store, StoreError};
use crate::testing::{MemoryStore, batch, record, settings};

/// Spec 027, R14: a store poisoned during `label` → the error, the
/// channel reopened and `write_failed`, `StorageFailed` queued for the
/// next tick, no `Reconnect`; the reopened channel still answers.
#[test]
fn s027_t14_r14_direct_writer_poisoned() {
    let (fixture, mut device) = opened();
    let id = id();
    fixture.faults.poison_after(1);
    assert_eq!(
        device.label(id, PEER, "ann", NOW),
        Err(Error::Store(StoreError::Io))
    );
    assert_eq!(device.queued, [Event::StorageFailed { channel: id }]);
    let info = &device.channels()[0];
    assert!(info.write_failed);
    // The poisoned commit stood: the reopened state shows it.
    assert_eq!(device.peers(id).unwrap()[0].label.as_deref(), Some("ann"));
    assert!(device.messages(id, NOW).unwrap().is_empty());
    let probe_at = device.channels.first().and_then(|open| open.probe_at);
    assert_eq!(probe_at, Some(NOW + 60_000));
}

/// Spec 027, R14: a store whose commits always fail → one reopen with
/// `StorageFailed`; the marked channel listed and readable, its further
/// failures reopening silently with no event, `leave` working, and the
/// other channels unaffected.
#[test]
fn s027_t14_r14_failing_commits() {
    let (fixture, _) = with_peer();
    fixture.plant_channel(2, Vec::new());
    let mut device = fixture.open().unwrap();
    let id = id();
    let other = config(2).channel_id();
    fixture.faults.fail_commits(true);
    assert!(device.mute(id, PEER, true).is_err());
    assert_eq!(device.queued, [Event::StorageFailed { channel: id }]);
    device.queued.clear();
    assert!(device.label(id, PEER, "ann", NOW).is_err());
    assert!(device.send(id, "hi", None, NOW).is_err());
    assert!(device.queued.is_empty());
    let infos = device.channels();
    assert!(
        infos
            .iter()
            .find(|info| info.id == id)
            .unwrap()
            .write_failed
    );
    assert!(
        !infos
            .iter()
            .find(|info| info.id == other)
            .unwrap()
            .write_failed
    );
    assert!(device.messages(id, NOW).unwrap().is_empty());
    assert!(device.peers(id).is_ok());
    fixture.faults.fail_commits(false);
    device.rename_channel(other, "hall").unwrap();
    device.leave(id).unwrap();
    assert_eq!(device.channels().len(), 1);
}

/// Spec 027, R14: the probe time of a call that takes no `now` counts
/// from the `now` of the last call that carried one.
#[test]
fn s027_t14_r14_probe_time_from_the_latest_now() {
    let (fixture, mut device) = opened();
    let id = id();
    device.label(id, PEER, "ann", NOW + 5_000).unwrap();
    fixture.faults.fail_commits(true);
    assert!(device.mute(id, PEER, true).is_err());
    let probe_at = device.channels.first().and_then(|open| open.probe_at);
    assert_eq!(probe_at, Some(NOW + 65_000));
}

/// Spec 027, R14: a successful writer that changes the status or a peer
/// queues `StatusChanged`; `regenerate_identity` returns it; a reader
/// queues nothing.
#[test]
fn s027_t14_r14_status_changed() {
    let (_fixture, mut device) = opened();
    let id = id();
    device.mute(id, PEER, true).unwrap();
    assert_eq!(device.queued, [Event::StatusChanged { channel: id }]);
    device.queued.clear();
    device.channel_status(id).unwrap();
    device.peers(id).unwrap();
    assert!(device.queued.is_empty());
    let events = device.regenerate_identity(id, NOW).unwrap();
    assert_eq!(events, [Event::StatusChanged { channel: id }]);
    assert!(device.queued.is_empty());
}

/// Spec 027, R14: a reopen that fails moves the channel to `broken`, with
/// its `channel_id` and its local name, and `StorageFailed` queued.
#[test]
fn s027_t14_r14_failed_reopen() {
    let (fixture, mut device) = opened();
    let id = id();
    device.rename_channel(id, "kitchen").unwrap();
    device.queued.clear();
    fixture.faults.poison_after(1);
    fixture.faults.fail_create(true);
    assert!(device.label(id, PEER, "ann", NOW).is_err());
    assert!(device.channels().is_empty());
    assert_eq!(device.queued, [Event::StorageFailed { channel: id }]);
    let broken = device.status().broken;
    assert_eq!(broken.len(), 1);
    assert_eq!(broken[0].reason, StoreError::Io);
    assert_eq!(broken[0].channel_id, Some(id));
    assert_eq!(broken[0].channel_name.as_deref(), Some("kitchen"));
    let dir = fixture.vault.clone();
    let name = crate::storage::Vault::dir_name(&dir, &id).unwrap();
    assert_eq!(broken[0].name, name.to_hex());
}

/// Spec 027, R14: `OutboxFull` from `send` is returned as it is and
/// reopens nothing.
#[test]
fn s027_t14_r14_outbox_full_reopens_nothing() {
    let (_fixture, mut device) = opened();
    let id = id();
    for n in 0..31 {
        device.send(id, &format!("m{n}"), None, NOW).unwrap();
    }
    device.queued.clear();
    assert_eq!(
        device.send(id, "one too many", None, NOW).err(),
        Some(Error::Store(StoreError::OutboxFull))
    );
    assert!(!device.channels()[0].write_failed);
    assert!(device.queued.is_empty());
}

/// Spec 027, R14: a direct `send` on a marked channel poisoned after its
/// rename → reopened silently and `Ok(Sent)`, with no event.
#[test]
fn s027_t14_r14_marked_send_poisoned_after_its_commit() {
    let (fixture, mut device) = opened();
    let id = id();
    fixture.faults.fail_at(1);
    assert!(device.mute(id, PEER, true).is_err());
    device.queued.clear();
    fixture.faults.poison_after(1);
    let sent = device.send(id, "hello", None, NOW).unwrap();
    assert!(sent.events.is_empty());
    assert!(device.queued.is_empty());
    assert_eq!(
        device.messages(id, NOW).unwrap()[0].client_ref,
        Some(sent.client_ref)
    );
    assert!(device.channels()[0].write_failed);
}

/// Spec 027, R14: a reopen keeps the channel's in-session values.
#[test]
fn s027_t14_r14_reopen_carries_the_session() {
    let (fixture, mut device) = opened();
    let id = id();
    // A live sample an hour ahead raises `clock_off` (spec 021 R25).
    device
        .channel_mut(id)
        .unwrap()
        .clock_sample(NOW + 3_600_000, NOW, true);
    let carry = device.channel(id).unwrap().session_carry();
    assert!(device.channel_status(id).unwrap().clock_off);
    fixture.faults.fail_at(1);
    assert!(device.mute(id, PEER, true).is_err());
    assert_eq!(device.channel(id).unwrap().session_carry(), carry);
    assert!(device.channel_status(id).unwrap().clock_off);
}

/// Spec 027, R8: a marked channel whose `leave` fails once is reopened
/// silently and left; one whose `destroy` keeps failing returns the
/// error and stays listed.
#[test]
fn s027_t08_r08_leave_a_marked_channel() {
    let (fixture, mut device) = opened();
    let id = id();
    fixture.faults.fail_at(1);
    assert!(device.mute(id, PEER, true).is_err());
    fixture.faults.fail_at(1);
    device.leave(id).unwrap();
    assert!(device.channels().is_empty());

    let (fixture, mut device) = opened();
    fixture.faults.fail_at(1);
    assert!(device.mute(id, PEER, true).is_err());
    fixture.faults.fail_destroys(true);
    assert_eq!(device.leave(id), Err(Error::Store(StoreError::Io)));
    assert_eq!(device.channels().len(), 1);
    assert!(device.channels()[0].write_failed);

    // An unmarked channel is not retried.
    let (fixture, mut device) = opened();
    fixture.faults.fail_at(1);
    assert_eq!(device.leave(id), Err(Error::Store(StoreError::Io)));
    assert_eq!(device.channels().len(), 1);
    assert!(!device.channels()[0].write_failed);
}

/// Spec 027, R15: a compaction fault during `open` → `open` succeeds, the
/// channel `write_failed` and `StorageFailed` queued for the first tick.
#[test]
fn s027_t15_r15_purge_failure_at_open() {
    let fixture = Fixture::new();
    fixture.save_settings(&settings("wss://example.org", 30, None));
    fixture.plant_channel(1, vec![record(NOW - 1, 1_000), record(NOW + DAY_MS, 10)]);
    fixture.faults.fail_compactions(true);
    let device = fixture.open().unwrap();
    let id = config(1).channel_id();
    assert!(device.channels()[0].write_failed);
    assert!(
        device
            .queued
            .contains(&Event::StorageFailed { channel: id })
    );
    assert_eq!(
        device.channels.first().and_then(|open| open.probe_at),
        Some(NOW + 60_000)
    );
}

/// Spec 027, R15: a direct `purge_expired` that fails is handled by R14.
#[test]
fn s027_t15_r15_direct_purge_failure() {
    let fixture = Fixture::new();
    fixture.save_settings(&settings("wss://example.org", 30, None));
    let dir = fixture.plant_channel(1, Vec::new());
    let mut device = fixture.open().unwrap();
    drop(device);
    let mut store = MemoryStore::handle(&fixture.vault, dir);
    let (state, _) = store.load().unwrap().unwrap();
    store
        .commit(&batch(state, vec![record(NOW + 1_000, 10)]))
        .unwrap();
    device = fixture.open().unwrap();
    let id = config(1).channel_id();
    fixture.faults.fail_compactions(true);
    assert_eq!(
        device.purge_expired(id, NOW + 2_000),
        Err(Error::Store(StoreError::Io))
    );
    assert!(device.channels()[0].write_failed);
    assert_eq!(device.queued, [Event::StorageFailed { channel: id }]);
}
