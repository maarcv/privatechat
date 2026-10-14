//! Tests of the recovery of a failed store through the direct calls (spec
//! 027-core-api R14, R15, and R8 for a `write_failed` channel).

use super::dispatch::{PEER, id, opened, with_peer};
use super::{DAY_MS, Fixture, NOW, SERVER, config};
use crate::Error;
use crate::crypto::PublicKey;
use crate::device::Device;
use crate::proto::fingerprint::verify_qr;
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
    device.leave(id).unwrap();
    assert_eq!(device.channels().len(), 1);
    fixture.faults.fail_commits(false);
    device.rename_channel(other, "hall").unwrap();
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
/// rename → reopened silently and `Ok(Sent)`, with no `StorageFailed` and
/// the `StatusChanged` of a call that stood.
#[test]
fn s027_t14_r14_marked_send_poisoned_after_its_commit() {
    let (fixture, mut device) = opened();
    let id = id();
    fixture.faults.fail_at(1);
    assert!(device.mute(id, PEER, true).is_err());
    device.queued.clear();
    fixture.faults.poison_after(1);
    let sent = device.send(id, "hello", None, NOW).unwrap();
    assert_eq!(sent.events, [Event::StatusChanged { channel: id }]);
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

/// Spec 027, R14: every direct writer goes through the recovery: a store
/// failing during the call → the channel `write_failed` and
/// `StorageFailed` queued.
#[test]
fn s027_t14_r14_every_direct_writer_recovers() {
    let qr = verify_qr(config(1).id(), &PublicKey(PEER)).unwrap();
    type Call = Box<dyn Fn(&mut Device, [u8; 16]) -> bool>;
    let calls: Vec<(&str, Call)> = vec![
        (
            "verify",
            Box::new(|d, id| d.verify(id, PEER, Some("ann"), NOW).is_err()),
        ),
        (
            "verify_scanned",
            Box::new(move |d, id| d.verify_scanned(id, &qr, "ann", NOW).is_err()),
        ),
        ("retire", Box::new(|d, id| d.retire(id, PEER, NOW).is_err())),
        ("forget", Box::new(|d, id| d.forget(id, PEER).is_err())),
        (
            "rename_channel",
            Box::new(|d, id| d.rename_channel(id, "hall").is_err()),
        ),
    ];
    for (name, call) in calls {
        let (fixture, mut device) = opened();
        let id = id();
        fixture.faults.fail_at(1);
        assert!(call(&mut device, id), "{name}");
        assert_eq!(
            device.queued,
            [Event::StorageFailed { channel: id }],
            "{name}"
        );
        assert!(device.channels()[0].write_failed, "{name}");
    }
}

/// Spec 027, R14: a `regenerate_identity` that fails before its commit
/// returns the error and queues `StorageFailed`.
#[test]
fn s027_t14_r14_regeneration_failing_queues_its_event() {
    let (fixture, mut device) = opened();
    let id = id();
    fixture.faults.fail_at(1);
    assert_eq!(
        device.regenerate_identity(id, NOW),
        Err(Error::Store(StoreError::Io))
    );
    assert_eq!(device.queued, [Event::StorageFailed { channel: id }]);
}

/// Spec 027, R14: every call taking `&mut self` that carries a `now` sets
/// the time from which a later call without one counts the probe.
#[test]
fn s027_t14_r14_every_now_times_the_probe() {
    type Call = Box<dyn Fn(&mut Device, [u8; 16], u64)>;
    let calls: Vec<(&str, Call)> = vec![
        (
            "send",
            Box::new(|d, id, now| drop(d.send(id, "hi", None, now).unwrap())),
        ),
        (
            "purge_expired",
            Box::new(|d, id, now| assert_eq!(d.purge_expired(id, now), Ok(0))),
        ),
        (
            "verify",
            Box::new(|d, id, now| d.verify(id, PEER, Some("ann"), now).unwrap()),
        ),
        (
            "retire",
            Box::new(|d, id, now| d.retire(id, PEER, now).unwrap()),
        ),
        (
            "regenerate_identity",
            Box::new(|d, id, now| drop(d.regenerate_identity(id, now).unwrap())),
        ),
        (
            "verify_scanned",
            Box::new(|d, id, now| {
                let qr = verify_qr(config(1).id(), &PublicKey(PEER)).unwrap();
                assert_eq!(d.verify_scanned(id, &qr, "ann", now), Ok(PEER));
            }),
        ),
        (
            "create_channel",
            Box::new(|d, _, now| drop(d.create_channel(SERVER, 3_600, "room", now).unwrap())),
        ),
        (
            "import_qr",
            Box::new(|d, _, now| {
                let qr = config(1).export_qr(NOW).unwrap();
                drop(d.import_qr(&qr, false, now).unwrap());
            }),
        ),
        (
            "import_file",
            Box::new(|d, _, now| {
                let (file, password) = config(1).export_encrypted(NOW).unwrap();
                drop(d.import_file(&file, &password, false, now).unwrap());
            }),
        ),
    ];
    for (name, call) in calls {
        let (fixture, mut device) = opened();
        let id = id();
        call(&mut device, id, NOW + 5_000);
        fixture.faults.fail_commits(true);
        assert!(device.rename_channel(id, "hall").is_err(), "{name}");
        let probe_at = device.channels.first().and_then(|open| open.probe_at);
        assert_eq!(probe_at, Some(NOW + 65_000), "{name}");
    }
}

/// Spec 027, R14: a reopen takes the fresh instance's peers flag, so a
/// later writer that changes nothing raises no `StatusChanged`.
#[test]
fn s027_t14_r14_reopen_takes_the_peers_flag() {
    let (fixture, mut device) = opened();
    let id = id();
    fixture.faults.fail_at(1);
    assert!(device.mute(id, PEER, true).is_err());
    device.queued.clear();
    assert_eq!(device.purge_expired(id, NOW), Ok(0));
    assert!(device.queued.is_empty());
}

/// Spec 027, R7 and R14: a reopened channel keeps its place in
/// `channels()`.
#[test]
fn s027_t14_r14_reopen_keeps_the_order() {
    let (fixture, _) = with_peer();
    fixture.plant_channel(2, Vec::new());
    let mut device = fixture.open().unwrap();
    let before: Vec<[u8; 16]> = device.channels().iter().map(|info| info.id).collect();
    fixture.faults.fail_at(1);
    assert!(device.rename_channel(before[0], "hall").is_err());
    let after: Vec<[u8; 16]> = device.channels().iter().map(|info| info.id).collect();
    assert_eq!(after, before);
}

/// Spec 027, R8 and R14: a marked channel whose silent reopen in `leave`
/// fails moves to `broken` with `StorageFailed` queued.
#[test]
fn s027_t08_r08_leave_reopen_fails() {
    let (fixture, mut device) = opened();
    let id = id();
    fixture.faults.fail_at(1);
    assert!(device.mute(id, PEER, true).is_err());
    device.queued.clear();
    fixture.faults.fail_at(1);
    fixture.faults.fail_create(true);
    assert_eq!(device.leave(id), Err(Error::Store(StoreError::Io)));
    assert!(device.channels().is_empty());
    assert_eq!(device.status().broken[0].channel_id, Some(id));
    assert_eq!(device.queued, [Event::StorageFailed { channel: id }]);
}

/// Spec 027, R14: a direct writer that meets `Corrupt` reopens too, and
/// a state that no longer opens moves the channel to `broken`.
#[test]
fn s027_t14_r14_corrupt_state_breaks_the_channel() {
    let (fixture, dir) = with_peer();
    let mut device = fixture.open().unwrap();
    let id = id();
    let (_, log) = fixture.vault.get_raw(&dir);
    fixture
        .vault
        .put_raw(&dir, Some(b"not a state"), log.as_deref());
    assert_eq!(
        device.mute(id, PEER, true),
        Err(Error::Store(StoreError::Corrupt))
    );
    assert!(device.channels().is_empty());
    assert_eq!(device.status().broken[0].reason, StoreError::Corrupt);
    assert_eq!(device.queued, [Event::StorageFailed { channel: id }]);
}

/// Spec 027, R14: `regenerate_identity` on a marked channel poisoned
/// after its rename → `Ok`, and the status change it made is reported.
#[test]
fn s027_t14_r14_marked_regeneration_reports_its_status() {
    let (fixture, mut device) = opened();
    let id = id();
    fixture.faults.fail_at(1);
    assert!(device.mute(id, PEER, true).is_err());
    device.queued.clear();
    fixture.faults.poison_after(1);
    let events = device.regenerate_identity(id, NOW).unwrap();
    assert!(device.channel_status(id).unwrap().retirement_pending);
    assert_eq!(events, [Event::StatusChanged { channel: id }]);
}

/// Spec 027, R9 and spec 021 R33: after a regeneration, a `send` whose
/// commit fails before its rename is not taken for the entry still waiting
/// under the retired key with the same counter.
#[test]
fn s027_t09_r09_send_after_a_regeneration_failing() {
    let (fixture, mut device) = opened();
    let id = id();
    let waiting = device.send(id, "before", None, NOW).unwrap();
    device.regenerate_identity(id, NOW).unwrap();
    fixture.faults.fail_at(1);
    assert_eq!(
        device.send(id, "after", None, NOW).err(),
        Some(Error::Store(StoreError::Io))
    );
    let messages = device.messages(id, NOW).unwrap();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].client_ref, Some(waiting.client_ref));
}

/// Plants the own-key alert in channel 1 of `fixture`, before it opens.
fn plant_alert(fixture: &Fixture) {
    let dir = crate::storage::Vault::dir_name(&fixture.vault.clone(), &id()).unwrap();
    let mut store = MemoryStore::handle(&fixture.vault, dir);
    let (mut state, _) = store.load().unwrap().unwrap();
    state.own_key_used_elsewhere = true;
    store.commit(&batch(state, Vec::new())).unwrap();
}

/// Spec 027, R14 and R9: `regenerate_identity` after an own-key alert →
/// `StatusChanged` in its events and the alert cleared; poisoned after
/// its rename → `Ok` and no alert in `status()`.
#[test]
fn s027_t14_r14_regeneration_after_an_alert() {
    for poisoned in [false, true] {
        let (fixture, _) = with_peer();
        plant_alert(&fixture);
        let mut device = fixture.open().unwrap();
        let id = id();
        assert!(device.channel_status(id).unwrap().own_key_used_elsewhere);
        if poisoned {
            fixture.faults.poison_after(1);
        }
        let events = device.regenerate_identity(id, NOW).unwrap();
        let expected = if poisoned {
            Event::StorageFailed { channel: id }
        } else {
            Event::StatusChanged { channel: id }
        };
        assert_eq!(events, [expected]);
        let status = device.channel_status(id).unwrap();
        assert!(!status.own_key_used_elsewhere);
        assert!(status.retirement_pending);
    }
}

/// Spec 027, R14: a reopen keeps the gaps and the ignored keys of the
/// session, not only `clock_off`.
#[test]
fn s027_t14_r14_reopen_carries_gaps_and_ignored_keys() {
    let (fixture, mut device) = opened();
    let id = id();
    let carry = crate::session::channel::SessionCarry::for_tests(PEER, [0x77; 32]);
    device.channel_mut(id).unwrap().carry_session(carry.clone());
    assert_eq!(device.gaps(id).unwrap().len(), 1);
    assert_eq!(device.channel_status(id).unwrap().ignored_keys, 1);
    fixture.faults.fail_at(1);
    assert!(device.mute(id, PEER, true).is_err());
    assert_eq!(device.channel(id).unwrap().session_carry(), carry);
    assert_eq!(device.gaps(id).unwrap().len(), 1);
    assert_eq!(device.channel_status(id).unwrap().ignored_keys, 1);
}

/// Spec 027, R9: a `send` whose commit fails before its rename, with an
/// earlier message of the same key still waiting, is not taken for that
/// earlier entry.
#[test]
fn s027_t09_r09_send_failing_with_an_earlier_entry_waiting() {
    let (fixture, mut device) = opened();
    let id = id();
    let waiting = device.send(id, "before", None, NOW).unwrap();
    fixture.faults.fail_at(1);
    assert_eq!(
        device.send(id, "after", None, NOW).err(),
        Some(Error::Store(StoreError::Io))
    );
    let messages = device.messages(id, NOW).unwrap();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].client_ref, Some(waiting.client_ref));
}

/// Spec 027, R14: a marked channel whose silent reopen in a direct writer
/// fails moves to `broken` with `StorageFailed` queued.
#[test]
fn s027_t14_r14_marked_reopen_fails() {
    let (fixture, mut device) = opened();
    let id = id();
    fixture.faults.fail_at(1);
    assert!(device.mute(id, PEER, true).is_err());
    device.queued.clear();
    fixture.faults.fail_at(1);
    fixture.faults.fail_create(true);
    assert!(device.label(id, PEER, "ann", NOW).is_err());
    assert!(device.channels().is_empty());
    assert_eq!(device.status().broken[0].channel_id, Some(id));
    assert_eq!(device.queued, [Event::StorageFailed { channel: id }]);
}

/// Spec 027, R14: `LogFull` from `send` is returned as it is and reopens
/// nothing.
#[test]
fn s027_t14_r14_log_full_reopens_nothing() {
    let (_fixture, mut device) = opened();
    let id = id();
    // One byte inside spec 021 R18's headroom.
    let full = crate::storage::MAX_LOG_LEN - 1_114_156 + 1;
    let channel = device.channel_mut(id).unwrap();
    channel.fill_log(NOW + DAY_MS, full);
    // The flag a loaded channel starts with (spec 021 R1).
    channel.take_peers_changed();
    assert_eq!(
        device.send(id, "hi", None, NOW).err(),
        Some(Error::Store(StoreError::LogFull))
    );
    assert!(!device.channels()[0].write_failed);
    assert!(device.queued.is_empty());
}

/// Spec 027, R14: a `send` on a marked channel poisoned after its rename
/// that changed one's own name reports `StatusChanged`, as the same call
/// on an unmarked channel does.
#[test]
fn s027_t14_r14_marked_send_reports_a_new_own_name() {
    let (fixture, mut device) = opened();
    let id = id();
    fixture.faults.fail_at(1);
    assert!(device.mute(id, PEER, true).is_err());
    device.queued.clear();
    fixture.faults.poison_after(1);
    let sent = device.send(id, "hello", Some("newname"), NOW).unwrap();
    assert_eq!(
        device.channels()[0].own_display_name.as_deref(),
        Some("newname")
    );
    assert_eq!(sent.events, [Event::StatusChanged { channel: id }]);
}

/// Spec 027, R14: a further failure of a marked channel keeps its probe
/// time, and its silent reopen takes the fresh instance's peers flag.
#[test]
fn s027_t14_r14_marked_failure_keeps_the_mark() {
    let (fixture, mut device) = opened();
    let id = id();
    fixture.faults.fail_at(1);
    assert!(device.mute(id, PEER, true).is_err());
    fixture.faults.fail_at(1);
    assert!(device.label(id, PEER, "ann", NOW + 30_000).is_err());
    let probe_at = device.channels.first().and_then(|open| open.probe_at);
    assert_eq!(probe_at, Some(NOW + 60_000));
    device.queued.clear();
    assert_eq!(device.purge_expired(id, NOW + 30_000), Ok(0));
    assert!(device.queued.is_empty());
}
