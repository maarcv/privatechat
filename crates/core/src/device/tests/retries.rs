//! Tests of the retry of `broken` entries on the tick (spec 027-core-api
//! R12, and R3 and R5 for what makes it due).

use super::dispatch::{PEER, id, opened};
use super::tick::{MINUTE, TEN_MINUTES};
use super::{NOW, config};
use crate::device::Device;
use crate::session::connection::Event;
use crate::storage::StoreError;
use crate::testing::Faults;

/// Breaks channel 1 through a failing direct writer whose reopen fails,
/// at `NOW`, with every later `Vault::create` failing too.
fn break_channel(faults: &Faults, device: &mut Device) {
    faults.poison_after(1);
    faults.fail_create(true);
    assert!(device.label(id(), PEER, "ann", NOW).is_err());
    device.on_tick(NOW);
    let broken = device.status().broken;
    let entry = broken
        .iter()
        .find(|entry| entry.channel_id == Some(id()))
        .unwrap();
    assert_eq!(entry.reason, StoreError::Io);
}

/// Spec 027, R12: an `Io` entry with a `channel_id` is not retried before
/// ten minutes; a retry that fails updates the entry and waits ten more
/// minutes; once the store reads again the next due tick brings the
/// channel back with `StatusChanged`, listed and out of `broken`.
#[test]
fn s027_t12_r12_retry_of_a_broken_entry() {
    let (fixture, mut device) = opened();
    break_channel(&fixture.faults, &mut device);
    assert!(device.on_tick(NOW + TEN_MINUTES - 1_000).is_empty());
    // Due: it fails again and waits ten more minutes.
    assert!(device.on_tick(NOW + TEN_MINUTES).is_empty());
    assert_eq!(device.status().broken.len(), 1);
    fixture.faults.fail_create(false);
    assert!(device.on_tick(NOW + 2 * TEN_MINUTES - 1_000).is_empty());
    assert_eq!(
        device.on_tick(NOW + 2 * TEN_MINUTES),
        [Event::StatusChanged { channel: id() }]
    );
    assert!(device.status().broken.is_empty());
    assert_eq!(device.channels()[0].id, id());
    assert_eq!(device.connections()[0].channels, [id()]);
}

/// Spec 027, R12: a retry that finds the directory corrupt records
/// `Corrupt`, which stops the retries.
#[test]
fn s027_t12_r12_corrupt_stops_the_retries() {
    let (fixture, mut device) = opened();
    break_channel(&fixture.faults, &mut device);
    fixture.faults.fail_create(false);
    let dir = crate::storage::Vault::dir_name(&fixture.vault.clone(), &id()).unwrap();
    fixture.vault.put_raw(&dir, Some(b"not a state"), None);
    device.on_tick(NOW + TEN_MINUTES);
    assert_eq!(device.status().broken[0].reason, StoreError::Corrupt);
    let (state, log) = (None::<&[u8]>, None::<&[u8]>);
    fixture.vault.put_raw(&dir, state, log);
    assert!(device.on_tick(NOW + 3 * TEN_MINUTES).is_empty());
    assert_eq!(device.status().broken.len(), 1);
}

/// Spec 027, R12: with the clock set back, a recorded time later than
/// `now` counts as passed and the next tick retries.
#[test]
fn s027_t12_r12_retry_after_a_clock_set_back() {
    let (fixture, mut device) = opened();
    break_channel(&fixture.faults, &mut device);
    fixture.faults.fail_create(false);
    assert_eq!(
        device.on_tick(NOW - MINUTE),
        [Event::StatusChanged { channel: id() }]
    );
    assert!(device.status().broken.is_empty());
}

/// Spec 027, R3: a `leave` of another channel makes the retry due at the
/// next tick and the probe of a marked channel at the tick after, one
/// reopen a tick.
#[test]
fn s027_t03_r03_leave_makes_the_retries_due() {
    let (fixture, _) = super::dispatch::with_peer();
    fixture.plant_channel(2, Vec::new());
    fixture.plant_channel(3, Vec::new());
    let mut device = fixture.open().unwrap();
    device.on_tick(NOW);
    break_channel(&fixture.faults, &mut device);
    fixture.faults.fail_create(false);
    fixture.faults.fail_at(1);
    let marked = config(2).channel_id();
    assert!(device.rename_channel(marked, "x").is_err());
    device.on_tick(NOW + 1_000);
    device.leave(config(3).channel_id()).unwrap();
    assert_eq!(
        device.on_tick(NOW + 2_000),
        [Event::StatusChanged { channel: id() }]
    );
    assert!(
        device
            .channels()
            .iter()
            .any(|info| info.id == marked && info.write_failed)
    );
    assert_eq!(
        device.on_tick(NOW + 3_000),
        [Event::StatusChanged { channel: marked }]
    );
}

/// Spec 027, R3: an `Io` entry with a `channel_id` is removed by
/// `remove_broken`, and another entry's retry is due at the next tick.
#[test]
fn s027_t03_r03_remove_broken_makes_the_retries_due() {
    let (fixture, mut device) = opened();
    let corrupt = fixture.plant_corrupt(0xc0);
    drop(device);
    device = fixture.open().unwrap();
    break_channel(&fixture.faults, &mut device);
    fixture.faults.fail_create(false);
    device.remove_broken(&corrupt.to_hex()).unwrap();
    assert_eq!(
        device.on_tick(NOW + 1_000),
        [Event::StatusChanged { channel: id() }]
    );

    let (fixture, mut device) = opened();
    break_channel(&fixture.faults, &mut device);
    let name = device.status().broken[0].name.clone();
    fixture.faults.fail_create(false);
    device.remove_broken(&name).unwrap();
    assert!(device.status().broken.is_empty());
    assert!(device.on_tick(NOW + TEN_MINUTES).is_empty());
}

/// Spec 027, R5: an `Io` entry from `open`, whose import retry fails with
/// `Io`, carries the `channel_id` and is retried by the next due tick.
#[test]
fn s027_t05_r05_failed_import_retry_is_retried_on_the_tick() {
    let (fixture, device) = opened();
    drop(device);
    fixture.faults.fail_loads(true);
    let mut device = fixture.open().unwrap();
    let qr = config(1).export_qr(NOW).unwrap();
    assert!(device.import_qr(&qr, false, NOW).is_err());
    assert_eq!(device.status().broken[0].channel_id, Some(id()));
    fixture.faults.fail_loads(false);
    assert!(device.on_tick(NOW + TEN_MINUTES - 1_000).is_empty());
    assert_eq!(
        device.on_tick(NOW + TEN_MINUTES),
        [Event::StatusChanged { channel: id() }]
    );
}
