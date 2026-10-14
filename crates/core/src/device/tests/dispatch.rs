//! Tests of the per-channel calls (spec 027-core-api R9).

use super::{Fixture, NOW, config};
use crate::Error;
use crate::crypto::PublicKey;
use crate::device::Device;
use crate::proto::fingerprint::verify_qr;
use crate::session::connection::Event;
use crate::storage::state::items::PeerRecord;
use crate::storage::{DirName, Store, StoreError};
use crate::testing::{MemoryStore, batch, settings};

/// A peer's public key, any 32 bytes.
pub(super) const PEER: [u8; 32] = [0x5e; 32];

/// A peer record of `pk`, unknown to the user.
pub(super) fn peer(pk: [u8; 32]) -> PeerRecord {
    PeerRecord {
        pk: PublicKey(pk),
        label: None,
        verified: false,
        muted: false,
        retired_at: None,
        first_seen: NOW,
        last_seen: NOW,
        max_counter: None,
        last_display_name: None,
    }
}

/// A fixture with saved settings and channel 1 holding the peer `PEER`,
/// and the channel's directory.
pub(super) fn with_peer() -> (Fixture, DirName) {
    let fixture = Fixture::new();
    fixture.save_settings(&settings("wss://example.org", 30, None));
    let dir = fixture.plant_channel(1, Vec::new());
    let mut store = MemoryStore::handle(&fixture.vault, dir);
    let (mut state, _) = store.load().unwrap().unwrap();
    state.peers.push(peer(PEER));
    store.commit(&batch(state, Vec::new())).unwrap();
    (fixture, dir)
}

/// The `channel_id` of channel 1.
pub(super) fn id() -> [u8; 16] {
    config(1).channel_id()
}

/// Spec 027, R9: every per-channel call with an unknown id is
/// `UnknownChannel` and commits nothing.
#[test]
fn s027_t09_r09_unknown_channel() {
    let (fixture, dir) = with_peer();
    let mut device = fixture.open().unwrap();
    let handle = MemoryStore::handle(&fixture.vault, dir);
    let commits = handle.all_commits();
    let unknown = [0xee; 16];
    let qr = verify_qr(config(1).id(), &PublicKey(PEER)).unwrap();
    assert_eq!(
        device.send(unknown, "hi", None, NOW).err(),
        Some(Error::UnknownChannel)
    );
    assert_eq!(
        device.messages(unknown, NOW).err(),
        Some(Error::UnknownChannel)
    );
    assert_eq!(
        device.purge_expired(unknown, NOW),
        Err(Error::UnknownChannel)
    );
    assert_eq!(
        device.channel_status(unknown).err(),
        Some(Error::UnknownChannel)
    );
    assert_eq!(device.gaps(unknown).err(), Some(Error::UnknownChannel));
    assert_eq!(device.peers(unknown).err(), Some(Error::UnknownChannel));
    assert_eq!(
        device.label(unknown, PEER, "ann", NOW),
        Err(Error::UnknownChannel)
    );
    assert_eq!(
        device.verify(unknown, PEER, Some("ann"), NOW),
        Err(Error::UnknownChannel)
    );
    assert_eq!(
        device.verify_scanned(unknown, &qr, "ann", NOW),
        Err(Error::UnknownChannel)
    );
    assert_eq!(device.mute(unknown, PEER, true), Err(Error::UnknownChannel));
    assert!(matches!(
        device.fingerprint(unknown, PEER),
        Err(Error::UnknownChannel)
    ));
    assert!(matches!(
        device.own_fingerprint(unknown),
        Err(Error::UnknownChannel)
    ));
    assert_eq!(
        device.retire(unknown, PEER, NOW),
        Err(Error::UnknownChannel)
    );
    assert_eq!(
        device.regenerate_identity(unknown, NOW),
        Err(Error::UnknownChannel)
    );
    assert_eq!(
        device.own_old_keys(unknown).err(),
        Some(Error::UnknownChannel)
    );
    assert_eq!(device.forget(unknown, PEER), Err(Error::UnknownChannel));
    assert_eq!(handle.all_commits(), commits);
    assert!(device.queued.is_empty());
}

/// Spec 027, R9: with a known id each call returns what the `Channel`
/// method returns.
#[test]
fn s027_t09_r09_dispatch() {
    let (fixture, _) = with_peer();
    let mut device = fixture.open().unwrap();
    let id = id();
    let sent = device.send(id, "hello", Some("me"), NOW).unwrap();
    assert_eq!(sent.message.client_ref, Some(sent.client_ref));
    let messages = device.messages(id, NOW).unwrap();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0], sent.message);
    assert_eq!(device.channels()[0].own_display_name.as_deref(), Some("me"));

    device.label(id, PEER, "ann", NOW).unwrap();
    let peers = device.peers(id).unwrap();
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].label.as_deref(), Some("ann"));
    assert_eq!(
        device.label(id, [0x01; 32], "bob", NOW),
        Err(Error::UnknownPeer)
    );
    device.mute(id, PEER, true).unwrap();
    assert!(device.peers(id).unwrap()[0].muted);
    device.verify(id, PEER, None, NOW).unwrap();
    assert!(device.peers(id).unwrap()[0].verified);
    let qr = verify_qr(config(1).id(), &PublicKey(PEER)).unwrap();
    assert_eq!(device.verify_scanned(id, &qr, "ann", NOW), Ok(PEER));
    assert_eq!(
        device.fingerprint(id, PEER).unwrap(),
        crate::proto::fingerprint::presentation(config(1).id(), &PublicKey(PEER)).unwrap()
    );
    device.own_fingerprint(id).unwrap();
    assert!(device.gaps(id).unwrap().is_empty());
    assert!(!device.channel_status(id).unwrap().retirement_pending);
    assert_eq!(device.purge_expired(id, NOW), Ok(0));

    let events = device.regenerate_identity(id, NOW).unwrap();
    assert_eq!(events, [Event::StatusChanged { channel: id }]);
    assert!(device.channel_status(id).unwrap().retirement_pending);
    assert_eq!(device.own_old_keys(id).unwrap().len(), 1);
    assert_eq!(
        device.regenerate_identity(id, NOW),
        Err(Error::RetirementPending)
    );
    device.retire(id, PEER, NOW).unwrap();
    assert!(device.peers(id).unwrap()[0].retired_at.is_some());
    device.forget(id, PEER).unwrap();
    assert!(device.peers(id).unwrap().is_empty());
    assert_eq!(device.forget(id, PEER), Err(Error::UnknownPeer));
}

/// Spec 027, R9: a `send` whose commit is let through and then poisoned
/// → `Ok(Sent)` with the entry's `ClientRef`, and `StorageFailed` among
/// its events.
#[test]
fn s027_t09_r09_send_poisoned_after_its_commit() {
    let (fixture, _) = with_peer();
    let mut device = fixture.open().unwrap();
    let id = id();
    fixture.faults.poison_after(1);
    let sent = device.send(id, "hello", None, NOW).unwrap();
    assert_eq!(sent.events, [Event::StorageFailed { channel: id }]);
    let messages = device.messages(id, NOW).unwrap();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].client_ref, Some(sent.client_ref));
    assert_eq!(sent.message, messages[0]);
    assert!(device.channels()[0].write_failed);
}

/// Spec 027, R9: a `send` whose commit fails before its rename returns
/// its error, and `StorageFailed` waits for the next tick.
#[test]
fn s027_t09_r09_send_failing_before_its_commit() {
    let (fixture, _) = with_peer();
    let mut device = fixture.open().unwrap();
    let id = id();
    fixture.faults.fail_at(1);
    assert_eq!(
        device.send(id, "hello", None, NOW).err(),
        Some(Error::Store(StoreError::Io))
    );
    assert!(device.messages(id, NOW).unwrap().is_empty());
    assert_eq!(device.queued, [Event::StorageFailed { channel: id }]);
}

/// Spec 027, R9: `regenerate_identity` poisoned after its rename → `Ok`,
/// the retirement pending.
#[test]
fn s027_t09_r09_regeneration_poisoned_after_its_commit() {
    let (fixture, _) = with_peer();
    let mut device = fixture.open().unwrap();
    let id = id();
    fixture.faults.poison_after(1);
    let events = device.regenerate_identity(id, NOW).unwrap();
    assert_eq!(events, [Event::StorageFailed { channel: id }]);
    assert!(device.channel_status(id).unwrap().retirement_pending);
}

/// The device of `with_peer`, for the tests that need one quickly.
pub(super) fn opened() -> (Fixture, Device) {
    let (fixture, _) = with_peer();
    let device = fixture.open().unwrap();
    (fixture, device)
}
