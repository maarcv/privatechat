//! Tests of spec 024-key-retired: a received retirement from a known peer,
//! a stranger and one's own key, and the manual `retire`.

use super::{DAY_MS, HOUR_MS, MARGIN_MS, NOW, pk_of, receiver, reopened, sealed};
use crate::Error;
use crate::crypto::PublicKey;
use crate::proto::payload::PayloadKind;
use crate::session::channel::{Channel, MessageContent, PeerId, Received, Sender};
use crate::storage::state::items::PeerRecord;
use crate::storage::{Content, LogEntry, StoreError};
use crate::testing::state_eq;

const ANN: [u8; 32] = [0x41; 32];
const BOB: [u8; 32] = [0x42; 32];
const CAT: [u8; 32] = [0x43; 32];
const DAN: [u8; 32] = [0x44; 32];

/// The `server_id` of the blob of `seed` at `counter`, `kind` 0 for a text
/// and 1 for a retirement.
fn sid_of(seed: [u8; 32], counter: u64, kind: u8) -> [u8; 16] {
    let mut server_id = [0; 16];
    server_id[..2].copy_from_slice(&seed[..2]);
    server_id[2] = kind;
    server_id[8..].copy_from_slice(&counter.to_be_bytes());
    server_id
}

/// Delivers a text of `seed` at `counter`, sent and received at `NOW`.
fn text(channel: &mut Channel, seed: [u8; 32], counter: u64) -> Result<Option<Received>, Error> {
    let blob = sealed(channel, seed, counter, NOW, PayloadKind::Text, None);
    channel.decrypt(&blob, sid_of(seed, counter, 0), NOW, NOW)
}

/// Delivers a `key_retired` of `seed` at the last counter, as the copy
/// numbered `copy`, sent and received at `NOW`.
fn retirement(channel: &mut Channel, seed: [u8; 32], copy: u64) -> Result<Option<Received>, Error> {
    let blob = sealed(channel, seed, u64::MAX, NOW, PayloadKind::KeyRetired, None);
    channel.decrypt(&blob, sid_of(seed, copy, 1), NOW, NOW)
}

/// The record of `seed`'s key.
fn record_of(channel: &Channel, seed: [u8; 32]) -> Option<&PeerRecord> {
    channel.peer(&PublicKey(pk_of(seed)))
}

/// The `key_retired` message records of the log.
fn retirements_listed(channel: &Channel) -> usize {
    channel
        .records
        .iter()
        .filter(|record| {
            matches!(&record.entry,
                LogEntry::Message(message) if matches!(message.content, Content::KeyRetired))
        })
        .count()
}

/// Spec 024, R1: a labelled, verified peer's retirement retires it with its
/// label and `verified`; every later blob of its key is `RetiredKey` and
/// commits nothing.
#[test]
fn s024_t01_r01_retirement_from_known_peer() {
    let (mut channel, handle, _) = receiver(3_600);
    text(&mut channel, ANN, 0).unwrap();
    channel.label(pk_of(ANN), "Ann", NOW).unwrap();
    channel.verify(pk_of(ANN), None, NOW).unwrap();
    // A retirement that would expire before it is shown, or that no
    // member accepts any more, changes nothing.
    let commits = handle.commits();
    for (copy, sent_at) in [
        (8, NOW - HOUR_MS - 120_000),
        (9, NOW - HOUR_MS - MARGIN_MS - 60_000),
    ] {
        let late = sealed(
            &channel,
            ANN,
            u64::MAX,
            sent_at,
            PayloadKind::KeyRetired,
            None,
        );
        let result = channel.decrypt(&late, sid_of(ANN, copy, 1), NOW, NOW);
        assert_eq!(result, Err(Error::Expired), "{sent_at}");
        assert_eq!(record_of(&channel, ANN).unwrap().retired_at, None);
    }
    assert_eq!(handle.commits(), commits);

    let received = retirement(&mut channel, ANN, 0).unwrap().unwrap();
    assert_eq!(handle.commits(), commits + 1);
    // Its seen record lasts one TTL from `sent_at`, as a text's.
    let seen = channel.records.iter().find(|record| {
        matches!(&record.entry, LogEntry::Seen { sender_pk, counter, .. }
            if sender_pk.0 == pk_of(ANN) && *counter == u64::MAX)
    });
    assert_eq!(seen.map(|record| record.purge_at), Some(NOW + HOUR_MS));
    assert_eq!(received.content, MessageContent::KeyRetired);
    assert_eq!(received.sender, Sender::Peer { pk: pk_of(ANN) });
    assert_eq!(retirements_listed(&channel), 1);
    for stored in [&channel, &reopened(&handle)] {
        let ann = record_of(stored, ANN).unwrap();
        assert_eq!(ann.retired_at, Some(NOW));
        assert_eq!(ann.label.as_deref(), Some("Ann"));
        assert!(ann.verified);
        assert_eq!(ann.max_counter, Some(u64::MAX));
    }

    let commits = handle.commits();
    for counter in [1, 1 << 40] {
        assert_eq!(text(&mut channel, ANN, counter), Err(Error::RetiredKey));
    }
    assert_eq!(retirement(&mut channel, ANN, 1), Err(Error::RetiredKey));
    assert_eq!(handle.commits(), commits);

    // A label alone is enough; a muted labelled peer too.
    text(&mut channel, BOB, 0).unwrap();
    channel.label(pk_of(BOB), "Bob", NOW).unwrap();
    channel.mute(pk_of(BOB), true).unwrap();
    assert!(retirement(&mut channel, BOB, 0).unwrap().is_some());
    let bob = record_of(&channel, BOB).unwrap();
    assert_eq!(bob.retired_at, Some(NOW));
    assert!(bob.muted && !bob.verified);

    // `verified` alone is enough, from a loaded state; `retired_at` and
    // `last_seen` are the arrival's `now`, the listed time its
    // `received_at`.
    let mut next = channel.next_state();
    next.peers.push(PeerRecord {
        pk: PublicKey(pk_of(CAT)),
        label: None,
        verified: true,
        muted: false,
        retired_at: None,
        first_seen: NOW,
        last_seen: NOW,
        max_counter: None,
        last_display_name: None,
    });
    channel.commit(next, Vec::new()).unwrap();
    let later = NOW + 5_000;
    let blob = sealed(&channel, CAT, u64::MAX, NOW, PayloadKind::KeyRetired, None);
    let received = channel.decrypt(&blob, sid_of(CAT, 0, 1), NOW + 1_000, later);
    assert_eq!(received.unwrap().unwrap().received_at, NOW + 1_000);
    let cat = record_of(&channel, CAT).unwrap();
    assert_eq!((cat.retired_at, cat.last_seen), (Some(later), later));
}

/// Spec 024, R2: a stranger's retirement leaves no record and no message;
/// an unknown peer's removes it; a muted unknown stays, its key spent.
#[test]
fn s024_t02_r02_retirement_from_stranger() {
    let (mut channel, handle, _) = receiver(3_600);
    let (commits, all) = (handle.commits(), handle.all_commits());
    assert_eq!(retirement(&mut channel, ANN, 0), Ok(None));
    assert!(record_of(&channel, ANN).is_none());
    assert_eq!(handle.commits(), commits);
    assert_eq!(handle.all_commits(), all + 1);
    assert_eq!(reopened(&handle).state.cursor, Some(NOW));
    // The cursor alone, so a second copy in the same minute commits nothing.
    assert_eq!(retirement(&mut channel, ANN, 1), Ok(None));
    assert_eq!(handle.all_commits(), all + 1);
    assert_eq!(retirements_listed(&channel), 0);

    text(&mut channel, BOB, 0).unwrap();
    let records = channel.records.len();
    channel.take_peers_changed();
    assert_eq!(retirement(&mut channel, BOB, 0), Ok(None));
    assert!(record_of(&channel, BOB).is_none());
    assert!(record_of(&reopened(&handle), BOB).is_none());
    assert_eq!(channel.records.len(), records);
    assert!(channel.take_peers_changed());

    text(&mut channel, DAN, 0).unwrap();
    text(&mut channel, CAT, 0).unwrap();
    channel.mute(pk_of(CAT), true).unwrap();
    let later = NOW + 7_000;
    let blob = sealed(&channel, CAT, u64::MAX, NOW, PayloadKind::KeyRetired, None);
    let result = channel.decrypt(&blob, sid_of(CAT, 0, 1), NOW, later);
    assert_eq!(result, Ok(None));
    assert_eq!(channel.records.len(), records + 4);
    for stored in [&channel, &reopened(&handle)] {
        let cat = record_of(stored, CAT).unwrap();
        assert!(cat.muted && cat.label.is_none() && !cat.verified);
        assert_eq!(cat.retired_at, None);
        assert_eq!((cat.max_counter, cat.last_seen), (Some(u64::MAX), later));
        assert_eq!(record_of(stored, DAN).unwrap().max_counter, Some(0));
    }
    let commits = handle.commits();
    assert_eq!(text(&mut channel, CAT, 9), Err(Error::Replay));
    assert_eq!(handle.commits(), commits);

    // No number of strangers grows the list.
    let (mut channel, _, _) = receiver(3_600);
    for index in 0..530_u16 {
        let mut seed = [0x77; 32];
        seed[..2].copy_from_slice(&index.to_be_bytes());
        text(&mut channel, seed, 0).unwrap();
        assert_eq!(retirement(&mut channel, seed, 0), Ok(None));
    }
    assert!(channel.state.peers.is_empty());
}

/// Spec 024, R3: one's own key retired elsewhere sets `read_only` with the
/// own-key event in one commit, and `encrypt` refuses from then on.
#[test]
fn s024_t03_r03_own_key_retired_elsewhere() {
    let (mut channel, handle, _) = receiver(3_600);
    let own = *channel.state.identity_seed.expose();
    let commits = handle.commits();
    let blob = sealed(&channel, own, u64::MAX, NOW, PayloadKind::KeyRetired, None);
    let received = channel.decrypt(&blob, sid_of(own, 0, 1), NOW, NOW).unwrap();
    let received = received.unwrap();
    assert_eq!(received.sender, Sender::OwnKeyElsewhere { pk: pk_of(own) });
    assert_eq!(handle.commits(), commits + 1);
    let state = &reopened(&handle).state;
    assert!(state.read_only && state.own_key_used_elsewhere);
    assert!(channel.status().read_only);
    assert_eq!(channel.encrypt("hi", None, NOW), Err(Error::RetiredKey));

    // Nothing but spec 025-identity-regen clears it, a later text of
    // one's own key from elsewhere included.
    text(&mut channel, ANN, 0).unwrap();
    text(&mut channel, own, 3).unwrap();
    channel.flush(NOW + 60_000).unwrap();
    assert!(reopened(&handle).state.read_only);
}

/// Spec 024, R4: `retire` refuses a key with no record, retires a peer once
/// with its label kept, and commits nothing the second time.
#[test]
fn s024_t04_r04_manual_retire() {
    let (mut channel, handle, _) = receiver(3_600);
    let commits = handle.all_commits();
    assert_eq!(channel.retire(pk_of(ANN), NOW), Err(Error::UnknownPeer));
    assert_eq!(handle.all_commits(), commits);

    text(&mut channel, ANN, 0).unwrap();
    channel.label(pk_of(ANN), "Ann", NOW).unwrap();
    channel.retire(pk_of(ANN), NOW + 1).unwrap();
    let stored = reopened(&handle);
    let ann = record_of(&stored, ANN).unwrap();
    assert_eq!(ann.retired_at, Some(NOW + 1));
    assert_eq!(ann.label.as_deref(), Some("Ann"));
    assert!(channel.peers().unwrap()[0].retired_at.is_some());

    let commits = handle.all_commits();
    channel.retire(pk_of(ANN), NOW + 2).unwrap();
    assert_eq!(handle.all_commits(), commits);
    assert_eq!(record_of(&channel, ANN).unwrap().retired_at, Some(NOW + 1));
    assert_eq!(text(&mut channel, ANN, 1), Err(Error::RetiredKey));

    // `retire` takes a `now` and may commit, so it records it for the
    // truncation banner (spec 021-channel-session R1), refused or not.
    let (mut channel, handle, _) = receiver(3_600);
    let mut next = channel.next_state();
    next.truncated_at = Some(NOW);
    channel.commit(next, Vec::new()).unwrap();
    let mut channel = reopened(&handle);
    assert!(channel.status().truncated_before.is_some());
    let late = NOW + 2 * DAY_MS;
    assert_eq!(channel.retire(pk_of(ANN), late), Err(Error::UnknownPeer));
    assert_eq!(channel.status().truncated_before, None);
}

/// Spec 024, R5: retiring finds room with 500 labelled peers, and a purge
/// keeps every retired record.
#[test]
fn s024_t05_r05_retire_is_never_refused() {
    let (mut channel, handle, _) = receiver(3_600);
    let mut next = channel.next_state();
    for index in 0..500_u16 {
        let mut pk: PeerId = [0x55; 32];
        pk[..2].copy_from_slice(&index.to_be_bytes());
        next.peers.push(PeerRecord {
            pk: PublicKey(pk),
            label: Some(format!("peer {index}")),
            verified: false,
            muted: false,
            retired_at: None,
            first_seen: NOW,
            last_seen: NOW,
            max_counter: None,
            last_display_name: None,
        });
    }
    channel.commit(next, Vec::new()).unwrap();
    text(&mut channel, ANN, 0).unwrap();
    channel.retire(pk_of(ANN), NOW).unwrap();
    let labelled = channel.state.peers[0].pk.0;
    channel.retire(labelled, NOW).unwrap();

    assert!(channel.purge_expired(NOW + DAY_MS).unwrap() > 0);
    for stored in [&channel, &reopened(&handle)] {
        let retired = stored
            .state
            .peers
            .iter()
            .filter(|peer| peer.retired_at.is_some());
        assert_eq!(retired.count(), 2);
        assert_eq!(stored.state.peers.len(), 501);
    }
}

/// Spec 024, R6: a `retire` whose commit fails leaves memory and the
/// reopened store as they were.
#[test]
fn s024_t06_r06_failing_store() {
    let (mut channel, handle, faults) = receiver(3_600);
    text(&mut channel, ANN, 0).unwrap();
    let before = channel.state.duplicate();
    faults.fail_commits(true);
    assert_eq!(
        channel.retire(pk_of(ANN), NOW),
        Err(Error::Store(StoreError::Io))
    );
    assert!(state_eq(&channel.state, &before));
    assert!(state_eq(&reopened(&handle).state, &before));

    // A received retirement fails the same way on each branch of R1 and R2
    // (AGENTS 23).
    faults.fail_commits(false);
    text(&mut channel, BOB, 0).unwrap();
    text(&mut channel, CAT, 0).unwrap();
    channel.label(pk_of(ANN), "Ann", NOW).unwrap();
    channel.mute(pk_of(CAT), true).unwrap();
    let before = channel.state.duplicate();
    faults.fail_commits(true);
    for seed in [ANN, BOB, CAT] {
        let result = retirement(&mut channel, seed, 0);
        assert_eq!(result, Err(Error::Store(StoreError::Io)));
        assert!(state_eq(&channel.state, &before));
        assert!(state_eq(&reopened(&handle).state, &before));
    }
}
