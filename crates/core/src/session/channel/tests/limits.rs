//! Tests of spec 026-peer-limits: the two budgets, the room check, the
//! eviction of strangers, the labelled budget, `forget` and the ignored
//! keys.

use super::super::limits::{
    MAX_IGNORED_TRACKED, MAX_LABELLED_PEERS, MAX_UNKNOWN_PEERS, is_unknown,
};
use super::{HOUR_MS, NOW, own_text, pk_of, receiver, reopened, sealed};
use crate::Error;
use crate::crypto::PublicKey;
use crate::proto::fingerprint::verify_qr;
use crate::proto::payload::PayloadKind;
use crate::session::channel::{Channel, Received};
use crate::storage::StoreError;
use crate::storage::state::MAX_PEERS;
use crate::storage::state::items::PeerRecord;
use crate::testing::state_eq;

/// The seed of the `n`-th stranger.
fn stranger(n: u16) -> [u8; 32] {
    let mut seed = [0x5a; 32];
    seed[..2].copy_from_slice(&n.to_be_bytes());
    seed
}

/// An unknown record of `seed`, last heard from at `last_seen`.
fn unknown(seed: [u8; 32], last_seen: u64, muted: bool) -> PeerRecord {
    PeerRecord {
        muted,
        first_seen: last_seen,
        last_seen,
        ..unknown_with_pk(pk_of(seed))
    }
}

/// The `n`-th labelled record, under a key no test signs with.
fn labelled(n: u16) -> PeerRecord {
    let mut pk = [0x4c; 32];
    pk[..2].copy_from_slice(&n.to_be_bytes());
    PeerRecord {
        label: Some(format!("peer {n}")),
        ..unknown_with_pk(pk)
    }
}

/// An unknown record of the raw key `pk`.
fn unknown_with_pk(pk: [u8; 32]) -> PeerRecord {
    PeerRecord {
        pk: PublicKey(pk),
        label: None,
        verified: false,
        muted: false,
        retired_at: None,
        first_seen: NOW,
        last_seen: NOW,
        max_counter: Some(10),
        last_display_name: None,
    }
}

/// Plants `peers` as the channel's records.
fn plant(channel: &mut Channel, peers: Vec<PeerRecord>) {
    let mut next = channel.next_state();
    next.peers = peers;
    channel.commit(next, Vec::new()).unwrap();
}

/// `count` labelled records and the strangers `1..=unknowns`, heard from
/// at `NOW + n`, all muted when `muted`.
fn crowd(count: u16, unknowns: u16, muted: bool) -> Vec<PeerRecord> {
    (0..count)
        .map(labelled)
        .chain((1..=unknowns).map(|n| unknown(stranger(n), NOW + u64::from(n), muted)))
        .collect()
}

/// A text of `seed` at `counter`, sent and received at `at`, under a
/// `server_id` of its own.
fn text(
    channel: &mut Channel,
    seed: [u8; 32],
    counter: u64,
    at: u64,
) -> Result<Option<Received>, Error> {
    // `sent_at` is a whole minute (spec 013 R8); `at` is the arrival.
    let blob = sealed(
        channel,
        seed,
        counter,
        at - at % 60_000,
        PayloadKind::Text,
        None,
    );
    let mut server_id = [0; 16];
    server_id[..2].copy_from_slice(&seed[..2]);
    server_id[8..].copy_from_slice(&counter.to_be_bytes());
    channel.decrypt(&blob, server_id, at, at)
}

/// Whether `seed`'s key has a record.
fn has_record(channel: &Channel, seed: [u8; 32]) -> bool {
    channel.peer(&PublicKey(pk_of(seed))).is_some()
}

/// Spec 026, R1: unknown is no label, not verified and not retired, muted
/// or not; any of the three puts a peer in the labelled budget.
#[test]
fn s026_t01_r01_budgets() {
    let muted = unknown(stranger(1), NOW, true);
    assert!(is_unknown(&muted));
    assert!(is_unknown(&unknown(stranger(2), NOW, false)));
    let verified = PeerRecord {
        verified: true,
        ..unknown(stranger(3), NOW, false)
    };
    let retired = PeerRecord {
        retired_at: Some(NOW),
        ..unknown(stranger(4), NOW, false)
    };
    for peer in [labelled(0), verified, retired] {
        assert!(!is_unknown(&peer));
    }
}

/// Spec 026, R2: a new key finds room while an unmuted stranger can make
/// it, below both limits, or never when every stranger is muted at a
/// limit; one's own key is never refused.
#[test]
fn s026_t02_r02_room_check() {
    let newcomer = stranger(900);
    let mut one_unmuted = crowd(0, 50, true);
    one_unmuted[7].muted = false;
    let mut full_one_unmuted = crowd(500, 50, true);
    full_one_unmuted[503].muted = false;
    for (peers, room) in [
        (crowd(0, 49, true), true),
        // Labelled peers do not count against the 50.
        (crowd(10, 40, true), true),
        (crowd(500, 10, true), true),
        (one_unmuted, true),
        (crowd(0, 50, true), false),
        (full_one_unmuted, true),
        (crowd(500, 50, true), false),
        // 501 after a retirement by hand, and 49 muted strangers: 550.
        (crowd(501, 49, true), false),
    ] {
        let (mut channel, handle, _) = receiver(3_600);
        plant(&mut channel, peers);
        let commits = handle.commits();
        let result = text(&mut channel, newcomer, 0, NOW);
        if room {
            assert!(matches!(result, Ok(Some(_))), "{result:?}");
            assert!(has_record(&channel, newcomer));
        } else {
            assert_eq!(result, Err(Error::PeerLimit));
            assert_eq!(handle.commits(), commits);
            assert!(!has_record(&channel, newcomer));
            // Sealed elsewhere: the own-key alert, never a peer.
            let own = own_text(&channel, 0, NOW);
            let result = channel.decrypt(&own, [0xee; 16], NOW, NOW);
            assert!(matches!(result, Ok(Some(_))), "{result:?}");
            assert!(channel.status().own_key_used_elsewhere);
        }
    }
}

/// Spec 026, R2: only a key with no record is checked for room: at a
/// limit with every stranger muted, a labelled peer and a muted stranger
/// already known still write.
#[test]
fn s026_t02_r02_known_keys_need_no_room() {
    let (mut channel, _, _) = receiver(3_600);
    let mut peers = crowd(499, 50, true);
    peers.push(PeerRecord {
        label: Some("Ann".to_owned()),
        ..unknown(stranger(700), NOW, false)
    });
    plant(&mut channel, peers);
    assert!(channel.status().unknown_limit_reached);
    assert!(matches!(
        text(&mut channel, stranger(700), 11, NOW),
        Ok(Some(_))
    ));
    assert!(text(&mut channel, stranger(1), 11, NOW).is_ok());
    assert_eq!(channel.status().ignored_keys, 0);
}

/// Spec 026, R2: the room check comes after the retired check, so one's
/// own old key is `RetiredKey` and never counted, and before the
/// `server_id` replay check of step 6.
#[test]
fn s026_t02_r02_room_check_order() {
    let (mut channel, _, _) = receiver(3_600);
    let old_seed = *channel.state.identity_seed.expose();
    text(&mut channel, stranger(800), 0, NOW).unwrap();
    channel.regenerate_identity(NOW).unwrap();
    plant(&mut channel, crowd(0, 50, true));
    let old = sealed(&channel, old_seed, 3, NOW, PayloadKind::Text, None);
    assert_eq!(
        channel.decrypt(&old, [0x77; 16], NOW, NOW),
        Err(Error::RetiredKey)
    );
    assert_eq!(channel.status().ignored_keys, 0);
    // `stranger(800)`'s message left a seen record under this `server_id`.
    let mut seen = [0; 16];
    seen[..2].copy_from_slice(&stranger(800)[..2]);
    let blob = sealed(&channel, stranger(900), 0, NOW, PayloadKind::Text, None);
    assert_eq!(
        channel.decrypt(&blob, seen, NOW, NOW),
        Err(Error::PeerLimit)
    );
}

/// Spec 026, R3: a key that needs room evicts the unmuted stranger heard
/// from longest ago, ties to the smaller key, never a muted or a retired
/// one and never itself; the evicted key writing again is a new unknown,
/// its gap gone with its record.
#[test]
fn s026_t03_r03_lru_eviction() {
    let (mut channel, _, _) = receiver(3_600);
    let mut peers = crowd(0, 50, false);
    // The retired record and the muted stranger are older than everyone.
    peers.push(PeerRecord {
        retired_at: Some(NOW),
        ..unknown(stranger(70), NOW - 10, false)
    });
    peers[0].muted = true;
    peers[0].last_seen = NOW - 5;
    // Strangers 2 and 3 are the oldest unmuted ones, tied, the larger key
    // first in the list so that the order of the list cannot break the tie.
    peers[1].last_seen = NOW - 1;
    peers[2].last_seen = NOW - 1;
    if peers[1].pk.0 < peers[2].pk.0 {
        peers.swap(1, 2);
    }
    plant(&mut channel, peers);
    let (two, three) = (pk_of(stranger(2)), pk_of(stranger(3)));
    let (smaller, larger) = if two < three {
        (stranger(2), stranger(3))
    } else {
        (stranger(3), stranger(2))
    };

    // `now` below every `last_seen`: every stranger ranks as stamped ahead,
    // still oldest first, ties to the smaller key.
    let newcomer = stranger(900);
    channel.take_peers_changed();
    text(&mut channel, newcomer, 0, NOW - 3_600).unwrap();
    assert!(channel.take_peers_changed());
    assert!(has_record(&channel, newcomer));
    assert!(!has_record(&channel, smaller));
    assert!(has_record(&channel, larger));
    assert!(has_record(&channel, stranger(1)) && has_record(&channel, stranger(70)));
    assert_eq!(channel.state.peers.len(), 51);

    // An hour later, past every stamp: the newcomer, heard from at
    // `NOW - 3 600`, is now the oldest.
    text(&mut channel, stranger(901), 0, NOW + HOUR_MS).unwrap();
    assert!(!has_record(&channel, newcomer));
    // Then the other tied stranger, at `NOW - 1`.
    text(&mut channel, stranger(902), 0, NOW + HOUR_MS).unwrap();
    assert!(!has_record(&channel, larger));
    assert!(has_record(&channel, stranger(4)));

    // An evicted key comes back as new at any counter, and its gap is gone.
    let (mut channel, _, _) = receiver(3_600);
    plant(&mut channel, crowd(0, 50, false));
    text(&mut channel, stranger(1), 15, NOW + 1).unwrap();
    text(&mut channel, stranger(2), 15, NOW + 1).unwrap();
    assert_eq!(channel.gaps().len(), 2);
    let mut next = channel.next_state();
    next.peers[0].last_seen = NOW - 1;
    channel.commit(next, Vec::new()).unwrap();
    text(&mut channel, stranger(900), 0, NOW + HOUR_MS).unwrap();
    assert!(!has_record(&channel, stranger(1)));
    let left: Vec<[u8; 32]> = channel.gaps().iter().map(|gap| gap.peer).collect();
    assert_eq!(left, [pk_of(stranger(2))]);
    assert!(matches!(
        text(&mut channel, stranger(1), 3, NOW + HOUR_MS),
        Ok(Some(_))
    ));
    let back = channel.peer(&PublicKey(pk_of(stranger(1)))).unwrap();
    assert_eq!(back.max_counter, Some(3));

    // At the limit, a stale message and a `key_retired` from a new key
    // create and evict nothing: only a consumed, not stale message does.
    let (mut channel, handle, _) = receiver(3_600);
    plant(&mut channel, crowd(0, 50, false));
    let stale = sealed(
        &channel,
        stranger(900),
        0,
        NOW - 2 * HOUR_MS,
        PayloadKind::Text,
        None,
    );
    assert_eq!(
        channel.decrypt(&stale, [0x90; 16], NOW, NOW),
        Err(Error::Expired)
    );
    let retired = sealed(
        &channel,
        stranger(901),
        u64::MAX,
        NOW,
        PayloadKind::KeyRetired,
        None,
    );
    let commits = handle.commits();
    assert_eq!(channel.decrypt(&retired, [0x91; 16], NOW, NOW), Ok(None));
    assert_eq!(handle.commits(), commits);
    assert_eq!(channel.state.peers.len(), MAX_UNKNOWN_PEERS);
    assert!(has_record(&channel, stranger(1)));
    assert_eq!(channel.status().ignored_keys, 0);

    // Below both limits nobody is evicted, whatever the labelled peers.
    for (count, unknowns) in [(10u16, 40u16), (500, 10)] {
        let (mut channel, _, _) = receiver(3_600);
        plant(&mut channel, crowd(count, unknowns, false));
        text(&mut channel, stranger(900), 0, NOW).unwrap();
        let total = usize::from(count + unknowns) + 1;
        assert_eq!(channel.state.peers.len(), total);
        assert!((1..=unknowns).all(|n| has_record(&channel, stranger(n))));
        assert_eq!(channel.status().ignored_keys, 0);
    }

    // Never itself: every stranger heard from at the same `now` and the
    // newcomer's key the smallest of all, the newcomer stays.
    let (mut channel, _, _) = receiver(3_600);
    let mut peers = crowd(0, 50, false);
    for peer in &mut peers {
        peer.last_seen = NOW;
    }
    let smallest = peers.iter().map(|peer| peer.pk.0).min().unwrap();
    plant(&mut channel, peers);
    let newcomer = (1_000..)
        .map(stranger)
        .find(|seed| pk_of(*seed) < smallest)
        .unwrap();
    text(&mut channel, newcomer, 0, NOW).unwrap();
    assert!(has_record(&channel, newcomer));
    assert!(channel.peer(&PublicKey(smallest)).is_none());
    assert_eq!(channel.state.peers.len(), MAX_UNKNOWN_PEERS);

    // Strangers stamped ahead, by a clock since corrected, go before an
    // older newcomer: they no longer shield a flood. Stamped a few ms or a
    // year ahead, first seen before the jump; one that writes again is
    // stamped `now`; the server's `received_at` decides nothing.
    for ahead in [0, 365 * 24 * 3_600_000] {
        let (mut channel, _, _) = receiver(3_600);
        let mut peers = crowd(0, 49, false);
        for peer in &mut peers {
            peer.first_seen = NOW - HOUR_MS;
            peer.last_seen += ahead;
        }
        plant(&mut channel, peers);
        text(&mut channel, stranger(900), 0, NOW - 3_600).unwrap();
        text(&mut channel, stranger(1), 11, NOW).unwrap();
        let blob = sealed(&channel, stranger(901), 0, NOW, PayloadKind::Text, None);
        channel
            .decrypt(&blob, [0x91; 16], NOW - 4_000, NOW)
            .unwrap();
        assert!(has_record(&channel, stranger(900)) && has_record(&channel, stranger(1)));
        assert!(!has_record(&channel, stranger(2)));
        assert_eq!(channel.status().ignored_keys, 1);
    }

    // At 550 the total stays at 550: with 500 labelled, and with 501 after
    // a retirement by hand and only 49 strangers.
    for (count, unknowns) in [(500, 50), (501, 49)] {
        let (mut channel, _, _) = receiver(3_600);
        plant(&mut channel, crowd(count, unknowns, false));
        text(&mut channel, stranger(900), 0, NOW).unwrap();
        assert_eq!(channel.state.peers.len(), MAX_PEERS);
        assert!(!has_record(&channel, stranger(1)));
    }
}

/// Spec 026, R4: with 500 labelled, or 501 after a retirement by hand, a
/// label or a verification that would add to the budget is `PeerLimit`
/// and commits nothing; one that adds nothing, and `retire`, succeed.
#[test]
fn s026_t04_r04_labelled_budget() {
    for retired_by_hand in [false, true] {
        let (mut channel, handle, _) = receiver(3_600);
        let mut peers = crowd(500, 2, false);
        if retired_by_hand {
            peers.push(unknown(stranger(3), NOW, false));
        }
        plant(&mut channel, peers);
        if retired_by_hand {
            channel.retire(pk_of(stranger(3)), NOW).unwrap();
        }
        let target = pk_of(stranger(1));
        let qr = verify_qr(channel.config.id(), &PublicKey(pk_of(stranger(800)))).unwrap();
        let known_qr = verify_qr(channel.config.id(), &PublicKey(target)).unwrap();
        let commits = handle.all_commits();
        // The name and the collision come first (spec 022 R7).
        assert_eq!(channel.label(target, "", NOW), Err(Error::BadPayload));
        assert_eq!(channel.label(target, "peer 0", NOW), Err(Error::LabelInUse));
        assert_eq!(channel.label(target, "Ann", NOW), Err(Error::PeerLimit));
        assert_eq!(
            channel.verify_scanned(&known_qr, "Ann", NOW),
            Err(Error::PeerLimit)
        );
        assert_eq!(
            channel.verify(target, Some("Ann"), NOW),
            Err(Error::PeerLimit)
        );
        assert_eq!(
            channel.verify_scanned(&qr, "Bea", NOW),
            Err(Error::PeerLimit)
        );
        assert_eq!(handle.all_commits(), commits);
        assert!(channel.status().labelled_limit_reached);

        // A muted stranger is unknown too (R1).
        channel.mute(pk_of(stranger(2)), true).unwrap();
        let commits = handle.all_commits();
        let muted = pk_of(stranger(2));
        assert_eq!(channel.label(muted, "Mut", NOW), Err(Error::PeerLimit));
        assert_eq!(
            channel.verify(muted, Some("Mut"), NOW),
            Err(Error::PeerLimit)
        );
        assert_eq!(handle.all_commits(), commits);

        // Already in the budget: a new label and a verification add nothing.
        let inside = channel.state.peers[0].pk.0;
        channel.label(inside, "Renamed", NOW).unwrap();
        channel.verify(inside, None, NOW).unwrap();
        channel.retire(pk_of(stranger(2)), NOW).unwrap();
        // A retired peer with no label is already in the budget.
        if retired_by_hand {
            channel.label(pk_of(stranger(3)), "Old", NOW).unwrap();
        }
    }

    // A verified or a retired peer with no label counts as much as a
    // labelled one (R1).
    for verified in [true, false] {
        let (mut channel, _, _) = receiver(3_600);
        let mut peers = crowd(499, 1, false);
        peers.push(PeerRecord {
            verified,
            retired_at: (!verified).then_some(NOW),
            ..unknown(stranger(2), NOW, false)
        });
        plant(&mut channel, peers);
        assert!(channel.status().labelled_limit_reached);
        assert_eq!(
            channel.label(pk_of(stranger(1)), "Ann", NOW),
            Err(Error::PeerLimit)
        );
    }

    // Below 500 a label admits; a pre-verification that would make a 551st
    // record does not, and commits nothing. 51 strangers is a planted
    // state no flow reaches: it checks the defence R4 names.
    let (mut channel, _, _) = receiver(3_600);
    plant(&mut channel, crowd(499, 50, false));
    channel.label(pk_of(stranger(1)), "Ann", NOW).unwrap();
    let (mut channel, handle, _) = receiver(3_600);
    let mut peers = crowd(499, 50, false);
    peers.push(unknown(stranger(51), NOW, false));
    plant(&mut channel, peers);
    let qr = verify_qr(channel.config.id(), &PublicKey(pk_of(stranger(800)))).unwrap();
    let commits = handle.all_commits();
    assert_eq!(
        channel.verify_scanned(&qr, "Bea", NOW),
        Err(Error::PeerLimit)
    );
    assert_eq!(handle.all_commits(), commits);
    channel.label(pk_of(stranger(1)), "Ann", NOW).unwrap();
}

/// Spec 026, R5: `forget` removes a labelled and a retired record, each
/// in one commit; a key with no record is `UnknownPeer`; a forgotten key
/// writes again as a new unknown.
#[test]
fn s026_t05_r05_forget() {
    let (mut channel, handle, _) = receiver(3_600);
    let retired = PeerRecord {
        retired_at: Some(NOW),
        ..unknown(stranger(2), NOW, false)
    };
    plant(
        &mut channel,
        vec![
            PeerRecord {
                label: Some("Ann".to_owned()),
                ..unknown(stranger(1), NOW, false)
            },
            retired,
            labelled(9),
        ],
    );
    for seed in [stranger(1), stranger(2)] {
        let commits = handle.all_commits();
        channel.take_peers_changed();
        channel.forget(pk_of(seed)).unwrap();
        assert!(channel.take_peers_changed());
        assert_eq!(handle.all_commits(), commits + 1);
        assert!(!has_record(&reopened(&handle), seed));
        // Only that record: a bystander the user named stays.
        assert!(reopened(&handle).peer(&labelled(9).pk).is_some());
    }
    // The gap goes with the record, another's stays (spec 021 R24).
    for seed in [stranger(4), stranger(5)] {
        text(&mut channel, seed, 0, NOW).unwrap();
        text(&mut channel, seed, 5, NOW).unwrap();
    }
    assert_eq!(channel.gaps().len(), 2);
    let peers = channel.state.peers.len();
    channel.forget(pk_of(stranger(4))).unwrap();
    let left: Vec<[u8; 32]> = channel.gaps().iter().map(|gap| gap.peer).collect();
    assert_eq!(left, [pk_of(stranger(5))]);
    assert_eq!(channel.state.peers.len(), peers - 1);
    assert!(has_record(&reopened(&handle), stranger(5)));
    let commits = handle.all_commits();
    assert_eq!(channel.forget(pk_of(stranger(3))), Err(Error::UnknownPeer));
    assert_eq!(handle.all_commits(), commits);
    assert!(matches!(
        text(&mut channel, stranger(2), 0, NOW),
        Ok(Some(_))
    ));
    let back = channel.peer(&PublicKey(pk_of(stranger(2)))).unwrap();
    assert!(is_unknown(back));
}

/// Spec 026, R6: distinct keys rejected or evicted, not the user's own
/// refused calls, counted in memory alone up to 1 024; the two flags
/// follow R2 and R4.
#[test]
fn s026_t06_r06_ignored_keys() {
    let (mut channel, handle, _) = receiver(3_600);
    plant(&mut channel, crowd(0, 50, true));
    assert!(channel.status().unknown_limit_reached);
    for counter in 0..10 {
        assert_eq!(
            text(&mut channel, stranger(900), counter, NOW),
            Err(Error::PeerLimit)
        );
    }
    assert_eq!(channel.status().ignored_keys, 1);
    channel.mute(pk_of(stranger(1)), false).unwrap();
    assert!(!channel.status().unknown_limit_reached);
    text(&mut channel, stranger(901), 0, NOW).unwrap();
    assert_eq!(channel.status().ignored_keys, 2);
    // The evicted stranger is counted, not the newcomer.
    assert!(channel.carry.ignored_keys.contains(&pk_of(stranger(1))));
    assert!(!channel.carry.ignored_keys.contains(&pk_of(stranger(901))));
    // The newcomer took the evicted place, unmuted.
    assert!(!channel.status().unknown_limit_reached);
    // The user's own call refused by R4 is not counted.
    plant(&mut channel, crowd(500, 1, false));
    assert_eq!(
        channel.label(pk_of(stranger(1)), "Ann", NOW),
        Err(Error::PeerLimit)
    );
    assert_eq!(channel.status().ignored_keys, 2);

    let (mut full, _, _) = receiver(3_600);
    plant(&mut full, crowd(500, 1, false));
    let status = full.status();
    assert!(status.labelled_limit_reached && !status.unknown_limit_reached);
    assert_eq!(
        full.label(pk_of(stranger(1)), "Ann", NOW),
        Err(Error::PeerLimit)
    );
    assert_eq!(full.status().ignored_keys, 0);
    plant(&mut full, crowd(499, 0, false));
    assert!(!full.status().labelled_limit_reached);

    assert_eq!(reopened(&handle).status().ignored_keys, 0);
    for n in 0..1_100u16 {
        channel.ignore_key(pk_of(stranger(n)));
    }
    assert_eq!(channel.status().ignored_keys, 1_024);
    // The spec's numbers, pinned once (Interface).
    assert_eq!(
        (
            MAX_UNKNOWN_PEERS,
            MAX_LABELLED_PEERS,
            MAX_PEERS,
            MAX_IGNORED_TRACKED
        ),
        (50, 500, 550, 1_024)
    );
}

/// Spec 026, R7: `forget` and an evicting `decrypt` whose commit fails
/// leave memory and the reopened state as they were, nothing counted.
#[test]
fn s026_t07_r07_failing_store() {
    let (mut channel, handle, faults) = receiver(3_600);
    plant(&mut channel, crowd(1, 50, false));
    // The stranger an eviction takes and the one `forget` takes have a gap.
    text(&mut channel, stranger(1), 15, NOW).unwrap();
    text(&mut channel, stranger(2), 15, NOW + 1).unwrap();
    let gaps = channel.gaps();
    assert_eq!(gaps.len(), 2);
    let before = channel.state.duplicate();
    faults.fail_commits(true);
    assert_eq!(
        channel.forget(pk_of(stranger(2))),
        Err(Error::Store(StoreError::Io))
    );
    assert_eq!(
        text(&mut channel, stranger(900), 0, NOW),
        Err(Error::Store(StoreError::Io))
    );
    assert!(state_eq(&channel.state, &before));
    assert!(state_eq(&reopened(&handle).state, &before));
    assert_eq!(channel.status().ignored_keys, 0);
    assert_eq!(channel.gaps(), gaps);
}
