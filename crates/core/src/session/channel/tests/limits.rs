//! Tests of spec 026-peer-limits: the two budgets, the room check, the
//! eviction of strangers, the labelled budget, `forget` and the ignored
//! keys.

use super::super::limits::{
    MAX_IGNORED_TRACKED, MAX_LABELLED_PEERS, MAX_UNKNOWN_PEERS, is_unknown,
};
use super::{NOW, own_text, pk_of, receiver, reopened, sealed};
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
        pk: PublicKey(pk_of(seed)),
        label: None,
        verified: false,
        muted,
        retired_at: None,
        first_seen: last_seen,
        last_seen,
        max_counter: Some(10),
        last_display_name: None,
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
            let own = own_text(&channel, 0, NOW);
            assert_ne!(
                channel.decrypt(&own, [0xee; 16], NOW, NOW),
                Err(Error::PeerLimit)
            );
        }
    }
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

    // `now` below every `last_seen`: the newcomer is never the oldest.
    let newcomer = stranger(900);
    text(&mut channel, newcomer, 0, NOW - 3_600).unwrap();
    assert!(has_record(&channel, newcomer));
    assert!(!has_record(&channel, smaller));
    assert!(has_record(&channel, larger));
    assert!(has_record(&channel, stranger(1)) && has_record(&channel, stranger(70)));
    assert_eq!(channel.state.peers.len(), 51);

    // The newcomer, heard from at `NOW - 3 600`, is now the oldest.
    text(&mut channel, stranger(901), 0, NOW).unwrap();
    assert!(!has_record(&channel, newcomer));
    let next = channel
        .state
        .peers
        .iter()
        .filter(|p| is_unknown(p) && !p.muted);
    let oldest = next.min_by_key(|p| (p.last_seen, p.pk.0)).unwrap().pk.0;
    text(&mut channel, stranger(902), 0, NOW).unwrap();
    assert!(channel.peer(&PublicKey(oldest)).is_none());

    // An evicted key comes back as new at any counter, and its gap is gone.
    let (mut channel, _, _) = receiver(3_600);
    plant(&mut channel, crowd(0, 50, false));
    text(&mut channel, stranger(1), 11, NOW + 1).unwrap();
    text(&mut channel, stranger(1), 15, NOW + 1).unwrap();
    assert_eq!(channel.gaps().len(), 1);
    let mut next = channel.next_state();
    next.peers[0].last_seen = NOW - 1;
    channel.commit(next, Vec::new()).unwrap();
    text(&mut channel, stranger(900), 0, NOW).unwrap();
    assert!(!has_record(&channel, stranger(1)));
    assert!(channel.gaps().is_empty());
    assert!(matches!(
        text(&mut channel, stranger(1), 3, NOW + 2),
        Ok(Some(_))
    ));
    let back = channel.peer(&PublicKey(pk_of(stranger(1)))).unwrap();
    assert_eq!(back.max_counter, Some(3));

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
        let commits = handle.all_commits();
        assert_eq!(channel.label(target, "Ann", NOW), Err(Error::PeerLimit));
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

        // Already in the budget: a new label and a verification add nothing.
        let inside = channel.state.peers[0].pk.0;
        channel.label(inside, "Renamed", NOW).unwrap();
        channel.verify(inside, None, NOW).unwrap();
        channel.retire(pk_of(stranger(2)), NOW).unwrap();
    }

    // Below 500 a label admits; a pre-verification that would make a 551st
    // record does not.
    let (mut channel, _, _) = receiver(3_600);
    plant(&mut channel, crowd(499, 50, false));
    channel.label(pk_of(stranger(1)), "Ann", NOW).unwrap();
    let (mut channel, _, _) = receiver(3_600);
    let mut peers = crowd(499, 50, false);
    peers.push(unknown(stranger(51), NOW, false));
    plant(&mut channel, peers);
    let qr = verify_qr(channel.config.id(), &PublicKey(pk_of(stranger(800)))).unwrap();
    assert_eq!(
        channel.verify_scanned(&qr, "Bea", NOW),
        Err(Error::PeerLimit)
    );
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
        ],
    );
    for seed in [stranger(1), stranger(2)] {
        let commits = handle.all_commits();
        channel.forget(pk_of(seed)).unwrap();
        assert_eq!(handle.all_commits(), commits + 1);
        assert!(!has_record(&reopened(&handle), seed));
    }
    // The gap goes with the record (spec 021 R24).
    text(&mut channel, stranger(4), 0, NOW).unwrap();
    text(&mut channel, stranger(4), 5, NOW).unwrap();
    assert_eq!(channel.gaps().len(), 1);
    channel.forget(pk_of(stranger(4))).unwrap();
    assert!(channel.gaps().is_empty());
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
    // The newcomer took the evicted place, unmuted.
    assert!(!channel.status().unknown_limit_reached);

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
    let tracked = u32::try_from(MAX_IGNORED_TRACKED).unwrap();
    assert_eq!(channel.status().ignored_keys, tracked);
    assert_eq!(MAX_UNKNOWN_PEERS + MAX_LABELLED_PEERS, MAX_PEERS);
}

/// Spec 026, R7: `forget` and an evicting `decrypt` whose commit fails
/// leave memory and the reopened state as they were, nothing counted.
#[test]
fn s026_t07_r07_failing_store() {
    let (mut channel, handle, faults) = receiver(3_600);
    plant(&mut channel, crowd(1, 50, false));
    let before = channel.state.duplicate();
    faults.fail_commits(true);
    let labelled_pk = channel.state.peers[0].pk.0;
    assert_eq!(
        channel.forget(labelled_pk),
        Err(Error::Store(StoreError::Io))
    );
    assert_eq!(
        text(&mut channel, stranger(900), 0, NOW),
        Err(Error::Store(StoreError::Io))
    );
    assert!(state_eq(&channel.state, &before));
    assert!(state_eq(&reopened(&handle).state, &before));
    assert_eq!(channel.status().ignored_keys, 0);
}
