//! Tests of spec 022-peers-tofu R1–R3 and R6–R15: the record created and
//! updated on receive, the list, the calls that change a peer, and the
//! warnings. The name functions are tested in `session/names/tests.rs`.

use super::{HOUR_MS, MARGIN_MS, NOW, own_text, pk_of, receiver, reopened, sealed};
use crate::Error;
use crate::crypto::{PublicKey, Secret};
use crate::proto::config::ChannelId;
use crate::proto::fingerprint::{presentation, verify_qr};
use crate::proto::payload::PayloadKind;
use crate::session::channel::peers::Peer;
use crate::session::channel::{Channel, MessageContent, PeerId, Received};
use crate::storage::StoreError;
use crate::storage::state::items::{OldKey, PeerRecord};
use crate::testing::{MemoryStore, state_eq};

const ANN: [u8; 32] = [0x41; 32];
const BOB: [u8; 32] = [0x42; 32];
const CAT: [u8; 32] = [0x43; 32];
const DAN: [u8; 32] = [0x44; 32];

/// Delivers a text of `seed` at `counter`, sent at `NOW` and received at
/// `now`, with `name`.
fn deliver(
    channel: &mut Channel,
    seed: [u8; 32],
    counter: u64,
    now: u64,
    name: Option<&str>,
) -> Result<Option<Received>, Error> {
    let blob = sealed(channel, seed, counter, NOW, PayloadKind::Text, name);
    let mut server_id = [seed[0]; 16];
    server_id[8..].copy_from_slice(&counter.to_be_bytes());
    channel.decrypt(&blob, server_id, now, now)
}

/// Commits a peer record for `pk`, as the specs that retire or verify a
/// peer would leave it.
fn plant(channel: &mut Channel, pk: PeerId, label: &str, verified: bool, retired: bool) {
    let mut next = channel.next_state();
    next.peers.push(PeerRecord {
        pk: PublicKey(pk),
        label: Some(label.to_owned()),
        verified,
        muted: false,
        retired_at: retired.then_some(NOW),
        first_seen: NOW,
        last_seen: NOW,
        max_counter: Some(0),
        last_display_name: None,
    });
    channel.commit(next, Vec::new()).unwrap();
}

/// The record of `pk`.
fn record_of(channel: &Channel, pk: PeerId) -> Option<&PeerRecord> {
    channel.peer(&PublicKey(pk))
}

/// The name a received text was signed with, as handed to a client.
fn name_of(received: &Received) -> Option<String> {
    let MessageContent::Text { display_name, .. } = &received.content else {
        return Some("not a text".to_owned());
    };
    display_name.clone()
}

/// Asserts that `result` is `error` and that nothing was committed.
fn refused<T>(result: Result<T, Error>, error: Error, handle: &MemoryStore, commits: u32) {
    assert!(matches!(result, Err(e) if e == error), "{error:?}");
    assert_eq!(handle.all_commits(), commits, "{error:?}");
}

/// Spec 022, R1: a consumed message from a new key creates its record; a
/// stale message, a `key_retired` and one's own key create none.
#[test]
fn s022_t01_r01_first_message_creates_peer() {
    let (mut channel, _, _) = receiver(3_600);
    deliver(&mut channel, ANN, 0, NOW, Some("Ann")).unwrap();
    let peers = channel.peers().unwrap();
    assert_eq!(peers.len(), 1);
    let ann = &peers[0];
    assert_eq!(ann.id, pk_of(ANN));
    assert_eq!(ann.suggested_name.as_deref(), Some("Ann"));
    assert_eq!(ann.label, None);
    assert!(!ann.verified && !ann.muted);
    assert_eq!(ann.retired_at, None);
    assert_eq!((ann.first_seen, ann.last_seen), (NOW, NOW));
    assert_eq!(
        record_of(&channel, pk_of(ANN)).unwrap().max_counter,
        Some(0)
    );

    let old = NOW - HOUR_MS - MARGIN_MS - 60_000;
    let stale = sealed(&channel, BOB, 0, old, PayloadKind::Text, Some("Bob"));
    assert_eq!(
        channel.decrypt(&stale, [2; 16], NOW, NOW),
        Err(Error::Expired)
    );
    assert!(record_of(&channel, pk_of(BOB)).is_none());

    let retired = sealed(&channel, CAT, 0, NOW, PayloadKind::KeyRetired, None);
    channel.decrypt(&retired, [3; 16], NOW, NOW).unwrap();
    assert!(record_of(&channel, pk_of(CAT)).is_none());

    let own = own_text(&channel, 0, NOW);
    channel.decrypt(&own, [4; 16], NOW, NOW).unwrap();
    assert!(channel.state.own_key_used_elsewhere);
    assert_eq!(channel.peers().unwrap().len(), 1);
}

/// Spec 022, R2: a later message moves `last_seen`; one without a name
/// keeps the previous name, one with a name replaces it.
#[test]
fn s022_t02_r02_later_messages_update() {
    let (mut channel, handle, _) = receiver(3_600);
    deliver(&mut channel, ANN, 0, NOW, Some("Ann")).unwrap();
    deliver(&mut channel, ANN, 1, NOW + 1_000, None).unwrap();
    let ann = &channel.peers().unwrap()[0];
    assert_eq!((ann.first_seen, ann.last_seen), (NOW, NOW + 1_000));
    assert_eq!(ann.suggested_name.as_deref(), Some("Ann"));
    deliver(&mut channel, ANN, 2, NOW + 2_000, Some("Annie")).unwrap();
    let ann = &reopened(&handle).peers().unwrap()[0];
    assert_eq!(ann.last_seen, NOW + 2_000);
    assert_eq!(ann.suggested_name.as_deref(), Some("Annie"));
}

/// Spec 022, R3: every peer in `first_seen` order, whatever the order of
/// the records; reading commits nothing.
#[test]
fn s022_t03_r03_peers_in_order() {
    let (mut channel, handle, _) = receiver(3_600);
    deliver(&mut channel, ANN, 0, NOW + 2, None).unwrap();
    deliver(&mut channel, BOB, 0, NOW + 3, None).unwrap();
    // A record appended last but first seen earliest.
    let mut next = channel.next_state();
    let mut cat = record_of(&channel, pk_of(ANN)).unwrap().clone();
    cat.pk = PublicKey(pk_of(CAT));
    cat.first_seen = NOW + 1;
    next.peers.push(cat);
    channel.commit(next, Vec::new()).unwrap();
    let commits = handle.all_commits();
    let ids: Vec<PeerId> = channel.peers().unwrap().iter().map(|p| p.id).collect();
    assert_eq!(ids, [pk_of(CAT), pk_of(ANN), pk_of(BOB)]);
    assert_eq!(handle.all_commits(), commits);
}

/// Spec 022, R6: names come out cleaned in `peers()` and in the
/// `Received`; a name of blanks comes out as no name.
#[test]
fn s022_t06_r06_names_cleaned_in_peers_and_received() {
    let (mut channel, _, _) = receiver(3_600);
    let received = deliver(&mut channel, ANN, 0, NOW, Some("Ann\u{202E}")).unwrap();
    assert_eq!(name_of(&received.unwrap()).as_deref(), Some("Ann"));
    let cases = [
        (BOB, "\u{200B}\u{2800}\u{FEFF}", None),
        (CAT, "   ", None),
        (DAN, "\u{3000}", None),
        ([0x45; 32], "Bob\u{2029}Alice", Some("BobAlice")),
        ([0x46; 32], "Bob\u{2028}Alice", Some("BobAlice")),
    ];
    for (seed, sent, shown) in cases {
        let received = deliver(&mut channel, seed, 0, NOW, Some(sent)).unwrap();
        assert_eq!(name_of(&received.unwrap()).as_deref(), shown, "{sent:?}");
    }
    let peers = channel.peers().unwrap();
    let names: Vec<Option<&str>> = peers.iter().map(|p| p.suggested_name.as_deref()).collect();
    assert_eq!(
        names,
        [
            Some("Ann"),
            None,
            None,
            None,
            Some("BobAlice"),
            Some("BobAlice")
        ]
    );
    // A label is cleaned on the way out too.
    channel.label(pk_of(ANN), "Ann\u{200B}a", NOW).unwrap();
    assert_eq!(channel.peers().unwrap()[0].label.as_deref(), Some("Anna"));
}

/// Spec 022, R7: each error in order, with nothing committed; a retired
/// label is free, and a verified target may share an unverified one's.
#[test]
fn s022_t07_r07_label_rules() {
    let (mut channel, handle, _) = receiver(3_600);
    deliver(&mut channel, ANN, 0, NOW, None).unwrap();
    deliver(&mut channel, BOB, 0, NOW, None).unwrap();
    let commits = handle.all_commits();
    let result = channel.label(pk_of(CAT), "", NOW);
    refused(result, Error::UnknownPeer, &handle, commits);
    let too_long = "a".repeat(65);
    for name in ["", too_long.as_str(), "Bo\u{7}b", "\u{200B} \u{3164}"] {
        let result = channel.label(pk_of(ANN), name, NOW);
        refused(result, Error::BadPayload, &handle, commits);
    }
    channel.label(pk_of(ANN), &"a".repeat(64), NOW).unwrap();
    channel.label(pk_of(ANN), "Alice", NOW).unwrap();
    let commits = handle.all_commits();
    let result = channel.label(pk_of(BOB), "AL ICE", NOW);
    refused(result, Error::LabelInUse, &handle, commits);
    // Relabelling a peer with its own label is no collision.
    channel.label(pk_of(ANN), "alice", NOW).unwrap();

    plant(&mut channel, pk_of(CAT), "Carol", false, true);
    channel.label(pk_of(BOB), "carol", NOW).unwrap();
    plant(&mut channel, pk_of(DAN), "Dan", true, false);
    channel.label(pk_of(DAN), "Alice", NOW).unwrap();
    let stored = reopened(&handle);
    assert_eq!(
        record_of(&stored, pk_of(BOB)).unwrap().label.as_deref(),
        Some("carol")
    );
    assert_eq!(
        record_of(&stored, pk_of(DAN)).unwrap().label.as_deref(),
        Some("Alice")
    );
}

/// Spec 022, R8: a labelled peer keeps its label; an unlabelled one needs
/// a valid label, which may be one an unverified key holds.
#[test]
fn s022_t08_r08_verify() {
    let (mut channel, handle, _) = receiver(3_600);
    for seed in [ANN, BOB, CAT, DAN] {
        deliver(&mut channel, seed, 0, NOW, None).unwrap();
    }
    let commits = handle.all_commits();
    let result = channel.verify(pk_of([0x47; 32]), Some("X"), NOW);
    refused(result, Error::UnknownPeer, &handle, commits);
    let result = channel.verify(pk_of(ANN), None, NOW);
    refused(result, Error::BadPayload, &handle, commits);
    let result = channel.verify(pk_of(DAN), Some("D\u{7}"), NOW);
    refused(result, Error::BadPayload, &handle, commits);

    channel.label(pk_of(ANN), "Ann", NOW).unwrap();
    channel.verify(pk_of(ANN), Some("Other"), NOW).unwrap();
    let ann = record_of(&channel, pk_of(ANN)).unwrap();
    assert!(ann.verified);
    assert_eq!(ann.label.as_deref(), Some("Ann"));

    channel.label(pk_of(CAT), "Alice", NOW).unwrap();
    channel.verify(pk_of(BOB), Some("alice"), NOW).unwrap();
    let stored = reopened(&handle);
    let bob = record_of(&stored, pk_of(BOB)).unwrap();
    assert!(bob.verified);
    assert_eq!(bob.label.as_deref(), Some("alice"));
}

/// Spec 022, R9: the QR's errors, one's own keys refused, a known key
/// verified, a new key pre-verified and then accepted from counter 0.
#[test]
fn s022_t09_r09_verify_scanned() {
    let (mut channel, handle, _) = receiver(3_600);
    let qr_of = |seed| verify_qr(channel.config.id(), &PublicKey(pk_of(seed))).unwrap();
    let (ann_qr, bob_qr, cat_qr, dan_qr) = (qr_of(ANN), qr_of(BOB), qr_of(CAT), qr_of(DAN));
    let eve_qr = qr_of([0x45; 32]);
    deliver(&mut channel, ANN, 0, NOW, None).unwrap();
    deliver(&mut channel, BOB, 0, NOW, None).unwrap();
    let mut next = channel.next_state();
    next.own_old_keys.push(OldKey {
        pk: PublicKey(pk_of([0x99; 32])),
        retired_at: NOW,
    });
    channel.commit(next, Vec::new()).unwrap();
    let commits = handle.all_commits();

    let other = verify_qr(&ChannelId([0x77; 16]), &PublicKey(pk_of(ANN))).unwrap();
    let result = channel.verify_scanned(&other, "Ann", NOW);
    refused(result, Error::WrongChannel, &handle, commits);
    let result = channel.verify_scanned(b"verify:v1:", "Ann", NOW);
    refused(result, Error::BadPayload, &handle, commits);
    let own = channel.own_fingerprint().unwrap().qr;
    refused(
        channel.verify_scanned(&own, "Me", NOW),
        Error::OwnKey,
        &handle,
        commits,
    );
    let old = verify_qr(channel.config.id(), &PublicKey(pk_of([0x99; 32]))).unwrap();
    refused(
        channel.verify_scanned(&old, "Me", NOW),
        Error::OwnKey,
        &handle,
        commits,
    );
    let result = channel.verify_scanned(&dan_qr, "D\u{7}", NOW);
    refused(result, Error::BadPayload, &handle, commits);
    assert!(record_of(&channel, pk_of(DAN)).is_none());

    assert_eq!(channel.verify_scanned(&ann_qr, "Ann", NOW), Ok(pk_of(ANN)));
    let ann = record_of(&channel, pk_of(ANN)).unwrap();
    assert!(ann.verified);
    assert_eq!(ann.label.as_deref(), Some("Ann"));
    // A labelled peer keeps its label, and the given one is not checked.
    channel.label(pk_of(BOB), "Bob", NOW).unwrap();
    channel.verify_scanned(&bob_qr, "B\u{7}", NOW).unwrap();
    assert_eq!(
        record_of(&channel, pk_of(BOB)).unwrap().label.as_deref(),
        Some("Bob")
    );

    channel.verify_scanned(&cat_qr, "Cat", NOW + 5).unwrap();
    let cat = record_of(&channel, pk_of(CAT)).unwrap();
    assert!(cat.verified && !cat.muted);
    assert_eq!(cat.label.as_deref(), Some("Cat"));
    assert_eq!(cat.max_counter, None);
    assert_eq!((cat.first_seen, cat.last_seen), (NOW + 5, NOW + 5));
    assert!(
        deliver(&mut channel, CAT, 0, NOW + 6, None)
            .unwrap()
            .is_some()
    );

    // An unverified peer holds "Dan"; the pre-verified key may take it.
    deliver(&mut channel, DAN, 0, NOW, None).unwrap();
    channel.label(pk_of(DAN), "Dan", NOW).unwrap();
    channel.verify_scanned(&eve_qr, "dan", NOW).unwrap();
    let stored = reopened(&handle);
    let eve = record_of(&stored, pk_of([0x45; 32])).unwrap();
    assert!(eve.verified);
    assert_eq!(eve.label.as_deref(), Some("dan"));
}

/// Spec 022, R10: mute and unmute commit, the same value does not; the
/// calls set the peers-changed flag.
#[test]
fn s022_t10_r10_mute() {
    let (mut channel, handle, _) = receiver(3_600);
    deliver(&mut channel, ANN, 0, NOW, None).unwrap();
    let commits = handle.all_commits();
    refused(
        channel.mute(pk_of(BOB), true),
        Error::UnknownPeer,
        &handle,
        commits,
    );
    channel.mute(pk_of(ANN), true).unwrap();
    assert_eq!(handle.all_commits(), commits + 1);
    channel.mute(pk_of(ANN), true).unwrap();
    assert_eq!(handle.all_commits(), commits + 1);
    assert!(record_of(&reopened(&handle), pk_of(ANN)).unwrap().muted);
    channel.mute(pk_of(ANN), false).unwrap();
    assert_eq!(handle.all_commits(), commits + 2);
    assert!(!record_of(&reopened(&handle), pk_of(ANN)).unwrap().muted);

    channel.take_peers_changed();
    channel.label(pk_of(ANN), "Ann", NOW).unwrap();
    assert!(channel.take_peers_changed());
    assert!(!channel.take_peers_changed());
    channel.verify(pk_of(ANN), None, NOW).unwrap();
    assert!(channel.take_peers_changed());
    channel.mute(pk_of(ANN), true).unwrap();
    assert!(channel.take_peers_changed());
}

/// Spec 022, R11: an error commits nothing, and a failed commit leaves
/// memory and the reopened store as they were.
#[test]
fn s022_t11_r11_errors_and_failing_store() {
    let (mut channel, handle, faults) = receiver(3_600);
    deliver(&mut channel, ANN, 0, NOW, None).unwrap();
    deliver(&mut channel, BOB, 0, NOW, None).unwrap();
    channel.label(pk_of(BOB), "Bob", NOW).unwrap();
    let unknown = pk_of(CAT);
    let commits = handle.all_commits();
    refused(
        channel.label(unknown, "Cat", NOW),
        Error::UnknownPeer,
        &handle,
        commits,
    );
    refused(
        channel.label(pk_of(ANN), "bob", NOW),
        Error::LabelInUse,
        &handle,
        commits,
    );
    refused(
        channel.verify(unknown, None, NOW),
        Error::UnknownPeer,
        &handle,
        commits,
    );
    refused(
        channel.mute(unknown, true),
        Error::UnknownPeer,
        &handle,
        commits,
    );

    let qr = verify_qr(channel.config.id(), &PublicKey(pk_of(CAT))).unwrap();
    let before = channel.state.duplicate();
    faults.fail_commits(true);
    let io = Error::Store(StoreError::Io);
    assert_eq!(channel.label(pk_of(ANN), "Ann", NOW), Err(io));
    assert_eq!(channel.verify(pk_of(BOB), None, NOW), Err(io));
    assert_eq!(channel.verify_scanned(&qr, "Cat", NOW), Err(io));
    assert_eq!(channel.mute(pk_of(ANN), true), Err(io));
    assert!(state_eq(&channel.state, &before));
    assert!(state_eq(&reopened(&handle).state, &before));
}

/// Spec 022, R12: the fingerprint of any key of the channel, with or
/// without a record, and one's own.
#[test]
fn s022_t12_r12_fingerprints() {
    let (mut channel, _, _) = receiver(3_600);
    deliver(&mut channel, ANN, 0, NOW, None).unwrap();
    plant(&mut channel, pk_of(BOB), "Bob", false, true);
    let mut next = channel.next_state();
    next.own_old_keys.push(OldKey {
        pk: PublicKey(pk_of(CAT)),
        retired_at: NOW,
    });
    channel.commit(next, Vec::new()).unwrap();
    for seed in [ANN, BOB, CAT, DAN] {
        let pk = PublicKey(pk_of(seed));
        let expected = presentation(channel.config.id(), &pk).unwrap();
        assert_eq!(channel.fingerprint(pk.0).unwrap(), expected);
    }
    let own = PublicKey(pk_of(*channel.state.identity_seed.expose()));
    let expected = presentation(channel.config.id(), &own).unwrap();
    assert_eq!(channel.own_fingerprint().unwrap(), expected);
}

/// The peer of `pk` in `peers()`.
fn listed(channel: &Channel, pk: PeerId) -> Peer {
    let peers = channel.peers().unwrap();
    peers.into_iter().find(|peer| peer.id == pk).unwrap()
}

/// Spec 022, R13: an unknown peer claiming a labelled, retired or own
/// name says whose; a peer with a label claims nothing.
#[test]
fn s022_t13_r13_claims() {
    let unknown = [0x50; 32];
    let (mut channel, _, _) = receiver(3_600);
    deliver(&mut channel, ANN, 0, NOW, None).unwrap();
    channel.label(pk_of(ANN), "Alice", NOW).unwrap();
    deliver(&mut channel, unknown, 0, NOW + 10, Some("al ice")).unwrap();
    assert_eq!(
        listed(&channel, pk_of(unknown)).claims_name_of,
        Some(pk_of(ANN))
    );
    assert_eq!(listed(&channel, pk_of(ANN)).claims_name_of, None);
    deliver(&mut channel, BOB, 0, NOW, Some("Alice")).unwrap();
    channel.label(pk_of(BOB), "Bob", NOW).unwrap();
    assert_eq!(listed(&channel, pk_of(BOB)).claims_name_of, None);

    // A retired holder, appended after a later-seen one: the first seen.
    let (mut channel, _, _) = receiver(3_600);
    deliver(&mut channel, ANN, 0, NOW + 5, None).unwrap();
    plant(&mut channel, pk_of(CAT), "Alice", false, true);
    deliver(&mut channel, unknown, 0, NOW + 10, Some("ALICE")).unwrap();
    assert_eq!(
        listed(&channel, pk_of(unknown)).claims_name_of,
        Some(pk_of(CAT))
    );
    channel.label(pk_of(ANN), "alice", NOW).unwrap();
    assert_eq!(
        listed(&channel, pk_of(unknown)).claims_name_of,
        Some(pk_of(CAT))
    );
    assert!(!listed(&channel, pk_of(unknown)).claims_own_name);

    let mut next = channel.next_state();
    next.own_display_name = Some("Me\u{200B}".to_owned());
    channel.commit(next, Vec::new()).unwrap();
    deliver(&mut channel, DAN, 0, NOW, Some("me")).unwrap();
    let dan = listed(&channel, pk_of(DAN));
    assert!(dan.claims_own_name);
    assert_eq!(dan.claims_name_of, None);
    channel.label(pk_of(DAN), "Dan", NOW).unwrap();
    assert!(!listed(&channel, pk_of(DAN)).claims_own_name);

    // A retired peer with no label is not unknown: it claims nothing.
    let mut next = channel.next_state();
    let mut retired = record_of(&channel, pk_of(unknown)).unwrap().clone();
    retired.pk = PublicKey(pk_of([0x51; 32]));
    retired.retired_at = Some(NOW);
    next.peers.push(retired);
    channel.commit(next, Vec::new()).unwrap();
    let retired = listed(&channel, pk_of([0x51; 32]));
    assert_eq!(retired.suggested_name.as_deref(), Some("ALICE"));
    assert_eq!(retired.claims_name_of, None);
}

/// Spec 022, R14: colliding labels flag both peers, retired ones included.
#[test]
fn s022_t14_r14_label_collision_flag() {
    let (mut channel, _, _) = receiver(3_600);
    deliver(&mut channel, ANN, 0, NOW, None).unwrap();
    deliver(&mut channel, BOB, 0, NOW, None).unwrap();
    channel.label(pk_of(ANN), "Alice", NOW).unwrap();
    channel.label(pk_of(BOB), "Bob", NOW).unwrap();
    assert!(!listed(&channel, pk_of(ANN)).label_collides);
    deliver(&mut channel, CAT, 0, NOW, None).unwrap();
    channel.verify(pk_of(CAT), Some("ALICE"), NOW).unwrap();
    let qr = verify_qr(channel.config.id(), &PublicKey(pk_of(DAN))).unwrap();
    channel.verify_scanned(&qr, "b ob", NOW).unwrap();
    for seed in [ANN, BOB, CAT, DAN] {
        assert!(
            listed(&channel, pk_of(seed)).label_collides,
            "{:x}",
            seed[0]
        );
    }

    let (mut channel, _, _) = receiver(3_600);
    plant(&mut channel, pk_of(ANN), "Alice", false, true);
    deliver(&mut channel, BOB, 0, NOW, None).unwrap();
    channel.label(pk_of(BOB), "alice", NOW).unwrap();
    deliver(&mut channel, CAT, 0, NOW, None).unwrap();
    assert!(listed(&channel, pk_of(ANN)).label_collides);
    assert!(listed(&channel, pk_of(BOB)).label_collides);
    assert!(!listed(&channel, pk_of(CAT)).label_collides);
}

/// Two identity seeds whose keys share the first 44 bits of their
/// fingerprints in the channel of the 013 vectors, so the same 4 words:
/// found once by a birthday search over seeds `BE64(i) ‖ 0^23 ‖ 0x5e`
/// (i = 4 000 278 and 5 345 671), outside the test suite.
const TWIN_A: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x3d, 0x0a, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x5e,
];
const TWIN_B: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x51, 0x91, 0x87, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x5e,
];

/// Spec 022, R15: two peers with the same 4 words are both flagged, and a
/// peer whose words equal one's own.
#[test]
fn s022_t15_r15_short_identifier_collision() {
    let (mut channel, _, _) = receiver(3_600);
    let (a, b) = (pk_of(TWIN_A), pk_of(TWIN_B));
    assert_ne!(a, b);
    assert_eq!(
        channel.fingerprint(a).unwrap().short,
        channel.fingerprint(b).unwrap().short
    );
    assert_ne!(
        channel.fingerprint(a).unwrap().words,
        channel.fingerprint(b).unwrap().words
    );
    deliver(&mut channel, ANN, 0, NOW, None).unwrap();
    plant(&mut channel, a, "A", false, false);
    plant(&mut channel, b, "B", false, true);
    assert!(listed(&channel, a).short_collides);
    assert!(listed(&channel, b).short_collides);
    assert!(!listed(&channel, pk_of(ANN)).short_collides);

    let (mut channel, _, _) = receiver(3_600);
    let mut next = channel.next_state();
    next.identity_seed = Secret::from_bytes(TWIN_A);
    channel.commit(next, Vec::new()).unwrap();
    deliver(&mut channel, TWIN_B, 0, NOW, None).unwrap();
    deliver(&mut channel, ANN, 0, NOW, None).unwrap();
    assert_eq!(
        channel.own_fingerprint().unwrap().short,
        listed(&channel, b).short
    );
    assert!(listed(&channel, b).short_collides);
    assert!(!listed(&channel, pk_of(ANN)).short_collides);
}
