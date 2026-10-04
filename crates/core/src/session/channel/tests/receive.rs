//! Tests of the receive pipeline: R3, R9–R12, the cursor half of R20, the
//! peer half of R26 and the `decrypt` clauses of R18 and R32.

use super::{HOUR_MS, MARGIN_MS, NOW, pk_of, receiver, reopened, seal, sid, text_from};
use crate::Error;
use crate::crypto::PublicKey;
use crate::proto::envelope::{self, text_k1};
use crate::session::channel::{Channel, MessageContent, Received, Sender};
use crate::storage::state::items::OldKey;
use crate::storage::{Content, LogEntry, LogRecord, StoreError};
use crate::testing::state_eq;
use crate::vectors::{self, Vector};

const PEER: [u8; 32] = [0x77; 32];

/// The verdict of a fresh channel on one 013 vector, which is every
/// verdict of spec 013 with no commit for a rejection.
fn check_decrypt(vector: &Vector) {
    let (mut channel, handle, _) = receiver(text_k1::TTL_SECONDS);
    let blob = if vector.has_input("blob") {
        vector.input("blob").bytes()
    } else {
        vector.expected("blob").bytes()
    };
    let received_at = vector.input("received_at").u64_hex();
    let now = vector.input("now").u64_hex();
    let result = channel.decrypt(blob, sid(1), received_at, now);
    let name = vector.name();
    // A negative vector names its error, a positive one what `open` read,
    // which `decrypt` returns as `Expired` when stale.
    let verdict = match &result {
        Ok(Some(received)) if received.content == MessageContent::Unreadable => {
            "unreadable".to_owned()
        }
        Ok(Some(_)) => "message".to_owned(),
        Ok(None) => "none".to_owned(),
        Err(Error::Expired) if !vector.has_input("blob") => "stale".to_owned(),
        Err(error) => format!("{error:?}"),
    };
    let expected = if vector.has_input("blob") {
        vector.expected("error").text()
    } else {
        vector.expected("content").text()
    };
    assert_eq!(verdict, expected, "{name}");
    let consumed = matches!(result, Ok(Some(_)));
    assert_eq!(handle.commits(), if consumed { 2 } else { 1 }, "{name}");
}

/// Spec 021, R3 and the Vectors section: a fresh channel reproduces every
/// verdict of `013.json`, a rejection committing nothing; a cursor-only
/// commit happens once per minute of cursor; a `decrypt` failing with
/// `Store(Io)` leaves the cursor unchanged.
#[test]
fn s021_t03_r03_rejection_commits_cursor_only() {
    let names = [
        "text_k1",
        "text_k63",
        "key_retired",
        "expired_received_at",
        "mutate_version",
        "mutate_channel_id",
        "mutate_enc_hdr",
        "mutate_nonce",
        "mutate_ciphertext",
        "mutate_signature",
        "signed_ciphertext_only",
        "short_blob",
        "long_blob",
        "unaligned_blob",
        "unknown_payload_key",
        "unknown_type",
        "bad_padding",
        "bad_payload_record",
        "missing_sent_at",
        "sent_at_not_a_minute",
        "display_name_too_long",
        "display_name_control",
        "display_name_not_utf8",
        "display_name_in_key_retired",
        "stale_sent_at",
        "stale_unknown_type",
        "stale_missing_type",
        "stale_trailing_garbage",
        "future_sent_at",
        "aead_forged_signed",
    ];
    let entries: Vec<(&str, vectors::Checker)> = names
        .iter()
        .map(|name| (*name, check_decrypt as vectors::Checker))
        .collect();
    vectors::check_all("013", &entries);

    let (mut channel, handle, faults) = receiver(3_600);
    let blob = text_from(&channel, PEER, 0, NOW);
    channel.decrypt(&blob, sid(1), NOW, NOW).unwrap();
    let all = handle.all_commits();
    // 100 replays within one minute: one cursor commit.
    for n in 0..100u64 {
        let result = channel.decrypt(
            &blob,
            sid(2),
            NOW + 60_000 + n * 500,
            NOW + 60_000 + n * 500,
        );
        assert_eq!(result, Err(Error::Replay));
    }
    assert_eq!(handle.all_commits(), all + 1);
    assert_eq!(handle.commits(), 2);

    let fresh = text_from(&channel, PEER, 1, NOW + 120_000);
    faults.fail_commits(true);
    let cursor = channel.cursor();
    let result = channel.decrypt(&fresh, sid(3), NOW + 180_000, NOW + 180_000);
    assert_eq!(result, Err(Error::Store(StoreError::Io)));
    assert_eq!(channel.cursor(), cursor);
}

/// Spec 021, R9: the signature before any state; a repeated `server_id`,
/// a republished blob of a removed sender and a counter at or below
/// `max_counter` are `Replay`.
#[test]
fn s021_t09_r09_state_check_order() {
    let (mut channel, handle, _) = receiver(3_600);
    let first = text_from(&channel, PEER, 5, NOW);
    channel.decrypt(&first, sid(1), NOW, NOW).unwrap();
    let mut forged = text_from(&channel, PEER, 6, NOW);
    let last = forged.len() - 1;
    forged[last] ^= 1;
    assert_eq!(
        channel.decrypt(&forged, sid(1), NOW, NOW),
        Err(Error::BadSignature)
    );
    let second = text_from(&channel, PEER, 6, NOW);
    assert_eq!(
        channel.decrypt(&second, sid(1), NOW, NOW),
        Err(Error::Replay)
    );
    let lower = text_from(&channel, PEER, 5, NOW + 60_000);
    assert_eq!(
        channel.decrypt(&lower, sid(2), NOW, NOW),
        Err(Error::Replay)
    );
    assert_eq!(handle.commits(), 2);
    // The sender evicted: its seen record still stops the copy.
    let mut next = channel.next_state();
    next.peers.clear();
    channel.commit(next, Vec::new()).unwrap();
    assert_eq!(
        channel.decrypt(&first, sid(3), NOW, NOW),
        Err(Error::Replay)
    );
    assert!(channel.state.peers.is_empty());
}

/// Spec 021, R10 and R26: a stale message, or one that would expire
/// before it is shown, is `Expired` and creates no peer; a message is shown
/// for a TTL from `min(sent_at, now)`, its seen record kept until
/// `sent_at + ttl_ms`.
#[test]
fn s021_t10_r10_stale_is_expired() {
    for vector in ["stale_sent_at", "future_sent_at"] {
        let vector = vectors::load("013", vector);
        let (mut channel, _, _) = receiver(text_k1::TTL_SECONDS);
        let blob = vector.expected("blob").bytes();
        let (received_at, now) = (
            vector.input("received_at").u64_hex(),
            vector.input("now").u64_hex(),
        );
        assert_eq!(
            channel.decrypt(blob, sid(1), received_at, now),
            Err(Error::Expired)
        );
        assert!(channel.state.peers.is_empty());
    }
    let (mut channel, handle, _) = receiver(3_600);
    for sent_at in [NOW - HOUR_MS - 60_000, NOW - HOUR_MS - MARGIN_MS - 60_000] {
        let blob = text_from(&channel, PEER, 1, sent_at);
        assert_eq!(
            channel.decrypt(&blob, sid(1), NOW, NOW),
            Err(Error::Expired)
        );
    }
    assert!(channel.state.peers.is_empty());
    assert_eq!(handle.commits(), 1);

    let blob = text_from(&channel, PEER, 1, NOW);
    let received = channel
        .decrypt(&blob, sid(1), NOW - HOUR_MS + 1_000, NOW)
        .unwrap()
        .unwrap();
    assert_eq!(received.expires_at, NOW + HOUR_MS);
    let [message, seen] = last_two(&channel);
    assert_eq!(
        (message.purge_at, seen.purge_at),
        (NOW + HOUR_MS, NOW + HOUR_MS)
    );

    let ahead = text_from(&channel, PEER, 2, NOW + HOUR_MS);
    let received = channel.decrypt(&ahead, sid(2), NOW, NOW).unwrap().unwrap();
    assert_eq!(received.expires_at, NOW + HOUR_MS);
    let [message, seen] = last_two(&channel);
    assert_eq!(
        (message.purge_at, seen.purge_at),
        (NOW + HOUR_MS, NOW + 2 * HOUR_MS)
    );
}

/// The last two records: a message and its seen record.
fn last_two(channel: &Channel) -> [&LogRecord; 2] {
    let records = &channel.records;
    let (message, seen) = (&records[records.len() - 2], &records[records.len() - 1]);
    assert!(matches!(message.entry, LogEntry::Message(_)));
    assert!(matches!(seen.entry, LogEntry::Seen { .. }));
    [message, seen]
}

/// Spec 021, R11: one commit of the record, the seen record, the new peer
/// and the cursor; the listed time clamped between `sent_at − 360 000` and
/// `now`; an unreadable message kept as `content` 2.
#[test]
fn s021_t11_r11_consumed_single_commit() {
    let (mut channel, handle, _) = receiver(3_600);
    let blob = text_from(&channel, PEER, 3, NOW);
    let received = channel
        .decrypt(&blob, sid(1), NOW + 5_000, NOW)
        .unwrap()
        .unwrap();
    assert_eq!(received.received_at, NOW);
    assert_eq!(handle.commits(), 2);
    let stored = reopened(&handle);
    assert!(state_eq(&stored.state, &channel.state));
    assert_eq!(stored.records.len(), 2);
    assert_eq!(stored.cursor(), Some(NOW));
    let peer = &stored.state.peers[0];
    assert_eq!(peer.pk.0, pk_of(PEER));
    assert_eq!(
        (peer.first_seen, peer.last_seen, peer.max_counter),
        (NOW, NOW, Some(3))
    );
    assert_eq!(
        peer.last_display_name.as_deref().map(|n| &n[..]),
        Some(&b"Bea"[..])
    );

    // A seven-day channel: an arrival dated six days before `sent_at`.
    let (mut week, _, _) = receiver(604_800);
    let blob = text_from(&week, PEER, 1, NOW);
    let early = NOW - 6 * 86_400_000;
    let received = week.decrypt(&blob, sid(1), early, NOW).unwrap().unwrap();
    assert_eq!(received.received_at, NOW - MARGIN_MS);

    let garbage = seal(&channel, PEER, |ctx, sender, nonce| {
        envelope::seal_padded(ctx, sender, 4, nonce, &[0; 1_024])
    });
    let received = channel
        .decrypt(&garbage, sid(2), NOW, NOW)
        .unwrap()
        .unwrap();
    assert!(received.content == MessageContent::Unreadable);
    assert_eq!(received.sent_at, None);
    let [message, _] = last_two(&channel);
    assert!(
        matches!(&message.entry, LogEntry::Message(m) if matches!(m.content, Content::Unreadable))
    );
}

/// Spec 021, R12: the `Received` of `text_k1`.
#[test]
fn s021_t12_r12_received_fields() {
    let vector = vectors::load("013", "text_k1");
    let (mut channel, _, _) = receiver(text_k1::TTL_SECONDS);
    let blob = vector.expected("blob").bytes();
    let received = channel
        .decrypt(blob, sid(9), text_k1::RECEIVED_AT, text_k1::NOW)
        .unwrap()
        .unwrap();
    let expected = Received {
        server_id: sid(9),
        sender: Sender::Peer {
            pk: pk_of(text_k1::SENDER_SEED),
        },
        received_at: text_k1::RECEIVED_AT,
        sent_at: Some(text_k1::SENT_AT),
        expires_at: text_k1::SENT_AT + HOUR_MS,
        content: MessageContent::Text {
            body: String::from_utf8(text_k1::BODY.to_vec()).unwrap(),
            display_name: None,
        },
    };
    assert!(received == expected);
}

/// Spec 021, R20: the cursor is the largest pushed time, clamped to `now`;
/// a push older than a TTL by the local clock leaves it.
#[test]
fn s021_t20_r20_cursor() {
    let (mut channel, _, _) = receiver(3_600);
    let blob = text_from(&channel, PEER, 0, 0);
    // A later push dated earlier leaves the cursor at the largest.
    for (n, received_at, cursor) in [(0, 5, 5), (1, 7, 7), (2, 3, 7)] {
        let verdict = channel.decrypt(&blob, sid(n), received_at, 10_000);
        assert!(!matches!(verdict, Err(Error::Store(_))), "{received_at}");
        assert_eq!(channel.cursor(), Some(cursor), "{received_at}");
    }
    let verdict = channel.decrypt(&blob, sid(9), u64::MAX, 1_000_000);
    assert_eq!(verdict, Err(Error::Replay));
    assert_eq!(channel.cursor(), Some(1_000_000));
    // At exactly one TTL old by the local clock, the push still moves it.
    let at = 1_000_000 + 60_000;
    let _ = channel.decrypt(&blob, sid(11), at, at + HOUR_MS);
    assert_eq!(channel.cursor(), Some(at));
    // The clock two hours ahead of the server in a one-hour channel.
    let fresh = text_from(&channel, PEER, 1, NOW);
    let result = channel.decrypt(&fresh, sid(10), NOW, NOW + 2 * HOUR_MS);
    assert_eq!(result, Err(Error::Expired));
    assert_eq!(channel.cursor(), Some(1_060_000));
}

/// Spec 021, R26: a copy pushed after its sender was removed and the log
/// purged is still a `Replay` by its pair, the body already gone.
#[test]
fn s021_t26_r26_peer_purge_at() {
    let (mut channel, handle, _) = receiver(3_600);
    let ahead = text_from(&channel, PEER, 0, NOW + HOUR_MS);
    channel.decrypt(&ahead, sid(1), NOW, NOW).unwrap();
    let mut next = channel.next_state();
    next.peers.clear();
    channel.commit(next, Vec::new()).unwrap();
    channel
        .store
        .compact(&channel.state, NOW + HOUR_MS + 1)
        .unwrap();
    let mut channel = reopened(&handle);
    assert_eq!(channel.records.len(), 1);
    let later = NOW + 2 * HOUR_MS - 60_000;
    assert_eq!(
        channel.decrypt(&ahead, sid(2), later, later),
        Err(Error::Replay)
    );
}

/// Spec 021, R32: a `decrypt` whose commit fails leaves memory, the cursor
/// and the reopened state as before.
#[test]
fn s021_t32_r32_failing_decrypt() {
    let (mut channel, handle, faults) = receiver(3_600);
    let blob = text_from(&channel, PEER, 0, NOW);
    let before = channel.state.duplicate();
    faults.fail_commits(true);
    assert_eq!(
        channel.decrypt(&blob, sid(1), NOW, NOW),
        Err(Error::Store(StoreError::Io))
    );
    assert!(state_eq(&reopened(&handle).state, &before));
    assert!(state_eq(&channel.state, &before));
    assert_eq!(channel.cursor(), None);
    assert!(channel.records.is_empty() && channel.expiry.oldest_expiry().is_none());
    assert!(channel.gaps().is_empty());
    // Nothing marked the push as seen: it is consumed when it comes again.
    faults.fail_commits(false);
    assert!(channel.decrypt(&blob, sid(1), NOW, NOW).unwrap().is_some());
}

/// Spec 021, R9: a counter at or below `max_counter` that no seen record
/// holds is `Replay`; a retired peer and an old key of one's own that is
/// not the one being retired are `RetiredKey`, with no commit.
#[test]
fn s021_t09_r09_max_counter_and_retired_keys() {
    let (mut channel, handle, _) = receiver(3_600);
    channel
        .decrypt(&text_from(&channel, PEER, 5, NOW), sid(1), NOW, NOW)
        .unwrap();
    let lower = text_from(&channel, PEER, 4, NOW);
    assert_eq!(
        channel.decrypt(&lower, sid(2), NOW, NOW),
        Err(Error::Replay)
    );

    let old = [0x66; 32];
    let mut next = channel.next_state();
    next.peers[0].retired_at = Some(NOW);
    next.own_old_keys.push(OldKey {
        pk: PublicKey(pk_of(old)),
        retired_at: NOW,
    });
    channel.commit(next, Vec::new()).unwrap();
    let commits = handle.commits();
    for (seed, id) in [(PEER, 3), (old, 4)] {
        let blob = text_from(&channel, seed, 9, NOW);
        assert_eq!(
            channel.decrypt(&blob, sid(id), NOW, NOW),
            Err(Error::RetiredKey)
        );
    }
    assert_eq!(handle.commits(), commits);
}

/// Spec 021, R3: a rejected push commits the cursor alone, never a waiting
/// `synced_at`.
#[test]
fn s021_t03_r03_rejection_leaves_synced_at() {
    let (mut channel, handle, _) = receiver(3_600);
    let blob = text_from(&channel, PEER, 0, NOW);
    channel.decrypt(&blob, sid(1), NOW, NOW).unwrap();
    channel.synced(NOW).unwrap();
    channel.synced(NOW + 1_000).unwrap();
    let all = handle.all_commits();
    assert_eq!(
        channel.decrypt(&blob, sid(2), NOW, NOW + 2_000_000),
        Err(Error::Replay)
    );
    assert_eq!(handle.all_commits(), all);
    assert_eq!(reopened(&handle).synced_at(), Some(NOW));
}
