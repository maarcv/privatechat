//! The fuzz target's verdict function (R29) and the exchange property of
//! R30.

use proptest::collection::vec;
use proptest::prelude::{ProptestConfig, proptest};

use super::{config_with, store_for};
use crate::Error;
use crate::fuzz_entry::channel_decrypt_verdict;
use crate::session::channel::{AckOutcome, Channel, MessageContent, Sender};
use crate::storage::StoreError;
use crate::testing::{FailingStore, Faults, MemoryStore, records_eq, state_eq};
use crate::vectors::{self, Vector};

/// A whole minute.
const NOW: u64 = 1_790_000_040_000;
const MESSAGES: u64 = 1_000;

/// The seed layout of R29: the two times, a `server_id`, the blob.
fn seed(vector: &Vector) -> Vec<u8> {
    let blob = if vector.has_input("blob") {
        vector.input("blob").bytes()
    } else {
        vector.expected("blob").bytes()
    };
    let received_at = vector.input("received_at").u64_hex().to_be_bytes();
    let now = vector.input("now").u64_hex().to_be_bytes();
    [&received_at[..], &now, &[0; 16], blob].concat()
}

/// The verdict function returns for a 013 seed.
fn check_returns(vector: &Vector) {
    assert!(
        channel_decrypt_verdict(&seed(vector)).is_some(),
        "{}",
        vector.name()
    );
}

/// Spec 021, R29: the verdict function of `channel_decrypt` returns for
/// every 013 seed, and the blob of `text_k1` reaches the own-key branch,
/// since the target's channel has the sender of `text_k1` as its own key.
#[test]
fn s021_t29_r29_channel_decrypt_target() {
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
        .map(|name| (*name, check_returns as vectors::Checker))
        .collect();
    vectors::check_all("013", &entries);
    let text_k1 = seed(&vectors::load("013", "text_k1"));
    let verdict = channel_decrypt_verdict(&text_k1);
    let sender = verdict
        .and_then(Result::ok)
        .flatten()
        .map(|received| received.sender);
    assert!(matches!(sender, Some(Sender::OwnKeyElsewhere { .. })));
    assert_eq!(channel_decrypt_verdict(&[0; 31]).map(|_| ()), None);
}

/// Runs `call` again once when the injected failure hit it.
fn retried<T>(mut call: impl FnMut() -> Result<T, Error>) -> Result<T, Error> {
    match call() {
        Err(Error::Store(StoreError::Io)) => call(),
        other => other,
    }
}

/// Two members of one channel exchange `MESSAGES` messages through a list
/// that stands in for the server; the push of message `i` comes twice
/// when `doubles[i]` is 0, and the `fail_at`-th commit fails.
fn exchange(fail_at: u32, doubles: &[u8]) {
    let config = config_with(3_600);
    let faults = Faults::new();
    let mut members: Vec<(Channel, MemoryStore)> = (0..2)
        .map(|_| {
            let (store, handle) = store_for(&config);
            let failing = Box::new(FailingStore::new(store, faults.clone()));
            (Channel::create(&config, failing).unwrap().0, handle)
        })
        .collect();
    faults.fail_at(fail_at);
    let mut received = [Vec::new(), Vec::new()];
    for i in 0..MESSAGES {
        let now = NOW + i * 1_000;
        let from = usize::try_from(i % 2).unwrap();
        let body = format!("message {i}");
        let sender = &mut members[from].0;
        let client_ref = retried(|| sender.encrypt(&body, None, now)).unwrap();
        let step = retried(|| sender.outbox(now, &[], false)).unwrap();
        assert_eq!(step.publish.len(), 1, "{i}");
        let blob = step.publish[0].1.clone();
        let mut server_id = [0; 16];
        server_id[8..].copy_from_slice(&i.to_be_bytes());
        let outcome = retried(|| sender.acked(client_ref, server_id, now, now)).unwrap();
        assert_eq!(outcome.outcome, AckOutcome::Delivered, "{i}");
        let pushes = if doubles[usize::try_from(i).unwrap()] == 0 {
            2
        } else {
            1
        };
        for push in 0..pushes {
            for (to, (member, _)) in members.iter_mut().enumerate() {
                let verdict = retried(|| member.decrypt(&blob, server_id, now, now));
                if to == from || push > 0 {
                    assert_eq!(verdict.map(|_| ()), Err(Error::Replay), "{i} {to} {push}");
                } else if let Ok(Some(message)) = verdict {
                    received[to].push(message.content);
                } else {
                    assert!(verdict.is_ok(), "{i} {to}: {verdict:?}");
                }
            }
        }
    }
    for (to, (member, handle)) in members.iter().enumerate() {
        let expected: Vec<MessageContent> = (0..MESSAGES)
            .filter(|i| usize::try_from(i % 2).unwrap() != to)
            .map(|i| MessageContent::Text {
                body: format!("message {i}"),
                display_name: None,
            })
            .collect();
        assert!(received[to] == expected, "member {to}");
        let stored = Channel::open_stored(Box::new(handle.reopen())).unwrap();
        assert!(state_eq(&stored.state, &member.state), "member {to}");
        assert!(records_eq(&stored.records, &member.records), "member {to}");
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 4, max_shrink_iters: 0, ..ProptestConfig::default() })]

    /// Spec 021, R30: every message is delivered once, every duplicate is
    /// `Replay`, and each reopened state equals the one in memory, whichever
    /// commit fails; proptest prints the failing case.
    #[test]
    fn s021_t30_r30_thousand_messages(fail_at in 1u32..3_000, doubles in vec(0u8..100, 1_000)) {
        exchange(fail_at, &doubles);
    }
}
