//! Tests of sending: R7, R8, R26 for one's own message, R33, and the
//! `encrypt` clauses of R2 and R32.

use super::{SERVER, config_on, new_channel, new_store, reopened};
use crate::Error;
use crate::proto::envelope::{self, ChannelCtx};
use crate::session::channel::Channel;
use crate::storage::{ChannelState, Content, LogEntry, LogRecord, Message, StoreError};
use crate::testing::{FailingStore, Faults, state_eq};

const NOW: u64 = 1_790_000_123_456;
const HOUR_MS: u64 = 3_600_000;

/// A change to a state, made through one commit.
type Change = fn(&mut ChannelState);

/// The message a record holds, if it is one.
fn message_of(record: &LogRecord) -> Option<&Message> {
    match &record.entry {
        LogEntry::Message(message) => Some(message),
        _ => None,
    }
}

/// Sets `change` on the channel's state through one commit.
fn set(channel: &mut Channel, change: Change) {
    let mut next = channel.next_state();
    change(&mut next);
    channel.commit(next, Vec::new()).unwrap();
}

/// Spec 021, R7: the refusals in their order, each with no commit; then
/// one commit with the counter, the entry and the record, `sent_at` a
/// whole minute, and the name rules.
#[test]
fn s021_t07_r07_encrypt_order_and_commit() {
    let refusals: [(Change, Error); 3] = [
        // Read-only and exhausted: the first check wins.
        (
            |s| (s.read_only, s.send_counter) = (true, u64::MAX),
            Error::RetiredKey,
        ),
        (|s| s.send_counter = u64::MAX, Error::CounterExhausted),
        (|_| (), Error::Store(StoreError::OutboxFull)),
    ];
    for (change, error) in refusals {
        let (mut full, handle) = new_channel();
        for _ in 0..31 {
            full.encrypt("hi", None, NOW).unwrap();
        }
        set(&mut full, change);
        let commits = handle.commits();
        assert_eq!(full.encrypt("hi", Some(&"n".repeat(65)), NOW), Err(error));
        assert_eq!(handle.commits(), commits);
    }

    let (mut channel, handle) = new_channel();
    for (body, name) in [("hi", Some("n".repeat(65))), (&*"b".repeat(64_512), None)] {
        let result = channel.encrypt(body, name.as_deref(), NOW);
        assert_eq!(result, Err(Error::BadPayload));
    }
    assert_eq!(handle.commits(), 1);
    channel.encrypt("hi", Some("Ann"), NOW).unwrap();
    assert_eq!(handle.commits(), 2);
    let stored = reopened(&handle);
    assert_eq!(stored.state.send_counter, 1);
    assert_eq!(stored.state.outbox.len(), 1);
    assert_eq!(stored.records.len(), 1);
    assert_eq!(stored.state.outbox[0].sent_at, NOW - NOW % 60_000);
    assert_eq!(stored.state.own_display_name.as_deref(), Some("Ann"));

    // `None` keeps the stored name, `Some("")` clears it.
    let names = |channel: &Channel| {
        let message = message_of(channel.records.last().unwrap()).expect("a message");
        message.display_name.as_ref().map(|name| name.to_vec())
    };
    channel.encrypt("hi", None, NOW).unwrap();
    assert_eq!(names(&channel), Some(b"Ann".to_vec()));
    channel.encrypt("hi", Some(""), NOW).unwrap();
    assert_eq!(names(&channel), None);
    assert_eq!(reopened(&handle).state.own_display_name, None);
}

/// Spec 021, R8 and R26: the entry carries the signature and counter the
/// blob was sealed with; one's own record has no `server_id`, the entry's
/// `client_ref` and `sent_at`, and its `purge_at`.
#[test]
fn s021_t08_r08_outbox_entry_and_own_record() {
    let (mut channel, _) = new_channel();
    channel.encrypt("first", None, NOW).unwrap();
    let client_ref = channel.encrypt("second", Some("Ann"), NOW).unwrap();
    let entry = &channel.state.outbox[1];
    assert_eq!(entry.client_ref, client_ref.bytes);
    assert_eq!(entry.counter, 1);
    assert!(!entry.under_retired_key);
    let ctx = ChannelCtx::from_config(channel.config()).unwrap();
    let verified = envelope::verify(&entry.blob, &ctx, NOW, NOW).unwrap();
    assert_eq!(verified.signature(), &entry.signature.0);
    assert_eq!(verified.counter(), 1);
    let sent_at = NOW - NOW % 60_000;
    let record = channel.records.last().unwrap();
    assert_eq!(record.purge_at, sent_at + 2 * HOUR_MS + 420_000);
    let message = message_of(record).expect("a message");
    assert_eq!(message.server_id, None);
    assert_eq!(message.received_at, NOW);
    assert_eq!(message.sent_at, Some(sent_at));
    assert_eq!(message.counter, 1);
    assert_eq!(message.own_client_ref, Some(client_ref.bytes));
    assert_eq!(&message.sender_pk, verified.sender_pk());
    assert!(matches!(&message.content, Content::Text(body) if **body == *b"second"));
}

/// Spec 021, R26: one's own message near the end of time saturates.
#[test]
fn s021_t26_r26_purge_at() {
    let (mut channel, _) = new_channel();
    channel.encrypt("late", None, u64::MAX).unwrap();
    assert_eq!(channel.records.last().unwrap().purge_at, u64::MAX);
}

/// Spec 021, R33: the `ClientRef` of the entry sealed with a counter.
#[test]
fn s021_t33_r33_send_counter_and_outbox_ref() {
    let (mut channel, _) = new_channel();
    assert_eq!(channel.send_counter(), 0);
    assert_eq!(channel.outbox_ref(0), None);
    let client_ref = channel.encrypt("hi", None, NOW).unwrap();
    assert_eq!(
        channel.outbox_ref(channel.send_counter() - 1),
        Some(client_ref)
    );
    assert_eq!(channel.outbox_ref(channel.send_counter()), None);
}

/// Spec 021, R2 and R32: after a successful `encrypt`, memory and a
/// reopened store agree; after a failed one, both hold the state before.
#[test]
fn s021_t02_r02_encrypt_installs_after_ok() {
    let (store, handle) = new_store();
    let faults = Faults::new();
    let failing = Box::new(FailingStore::new(store, faults.clone()));
    let (mut channel, _) = Channel::create(&config_on(SERVER), failing).unwrap();
    channel.encrypt("one", None, NOW).unwrap();
    assert!(state_eq(&channel.state, &reopened(&handle).state));

    let before = channel.state.duplicate();
    faults.fail_commits(true);
    let result = channel.encrypt("two", Some("Ann"), NOW);
    assert_eq!(result, Err(Error::Store(StoreError::Io)));
    assert!(state_eq(&channel.state, &before));
    assert_eq!(channel.records.len(), 1);
    let stored = reopened(&handle);
    assert!(state_eq(&stored.state, &before));
    assert_eq!(stored.records.len(), 1);
}
