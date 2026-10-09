//! Tests of spec 028 R8 and R9: the truncation decided when a `subscribe`
//! is queued and again at its `ok`, and what the `ok` and the ticks call.

use super::{DAY, SERVER, T0, channel, connected, error, hello, ids, ok};
use crate::crypto::{Nonce, Secret};
use crate::proto::config::Config;
use crate::proto::envelope::{self, ChannelCtx, SenderKey};
use crate::proto::payload::{Payload, PayloadKind};
use crate::session::channel::Channel;
use crate::session::connection::{Channels, Event};
use crate::session::frames::Frame;
use crate::storage::Vault;
use crate::testing::{MemoryStore, MemoryVault};

/// A minute-long channel.
const MINUTE: u32 = 60;

fn truncated(channel: [u8; 16], now: u64, ttl_seconds: u32) -> Event {
    Event::HistoryTruncated {
        channel,
        before: now - u64::from(ttl_seconds) * 1_000,
    }
}

/// Moves the cursor of `channel` to `at`: any push does (spec 021 R20).
fn read_up_to(channel: &mut Channel, at: u64) {
    channel.decrypt(&[0; 8], [9; 16], at, at).ok();
}

/// The events of a `hello` at `now` to a fresh connection over `channels`.
fn hello_events(channels: &mut Channels, now: u64) -> Vec<Event> {
    let mut session = connected(channels, now);
    session.on_frame(&hello(1, &[1]), channels, now).events
}

/// Spec 028, R8: a channel away longer than a TTL → `HistoryTruncated` at
/// the `hello`, before any `ok`, recorded in the channel; `last` is
/// `max(cursor, synced_at)` with a future `synced_at` ignored; with no
/// `last`, `created_at` with six minutes of margin; one decision a
/// connection; a quiet channel synced recently, reopened → none.
#[test]
fn s028_t08_r08_truncation_before_backlog() {
    // A cursor a day and a millisecond old, and one a day old exactly.
    for (age, found) in [(86_400_001, true), (86_400_000, false)] {
        let mut channels = vec![channel(1, DAY, T0 - 2 * 86_400_000)];
        read_up_to(&mut channels[0], T0 - age);
        let id = ids(&channels)[0];
        let events = hello_events(&mut channels, T0);
        let expected: Vec<Event> = if found {
            vec![truncated(id, T0, DAY)]
        } else {
            vec![]
        };
        assert_eq!(events, expected, "{age}");
        let before = channels[0].status().truncated_before;
        assert_eq!(before, found.then_some(T0 - 86_400_000), "{age}");
    }

    // A recent `synced_at` hides an old cursor; one in the future does not.
    for (synced_at, found) in [(T0 - 1_000, false), (T0 + 1_000, true)] {
        let mut channels = vec![channel(1, DAY, T0 - 2 * 86_400_000)];
        read_up_to(&mut channels[0], T0 - 86_400_001);
        channels[0].synced(synced_at).unwrap();
        let found_now = !hello_events(&mut channels, T0).is_empty();
        assert_eq!(found_now, found, "{synced_at}");
    }

    // Never synced: `created_at + ttl_ms + 360 000` — a channel created a
    // minute ago, and an imported one five minutes past its TTL, are not
    // truncated; six minutes and a millisecond past it, it is.
    for (created_at, found) in [
        (T0 - 60_000, false),
        (T0 - 86_400_000 - 300_000, false),
        (T0 - 86_400_000 - 360_000, false),
        (T0 - 86_400_000 - 360_001, true),
    ] {
        let mut channels = vec![channel(1, DAY, created_at)];
        let found_now = !hello_events(&mut channels, T0).is_empty();
        assert_eq!(found_now, found, "{created_at}");
    }

    // Every channel queued is judged: two away longer than a TTL, in queue
    // order.
    let mut channels = vec![
        channel(3, DAY, T0 - 2 * 86_400_000),
        channel(4, DAY, T0 - 2 * 86_400_000),
    ];
    let [a, b] = [ids(&channels)[0], ids(&channels)[1]];
    let events = hello_events(&mut channels, T0);
    assert_eq!(events, [truncated(a, T0, DAY), truncated(b, T0, DAY)]);
    assert!(
        channels
            .iter()
            .all(|c| c.status().truncated_before.is_some())
    );

    // One decision a connection: a channel subscribed again under a second
    // `hello` gives no second event; a new connection decides again.
    let mut channels = vec![channel(1, DAY, T0 - 2 * 86_400_000)];
    let id = ids(&channels)[0];
    let mut session = connected(&channels, T0);
    let step = session.on_frame(&hello(1, &[1]), &mut channels, T0);
    assert_eq!(step.events, [truncated(id, T0, DAY)]);
    assert_eq!(session.outgoing().len(), 1);
    session.on_frame(&error("nonce_expired", Some(id)), &mut channels, T0 + 100);
    let step = session.on_frame(&hello(2, &[1]), &mut channels, T0 + 1_200);
    assert!(step.events.is_empty());
    assert_eq!(session.outgoing().len(), 1);
    let mut session = connected(&channels, T0 + 2_000);
    let step = session.on_frame(&hello(3, &[1]), &mut channels, T0 + 2_000);
    assert_eq!(step.events, [truncated(id, T0 + 2_000, DAY)]);

    // A one-minute channel complete 40 s before the `hello`, whose `ok`
    // comes 30 s later: truncated at the `ok`, which calls no `synced`.
    let mut channels = vec![channel(2, MINUTE, T0 - 600_000)];
    let id = ids(&channels)[0];
    channels[0].synced(T0 - 40_000).unwrap();
    let mut session = connected(&channels, T0);
    assert!(
        session
            .on_frame(&hello(1, &[1]), &mut channels, T0)
            .events
            .is_empty()
    );
    for at in (1..=30).map(|second| T0 + second * 1_000) {
        assert!(session.on_tick(&mut channels, at).events.is_empty());
    }
    // A backlog push dated after the expired stretch, before the `ok`, does
    // not hide it: the `ok` judges by the `last` of the `subscribe`.
    read_up_to(&mut channels[0], T0 + 29_000);
    let step = session.on_frame(&ok(id), &mut channels, T0 + 30_000);
    assert_eq!(
        step.events,
        [
            truncated(id, T0 + 30_000, MINUTE),
            Event::Subscribed { channel: id }
        ]
    );
    assert_eq!(channels[0].synced_at(), Some(T0 - 40_000));
    assert!(channels[0].status().truncated_before.is_some());

    // Found at the `hello`, with the `ok` 31 s later: recorded again at the
    // `ok`, since what expired meanwhile is missing too, then synced, so
    // that the commit of `synced` writes the new truncation.
    let (mut channels, handle) = stored_channel(MINUTE, T0 - 600_000);
    let id = ids(&channels)[0];
    let mut session = connected(&channels, T0);
    let step = session.on_frame(&hello(1, &[1]), &mut channels, T0);
    assert_eq!(step.events, [truncated(id, T0, MINUTE)]);
    for at in (1..=31).map(|second| T0 + second * 1_000) {
        assert!(session.on_tick(&mut channels, at).events.is_empty());
    }
    let step = session.on_frame(&ok(id), &mut channels, T0 + 31_000);
    assert_eq!(
        step.events,
        [
            truncated(id, T0 + 31_000, MINUTE),
            Event::Subscribed { channel: id }
        ]
    );
    assert_eq!(channels[0].synced_at(), Some(T0 + 31_000));
    let reopened = Channel::open_stored(Box::new(handle.reopen())).unwrap();
    let before = reopened.status().truncated_before;
    assert_eq!(before, Some(T0 + 31_000 - 60_000));

    // A quiet channel whose `synced_at` is recent, reopened from its store.
    let (mut channels, handle) = stored_channel(DAY, T0 - 2 * 86_400_000);
    channels[0].synced(T0 - 3_600_000).unwrap();
    let mut reopened = vec![Channel::open_stored(Box::new(handle.reopen())).unwrap()];
    assert_eq!(reopened[0].synced_at(), Some(T0 - 3_600_000));
    let id = ids(&reopened)[0];
    let mut session = connected(&reopened, T0);
    assert!(
        session
            .on_frame(&hello(1, &[1]), &mut reopened, T0)
            .events
            .is_empty()
    );
    // Its `ok` judges again by that `synced_at`: no truncation, synced.
    let step = session.on_frame(&ok(id), &mut reopened, T0 + 500);
    assert_eq!(step.events, [Event::Subscribed { channel: id }]);
    assert_eq!(reopened[0].synced_at(), Some(T0 + 500));
}

/// A channel of `ttl_seconds` and `created_at`, with a handle on its store.
fn stored_channel(ttl_seconds: u32, created_at: u64) -> (Channels, MemoryStore) {
    let k_ch = Secret::from_bytes([1; 32]);
    let config = Config::from_parts(k_ch, SERVER, ttl_seconds, "room", created_at).unwrap();
    let mut vault = MemoryVault::new();
    let store = vault.create(&config.channel_id()).unwrap();
    let handle = MemoryStore::handle(&vault, vault.dir_name(&config.channel_id()).unwrap());
    (vec![Channel::create(&config, store).unwrap().0], handle)
}

/// The blob Bob seals with `counter` at `sent_at`, a whole minute.
fn bob_blob(channel: &Channel, counter: u64, sent_at: u64) -> Vec<u8> {
    let ctx = ChannelCtx::from_config(channel.config()).unwrap();
    let bob = SenderKey::from_seed(&Secret::from_bytes([0x42; 32])).unwrap();
    let payload = Payload {
        kind: PayloadKind::Text,
        display_name: None,
        sent_at,
        body: b"hi".to_vec(),
    };
    let nonce = Nonce(core::array::from_fn(|i| {
        counter.to_be_bytes()[i % 8] ^ u8::try_from(i).unwrap()
    }));
    envelope::seal(&ctx, &bob, counter, &nonce, &payload)
        .unwrap()
        .blob
}

/// Spec 028, R8 and R10: a cursor older than `ttl_ms + 360 000`, then a
/// backlog of Bob's counters 250–300 over a `max_counter` of 100 → the
/// truncation is recorded before the backlog is decrypted, and no gap is
/// recorded for 250.
#[test]
fn s028_t08_r08_backlog_after_truncation_no_gap() {
    let mut channels = vec![channel(1, DAY, T0)];
    let id = ids(&channels)[0];
    let first = bob_blob(&channels[0], 100, T0);
    assert!(
        channels[0]
            .decrypt(&first, [1; 16], T0 + 1, T0 + 1)
            .unwrap()
            .is_some()
    );
    let at = T0 + 86_400_000 + 420_000;
    let mut session = connected(&channels, at);
    let step = session.on_frame(&hello(1, &[1]), &mut channels, at);
    assert_eq!(step.events, [truncated(id, at, DAY)]);
    for counter in 250..=300 {
        let push = Frame::Push {
            channel_id: id,
            server_id: [u8::try_from(counter - 200).unwrap(); 16],
            received_at: at + 1,
            blob: bob_blob(&channels[0], counter, at),
        }
        .encode()
        .unwrap();
        let step = session.on_frame(&push, &mut channels, at + 2);
        assert!(
            matches!(step.events[..], [Event::Message { .. }]),
            "{counter}"
        );
    }
    assert_eq!(channels[0].gaps(), []);
}
