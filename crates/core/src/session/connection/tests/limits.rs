//! Tests of spec 028 R15 and R16: the publish rate, and each `error` code
//! with the pause, refusal, hold or new `subscribe` it leads to.

use super::acks::{ack, subscribed};
use super::traffic::{alice, published};
use super::{CONNECTION, DAY, HOST, T0, channel, connected, hello, ids, ok, reconnect};
use crate::session::channel::ClientRef;
use crate::session::connection::{Channels, Event, Session};
use crate::session::frames::Frame;
use crate::storage::StoreError;
use crate::testing::MemoryServer;

/// How long a pause lasts (R16), and R15's window.
const MINUTE: u64 = 60_000;

/// An `error` with `code`, naming what it names.
fn refusal(code: &str, channel_id: Option<[u8; 16]>, client_ref: Option<ClientRef>) -> Vec<u8> {
    Frame::Error {
        code: code.to_owned(),
        message: String::new(),
        channel_id,
        client_ref: client_ref.map(|client_ref| client_ref.bytes),
    }
    .encode()
    .unwrap()
}

/// Ticks every second after `from` up to `to`, `to` included, gathering
/// the entries published and the events.
fn tick_until(
    session: &mut Session,
    channels: &mut Channels,
    from: u64,
    to: u64,
) -> (Vec<ClientRef>, Vec<Event>) {
    let (mut sent, mut events) = (Vec::new(), Vec::new());
    let mut now = from;
    while now < to {
        now = (now + 1_000).min(to);
        events.extend(session.on_tick(channels, now).events);
        sent.extend(published(session));
    }
    (sent, events)
}

/// Two one-day channels, both subscribed at `T0 + 1_100`, and an entry of
/// the first published then and in flight.
fn two_subscribed() -> (Channels, Session, ClientRef) {
    let mut channels = vec![channel(1, DAY, T0), channel(2, DAY, T0)];
    let [first, second]: [[u8; 16]; 2] = ids(&channels).try_into().unwrap();
    let mut session = connected(&channels, T0);
    session.on_frame(&hello(1, &[1]), &mut channels, T0);
    session.on_frame(&ok(first), &mut channels, T0);
    session.on_tick(&mut channels, T0 + 1_100);
    session.on_frame(&ok(second), &mut channels, T0 + 1_100);
    session.outgoing();
    let sent = channels[0].encrypt("hi", None, T0 + 1_100).unwrap();
    session.after_send(first, &mut channels, T0 + 1_100);
    assert_eq!(published(&mut session), [sent]);
    (channels, session, sent)
}

/// Spec 028, R15: 31 sends in one minute → 30 `publish`es at once, the
/// 31st after the window; a new connection forgets the count and still
/// queues 30 at most; a publish recorded later than `now` counts as past.
#[test]
fn s028_t15_r15_publish_rate() {
    let mut channels = vec![channel(1, DAY, T0)];
    let id = ids(&channels)[0];
    let mut session = subscribed(&mut channels, T0);
    let (mut sent, mut at_once) = (Vec::new(), Vec::new());
    for second in 0..31 {
        let now = T0 + second * 1_000;
        session.on_tick(&mut channels, now);
        at_once.extend(published(&mut session));
        sent.push(channels[0].encrypt("hi", None, now).unwrap());
        session.after_send(id, &mut channels, now);
        at_once.extend(published(&mut session));
    }
    assert_eq!(at_once, sent[..30]);
    let (held, _) = tick_until(&mut session, &mut channels, T0 + 30_000, T0 + MINUTE - 1);
    assert_eq!(held, []);
    session.on_tick(&mut channels, T0 + MINUTE);
    assert_eq!(published(&mut session), [sent[30]]);

    // The window holds 30 again; a clock set back drops what it recorded
    // later than `now`. An `ack` makes room in the `outbox` (spec
    // 021-channel-session R8).
    session.on_frame(&ack(sent[0], 1, T0 + 100), &mut channels, T0 + MINUTE);
    let late = channels[0].encrypt("late", None, T0 + MINUTE).unwrap();
    session.after_send(id, &mut channels, T0 + MINUTE + 500);
    assert_eq!(published(&mut session), []);
    session.on_tick(&mut channels, T0 + 10_000);
    assert_eq!(published(&mut session), [late]);

    // A new connection: 31 entries unanswered, 30 leave at the `ok`.
    session.on_disconnect();
    session.on_connect(T0 + 11_000, &[]);
    session.on_frame(&hello(2, &[1]), &mut channels, T0 + 11_000);
    session.outgoing();
    session.on_frame(&ok(id), &mut channels, T0 + 11_000);
    assert_eq!(published(&mut session).len(), 30);
}

/// Spec 028, R16: every code but `bad_blob` and a `rate_limited` that
/// ends a `subscribe`: the named entry leaves the in-flight set; `bad_auth`
/// and `bad_ttl` refuse the named channel for the connection;
/// `channel_quota` pauses the channel of the entry, the named one, or
/// every one; a `rate_limited` naming an entry, or nothing, and
/// `server_full` pause every channel; a `rate_limited` naming a subscribed
/// channel, `not_subscribed` and an unnamed refusal ask for a new
/// connection; `unsupported_version` is R2's; another code does nothing.
#[test]
fn s028_t16_r16_error_codes() {
    // Another code: nothing, but the entry is out of flight, so the next
    // tick publishes it again.
    let (mut channels, mut session, sent) = two_subscribed();
    let [first, second]: [[u8; 16]; 2] = ids(&channels).try_into().unwrap();
    let step = session.on_frame(
        &refusal("teapot", None, Some(sent)),
        &mut channels,
        T0 + 1_200,
    );
    assert!(step.events.is_empty());
    session.on_tick(&mut channels, T0 + 2_000);
    assert_eq!(published(&mut session), [sent]);
    let step = session.on_frame(
        &refusal("not_subscribed", Some(first), Some(sent)),
        &mut channels,
        T0 + 2_100,
    );
    assert_eq!(step.events, [reconnect()]);
    session.on_tick(&mut channels, T0 + 3_000);
    assert_eq!(published(&mut session), [sent]);

    // `bad_auth` and `bad_ttl`: the named channel is refused, and not
    // subscribed again on this connection, even after a new `hello`; one
    // naming none is a `Reconnect`; a new connection forgets the refusal.
    for code in ["bad_auth", "bad_ttl"] {
        let (mut channels, mut session, _) = two_subscribed();
        let step = session.on_frame(
            &refusal(code, Some(second), None),
            &mut channels,
            T0 + 1_200,
        );
        assert_eq!(step.events, [Event::SubscribeRefused { channel: second }]);
        let stranger = refusal(code, Some([9; 16]), None);
        assert!(
            session
                .on_frame(&stranger, &mut channels, T0 + 1_300)
                .events
                .is_empty()
        );
        session.on_frame(&hello(2, &[1]), &mut channels, T0 + 1_400);
        let (_, events) = tick_until(&mut session, &mut channels, T0 + 1_400, T0 + 5_000);
        assert!(events.is_empty(), "{events:?}");
        assert!(session.outgoing().is_empty());
        let step = session.on_frame(&refusal(code, None, None), &mut channels, T0 + 5_100);
        assert_eq!(step.events, [reconnect()]);
        session.on_connect(T0 + 6_000, &[]);
        session.on_frame(&hello(3, &[1]), &mut channels, T0 + 6_000);
        session.on_tick(&mut channels, T0 + 7_100);
        let mut again = super::subscribed_ids(&mut session, &channels);
        again.sort_unstable();
        let mut both = [first, second];
        both.sort_unstable();
        assert_eq!(again, both);
    }

    // `channel_quota` naming the entry: its channel alone publishes
    // nothing for a minute, the other still does at once.
    let (mut channels, mut session, sent) = two_subscribed();
    let quota = refusal("channel_quota", Some(second), Some(sent));
    let step = session.on_frame(&quota, &mut channels, T0 + 1_200);
    assert_eq!(step.events, [Event::ChannelFull { channel: first }]);
    channels[0].encrypt("more", None, T0 + 1_200).unwrap();
    session.after_send(first, &mut channels, T0 + 1_200);
    assert_eq!(published(&mut session), []);
    let other = channels[1].encrypt("other", None, T0 + 1_300).unwrap();
    session.after_send(second, &mut channels, T0 + 1_300);
    assert_eq!(published(&mut session), [other]);
    let (held, _) = tick_until(
        &mut session,
        &mut channels,
        T0 + 1_300,
        T0 + 1_200 + MINUTE - 1,
    );
    assert_eq!(held, []);
    session.on_tick(&mut channels, T0 + 1_200 + MINUTE);
    assert_eq!(published(&mut session).len(), 2);

    // Naming the channel alone, nothing, or a channel of no session.
    let (mut channels, mut session, _) = two_subscribed();
    let step = session.on_frame(
        &refusal("channel_quota", Some(second), None),
        &mut channels,
        T0 + 1_200,
    );
    assert_eq!(step.events, [Event::ChannelFull { channel: second }]);
    let step = session.on_frame(
        &refusal("channel_quota", None, None),
        &mut channels,
        T0 + 1_300,
    );
    let full = [first, second].map(|channel| Event::ChannelFull { channel });
    assert_eq!(step.events, full);
    let step = session.on_frame(
        &refusal("channel_quota", Some([9; 16]), None),
        &mut channels,
        T0 + 1_400,
    );
    assert!(step.events.is_empty());
    // A new connection forgets the pause: the entry leaves at the `ok`.
    session.on_connect(T0 + 2_000, &[]);
    session.on_frame(&hello(2, &[1]), &mut channels, T0 + 2_000);
    session.outgoing();
    session.on_frame(&ok(first), &mut channels, T0 + 2_000);
    assert_eq!(published(&mut session).len(), 1);

    // `rate_limited` naming an entry, or nothing, and `server_full`: no
    // channel publishes for a minute; an entry named leaves the in-flight
    // set and is published again after it.
    let full = Event::ServerFull {
        connection: CONNECTION,
    };
    for (code, named, events) in [
        ("rate_limited", true, vec![]),
        ("rate_limited", false, vec![]),
        ("server_full", false, vec![full]),
    ] {
        let (mut channels, mut session, sent) = two_subscribed();
        let entry = named.then_some(sent);
        let frame = refusal(code, entry.map(|_| first), entry);
        let step = session.on_frame(&frame, &mut channels, T0 + 1_200);
        assert_eq!(step.events, events);
        let other = channels[1].encrypt("other", None, T0 + 1_300).unwrap();
        session.after_send(second, &mut channels, T0 + 1_300);
        let (held, _) = tick_until(
            &mut session,
            &mut channels,
            T0 + 1_200,
            T0 + 1_200 + MINUTE - 1,
        );
        assert_eq!(held, []);
        session.on_tick(&mut channels, T0 + 1_200 + MINUTE);
        let mut again = published(&mut session);
        again.sort_unstable_by_key(|client_ref| client_ref.bytes);
        let mut expected: Vec<_> = entry.into_iter().chain([other]).collect();
        expected.sort_unstable_by_key(|client_ref| client_ref.bytes);
        assert_eq!(again, expected, "{code} {named}");
    }

    // `rate_limited` naming a subscribed channel and no entry.
    let (mut channels, mut session, _) = two_subscribed();
    let step = session.on_frame(
        &refusal("rate_limited", Some(first), None),
        &mut channels,
        T0 + 1_200,
    );
    assert_eq!(step.events, [reconnect()]);

    // `unsupported_version`: R2's event, and nothing sent after it.
    let (mut channels, mut session, _) = two_subscribed();
    let step = session.on_frame(
        &refusal("unsupported_version", None, None),
        &mut channels,
        T0 + 1_200,
    );
    let unsupported = Event::UnsupportedServer {
        connection: CONNECTION,
    };
    assert_eq!(step.events, [unsupported]);
    channels[0].encrypt("more", None, T0 + 1_300).unwrap();
    session.after_send(first, &mut channels, T0 + 1_300);
    session.on_tick(&mut channels, T0 + 2_000);
    assert!(session.outgoing().is_empty());
}

/// Spec 028, R16: a `bad_blob` of an ordinary entry → `NotDelivered`, the
/// entry gone; of the current `key_retired` copy → that copy held within
/// its minute, the next minute's copy published; naming nothing →
/// `Reconnect`; naming an entry not in flight → nothing.
#[test]
fn s028_t16_r16_bad_blob() {
    let (mut channels, mut session, sent) = two_subscribed();
    let first = ids(&channels)[0];
    let step = session.on_frame(
        &refusal("bad_blob", Some(first), Some(sent)),
        &mut channels,
        T0 + 1_200,
    );
    let gone = Event::NotDelivered {
        channel: first,
        client_ref: sent,
        // `sent_at` is the minute it was sealed in (spec 013-wire-message R8).
        sent_at: T0,
    };
    assert_eq!(step.events, [gone]);
    session.on_tick(&mut channels, T0 + 2_000);
    assert_eq!(published(&mut session), []);
    let step = session.on_frame(
        &refusal("bad_blob", Some(first), Some(sent)),
        &mut channels,
        T0 + 2_100,
    );
    assert!(step.events.is_empty());
    let step = session.on_frame(
        &refusal("bad_blob", Some(first), None),
        &mut channels,
        T0 + 2_200,
    );
    assert_eq!(step.events, [reconnect()]);

    let (mut channels, _, _) = alice();
    let id = ids(&channels)[0];
    channels[0].regenerate_identity(T0).unwrap();
    let mut session = subscribed(&mut channels, T0);
    let [copy] = published(&mut session).try_into().unwrap();
    let step = session.on_frame(
        &refusal("bad_blob", Some(id), Some(copy)),
        &mut channels,
        T0 + 100,
    );
    assert!(step.events.is_empty());
    assert!(channels[0].status().retirement_pending);
    let (held, _) = tick_until(&mut session, &mut channels, T0 + 100, T0 + MINUTE - 1);
    assert_eq!(held, []);
    session.on_tick(&mut channels, T0 + MINUTE);
    let next = published(&mut session);
    assert_eq!(next.len(), 1);
    assert_ne!(next[0], copy);
}

/// Spec 028, R16 and R10: a `bad_blob` whose `abandon` fails → no
/// `NotDelivered`, the channel in `failed`, and the entry not published
/// again on this connection, after a cleared `write_failed` mark too,
/// unless a clearing with `storage_full` returns the channel to the
/// `LogFull` stall, which publishes.
#[test]
fn s028_t16_r16_bad_blob_abandon_fails() {
    for storage_full in [false, true] {
        let (mut channels, _, faults) = alice();
        let id = ids(&channels)[0];
        let sent = channels[0].encrypt("hi", None, T0).unwrap();
        let mut session = subscribed(&mut channels, T0);
        assert_eq!(published(&mut session), [sent]);
        faults.fail_commits(true);
        let step = session.on_frame(
            &refusal("bad_blob", Some(id), Some(sent)),
            &mut channels,
            T0 + 100,
        );
        faults.fail_commits(false);
        assert!(step.events.is_empty());
        assert_eq!(step.failed, [(id, StoreError::Io)]);
        session.on_tick(&mut channels, T0 + 1_000);
        assert_eq!(published(&mut session), []);

        session.set_write_failed(&channels[0], true, false);
        session.set_write_failed(&channels[0], false, storage_full);
        session.on_tick(&mut channels, T0 + 2_000);
        let again = if storage_full { vec![sent] } else { vec![] };
        assert_eq!(published(&mut session), again);
    }
}

/// Spec 028, R16 and R7: a `rate_limited` naming a channel awaiting `ok`
/// and no entry → that channel subscribed again at the next tick, while a
/// publish on another subscribed channel still goes at once; one arriving
/// 130 s after the `hello` → a `subscribe` under the old nonce, the
/// server's `nonce_expired` and fresh `hello`, and the `subscribe` under the
/// new nonce, with no `Reconnect`.
#[test]
fn s028_t16_r16_rate_limited_subscribe() {
    let mut channels = vec![channel(1, DAY, T0), channel(2, DAY, T0)];
    let [first, second]: [[u8; 16]; 2] = ids(&channels).try_into().unwrap();
    let mut session = connected(&channels, T0);
    session.on_frame(&hello(1, &[1]), &mut channels, T0);
    session.on_frame(&ok(first), &mut channels, T0);
    session.on_tick(&mut channels, T0 + 1_100);
    session.outgoing();
    let ended = refusal("rate_limited", Some(second), None);
    let step = session.on_frame(&ended, &mut channels, T0 + 1_200);
    assert!(step.events.is_empty());
    let sent = channels[0].encrypt("hi", None, T0 + 1_200).unwrap();
    session.after_send(first, &mut channels, T0 + 1_200);
    assert_eq!(published(&mut session), [sent]);
    session.on_tick(&mut channels, T0 + 2_000);
    assert!(session.outgoing().is_empty());
    session.on_tick(&mut channels, T0 + 2_200);
    assert_eq!(super::subscribed_ids(&mut session, &channels), [second]);
    let step = session.on_frame(&ok(second), &mut channels, T0 + 2_300);
    assert_eq!(step.events, [Event::Subscribed { channel: second }]);

    // 130 s after the `hello`, through the server: an ignored frame every
    // 30 s keeps R9's 60 000 ms rule quiet while the server holds it.
    let mut server = MemoryServer::new(&[HOST]);
    let mut channels = vec![channel(1, DAY, T0)];
    let id = ids(&channels)[0];
    let mut session = connected(&channels, T0);
    server.connect(CONNECTION, T0);
    let mut events = Vec::new();
    for second in 0..=140 {
        let now = T0 + second * 1_000;
        if second == 130 {
            server.end(CONNECTION, &id);
        }
        let frames = match second {
            0 => server.read(CONNECTION, 1),
            130.. => server.read(CONNECTION, 100),
            _ if second % 30 == 0 => vec![ok([0xee; 16])],
            _ => Vec::new(),
        };
        for frame in &frames {
            events.extend(session.on_frame(frame, &mut channels, now).events);
        }
        events.extend(session.on_tick(&mut channels, now).events);
        for frame in session.outgoing() {
            server.receive(CONNECTION, &frame, now);
        }
    }
    assert_eq!(events, [Event::Subscribed { channel: id }]);
}

/// Spec 028, R16 and R7: two subscriptions ended 12 s apart past the
/// `hello`'s window, with 20 s of delay from client to server → both
/// subscribed again, neither refused: the second `subscribe` under the old
/// nonce waits for the fresh `hello` the first one brings.
#[test]
fn s028_t16_r16_two_endings_delayed() {
    const DELAY: u64 = 20_000;
    let mut server = MemoryServer::new(&[HOST]);
    let mut channels = vec![
        channel(1, DAY, T0),
        channel(2, DAY, T0),
        channel(3, DAY, T0),
    ];
    let [kept, a, b]: [[u8; 16]; 3] = ids(&channels).try_into().unwrap();
    let mut session = connected(&channels, T0);
    server.connect(CONNECTION, T0);
    let mut link: Vec<(u64, Vec<u8>)> = Vec::new();
    let mut events = Vec::new();
    for second in 0..=140 {
        let now = T0 + second * 1_000;
        let (due, later): (Vec<_>, Vec<_>) =
            link.into_iter().partition(|(at, _)| at + DELAY <= now);
        link = later;
        for (_, frame) in due {
            server.receive(CONNECTION, &frame, now);
        }
        match second {
            55 => server.end(CONNECTION, &a),
            67 => server.end(CONNECTION, &b),
            _ => {}
        }
        // Unread, the server holds `a` and `b` catching up until it ends
        // them.
        let max = match second {
            ..=21 | 67.. => 100,
            55 => 1,
            _ => 0,
        };
        for frame in server.read(CONNECTION, max) {
            events.extend(session.on_frame(&frame, &mut channels, now).events);
        }
        if second == 60 {
            let sent = channels[0].encrypt("hi", None, now).unwrap();
            session.after_send(kept, &mut channels, now);
            assert_eq!(published(&mut session), [sent]);
        }
        events.extend(session.on_tick(&mut channels, now).events);
        link.extend(session.outgoing().into_iter().map(|frame| (now, frame)));
    }
    let subscribed = [kept, a, b].map(|channel| Event::Subscribed { channel });
    assert_eq!(events, subscribed);
}
