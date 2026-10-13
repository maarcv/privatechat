//! Tests of spec 028 R15 and R16: the publish rate, and each `error` code
//! with the pause, refusal, hold or new `subscribe` it leads to.

use super::acks::{ack, subscribed};
use super::traffic::{alice, published};
use super::{CONNECTION, DAY, HOST, T0, channel, connected, hello, ids, ok, reconnect};
use crate::session::channel::{Channel, ClientRef};
use crate::session::connection::{Channels, Event, Session};
use crate::session::frames::Frame;
use crate::storage::StoreError;
use crate::testing::MemoryServer;

/// How long a pause lasts (R16), and R15's window.
const MINUTE: u64 = 60_000;

/// An `error` with `code`, naming what it names.
pub(super) fn error_frame(
    code: &str,
    channel_id: Option<[u8; 16]>,
    client_ref: Option<ClientRef>,
) -> Vec<u8> {
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
/// ends a `subscribe`: the named entry leaves the in-flight set, held
/// until the minute it was published in ends; `bad_auth`
/// and `bad_ttl` refuse the named channel for the connection;
/// `channel_quota` pauses the channel of the entry, the named one, or
/// every one; a `rate_limited` naming an entry, or nothing, and
/// `server_full` pause every channel; a `rate_limited` naming a subscribed
/// channel, `not_subscribed` and an unnamed refusal ask for a new
/// connection; `unsupported_version` is R2's; another code does nothing.
#[test]
fn s028_t16_r16_error_codes() {
    // Another code: nothing, but the entry is out of flight, held until the
    // minute it was published in ends, then published again.
    let (mut channels, mut session, sent) = two_subscribed();
    let [first, second]: [[u8; 16]; 2] = ids(&channels).try_into().unwrap();
    let step = session.on_frame(
        &error_frame("teapot", None, Some(sent)),
        &mut channels,
        T0 + 1_200,
    );
    assert!(step.events.is_empty());
    let (held, _) = tick_until(&mut session, &mut channels, T0 + 1_200, T0 + MINUTE - 1);
    assert_eq!(held, []);
    session.on_tick(&mut channels, T0 + MINUTE);
    assert_eq!(published(&mut session), [sent]);
    // `not_subscribed` naming it: a `Reconnect`, and the same hold.
    let step = session.on_frame(
        &error_frame("not_subscribed", Some(first), Some(sent)),
        &mut channels,
        T0 + MINUTE + 100,
    );
    assert_eq!(step.events, [reconnect()]);
    let (held, _) = tick_until(
        &mut session,
        &mut channels,
        T0 + MINUTE + 100,
        T0 + 2 * MINUTE - 1,
    );
    assert_eq!(held, []);
    session.on_tick(&mut channels, T0 + 2 * MINUTE);
    assert_eq!(published(&mut session), [sent]);
    let step = session.on_frame(
        &error_frame("not_subscribed", None, None),
        &mut channels,
        T0 + 2 * MINUTE + 100,
    );
    assert_eq!(step.events, [reconnect()]);
    // `nonce_expired` naming no channel: a `Reconnect`, and the same hold.
    let step = session.on_frame(
        &error_frame("nonce_expired", None, Some(sent)),
        &mut channels,
        T0 + 2 * MINUTE + 200,
    );
    assert_eq!(step.events, [reconnect()]);
    let (held, _) = tick_until(
        &mut session,
        &mut channels,
        T0 + 2 * MINUTE + 200,
        T0 + 3 * MINUTE - 1,
    );
    assert_eq!(held, []);
    session.on_tick(&mut channels, T0 + 3 * MINUTE);
    assert_eq!(published(&mut session), [sent]);

    // `bad_auth` and `bad_ttl`: the named channel is refused, and not
    // subscribed again on this connection, even after a new `hello`; one
    // naming none is a `Reconnect`; a new connection forgets the refusal.
    for code in ["bad_auth", "bad_ttl"] {
        let (mut channels, mut session, sent) = two_subscribed();
        let step = session.on_frame(
            &error_frame(code, Some(second), Some(sent)),
            &mut channels,
            T0 + 1_200,
        );
        assert_eq!(step.events, [Event::SubscribeRefused { channel: second }]);
        // The entry it named is held within its minute.
        session.on_tick(&mut channels, T0 + 1_300);
        assert_eq!(published(&mut session), []);
        let stranger = error_frame(code, Some([9; 16]), None);
        assert!(
            session
                .on_frame(&stranger, &mut channels, T0 + 1_300)
                .events
                .is_empty()
        );
        // Refused, it publishes nothing.
        channels[1].encrypt("hi", None, T0 + 1_300).unwrap();
        session.after_send(second, &mut channels, T0 + 1_300);
        assert!(session.outgoing().is_empty());
        session.on_frame(&hello(2, &[1]), &mut channels, T0 + 1_400);
        for at in (2..=5).map(|second| T0 + second * 1_000) {
            assert!(session.on_tick(&mut channels, at).events.is_empty());
            assert!(super::subscribed_ids(&mut session, &channels).is_empty());
        }
        let step = session.on_frame(&error_frame(code, None, None), &mut channels, T0 + 5_100);
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

    // A refusal of a channel still queued: its `subscribe` never leaves;
    // one awaiting its `ok`: a later `ok` does not subscribe it.
    let mut three: Channels = (1..=3).map(|byte| channel(byte, DAY, T0)).collect();
    let [one, two, queued]: [[u8; 16]; 3] = ids(&three).try_into().unwrap();
    let mut session = connected(&three, T0);
    session.on_frame(&hello(1, &[1]), &mut three, T0);
    assert_eq!(super::subscribed_ids(&mut session, &three), [one]);
    for (named, at) in [(queued, T0 + 100), (one, T0 + 200)] {
        let step = session.on_frame(&error_frame("bad_auth", Some(named), None), &mut three, at);
        assert_eq!(step.events, [Event::SubscribeRefused { channel: named }]);
    }
    let mut released = Vec::new();
    for at in (1..=5).map(|second| T0 + second * 1_000) {
        session.on_tick(&mut three, at);
        released.extend(super::subscribed_ids(&mut session, &three));
    }
    assert_eq!(released, [two]);
    assert!(
        session
            .on_frame(&ok(one), &mut three, T0 + 5_100)
            .events
            .is_empty()
    );

    // `channel_quota` naming the entry: its channel alone publishes
    // nothing for a minute, the other still does at once.
    let (mut channels, mut session, sent) = two_subscribed();
    let quota = error_frame("channel_quota", Some(second), Some(sent));
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
        &error_frame("channel_quota", Some(second), None),
        &mut channels,
        T0 + 1_200,
    );
    assert_eq!(step.events, [Event::ChannelFull { channel: second }]);
    let step = session.on_frame(
        &error_frame("channel_quota", None, None),
        &mut channels,
        T0 + 1_300,
    );
    let full = [first, second].map(|channel| Event::ChannelFull { channel });
    assert_eq!(step.events, full);
    let step = session.on_frame(
        &error_frame("channel_quota", Some([9; 16]), None),
        &mut channels,
        T0 + 1_400,
    );
    assert!(step.events.is_empty());
    // An entry not in flight and no channel: every channel.
    let unknown = ClientRef { bytes: [9; 16] };
    let step = session.on_frame(
        &error_frame("channel_quota", None, Some(unknown)),
        &mut channels,
        T0 + 1_500,
    );
    assert_eq!(step.events, full);
    // A new connection forgets the pause: the entry leaves at the `ok`.
    session.on_connect(T0 + 2_000, &[]);
    session.on_frame(&hello(2, &[1]), &mut channels, T0 + 2_000);
    session.outgoing();
    session.on_frame(&ok(first), &mut channels, T0 + 2_000);
    assert_eq!(published(&mut session).len(), 1);

    // `rate_limited` naming an entry, or nothing, and `server_full`: no
    // channel publishes for a minute; an entry named leaves the in-flight
    // set and is published again after it.
    let busy = || {
        vec![Event::ServerFull {
            connection: CONNECTION,
        }]
    };
    for (code, named, events) in [
        ("server_full", false, busy()),
        ("rate_limited", true, vec![]),
        ("rate_limited", false, vec![]),
        ("server_full", true, busy()),
    ] {
        let (mut channels, mut session, sent) = two_subscribed();
        let entry = named.then_some(sent);
        let frame = error_frame(code, entry.map(|_| first), entry);
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

    // A pause running at an `ok`: the `outbox` waits for its end. A clock
    // set back before the pause ends it; a new connection forgets it.
    let mut channels = vec![channel(1, DAY, T0), channel(2, DAY, T0)];
    let mut session = connected(&channels, T0);
    session.on_frame(&hello(1, &[1]), &mut channels, T0);
    session.on_frame(&ok(first), &mut channels, T0);
    session.on_tick(&mut channels, T0 + 1_100);
    session.outgoing();
    let waiting = channels[1].encrypt("waiting", None, T0 + 1_100).unwrap();
    let busy = error_frame("server_full", None, None);
    session.on_frame(&busy, &mut channels, T0 + 1_200);
    session.on_frame(&ok(second), &mut channels, T0 + 1_300);
    let (held, _) = tick_until(
        &mut session,
        &mut channels,
        T0 + 1_300,
        T0 + 1_200 + MINUTE - 1,
    );
    assert_eq!(held, []);
    session.on_tick(&mut channels, T0 + 1_200 + MINUTE);
    assert_eq!(published(&mut session), [waiting]);
    let more = channels[1]
        .encrypt("more", None, T0 + MINUTE + 2_000)
        .unwrap();
    session.on_frame(&busy, &mut channels, T0 + MINUTE + 2_000);
    session.on_tick(&mut channels, T0 + 10_000);
    assert_eq!(published(&mut session), [more]);
    let late = channels[1].encrypt("late", None, T0 + 10_000).unwrap();
    session.on_frame(&busy, &mut channels, T0 + 10_000);
    session.on_connect(T0 + 11_000, &[]);
    session.on_frame(&hello(2, &[1]), &mut channels, T0 + 11_000);
    session.on_tick(&mut channels, T0 + 12_100);
    session.outgoing();
    session.on_frame(&ok(second), &mut channels, T0 + 12_200);
    let again = published(&mut session);
    assert!(again.contains(&late), "{again:?}");

    // `rate_limited` naming a subscribed channel and no entry.
    let (mut channels, mut session, _) = two_subscribed();
    let step = session.on_frame(
        &error_frame("rate_limited", Some(first), None),
        &mut channels,
        T0 + 1_200,
    );
    assert_eq!(step.events, [reconnect()]);

    // `unsupported_version`: R2's event, and nothing sent after it.
    let (mut channels, mut session, _) = two_subscribed();
    let step = session.on_frame(
        &error_frame("unsupported_version", None, None),
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
/// the minute it was sealed in, the next minute's copy published, also
/// when the `bad_blob` comes in that next minute; naming nothing →
/// `Reconnect`; naming an entry not in flight → nothing.
#[test]
fn s028_t16_r16_bad_blob() {
    let (mut channels, mut session, sent) = two_subscribed();
    let first = ids(&channels)[0];
    let step = session.on_frame(
        &error_frame("bad_blob", Some(first), Some(sent)),
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
        &error_frame("bad_blob", Some(first), Some(sent)),
        &mut channels,
        T0 + 2_100,
    );
    assert!(step.events.is_empty());
    // Naming another channel: the entry's own channel abandons it.
    let (mut channels, mut session, sent) = two_subscribed();
    let [first, second]: [[u8; 16]; 2] = ids(&channels).try_into().unwrap();
    let step = session.on_frame(
        &error_frame("bad_blob", Some(second), Some(sent)),
        &mut channels,
        T0 + 1_200,
    );
    let gone = Event::NotDelivered {
        channel: first,
        client_ref: sent,
        sent_at: T0,
    };
    assert_eq!(step.events, [gone]);
    session.on_tick(&mut channels, T0 + MINUTE);
    assert_eq!(published(&mut session), []);
    let step = session.on_frame(
        &error_frame("bad_blob", Some(first), None),
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
        &error_frame("bad_blob", Some(id), Some(copy)),
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

    // A copy sealed in one minute and refused in the next: the hold ends
    // with the minute it was sealed in, and the next tick re-seals it.
    let mut channels = vec![channel(3, 60, T0)];
    let id = ids(&channels)[0];
    channels[0].regenerate_identity(T0).unwrap();
    let mut session = subscribed(&mut channels, T0 + 59_500);
    let [copy] = published(&mut session).try_into().unwrap();
    let refused = error_frame("bad_blob", Some(id), Some(copy));
    session.on_frame(&refused, &mut channels, T0 + MINUTE + 500);
    session.on_tick(&mut channels, T0 + MINUTE + 1_000);
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
            &error_frame("bad_blob", Some(id), Some(sent)),
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
        assert_eq!(published(&mut session), []);
        // Past the hold of the minute it was published in.
        session.on_tick(&mut channels, T0 + MINUTE);
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
    let ended = error_frame("rate_limited", Some(second), None);
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
/// nonce waits for the fresh `hello` the first one brings, while the first
/// left at once, the other still awaiting its `ok`. One ended within the
/// window and one past it: the second leaves at once, the first, fresh,
/// still awaiting its `ok`.
#[test]
fn s028_t16_r16_two_endings_delayed() {
    let (events, a_again, _) = delayed_endings((55, 67));
    assert_eq!(a_again, Some(55));
    assert_eq!(events.len(), 3, "{events:?}");
    let (events, a_again, b_again) = delayed_endings((30, 55));
    assert_eq!((a_again, b_again), (Some(30), Some(55)));
    assert_eq!(events.len(), 3, "{events:?}");
}

/// Three channels through `MemoryServer` with 20 s of delay from client
/// to server, the second and third ended at seconds `ends`, the server
/// read only at those seconds until the second ending; the events (all
/// `Subscribed`, checked) and the seconds at which the two ended channels
/// first write a `subscribe` again.
fn delayed_endings(ends: (u64, u64)) -> (Vec<Event>, Option<u64>, Option<u64>) {
    const DELAY: u64 = 20_000;
    let (first_end, second_end) = ends;
    let mut server = MemoryServer::new(&[HOST]);
    let mut channels = vec![
        channel(1, DAY, T0),
        channel(2, DAY, T0),
        channel(3, DAY, T0),
    ];
    let [kept, a, b]: [[u8; 16]; 3] = ids(&channels).try_into().unwrap();
    let pk = |channel: &Channel| channel.config().channel_keypair().unwrap().0.0;
    let (pk_a, pk_b) = (pk(&channels[1]), pk(&channels[2]));
    let mut session = connected(&channels, T0);
    server.connect(CONNECTION, T0);
    let mut link: Vec<(u64, Vec<u8>)> = Vec::new();
    let mut events = Vec::new();
    let (mut a_again, mut b_again) = (None, None);
    for second in 0..=140 {
        let now = T0 + second * 1_000;
        let (due, later): (Vec<_>, Vec<_>) =
            link.into_iter().partition(|(at, _)| at + DELAY <= now);
        link = later;
        for (_, frame) in due {
            server.receive(CONNECTION, &frame, now);
        }
        if second == first_end {
            server.end(CONNECTION, &a);
        }
        if second == second_end {
            server.end(CONNECTION, &b);
        }
        // Unread, the server holds what catches up until it ends it: at an
        // ending only its `error` is read.
        let max = match second {
            ..=21 => 100,
            _ if second == first_end || second == second_end => 1,
            _ if second > second_end => 100,
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
        let written = session.outgoing();
        for frame in &written {
            if let Frame::Subscribe { pk_ch, .. } = Frame::decode(frame).unwrap() {
                if pk_ch == pk_a && second >= first_end {
                    a_again.get_or_insert(second);
                }
                if pk_ch == pk_b && second >= second_end {
                    b_again.get_or_insert(second);
                }
            }
        }
        link.extend(written.into_iter().map(|frame| (now, frame)));
    }
    let mut subscribed: Vec<_> = events
        .iter()
        .filter_map(|event| match event {
            Event::Subscribed { channel } => Some(*channel),
            _ => None,
        })
        .collect();
    subscribed.sort_unstable();
    let mut all = [kept, a, b];
    all.sort_unstable();
    assert_eq!(subscribed, all, "{events:?}");
    (events, a_again, b_again)
}

/// Spec 028, R16: a pause renewed after it ended pauses again, for a
/// `rate_limited` and a `channel_quota`; a `rate_limited` naming a
/// subscribed channel and an entry not in flight pauses, with no event.
#[test]
fn s028_t16_r16_pauses_renew() {
    let unknown = ClientRef { bytes: [9; 16] };
    for (code, named) in [
        ("rate_limited", None),
        ("rate_limited", Some(unknown)),
        ("channel_quota", None),
    ] {
        let (mut channels, mut session, _) = two_subscribed();
        let first = ids(&channels)[0];
        let channel_id = (code == "channel_quota" || named.is_some()).then_some(first);
        let frame = error_frame(code, channel_id, named);
        let step = session.on_frame(&frame, &mut channels, T0 + 1_200);
        let quiet = code == "rate_limited";
        assert_eq!(step.events.is_empty(), quiet, "{code}");
        let end = T0 + 1_200 + MINUTE;
        tick_until(&mut session, &mut channels, T0 + 1_200, end);
        session.outgoing();
        session.on_frame(&frame, &mut channels, end + 1_000);
        let late = channels[0].encrypt("late", None, end + 1_000).unwrap();
        session.after_send(first, &mut channels, end + 1_000);
        assert_eq!(published(&mut session), [], "{code} {named:?}");
        let (held, _) = tick_until(&mut session, &mut channels, end + 1_000, end + MINUTE + 999);
        assert_eq!(held, [], "{code} {named:?}");
        session.on_tick(&mut channels, end + MINUTE + 1_000);
        assert_eq!(published(&mut session), [late], "{code} {named:?}");
    }

    // Renewed while it runs: the pause runs a minute from the renewal.
    for (code, channel_id) in [
        ("rate_limited", None),
        ("server_full", None),
        ("channel_quota", Some(0)),
    ] {
        let (mut channels, mut session, _) = two_subscribed();
        let first = ids(&channels)[0];
        let frame = error_frame(code, channel_id.map(|_| first), None);
        session.on_frame(&frame, &mut channels, T0 + 1_200);
        tick_until(&mut session, &mut channels, T0 + 1_200, T0 + 31_200);
        session.on_frame(&frame, &mut channels, T0 + 31_200);
        let late = channels[0].encrypt("late", None, T0 + 31_200).unwrap();
        session.after_send(first, &mut channels, T0 + 31_200);
        let renewed = T0 + 31_200 + MINUTE;
        let (held, _) = tick_until(&mut session, &mut channels, T0 + 31_200, renewed - 1);
        assert_eq!(held, [], "{code}");
        session.on_tick(&mut channels, renewed);
        assert_eq!(published(&mut session), [late], "{code}");
    }
}

/// Spec 028, R16 and R6: a `subscribe` queued again after a `rate_limited`
/// takes its place by expiry among those still queued: a one-minute
/// channel ended while one-day channels wait leaves next.
#[test]
fn s028_t16_r16_subscribe_again_in_order() {
    let mut channels: Channels = (1..=4).map(|byte| channel(byte, DAY, T0)).collect();
    channels.insert(0, channel(9, 60, T0));
    let minute = ids(&channels)[0];
    let mut session = connected(&channels, T0);
    session.on_frame(&hello(1, &[1]), &mut channels, T0);
    assert_eq!(super::subscribed_ids(&mut session, &channels), [minute]);
    session.on_tick(&mut channels, T0 + 1_100);
    session.outgoing();
    let ended = error_frame("rate_limited", Some(minute), None);
    session.on_frame(&ended, &mut channels, T0 + 1_200);
    session.on_tick(&mut channels, T0 + 2_200);
    assert_eq!(super::subscribed_ids(&mut session, &channels), [minute]);

    // Three channels expiring together: the one released first, ended,
    // goes behind those still queued.
    let mut channels: Channels = (1..=3).map(|byte| channel(byte, DAY, T0)).collect();
    let [one, two, three]: [[u8; 16]; 3] = ids(&channels).try_into().unwrap();
    let mut session = connected(&channels, T0);
    session.on_frame(&hello(1, &[1]), &mut channels, T0);
    assert_eq!(super::subscribed_ids(&mut session, &channels), [one]);
    session.on_frame(
        &error_frame("rate_limited", Some(one), None),
        &mut channels,
        T0 + 200,
    );
    let mut released = Vec::new();
    for at in (1..=7).map(|second| T0 + second * 1_000) {
        session.on_tick(&mut channels, at);
        released.extend(super::subscribed_ids(&mut session, &channels));
    }
    assert_eq!(released, [two, three, one]);
}

/// Spec 028, R14 and R16: a subscribed channel paused by a `rate_limited`
/// the server renews still drops its stale entries on a tick →
/// `NotDelivered`, with no `publish` queued; an `expire_outbox` whose
/// commit fails there → `(channel, Io)` in `failed` and the channel frozen.
#[test]
fn s028_t14_r14_paused_channel_expires() {
    for fails in [false, true] {
        let (mut channels, handle, faults) = alice();
        let id = ids(&channels)[0];
        let sent = channels[0].encrypt("hi", None, T0).unwrap();
        let mut session = subscribed(&mut channels, T0);
        assert_eq!(published(&mut session), [sent]);
        // Out of flight, and every channel paused, again and again.
        let stale = T0 + 86_400_000 + 360_001;
        for at in [T0 + 100, stale - 30_000] {
            let renewed = error_frame("rate_limited", None, Some(sent));
            session.on_frame(&renewed, &mut channels, at);
        }
        faults.fail_commits(fails);
        let step = session.on_tick(&mut channels, stale);
        faults.fail_commits(false);
        assert_eq!(published(&mut session), []);
        let lost = Event::NotDelivered {
            channel: id,
            client_ref: sent,
            sent_at: T0,
        };
        if fails {
            assert_eq!(step.failed, [(id, StoreError::Io)]);
            assert!(!step.events.contains(&lost));
            let commits = handle.all_commits();
            session.on_tick(&mut channels, stale + 1_000);
            assert_eq!(handle.all_commits(), commits);
        } else {
            assert!(step.events.contains(&lost), "{:?}", step.events);
            assert!(step.failed.is_empty());
        }
    }
}

/// Spec 028, R16 and R10: a `bad_blob` of an entry of a frozen channel
/// calls nothing of it: no `abandon`, no commit, no event.
#[test]
fn s028_t16_r16_bad_blob_frozen() {
    let (mut channels, handle, _) = alice();
    let id = ids(&channels)[0];
    let sent = channels[0].encrypt("hi", None, T0).unwrap();
    let mut session = subscribed(&mut channels, T0);
    assert_eq!(published(&mut session), [sent]);
    session.set_write_failed(&channels[0], true, false);
    let commits = handle.all_commits();
    let step = session.on_frame(
        &error_frame("bad_blob", Some(id), Some(sent)),
        &mut channels,
        T0 + 100,
    );
    assert!(step.events.is_empty() && step.failed.is_empty());
    assert_eq!(handle.all_commits(), commits);
}
