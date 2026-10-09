//! Tests of spec 028 R1, R2 and R4–R7 at the level of the session: its
//! frames are read back with `Frame::decode`, and the server is
//! `MemoryServer`.

use super::{Channels, Event, HELLO_WAIT_MS, NONCE_WINDOW_MS, SUBSCRIBE_SPACING_MS, Session, Step};
use crate::crypto::{self, PublicKey, Signature};
use crate::proto::auth::auth_message;
use crate::proto::config::Config;
use crate::session::channel::Channel;
use crate::session::frames::Frame;
use crate::storage::Vault;
use crate::testing::{MemoryServer, MemoryVault};

const SERVER: &str = "wss://chat.example.org:9001";
const HOST: &str = "chat.example.org";
const CONNECTION: u64 = 7;
const DAY: u32 = 86_400;
/// A whole minute, so that the times below read easily.
const T0: u64 = 1_790_000_040_000;

/// A channel of key `byte`, `ttl_seconds` and `created_at`.
fn channel(byte: u8, ttl_seconds: u32, created_at: u64) -> Channel {
    let k_ch = crypto::Secret::from_bytes([byte; 32]);
    let config = Config::from_parts(k_ch, SERVER, ttl_seconds, "room", created_at).unwrap();
    let store = MemoryVault::new().create(&config.channel_id()).unwrap();
    Channel::create(&config, store).unwrap().0
}

/// The ids of `channels`, in order.
fn ids(channels: &Channels) -> Vec<[u8; 16]> {
    channels
        .iter()
        .map(|channel| channel.config().channel_id())
        .collect()
}

/// A connected session over `channels`.
fn connected(channels: &Channels, now: u64) -> Session {
    let mut session = Session::new(CONNECTION, ids(channels));
    session.on_connect(now, &[]);
    session
}

/// A `hello` frame with `proto_versions`.
fn hello(nonce: u8, proto_versions: &[u8]) -> Vec<u8> {
    Frame::Hello {
        server_nonce: [nonce; 32],
        proto_versions: proto_versions.to_vec(),
    }
    .encode()
    .unwrap()
}

fn ok(channel_id: [u8; 16]) -> Vec<u8> {
    Frame::Ok { channel_id }.encode().unwrap()
}

fn nonce_expired(channel_id: Option<[u8; 16]>) -> Vec<u8> {
    Frame::Error {
        code: "nonce_expired".to_owned(),
        message: String::new(),
        channel_id,
        client_ref: None,
    }
    .encode()
    .unwrap()
}

/// The `pk_ch`, `since` and `sig` of each `subscribe` written.
fn subscribes(session: &mut Session) -> Vec<([u8; 32], Option<u64>, [u8; 64])> {
    let frames = session.outgoing();
    let subscribes: Vec<_> = frames
        .iter()
        .filter_map(|frame| match Frame::decode(frame).unwrap() {
            Frame::Subscribe {
                pk_ch, since, sig, ..
            } => Some((pk_ch, since, sig)),
            _ => None,
        })
        .collect();
    assert_eq!(subscribes.len(), frames.len(), "only subscribes");
    subscribes
}

/// The `channel_id` each written `subscribe` names, by its `pk_ch`.
fn subscribed_ids(session: &mut Session, channels: &Channels) -> Vec<[u8; 16]> {
    subscribes(session)
        .iter()
        .map(|(pk_ch, ..)| {
            let channel = channels
                .iter()
                .find(|channel| channel.config().channel_keypair().unwrap().0.0 == *pk_ch)
                .unwrap();
            channel.config().channel_id()
        })
        .collect()
}

fn reconnect() -> Event {
    Event::Reconnect {
        connection: CONNECTION,
    }
}

/// Ticks every `every` ms from `from` to `to`, gathering the `subscribe`s
/// written and when.
fn tick_releases(
    session: &mut Session,
    channels: &mut Channels,
    from: u64,
    to: u64,
    every: u64,
) -> (Vec<u64>, Vec<Event>) {
    let (mut times, mut events) = (Vec::new(), Vec::new());
    let mut now = from;
    while now <= to {
        events.extend(session.on_tick(channels, now).events);
        times.extend(session.outgoing().iter().map(|_| now));
        now += every;
    }
    (times, events)
}

/// Spec 028, R1: a frame that breaks its schema is dropped with
/// `Reconnect`, once per connection.
#[test]
fn s028_t01_r01_bad_frame_reconnects() {
    let mut channels = vec![channel(1, DAY, T0)];
    let mut session = connected(&channels, T0);
    let bad = Frame::Ok {
        channel_id: [4; 16],
    }
    .encode()
    .unwrap();
    let step = session.on_frame(&bad[..bad.len() - 1], &mut channels, T0);
    assert_eq!(step.events, [reconnect()]);
    let step = session.on_frame(&[0, 0, 0, 0, 1, 7], &mut channels, T0);
    assert!(step.events.is_empty());
    assert!(session.outgoing().is_empty());
}

/// Spec 028, R2: `[1]` → a `subscribe`; an empty list, `[2]` and nine items
/// with 1 → `UnsupportedServer`, and nothing is sent, not even after a good
/// `hello` or a tick, until the next `on_connect`.
#[test]
fn s028_t02_r02_version_list_in_session() {
    let mut channels = vec![channel(1, DAY, T0)];
    let mut session = connected(&channels, T0);
    session.on_frame(&hello(1, &[1]), &mut channels, T0);
    assert_eq!(subscribes(&mut session).len(), 1);

    let nine: Vec<u8> = (1..=9).collect();
    for versions in [&[][..], &[2], &nine] {
        let mut session = connected(&channels, T0);
        let step = session.on_frame(&hello(1, versions), &mut channels, T0);
        assert_eq!(
            step.events,
            [Event::UnsupportedServer {
                connection: CONNECTION
            }],
            "{versions:?}"
        );
        session.on_frame(&hello(2, &[1]), &mut channels, T0 + 1);
        let late = session.on_tick(&mut channels, T0 + 2 * HELLO_WAIT_MS);
        assert!(late.events.is_empty());
        assert!(session.outgoing().is_empty());
        session.on_connect(T0 + 10, &[]);
        session.on_frame(&hello(3, &[1]), &mut channels, T0 + 10);
        assert_eq!(subscribes(&mut session).len(), 1);
    }
}

/// Spec 028, R4: the server sends the backlog in order, then a push
/// published while it streamed, then `ok`, never that push ahead of the
/// backlog; two `publish`es on one connection are stored and acknowledged in
/// the order sent.
#[test]
fn s028_t04_r04_memory_server_contract() {
    let mut channels = vec![channel(1, DAY, T0)];
    let channel_id = channels[0].config().channel_id();
    let mut server = MemoryServer::new(&[HOST]);
    let mut writer = connected(&channels, T0);
    server.connect(1, T0);
    for frame in server.read(1, 10) {
        writer.on_frame(&frame, &mut channels, T0);
    }
    for frame in writer.outgoing() {
        server.receive(1, &frame, T0);
    }
    assert!(matches!(
        Frame::decode(&server.read(1, 10)[0]).unwrap(),
        Frame::Ok { .. }
    ));
    let publish = |client_ref: u8| {
        Frame::Publish {
            channel_id,
            client_ref: [client_ref; 16],
            blob: vec![client_ref; 3],
        }
        .encode()
        .unwrap()
    };
    // Two publishes in one millisecond: stored and acknowledged in order.
    server.receive(1, &publish(1), T0 + 5);
    server.receive(1, &publish(2), T0 + 5);
    let acks: Vec<[u8; 16]> = server
        .read(1, 10)
        .iter()
        .filter_map(|frame| match Frame::decode(frame).unwrap() {
            Frame::Ack { client_ref, .. } => Some(client_ref),
            _ => None,
        })
        .collect();
    assert_eq!(acks, [[1; 16], [2; 16]]);
    let stored = server.stored(&channel_id);
    assert_eq!(
        stored.iter().map(|(_, at)| *at).collect::<Vec<_>>(),
        [T0 + 5, T0 + 6]
    );

    // A second connection subscribes; a third blob arrives while its backlog
    // streams.
    let mut reader = connected(&channels, T0 + 10);
    server.connect(2, T0 + 10);
    for frame in server.read(2, 1) {
        reader.on_frame(&frame, &mut channels, T0 + 10);
    }
    for frame in reader.outgoing() {
        server.receive(2, &frame, T0 + 10);
    }
    let first = server.read(2, 1);
    server.receive(1, &publish(3), T0 + 20);
    let rest = server.read(2, 10);
    let order: Vec<String> = first
        .iter()
        .chain(&rest)
        .map(|frame| match Frame::decode(frame).unwrap() {
            Frame::Push { blob, .. } => format!("push {}", blob[0]),
            Frame::Ok { .. } => "ok".to_owned(),
            other => format!("{other:?}"),
        })
        .collect();
    assert_eq!(order, ["push 1", "push 2", "push 3", "ok"]);
}

/// Spec 028, R5: after `on_disconnect` nothing is queued; after
/// `on_connect` the subscriptions of the last connection are forgotten,
/// and a channel in `skip` is not subscribed.
#[test]
fn s028_t05_r05_reconnect_forgets_connection() {
    let mut channels = vec![channel(1, DAY, T0), channel(2, DAY, T0)];
    let [first, second] = [ids(&channels)[0], ids(&channels)[1]];
    let mut session = connected(&channels, T0);
    session.on_frame(&hello(1, &[1]), &mut channels, T0);
    let first_subscribed = subscribed_ids(&mut session, &channels)[0];
    session.on_frame(&ok(first_subscribed), &mut channels, T0);
    session.on_disconnect();
    let step = session.on_tick(&mut channels, T0 + 2_000);
    assert!(step.events.is_empty());
    let step = session.on_frame(&hello(2, &[1]), &mut channels, T0 + 2_000);
    assert!(step.events.is_empty());
    assert!(session.outgoing().is_empty());

    // Both channels again, though one was subscribed on the last connection.
    session.on_connect(T0 + 3_000, &[]);
    session.on_frame(&hello(3, &[1]), &mut channels, T0 + 3_000);
    session.on_tick(&mut channels, T0 + 4_100);
    let mut again = subscribed_ids(&mut session, &channels);
    again.sort_unstable();
    let mut both = [first, second];
    both.sort_unstable();
    assert_eq!(again, both);

    // A channel the `Device` refuses is not subscribed.
    session.on_connect(T0 + 10_000, &[second]);
    session.on_frame(&hello(4, &[1]), &mut channels, T0 + 10_000);
    let (_, events) = tick_releases(&mut session, &mut channels, T0 + 10_000, T0 + 20_000, 1_100);
    assert!(events.is_empty());
    session.on_frame(&hello(5, &[1]), &mut channels, T0 + 20_000);
    assert!(session.outgoing().is_empty());
}

/// Spec 028, R6: the signature verifies over the §6 message with the
/// config's host; `since` is the cursor down to the minute, absent with no
/// cursor; subscribes leave at least 1 100 ms apart, the channel whose
/// history expires first first; a second `hello` discards the unreleased
/// ones and subscribes only channels not subscribed; the spacing holds
/// across a `nonce_expired` and a new `hello`.
#[test]
fn s028_t06_r06_subscribe_contents_and_pacing() {
    let mut channels = vec![channel(1, DAY, T0)];
    // Any push moves the cursor (spec 021 R20); this one is no message.
    channels[0].decrypt(&[0; 8], [9; 16], 90_000, 90_000).ok();
    let mut session = connected(&channels, T0);
    session.on_frame(&hello(1, &[1]), &mut channels, T0);
    let written = subscribes(&mut session);
    assert_eq!(written.len(), 1);
    let (pk_ch, since, sig) = written[0];
    assert_eq!(since, Some(60_000));
    let config = channels[0].config();
    let message = auth_message(&[1; 32], config.id(), DAY, HOST);
    assert!(crypto::verify_detached(&PublicKey(pk_ch), &message, &Signature(sig)).is_ok());
    let on_url = auth_message(&[1; 32], config.id(), DAY, "chat.example.org:9001");
    assert!(crypto::verify_detached(&PublicKey(pk_ch), &on_url, &Signature(sig)).is_err());

    // A new channel has no cursor and no `since`.
    let mut fresh = vec![channel(2, DAY, T0)];
    let mut session = connected(&fresh, T0);
    session.on_frame(&hello(1, &[1]), &mut fresh, T0);
    assert_eq!(subscribes(&mut session)[0].1, None);

    // Three channels, ticks every 100 ms: 1 100 ms apart.
    let mut three = vec![
        channel(1, DAY, T0),
        channel(2, DAY, T0),
        channel(3, DAY, T0),
    ];
    let mut session = connected(&three, T0);
    session.on_frame(&hello(1, &[1]), &mut three, T0);
    let mut released = vec![T0; subscribes(&mut session).len()];
    released.extend(tick_releases(&mut session, &mut three, T0, T0 + 5_000, 100).0);
    assert_eq!(released, [T0, T0 + 1_100, T0 + 2_200]);

    // A second `hello` while one is unreleased: subscribes the two not yet
    // subscribed, the one with its `ok` left out.
    let mut session = connected(&three, T0);
    session.on_frame(&hello(1, &[1]), &mut three, T0);
    let first = subscribed_ids(&mut session, &three)[0];
    session.on_frame(&ok(first), &mut three, T0 + 500);
    session.on_tick(&mut three, T0 + 1_100);
    let second = subscribed_ids(&mut session, &three)[0];
    session.on_frame(&hello(2, &[1]), &mut three, T0 + 1_500);
    assert!(session.outgoing().is_empty());
    session.on_tick(&mut three, T0 + 2_200);
    let third = subscribed_ids(&mut session, &three);
    assert_eq!(third.len(), 1);
    assert!(![first, second].contains(&third[0]));
    let (_, events) = tick_releases(&mut session, &mut three, T0 + 2_300, T0 + 10_000, 100);
    assert!(events.is_empty());
    assert!(session.outgoing().is_empty());

    // A 60-second channel among 15 one-day channels leaves first.
    let mut sixteen: Channels = (1..=15).map(|byte| channel(byte, DAY, T0)).collect();
    sixteen.push(channel(16, 60, T0));
    let short = sixteen[15].config().channel_id();
    let mut session = connected(&sixteen, T0);
    session.on_frame(&hello(1, &[1]), &mut sixteen, T0);
    assert_eq!(subscribed_ids(&mut session, &sixteen), [short]);

    // A `nonce_expired` and a new `hello` 300 ms after a release: the next
    // one waits 1 100 ms from that release.
    let mut two = vec![channel(1, DAY, T0), channel(2, DAY, T0)];
    let mut session = connected(&two, T0);
    session.on_frame(&hello(1, &[1]), &mut two, T0);
    let refused = subscribed_ids(&mut session, &two)[0];
    session.on_frame(&nonce_expired(Some(refused)), &mut two, T0 + 200);
    session.on_frame(&hello(2, &[1]), &mut two, T0 + 300);
    assert!(session.outgoing().is_empty());
    session.on_tick(&mut two, T0 + SUBSCRIBE_SPACING_MS - 1);
    assert!(session.outgoing().is_empty());
    session.on_tick(&mut two, T0 + SUBSCRIBE_SPACING_MS);
    assert_eq!(subscribes(&mut session).len(), 1);
}

/// Spec 028, R7: sixteen channels with a tick every second all leave by
/// about 31 s; a `subscribe` that would leave more than 50 000 ms after its
/// `hello` → `Reconnect`; no `hello` within 50 000 ms of `on_connect` or of
/// a `nonce_expired` → `Reconnect`.
#[test]
fn s028_t07_r07_nonce_window() {
    let mut sixteen: Channels = (1..=16).map(|byte| channel(byte, DAY, T0)).collect();
    let mut session = connected(&sixteen, T0);
    session.on_frame(&hello(1, &[1]), &mut sixteen, T0);
    let mut released = vec![T0; session.outgoing().len()];
    let (times, events) = tick_releases(&mut session, &mut sixteen, T0, T0 + 60_000, 1_000);
    released.extend(times);
    assert!(events.is_empty());
    assert_eq!(released.len(), 16);
    assert_eq!(released.last(), Some(&(T0 + 30_000)));

    // The second of two channels, at the edge of the window and past it.
    let mut two = vec![channel(1, DAY, T0), channel(2, DAY, T0)];
    for (late, leaves) in [(NONCE_WINDOW_MS, true), (NONCE_WINDOW_MS + 1, false)] {
        let mut session = connected(&two, T0);
        session.on_frame(&hello(1, &[1]), &mut two, T0);
        session.outgoing();
        let step = session.on_tick(&mut two, T0 + late);
        assert_eq!(session.outgoing().len(), usize::from(leaves));
        let expected: Vec<Event> = if leaves { vec![] } else { vec![reconnect()] };
        assert_eq!(step.events, expected);
    }

    // No `hello` after `on_connect`.
    let mut session = connected(&two, T0);
    assert!(
        session
            .on_tick(&mut two, T0 + HELLO_WAIT_MS)
            .events
            .is_empty()
    );
    assert_eq!(
        session.on_tick(&mut two, T0 + HELLO_WAIT_MS + 1).events,
        [reconnect()]
    );

    // No `hello` after `nonce_expired`; and one that names no channel is a
    // `Reconnect` at once.
    let mut session = connected(&two, T0);
    session.on_frame(&hello(1, &[1]), &mut two, T0);
    let refused = subscribed_ids(&mut session, &two)[0];
    session.on_frame(&nonce_expired(Some(refused)), &mut two, T0 + 1_000);
    let quiet: Step = session.on_tick(&mut two, T0 + 1_000 + HELLO_WAIT_MS);
    assert!(quiet.events.is_empty());
    assert!(session.outgoing().is_empty());
    let late = session.on_tick(&mut two, T0 + 1_001 + HELLO_WAIT_MS);
    assert_eq!(late.events, [reconnect()]);
    let mut session = connected(&two, T0);
    session.on_frame(&hello(1, &[1]), &mut two, T0);
    let step = session.on_frame(&nonce_expired(None), &mut two, T0 + 1_000);
    assert_eq!(step.events, [reconnect()]);
}
