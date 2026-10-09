//! Tests of spec 028 R1, R2, R4–R7 and the `ok` of R9 at the level of the
//! session: its frames are read back with `Frame::decode`, and the server
//! is `MemoryServer`.

use super::{Channels, Event, HELLO_WAIT_MS, NONCE_WINDOW_MS, SUBSCRIBE_SPACING_MS, Session, Step};
use crate::crypto::{self, PublicKey, Signature};
use crate::proto::config::Config;
use crate::session::channel::Channel;
use crate::session::frames::Frame;
use crate::storage::Vault;
use crate::testing::{MemoryServer, MemoryVault};

mod ok;
mod truncation;

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

/// The record of these fields.
fn record(fields: &[(u8, &[u8])]) -> Vec<u8> {
    let mut record = Vec::new();
    for (key, value) in fields {
        record.push(*key);
        record.extend_from_slice(&u32::try_from(value.len()).unwrap().to_be_bytes());
        record.extend_from_slice(value);
    }
    record
}

/// Spec 028, R1: 70 001 bytes, `type` 7, a missing key and a 33-byte `code`
/// are dropped with `Reconnect`, and nothing is sent; on a new connection
/// it comes again.
#[test]
fn s028_t01_r01_bad_frame_reconnects() {
    let mut channels = vec![channel(1, DAY, T0)];
    let ok = ok([4; 16]);
    let long = [ok.clone(), record(&[(9, &vec![0; 70_001 - ok.len() - 5])])].concat();
    assert_eq!(long.len(), 70_001);
    let bad = [
        long,
        record(&[(0, &[7])]),
        record(&[(0, &[2])]),
        record(&[(0, &[6]), (1, &[b'c'; 33]), (2, &[])]),
    ];
    for frame in &bad {
        let mut session = connected(&channels, T0);
        let step = session.on_frame(frame, &mut channels, T0);
        assert_eq!(step.events, [reconnect()]);
        assert!(session.outgoing().is_empty());
        session.on_connect(T0 + 1, &[]);
        let step = session.on_frame(frame, &mut channels, T0 + 1);
        assert_eq!(step.events, [reconnect()]);
    }
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
    // A `subscribe` not yet written when an unsupported `hello` arrives is
    // not written.
    let mut session = connected(&channels, T0);
    session.on_frame(&hello(1, &[1]), &mut channels, T0);
    session.on_frame(&hello(2, &[2]), &mut channels, T0 + 1);
    assert!(session.outgoing().is_empty());

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
        let bad = session.on_frame(&[0, 0, 0, 0, 1, 7], &mut channels, T0 + 1);
        assert!(bad.events.is_empty());
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
    // Each `ack` before its echo to the publisher's own subscription.
    let seen: Vec<String> = server
        .read(1, 10)
        .iter()
        .map(|frame| match Frame::decode(frame).unwrap() {
            Frame::Ack { client_ref, .. } => format!("ack {}", client_ref[0]),
            Frame::Push { blob, .. } => format!("push {}", blob[0]),
            other => format!("{other:?}"),
        })
        .collect();
    assert_eq!(seen, ["ack 1", "push 1", "ack 2", "push 2"]);
    let ids: std::collections::BTreeSet<[u8; 16]> = server
        .stored(&channel_id)
        .iter()
        .map(|(id, _)| *id)
        .collect();
    assert_eq!(ids.len(), 2, "each blob its own server_id");
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
    assert_eq!(first.len(), 1);
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

/// Feeds what the server has for `connection` to `session` and what the
/// session writes back to the server, until both are quiet; returns every
/// frame the server sent.
fn pump(
    server: &mut MemoryServer,
    connection: u64,
    session: &mut Session,
    channels: &mut Channels,
    now: u64,
) -> Vec<Frame> {
    let mut read = Vec::new();
    loop {
        let frames = server.read(connection, 100);
        for frame in &frames {
            session.on_frame(frame, channels, now);
        }
        let written = session.outgoing();
        for frame in &written {
            server.receive(connection, frame, now);
        }
        if frames.is_empty() && written.is_empty() {
            return read;
        }
        read.extend(frames.iter().map(|frame| Frame::decode(frame).unwrap()));
    }
}

/// The `code` of each `error` among `frames`.
fn error_codes(frames: &[Frame]) -> Vec<&str> {
    frames
        .iter()
        .filter_map(|frame| match frame {
            Frame::Error { code, .. } => Some(code.as_str()),
            _ => None,
        })
        .collect()
}

/// The `received_at` of each `push` among `frames`.
fn pushed(frames: &[Frame]) -> Vec<u64> {
    frames
        .iter()
        .filter_map(|frame| match frame {
            Frame::Push { received_at, .. } => Some(*received_at),
            _ => None,
        })
        .collect()
}

/// A `publish` of one byte on `channel_id`.
fn publish(channel_id: [u8; 16], client_ref: u8) -> Vec<u8> {
    Frame::Publish {
        channel_id,
        client_ref: [client_ref; 16],
        blob: vec![client_ref],
    }
    .encode()
    .unwrap()
}

/// A new connection of a fresh session over `channel`, subscribed through
/// `server` at `now`; the frames the server sent.
fn subscribe_at(
    server: &mut MemoryServer,
    connection: u64,
    channel: Channel,
    now: u64,
) -> Vec<Frame> {
    let mut channels = vec![channel];
    let mut session = connected(&channels, now);
    server.connect(connection, now);
    pump(server, connection, &mut session, &mut channels, now)
}

/// Spec 028, R4: the test server checks the configured hosts and the
/// nonce's age, answers a `publish` of a channel not
/// subscribed with `not_subscribed`, and streams the backlog from `since`
/// (read as `now` when later) of the blobs a TTL has not expired.
#[test]
fn s028_t04_r04_memory_server_checks() {
    for (hosts, accepted) in [
        (&["other.example"][..], false),
        (&["other.example", HOST], true),
    ] {
        let mut server = MemoryServer::new(hosts);
        let frames = subscribe_at(&mut server, 1, channel(1, DAY, T0), T0);
        let oks = frames
            .iter()
            .filter(|frame| matches!(frame, Frame::Ok { .. }))
            .count();
        assert_eq!(oks, usize::from(accepted));
        let refusals: &[&str] = if accepted { &[] } else { &["bad_auth"] };
        assert_eq!(error_codes(&frames), refusals);
    }

    // A `subscribe` 60 001 ms after its `hello`: `nonce_expired`, then a new
    // nonce; two connections get two nonces.
    let mut server = MemoryServer::new(&[HOST]);
    let mut channels = vec![channel(1, DAY, T0)];
    let mut session = connected(&channels, T0);
    server.connect(1, T0);
    server.connect(2, T0);
    let hellos: Vec<Vec<u8>> = [server.read(1, 1), server.read(2, 1)].concat();
    assert_ne!(hellos[0], hellos[1]);
    session.on_frame(&hellos[0], &mut channels, T0);
    server.receive(1, &session.outgoing()[0], T0 + 60_001);
    let answer: Vec<Frame> = server
        .read(1, 10)
        .iter()
        .map(|f| Frame::decode(f).unwrap())
        .collect();
    assert_eq!(error_codes(&answer), ["nonce_expired"]);
    let first_nonce = &hellos[0][10..42];
    assert!(matches!(&answer[1], Frame::Hello { server_nonce, .. }
        if server_nonce.as_slice() != first_nonce));
    assert!(server.read(1, 10).is_empty());
    // Under the new nonce, 59 000 ms after it, the channel is accepted.
    let renewed = T0 + 60_001;
    for frame in answer.iter().map(|frame| frame.encode().unwrap()) {
        session.on_frame(&frame, &mut channels, renewed);
    }
    server.receive(1, &session.outgoing()[0], renewed + 59_000);
    let accepted = decoded(server.read(1, 10));
    assert!(matches!(accepted[..], [Frame::Ok { .. }]));
    // A subscribe exactly 60 000 ms after its `hello` is accepted.
    let mut other = vec![channel(2, DAY, T0)];
    let mut late = connected(&other, T0);
    late.on_frame(&hellos[1], &mut other, T0);
    server.receive(2, &late.outgoing()[0], T0 + 60_000);
    assert!(matches!(
        decoded(server.read(2, 10))[..],
        [Frame::Ok { .. }]
    ));

    // A publish before any subscribe is refused, naming both.
    let channel_id = channels[0].config().channel_id();
    server.receive(2, &publish(channel_id, 5), T0);
    let refusal = Frame::decode(&server.read(2, 1)[0]).unwrap();
    assert!(
        matches!(refusal, Frame::Error { code, channel_id: Some(id), client_ref: Some(r), .. }
        if code == "not_subscribed" && id == channel_id && r == [5; 16])
    );

    // A 60-second channel: blobs at +1 000 and +60 000, then three in one
    // millisecond at +60 500.
    let mut server = MemoryServer::new(&[HOST]);
    let mut writer = vec![channel(3, 60, T0)];
    let id = writer[0].config().channel_id();
    let mut session = connected(&writer, T0);
    server.connect(1, T0);
    pump(&mut server, 1, &mut session, &mut writer, T0);
    for (at, client_ref) in [
        (T0 + 1_000, 1),
        (T0 + 60_000, 2),
        (T0 + 60_500, 3),
        (T0 + 60_500, 4),
    ] {
        server.receive(1, &publish(id, client_ref), at);
    }
    let times: Vec<u64> = server.stored(&id).iter().map(|(_, at)| *at).collect();
    assert_eq!(times, [T0 + 1_000, T0 + 60_000, T0 + 60_500, T0 + 60_501]);
    // No cursor at +60 500: the blob of +1 000 has not expired yet.
    let all = subscribe_at(&mut server, 2, channel(3, 60, T0), T0 + 60_500);
    assert_eq!(pushed(&all), times);
    // At +61 000 it has.
    let later = subscribe_at(&mut server, 3, channel(3, 60, T0), T0 + 61_000);
    assert_eq!(pushed(&later), &times[1..]);
    // A cursor at +60 400 asks from +60 000, the blob at exactly `since`
    // included.
    let mut reader = channel(3, 60, T0);
    reader
        .decrypt(&[0; 8], [9; 16], T0 + 60_400, T0 + 60_400)
        .ok();
    assert_eq!(
        pushed(&subscribe_at(&mut server, 4, reader, T0 + 60_500)),
        &times[1..]
    );
    // A `since` later than `now` is read as `now`.
    let mut ahead = channel(3, 60, T0);
    ahead
        .decrypt(&[0; 8], [9; 16], T0 + 200_000, T0 + 200_000)
        .ok();
    assert_eq!(
        pushed(&subscribe_at(&mut server, 5, ahead, T0 + 60_501)),
        [T0 + 60_501]
    );

    // Two subscriptions on one connection: each gets its backlog, then its
    // `ok`.
    // Both catch up at once: their subscribes arrive before any read.
    let mut both = vec![channel(3, 60, T0), channel(4, DAY, T0)];
    let mut session = connected(&both, T0 + 60_500);
    server.connect(6, T0 + 60_500);
    session.on_frame(&server.read(6, 1)[0], &mut both, T0 + 60_500);
    session.on_tick(&mut both, T0 + 61_600);
    for frame in session.outgoing() {
        server.receive(6, &frame, T0 + 61_600);
    }
    let frames = decoded(server.read(6, 100));
    let oks = frames
        .iter()
        .filter(|f| matches!(f, Frame::Ok { .. }))
        .count();
    assert_eq!(oks, 2);
    // Read at +61 600, after the blob of +1 000 expired.
    assert_eq!(pushed(&frames), &times[1..]);

    // A `subscribe` without `since` gets every unexpired blob.
    let mut bare = vec![channel(3, 60, T0)];
    bare[0]
        .decrypt(&[0; 8], [9; 16], T0 + 60_400, T0 + 60_400)
        .ok();
    let mut session = connected(&bare, T0 + 60_500);
    server.connect(7, T0 + 60_500);
    session.on_frame(&server.read(7, 1)[0], &mut bare, T0 + 60_500);
    let unbounded = match Frame::decode(&session.outgoing()[0]).unwrap() {
        Frame::Subscribe {
            pk_ch,
            ttl_seconds,
            sig,
            since,
        } => {
            assert_eq!(since, Some(T0 + 60_000));
            Frame::Subscribe {
                pk_ch,
                ttl_seconds,
                sig,
                since: None,
            }
        }
        other => other,
    };
    server.receive(7, &unbounded.encode().unwrap(), T0 + 60_500);
    assert_eq!(pushed(&decoded(server.read(7, 10))), times);

    // Live pushes reach a subscription after its `ok`; a closed socket gets
    // nothing.
    server.receive(1, &publish(id, 6), T0 + 70_000);
    assert_eq!(pushed(&decoded(server.read(2, 10))), [T0 + 70_000]);
    server.disconnect(3);
    assert!(server.read(3, 10).is_empty());
}

fn decoded(frames: Vec<Vec<u8>>) -> Vec<Frame> {
    frames
        .iter()
        .map(|frame| Frame::decode(frame).unwrap())
        .collect()
}

/// Spec 028, R5: what a closed connection had not written is not written;
/// a new connection subscribes every channel again, the first at once even
/// within 1 100 ms of the last release; a channel in `skip` is not
/// subscribed; nothing is queued between `on_disconnect` and `on_connect`.
#[test]
fn s028_t05_r05_reconnect_forgets_connection() {
    let mut channels = vec![channel(1, DAY, T0), channel(2, DAY, T0)];
    let [first, second] = [ids(&channels)[0], ids(&channels)[1]];
    let mut session = connected(&channels, T0);
    session.on_frame(&hello(1, &[1]), &mut channels, T0);
    session.on_frame(&ok(first), &mut channels, T0 + 100);
    session.on_tick(&mut channels, T0 + 1_100);
    session.on_disconnect();
    assert!(session.outgoing().is_empty());
    assert!(session.on_tick(&mut channels, T0 + 2_000).events.is_empty());
    let step = session.on_frame(&hello(2, &[1]), &mut channels, T0 + 2_000);
    assert!(step.events.is_empty());
    assert!(session.outgoing().is_empty());

    // `first` synced at its `ok`, so the never-synced `second` leaves first
    // (R6).
    session.on_connect(T0 + 1_200, &[]);
    session.on_frame(&hello(3, &[1]), &mut channels, T0 + 1_200);
    assert_eq!(subscribed_ids(&mut session, &channels), [second]);
    session.on_tick(&mut channels, T0 + 2_300);
    assert_eq!(subscribed_ids(&mut session, &channels), [first]);

    session.on_connect(T0 + 10_000, &[second]);
    session.on_frame(&hello(4, &[1]), &mut channels, T0 + 10_000);
    assert_eq!(subscribed_ids(&mut session, &channels), [first]);
    let (released, events) =
        tick_releases(&mut session, &mut channels, T0 + 10_000, T0 + 20_000, 100);
    assert!(released.is_empty());
    assert!(events.is_empty());
    let step = session.on_frame(&ok(second), &mut channels, T0 + 20_000);
    assert!(step.events.is_empty());
}

/// The bytes of `docs/spec.md` §6, written out: the tag, the nonce, the
/// channel, the TTL big-endian and the host.
fn section_6_message(nonce: u8, channel_id: [u8; 16], ttl_seconds: u32, host: &str) -> Vec<u8> {
    [
        b"privatechat/auth/v1".as_slice(),
        &[nonce; 32],
        &channel_id,
        &ttl_seconds.to_be_bytes(),
        host.as_bytes(),
    ]
    .concat()
}

/// Spec 028, R6: the signature verifies over the §6 message with the
/// config's host; `since` is the cursor down to the minute, 0 with no
/// cursor, so every `subscribe` has one size; subscribes leave at least
/// 1 100 ms apart, by `last + ttl_ms` or `created_at + ttl_ms`; a second
/// `hello` discards the unreleased ones and subscribes only channels not
/// subscribed; the spacing holds across a `nonce_expired` and a new
/// `hello`, after which the refused channel is subscribed again, also when
/// it had its `ok`; a session subscribes its own channels alone.
#[test]
fn s028_t06_r06_subscribe_contents_and_pacing() {
    let mut channels = vec![channel(1, DAY, T0)];
    // Any push moves the cursor (spec 021 R20); this one is no message.
    channels[0].decrypt(&[0; 8], [9; 16], 90_000, 90_000).ok();
    // `since` follows the cursor, not a later `synced_at`.
    channels[0].synced(150_000).unwrap();
    let mut session = connected(&channels, T0);
    session.on_frame(&hello(1, &[1]), &mut channels, T0);
    let written = subscribes(&mut session);
    assert_eq!(written.len(), 1);
    let (pk_ch, since, sig) = written[0];
    assert_eq!(since, Some(60_000));
    let channel_id = channels[0].config().channel_id();
    let message = section_6_message(1, channel_id, DAY, HOST);
    assert!(crypto::verify_detached(&PublicKey(pk_ch), &message, &Signature(sig)).is_ok());
    let on_url = section_6_message(1, channel_id, DAY, "chat.example.org:9001");
    assert!(crypto::verify_detached(&PublicKey(pk_ch), &on_url, &Signature(sig)).is_err());

    // A new channel has no cursor and sends `since` 0, so that its
    // `subscribe` has the size of every other.
    let mut fresh = vec![channel(2, DAY, T0)];
    let mut session = connected(&fresh, T0);
    session.on_frame(&hello(1, &[1]), &mut fresh, T0);
    assert_eq!(subscribes(&mut session)[0].1, Some(0));

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
    // subscribed, the one with its `ok` left out, once each.
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
    let (later, events) = tick_releases(&mut session, &mut three, T0 + 2_300, T0 + 10_000, 100);
    assert!(later.is_empty());
    assert!(events.is_empty());

    // A 60-second channel among 15 one-day channels leaves first.
    let mut sixteen: Channels = (1..=15).map(|byte| channel(byte, DAY, T0)).collect();
    sixteen.push(channel(16, 60, T0));
    let short = sixteen[15].config().channel_id();
    let mut session = connected(&sixteen, T0);
    session.on_frame(&hello(1, &[1]), &mut sixteen, T0);
    assert_eq!(subscribed_ids(&mut session, &sixteen), [short]);

    // One TTL: the older `created_at` first; then a cursor older than the
    // other channel's `created_at` first.
    let mut by_creation = vec![channel(1, DAY, T0), channel(2, DAY, T0 - 1)];
    let older = by_creation[1].config().channel_id();
    let mut session = connected(&by_creation, T0);
    session.on_frame(&hello(1, &[1]), &mut by_creation, T0);
    assert_eq!(subscribed_ids(&mut session, &by_creation), [older]);
    let mut by_cursor = vec![channel(1, DAY, T0), channel(2, DAY, T0 + 10)];
    by_cursor[1].decrypt(&[0; 8], [9; 16], T0 - 5, T0 - 5).ok();
    let behind = by_cursor[1].config().channel_id();
    let mut session = connected(&by_cursor, T0);
    session.on_frame(&hello(1, &[1]), &mut by_cursor, T0);
    assert_eq!(subscribed_ids(&mut session, &by_cursor), [behind]);
    // `last` is `max(cursor, synced_at)`, a `synced_at` later than `now`
    // ignored. The synced channel is created at +10, the other at
    // `created`: a `synced_at` before +0 puts it first; one in the future
    // counts for nothing, so its `created_at` puts it first again; a cursor
    // older than the other's `created_at`, under a later `synced_at`, does
    // not.
    for (synced_at, cursor, created, first_out) in [
        (T0 - 5, None, T0, true),
        (T0 + 10_000_000, None, T0 + 20, true),
        (T0 - 5, Some(T0 - 10), T0 - 7, false),
        (T0 - 20, Some(T0 - 5), T0 - 10, false),
    ] {
        let mut pair = vec![channel(1, DAY, created), channel(2, DAY, T0 + 10)];
        if let Some(cursor) = cursor {
            pair[1].decrypt(&[0; 8], [9; 16], cursor, cursor).ok();
        }
        pair[1].synced(synced_at).unwrap();
        let synced = pair[1].config().channel_id();
        let mut session = connected(&pair, T0);
        session.on_frame(&hello(1, &[1]), &mut pair, T0);
        let out = subscribed_ids(&mut session, &pair)[0];
        assert_eq!(out == synced, first_out, "{synced_at} {cursor:?}");
    }

    // A `synced_at` equal to `now` counts.
    let mut pair = vec![channel(1, DAY, T0 + 5), channel(2, DAY, T0 + 10)];
    pair[1].synced(T0).unwrap();
    let synced = pair[1].config().channel_id();
    let mut session = connected(&pair, T0);
    session.on_frame(&hello(1, &[1]), &mut pair, T0);
    assert_eq!(subscribed_ids(&mut session, &pair), [synced]);

    // A channel the `Device` closed before its turn is skipped, quietly.
    let mut three = vec![
        channel(1, DAY, T0),
        channel(2, DAY, T0),
        channel(3, DAY, T0),
    ];
    let last = three[2].config().channel_id();
    let mut session = connected(&three, T0);
    session.on_frame(&hello(1, &[1]), &mut three, T0);
    session.outgoing();
    three.remove(1);
    assert!(session.on_tick(&mut three, T0 + 1_100).events.is_empty());
    assert!(session.outgoing().is_empty());
    assert!(session.on_tick(&mut three, T0 + 1_200).events.is_empty());
    assert_eq!(subscribed_ids(&mut session, &three), [last]);

    // A `nonce_expired` and a new `hello` 300 ms after a release: the next
    // one waits 1 100 ms from that release, and the refused channel comes
    // again; an error of another code changes nothing.
    let mut two = vec![channel(1, DAY, T0), channel(2, DAY, T0)];
    let mut session = connected(&two, T0);
    session.on_frame(&hello(1, &[1]), &mut two, T0);
    let refused = subscribed_ids(&mut session, &two)[0];
    session.on_frame(&error("teapot", Some(refused)), &mut two, T0 + 100);
    session.on_frame(&error("nonce_expired", Some(refused)), &mut two, T0 + 200);
    session.on_frame(&hello(2, &[1]), &mut two, T0 + 300);
    assert!(session.outgoing().is_empty());
    session.on_tick(&mut two, T0 + SUBSCRIBE_SPACING_MS - 1);
    assert!(session.outgoing().is_empty());
    let mut again = Vec::new();
    for at in [T0 + SUBSCRIBE_SPACING_MS, T0 + 2 * SUBSCRIBE_SPACING_MS] {
        session.on_tick(&mut two, at);
        again.extend(subscribed_ids(&mut session, &two));
    }
    assert_eq!(again.len(), 2);
    assert!(again.contains(&refused));

    // A `nonce_expired` naming a channel that had its `ok` frees it too.
    let mut session = connected(&two, T0);
    session.on_frame(&hello(1, &[1]), &mut two, T0);
    let done = subscribed_ids(&mut session, &two)[0];
    session.on_frame(&ok(done), &mut two, T0 + 100);
    session.on_frame(&error("nonce_expired", Some(done)), &mut two, T0 + 200);
    session.on_frame(&hello(2, &[1]), &mut two, T0 + 1_100);
    session.on_tick(&mut two, T0 + 2_200);
    assert!(subscribed_ids(&mut session, &two).contains(&done));

    // A session subscribes its own channels alone, whatever the `Device`
    // holds.
    let own = ids(&two)[0];
    let mut session = Session::new(CONNECTION, vec![own]);
    session.on_connect(T0, &[]);
    session.on_frame(&hello(1, &[1]), &mut two, T0);
    assert_eq!(subscribed_ids(&mut session, &two), [own]);
    let (released, _) = tick_releases(&mut session, &mut two, T0, T0 + 5_000, 100);
    assert!(released.is_empty());

    // An error of another code leaves the queue alone.
    let mut session = connected(&two, T0);
    session.on_frame(&hello(1, &[1]), &mut two, T0);
    session.outgoing();
    session.on_frame(&error("teapot", Some(refused)), &mut two, T0 + 100);
    session.on_tick(&mut two, T0 + SUBSCRIBE_SPACING_MS);
    assert_eq!(session.outgoing().len(), 1);
}

fn error(code: &str, channel_id: Option<[u8; 16]>) -> Vec<u8> {
    Frame::Error {
        code: code.to_owned(),
        message: String::new(),
        channel_id,
        client_ref: None,
    }
    .encode()
    .unwrap()
}

/// Spec 028, R7: sixteen channels with a tick every second all leave by
/// about 31 s; a `subscribe` that would leave more than 50 000 ms after its
/// `hello` → `Reconnect`; no `hello` within 50 000 ms of `on_connect` or of
/// a `nonce_expired` (a second one not restarting the wait) → `Reconnect`;
/// a clock set back counts the time recorded as long past; after a second
/// `hello`, a tick-released `subscribe` signs its nonce, within the window
/// counted from it.
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

    // Ticks every second release one `subscribe` every two (R6), so 27
    // channels outlast the window: the 26th leaves at its edge, and the
    // next tick, past it and within 1 100 ms of that release, is a
    // `Reconnect` at once. Ticks this close keep R9's 5 000 ms rule quiet.
    let mut many: Channels = (1..=27).map(|byte| channel(byte, DAY, T0)).collect();
    let mut session = connected(&many, T0);
    session.on_frame(&hello(1, &[1]), &mut many, T0);
    session.outgoing();
    let (times, events) = tick_releases(&mut session, &mut many, T0, T0 + NONCE_WINDOW_MS, 1_000);
    assert!(events.is_empty());
    assert_eq!(times.len(), 25);
    assert_eq!(times.last(), Some(&(T0 + NONCE_WINDOW_MS)));
    let step = session.on_tick(&mut many, T0 + NONCE_WINDOW_MS + 1);
    assert_eq!(step.events, [reconnect()]);
    assert!(session.outgoing().is_empty());
    // Past the window the queue is gone: one `Reconnect`, not one a tick.
    let step = session.on_tick(&mut many, T0 + NONCE_WINDOW_MS + 1_000);
    assert!(step.events.is_empty());
    assert!(session.outgoing().is_empty());

    // No `hello` after `on_connect`.
    let mut two = vec![channel(1, DAY, T0), channel(2, DAY, T0)];
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

    // No `hello` after `nonce_expired`, a second one 39 s later not
    // restarting the wait; one that names no channel is a `Reconnect` at
    // once.
    let mut session = connected(&two, T0);
    session.on_frame(&hello(1, &[1]), &mut two, T0);
    let refused = subscribed_ids(&mut session, &two)[0];
    let named = session.on_frame(&error("nonce_expired", Some(refused)), &mut two, T0 + 1_000);
    assert!(named.events.is_empty());
    session.on_frame(
        &error("nonce_expired", Some(refused)),
        &mut two,
        T0 + 40_000,
    );
    let quiet: Step = session.on_tick(&mut two, T0 + 1_000 + HELLO_WAIT_MS);
    assert!(quiet.events.is_empty());
    assert!(session.outgoing().is_empty());
    let late = session.on_tick(&mut two, T0 + 1_001 + HELLO_WAIT_MS);
    assert_eq!(late.events, [reconnect()]);
    let mut session = connected(&two, T0);
    session.on_frame(&hello(1, &[1]), &mut two, T0);
    let step = session.on_frame(&error("nonce_expired", None), &mut two, T0 + 1_000);
    assert_eq!(step.events, [reconnect()]);
    // ... and the queue is gone: no subscribe leaves under the old nonce.
    session.outgoing();
    session.on_tick(&mut two, T0 + 2_000);
    assert!(session.outgoing().is_empty());

    // The clock set back: before the `hello` → `Reconnect`; before
    // `on_connect` → `Reconnect`; before the last release only → the next
    // one leaves, with R9's `Reconnect` for a call earlier than the last.
    let mut session = connected(&two, T0);
    session.on_frame(&hello(1, &[1]), &mut two, T0);
    assert_eq!(
        session.on_tick(&mut two, T0 - 600_000).events,
        [reconnect()]
    );
    let mut session = connected(&two, T0);
    assert_eq!(session.on_tick(&mut two, T0 - 1).events, [reconnect()]);
    let mut three = vec![
        channel(1, DAY, T0),
        channel(2, DAY, T0),
        channel(3, DAY, T0),
    ];
    let mut session = connected(&three, T0);
    session.on_frame(&hello(1, &[1]), &mut three, T0);
    session.on_tick(&mut three, T0 + 1_100);
    session.outgoing();
    assert_eq!(session.on_tick(&mut three, T0 + 500).events, [reconnect()]);
    assert_eq!(session.outgoing().len(), 1);

    // A second `hello` replaces the first: the `subscribe`s released by
    // ticks after it sign its nonce, and its window runs from it, so the
    // last leaves past the first `hello`'s window.
    let mut session = connected(&many, T0);
    session.on_frame(&hello(1, &[1]), &mut many, T0);
    session.outgoing();
    tick_releases(&mut session, &mut many, T0, T0 + 40_000, 1_000);
    session.outgoing();
    let step = session.on_frame(&hello(2, &[1]), &mut many, T0 + 40_500);
    assert!(step.events.is_empty());
    let mut written = subscribes(&mut session);
    let mut last = T0 + 40_500;
    let mut now = T0 + 41_000;
    while now <= T0 + 40_500 + NONCE_WINDOW_MS {
        assert!(session.on_tick(&mut many, now).events.is_empty());
        let released = subscribes(&mut session);
        if !released.is_empty() {
            last = now;
        }
        written.extend(released);
        now += 1_000;
    }
    assert_eq!(written.len(), 6);
    assert!(last > T0 + NONCE_WINDOW_MS);
    for (pk_ch, _, sig) in written {
        let signer = many
            .iter()
            .find(|channel| channel.config().channel_keypair().unwrap().0.0 == pk_ch)
            .unwrap();
        let message = section_6_message(2, signer.config().channel_id(), DAY, HOST);
        assert!(crypto::verify_detached(&PublicKey(pk_ch), &message, &Signature(sig)).is_ok());
    }
}

/// Spec 028, R9 (this slice's part): an `ok` of a channel awaiting one →
/// `Subscribed`; a second `ok`, and one of a channel never subscribed → no
/// event.
#[test]
fn s028_t09_r09_ok_marks_subscribed() {
    let mut channels = vec![channel(1, DAY, T0), channel(2, DAY, T0)];
    let [first, second] = [ids(&channels)[0], ids(&channels)[1]];
    let mut session = connected(&channels, T0);
    session.on_frame(&hello(1, &[1]), &mut channels, T0);
    let step = session.on_frame(&ok(first), &mut channels, T0 + 10);
    assert_eq!(step.events, [Event::Subscribed { channel: first }]);
    assert!(
        session
            .on_frame(&ok(first), &mut channels, T0 + 20)
            .events
            .is_empty()
    );
    // An `ok` that arrives while the session waits for a fresh `hello` still
    // counts.
    let mut late = connected(&channels, T0);
    late.on_frame(&hello(1, &[1]), &mut channels, T0);
    late.on_tick(&mut channels, T0 + 1_100);
    late.on_frame(
        &error("nonce_expired", Some(second)),
        &mut channels,
        T0 + 1_200,
    );
    let step = late.on_frame(&ok(first), &mut channels, T0 + 1_300);
    assert_eq!(step.events, [Event::Subscribed { channel: first }]);
    assert!(
        session
            .on_frame(&ok(second), &mut channels, T0 + 30)
            .events
            .is_empty()
    );
    assert!(
        session
            .on_frame(&ok([0xee; 16]), &mut channels, T0 + 40)
            .events
            .is_empty()
    );
    // A well-formed push of a channel the session does not know: ignored.
    let push = Frame::Push {
        channel_id: [0xee; 16],
        server_id: [1; 16],
        received_at: T0,
        blob: vec![1],
    };
    session.outgoing();
    let step = session.on_frame(&push.encode().unwrap(), &mut channels, T0 + 50);
    assert!(step.events.is_empty());
    assert!(session.outgoing().is_empty());
    // Its `Debug` shows the channel's 4-byte prefix alone (AGENTS 19).
    let shown = format!(
        "{:?}",
        Event::Subscribed {
            channel: [0xab; 16]
        }
    );
    assert_eq!(shown, "Subscribed(abababab)");
    assert_eq!(format!("{:?}", reconnect()), "Reconnect(7)");
    let unsupported = Event::UnsupportedServer {
        connection: CONNECTION,
    };
    assert_eq!(format!("{unsupported:?}"), "UnsupportedServer(7)");
}
