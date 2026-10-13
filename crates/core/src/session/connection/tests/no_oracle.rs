//! The no-oracle property of spec 028 R18: two runs that differ only in the
//! bytes of the pushes from other members write the same frames at the
//! same calls.

use proptest::collection::vec;
use proptest::option;
use proptest::prelude::{
    Just, ProptestConfig, Strategy, any, prop_assert_eq, prop_oneof, proptest,
};

use super::acks::ack;
use super::limits::error_frame;
use super::traffic::member;
use super::{CONNECTION, DAY, DAY_MS, T0, channel, hello, ids, ok};
use crate::session::channel::{Channel, ClientRef};
use crate::session::connection::{Channels, Event, Session, Step};
use crate::session::frames::{
    CODE_BAD_AUTH, CODE_BAD_BLOB, CODE_CHANNEL_QUOTA, CODE_NONCE_EXPIRED, CODE_RATE_LIMITED,
    CODE_SERVER_FULL, Frame,
};

/// Past both channels' windows for what was sealed at `T0`.
const START: u64 = T0 + 8 * DAY_MS;

/// What a push from another member carries.
#[derive(Clone, Debug)]
enum Kind {
    /// A message sealed at the push's time.
    Valid,
    /// A valid message with its last byte flipped.
    Forged,
    /// A valid message of the other channel.
    OtherChannel,
    /// A message sealed at `T0`, past its window.
    Expired,
    /// The channel's first message, which the run may have had already.
    Replayed,
    /// The `key_retired` of a member that regenerated its key.
    Retired,
    /// Bytes that are no blob.
    Garbage(Vec<u8>),
}

/// One call of the run, or the frame the server sends at it, each some
/// time after the one before, so that a window may open between ticks.
#[derive(Clone, Debug)]
enum Op {
    /// `on_tick`.
    Tick,
    /// The user sends this many messages on channel `0` or `1`, then
    /// `after_send`: two bursts fill R15's minute.
    Send(usize, u8),
    /// A push to channel `0` or `1` with `server_id` `[n; 16]`, `n` drawn
    /// from a few so that some come again: run `i` gets kind `i`.
    Push(usize, u8, [Kind; 2]),
    /// The `ok` of channel `0` or `1`.
    Ok(usize),
    /// The `ack` of the oldest `publish` not yet acknowledged, with
    /// `server_id` `[n; 16]`, `n` drawn from the pushes' few.
    Ack(u8),
    /// An `error` with this code, naming channel `0` or `1` or none, and
    /// the oldest `publish` not yet acknowledged or none.
    Error(&'static str, Option<usize>, bool),
    /// The user regenerates the key of channel `0` or `1`, then
    /// `after_send`: its `key_retired` and its old key's entries are
    /// pending.
    Regenerate(usize),
    /// The socket closes and a new one opens, with its `hello`.
    Reconnect,
    /// A fresh `hello` on the same socket, as after a `nonce_expired`.
    Hello,
}

fn kind() -> impl Strategy<Value = Kind> {
    prop_oneof![
        Just(Kind::Valid),
        Just(Kind::Forged),
        Just(Kind::OtherChannel),
        Just(Kind::Expired),
        Just(Kind::Replayed),
        Just(Kind::Retired),
        vec(any::<u8>(), 1..600).prop_map(Kind::Garbage),
    ]
}

/// The time before a call: mostly under the 5 000 ms of R9's gap, at
/// times past a minute, so that a pause, a hold or R15's window may end
/// before a frame rather than a tick.
fn delay() -> impl Strategy<Value = u64> {
    prop_oneof![9 => 0u64..2_000, 1 => Just(61_000)]
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        4 => Just(Op::Tick),
        2 => (0usize..2, 1u8..=20).prop_map(|(channel, count)| Op::Send(channel, count)),
        6 => (0usize..2, 0u8..8, kind(), kind())
            .prop_map(|(channel, n, a, b)| Op::Push(channel, n, [a, b])),
        2 => (0usize..2).prop_map(Op::Ok),
        2 => (0u8..8).prop_map(Op::Ack),
        1 => (0usize..2).prop_map(Op::Regenerate),
        1 => Just(Op::Reconnect),
        3 => Just(Op::Hello),
        3 => (
            prop_oneof![
                Just(CODE_RATE_LIMITED),
                Just(CODE_CHANNEL_QUOTA),
                Just(CODE_SERVER_FULL),
                Just(CODE_BAD_BLOB),
                Just(CODE_NONCE_EXPIRED),
                Just(CODE_BAD_AUTH),
            ],
            option::of(0usize..2),
            any::<bool>(),
        )
            .prop_map(|(code, channel, entry)| Op::Error(code, channel, entry)),
    ]
}

/// A one-day channel and a seven-day one, both created at `T0`.
fn alice() -> Channels {
    vec![channel(1, DAY, T0), channel(2, 7 * DAY, T0)]
}

/// The blob a new member of `channel`'s channel seals for "hi" at `now`.
fn sealed_at(channel: &Channel, now: u64) -> Vec<u8> {
    let mut sender = member(channel);
    let client_ref = sender.encrypt("hi", None, now).unwrap();
    let step = sender.outbox(now, &[], false).unwrap();
    let (_, blob) = step
        .publish
        .into_iter()
        .find(|(entry, _)| *entry == client_ref)
        .unwrap();
    blob
}

/// The `key_retired` of a new member of `channel`'s channel that
/// regenerated its key at `now`.
fn retired_at(channel: &Channel, now: u64) -> Vec<u8> {
    let mut sender = member(channel);
    sender.regenerate_identity(now).unwrap();
    let step = sender.outbox(now, &[], false).unwrap();
    step.publish[0].1.clone()
}

/// The blob of `kind` for channel `index` of `channels` at `now`; `first`
/// is the channel's first message.
fn blob(kind: &Kind, channels: &Channels, index: usize, first: &[u8], now: u64) -> Vec<u8> {
    let channel = &channels[index];
    match kind {
        Kind::Valid => sealed_at(channel, now),
        Kind::Forged => {
            let mut forged = sealed_at(channel, now);
            if let Some(last) = forged.last_mut() {
                *last ^= 1;
            }
            forged
        }
        Kind::OtherChannel => sealed_at(&channels[1 - index], now),
        Kind::Expired => sealed_at(channel, T0),
        Kind::Replayed => first.to_vec(),
        Kind::Retired => retired_at(channel, now),
        Kind::Garbage(bytes) => bytes.clone(),
    }
}

/// A frame written, without the bytes R18 leaves out: the `sig` of a
/// `subscribe`, the `client_ref` and the blob of a `publish`, whose length
/// stays.
fn masked(frame: &[u8]) -> String {
    match Frame::decode(frame).unwrap() {
        Frame::Subscribe {
            pk_ch,
            ttl_seconds,
            since,
            ..
        } => format!("subscribe {pk_ch:?} {ttl_seconds} {since:?}"),
        Frame::Publish {
            channel_id, blob, ..
        } => format!("publish {channel_id:?} {}", blob.len()),
        _ => format!("{frame:?}"),
    }
}

/// What a call left that a server could see, or that the `Device` acts
/// on: the frames written, masked, the events but `Message` and
/// `StatusChanged`, which tell the user what came, with no `client_ref`,
/// and the channels of the failed list.
type Seen = (Vec<String>, Vec<Event>, Vec<[u8; 16]>);

/// `event` with its `client_ref`, which differs from run to run, zeroed.
fn without_client_ref(mut event: Event) -> Event {
    if let Event::Delivered { client_ref, .. } | Event::NotDelivered { client_ref, .. } = &mut event
    {
        client_ref.bytes = [0; 16];
    }
    event
}

/// Run `side` of `ops`, each after its delay, the pushes carrying kind
/// `side`: what each call left.
fn run(ops: &[(u64, Op)], side: usize) -> Vec<Seen> {
    let mut channels = alice();
    let channel_ids = ids(&channels);
    let first: Vec<Vec<u8>> = channels
        .iter()
        .map(|channel| sealed_at(channel, START))
        .collect();
    let mut session = Session::new(CONNECTION, channel_ids.clone());
    let mut unacked: Vec<ClientRef> = Vec::new();
    let mut written = Vec::new();
    let mut now = START;
    let mut hellos = 1;
    session.on_connect(now, &[]);
    session.on_frame(&hello(hellos, &[1]), &mut channels, now);
    for (delay, op) in ops {
        now += 1 + delay;
        let step = match op {
            Op::Tick => session.on_tick(&mut channels, now),
            Op::Send(index, count) => {
                for _ in 0..*count {
                    // Past 31 entries the `outbox` is full, in both runs.
                    if channels[*index].encrypt("hello", None, now).is_err() {
                        break;
                    }
                }
                session.after_send(channel_ids[*index], &mut channels, now)
            }
            Op::Push(index, server_id, kinds) => {
                let blob = blob(&kinds[side], &channels, *index, &first[*index], now);
                let push = push_at(channel_ids[*index], *server_id, &blob, now);
                session.on_frame(&push, &mut channels, now)
            }
            Op::Ok(index) => session.on_frame(&ok(channel_ids[*index]), &mut channels, now),
            Op::Ack(server_id) if !unacked.is_empty() => {
                let client_ref = unacked.remove(0);
                session.on_frame(&ack(client_ref, *server_id, now), &mut channels, now)
            }
            Op::Ack(_) => Step::default(),
            Op::Error(code, channel, entry) => {
                let channel_id = channel.map(|index| channel_ids[index]);
                let client_ref = match entry {
                    true if !unacked.is_empty() => Some(unacked.remove(0)),
                    _ => None,
                };
                let error = error_frame(code, channel_id, client_ref);
                session.on_frame(&error, &mut channels, now)
            }
            Op::Regenerate(index) => {
                // A second one while the first is pending fails, in both
                // runs.
                let _ = channels[*index].regenerate_identity(now);
                session.after_send(channel_ids[*index], &mut channels, now)
            }
            Op::Reconnect => {
                session.on_disconnect();
                unacked.clear();
                hellos += 1;
                session.on_connect(now, &[]);
                session.on_frame(&hello(hellos, &[1]), &mut channels, now)
            }
            Op::Hello => {
                hellos += 1;
                session.on_frame(&hello(hellos, &[1]), &mut channels, now)
            }
        };
        let frames = session.outgoing();
        for frame in &frames {
            if let Frame::Publish { client_ref, .. } = Frame::decode(frame).unwrap() {
                unacked.push(ClientRef { bytes: client_ref });
            }
        }
        let events = step
            .events
            .into_iter()
            .filter(|event| !matches!(event, Event::Message { .. } | Event::StatusChanged { .. }))
            .map(without_client_ref)
            .collect();
        let failed = step
            .failed
            .iter()
            .map(|(channel_id, _)| *channel_id)
            .collect();
        let masked = frames.iter().map(|frame| masked(frame)).collect();
        written.push((masked, events, failed));
    }
    written
}

/// The `push` of `blob` to `channel_id` with `server_id` `[n; 16]`, stored at
/// `now`.
fn push_at(channel_id: [u8; 16], n: u8, blob: &[u8], now: u64) -> Vec<u8> {
    Frame::Push {
        channel_id,
        server_id: [n; 16],
        received_at: now,
        blob: blob.to_vec(),
    }
    .encode()
    .unwrap()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Spec 028, R18: runs that differ only in the bytes of pushes from
    /// other members (valid, forged, of the other channel, expired,
    /// replayed, a `key_retired`, garbage), among ticks, sends,
    /// regenerations of one's own key, `ok`s, `ack`s, `error`s and
    /// reconnections, write the same frames at the
    /// same calls, but for a `subscribe`'s `sig` and a `publish`'s
    /// `client_ref` and blob bytes, and leave the same events, but those
    /// that tell the user what came and the `client_ref`s, and the same
    /// failed list.
    #[test]
    fn s028_t18_r18_no_oracle(ops in vec((delay(), op()), 1..60)) {
        prop_assert_eq!(run(&ops, 0), run(&ops, 1));
    }
}
