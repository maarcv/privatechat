//! The no-oracle property of spec 028 R18: two runs that differ only in the
//! bytes of the pushes from other members write the same frames at the
//! same calls.

use proptest::collection::vec;
use proptest::prelude::{
    Just, ProptestConfig, Strategy, any, prop_assert_eq, prop_oneof, proptest,
};

use super::acks::ack;
use super::traffic::member;
use super::{CONNECTION, DAY, T0, channel, hello, ids, ok};
use crate::session::channel::{Channel, ClientRef};
use crate::session::connection::{Channels, Session};
use crate::session::frames::Frame;

const DAY_MS: u64 = 86_400_000;

/// Past the one-day channel's window for what was sealed at `T0`.
const START: u64 = T0 + 3 * DAY_MS;

/// What a push from another member carries.
#[derive(Clone, Debug)]
enum Kind {
    /// A message sealed at the push's time.
    Valid,
    /// A valid message with its last byte flipped.
    Forged,
    /// A message sealed at `T0`, past its window.
    Expired,
    /// The channel's first message, which the run may have had already.
    Replayed,
    /// The `key_retired` of a member that regenerated its key.
    Retired,
    /// Bytes that are no blob.
    Garbage(Vec<u8>),
}

/// One call of the run, or the frames the server sends at it.
#[derive(Clone, Debug)]
enum Op {
    /// The clock moves on by this many ms, then `on_tick`.
    Tick(u64),
    /// The user sends this many messages on channel `0` or `1`, then
    /// `after_send`: two bursts fill R15's minute.
    Send(usize, u8),
    /// A push to channel `0` or `1`: the first run gets the first kind,
    /// the second run the second.
    Push(usize, Kind, Kind),
    /// The `ok` of channel `0` or `1`.
    Ok(usize),
    /// The `ack` of the oldest `publish` not yet acknowledged.
    Ack,
    /// The socket closes and a new one opens, with its `hello`.
    Reconnect,
}

fn kind() -> impl Strategy<Value = Kind> {
    prop_oneof![
        Just(Kind::Valid),
        Just(Kind::Forged),
        Just(Kind::Expired),
        Just(Kind::Replayed),
        Just(Kind::Retired),
        vec(any::<u8>(), 1..300).prop_map(Kind::Garbage),
    ]
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        3 => (1u64..3_000).prop_map(Op::Tick),
        1 => Just(Op::Tick(61_000)),
        2 => (0usize..2, 1u8..=20).prop_map(|(channel, count)| Op::Send(channel, count)),
        6 => (0usize..2, kind(), kind()).prop_map(|(channel, a, b)| Op::Push(channel, a, b)),
        2 => (0usize..2).prop_map(Op::Ok),
        2 => Just(Op::Ack),
        1 => Just(Op::Reconnect),
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

/// The blob of `kind` for `channel` at `now`; `first` is the channel's
/// first message.
fn blob(kind: &Kind, channel: &Channel, first: &[u8], now: u64) -> Vec<u8> {
    match kind {
        Kind::Valid => sealed_at(channel, now),
        Kind::Forged => {
            let mut forged = sealed_at(channel, now);
            if let Some(last) = forged.last_mut() {
                *last ^= 1;
            }
            forged
        }
        Kind::Expired => sealed_at(channel, T0),
        Kind::Replayed => first.to_vec(),
        Kind::Retired => retired_at(channel, now),
        Kind::Garbage(bytes) => bytes.clone(),
    }
}

/// A frame written, without the bytes R18 leaves out: the `sig` of a
/// `subscribe`, the `client_ref` and the blob of a `publish`.
fn masked(frame: &[u8]) -> String {
    match Frame::decode(frame).unwrap() {
        Frame::Subscribe {
            pk_ch,
            ttl_seconds,
            since,
            ..
        } => format!("subscribe {pk_ch:?} {ttl_seconds} {since:?}"),
        Frame::Publish { channel_id, .. } => format!("publish {channel_id:?}"),
        _ => format!("{frame:?}"),
    }
}

/// One run of `ops`, with the push blobs of `blobs` in order: the frames
/// written after each call.
fn run(ops: &[Op], blobs: &[Vec<u8>]) -> Vec<Vec<String>> {
    let mut channels = alice();
    let channel_ids = ids(&channels);
    let mut session = Session::new(CONNECTION, channel_ids.clone());
    let mut blobs = blobs.iter();
    let mut unacked: Vec<ClientRef> = Vec::new();
    let mut written = Vec::new();
    let mut now = START;
    let mut hellos = 1;
    session.on_connect(now, &[]);
    session.on_frame(&hello(hellos, &[1]), &mut channels, now);
    for (n, op) in ops.iter().enumerate() {
        let n = u8::try_from(n % 250).unwrap();
        now += 1;
        match op {
            Op::Tick(by) => {
                now += by;
                session.on_tick(&mut channels, now);
            }
            Op::Send(index, count) => {
                for _ in 0..*count {
                    // Past 31 entries the `outbox` is full, in both runs.
                    if channels[*index].encrypt("hello", None, now).is_err() {
                        break;
                    }
                }
                session.after_send(channel_ids[*index], &mut channels, now);
            }
            Op::Push(index, ..) => {
                let blob = blobs.next().unwrap();
                session.on_frame(
                    &push_at(channel_ids[*index], n, blob, now),
                    &mut channels,
                    now,
                );
            }
            Op::Ok(index) => {
                session.on_frame(&ok(channel_ids[*index]), &mut channels, now);
            }
            Op::Ack => {
                if !unacked.is_empty() {
                    let client_ref = unacked.remove(0);
                    session.on_frame(&ack(client_ref, n, now), &mut channels, now);
                }
            }
            Op::Reconnect => {
                session.on_disconnect();
                unacked.clear();
                hellos += 1;
                session.on_connect(now, &[]);
                session.on_frame(&hello(hellos, &[1]), &mut channels, now);
            }
        }
        let frames = session.outgoing();
        for frame in &frames {
            if let Frame::Publish { client_ref, .. } = Frame::decode(frame).unwrap() {
                unacked.push(ClientRef { bytes: client_ref });
            }
        }
        written.push(frames.iter().map(|frame| masked(frame)).collect());
    }
    written
}

/// The `push` of `blob` to `channel_id` as server message `n`, stored at
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

/// The blobs of each run, in the order of their pushes: the times the
/// pushes come at do not depend on the run.
fn blobs_of(ops: &[Op]) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let channels = alice();
    let first: Vec<Vec<u8>> = channels
        .iter()
        .map(|channel| sealed_at(channel, START))
        .collect();
    let (mut a, mut b) = (Vec::new(), Vec::new());
    let mut now = START;
    for op in ops {
        now += 1;
        match op {
            Op::Tick(by) => now += by,
            Op::Push(index, kind_a, kind_b) => {
                let channel = &channels[*index];
                a.push(blob(kind_a, channel, &first[*index], now));
                b.push(blob(kind_b, channel, &first[*index], now));
            }
            _ => {}
        }
    }
    (a, b)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Spec 028, R18: runs that differ only in the bytes of pushes from
    /// other members (valid, forged, expired, replayed, a `key_retired`,
    /// garbage) write the same frames at the same calls, but for a
    /// `subscribe`'s `sig` and a `publish`'s `client_ref` and blob.
    #[test]
    fn s028_t18_r18_no_oracle(ops in vec(op(), 1..60)) {
        let (a, b) = blobs_of(&ops);
        prop_assert_eq!(run(&ops, &a), run(&ops, &b));
    }
}
