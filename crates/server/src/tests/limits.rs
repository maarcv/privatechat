//! Spec 033-rate-limit-quotas over a real socket, with a `ManualClock`: the
//! limits of one connection.

use std::sync::Arc;
use std::time::Duration;

use futures_util::StreamExt;
use tokio::net::TcpSocket;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;

use privatechat_core::testing::subscribe_credential;
use privatechat_core::{Frame, relay};

use super::TestDir;
use super::catch_up::{T0, backlog, plant, store_many, subscribe_since};
use super::publish::{blob_of, client_ref, fill_writer, hold_writer, publish, refused};
use super::store::writer::{Harness, NO_QUOTA, request as writer_request};
use super::ws::{
    Client, DAY, HOST, Received, channel, connect, hello, receive, receive_within, send, start,
    subscribe,
};
use crate::clock::ManualClock;
use crate::hub::{Encoded, Hub, Pending};
use crate::limits::{
    CHANNEL_WINDOW_MS, CONN_PUBLISH_MAX, CONN_PUBLISH_WINDOW_MS, ChannelLimits, MAX_SUBSCRIPTIONS,
    PING_INTERVAL_MS, PONG_TIMEOUT_MS, SEND_QUEUE_BYTES, SEND_QUEUE_FRAMES, SUBSCRIBE_GAP_MS,
    WRITE_TIMEOUT_MS, pong_overdue,
};
use crate::store::writer::Row;
use crate::store::writer::purge::PURGE_INTERVAL_MS;
use crate::store::writer::test::{Hooks, Pause};
use crate::store::writer::{Refusal, WriteOutcome, WriteRequest};

/// A `publish` of a blob of the smallest size on the test channel.
fn on_channel(n: u16) -> Frame {
    publish(channel(), n, blob_of(channel(), 1))
}

/// `n` `ack`s, each with its echo, in any order of the two kinds.
async fn acked(client: &mut Client, n: usize) {
    let (mut acks, mut pushes) = (0, 0);
    while acks + pushes < 2 * n {
        match receive(client).await {
            Received::Frame(Frame::Ack { .. }) => acks += 1,
            Received::Frame(Frame::Push { .. }) => pushes += 1,
            other => {
                let unexpected = Some(other);
                assert!(
                    unexpected.is_none(),
                    "unexpected {unexpected:?} after {acks} acks"
                );
                break;
            }
        }
    }
    assert_eq!((acks, pushes), (n, n));
}

#[tokio::test(flavor = "multi_thread")]
async fn s033_t01_r01_connection_publish_rate() {
    let clock = Arc::new(ManualClock::new(T0));
    let server = start(&clock).await;
    let mut client = connect(server.address).await;
    let nonce = hello(&mut client).await;
    send(&mut client, &subscribe_since(&nonce, None)).await;
    assert!(backlog(&mut client, channel()).await.is_empty());

    let max = u16::try_from(CONN_PUBLISH_MAX).unwrap();
    for n in 0..max {
        send(&mut client, &on_channel(n)).await;
    }
    acked(&mut client, CONN_PUBLISH_MAX).await;
    send(&mut client, &on_channel(max)).await;
    refused(
        &mut client,
        "rate_limited",
        channel(),
        Some(client_ref(max)),
    )
    .await;

    // At the edge of the window the first 30 still count.
    clock.advance_mono(CONN_PUBLISH_WINDOW_MS);
    send(&mut client, &on_channel(max + 1)).await;
    refused(
        &mut client,
        "rate_limited",
        channel(),
        Some(client_ref(max + 1)),
    )
    .await;

    // Past it, 30 more: the two refused did not count.
    clock.advance_mono(1);
    for n in 0..max {
        send(&mut client, &on_channel(100 + n)).await;
    }
    acked(&mut client, CONN_PUBLISH_MAX).await;
    send(&mut client, &on_channel(200)).await;
    refused(
        &mut client,
        "rate_limited",
        channel(),
        Some(client_ref(200)),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn s033_t01_r01_writer_refusal_not_counted() {
    // A publish the writer's full queue refuses was not handed: 30 more fit
    // in the window afterwards.
    let clock = Arc::new(ManualClock::new(T0));
    let server = start(&clock).await;
    let mut client = connect(server.address).await;
    let nonce = hello(&mut client).await;
    send(&mut client, &subscribe_since(&nonce, None)).await;
    assert!(backlog(&mut client, channel()).await.is_empty());
    let held = hold_writer(&server).await;
    let filled = fill_writer(&server, [7; 16]);
    send(&mut client, &on_channel(0)).await;
    refused(&mut client, "rate_limited", channel(), Some(client_ref(0))).await;
    drop(held);
    // Until the writer has stored every filler and its queue is empty.
    let mut drained = false;
    for _ in 0..3_000 {
        if server.shared.hub().committed(&[7; 16]) == filled {
            drained = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(drained, "the writer did not store its queue in 30 s");
    let max = u16::try_from(CONN_PUBLISH_MAX).unwrap();
    for n in 1..=max {
        send(&mut client, &on_channel(n)).await;
    }
    acked(&mut client, CONN_PUBLISH_MAX).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn s033_t02_r02_subscribe_gap() {
    let clock = Arc::new(ManualClock::new(T0));
    let server = start(&clock).await;
    let mut client = connect(server.address).await;
    hello(&mut client).await;
    let forged = subscribe(&[9; 32], HOST);

    send(&mut client, &forged).await;
    refused(&mut client, "bad_auth", channel(), None).await;
    // 999 ms later: refused before any check, not a failed attempt.
    clock.advance_mono(SUBSCRIBE_GAP_MS - 1);
    send(&mut client, &forged).await;
    refused(&mut client, "rate_limited", channel(), None).await;
    // The refused one counts too: 1 499 ms after the checked one, 500 ms
    // after it, still too soon.
    clock.advance_mono(500);
    send(&mut client, &forged).await;
    refused(&mut client, "rate_limited", channel(), None).await;
    // 1 000 ms after that one: checked, the second failure, not the third.
    clock.advance_mono(SUBSCRIBE_GAP_MS);
    send(&mut client, &forged).await;
    refused(&mut client, "bad_auth", channel(), None).await;
    assert!(matches!(
        receive_within(&mut client, 300).await,
        Received::Nothing
    ));
    clock.advance_mono(SUBSCRIBE_GAP_MS);
    send(&mut client, &forged).await;
    refused(&mut client, "bad_auth", channel(), None).await;
    assert!(matches!(receive(&mut client).await, Received::Close(1008)));

    // Past the first-subscribe deadline, a subscribe too soon gets no
    // refusal, only the close of spec 031 R7.
    let mut client = connect(server.address).await;
    hello(&mut client).await;
    clock.advance_mono(59_500);
    send(&mut client, &forged).await;
    refused(&mut client, "bad_auth", channel(), None).await;
    // 60 001 ms after the hello, 501 ms after the last subscribe. The tick
    // may close first; either way no `rate_limited` comes.
    clock.advance_mono(501);
    send(&mut client, &forged).await;
    assert!(matches!(receive(&mut client).await, Received::Close(1008)));
}

/// A `subscribe` of the `n`th key under `nonce`, and its `channel_id`.
fn keyed(n: u8, nonce: &[u8; 32]) -> (Frame, [u8; 16]) {
    let k_ch = [0x50 + n; 32];
    let (pk_ch, sig) = subscribe_credential(k_ch, DAY, nonce, HOST).unwrap();
    let channel_id = relay::channel_id(&pk_ch, DAY).unwrap();
    let frame = Frame::Subscribe {
        pk_ch,
        ttl_seconds: DAY,
        sig,
        since: None,
    };
    (frame, channel_id)
}

#[tokio::test(flavor = "multi_thread")]
async fn s033_t03_r03_sixteen_channels() {
    let clock = Arc::new(ManualClock::new(T0));
    let server = start(&clock).await;
    let mut client = connect(server.address).await;
    let nonce = hello(&mut client).await;
    let max = u8::try_from(MAX_SUBSCRIPTIONS).unwrap();
    for n in 0..max {
        let (frame, channel_id) = keyed(n, &nonce);
        send(&mut client, &frame).await;
        assert!(backlog(&mut client, channel_id).await.is_empty());
        clock.advance_mono(SUBSCRIBE_GAP_MS);
    }
    // A second subscribe of a channel held, with 16 held: ignored; and
    // again at once, refused by R2, not closed.
    let (held, held_id) = keyed(0, &nonce);
    send(&mut client, &held).await;
    assert!(matches!(
        receive_within(&mut client, 300).await,
        Received::Nothing
    ));
    send(&mut client, &held).await;
    refused(&mut client, "rate_limited", held_id, None).await;
    assert!(matches!(
        receive_within(&mut client, 300).await,
        Received::Nothing
    ));
    // A 17th channel, its signature forged: refused before spec 031 would
    // answer `bad_auth`, then the close.
    clock.advance_mono(SUBSCRIBE_GAP_MS);
    let (frame, channel_id) = keyed(max, &[9; 32]);
    send(&mut client, &frame).await;
    refused(&mut client, "rate_limited", channel_id, None).await;
    assert!(matches!(receive(&mut client).await, Received::Close(1008)));

    // A 17th channel that also comes too soon: one refusal, then the close.
    let mut client = connect(server.address).await;
    let nonce = hello(&mut client).await;
    for n in 0..max {
        let (frame, channel_id) = keyed(n, &nonce);
        send(&mut client, &frame).await;
        assert!(backlog(&mut client, channel_id).await.is_empty());
        clock.advance_mono(SUBSCRIBE_GAP_MS);
    }
    clock.advance_mono(1);
    send(&mut client, &keyed(0, &nonce).0).await;
    let (frame, channel_id) = keyed(max, &nonce);
    send(&mut client, &frame).await;
    refused(&mut client, "rate_limited", channel_id, None).await;
    assert!(matches!(receive(&mut client).await, Received::Close(1008)));
}

/// A client subscribed to the test channel on a new server, its empty
/// backlog read; the server's first connection, of id 0.
async fn subscriber(clock: &Arc<ManualClock>) -> (super::ws::Server, Client) {
    let server = start(clock).await;
    let mut client = connect(server.address).await;
    let nonce = hello(&mut client).await;
    send(&mut client, &subscribe_since(&nonce, None)).await;
    assert!(backlog(&mut client, channel()).await.is_empty());
    (server, client)
}

/// A client of `server` with a 65 536-byte receive buffer, so that what it
/// does not read soon stalls the server's writes.
async fn slow_client(server: &super::ws::Server) -> Client {
    let socket = TcpSocket::new_v4().unwrap();
    socket.set_recv_buffer_size(65_536).unwrap();
    let stream = socket.connect(server.address).await.unwrap();
    let stream = tokio_tungstenite::MaybeTlsStream::Plain(stream);
    let (client, _) = tokio_tungstenite::client_async(format!("ws://{}/", server.address), stream)
        .await
        .unwrap();
    client
}

/// The next message of `client`, whatever it is, within 10 s.
async fn next_message(client: &mut Client) -> Option<Message> {
    tokio::time::timeout(Duration::from_secs(10), client.next())
        .await
        .ok()
        .flatten()
        .and_then(Result::ok)
}

/// Some ticks of the deadline task, in real time.
async fn ticks() {
    tokio::time::sleep(Duration::from_millis(300)).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn s033_t04_r04_ping_pong() {
    // The rule at its edges: a ping due at 30 000, the last other write
    // completed before it, or after it.
    let due = Some(30_000);
    assert!(!pong_overdue(59_999, due, 29_999));
    assert!(pong_overdue(60_000, due, 29_999));
    assert!(
        !pong_overdue(60_000, due, 30_000),
        "a write completed since"
    );
    assert!(!pong_overdue(90_000, None, 0), "the pong came");

    // A ping every 30 000 ms, the first a whole interval after the connect;
    // answered, the connection goes on.
    let clock = Arc::new(ManualClock::new(T0));
    let server = start(&clock).await;
    let mut client = connect(server.address).await;
    let first = next_message(&mut client).await;
    let nonce = match &first {
        Some(Message::Binary(bytes)) => match Frame::decode(bytes) {
            Ok(Frame::Hello { server_nonce, .. }) => Some(server_nonce),
            _ => None,
        },
        _ => None,
    };
    assert!(nonce.is_some(), "not the hello first: {first:?}");
    send(
        &mut client,
        &subscribe_since(&nonce.unwrap_or_default(), None),
    )
    .await;
    assert!(backlog(&mut client, channel()).await.is_empty());
    clock.advance_mono(PING_INTERVAL_MS - 1);
    ticks().await;
    let early = tokio::time::timeout(Duration::from_millis(100), client.next()).await;
    assert!(early.is_err(), "a ping before its interval: {early:?}");
    clock.advance_mono(1);
    let ping = next_message(&mut client).await;
    assert!(matches!(ping, Some(Message::Ping(_))), "{ping:?}");
    assert!(matches!(
        receive_within(&mut client, 300).await,
        Received::Nothing
    ));
    clock.advance_mono(PING_INTERVAL_MS);
    let ping = next_message(&mut client).await;
    assert!(matches!(ping, Some(Message::Ping(_))), "{ping:?}");
    // Reading again sends the pong.
    assert!(matches!(
        receive_within(&mut client, 300).await,
        Received::Nothing
    ));

    // A client that stops reading and answering: closed with 1001
    // `PONG_TIMEOUT_MS` after the ping was due, not a millisecond before.
    let clock = Arc::new(ManualClock::new(T0));
    let (server, mut client) = subscriber(&clock).await;
    clock.advance_mono(PING_INTERVAL_MS);
    ticks().await;
    clock.advance_mono(PONG_TIMEOUT_MS - 1);
    ticks().await;
    assert_eq!(server.shared.hub().subscriptions(0), 1, "closed early");
    clock.advance_mono(1);
    ticks().await;
    assert_eq!(server.shared.hub().subscriptions(0), 0, "not closed");
    let ping = next_message(&mut client).await;
    assert!(matches!(ping, Some(Message::Ping(_))), "{ping:?}");
    assert!(matches!(receive(&mut client).await, Received::Close(1001)));

    // A client that sends pings of its own but reads nothing: its pings are
    // no pong, and it is closed all the same.
    let clock = Arc::new(ManualClock::new(T0));
    let (server, mut client) = subscriber(&clock).await;
    clock.advance_mono(PING_INTERVAL_MS);
    ticks().await;
    futures_util::SinkExt::send(&mut client, Message::Ping(Vec::new().into()))
        .await
        .unwrap();
    ticks().await;
    clock.advance_mono(PONG_TIMEOUT_MS);
    ticks().await;
    assert_eq!(
        server.shared.hub().subscriptions(0),
        0,
        "a ping taken for a pong"
    );

    // A ping sent late, its 30 000 ms counted from when it was due.
    let clock = Arc::new(ManualClock::new(T0));
    let (server, _client) = subscriber(&clock).await;
    clock.advance_mono(PING_INTERVAL_MS + 1_000);
    ticks().await;
    clock.advance_mono(PONG_TIMEOUT_MS - 1_000);
    ticks().await;
    assert_eq!(server.shared.hub().subscriptions(0), 0, "not closed");

    // A client reading steadily but slowly behind a large backlog, its pongs
    // late behind it: the writes go on, and it is not closed.
    let clock = Arc::new(ManualClock::new(T0));
    let server = start(&clock).await;
    plant(&server, channel(), 40, 64_673, T0 - 300, T0 + 3_600_000);
    let mut client = slow_client(&server).await;
    let nonce = hello(&mut client).await;
    send(&mut client, &subscribe_since(&nonce, None)).await;
    let (mut pushes, mut pings) = (0, 0);
    loop {
        match next_message(&mut client).await {
            Some(Message::Binary(bytes)) => match Frame::decode(&bytes) {
                Ok(Frame::Push { .. }) => {
                    // `STEP` of the clock a push: pings come due among the
                    // pushes and wait behind those the socket holds, while
                    // every push read lets another write complete.
                    pushes += 1;
                    clock.advance_mono(STEP);
                    ticks().await;
                }
                Ok(Frame::Ok { .. }) => break,
                other => {
                    let unexpected = Some(other);
                    assert!(unexpected.is_none(), "unexpected {unexpected:?}");
                    break;
                }
            },
            Some(Message::Ping(_)) => pings += 1,
            other => {
                let unexpected = Some(other);
                assert!(
                    unexpected.is_none(),
                    "unexpected {unexpected:?} after {pushes} pushes"
                );
                break;
            }
        }
    }
    assert_eq!(pushes, 40);
    assert!(pings >= 1, "no ping among the pushes");
    // After `ok`, well past the due time of every ping sent: still open.
    for _ in 0..4 {
        clock.advance_mono(PING_INTERVAL_MS / 2);
        let next = tokio::time::timeout(Duration::from_millis(300), client.next()).await;
        assert!(
            matches!(next, Err(_) | Ok(Some(Ok(Message::Ping(_))))),
            "{next:?}"
        );
    }
}

/// The clock a slow reader moves for each push it reads.
const STEP: u64 = 6_000;

#[tokio::test(flavor = "multi_thread")]
async fn s033_t05_r05_send_queue_and_write_deadline() {
    // A subscriber whose writes are paused: 256 frames waiting, the one
    // being written included, fit; the 257th closes it with 1013.
    let frames = u16::try_from(SEND_QUEUE_FRAMES).unwrap();
    for (count, closed) in [(frames, false), (frames + 1, true)] {
        let clock = Arc::new(ManualClock::new(T0));
        let (server, mut client) = subscriber(&clock).await;
        server.shared.hooks.pause_writes(true);
        store_many(&server, channel(), count, 1_185).await;
        server.shared.hooks.pause_writes(false);
        let mut pushes = 0;
        let end = loop {
            match receive_within(&mut client, 500).await {
                Received::Frame(Frame::Push { .. }) => pushes += 1,
                other => break other,
            }
        };
        if closed {
            assert!(matches!(end, Received::Close(1013)), "{end:?}");
            assert!(pushes <= 1, "{pushes} pushes past the drop");
        } else {
            assert!(matches!(end, Received::Nothing), "{end:?}");
            assert_eq!(pushes, usize::from(count));
        }
    }

    // Blobs of 64 673 bytes: 64 frames fit in 4 MiB, the 65th does not.
    let row = Row {
        server_id: [0; 16],
        received_at: T0,
        blob: vec![1; 64_673],
    };
    let frame = crate::frames::push(channel(), row).encode().unwrap().len();
    assert!(64 * frame <= SEND_QUEUE_BYTES && 65 * frame > SEND_QUEUE_BYTES);
    for (count, closed) in [(64u16, false), (65, true)] {
        let clock = Arc::new(ManualClock::new(T0));
        let (server, mut client) = subscriber(&clock).await;
        server.shared.hooks.pause_writes(true);
        store_many(&server, channel(), count, 64_673).await;
        server.shared.hooks.pause_writes(false);
        let mut pushes = 0;
        let end = loop {
            match receive_within(&mut client, 500).await {
                Received::Frame(Frame::Push { .. }) => pushes += 1,
                other => break other,
            }
        };
        if closed {
            assert!(matches!(end, Received::Close(1013)), "{end:?}");
        } else {
            assert!(matches!(end, Received::Nothing), "{end:?}");
            assert_eq!(pushes, usize::from(count));
        }
    }

    // A ping whose write stalls: dropped with no close frame, like any write.
    let clock = Arc::new(ManualClock::new(T0));
    let (server, mut client) = subscriber(&clock).await;
    server.shared.hooks.pause_writes(true);
    clock.advance_mono(PING_INTERVAL_MS);
    ticks().await;
    clock.advance_mono(WRITE_TIMEOUT_MS);
    ticks().await;
    assert_eq!(server.shared.hub().subscriptions(0), 0, "not dropped");
    server.shared.hooks.pause_writes(false);
    let last = next_message(&mut client).await;
    assert!(!matches!(last, Some(Message::Close(_))), "{last:?}");

    // A close frame whose write stalls: dropped at the same deadline, not
    // before it, and the client never gets the close.
    let clock = Arc::new(ManualClock::new(T0));
    let (server, mut client) = subscriber(&clock).await;
    server.shared.hooks.pause_writes(true);
    futures_util::SinkExt::send(&mut client, Message::Text("x".into()))
        .await
        .unwrap();
    ticks().await;
    clock.advance_mono(WRITE_TIMEOUT_MS - 1);
    ticks().await;
    assert_eq!(server.shared.hooks.tasks(), 1, "the close dropped early");
    clock.advance_mono(1);
    ticks().await;
    assert_eq!(server.shared.hooks.tasks(), 0, "the close never dropped");
    server.shared.hooks.pause_writes(false);
    let last = next_message(&mut client).await;
    assert!(!matches!(last, Some(Message::Close(_))), "{last:?}");

    // A client that stops reading with a small receive buffer: a write stuck
    // mid-frame, part of it taken; the TCP connection dropped with no close
    // frame `WRITE_TIMEOUT_MS` of the monotonic clock after that write began.
    let clock = Arc::new(ManualClock::new(T0));
    let server = start(&clock).await;
    plant(&server, channel(), 40, 64_673, T0 - 300, T0 + 3_600_000);
    let mut client = slow_client(&server).await;
    let nonce = hello(&mut client).await;
    send(&mut client, &subscribe_since(&nonce, None)).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    clock.advance_mono(WRITE_TIMEOUT_MS - 1);
    ticks().await;
    assert_eq!(server.shared.hub().subscriptions(0), 1, "dropped early");
    clock.advance_mono(1);
    ticks().await;
    assert_eq!(server.shared.hub().subscriptions(0), 0, "not dropped");
    let mut pushes = 0;
    let end = loop {
        match next_message(&mut client).await {
            Some(Message::Binary(_)) => pushes += 1,
            other => break other,
        }
    };
    assert!(pushes < 40, "all {pushes} pushes came");
    assert!(!matches!(end, Some(Message::Close(_))), "{end:?}");
}

#[test]
fn s033_t05_r05_queue_bytes() {
    // 4 MiB of frames waiting, exactly, fit; one byte more overflows; a frame
    // written makes room again (spec 033-rate-limit-quotas R5).
    let mut hub = Hub::default();
    let (sender, _queue) = mpsc::channel(SEND_QUEUE_FRAMES);
    let pending = Arc::new(Pending::default());
    hub.connect(1, sender, pending.clone());
    let frame = Encoded::from(vec![0; SEND_QUEUE_BYTES / 64]);
    for _ in 0..64 {
        hub.enqueue(1, frame.clone());
    }
    assert!(!pending.overflowed(), "4 MiB fit");
    pending.written(frame.len());
    hub.enqueue(1, frame.clone());
    assert!(!pending.overflowed(), "a frame written made room");
    hub.enqueue(1, Encoded::from_static(b"x"));
    assert!(pending.overflowed(), "one byte past 4 MiB");
}

/// A writer with `limits` on a database of its own, its clock at `T0`.
fn limited(
    name: &str,
    limits: ChannelLimits,
    hooks: Hooks,
) -> (TestDir, Arc<ManualClock>, Harness) {
    let dir = TestDir::new(name);
    let clock = Arc::new(ManualClock::new(T0));
    let harness = Harness::with_limits(&dir.db(), &clock, hooks, NO_QUOTA, limits);
    (dir, clock, harness)
}

/// Request `n` on channel `[channel; 16]` with a blob of `bytes` bytes.
fn sized(n: u16, channel: u8, bytes: usize) -> WriteRequest {
    WriteRequest {
        blob: vec![channel; bytes],
        ..writer_request(n, channel, DAY)
    }
}

/// Submits `requests` while the writer is held, so that they are stored in
/// one transaction, and returns their outcomes in order.
fn one_transaction(
    harness: &Harness,
    pause: &Pause,
    requests: Vec<WriteRequest>,
) -> Vec<WriteOutcome> {
    pause.hold();
    let n = requests.len();
    for request in requests {
        harness.writer.submit(request).unwrap();
    }
    pause.release();
    let batch = harness.next();
    assert_eq!(batch.len(), n, "not one transaction");
    batch
}

#[test]
fn s033_t06_r06_channel_rate() {
    let limits = ChannelLimits::default();
    let max = u16::try_from(limits.publish_per_min).unwrap();

    // 120 inserts within 60 000 ms, from seven connections; the 121st refused.
    let (_dir, clock, harness) = limited("s033_t06", limits, Hooks::default());
    for n in 0..max {
        let outcome = harness.store(writer_request(n, 1, DAY));
        assert!(outcome.result.is_ok(), "{n}: {outcome:?}");
    }
    assert_eq!(
        harness.store(writer_request(max, 1, DAY)).result,
        Err(Refusal::RateLimited)
    );
    // Another channel is not counted.
    assert!(harness.store(writer_request(max, 2, DAY)).result.is_ok());
    // At the edge of the window the 120 still count; past it, accepted.
    clock.advance_mono(CHANNEL_WINDOW_MS);
    assert_eq!(
        harness.store(writer_request(max + 1, 1, DAY)).result,
        Err(Refusal::RateLimited)
    );
    clock.advance_mono(1);
    assert!(
        harness
            .store(writer_request(max + 2, 1, DAY))
            .result
            .is_ok()
    );

    // Blobs of 64 673 bytes: refused once the next would pass 4 MiB.
    let fit = u16::try_from(limits.bytes_per_min / 64_673).unwrap();
    for n in 0..fit {
        assert!(harness.store(sized(n, 3, 64_673)).result.is_ok());
    }
    assert_eq!(
        harness.store(sized(fit, 3, 64_673)).result,
        Err(Refusal::RateLimited)
    );
    assert!(
        harness.store(sized(fit + 1, 3, 1_185)).result.is_ok(),
        "within the bytes left"
    );

    // The inserts of the same transaction count.
    let pause = Pause::paused();
    pause.release();
    let hooks = Hooks {
        pause: Some(pause.clone()),
        ..Hooks::default()
    };
    let (_dir, _clock, harness) = limited("s033_t06_batch", limits, hooks);
    let batch = one_transaction(
        &harness,
        &pause,
        (0..=max).map(|n| writer_request(n, 1, DAY)).collect(),
    );
    let refused: Vec<usize> = (0..batch.len())
        .filter(|k| batch[*k].result.is_err())
        .collect();
    assert_eq!(refused, vec![usize::from(max)]);
    assert_eq!(batch[usize::from(max)].result, Err(Refusal::RateLimited));
}

#[test]
fn s033_t07_r07_channel_quota() {
    let limits = ChannelLimits {
        max_blobs: 5,
        ..ChannelLimits::RAISED
    };

    // Five held; the sixth refused, the five still there.
    let (dir, _clock, harness) = limited("s033_t07", limits, Hooks::default());
    for n in 0..5 {
        assert!(harness.store(writer_request(n, 1, DAY)).result.is_ok());
    }
    assert_eq!(
        harness.store(writer_request(5, 1, DAY)).result,
        Err(Refusal::ChannelQuota)
    );
    assert_eq!(rows_of(&dir, 1), 5);

    // Six in one transaction: the sixth refused.
    let pause = Pause::paused();
    pause.release();
    let hooks = Hooks {
        pause: Some(pause.clone()),
        ..Hooks::default()
    };
    let (_dir, _clock, held) = limited("s033_t07_batch", limits, hooks);
    let batch = one_transaction(
        &held,
        &pause,
        (0..6).map(|n| writer_request(n, 1, DAY)).collect(),
    );
    assert!(batch[..5].iter().all(|outcome| outcome.result.is_ok()));
    assert_eq!(batch[5].result, Err(Refusal::ChannelQuota));

    // Two of five expire and the purge removes them: two more fit.
    let (purged_tx, purged) = std::sync::mpsc::channel();
    let hooks = Hooks {
        purge_round: Some(Box::new(move |rows| {
            let _ = purged_tx.send(rows);
        })),
        ..Hooks::default()
    };
    let (dir, clock, harness) = limited("s033_t07_purge", limits, hooks);
    for n in 0..2 {
        assert!(harness.store(writer_request(n, 1, 60)).result.is_ok());
    }
    for n in 2..5 {
        assert!(harness.store(writer_request(n, 1, DAY)).result.is_ok());
    }
    assert_eq!(
        harness.store(writer_request(5, 1, DAY)).result,
        Err(Refusal::ChannelQuota)
    );
    clock.advance(PURGE_INTERVAL_MS + 1);
    let mut removed = 0;
    while removed < 2 {
        removed += purged.recv_timeout(Duration::from_secs(30)).unwrap();
    }
    assert_eq!(rows_of(&dir, 1), 3);
    for n in 6..8 {
        assert!(harness.store(writer_request(n, 1, DAY)).result.is_ok());
    }
    assert_eq!(
        harness.store(writer_request(8, 1, DAY)).result,
        Err(Refusal::ChannelQuota)
    );

    // The same on bytes: 500 bytes held, five blobs of 100.
    let limits = ChannelLimits {
        max_bytes: 500,
        ..ChannelLimits::RAISED
    };
    let (_dir, _clock, harness) = limited("s033_t07_bytes", limits, Hooks::default());
    for n in 0..5 {
        assert!(harness.store(writer_request(n, 1, DAY)).result.is_ok());
    }
    assert_eq!(
        harness.store(writer_request(5, 1, DAY)).result,
        Err(Refusal::ChannelQuota)
    );
}

/// The rows of channel `[channel; 16]` in the database of `dir`.
fn rows_of(dir: &TestDir, channel: u8) -> i64 {
    rusqlite::Connection::open(dir.db())
        .unwrap()
        .query_row(
            "SELECT count(*) FROM messages WHERE channel_id = ?1",
            [&[channel; 16][..]],
            |row| row.get(0),
        )
        .unwrap()
}
