//! Spec 033-rate-limit-quotas over a real socket, with a `ManualClock`: the
//! limits of one connection.

use std::sync::Arc;
use std::time::Duration;

use futures_util::StreamExt;
use tokio::net::TcpSocket;
use tokio_tungstenite::tungstenite::Message;

use privatechat_core::testing::subscribe_credential;
use privatechat_core::{Frame, relay};

use super::catch_up::{T0, backlog, plant, store_many, subscribe_since};
use super::publish::{blob_of, client_ref, fill_writer, hold_writer, publish, refused};
use super::ws::{
    Client, DAY, HOST, Received, channel, connect, hello, receive, receive_within, send, start,
    subscribe,
};
use crate::clock::ManualClock;
use crate::limits::{
    CONN_PUBLISH_MAX, CONN_PUBLISH_WINDOW_MS, MAX_SUBSCRIPTIONS, PING_INTERVAL_MS, PONG_TIMEOUT_MS,
    SEND_QUEUE_BYTES, SEND_QUEUE_FRAMES, SUBSCRIBE_GAP_MS, WRITE_TIMEOUT_MS, pong_overdue,
};
use crate::store::writer::Row;

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

    // A ping every 30 000 ms; answered, the connection goes on.
    let clock = Arc::new(ManualClock::new(T0));
    let (_server, mut client) = subscriber(&clock).await;
    for _ in 0..2 {
        clock.advance_mono(PING_INTERVAL_MS);
        let ping = next_message(&mut client).await;
        assert!(matches!(ping, Some(Message::Ping(_))), "{ping:?}");
        // Reading again sends the pong.
        assert!(matches!(
            receive_within(&mut client, 300).await,
            Received::Nothing
        ));
    }

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

    // A client reading steadily but slowly behind a large backlog, its pongs
    // late behind it: the writes go on, and it is not closed.
    let clock = Arc::new(ManualClock::new(T0));
    let server = start(&clock).await;
    plant(&server, channel(), 40, 64_673, T0 - 300, T0 + 3_600_000);
    let socket = TcpSocket::new_v4().unwrap();
    socket.set_recv_buffer_size(65_536).unwrap();
    let stream = socket.connect(server.address).await.unwrap();
    let stream = tokio_tungstenite::MaybeTlsStream::Plain(stream);
    let (mut client, _) =
        tokio_tungstenite::client_async(format!("ws://{}/", server.address), stream)
            .await
            .unwrap();
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

    // A client that stops reading with a small receive buffer: a write stuck
    // mid-frame, part of it taken; the TCP connection dropped with no close
    // frame `WRITE_TIMEOUT_MS` of the monotonic clock after that write began.
    let clock = Arc::new(ManualClock::new(T0));
    let server = start(&clock).await;
    plant(&server, channel(), 40, 64_673, T0 - 300, T0 + 3_600_000);
    let socket = TcpSocket::new_v4().unwrap();
    socket.set_recv_buffer_size(65_536).unwrap();
    let stream = socket.connect(server.address).await.unwrap();
    let stream = tokio_tungstenite::MaybeTlsStream::Plain(stream);
    let (mut client, _) =
        tokio_tungstenite::client_async(format!("ws://{}/", server.address), stream)
            .await
            .unwrap();
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
