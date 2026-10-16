//! Spec 030-ws-protocol R7–R10, R15, R16 over a real socket: the backlog
//! before `ok`, the live pushes held meanwhile, a second subscribe, the
//! queue bound, the disconnect and the internal errors.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use futures_util::StreamExt;
use privatechat_core::testing::subscribe_credential;
use privatechat_core::{Frame, relay};
use rusqlite::Connection;
use tokio::net::TcpSocket;
use tokio_tungstenite::tungstenite::Message;

use super::ws::{
    Client, DAY, HOST, Received, Server, channel, connect, hello, receive, receive_within, send,
    start, subscribe,
};
use crate::clock::ManualClock;
use std::sync::atomic::AtomicBool;

use tokio::sync::mpsc;

use crate::connection::QUEUE_FRAMES;
use crate::hub::{HOLD_FRAMES, Hub, Next, Registered};
use crate::store::writer::{Row, WriteOutcome, WriteRequest};

/// A wall clock of this century, which every planted blob outlives.
const T0: u64 = 1_800_000_000_000;

/// Inserts `n` blobs of `bytes` bytes into `channel_id`, by hand, with
/// `received_at` from `first` on and the given `expires_at`.
fn plant(server: &Server, channel_id: [u8; 16], n: u64, bytes: usize, first: u64, expires_at: u64) {
    let db = server.shared.db_path();
    let mut connection = Connection::open(db).unwrap();
    let transaction = connection.transaction().unwrap();
    for k in 0..n {
        let mut server_id = [0; 16];
        server_id[..8].copy_from_slice(&(first + k).to_be_bytes());
        server_id[8] = channel_id[0];
        transaction
            .execute(
                "INSERT INTO messages(server_id, channel_id, received_at, expires_at, blob) VALUES (?1, ?2, ?3, ?4, ?5)",
                (
                    &server_id[..],
                    &channel_id[..],
                    i64::try_from(first + k).unwrap(),
                    i64::try_from(expires_at).unwrap(),
                    vec![channel_id[0]; bytes],
                ),
            )
            .unwrap();
    }
    transaction.commit().unwrap();
}

/// A blob stored through the writer, as a `publish` of another connection.
fn store(server: &Server, channel_id: [u8; 16], n: u16, bytes: usize) {
    let mut client_ref = [0; 16];
    client_ref[..2].copy_from_slice(&n.to_be_bytes());
    server
        .shared
        .writer
        .submit(WriteRequest {
            connection: u64::MAX,
            client_ref,
            channel_id,
            ttl_seconds: DAY,
            blob: vec![channel_id[0]; bytes],
        })
        .unwrap();
}

/// `n` blobs of `bytes` bytes stored through the writer, in order, and
/// waited for: their `received_at` run from the clock's wall reading on.
async fn store_many(server: &Server, channel_id: [u8; 16], n: u16, bytes: usize) {
    let before = count(server, channel_id);
    for k in 0..n {
        loop {
            let mut client_ref = [0; 16];
            client_ref[..2].copy_from_slice(&k.to_be_bytes());
            let request = WriteRequest {
                connection: u64::MAX,
                client_ref,
                channel_id,
                ttl_seconds: DAY,
                blob: vec![channel_id[0]; bytes],
            };
            if server.shared.writer.submit(request).is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }
    for _ in 0..6_000 {
        if count(server, channel_id) == before + u64::from(n) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        count(server, channel_id),
        before + u64::from(n),
        "not stored in 60 s"
    );
}

fn count(server: &Server, channel_id: [u8; 16]) -> u64 {
    let connection = Connection::open(server.shared.db_path()).unwrap();
    let rows: i64 = connection
        .query_row(
            "SELECT count(*) FROM messages WHERE channel_id = ?1",
            [&channel_id[..]],
            |row| row.get(0),
        )
        .unwrap();
    u64::try_from(rows).unwrap()
}

/// A second channel, of another key.
const K_OTHER: [u8; 32] = [0x41; 32];

fn subscribe_other(nonce: &[u8; 32]) -> Frame {
    let (pk_ch, sig) = subscribe_credential(K_OTHER, DAY, nonce, HOST).unwrap();
    Frame::Subscribe {
        pk_ch,
        ttl_seconds: DAY,
        sig,
        since: Some(0),
    }
}

fn other_channel() -> [u8; 16] {
    let (pk_ch, _) = subscribe_credential(K_OTHER, DAY, &[0; 32], HOST).unwrap();
    relay::channel_id(&pk_ch, DAY).unwrap()
}

fn subscribe_since(nonce: &[u8; 32], since: Option<u64>) -> Frame {
    match subscribe(nonce, HOST) {
        Frame::Subscribe {
            pk_ch,
            ttl_seconds,
            sig,
            ..
        } => Frame::Subscribe {
            pk_ch,
            ttl_seconds,
            sig,
            since,
        },
        other => other,
    }
}

/// The `received_at` of every push the client receives until the `ok` of
/// `channel_id`, which must come; any other frame fails.
async fn backlog(client: &mut Client, channel_id: [u8; 16]) -> Vec<u64> {
    let mut times = Vec::new();
    loop {
        match receive(client).await {
            Received::Frame(Frame::Push {
                channel_id: of,
                received_at,
                ..
            }) if of == channel_id => times.push(received_at),
            Received::Frame(Frame::Ok { channel_id: of }) if of == channel_id => return times,
            other => {
                let unexpected = Some(other);
                assert!(
                    unexpected.is_none(),
                    "unexpected {unexpected:?} after {} pushes",
                    times.len()
                );
                return times;
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn s030_t07_r07_backlog_then_ok() {
    let clock = Arc::new(ManualClock::new(T0));
    let server = start(&clock).await;
    // With the clock stopped, the writer gives them T0, T0 + 1, ...
    store_many(&server, channel(), 1_200, 1_185).await;
    // One more blob, with a TTL the clock then passes: never sent.
    let short = WriteRequest {
        connection: u64::MAX,
        client_ref: [9; 16],
        channel_id: channel(),
        ttl_seconds: 60,
        blob: vec![1; 1_185],
    };
    server.shared.writer.submit(short).unwrap();
    for _ in 0..500 {
        if count(&server, channel()) == 1_201 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    clock.advance(60_001);

    let mut client = connect(server.address).await;
    let nonce = hello(&mut client).await;
    send(&mut client, &subscribe_since(&nonce, Some(T0 + 100))).await;
    let times = backlog(&mut client, channel()).await;
    assert_eq!(times, (T0 + 100..T0 + 1_200).collect::<Vec<_>>());

    let mut client = connect(server.address).await;
    let nonce = hello(&mut client).await;
    send(&mut client, &subscribe_since(&nonce, None)).await;
    assert_eq!(backlog(&mut client, channel()).await.len(), 1_200);

    // `since` a day ahead reads as now: nothing, then `ok`.
    let mut client = connect(server.address).await;
    let nonce = hello(&mut client).await;
    send(&mut client, &subscribe_since(&nonce, Some(T0 + 86_400_000))).await;
    assert!(backlog(&mut client, channel()).await.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn s030_t07_r07_pages_and_turns() {
    let clock = Arc::new(ManualClock::new(T0));
    let server = start(&clock).await;
    let alive = T0 + 3_600_000;
    // Forty blobs of the largest size: ten pages of four, then the empty read.
    plant(&server, channel(), 40, 64_673, T0 - 100, alive);
    let mut client = connect(server.address).await;
    let nonce = hello(&mut client).await;
    send(&mut client, &subscribe_since(&nonce, None)).await;
    assert_eq!(backlog(&mut client, channel()).await.len(), 40);
    assert_eq!(server.shared.hooks.reads(), 11);

    // Two subscriptions catching up at once take their pages in turn.
    plant(&server, other_channel(), 40, 64_673, T0 - 200, alive);
    let mut client = connect(server.address).await;
    let nonce = hello(&mut client).await;
    send(&mut client, &subscribe_since(&nonce, None)).await;
    send(&mut client, &subscribe_other(&nonce)).await;
    let mut order = Vec::new();
    let mut oks = 0;
    while oks < 2 {
        match receive(&mut client).await {
            Received::Frame(Frame::Push { channel_id, .. }) => order.push(channel_id == channel()),
            Received::Frame(Frame::Ok { .. }) => oks += 1,
            other => {
                let unexpected = Some(other);
                assert!(unexpected.is_none(), "unexpected {unexpected:?}");
                break;
            }
        }
    }
    assert_eq!(order.len(), 80);
    // Once both catch up, they take their pages in turn: while both have
    // pushes left, no channel sends more than one page (4 pushes) in a row.
    let first_other = order
        .iter()
        .position(|is_first| !is_first)
        .unwrap_or(order.len());
    let (mut left_first, mut left_other) = (40usize, 40usize);
    left_first -= first_other;
    let mut run = 0;
    let mut previous = None;
    for is_first in &order[first_other..] {
        if left_first == 0 || left_other == 0 {
            break;
        }
        run = if previous == Some(*is_first) {
            run + 1
        } else {
            1
        };
        previous = Some(*is_first);
        assert!(run <= 4, "a run of {run} pushes of one channel");
        if *is_first {
            left_first -= 1;
        } else {
            left_other -= 1;
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn s030_t07_r07_one_page_at_a_time() {
    let clock = Arc::new(ManualClock::new(T0));
    let server = start(&clock).await;
    plant(&server, channel(), 300, 64_673, T0 - 300, T0 + 3_600_000);
    // A client with a small receive buffer that does not read.
    let socket = TcpSocket::new_v4().unwrap();
    socket.set_recv_buffer_size(65_536).unwrap();
    let stream = socket.connect(server.address).await.unwrap();
    let (mut client, _) =
        tokio_tungstenite::client_async(format!("ws://{}/", server.address), stream)
            .await
            .unwrap();
    let nonce = match client.next().await {
        Some(Ok(Message::Binary(bytes))) => match Frame::decode(&bytes).unwrap() {
            Frame::Hello { server_nonce, .. } => server_nonce,
            _ => [0; 32],
        },
        _ => [0; 32],
    };
    let frame = subscribe_since(&nonce, None).encode().unwrap();
    futures_util::SinkExt::send(&mut client, Message::Binary(frame.into()))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    let reads = server.shared.hooks.reads();
    assert!(
        reads < 75,
        "{reads} pages read for a client that reads nothing"
    );
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(server.shared.hooks.reads(), reads);
}

#[tokio::test(flavor = "multi_thread")]
async fn s030_t08_r08_held_live_pushes() {
    let clock = Arc::new(ManualClock::new(T0));
    let server = start(&clock).await;
    plant(&server, channel(), 100, 1_185, T0 - 1_000, T0 + 3_600_000);
    let mut client = connect(server.address).await;
    let nonce = hello(&mut client).await;
    // The catch-up is slow: its writes wait while blobs are committed.
    server.shared.hooks.pause_writes(true);
    send(&mut client, &subscribe_since(&nonce, None)).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    for n in 0..10 {
        store(&server, channel(), n, 1_185);
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    server.shared.hooks.pause_writes(false);
    let times = backlog(&mut client, channel()).await;
    assert_eq!(times.len(), 110);
    assert!(
        times.windows(2).all(|pair| pair[0] < pair[1]),
        "out of order or twice"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn s030_t08_r08_hold_bound_ends_one_subscription() {
    for (count, bytes) in [(257u16, 1_185usize), (65, 64_673)] {
        let clock = Arc::new(ManualClock::new(T0));
        let server = start(&clock).await;
        let mut client = connect(server.address).await;
        let nonce = hello(&mut client).await;
        // A second channel, subscribed first, keeps receiving.
        send(&mut client, &subscribe_other(&nonce)).await;
        assert!(backlog(&mut client, other_channel()).await.is_empty());
        plant(&server, channel(), 10, 1_185, T0 - 1_000, T0 + 3_600_000);
        server.shared.hooks.pause_writes(true);
        send(&mut client, &subscribe_since(&nonce, None)).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        for n in 0..count {
            store(&server, channel(), n, bytes);
        }
        store(&server, other_channel(), 999, 1_185);
        tokio::time::sleep(Duration::from_millis(300)).await;
        server.shared.hooks.pause_writes(false);

        let mut ended = false;
        let mut other_push = false;
        let mut after_end = 0;
        while let Received::Frame(frame) = receive_within(&mut client, 500).await {
            match frame {
                Frame::Error {
                    code, channel_id, ..
                } if code == "rate_limited" && channel_id == Some(channel()) => ended = true,
                Frame::Push { channel_id, .. } | Frame::Ok { channel_id }
                    if channel_id == channel() =>
                {
                    after_end += usize::from(ended);
                }
                Frame::Push { channel_id, .. } if channel_id == other_channel() => {
                    other_push = true
                }
                other => {
                    let unexpected = Some(other);
                    assert!(unexpected.is_none(), "unexpected {unexpected:?}");
                }
            }
        }
        assert!(ended, "{count} held pushes did not end the subscription");
        assert_eq!(after_end, 0, "frames of the ended channel after its error");
        assert!(other_push, "the other channel stopped");

        // A new subscribe of the ended channel gets a fresh backlog.
        send(&mut client, &subscribe_since(&nonce, None)).await;
        let times = backlog(&mut client, channel()).await;
        assert_eq!(times.len(), 10 + usize::from(count));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn s030_t09_r09_second_subscribe_ignored() {
    let clock = Arc::new(ManualClock::new(T0));
    let server = start(&clock).await;
    plant(&server, channel(), 5, 1_185, T0 - 100, T0 + 3_600_000);
    let mut client = connect(server.address).await;
    let nonce = hello(&mut client).await;
    send(&mut client, &subscribe_since(&nonce, None)).await;
    send(&mut client, &subscribe_since(&nonce, None)).await;
    assert_eq!(backlog(&mut client, channel()).await.len(), 5);
    assert!(matches!(
        receive_within(&mut client, 300).await,
        Received::Nothing
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn s030_t10_r10_backlog_outside_queue() {
    let clock = Arc::new(ManualClock::new(T0));
    let server = start(&clock).await;
    store_many(&server, channel(), 1_000, 64_673).await;
    let mut client = connect(server.address).await;
    let nonce = hello(&mut client).await;
    send(&mut client, &subscribe_since(&nonce, None)).await;
    let mut pushes = 0;
    loop {
        match receive(&mut client).await {
            Received::Frame(Frame::Push { .. }) => {
                pushes += 1;
                if pushes % 50 == 0 {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            }
            Received::Frame(Frame::Ok { .. }) => break,
            other => {
                let unexpected = Some(other);
                assert!(
                    unexpected.is_none(),
                    "unexpected {unexpected:?} after {pushes}"
                );
                break;
            }
        }
    }
    assert_eq!(pushes, 1_000);
}

#[tokio::test(flavor = "multi_thread")]
async fn s030_t15_r15_disconnect_forgets() {
    let clock = Arc::new(ManualClock::new(T0));
    let server = start(&clock).await;
    let mut client = connect(server.address).await;
    let nonce = hello(&mut client).await;
    send(&mut client, &subscribe_since(&nonce, None)).await;
    assert!(backlog(&mut client, channel()).await.is_empty());
    assert!(server.shared.hub().subscriptions_of(0) > 0);
    drop(client);
    let mut forgotten = false;
    for _ in 0..100 {
        if server.shared.hub().subscriptions_of(0) == 0 {
            forgotten = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(forgotten);
}

#[tokio::test(flavor = "multi_thread")]
async fn s030_t16_r16_internal_error_closes() {
    let clock = Arc::new(ManualClock::new(T0));
    let server = start(&clock).await;
    plant(&server, channel(), 5, 1_185, T0 - 100, T0 + 3_600_000);
    // A backlog read that fails.
    server.shared.hooks.fail_reads.store(true, Ordering::SeqCst);
    let mut client = connect(server.address).await;
    let nonce = hello(&mut client).await;
    send(&mut client, &subscribe_since(&nonce, None)).await;
    assert!(matches!(receive(&mut client).await, Received::Close(1011)));
    server
        .shared
        .hooks
        .fail_reads
        .store(false, Ordering::SeqCst);
    // A `relay` call that fails: closed, and no `error` frame.
    server.shared.hooks.fail_relay.store(true, Ordering::SeqCst);
    let mut client = connect(server.address).await;
    let nonce = hello(&mut client).await;
    send(&mut client, &subscribe_since(&nonce, None)).await;
    assert!(matches!(receive(&mut client).await, Received::Close(1011)));
}

#[tokio::test(flavor = "multi_thread")]
async fn s030_t08_r08_held_before_ok() {
    let clock = Arc::new(ManualClock::new(T0));
    let server = start(&clock).await;
    let mut client = connect(server.address).await;
    let nonce = hello(&mut client).await;
    // The backlog is empty and read; the catch-up waits before its `ok`.
    server.shared.hooks.catch_up_paused.send_replace(true);
    send(&mut client, &subscribe_since(&nonce, None)).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    store_many(&server, channel(), 10, 1_185).await;
    server.shared.hooks.catch_up_paused.send_replace(false);
    // All of them, before `ok`, the backlog having been empty.
    let times = backlog(&mut client, channel()).await;
    assert_eq!(times, (T0..T0 + 10).collect::<Vec<_>>());

    // After `ok`, live pushes beyond the hold bound end nothing.
    for round in 0..2u64 {
        store_many(&server, channel(), 200, 1_185).await;
        for k in 0..200 {
            let received = receive(&mut client).await;
            let expected = T0 + 10 + round * 200 + k;
            assert!(
                matches!(&received, Received::Frame(Frame::Push { received_at, .. }) if *received_at == expected),
                "{received:?}"
            );
        }
    }
}

/// The generation of a new subscription; `Already` fails the test.
fn generation(registered: Registered) -> u64 {
    let generation = match registered {
        Registered::CatchingUp(generation) => Some(generation),
        Registered::Already => None,
    };
    assert!(generation.is_some(), "not a new subscription");
    generation.unwrap_or_default()
}

#[test]
fn s030_t08_r08_a_stale_step_does_not_act() {
    // A subscription ended by R8 and subscribed again: a step of the first
    // still waiting its turn finds the generation changed, and the second
    // streams its own backlog.
    let mut hub = Hub::default();
    let (sender, _queue) = mpsc::channel(QUEUE_FRAMES);
    hub.connect(1, sender, Arc::new(AtomicBool::new(false)));
    let first = generation(hub.subscribe(1, channel(), DAY));
    let flood: Vec<WriteOutcome> = (0..=u64::try_from(HOLD_FRAMES).unwrap())
        .map(|k| WriteOutcome {
            connection: 9,
            client_ref: [0; 16],
            channel_id: channel(),
            result: Ok(Row {
                server_id: [u8::try_from(k % 256).unwrap(); 16],
                received_at: T0 + k,
                blob: vec![1; 1_185],
            }),
        })
        .collect();
    hub.on_commit(flood);
    assert!(
        !hub.is_catching_up(1, &channel(), first),
        "ended by the hold bound"
    );
    let second = generation(hub.subscribe(1, channel(), DAY));
    assert_ne!(first, second);
    assert!(!hub.is_catching_up(1, &channel(), first));
    assert!(matches!(
        hub.after_backlog(1, channel(), first, None),
        Next::Gone
    ));
    assert!(hub.is_catching_up(1, &channel(), second));
    assert!(matches!(
        hub.after_backlog(1, channel(), second, None),
        Next::Subscribed
    ));
}
