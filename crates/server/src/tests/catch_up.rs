//! Spec 030-ws-protocol R7–R10, R15, R16 over a real socket: the backlog
//! before `ok`, the live pushes held meanwhile, a second subscribe, the
//! queue bound, the disconnect and the internal errors.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
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

use tokio::sync::mpsc;

use crate::connection::QUEUE_FRAMES;
use crate::hub::{Encoded, HOLD_FRAMES, Hub};
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
    // Waits for the hub, not the database: the writer hands a transaction
    // to the hub after it commits.
    let before = server.shared.hub().committed(&channel_id);
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
    let committed = || server.shared.hub().committed(&channel_id);
    for _ in 0..6_000 {
        if committed() == before + u64::from(n) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(committed(), before + u64::from(n), "not stored in 60 s");
}

/// The rows of `channel_id` in the database.
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
async fn s030_t07_r07_since_ahead_reads_as_now() {
    // Rows stamped past the server's wall clock (a clock set back): a
    // `since` past both still reads as now, and they are sent.
    let clock = Arc::new(ManualClock::new(T0));
    let server = start(&clock).await;
    plant(&server, channel(), 5, 1_185, T0 + 10, T0 + 3_600_000);
    let mut client = connect(server.address).await;
    let nonce = hello(&mut client).await;
    send(&mut client, &subscribe_since(&nonce, Some(T0 + 86_400_000))).await;
    let times = backlog(&mut client, channel()).await;
    assert_eq!(times, (T0 + 10..T0 + 15).collect::<Vec<_>>());
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
    plant(&server, channel(), 40, 64_673, T0 - 50, alive);
    plant(&server, other_channel(), 80, 64_673, T0 - 200, alive);
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
    assert_eq!(order.len(), 160);
    // Once both catch up, they take their pages in turn: the second starts
    // before the first is done, and while both have pushes left, no channel
    // sends more than one page (4 pushes) in a row.
    let first_other = order
        .iter()
        .position(|is_first| !is_first)
        .unwrap_or(order.len());
    assert!(
        first_other < 40,
        "the second waited for {first_other} pushes"
    );
    let (mut left_first, mut left_other) = (80usize, 80usize);
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
async fn s030_t07_r07_queue_before_the_next_page() {
    // A live push of a subscribed channel, queued while a backlog page is
    // being written, goes out before the next page. The clause of T07 with a
    // publish (its `ack` and echo) comes with R11 in slice (d).
    let clock = Arc::new(ManualClock::new(T0));
    let server = start(&clock).await;
    plant(&server, channel(), 40, 64_673, T0 - 100, T0 + 3_600_000);
    for round in 0..5u16 {
        let mut client = connect(server.address).await;
        let nonce = hello(&mut client).await;
        send(&mut client, &subscribe_other(&nonce)).await;
        let earlier = backlog(&mut client, other_channel()).await.len();
        assert_eq!(earlier, usize::from(round));
        server.shared.hooks.pause_writes(true);
        send(&mut client, &subscribe_since(&nonce, None)).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        store(&server, other_channel(), round, 1_185);
        tokio::time::sleep(Duration::from_millis(100)).await;
        server.shared.hooks.pause_writes(false);
        let mut before = 0;
        let mut live = false;
        loop {
            match receive(&mut client).await {
                Received::Frame(Frame::Push { channel_id, .. }) if channel_id == channel() => {
                    before += usize::from(!live);
                }
                Received::Frame(Frame::Push { channel_id, .. })
                    if channel_id == other_channel() =>
                {
                    live = true;
                }
                Received::Frame(Frame::Ok { channel_id }) if channel_id == channel() => break,
                other => {
                    let unexpected = Some(other);
                    assert!(unexpected.is_none(), "unexpected {unexpected:?}");
                    break;
                }
            }
        }
        assert!(live, "the live push never came");
        assert!(before <= 4, "{before} backlog pushes before the live push");
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

        // Subscribed once, it gets each new blob once.
        store(&server, channel(), 1_000, 1_185);
        assert!(matches!(
            receive(&mut client).await,
            Received::Frame(Frame::Push { channel_id, .. }) if channel_id == channel()
        ));
        assert!(matches!(
            receive_within(&mut client, 300).await,
            Received::Nothing
        ));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn s030_t08_r08_hold_bound_is_inclusive() {
    // 256 pushes, and 256 blobs of 16 KiB, exactly 4 MiB: both within the
    // bound, nothing ended.
    for (count, bytes) in [(256u16, 1_185usize), (256, 16_384)] {
        let clock = Arc::new(ManualClock::new(T0));
        let server = start(&clock).await;
        plant(&server, channel(), 10, 1_185, T0 - 1_000, T0 + 3_600_000);
        let mut client = connect(server.address).await;
        let nonce = hello(&mut client).await;
        server.shared.hooks.pause_writes(true);
        send(&mut client, &subscribe_since(&nonce, None)).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        store_many(&server, channel(), count, bytes).await;
        server.shared.hooks.pause_writes(false);
        let times = backlog(&mut client, channel()).await;
        assert_eq!(times.len(), 10 + usize::from(count));
    }
}

#[test]
fn s030_t08_r08_hold_bound_ends_the_largest_only() {
    // Two subscriptions catching up on one connection: past the frame bound,
    // the one holding the most pushes ends, alone.
    let mut hub = Hub::default();
    let (sender, mut queue) = mpsc::channel(QUEUE_FRAMES);
    hub.connect(1, sender, Arc::new(AtomicBool::new(false)));
    let large = generation(hub.subscribe(1, channel(), DAY));
    let small = generation(hub.subscribe(1, other_channel(), DAY));
    let outcome = |channel_id: [u8; 16], k: u64| WriteOutcome {
        connection: 9,
        client_ref: [0; 16],
        channel_id,
        result: Ok(Row {
            server_id: [u8::try_from(k % 256).unwrap(); 16],
            received_at: T0 + k,
            blob: vec![1; 1_185],
        }),
    };
    let mut outcomes: Vec<WriteOutcome> = (0..57).map(|k| outcome(other_channel(), k)).collect();
    outcomes.extend((57..257).map(|k| outcome(channel(), k)));
    hub.on_commit(outcomes);
    assert!(
        !hub.is_catching_up(1, &channel(), large),
        "the largest ended"
    );
    assert!(
        hub.is_catching_up(1, &other_channel(), small),
        "the other kept"
    );
    let error = queue.try_recv().map(|bytes| Frame::decode(&bytes));
    assert!(
        matches!(&error, Ok(Ok(Frame::Error { code, channel_id, .. })) if code == "rate_limited" && *channel_id == Some(channel())),
        "{error:?}"
    );
    assert!(queue.try_recv().is_err(), "one error only");
    assert_eq!(hub.subscriptions_of(1), 2, "the ended one still indexed");
    assert_eq!(hub.after_backlog(1, other_channel(), small, None).len(), 57);
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
async fn s030_t09_r09_second_subscribe_mid_backlog() {
    // A second subscribe while the backlog streams, pages ahead of its end:
    // the backlog once, one `ok`, nothing more.
    let clock = Arc::new(ManualClock::new(T0));
    let server = start(&clock).await;
    plant(&server, channel(), 2_000, 1_185, T0 - 3_000, T0 + 3_600_000);
    let mut client = connect(server.address).await;
    let nonce = hello(&mut client).await;
    send(&mut client, &subscribe_since(&nonce, None)).await;
    let first = receive(&mut client).await;
    assert!(
        matches!(first, Received::Frame(Frame::Push { .. })),
        "{first:?}"
    );
    send(&mut client, &subscribe_since(&nonce, None)).await;
    let rest = backlog(&mut client, channel()).await;
    assert_eq!(rest.len(), 1_999);
    assert!(matches!(
        receive_within(&mut client, 300).await,
        Received::Nothing
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn s030_t10_r10_overflow_closes_1013() {
    // A subscribed connection that writes nothing while more than a queue of
    // pushes come: closed with 1013 before anything past the dropped frame.
    let clock = Arc::new(ManualClock::new(T0));
    let server = start(&clock).await;
    let mut client = connect(server.address).await;
    let nonce = hello(&mut client).await;
    send(&mut client, &subscribe_since(&nonce, None)).await;
    assert!(backlog(&mut client, channel()).await.is_empty());
    server.shared.hooks.pause_writes(true);
    store_many(&server, channel(), 300, 1_185).await;
    server.shared.hooks.pause_writes(false);
    let mut times = Vec::new();
    let code = loop {
        match receive(&mut client).await {
            Received::Frame(Frame::Push { received_at, .. }) => times.push(received_at),
            Received::Close(code) => break Some(code),
            other => {
                let unexpected = Some(other);
                assert!(unexpected.is_none(), "unexpected {unexpected:?}");
                break None;
            }
        }
    };
    assert_eq!(code, Some(1013));
    // What came is the start of the stream, with no hole: nothing past the
    // dropped frame was written.
    let first = times.first().copied().unwrap_or(T0);
    let expected: Vec<u64> = (first..).take(times.len()).collect();
    assert_eq!(times, expected);
    assert!(times.len() <= 1, "{} pushes past the drop", times.len());
}

#[test]
fn s030_t10_r10_nothing_queued_past_a_drop() {
    // A queue of one: the `ok` fills it, the next push is dropped, and a
    // push after the slot frees up stays out too.
    let mut hub = Hub::default();
    let (sender, mut queue) = mpsc::channel(1);
    let overflowed = Arc::new(AtomicBool::new(false));
    hub.connect(1, sender, overflowed.clone());
    let subscription = generation(hub.subscribe(1, channel(), DAY));
    assert!(
        hub.after_backlog(1, channel(), subscription, None)
            .is_empty()
    );
    let push = |k: u64| WriteOutcome {
        connection: 9,
        client_ref: [0; 16],
        channel_id: channel(),
        result: Ok(Row {
            server_id: [u8::try_from(k).unwrap(); 16],
            received_at: T0 + k,
            blob: vec![1; 1_185],
        }),
    };
    hub.on_commit(vec![push(0)]);
    assert!(overflowed.load(Ordering::SeqCst));
    assert!(queue.try_recv().is_ok(), "the ok");
    hub.on_commit(vec![push(1)]);
    assert!(queue.try_recv().is_err(), "a push past the dropped one");
}

#[test]
fn s030_t10_r10_an_answer_counts() {
    // An answer to a `subscribe` that finds the queue full overflows it,
    // and nothing is queued after it.
    let mut hub = Hub::default();
    let (sender, mut queue) = mpsc::channel(1);
    let overflowed = Arc::new(AtomicBool::new(false));
    hub.connect(1, sender, overflowed.clone());
    hub.enqueue(1, Encoded::from_static(b"first"));
    assert!(!overflowed.load(Ordering::SeqCst));
    hub.enqueue(1, Encoded::from_static(b"second"));
    assert!(overflowed.load(Ordering::SeqCst));
    assert!(queue.try_recv().is_ok(), "the first");
    hub.enqueue(1, Encoded::from_static(b"third"));
    assert!(queue.try_recv().is_err(), "an answer past the dropped one");
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
    // The clause of T15 with a publish whose connection closes before the
    // commit comes with R11 in slice (d).
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

#[tokio::test(flavor = "multi_thread")]
async fn s030_t08_r08_held_after_a_backlog() {
    // A backlog read to its end, then blobs committed before the `ok`: they
    // come after the backlog, in order, once each.
    let clock = Arc::new(ManualClock::new(T0));
    let server = start(&clock).await;
    plant(&server, channel(), 20, 1_185, T0 - 100, T0 + 3_600_000);
    let mut client = connect(server.address).await;
    let nonce = hello(&mut client).await;
    server.shared.hooks.catch_up_paused.send_replace(true);
    send(&mut client, &subscribe_since(&nonce, None)).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    store_many(&server, channel(), 10, 1_185).await;
    server.shared.hooks.catch_up_paused.send_replace(false);
    let times = backlog(&mut client, channel()).await;
    let expected: Vec<u64> = (T0 - 100..T0 - 80).chain(T0..T0 + 10).collect();
    assert_eq!(times, expected);
}

#[test]
fn s030_t08_r08_the_bound_passed_chooses() {
    // Two channels flooded with small pushes and a third of a few large
    // blobs: the 257th push passes the frame bound, and one of the flooded
    // channels ends, not the third, which holds the most bytes.
    let third = [0x33; 16];
    let mut hub = Hub::default();
    let (sender, _queue) = mpsc::channel(QUEUE_FRAMES);
    hub.connect(1, sender, Arc::new(AtomicBool::new(false)));
    let first = generation(hub.subscribe(1, channel(), DAY));
    let second = generation(hub.subscribe(1, other_channel(), DAY));
    let large = generation(hub.subscribe(1, third, DAY));
    let outcome = |channel_id: [u8; 16], k: u64, bytes: usize| WriteOutcome {
        connection: 9,
        client_ref: [0; 16],
        channel_id,
        result: Ok(Row {
            server_id: [u8::try_from(k % 256).unwrap(); 16],
            received_at: T0 + k,
            blob: vec![1; bytes],
        }),
    };
    let mut outcomes: Vec<WriteOutcome> = (0..17).map(|k| outcome(third, k, 64_673)).collect();
    outcomes.extend((17..137).map(|k| outcome(channel(), k, 1_185)));
    outcomes.extend((137..257).map(|k| outcome(other_channel(), k, 1_185)));
    hub.on_commit(outcomes);
    assert!(hub.is_catching_up(1, &third, large), "the third goes on");
    let ended = [
        !hub.is_catching_up(1, &channel(), first),
        !hub.is_catching_up(1, &other_channel(), second),
    ];
    assert_eq!(ended.iter().filter(|ended| **ended).count(), 1, "{ended:?}");
}

#[test]
fn s030_t08_r08_bytes_passed_first() {
    // One channel of 65 large blobs passes 4 MiB while another holds more
    // pushes but fewer bytes: the one holding the most bytes ends.
    let mut hub = Hub::default();
    let (sender, _queue) = mpsc::channel(QUEUE_FRAMES);
    hub.connect(1, sender, Arc::new(AtomicBool::new(false)));
    let large = generation(hub.subscribe(1, channel(), DAY));
    let many = generation(hub.subscribe(1, other_channel(), DAY));
    let outcome = |channel_id: [u8; 16], k: u64, bytes: usize| WriteOutcome {
        connection: 9,
        client_ref: [0; 16],
        channel_id,
        result: Ok(Row {
            server_id: [u8::try_from(k % 256).unwrap(); 16],
            received_at: T0 + k,
            blob: vec![1; bytes],
        }),
    };
    let mut outcomes: Vec<WriteOutcome> = (0..100)
        .map(|k| outcome(other_channel(), k, 1_185))
        .collect();
    outcomes.extend((100..165).map(|k| outcome(channel(), k, 64_673)));
    hub.on_commit(outcomes);
    assert!(
        !hub.is_catching_up(1, &channel(), large),
        "the most bytes ended"
    );
    assert!(
        hub.is_catching_up(1, &other_channel(), many),
        "the most pushes kept"
    );
}

/// The generation of a new subscription; `None` fails the test.
fn generation(registered: Option<u64>) -> u64 {
    assert!(registered.is_some(), "not a new subscription");
    registered.unwrap_or_default()
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
    assert!(hub.after_backlog(1, channel(), first, None).is_empty());
    assert!(
        hub.is_catching_up(1, &channel(), second),
        "the stale step left the second as it was"
    );
    assert!(hub.after_backlog(1, channel(), second, None).is_empty());
    assert!(
        !hub.is_catching_up(1, &channel(), second),
        "the second is subscribed"
    );
}

/// One stored blob of `bytes` bytes, as the writer hands it to the hub.
fn committed(channel_id: [u8; 16], k: u64, bytes: usize) -> WriteOutcome {
    WriteOutcome {
        connection: 9,
        client_ref: [0; 16],
        channel_id,
        result: Ok(Row {
            server_id: [u8::try_from(k % 256).unwrap(); 16],
            received_at: T0 + k,
            blob: vec![1; bytes],
        }),
    }
}

#[test]
fn s030_t08_r08_floor_after_ok() {
    // The last backlog push reaches the hub after `ok`: dropped; the next
    // one goes to the queue.
    let mut hub = Hub::default();
    let (sender, mut queue) = mpsc::channel(QUEUE_FRAMES);
    hub.connect(1, sender, Arc::new(AtomicBool::new(false)));
    let first = generation(hub.subscribe(1, channel(), DAY));
    assert!(
        hub.after_backlog(1, channel(), first, Some(T0 + 5))
            .is_empty()
    );
    let ok = queue.try_recv().map(|bytes| Frame::decode(&bytes));
    assert!(matches!(ok, Ok(Ok(Frame::Ok { .. }))), "{ok:?}");
    hub.on_commit(vec![
        committed(channel(), 5, 1_185),
        committed(channel(), 6, 1_185),
    ]);
    let push = queue.try_recv().map(|bytes| Frame::decode(&bytes));
    assert!(
        matches!(push, Ok(Ok(Frame::Push { received_at, .. })) if received_at == T0 + 6),
        "{push:?}"
    );
    assert!(queue.try_recv().is_err(), "the last backlog push twice");
}

#[test]
fn s030_t08_r08_held_in_chunks() {
    // 40 held pushes of 16 KiB: chunks of at most 256 KiB, then `ok`.
    let mut hub = Hub::default();
    let (sender, mut queue) = mpsc::channel(QUEUE_FRAMES);
    hub.connect(1, sender, Arc::new(AtomicBool::new(false)));
    let first = generation(hub.subscribe(1, channel(), DAY));
    hub.on_commit((0..40).map(|k| committed(channel(), k, 16_384)).collect());
    for expected in [16, 16, 8] {
        assert_eq!(hub.after_backlog(1, channel(), first, None).len(), expected);
        assert!(hub.is_catching_up(1, &channel(), first));
        assert!(queue.try_recv().is_err(), "`ok` before the held pushes");
    }
    assert!(hub.after_backlog(1, channel(), first, None).is_empty());
    assert!(!hub.is_catching_up(1, &channel(), first));
    assert!(queue.try_recv().is_ok(), "no `ok`");
}

#[test]
fn s030_t08_r08_handed_out_bytes_leave_the_bound() {
    // 200 held pushes of 16 KiB, one chunk handed out, 60 more: 244 held,
    // 3 997 696 bytes, within the bound.
    let mut hub = Hub::default();
    let (sender, _queue) = mpsc::channel(QUEUE_FRAMES);
    hub.connect(1, sender, Arc::new(AtomicBool::new(false)));
    let first = generation(hub.subscribe(1, channel(), DAY));
    hub.on_commit((0..200).map(|k| committed(channel(), k, 16_384)).collect());
    assert_eq!(hub.after_backlog(1, channel(), first, None).len(), 16);
    hub.on_commit(
        (200..260)
            .map(|k| committed(channel(), k, 16_384))
            .collect(),
    );
    assert!(
        hub.is_catching_up(1, &channel(), first),
        "ended within the bound"
    );
}
