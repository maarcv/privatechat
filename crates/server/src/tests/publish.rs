//! Spec 030-ws-protocol R11–R14 over a real socket: the refusals of a
//! `publish`, its `ack` and its fan-out, the frames the server sends, and
//! their bytes against `028.json`; and the clauses of T07 and T15 that need a
//! `publish`.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use privatechat_core::testing::subscribe_credential;
use privatechat_core::{Frame, relay};

use super::catch_up::{T0, backlog, count, other_channel, plant, subscribe_other, subscribe_since};
use super::ws::{
    Client, DAY, HOST, Received, Server, channel, connect, hello, receive, receive_within, send,
    start, subscribe,
};
use crate::auth;
use crate::clock::ManualClock;
use crate::frames::{self, ErrorCode};
use crate::store::writer::{Row, WriteRequest};

/// A third channel, of a third key.
const K_THIRD: [u8; 32] = [0x42; 32];

fn third_channel() -> [u8; 16] {
    let (pk_ch, _) = subscribe_credential(K_THIRD, DAY, &[0; 32], HOST).unwrap();
    relay::channel_id(&pk_ch, DAY).unwrap()
}

fn subscribe_third(nonce: &[u8; 32]) -> Frame {
    let (pk_ch, sig) = subscribe_credential(K_THIRD, DAY, nonce, HOST).unwrap();
    Frame::Subscribe {
        pk_ch,
        ttl_seconds: DAY,
        sig,
        since: None,
    }
}

fn client_ref(n: u16) -> [u8; 16] {
    let mut client_ref = [0; 16];
    client_ref[..2].copy_from_slice(&n.to_be_bytes());
    client_ref
}

/// A blob of the smallest size that `check_blob` takes for `channel_id`.
fn blob_of(channel_id: [u8; 16], fill: u8) -> Vec<u8> {
    let mut blob = vec![fill; 1_185];
    blob[0] = 1;
    blob[1..17].copy_from_slice(&channel_id);
    blob
}

fn publish(channel_id: [u8; 16], n: u16, blob: Vec<u8>) -> Frame {
    Frame::Publish {
        channel_id,
        client_ref: client_ref(n),
        blob,
    }
}

/// A client subscribed to the test channel, its empty backlog read.
async fn subscribed(server: &Server) -> Client {
    let mut client = connect(server.address).await;
    let nonce = hello(&mut client).await;
    send(&mut client, &subscribe_since(&nonce, None)).await;
    assert!(backlog(&mut client, channel()).await.is_empty());
    client
}

/// The next `n` frames of `client`; anything else fails.
async fn frames(client: &mut Client, n: usize) -> Vec<Frame> {
    let mut frames = Vec::with_capacity(n);
    while frames.len() < n {
        match receive(client).await {
            Received::Frame(frame) => frames.push(frame),
            other => {
                let unexpected = Some(other);
                assert!(
                    unexpected.is_none(),
                    "unexpected {unexpected:?} after {} frames",
                    frames.len()
                );
                break;
            }
        }
    }
    frames
}

/// The next frame of `client` is the `error` `code` naming both fields.
async fn refused(client: &mut Client, code: &str, channel_id: [u8; 16], n: u16) {
    let received = receive(client).await;
    assert!(
        matches!(&received, Received::Frame(Frame::Error { code: got, channel_id: Some(of), client_ref: Some(by), .. })
            if got == code && *of == channel_id && *by == client_ref(n)),
        "{received:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn s030_t11_r11_publish_refusals() {
    let clock = Arc::new(ManualClock::new(T0));
    let server = start(&clock).await;
    let mut client = subscribed(&server).await;
    let before = count(&server, channel());

    send(
        &mut client,
        &publish(other_channel(), 1, blob_of(other_channel(), 1)),
    )
    .await;
    refused(&mut client, "not_subscribed", other_channel(), 1).await;

    let mut short = blob_of(channel(), 2);
    short.pop();
    let mut version_2 = blob_of(channel(), 3);
    version_2[0] = 2;
    for (n, blob) in [(2, short), (3, version_2), (4, blob_of(other_channel(), 4))] {
        send(&mut client, &publish(channel(), n, blob)).await;
        refused(&mut client, "bad_blob", channel(), n).await;
    }

    // The writer stopped and its queue full.
    let pause = server.shared.hooks.writer_pause.clone();
    tokio::task::spawn_blocking(move || pause.hold())
        .await
        .unwrap();
    loop {
        let filler = WriteRequest {
            connection: u64::MAX,
            client_ref: [0; 16],
            channel_id: other_channel(),
            ttl_seconds: DAY,
            blob: vec![1; 1_185],
        };
        if server.shared.writer.submit(filler).is_err() {
            break;
        }
    }
    send(&mut client, &publish(channel(), 5, blob_of(channel(), 5))).await;
    refused(&mut client, "rate_limited", channel(), 5).await;
    server.shared.hooks.writer_pause.release();

    assert!(matches!(
        receive_within(&mut client, 300).await,
        Received::Nothing
    ));
    assert_eq!(count(&server, channel()), before, "a refused blob stored");
}

#[tokio::test(flavor = "multi_thread")]
async fn s030_t12_r12_ack_and_fan_out() {
    // Three connections on one channel: the `ack`, then the push to all
    // three, the publisher included.
    let clock = Arc::new(ManualClock::new(T0));
    let server = start(&clock).await;
    let mut clients = Vec::new();
    for _ in 0..3 {
        clients.push(subscribed(&server).await);
    }
    send(
        &mut clients[0],
        &publish(channel(), 1, blob_of(channel(), 1)),
    )
    .await;
    let mut mine = frames(&mut clients[0], 2).await.into_iter();
    let ack = mine.next();
    let (server_id, received_at) = match &ack {
        Some(Frame::Ack {
            client_ref: acked,
            server_id,
            received_at,
        }) if *acked == client_ref(1) => (*server_id, *received_at),
        _ => ([0; 16], 0),
    };
    assert!(received_at != 0, "no ack first: {ack:?}");
    let mut pushes = vec![mine.next()];
    for client in &mut clients[1..] {
        pushes.extend(frames(client, 1).await.into_iter().map(Some));
    }
    assert_eq!(pushes.len(), 3);
    for pushed in pushes {
        assert!(
            matches!(&pushed, Some(Frame::Push { server_id: id, received_at: at, blob, .. })
                if *id == server_id && *at == received_at && *blob == blob_of(channel(), 1)),
            "{pushed:?}"
        );
    }

    // Four publishers interleaving 25 blobs each: one order everywhere, each
    // `ack` in the order sent and before its own echo.
    let server = start(&clock).await;
    let mut publishers = Vec::new();
    for _ in 0..4 {
        publishers.push(subscribed(&server).await);
    }
    for k in 0..25u16 {
        for (i, publisher) in (0u16..).zip(publishers.iter_mut()) {
            let n = i * 100 + k;
            send(
                publisher,
                &publish(channel(), n, blob_of(channel(), u8::try_from(k).unwrap())),
            )
            .await;
        }
    }
    let mut orders = Vec::new();
    for (i, publisher) in (0u16..).zip(publishers.iter_mut()) {
        let seen = frames(publisher, 125).await;
        let mut acks = Vec::new();
        let mut order = Vec::new();
        for frame in &seen {
            match frame {
                Frame::Ack {
                    client_ref,
                    server_id,
                    ..
                } => acks.push((*client_ref, *server_id)),
                Frame::Push {
                    server_id,
                    received_at,
                    ..
                } => {
                    // An echo of this publisher's own blob comes after its ack.
                    let mine = seen.iter().any(|other| {
                        matches!(other, Frame::Ack { server_id: acked, .. } if acked == server_id)
                    });
                    let acked = acks.iter().any(|(_, acked)| acked == server_id);
                    assert!(!mine || acked, "an echo before its ack");
                    order.push(*received_at);
                }
                other => {
                    let unexpected = Some(other);
                    assert!(unexpected.is_none(), "unexpected {unexpected:?}");
                }
            }
        }
        let sent: Vec<[u8; 16]> = (0..25).map(|k| client_ref(i * 100 + k)).collect();
        let acked: Vec<[u8; 16]> = acks.iter().map(|(client_ref, _)| *client_ref).collect();
        assert_eq!(acked, sent, "acks out of the order sent");
        assert!(order.windows(2).all(|pair| pair[0] < pair[1]));
        orders.push(order);
    }
    assert!(orders.windows(2).all(|pair| pair[0] == pair[1]));

    // One connection publishing 30 blobs: 30 `ack`s in order, each before
    // its own echo.
    let server = start(&clock).await;
    let mut client = subscribed(&server).await;
    for n in 0..30 {
        send(&mut client, &publish(channel(), n, blob_of(channel(), 7))).await;
    }
    let seen = frames(&mut client, 60).await;
    let mut acked = Vec::new();
    for frame in &seen {
        match frame {
            Frame::Ack {
                client_ref,
                server_id,
                ..
            } => acked.push((*client_ref, *server_id)),
            Frame::Push { server_id, .. } => {
                assert!(
                    acked.iter().any(|(_, id)| id == server_id),
                    "an echo before its ack"
                );
            }
            other => {
                let unexpected = Some(other);
                assert!(unexpected.is_none(), "unexpected {unexpected:?}");
            }
        }
    }
    let refs: Vec<[u8; 16]> = acked.iter().map(|(client_ref, _)| *client_ref).collect();
    assert_eq!(refs, (0..30).map(client_ref).collect::<Vec<_>>());

    // A refusal of the writer, in one batch with a publish before and after
    // it: its `error`, with both fields, between their `ack`s.
    let pause = server.shared.hooks.writer_pause.clone();
    tokio::task::spawn_blocking(move || pause.hold())
        .await
        .unwrap();
    for n in 100..103 {
        send(&mut client, &publish(channel(), n, blob_of(channel(), 8))).await;
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    server.shared.hooks.repeat_after.store(1, Ordering::SeqCst);
    server.shared.hooks.writer_pause.release();
    let seen = frames(&mut client, 5).await;
    assert!(
        matches!(
            &seen[..],
            [
                Frame::Ack { client_ref: first, .. },
                Frame::Push { .. },
                Frame::Error { code, channel_id: Some(of), client_ref: Some(refused), .. },
                Frame::Ack { client_ref: last, .. },
                Frame::Push { .. },
            ] if *first == client_ref(100)
                && code == "server_full"
                && *of == channel()
                && *refused == client_ref(101)
                && *last == client_ref(102)
        ),
        "{seen:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn s030_t13_r13_frames_sent() {
    // Every frame type the server sends, each through `receive`, which holds
    // every `error` of every test of this crate to R13.
    let clock = Arc::new(ManualClock::new(T0));
    let server = start(&clock).await;
    let mut client = connect(server.address).await;
    let nonce = hello(&mut client).await;
    send(&mut client, &subscribe(&[9; 32], HOST)).await;
    refused_subscribe(&mut client).await;
    send(&mut client, &subscribe_since(&nonce, None)).await;
    assert!(backlog(&mut client, channel()).await.is_empty());
    send(&mut client, &publish(channel(), 1, blob_of(channel(), 1))).await;
    let seen = frames(&mut client, 2).await;
    assert!(matches!(&seen[..], [Frame::Ack { .. }, Frame::Push { .. }]));
    send(
        &mut client,
        &publish(other_channel(), 2, blob_of(other_channel(), 2)),
    )
    .await;
    refused(&mut client, "not_subscribed", other_channel(), 2).await;
    send(&mut client, &publish(channel(), 3, vec![1; 1_185])).await;
    refused(&mut client, "bad_blob", channel(), 3).await;
    // No code is `unsupported_version`.
    assert!(
        super::ws::ERRORS
            .iter()
            .all(|(_, name, _)| *name != "unsupported_version")
    );
}

/// A forged `subscribe` answered with `bad_auth`.
async fn refused_subscribe(client: &mut Client) {
    let received = receive(client).await;
    assert!(
        matches!(&received, Received::Frame(Frame::Error { code, client_ref: None, .. }) if code == "bad_auth"),
        "{received:?}"
    );
}

/// The bytes of the hex string `text`.
fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
        .collect()
}

/// The `frame` input of the vector `name` of `028.json`, read from the text.
fn vector_frame(name: &str) -> Vec<u8> {
    let vectors = include_str!("../../../../specs/vectors/028.json");
    let at = vectors.find(&format!("\"name\": \"{name}\"")).unwrap();
    let key = "\"frame\": \"";
    let start = at + vectors[at..].find(key).unwrap() + key.len();
    let end = start + vectors[start..].find('"').unwrap();
    unhex(&vectors[start..end])
}

/// A hex field of the `expected` of the vector `name`, read from the text.
fn vector_field(name: &str, field: &str) -> Vec<u8> {
    let vectors = include_str!("../../../../specs/vectors/028.json");
    let at = vectors.find(&format!("\"name\": \"{name}\"")).unwrap();
    let key = format!("\"{field}\": \"");
    let start = at + vectors[at..].find(&key).unwrap() + key.len();
    let end = start + vectors[start..].find('"').unwrap();
    unhex(&vectors[start..end])
}

fn array<const N: usize>(bytes: &[u8]) -> [u8; N] {
    bytes.try_into().unwrap()
}

#[test]
fn s030_t14_r14_frames_match_vectors() {
    let field = |name, key| vector_field(name, key);
    let row_of = |name| Row {
        server_id: array(&field(name, "server_id")),
        received_at: u64::from_be_bytes(array(&field(name, "received_at"))),
        blob: if name == "push_reference" {
            field(name, "blob")
        } else {
            Vec::new()
        },
    };
    let code = String::from_utf8(field("error_reference", "code")).unwrap();
    let message = String::from_utf8(field("error_reference", "message")).unwrap();
    let error_code = super::ws::ERRORS
        .iter()
        .find(|(_, name, text)| *name == code && *text == message)
        .map(|(error_code, _, _)| *error_code);
    assert!(error_code.is_some(), "{code} {message}");
    let built = [
        (
            "hello_reference",
            auth::hello(array(&field("hello_reference", "server_nonce"))),
        ),
        (
            "ok_reference",
            frames::ok(array(&field("ok_reference", "channel_id"))),
        ),
        (
            "ack_reference",
            frames::ack(
                array(&field("ack_reference", "client_ref")),
                &row_of("ack_reference"),
            ),
        ),
        (
            "push_reference",
            frames::push(
                array(&field("push_reference", "channel_id")),
                row_of("push_reference"),
            ),
        ),
        (
            "error_reference",
            frames::error(
                error_code.unwrap_or(ErrorCode::BadAuth),
                Some(array(&field("error_reference", "channel_id"))),
                Some(array(&field("error_reference", "client_ref"))),
            ),
        ),
    ];
    for (name, frame) in built {
        assert_eq!(frame.encode().unwrap(), vector_frame(name), "{name}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn s030_t07_r07_publish_during_catch_up() {
    // A publish on a third, subscribed channel while two catch up: its `ack`
    // and echo come within one backlog page, together.
    let clock = Arc::new(ManualClock::new(T0));
    let server = start(&clock).await;
    let alive = T0 + 3_600_000;
    plant(&server, channel(), 40, 64_673, T0 - 100, alive);
    plant(&server, other_channel(), 40, 64_673, T0 - 200, alive);
    let mut client = connect(server.address).await;
    let nonce = hello(&mut client).await;
    send(&mut client, &subscribe_third(&nonce)).await;
    assert!(backlog(&mut client, third_channel()).await.is_empty());

    send(&mut client, &subscribe_since(&nonce, None)).await;
    send(&mut client, &subscribe_other(&nonce)).await;
    // The catch-up under way: a backlog push received, then the writes
    // paused within a page while the publish comes.
    let first = receive(&mut client).await;
    assert!(
        matches!(first, Received::Frame(Frame::Push { .. })),
        "{first:?}"
    );
    server.shared.hooks.pause_writes(true);
    send(
        &mut client,
        &publish(third_channel(), 1, blob_of(third_channel(), 1)),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    server.shared.hooks.pause_writes(false);

    let (mut oks, mut pages, mut ack_at, mut echo_at) = (0, 1usize, None, None);
    while oks < 2 {
        match receive(&mut client).await {
            Received::Frame(Frame::Push { channel_id, .. }) if channel_id == third_channel() => {
                echo_at = Some(pages);
            }
            Received::Frame(Frame::Push { .. }) => pages += 1,
            Received::Frame(Frame::Ack { .. }) => ack_at = Some(pages),
            Received::Frame(Frame::Ok { .. }) => oks += 1,
            other => {
                let unexpected = Some(other);
                assert!(unexpected.is_none(), "unexpected {unexpected:?}");
                break;
            }
        }
    }
    assert_eq!(pages, 80);
    // Before the catch-ups end. How many pushes come first depends on what
    // the socket buffers held when the writes paused; that the queue goes
    // out before each page is pinned by `queue_before_the_next_page`, whose
    // writes pause before the first page.
    assert!(
        ack_at.is_some_and(|at| at < 80),
        "ack after {ack_at:?} backlog pushes"
    );
    assert_eq!(
        echo_at, ack_at,
        "a backlog push between the ack and its echo"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn s030_t15_r15_publisher_gone_before_commit() {
    // The publisher leaves before the writer commits: stored and pushed to
    // the other subscriber, and no `ack` for anyone.
    let clock = Arc::new(ManualClock::new(T0));
    let server = start(&clock).await;
    let mut publisher = subscribed(&server).await;
    let mut other = subscribed(&server).await;
    let before = count(&server, channel());
    let pause = server.shared.hooks.writer_pause.clone();
    tokio::task::spawn_blocking(move || pause.hold())
        .await
        .unwrap();
    send(
        &mut publisher,
        &publish(channel(), 1, blob_of(channel(), 1)),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    drop(publisher);
    let mut forgotten = false;
    for _ in 0..100 {
        if server.shared.hub().subscriptions_of(0) == 0 {
            forgotten = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(forgotten);
    server.shared.hooks.writer_pause.release();
    let received = receive(&mut other).await;
    assert!(
        matches!(&received, Received::Frame(Frame::Push { blob, .. }) if *blob == blob_of(channel(), 1)),
        "{received:?}"
    );
    assert!(matches!(
        receive_within(&mut other, 300).await,
        Received::Nothing
    ));
    assert_eq!(count(&server, channel()), before + 1);
}
