//! Spec 030-ws-protocol over a real socket on 127.0.0.1: the route, the
//! message size, the `hello`, the frames a client never sends, and the
//! verdicts of spec 031 on the wire.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use privatechat_core::testing::subscribe_credential;
use privatechat_core::{Frame, relay};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::frame::Frame as RawFrame;
use tokio_tungstenite::tungstenite::protocol::frame::coding::{Data, OpCode};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

use std::sync::atomic::{AtomicUsize, Ordering};

use super::TestDir;
use crate::clock::{Clock, ManualClock};
use crate::connection::spawn_deadline_task;
use crate::frames::{self, ErrorCode};
use crate::http::{MAX_MESSAGE, Shared, router};
use crate::limits::ChannelLimits;
use crate::limits::SUBSCRIBE_GAP_MS;

pub(super) type Client = WebSocketStream<MaybeTlsStream<TcpStream>>;

pub(super) const HOST: &str = "chat.example.org";
pub(super) const K_CH: [u8; 32] = [0x40; 32];
pub(super) const DAY: u32 = 86_400;

/// A server on a free port of 127.0.0.1, with `clock` and a database of its
/// own, gone with it.
pub(super) struct Server {
    pub(super) address: SocketAddr,
    pub(super) shared: Arc<Shared>,
    _dir: TestDir,
}

/// Every test server gets a directory of its own.
static SERVERS: AtomicUsize = AtomicUsize::new(0);

pub(super) async fn start(clock: &Arc<ManualClock>) -> Server {
    start_with(clock, ChannelLimits::RAISED).await
}

/// A server whose channels have `limits`.
pub(super) async fn start_with(clock: &Arc<ManualClock>, limits: ChannelLimits) -> Server {
    let n = SERVERS.fetch_add(1, Ordering::SeqCst);
    let dir = TestDir::new(&format!("ws{n}"));
    let clock: Arc<dyn Clock> = clock.clone();
    let shared = Shared::open(&dir.db(), clock, vec![HOST.to_owned()], 1 << 40, limits).unwrap();
    spawn_deadline_task(shared.ticks.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(axum::serve(listener, router(shared.clone())).into_future());
    Server {
        address,
        shared,
        _dir: dir,
    }
}

pub(super) async fn connect(address: SocketAddr) -> Client {
    let (client, _) = tokio_tungstenite::connect_async(format!("ws://{address}/"))
        .await
        .unwrap();
    client
}

/// Every error code the server sends and its fixed text (R13).
pub(super) const ERRORS: [(ErrorCode, &str, &str); 8] = [
    (
        ErrorCode::BadAuth,
        "bad_auth",
        "subscription signature rejected",
    ),
    (
        ErrorCode::NonceExpired,
        "nonce_expired",
        "server nonce expired",
    ),
    (ErrorCode::BadTtl, "bad_ttl", "ttl out of range"),
    (
        ErrorCode::NotSubscribed,
        "not_subscribed",
        "channel not subscribed on this connection",
    ),
    (ErrorCode::BadBlob, "bad_blob", "blob rejected"),
    (ErrorCode::RateLimited, "rate_limited", "rate limited"),
    (ErrorCode::ChannelQuota, "channel_quota", "channel full"),
    (ErrorCode::ServerFull, "server_full", "server full"),
];

/// Spec 030 R13 on every frame a test receives: an `error` carries the fixed
/// text of its code, and never `unsupported_version`.
fn check_r13(frame: &Frame) {
    if let Frame::Error { code, message, .. } = frame {
        let known = ERRORS
            .iter()
            .any(|(_, name, text)| name == code && text == message);
        assert!(known, "an error of code {code:?} and text {message:?}");
    }
}

/// What the client receives next.
#[derive(Debug)]
pub(super) enum Received {
    Frame(Frame),
    Close(u16),
    Nothing,
}

pub(super) async fn receive(client: &mut Client) -> Received {
    loop {
        let next = tokio::time::timeout(Duration::from_secs(10), client.next()).await;
        match next {
            Ok(Some(Ok(Message::Binary(bytes)))) => {
                let frame = Frame::decode(&bytes).unwrap();
                check_r13(&frame);
                return Received::Frame(frame);
            }
            Ok(Some(Ok(Message::Close(frame)))) => {
                return Received::Close(frame.map_or(0, |frame| u16::from(frame.code)));
            }
            Ok(Some(Ok(Message::Ping(_) | Message::Pong(_)))) => continue,
            _ => return Received::Nothing,
        }
    }
}

/// What the client receives within `ms` of real time, if anything.
pub(super) async fn receive_within(client: &mut Client, ms: u64) -> Received {
    tokio::time::timeout(Duration::from_millis(ms), receive(client))
        .await
        .unwrap_or(Received::Nothing)
}

/// The nonce of the client's first frame, which must be the `hello`.
pub(super) async fn hello(client: &mut Client) -> [u8; 32] {
    let received = receive(client).await;
    let nonce = match &received {
        Received::Frame(Frame::Hello {
            server_nonce,
            proto_versions,
        }) if proto_versions == &[1] => Some(*server_nonce),
        _ => None,
    };
    assert!(nonce.is_some(), "expected a hello, got {received:?}");
    nonce.unwrap_or_default()
}

pub(super) async fn send(client: &mut Client, frame: &Frame) {
    client
        .send(Message::Binary(frame.encode().unwrap().into()))
        .await
        .unwrap();
}

pub(super) fn subscribe(nonce: &[u8; 32], host: &str) -> Frame {
    let (pk_ch, sig) = subscribe_credential(K_CH, DAY, nonce, host).unwrap();
    Frame::Subscribe {
        pk_ch,
        ttl_seconds: DAY,
        sig,
        since: Some(0),
    }
}

pub(super) fn channel() -> [u8; 16] {
    let (pk_ch, _) = subscribe_credential(K_CH, DAY, &[0; 32], HOST).unwrap();
    relay::channel_id(&pk_ch, DAY).unwrap()
}

/// The status line and the headers of a raw HTTP/1.1 request's answer.
async fn raw(address: SocketAddr, request: &str) -> String {
    let mut stream = TcpStream::connect(address).await.unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut answer = Vec::new();
    let mut buffer = [0u8; 1024];
    while !answer.windows(4).any(|end| end == b"\r\n\r\n") {
        let read = tokio::time::timeout(Duration::from_secs(10), stream.read(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        if read == 0 {
            break;
        }
        answer.extend_from_slice(&buffer[..read]);
    }
    String::from_utf8_lossy(&answer).to_lowercase()
}

/// A raw socket upgraded on `/`, its `hello` read past.
async fn upgraded(address: SocketAddr) -> TcpStream {
    let mut stream = TcpStream::connect(address).await.unwrap();
    let request = format!("GET / HTTP/1.1\r\nhost: h\r\n{UPGRADE}\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut answer = Vec::new();
    let mut byte = [0u8; 1];
    while !answer.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).await.unwrap();
        answer.push(byte[0]);
    }
    // The hello: a short binary frame, its length in one byte.
    let mut head = [0u8; 2];
    stream.read_exact(&mut head).await.unwrap();
    let mut hello = vec![0u8; usize::from(head[1] & 0x7f)];
    stream.read_exact(&mut hello).await.unwrap();
    stream
}

/// The code of the close frame the server writes next on a raw socket.
async fn close_code(stream: &mut TcpStream) -> Option<u16> {
    let mut head = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut head))
        .await
        .ok()?
        .ok()?;
    (head[0] == 0x88).then(|| u16::from_be_bytes([head[2], head[3]]))
}

const UPGRADE: &str = "upgrade: websocket\r\nconnection: upgrade\r\nsec-websocket-version: 13\r\nsec-websocket-key: dGhlIHNhbXBsZSBub25jZQ==\r\n";

#[tokio::test(flavor = "multi_thread")]
async fn s030_t03_r03_route_and_origin() {
    let server = start(&Arc::new(ManualClock::new(0))).await;
    let address = server.address;
    let empty = "content-length: 0";
    let head = raw(
        address,
        &format!("HEAD / HTTP/1.1\r\nhost: h\r\norigin: https://example.org\r\n{UPGRADE}\r\n"),
    )
    .await;
    assert!(head.starts_with("http/1.1 404"), "{head}");
    let origin_only = raw(
        address,
        "GET / HTTP/1.1\r\nhost: h\r\norigin: https://example.org\r\n\r\n",
    )
    .await;
    assert!(
        origin_only.starts_with("http/1.1 403") && origin_only.contains(empty),
        "{origin_only}"
    );
    let plain = raw(address, "GET / HTTP/1.1\r\nhost: h\r\n\r\n").await;
    assert!(
        plain.starts_with("http/1.1 404") && plain.contains(empty),
        "{plain}"
    );
    let other_path = raw(address, "GET /x HTTP/1.1\r\nhost: h\r\n\r\n").await;
    assert!(
        other_path.starts_with("http/1.1 404") && other_path.contains(empty),
        "{other_path}"
    );
    let post = raw(
        address,
        &format!("POST / HTTP/1.1\r\nhost: h\r\ncontent-length: 0\r\n{UPGRADE}\r\n"),
    )
    .await;
    assert!(
        post.starts_with("http/1.1 404") && post.contains(empty),
        "{post}"
    );
    let origin = raw(
        address,
        &format!("GET / HTTP/1.1\r\nhost: h\r\norigin: https://example.org\r\n{UPGRADE}\r\n"),
    )
    .await;
    assert!(
        origin.starts_with("http/1.1 403") && origin.contains(empty),
        "{origin}"
    );
    let offered = format!(
        "GET / HTTP/1.1\r\nhost: h\r\n{UPGRADE}sec-websocket-extensions: permessage-deflate\r\nsec-websocket-protocol: chat\r\n\r\n"
    );
    let upgraded = raw(address, &offered).await;
    assert!(upgraded.starts_with("http/1.1 101"), "{upgraded}");
    assert!(!upgraded.contains("sec-websocket-extensions"), "{upgraded}");
    assert!(!upgraded.contains("sec-websocket-protocol"), "{upgraded}");
}

#[tokio::test(flavor = "multi_thread")]
async fn s030_t04_r04_message_size() {
    let server = start(&Arc::new(ManualClock::new(0))).await;
    let address = server.address;
    // 70 000 bytes are read, and fail to decode as a frame.
    let mut client = connect(address).await;
    hello(&mut client).await;
    client
        .send(Message::Binary(vec![0; MAX_MESSAGE].into()))
        .await
        .unwrap();
    assert!(matches!(receive(&mut client).await, Received::Close(1008)));
    // One more is too big.
    let mut client = connect(address).await;
    hello(&mut client).await;
    client
        .send(Message::Binary(vec![0; MAX_MESSAGE + 1].into()))
        .await
        .unwrap();
    assert!(matches!(receive(&mut client).await, Received::Close(1009)));
    // Nor in two fragments of a message.
    let mut client = connect(address).await;
    hello(&mut client).await;
    let first = RawFrame::message(vec![0; 40_000], OpCode::Data(Data::Binary), false);
    let rest = RawFrame::message(vec![0; 30_001], OpCode::Data(Data::Continue), true);
    client.send(Message::Frame(first)).await.unwrap();
    client.send(Message::Frame(rest)).await.unwrap();
    assert!(matches!(receive(&mut client).await, Received::Close(1009)));
    // A frame that announces more is refused from its header alone.
    let mut stream = upgraded(address).await;
    let mut header = vec![0x82, 0x80 | 127];
    header.extend_from_slice(&(u64::try_from(MAX_MESSAGE).unwrap() + 1).to_be_bytes());
    header.extend_from_slice(&[1, 2, 3, 4]);
    stream.write_all(&header).await.unwrap();
    assert_eq!(close_code(&mut stream).await, Some(1009));
    // Text is not spoken here.
    let mut client = connect(address).await;
    hello(&mut client).await;
    client.send(Message::Text("hello".into())).await.unwrap();
    assert!(matches!(receive(&mut client).await, Received::Close(1003)));
    // Nor text that is not even UTF-8.
    let mut client = connect(address).await;
    hello(&mut client).await;
    let frame = RawFrame::message(vec![0xff, 0xfe], OpCode::Data(Data::Text), true);
    client.send(Message::Frame(frame)).await.unwrap();
    assert!(matches!(receive(&mut client).await, Received::Close(1003)));
}

#[tokio::test(flavor = "multi_thread")]
async fn s030_t05_r05_hello_first() {
    let server = start(&Arc::new(ManualClock::new(0))).await;
    let address = server.address;
    let mut client = connect(address).await;
    let nonce = hello(&mut client).await;
    assert_ne!(nonce, [0; 32]);
}

#[tokio::test(flavor = "multi_thread")]
async fn s030_t06_r06_bad_frames_close() {
    let clock = Arc::new(ManualClock::new(0));
    let server = start(&clock).await;
    let address = server.address;
    let push = Frame::Push {
        channel_id: [1; 16],
        server_id: [2; 16],
        received_at: 3,
        blob: vec![4; 1_185],
    };
    let ok = Frame::Ok {
        channel_id: [1; 16],
    };
    let server_hello = Frame::Hello {
        server_nonce: [1; 32],
        proto_versions: vec![1],
    };
    let ack = Frame::Ack {
        client_ref: [1; 16],
        server_id: [2; 16],
        received_at: 3,
    };
    let error = frames::error(ErrorCode::BadAuth, Some([1; 16]), None);
    let random = Message::Binary(vec![0xa5; 40].into());
    for message in [
        random,
        Message::Binary(push.encode().unwrap().into()),
        Message::Binary(ok.encode().unwrap().into()),
        Message::Binary(server_hello.encode().unwrap().into()),
        Message::Binary(ack.encode().unwrap().into()),
        Message::Binary(error.encode().unwrap().into()),
    ] {
        let mut client = connect(address).await;
        hello(&mut client).await;
        client.send(message).await.unwrap();
        // No `error` frame before the close.
        assert!(matches!(receive(&mut client).await, Received::Close(1008)));
    }

    // Three `bad_auth`: the third `error`, then the close.
    let mut client = connect(address).await;
    hello(&mut client).await;
    let forged = subscribe(&[9; 32], HOST);
    for _ in 0..3 {
        send(&mut client, &forged).await;
        let received = receive(&mut client).await;
        assert!(
            matches!(&received, Received::Frame(Frame::Error { code, channel_id, client_ref: None, .. })
                if code == "bad_auth" && *channel_id == Some(channel())),
            "{received:?}"
        );
        // Past the gap between two `subscribe`s (spec 033 R2).
        clock.advance_mono(SUBSCRIBE_GAP_MS);
    }
    assert!(matches!(receive(&mut client).await, Received::Close(1008)));

    // An accepted subscribe answers `ok` (the backlog comes with R7).
    let mut client = connect(address).await;
    let nonce = hello(&mut client).await;
    send(&mut client, &subscribe(&nonce, HOST)).await;
    let received = receive(&mut client).await;
    assert!(
        matches!(&received, Received::Frame(Frame::Ok { channel_id }) if *channel_id == channel()),
        "{received:?}"
    );

    // No accepted subscribe for 60 001 ms of the manual clock, moved in steps
    // of 1 000 ms while the client reads: nothing before 60 001 ms, then a
    // close with 1008 and no frame.
    let mut client = connect(address).await;
    hello(&mut client).await;
    for _ in 0..60 {
        clock.advance(1_000);
        assert!(matches!(
            receive_within(&mut client, 150).await,
            Received::Nothing
        ));
    }
    clock.advance(1);
    // At the next tick, within 100 ms of real time and not the 10 s of `receive`.
    assert!(matches!(
        receive_within(&mut client, 500).await,
        Received::Close(1008)
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn spec_031_verdicts_on_the_wire() {
    let clock = Arc::new(ManualClock::new(0));
    let server = start(&clock).await;
    let address = server.address;

    // A ping is answered, and the connection goes on.
    let mut client = connect(address).await;
    let nonce = hello(&mut client).await;
    client.send(Message::Ping(vec![7].into())).await.unwrap();
    let pong = tokio::time::timeout(Duration::from_secs(10), client.next()).await;
    assert!(matches!(pong, Ok(Some(Ok(Message::Pong(_))))), "{pong:?}");
    // A TTL out of range: `bad_ttl` naming the channel the client sent.
    let (pk_ch, sig) = subscribe_credential(K_CH, 60, &nonce, HOST).unwrap();
    let bad_ttl = Frame::Subscribe {
        pk_ch,
        ttl_seconds: 59,
        sig,
        since: Some(0),
    };
    send(&mut client, &bad_ttl).await;
    let expected = relay::channel_id(&pk_ch, 59).unwrap();
    let received = receive(&mut client).await;
    assert!(
        matches!(&received, Received::Frame(Frame::Error { code, message, channel_id, client_ref: None })
            if code == "bad_ttl" && message == "ttl out of range" && *channel_id == Some(expected)),
        "{received:?}"
    );
    // Its nonce accepted up to 60 000 ms, before its first-subscribe deadline.
    clock.advance(60_000);
    send(&mut client, &subscribe(&nonce, HOST)).await;
    let received = receive(&mut client).await;
    assert!(
        matches!(&received, Received::Frame(Frame::Ok { .. })),
        "{received:?}"
    );

    // Past 60 000 ms an accepted connection's nonce expires: the `error`,
    // then a `hello` with a new nonce, which then opens the channel.
    clock.advance(SUBSCRIBE_GAP_MS);
    send(&mut client, &subscribe(&nonce, HOST)).await;
    let received = receive(&mut client).await;
    assert!(
        matches!(&received, Received::Frame(Frame::Error { code, message, channel_id, .. })
            if code == "nonce_expired" && message == "server nonce expired" && *channel_id == Some(channel())),
        "{received:?}"
    );
    let fresh = hello(&mut client).await;
    assert_ne!(fresh, nonce);
    // The new nonce opens another channel (this one is already subscribed,
    // and a second subscribe of it gets nothing, R9).
    clock.advance(SUBSCRIBE_GAP_MS);
    let (pk_ch, sig) = subscribe_credential([0x41; 32], DAY, &fresh, HOST).unwrap();
    let other = Frame::Subscribe {
        pk_ch,
        ttl_seconds: DAY,
        sig,
        since: Some(0),
    };
    send(&mut client, &other).await;
    let received = receive(&mut client).await;
    let expected = relay::channel_id(&pk_ch, DAY).unwrap();
    assert!(
        matches!(&received, Received::Frame(Frame::Ok { channel_id }) if *channel_id == expected),
        "{received:?}"
    );
}

#[test]
fn error_codes_and_texts() {
    for (code, name, text) in ERRORS {
        assert_eq!((code.code(), code.message()), (name, text));
        assert!(text.is_ascii() && text.len() <= 256);
    }
}

/// Spec 032-storage-ttl R14: the deadline task wakes every 100 ms of real time.
#[test]
fn s032_t14_r14_deadline_tick() {
    assert_eq!(crate::connection::TICK, Duration::from_millis(100));
}
