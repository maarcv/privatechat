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
use tokio::sync::broadcast;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

use crate::clock::ManualClock;
use crate::connection::spawn_deadline_task;
use crate::http::{MAX_MESSAGE, Shared, router};

type Client = WebSocketStream<MaybeTlsStream<TcpStream>>;

const HOST: &str = "chat.example.org";
const K_CH: [u8; 32] = [0x40; 32];
const DAY: u32 = 86_400;

/// A server on a free port of 127.0.0.1, with `clock`.
async fn start(clock: &Arc<ManualClock>) -> SocketAddr {
    let (ticks, _) = broadcast::channel(16);
    let shared = Arc::new(Shared {
        clock: clock.clone(),
        hosts: vec![HOST.to_owned()],
        ticks: ticks.clone(),
    });
    spawn_deadline_task(ticks);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(axum::serve(listener, router(shared)).into_future());
    address
}

async fn connect(address: SocketAddr) -> Client {
    let (client, _) = tokio_tungstenite::connect_async(format!("ws://{address}/"))
        .await
        .unwrap();
    client
}

/// What the client receives next.
#[derive(Debug)]
enum Received {
    Frame(Frame),
    Close(u16),
    Nothing,
}

async fn receive(client: &mut Client) -> Received {
    loop {
        let next = tokio::time::timeout(Duration::from_secs(10), client.next()).await;
        match next {
            Ok(Some(Ok(Message::Binary(bytes)))) => {
                return Received::Frame(Frame::decode(&bytes).unwrap());
            }
            Ok(Some(Ok(Message::Close(frame)))) => {
                return Received::Close(frame.map_or(0, |frame| u16::from(frame.code)));
            }
            Ok(Some(Ok(Message::Ping(_) | Message::Pong(_)))) => continue,
            _ => return Received::Nothing,
        }
    }
}

/// The nonce of the client's first frame, which must be the `hello`.
async fn hello(client: &mut Client) -> [u8; 32] {
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

async fn send(client: &mut Client, frame: &Frame) {
    client
        .send(Message::Binary(frame.encode().unwrap().into()))
        .await
        .unwrap();
}

fn subscribe(nonce: &[u8; 32], host: &str) -> Frame {
    let (pk_ch, sig) = subscribe_credential(K_CH, DAY, nonce, host).unwrap();
    Frame::Subscribe {
        pk_ch,
        ttl_seconds: DAY,
        sig,
        since: Some(0),
    }
}

fn channel() -> [u8; 16] {
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

const UPGRADE: &str = "upgrade: websocket\r\nconnection: upgrade\r\nsec-websocket-version: 13\r\nsec-websocket-key: dGhlIHNhbXBsZSBub25jZQ==\r\n";

#[tokio::test(flavor = "multi_thread")]
async fn s030_t03_r03_route_and_origin() {
    let address = start(&Arc::new(ManualClock::new(0))).await;
    let empty = "content-length: 0";
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
    let address = start(&Arc::new(ManualClock::new(0))).await;
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
    // Text is not spoken here.
    let mut client = connect(address).await;
    hello(&mut client).await;
    client.send(Message::Text("hello".into())).await.unwrap();
    assert!(matches!(receive(&mut client).await, Received::Close(1003)));
}

#[tokio::test(flavor = "multi_thread")]
async fn s030_t05_r05_hello_first() {
    let address = start(&Arc::new(ManualClock::new(0))).await;
    let mut client = connect(address).await;
    let nonce = hello(&mut client).await;
    assert_ne!(nonce, [0; 32]);
}

#[tokio::test(flavor = "multi_thread")]
async fn s030_t06_r06_bad_frames_close() {
    let clock = Arc::new(ManualClock::new(0));
    let address = start(&clock).await;
    let push = Frame::Push {
        channel_id: [1; 16],
        server_id: [2; 16],
        received_at: 3,
        blob: vec![4; 1_185],
    };
    let ok = Frame::Ok {
        channel_id: [1; 16],
    };
    let random = Message::Binary(vec![0xa5; 40].into());
    for message in [
        random,
        Message::Binary(push.encode().unwrap().into()),
        Message::Binary(ok.encode().unwrap().into()),
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
    // of 1 000 ms: closed with 1008 and no frame.
    let mut client = connect(address).await;
    hello(&mut client).await;
    for _ in 0..60 {
        clock.advance(1_000);
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    clock.advance(1);
    assert!(matches!(receive(&mut client).await, Received::Close(1008)));
}
