//! Spec 033-rate-limit-quotas over a real socket, with a `ManualClock`: the
//! limits of one connection.

use std::sync::Arc;

use privatechat_core::testing::subscribe_credential;
use privatechat_core::{Frame, relay};

use super::catch_up::{T0, backlog, subscribe_since};
use super::ws::{
    Client, DAY, HOST, Received, channel, connect, hello, receive, receive_within, send, start,
    subscribe,
};
use crate::clock::ManualClock;
use crate::limits::{
    CONN_PUBLISH_MAX, CONN_PUBLISH_WINDOW_MS, MAX_SUBSCRIPTIONS, SUBSCRIBE_GAP_MS,
};

fn client_ref(n: u16) -> [u8; 16] {
    let mut client_ref = [0; 16];
    client_ref[..2].copy_from_slice(&n.to_be_bytes());
    client_ref
}

/// A `publish` of a blob of the smallest size on the test channel.
fn publish(n: u16) -> Frame {
    let mut blob = vec![1; 1_185];
    blob[1..17].copy_from_slice(&channel());
    Frame::Publish {
        channel_id: channel(),
        client_ref: client_ref(n),
        blob,
    }
}

/// The next frame is the `error` `code` naming `channel_id` and, for a
/// `publish`, its `client_ref`.
async fn refused(client: &mut Client, code: &str, channel_id: [u8; 16], by: Option<[u8; 16]>) {
    let received = receive(client).await;
    assert!(
        matches!(&received, Received::Frame(Frame::Error { code: got, channel_id: Some(of), client_ref, .. })
            if got == code && *of == channel_id && *client_ref == by),
        "{received:?}"
    );
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
        send(&mut client, &publish(n)).await;
    }
    acked(&mut client, CONN_PUBLISH_MAX).await;
    send(&mut client, &publish(max)).await;
    refused(
        &mut client,
        "rate_limited",
        channel(),
        Some(client_ref(max)),
    )
    .await;

    // At the edge of the window the first 30 still count.
    clock.advance_mono(CONN_PUBLISH_WINDOW_MS);
    send(&mut client, &publish(max + 1)).await;
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
        send(&mut client, &publish(100 + n)).await;
    }
    acked(&mut client, CONN_PUBLISH_MAX).await;
    send(&mut client, &publish(200)).await;
    refused(
        &mut client,
        "rate_limited",
        channel(),
        Some(client_ref(200)),
    )
    .await;
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
    // A second subscribe of a channel held, with 16 held: ignored.
    send(&mut client, &keyed(0, &nonce).0).await;
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
