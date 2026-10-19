//! Spec 033-rate-limit-quotas R8–R12: the caps of each listener, the IP
//! table and the byte budgets, on the `Gate` alone and over real sockets.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use privatechat_core::Frame;

use futures_util::SinkExt;
use tokio_tungstenite::tungstenite::Message;

use super::super::catch_up::{T0, backlog, other_channel, subscribe_other, subscribe_since};
use super::super::publish::{blob_of, client_ref, publish};
use super::super::store::writer::request as writer_request;
use super::super::ws::{
    Client, DAY, Received, Server, UPGRADE, channel, connect, hello, raw, receive, send,
    start_limited,
};
use super::limited;
use crate::clock::ManualClock;
use crate::limits::{
    Admission, CONN_PUBLISH_MAX, CONN_PUBLISH_WINDOW_MS, ChannelLimits, ConnectionLimits, Gate,
    IP_TABLE_MAX, Listener, MAX_SUBSCRIPTIONS, PING_INTERVAL_MS, PONG_TIMEOUT_MS, Refused,
    SEND_QUEUE_BYTES, SEND_QUEUE_FRAMES, SUBSCRIBE_GAP_MS, WRITE_TIMEOUT_MS,
};
use crate::store::writer::Refusal;
use crate::store::writer::test::Hooks;

fn ip(text: &str) -> Option<IpAddr> {
    Some(text.parse().unwrap())
}

/// `n` connections of `address` on the main listener at `now`, each
/// admitted.
fn admit_n(gate: &Arc<Gate>, address: Option<IpAddr>, n: u32, now: u64) -> Vec<Admission> {
    (0..n)
        .map(|k| {
            let admitted = gate.admit(Listener::Main, address, now);
            assert!(admitted.is_ok(), "{k}: {admitted:?}");
            admitted.unwrap()
        })
        .collect()
}

fn refused(gate: &Arc<Gate>, address: Option<IpAddr>, now: u64) -> Option<Refused> {
    gate.admit(Listener::Main, address, now).err()
}

/// The address `prefix:subnet::host` of IPv6.
fn v6(site: u16, subnet: u16, host: u16) -> Option<IpAddr> {
    Some(IpAddr::V6(Ipv6Addr::new(
        0x2001, 0xdb8, site, subnet, 0, 0, 0, host,
    )))
}

#[test]
fn s033_t08_r08_ip_limits() {
    let limits = ConnectionLimits::default();
    assert_eq!(
        (
            limits.ip_connections,
            limits.ip_unauth_connections,
            limits.ip_new_per_min,
            limits.ip48_connections,
            limits.ip48_unauth_connections,
            limits.ip48_subnets,
        ),
        (64, 20, 60, 256, 80, 256)
    );
    assert_eq!(IP_TABLE_MAX, 65_536);
    let address = ip("192.0.2.1");

    // 20 unauthenticated connections; the 21st refused, and not counted.
    let gate = Gate::new(limits);
    let mut held = admit_n(&gate, address, 20, 0);
    assert_eq!(refused(&gate, address, 0), Some(Refused::Address));
    // One subscribes, to two channels: one new one is accepted.
    held[0].authenticate();
    held[0].authenticate();
    held.extend(admit_n(&gate, address, 1, 0));
    assert_eq!(refused(&gate, address, 0), Some(Refused::Address));

    // 60 opened within 60 000 ms: the 61st refused, though few are open;
    // 60 001 ms after the first, accepted again.
    let gate = Gate::new(limits);
    for k in 0..60 {
        drop(admit_n(&gate, address, 1, k));
    }
    assert_eq!(refused(&gate, address, 60_000), Some(Refused::Address));
    // The window slides: one leaves it, one more fits.
    drop(admit_n(&gate, address, 1, 60_001));
    assert_eq!(refused(&gate, address, 60_001), Some(Refused::Address));

    // With `ip_connections = 3`, three subscribed connections hold it.
    let gate = Gate::new(ConnectionLimits {
        ip_connections: 3,
        ..limits
    });
    let mut held = admit_n(&gate, address, 3, 0);
    for admission in &mut held {
        admission.authenticate();
    }
    assert_eq!(refused(&gate, address, 0), Some(Refused::Address));

    // A subscribed connection that closes gives back no unauthenticated
    // slot of its address.
    let gate = Gate::new(limits);
    let _held = admit_n(&gate, address, 19, 0);
    let mut one = admit_n(&gate, address, 1, 0);
    one[0].authenticate();
    drop(one);
    let _last = admit_n(&gate, address, 1, 0);
    assert_eq!(refused(&gate, address, 0), Some(Refused::Address));

    // Two addresses of one /64 share one count; so do `::ffff:1.2.3.4` and
    // `1.2.3.4`.
    let gate = Gate::new(limits);
    let _held = admit_n(&gate, v6(1, 1, 1), 20, 0);
    assert_eq!(refused(&gate, v6(1, 1, 2), 0), Some(Refused::Address));
    let _held = admit_n(&gate, ip("1.2.3.4"), 10, 0);
    let _held = admit_n(&gate, ip("::ffff:1.2.3.4"), 10, 0);
    assert_eq!(refused(&gate, ip("1.2.3.4"), 0), Some(Refused::Address));
    assert_eq!(
        refused(&gate, ip("::ffff:1.2.3.4"), 0),
        Some(Refused::Address)
    );

    // Five /64s of one /48 at `ip_unauth_connections` each: the /48 refuses
    // past 80; with `ip48_unauth_connections = 200`, 100 accepted.
    for (ip48_unauth_connections, accepted) in [(80, 80), (200, 100)] {
        let gate = Gate::new(ConnectionLimits {
            ip48_unauth_connections,
            ..limits
        });
        let mut held = Vec::new();
        for subnet in 0..5 {
            for _ in 0..20 {
                held.extend(gate.admit(Listener::Main, v6(1, subnet, 1), 0).ok());
            }
        }
        assert_eq!(held.len(), accepted);
    }

    // The /48's open connections bound its /64s, subscribed or not.
    let gate = Gate::new(ConnectionLimits {
        ip48_connections: 30,
        ..limits
    });
    let mut held = admit_n(&gate, v6(1, 1, 1), 20, 0);
    held.iter_mut().for_each(Admission::authenticate);
    let _more = admit_n(&gate, v6(1, 2, 1), 10, 0);
    assert_eq!(refused(&gate, v6(1, 3, 1), 0), Some(Refused::Address));

    // A value of 0 refuses the first connection of a new entry too.
    for zero in [
        ConnectionLimits {
            ip_connections: 0,
            ..limits
        },
        ConnectionLimits {
            ip_new_per_min: 0,
            ..limits
        },
    ] {
        let gate = Gate::new(zero);
        assert_eq!(refused(&gate, ip("192.0.2.1"), 0), Some(Refused::Address));
        assert_eq!(refused(&gate, v6(1, 1, 1), 0), Some(Refused::Address));
    }
    for zero in [
        ConnectionLimits {
            ip48_unauth_connections: 0,
            ..limits
        },
        ConnectionLimits {
            ip48_subnets: 0,
            ..limits
        },
    ] {
        let gate = Gate::new(zero);
        assert_eq!(refused(&gate, v6(1, 1, 1), 0), Some(Refused::Address));
        assert_eq!(gate.entries(), 0);
    }
    // A new /64 of a known /48 starts a count of its own.
    let gate = Gate::new(ConnectionLimits {
        ip_unauth_connections: 1,
        ..limits
    });
    let _held = admit_n(&gate, v6(1, 1, 1), 1, 0);
    let _held = admit_n(&gate, v6(1, 2, 1), 1, 0);
    assert_eq!(gate.entries(), 3);
}

#[test]
fn s033_t08_r08_full_table() {
    let limits = ConnectionLimits {
        max_unauth_connections: u32::MAX,
        max_connections: u32::MAX,
        ..ConnectionLimits::default()
    };
    let gate = Gate::new(limits);
    let ipv4 = |n: usize| Some(IpAddr::V4(Ipv4Addr::from(u32::try_from(n).unwrap())));
    // A /48 known before the table fills, with one /64.
    let mut held = admit_n(&gate, v6(7, 0, 1), 1, 0);
    let mut n = 0;
    while gate.entries() < IP_TABLE_MAX - 1 {
        held.extend(admit_n(&gate, ipv4(n), 1, 0));
        n += 1;
    }
    // One slot left: a new /48 needs two, and is admitted without an entry.
    held.extend(admit_n(&gate, v6(6, 0, 1), 1, 0));
    assert_eq!(gate.entries(), IP_TABLE_MAX - 1);
    held.extend(admit_n(&gate, ipv4(n), 1, 0));
    n += 1;
    assert_eq!(gate.entries(), IP_TABLE_MAX);
    // A new IPv4 address is accepted without an entry...
    held.extend(admit_n(&gate, ipv4(n), 30, 0));
    assert_eq!(gate.entries(), IP_TABLE_MAX);
    // ...and so is a new /48; a known address is still checked.
    held.extend(admit_n(&gate, v6(8, 0, 1), 1, 0));
    held.extend(admit_n(&gate, ipv4(0), 19, 0));
    assert_eq!(refused(&gate, ipv4(0), 0), Some(Refused::Address));
    // A new /64 of the known /48 is counted in the /48 alone, whose bounds
    // still hold.
    held.extend(admit_n(&gate, v6(7, 1, 1), 79, 0));
    assert_eq!(gate.entries(), IP_TABLE_MAX);
    assert_eq!(refused(&gate, v6(7, 2, 1), 0), Some(Refused::Address));
    assert_eq!(refused(&gate, v6(7, 0, 1), 0), Some(Refused::Address));

    // Entry-less connections count toward the listener's cap: two more
    // fit, the third is refused.
    let gate_full = Gate::new(ConnectionLimits {
        max_unauth_connections: u32::try_from(IP_TABLE_MAX).unwrap() + 2,
        ..limits
    });
    let mut full = Vec::new();
    for k in 0..IP_TABLE_MAX {
        full.extend(admit_n(&gate_full, ipv4(k), 1, 0));
    }
    let _more = admit_n(&gate_full, ipv4(IP_TABLE_MAX), 2, 0);
    let fresh = ipv4(IP_TABLE_MAX + 1);
    assert_eq!(refused(&gate_full, fresh, 0), Some(Refused::Listener));
}

#[test]
fn s033_t08_r08_one_site_cycling_subnets() {
    let limits = ConnectionLimits::default();
    // Each connection closed at once: only its `opened` keeps its /64, and
    // the /48 has nothing open, so `ip48_subnets` alone refuses.
    let gate = Gate::new(limits);
    for subnet in 0..256 {
        drop(admit_n(&gate, v6(9, subnet, 1), 1, 0));
    }
    // A 257th /64 refused: the /48 holds 1 + 256 entries.
    assert_eq!(refused(&gate, v6(9, 256, 1), 0), Some(Refused::Address));
    assert_eq!(gate.entries(), 257);
    // A /64 it already holds is still admitted.
    let _held = admit_n(&gate, v6(9, 0, 1), 1, 0);

    // Held open and subscribed, its connections stay under
    // `ip48_connections`.
    let gate = Gate::new(ConnectionLimits {
        ip48_subnets: u32::MAX,
        ..limits
    });
    let mut held = Vec::new();
    for subnet in 0..256 {
        held.extend(admit_n(&gate, v6(9, subnet, 1), 1, 0));
        held.iter_mut().for_each(Admission::authenticate);
    }
    assert_eq!(refused(&gate, v6(9, 256, 1), 0), Some(Refused::Address));
}

#[test]
fn s033_t10_r10_each_listener_counted() {
    let limits = ConnectionLimits {
        max_connections: 1,
        onion_max_connections: 1,
        ..ConnectionLimits::default()
    };
    // A subscribed connection still holds its place under the cap.
    let gate = Gate::new(limits);
    let mut held = admit_n(&gate, ip("192.0.2.1"), 1, 0);
    held[0].authenticate();
    assert_eq!(refused(&gate, ip("192.0.2.2"), 0), Some(Refused::Listener));
    // An onion close frees an onion place, again and again.
    for _ in 0..3 {
        drop(gate.admit(Listener::Onion, None, 0).unwrap());
    }
    let _onion = gate.admit(Listener::Onion, None, 0).unwrap();
    assert_eq!(refused(&gate, ip("192.0.2.2"), 0), Some(Refused::Listener));
}

#[test]
fn s033_t08_r08_full_table_edges() {
    let limits = ConnectionLimits {
        max_unauth_connections: u32::MAX,
        max_connections: u32::MAX,
        ip48_subnets: 1,
        ..ConnectionLimits::default()
    };
    let gate = Gate::new(limits);
    let ipv4 = |n: usize| Some(IpAddr::V4(Ipv4Addr::from(u32::try_from(n).unwrap())));
    // A /48 already at `ip48_subnets`.
    let _site = admit_n(&gate, v6(7, 0, 1), 1, 0);
    let mut held = Vec::new();
    let mut n = 0;
    while gate.entries() < IP_TABLE_MAX - 2 {
        held.extend(admit_n(&gate, ipv4(n), 1, 0));
        n += 1;
    }
    // Two slots left: a new /48 and its /64 take both.
    held.extend(admit_n(&gate, v6(8, 0, 1), 1, 0));
    assert_eq!(gate.entries(), IP_TABLE_MAX);
    // Full: a new /64 of the /48 at `ip48_subnets` still gets 429.
    assert_eq!(refused(&gate, v6(7, 1, 1), 0), Some(Refused::Address));
}

#[test]
fn s033_t10_r10_unauthenticated_cap() {
    let gate = Gate::new(ConnectionLimits {
        max_unauth_connections: 2,
        ..ConnectionLimits::default()
    });
    let _b = admit_n(&gate, ip("192.0.2.1"), 1, 0);
    // A connection that subscribed frees no unauthenticated slot it does
    // not hold when it closes.
    let mut a = admit_n(&gate, ip("192.0.2.2"), 1, 0);
    a[0].authenticate();
    drop(a);
    let _c = admit_n(&gate, ip("192.0.2.3"), 1, 0);
    let entries = gate.entries();
    assert_eq!(refused(&gate, ip("192.0.2.4"), 0), Some(Refused::Listener));
    // A 503 counts nowhere, and comes before an address's 429.
    assert_eq!(gate.entries(), entries);
    assert_eq!(refused(&gate, ip("192.0.2.3"), 0), Some(Refused::Listener));
    let gate_v4 = Gate::new(ConnectionLimits {
        max_unauth_connections: 2,
        ip_unauth_connections: 1,
        ..ConnectionLimits::default()
    });
    let _one = admit_n(&gate_v4, ip("192.0.2.1"), 1, 0);
    assert_eq!(
        refused(&gate_v4, ip("192.0.2.1"), 0),
        Some(Refused::Address)
    );
    let _two = admit_n(&gate_v4, ip("192.0.2.2"), 1, 0);
    assert_eq!(
        refused(&gate_v4, ip("192.0.2.1"), 0),
        Some(Refused::Listener)
    );
    // The onion listener's count is its own.
    let _onion = gate.admit(Listener::Onion, None, 0).unwrap();
}

/// Waits up to 5 s of real time for `condition`.
async fn until(condition: impl Fn() -> bool) {
    for _ in 0..500 {
        if condition() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(condition(), "not within 5 s");
}

/// The status line of an upgrade on `address`, which must have an empty
/// body.
async fn status(address: SocketAddr) -> String {
    let answer = raw(
        address,
        &format!("GET / HTTP/1.1\r\nhost: h\r\n{UPGRADE}\r\n"),
    )
    .await;
    assert!(!answer.contains("upgrade: websocket"), "{answer}");
    assert!(answer.contains("content-length: 0"), "{answer}");
    answer.lines().next().unwrap_or_default().to_owned()
}

async fn server(clock: &Arc<ManualClock>, connections: ConnectionLimits) -> Server {
    start_limited(clock, ChannelLimits::RAISED, connections).await
}

/// A client that subscribed to the test channel.
async fn subscribed(address: SocketAddr) -> Client {
    let mut client = connect(address).await;
    let nonce = hello(&mut client).await;
    send(&mut client, &subscribe_since(&nonce, None)).await;
    assert!(backlog(&mut client, channel()).await.is_empty());
    client
}

#[tokio::test(flavor = "multi_thread")]
async fn s033_t08_r08_over_a_socket() {
    let clock = Arc::new(ManualClock::new(T0));
    let server = server(&clock, ConnectionLimits::default()).await;
    let mut held = Vec::new();
    for _ in 0..20 {
        held.push(connect(server.address).await);
    }
    assert_eq!(
        status(server.address).await,
        "http/1.1 429 too many requests"
    );
    // One subscribes: a new connection is accepted.
    let mut first = held.remove(0);
    let nonce = hello(&mut first).await;
    send(&mut first, &subscribe_since(&nonce, None)).await;
    assert!(backlog(&mut first, channel()).await.is_empty());
    held.push(connect(server.address).await);
    // Another address has a count of its own.
    server.shared.hooks.set_peer(ip("192.0.2.9"));
    held.push(connect(server.address).await);
}

#[tokio::test(flavor = "multi_thread")]
async fn s033_t08_r08_refused_before_counted() {
    // A request the route refuses is never counted: with one new
    // connection a minute, a 403 leaves room for the upgrade after it.
    let clock = Arc::new(ManualClock::new(T0));
    let one = ConnectionLimits {
        ip_new_per_min: 1,
        ..ConnectionLimits::default()
    };
    let server = server(&clock, one).await;
    let origin = format!("GET / HTTP/1.1\r\nhost: h\r\norigin: https://x\r\n{UPGRADE}\r\n");
    let answer = raw(server.address, &origin).await;
    assert!(answer.starts_with("http/1.1 403"), "{answer}");
    let not_upgrade = raw(server.address, "GET / HTTP/1.1\r\nhost: h\r\n\r\n").await;
    assert!(not_upgrade.starts_with("http/1.1 404"), "{not_upgrade}");
    assert_eq!(server.shared.gate.entries(), 0);
    let _client = connect(server.address).await;
    assert_eq!(
        status(server.address).await,
        "http/1.1 429 too many requests"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn s033_t09_r09_ip_forgotten() {
    // On the gate: kept 60 000 ms after it was opened, then removed.
    let gate = Gate::new(ConnectionLimits::default());
    let admission = gate.admit(Listener::Main, ip("192.0.2.1"), 0).unwrap();
    // The admission, all a connection gets from the gate, holds no
    // address: its `Debug` names every field.
    assert!(!format!("{admission:?}").contains("192"), "{admission:?}");
    drop(admission);
    gate.forget(60_000);
    assert_eq!(gate.entries(), 1);
    gate.forget(60_001);
    assert_eq!(gate.entries(), 0);
    // A /64 kept by the window alone keeps its /48.
    drop(gate.admit(Listener::Main, v6(1, 1, 1), 0).unwrap());
    assert_eq!(gate.entries(), 2);
    let again = gate.admit(Listener::Main, v6(1, 1, 2), 0).unwrap();
    assert_eq!(gate.entries(), 2);
    drop(again);
    gate.forget(60_001);
    assert_eq!(gate.entries(), 0);
    // An open connection keeps its entry, and its /48's, past the window.
    let held = gate.admit(Listener::Main, v6(1, 1, 1), 0).unwrap();
    gate.forget(120_000);
    assert_eq!(gate.entries(), 2);
    drop(held);
    assert_eq!(gate.entries(), 0);

    // Over a socket: the deadline task forgets it once the clock has moved.
    let clock = Arc::new(ManualClock::new(T0));
    let server = server(&clock, ConnectionLimits::default()).await;
    let client = subscribed(server.address).await;
    assert_eq!(server.shared.gate.entries(), 1);
    drop(client);
    clock.advance_mono(60_001);
    let gate = &server.shared.gate;
    until(|| gate.entries() == 0).await;
    // The onion listener creates no entry.
    let _onion = subscribed(server.onion).await;
    assert_eq!(gate.entries(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn s033_t10_r10_listener_caps() {
    let clock = Arc::new(ManualClock::new(T0));
    let caps = ConnectionLimits {
        max_connections: 2,
        onion_max_connections: 1,
        ..ConnectionLimits::default()
    };
    let server = server(&clock, caps).await;
    let main = [connect(server.address).await, connect(server.address).await];
    assert_eq!(
        status(server.address).await,
        "http/1.1 503 service unavailable"
    );
    let onion = connect(server.onion).await;
    assert_eq!(
        status(server.onion).await,
        "http/1.1 503 service unavailable"
    );
    // One main connection closes: the main listener accepts again, the
    // onion one still not.
    let [first, _second] = main;
    drop(first);
    until(|| server.shared.hooks.tasks() == 2).await;
    let _third = connect(server.address).await;
    assert_eq!(
        status(server.onion).await,
        "http/1.1 503 service unavailable"
    );
    drop(onion);

    // A third unauthenticated connection of a listener; a subscribed one
    // makes room.
    let server = server_unauth(&clock).await;
    for address in [server.address, server.onion] {
        let mut first = connect(address).await;
        let _second = connect(address).await;
        assert_eq!(status(address).await, "http/1.1 503 service unavailable");
        let nonce = hello(&mut first).await;
        send(&mut first, &subscribe_since(&nonce, None)).await;
        assert!(backlog(&mut first, channel()).await.is_empty());
        let _third = connect(address).await;
        drop(first);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn s033_t10_r10_counted_until_closed() {
    let clock = Arc::new(ManualClock::new(T0));
    let caps = ConnectionLimits {
        max_connections: 1,
        ..ConnectionLimits::default()
    };
    let server = server(&clock, caps).await;
    let mut client = connect(server.address).await;
    hello(&mut client).await;
    // A text frame closes it, but its close frame cannot be written: the
    // connection still counts.
    server.shared.hooks.pause_writes(true);
    client.send(Message::Text("x".into())).await.unwrap();
    for _ in 0..10 {
        assert_eq!(
            status(server.address).await,
            "http/1.1 503 service unavailable"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    server.shared.hooks.pause_writes(false);
    until(|| server.shared.hooks.tasks() == 0).await;
    let _next = connect(server.address).await;
}

async fn server_unauth(clock: &Arc<ManualClock>) -> Server {
    let caps = ConnectionLimits {
        max_unauth_connections: 2,
        ..ConnectionLimits::default()
    };
    server(clock, caps).await
}

#[test]
fn s033_t11_r11_configurable_values() {
    // A channel configured to 10 inserts a minute refuses the 11th.
    let limits = ChannelLimits {
        publish_per_min: 10,
        ..ChannelLimits::default()
    };
    let (_dir, _clock, harness) = limited("s033_t11", limits, Hooks::default());
    for n in 0..10 {
        assert!(harness.store(writer_request(n, 1, DAY)).result.is_ok());
    }
    assert_eq!(
        harness.store(writer_request(10, 1, DAY)).result,
        Err(Refusal::RateLimited)
    );
    // The defaults of the table "Limits".
    assert_eq!(
        ConnectionLimits::default(),
        ConnectionLimits {
            ip_connections: 64,
            ip_unauth_connections: 20,
            ip_new_per_min: 60,
            max_connections: 4_096,
            onion_max_connections: 1_024,
            max_unauth_connections: 1_024,
            ip_bytes_per_min: 8 * 1024 * 1024,
            onion_bytes_per_min: 32 * 1024 * 1024,
            ip48_connections: 256,
            ip48_unauth_connections: 80,
            ip48_subnets: 256,
            ip48_bytes_per_min: 128 * 1024 * 1024,
        }
    );
    // The constants of R1–R5, and spec 028's pacing (30 a minute, 16
    // channels, a subscribe per 1 100 ms).
    assert_eq!((CONN_PUBLISH_MAX, CONN_PUBLISH_WINDOW_MS), (30, 57_000));
    assert_eq!((SUBSCRIBE_GAP_MS, MAX_SUBSCRIPTIONS), (1_000, 16));
    const { assert!(SUBSCRIBE_GAP_MS < 1_100) };
    assert_eq!(
        (PING_INTERVAL_MS, PONG_TIMEOUT_MS, WRITE_TIMEOUT_MS),
        (30_000, 30_000, 30_000)
    );
    assert_eq!(
        (SEND_QUEUE_FRAMES, SEND_QUEUE_BYTES),
        (256, 4 * 1024 * 1024)
    );
}

/// A blob of 64 673 bytes, the largest, for `channel_id`.
fn large(channel_id: [u8; 16]) -> Vec<u8> {
    let mut blob = blob_of(channel_id, 7);
    blob.resize(64_673, 7);
    blob
}

/// A client of `address` subscribed to the test channel, or the other one.
async fn on(address: SocketAddr, other: bool) -> Client {
    let mut client = connect(address).await;
    let nonce = hello(&mut client).await;
    let (frame, channel_id) = if other {
        (subscribe_other(&nonce), other_channel())
    } else {
        (subscribe_since(&nonce, None), channel())
    };
    send(&mut client, &frame).await;
    // Through its backlog, whatever it holds, to its `ok`.
    backlog(&mut client, channel_id).await;
    client
}

/// The answer to `client`'s publish of a large blob as `n`, past its echo.
async fn published(client: &mut Client, channel_id: [u8; 16], n: u16) -> Frame {
    send(client, &publish(channel_id, n, large(channel_id))).await;
    loop {
        match receive(client).await {
            Received::Frame(Frame::Push { .. }) => {}
            Received::Frame(frame) => return frame,
            other => {
                let unexpected = Some(other);
                assert!(unexpected.is_none(), "{unexpected:?}");
            }
        }
    }
}

fn is_ack(frame: &Frame) -> bool {
    matches!(frame, Frame::Ack { .. })
}

fn is_rate_limited(frame: &Frame, channel_id: [u8; 16], n: u16) -> bool {
    matches!(frame, Frame::Error { code, channel_id: Some(of), client_ref: Some(by), .. }
        if code == "rate_limited" && *of == channel_id && *by == client_ref(n))
}

#[tokio::test(flavor = "multi_thread")]
async fn s033_t12_r12_ingest_budgets() {
    let clock = Arc::new(ManualClock::new(T0));
    let budgets = ConnectionLimits {
        // The fourth blob refused by one byte, so that a byte less counted
        // lets it through.
        ip_bytes_per_min: 4 * 64_673 - 1,
        // Three blobs exactly, so that a byte more counted refuses the third.
        onion_bytes_per_min: 3 * 64_673,
        ..ConnectionLimits::default()
    };
    let server = server(&clock, budgets).await;
    // One address, two of its channels, four connections: three blobs of
    // 64 673 bytes fit, the fourth does not.
    let mut clients = Vec::new();
    for k in 0..4 {
        clients.push((on(server.address, k % 2 == 1).await, k % 2 == 1));
    }
    let channel_of = |other: bool| if other { other_channel() } else { channel() };
    for (n, (client, other)) in clients.iter_mut().enumerate().take(3) {
        let n = u16::try_from(n).unwrap();
        assert!(is_ack(&published(client, channel_of(*other), n).await));
    }
    let (fourth, other) = &mut clients[3];
    let refused = published(fourth, channel_of(*other), 3).await;
    assert!(
        is_rate_limited(&refused, channel_of(*other), 3),
        "{refused:?}"
    );
    // At the edge of the window still refused; past it, accepted.
    clock.advance_mono(60_000);
    let refused = published(fourth, channel_of(*other), 4).await;
    assert!(
        is_rate_limited(&refused, channel_of(*other), 4),
        "{refused:?}"
    );
    clock.advance_mono(1);
    assert!(is_ack(&published(fourth, channel_of(*other), 5).await));

    // Two onion connections share one budget.
    let mut first = on(server.onion, false).await;
    let mut second = on(server.onion, true).await;
    for n in 10..13 {
        assert!(is_ack(&published(&mut first, channel(), n).await));
    }
    let refused = published(&mut second, other_channel(), 13).await;
    assert!(
        is_rate_limited(&refused, other_channel(), 13),
        "{refused:?}"
    );
    // The main listener's address is not the onion's.
    assert!(is_ack(&published(&mut clients[0].0, channel(), 14).await));
}

#[test]
fn s033_t12_r12_budgets_on_the_gate() {
    let limits = ConnectionLimits {
        ip_bytes_per_min: 300,
        ip48_bytes_per_min: 500,
        onion_bytes_per_min: 100,
        ..ConnectionLimits::default()
    };
    let gate = Gate::new(limits);
    let ok = || Ok::<(), ()>(());
    let spend = |admission: &Admission, bytes, now| admission.publish(bytes, now, ok);
    // An address's budget, up to it and not past it.
    let v4 = admit_n(&gate, ip("192.0.2.1"), 2, 0);
    assert_eq!(spend(&v4[0], 200, 0), Some(Ok(())));
    assert_eq!(spend(&v4[1], 100, 0), Some(Ok(())));
    assert_eq!(spend(&v4[1], 1, 0), None);
    // Another address has its own.
    let other = admit_n(&gate, ip("192.0.2.2"), 1, 0);
    assert_eq!(spend(&other[0], 300, 0), Some(Ok(())));
    // Two /64s of one /48: 300 each, 500 between them.
    let a = admit_n(&gate, v6(1, 1, 1), 1, 0);
    let b = admit_n(&gate, v6(1, 2, 1), 1, 0);
    assert_eq!(spend(&a[0], 300, 0), Some(Ok(())));
    assert_eq!(spend(&b[0], 201, 0), None);
    assert_eq!(spend(&b[0], 200, 0), Some(Ok(())));
    // A blob the writer refuses is not counted.
    let full = || Err::<(), ()>(());
    assert_eq!(other[0].publish(1, 0, full), None);
    let c = admit_n(&gate, ip("192.0.2.3"), 1, 0);
    assert_eq!(c[0].publish(300, 0, full), Some(Err(())));
    assert_eq!(spend(&c[0], 300, 0), Some(Ok(())));
    // The onion listener's budget is one for all its connections.
    let onion = [
        gate.admit(Listener::Onion, None, 0).unwrap(),
        gate.admit(Listener::Onion, None, 0).unwrap(),
    ];
    assert_eq!(spend(&onion[0], 60, 0), Some(Ok(())));
    assert_eq!(spend(&onion[1], 41, 0), None);
    assert_eq!(spend(&onion[1], 40, 0), Some(Ok(())));
    // The window slides at 60 000 ms, the forgotten bytes giving room back.
    assert_eq!(spend(&v4[0], 1, 60_000), None);
    assert_eq!(spend(&onion[1], 1, 60_000), None);
    assert_eq!(spend(&v4[0], 300, 60_001), Some(Ok(())));
    assert_eq!(spend(&onion[0], 100, 60_001), Some(Ok(())));
}

#[test]
fn s033_t12_r12_full_table() {
    let limits = ConnectionLimits {
        max_unauth_connections: u32::MAX,
        max_connections: u32::MAX,
        ip_bytes_per_min: 300,
        ..ConnectionLimits::default()
    };
    let gate = Gate::new(limits);
    let ipv4 = |n: usize| Some(IpAddr::V4(Ipv4Addr::from(u32::try_from(n).unwrap())));
    let _site = admit_n(&gate, v6(7, 0, 1), 1, 0);
    let mut held = Vec::new();
    let mut n = 0;
    while gate.entries() < IP_TABLE_MAX {
        held.extend(admit_n(&gate, ipv4(n), 1, 0));
        n += 1;
    }
    // A new /64 counted in its /48 alone still has its address's budget...
    let counted_in_site = admit_n(&gate, v6(7, 1, 1), 1, 0);
    let ok = || Ok::<(), ()>(());
    assert_eq!(counted_in_site[0].publish(300, 0, ok), Some(Ok(())));
    assert_eq!(counted_in_site[0].publish(1, 0, ok), None);
    // ...and the /48's, when that is the smaller.
    let gate = Gate::new(ConnectionLimits {
        ip48_bytes_per_min: 200,
        ..limits
    });
    let _site = admit_n(&gate, v6(7, 0, 1), 1, 0);
    let mut n = 0;
    while gate.entries() < IP_TABLE_MAX {
        held.extend(admit_n(&gate, ipv4(n), 1, 0));
        n += 1;
    }
    let counted_in_site = admit_n(&gate, v6(7, 1, 1), 1, 0);
    assert_eq!(counted_in_site[0].publish(201, 0, ok), None);
    assert_eq!(counted_in_site[0].publish(200, 0, ok), Some(Ok(())));
    // A new address with no entry has none: R10 alone bounds it.
    let entry_less = admit_n(&gate, ipv4(n), 1, 0);
    assert_eq!(entry_less[0].publish(1_000, 0, ok), Some(Ok(())));
}

#[test]
fn s033_t09_r09_kept_while_published() {
    // An entry counting only bytes published within 60 000 ms is kept, and
    // removed after.
    let gate = Gate::new(ConnectionLimits::default());
    let admission = admit_n(&gate, v6(1, 1, 1), 1, 0);
    let ok = || Ok::<(), ()>(());
    assert_eq!(admission[0].publish(10, 60_001, ok), Some(Ok(())));
    drop(admission);
    // Closed, and opened past the window: only its bytes keep it.
    gate.forget(120_001);
    assert_eq!(gate.entries(), 2);
    gate.forget(120_002);
    assert_eq!(gate.entries(), 0);
}
