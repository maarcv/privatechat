//! Spec 033-rate-limit-quotas R8–R11: the caps of each listener and the
//! IP table, on the `Gate` alone and over real sockets.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use futures_util::SinkExt;
use tokio_tungstenite::tungstenite::Message;

use super::super::catch_up::{T0, backlog, subscribe_since};
use super::super::store::writer::request as writer_request;
use super::super::ws::{
    Client, DAY, Server, UPGRADE, channel, connect, hello, raw, send, start_limited,
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
    assert!(refused(&gate, address, 60_001).is_none());

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

    // Past the listener's cap, an address with no entry is refused.
    let gate = Gate::new(ConnectionLimits {
        max_unauth_connections: 2,
        ..limits
    });
    let _held = admit_n(&gate, ipv4(1), 2, 0);
    assert_eq!(refused(&gate, ipv4(2), 0), Some(Refused::Listener));
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
    assert_eq!(refused(&gate, ip("192.0.2.4"), 0), Some(Refused::Listener));
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
async fn s033_t09_r09_ip_forgotten() {
    // On the gate: kept 60 000 ms after it was opened, then removed.
    let gate = Gate::new(ConnectionLimits::default());
    let admission = gate.admit(Listener::Main, ip("192.0.2.1"), 0).unwrap();
    // The connection holds no address.
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
