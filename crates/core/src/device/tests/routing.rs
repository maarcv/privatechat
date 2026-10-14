//! Tests of the routing of the connections (spec 027-core-api R11).

use super::dispatch::opened;
use super::tick::{HOST, connect_all, pump, run, subscribed, with_channels};
use super::{NOW, config};
use crate::session::connection::Event;
use crate::session::frames::Frame;
use crate::testing::MemoryServer;

/// gets no event and no frame.
#[test]
fn s027_t11_r11_routing() {
    let (_fixture, mut device) = with_channels(1);
    let mut server = MemoryServer::new(&[HOST]);
    let plan = device.connections()[0].id;
    let unknown = plan + 100;
    device.on_connect(unknown, NOW);
    assert!(device.outgoing(unknown).is_empty());
    let hello = Frame::Hello {
        server_nonce: [9; 32],
        proto_versions: vec![1],
    }
    .encode()
    .unwrap();
    assert!(device.on_frame(unknown, &hello, NOW).is_empty());
    device.on_disconnect(unknown);

    connect_all(&mut device, &mut server, NOW);
    let events = run(&mut device, &mut server, NOW, NOW + 5_000);
    assert!(subscribed(&events, config(1).channel_id()));
}

/// channels were all refused leaves the plan.
#[test]
fn s027_t11_r11_refused_channels() {
    let (_fixture, mut device) = with_channels(1);
    // A server configured for another host refuses every signature.
    let mut server = MemoryServer::new(&["other.example.org"]);
    let plan = device.connections()[0].id;
    connect_all(&mut device, &mut server, NOW);
    let events = run(&mut device, &mut server, NOW, NOW + 3_000);
    let channel = config(1).channel_id();
    assert!(events.contains(&Event::SubscribeRefused { channel }));
    assert!(device.connections().is_empty());
    device.on_disconnect(plan);
    server.disconnect(plan);
    server.connect(plan, NOW + 4_000);
    device.on_connect(plan, NOW + 4_000);
    pump(&mut device, &mut server, NOW + 4_000);
    run(&mut device, &mut server, NOW + 4_000, NOW + 8_000);
    assert!(device.outgoing(plan).is_empty());
}

/// Spec 027, R11: two plans on two servers each get their own frames.
#[test]
fn s027_t11_r11_two_plans() {
    let (_fixture, mut device) = with_channels(1);
    let other = crate::proto::config::Config::from_parts(
        crate::crypto::Secret::from_bytes([9; 32]),
        "wss://other.example.org",
        3_600,
        "room",
        0,
    )
    .unwrap();
    device
        .import_qr(&other.export_qr(NOW).unwrap(), false, NOW)
        .unwrap();
    let plans = device.connections();
    assert_eq!(plans.len(), 2);
    let mut servers = [
        MemoryServer::new(&[HOST]),
        MemoryServer::new(&["other.example.org"]),
    ];
    for (plan, server) in plans.iter().zip(servers.iter_mut()) {
        server.connect(plan.id, NOW);
        device.on_connect(plan.id, NOW);
    }
    let mut events = Vec::new();
    for now in (NOW..NOW + 5_000).step_by(1_000) {
        events.extend(device.on_tick(now));
        for _ in 0..5 {
            for (plan, server) in plans.iter().zip(servers.iter_mut()) {
                for frame in device.outgoing(plan.id) {
                    server.receive(plan.id, &frame, now);
                }
                for frame in server.read(plan.id, 100) {
                    events.extend(device.on_frame(plan.id, &frame, now));
                }
            }
        }
    }
    assert!(subscribed(&events, config(1).channel_id()));
    assert!(subscribed(&events, other.channel_id()));
}

/// channels is not refused, and leaves it once all are.
#[test]
fn s027_t11_r11_plan_left_out_only_when_all_refused() {
    let (_fixture, mut device) = with_channels(2);
    let plan = device.connections()[0].id;
    let link = device.links.get_mut(&plan).unwrap();
    link.refused.insert(config(1).channel_id());
    assert_eq!(device.connections().len(), 1);
    let link = device.links.get_mut(&plan).unwrap();
    link.refused.insert(config(2).channel_id());
    assert!(device.connections().is_empty());
}

/// `hello`.
#[test]
fn s027_t11_r11_refused_channel_not_resubscribed() {
    let (_fixture, mut device) = with_channels(1);
    let mut server = MemoryServer::new(&["other.example.org"]);
    let plan = device.connections()[0].id;
    connect_all(&mut device, &mut server, NOW);
    run(&mut device, &mut server, NOW, NOW + 3_000);
    device.on_disconnect(plan);
    server.disconnect(plan);
    server.connect(plan, NOW + 4_000);
    device.on_connect(plan, NOW + 4_000);
    for frame in server.read(plan, 100) {
        device.on_frame(plan, &frame, NOW + 4_000);
    }
    assert!(device.outgoing(plan).is_empty());
}

/// when its socket was open.
#[test]
fn s027_t11_r11_old_plan_id_ignored() {
    let (_fixture, mut device) = opened();
    let old = device.connections()[0].id;
    device.on_connect(old, NOW);
    device
        .import_qr(&config(2).export_qr(NOW).unwrap(), false, NOW)
        .unwrap();
    assert_ne!(device.connections()[0].id, old);
    let mut server = MemoryServer::new(&[HOST]);
    server.connect(old, NOW);
    for frame in server.read(old, 100) {
        assert!(device.on_frame(old, &frame, NOW).is_empty());
    }
    assert!(device.outgoing(old).is_empty());
}

/// unchanged: the connected channel still publishes on it.
#[test]
fn s027_t11_r11_replan_keeps_unchanged_sessions() {
    let (_fixture, mut device) = with_channels(1);
    let mut server = MemoryServer::new(&[HOST]);
    connect_all(&mut device, &mut server, NOW);
    run(&mut device, &mut server, NOW, NOW + 3_000);
    let plan = device.connections()[0].id;
    let other = crate::proto::config::Config::from_parts(
        crate::crypto::Secret::from_bytes([9; 32]),
        "wss://other.example.org",
        3_600,
        "room",
        0,
    )
    .unwrap();
    device
        .import_qr(&other.export_qr(NOW).unwrap(), false, NOW)
        .unwrap();
    assert!(device.connections().iter().any(|p| p.id == plan));
    device
        .send(config(1).channel_id(), "hi", None, NOW + 4_000)
        .unwrap();
    assert!(!device.outgoing(plan).is_empty());
}
