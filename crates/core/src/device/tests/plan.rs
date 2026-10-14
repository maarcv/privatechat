//! Tests of the connection plan and the create-time probe (spec
//! 027-core-api R10, R12, and R2 and R8 for the plan).

use super::{Fixture, NOW};
use crate::Error;
use crate::crypto::Secret;
use crate::device::{ConnectionPlan, Device, probe_hello};
use crate::proto::config::Config;
use crate::session::frames::Frame;
use crate::storage::StoreError;
use crate::testing::settings;

const ONION: &str = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion";
const PROXY: &str = "127.0.0.1:9050";

/// A fixture whose settings are saved, with `proxy`.
fn saved(proxy: Option<&str>) -> Fixture {
    let fixture = Fixture::new();
    fixture.save_settings(&settings("wss://example.org", 30, proxy));
    fixture
}

/// Imports the channel of key `[k; 32]` on `server_url` and returns its id.
fn import(device: &mut Device, k: u8, server_url: &str) -> [u8; 16] {
    let config =
        Config::from_parts(Secret::from_bytes([k; 32]), server_url, 3_600, "room", 0).unwrap();
    let qr = config.export_qr(NOW).unwrap();
    device.import_qr(&qr, false, NOW).unwrap().info.id
}

/// The plan that carries `id`.
fn plan_of(device: &Device, id: [u8; 16]) -> ConnectionPlan {
    device
        .connections()
        .into_iter()
        .find(|plan| plan.channels.contains(&id))
        .unwrap()
}

/// Whether `id` is in no run.
fn unplanned(device: &Device, id: [u8; 16]) -> bool {
    device
        .connections()
        .iter()
        .all(|plan| !plan.channels.contains(&id))
}

/// The `needs_proxy` of `id`'s `ChannelInfo`.
fn needs(device: &Device, id: [u8; 16]) -> bool {
    device
        .channels()
        .into_iter()
        .find(|info| info.id == id)
        .unwrap()
        .needs_proxy
}

/// Spec 027, R10: 17 channels on one server → runs of 16 and 1; an 18th
/// keeps the first run's `id`; leaving one of the 16 changes only that
/// run's `id`; leaving the only channel of a server leaves no plan for
/// it; two servers → two runs.
#[test]
fn s027_t10_r10_plan() {
    let fixture = saved(None);
    let mut device = fixture.open().unwrap();
    let ids: Vec<[u8; 16]> = (1..=17)
        .map(|k| import(&mut device, k, "wss://example.org"))
        .collect();
    let plans = device.connections();
    assert_eq!(plans.len(), 2);
    assert_eq!(plans[0].channels, ids[..16]);
    assert_eq!(plans[1].channels, ids[16..]);
    let route = &plans[0].route;
    assert_eq!(route.host, "example.org");
    assert_eq!(route.port, 443);
    assert!(route.tls);
    assert_eq!(route.socks5_proxy, None);
    assert_eq!(route.socks_username, None);

    let first = plans[0].id;
    let joined = plans[1].id;
    let eighteenth = import(&mut device, 18, "wss://example.org");
    let plans = device.connections();
    assert_eq!(plans[0].id, first);
    // The run the 18th joined changed, so it gets a new `id`.
    assert_ne!(plans[1].id, joined);
    assert_eq!(plans[1].channels, [ids[16], eighteenth]);
    let second = plans[1].id;

    device.leave(ids[3]).unwrap();
    let plans = device.connections();
    assert_ne!(plans[0].id, first);
    assert_eq!(plans[1].id, second);
    assert!(!plans[0].channels.contains(&ids[3]));
    assert_eq!(plans[0].channels.len(), 15);

    let alone = import(&mut device, 30, "wss://other.example.org:9001");
    let plan = plan_of(&device, alone);
    assert_eq!(plan.channels, [alone]);
    assert_eq!(plan.route.host, "other.example.org");
    assert_eq!(plan.route.port, 9001);
    assert_eq!(device.connections().len(), 3);
    device.leave(alone).unwrap();
    assert_eq!(device.connections().len(), 2);
    assert!(
        device
            .connections()
            .iter()
            .all(|plan| plan.route.host == "example.org")
    );
}

/// Spec 027, R10: a plan whose channels stand keeps its `id`, and every
/// other plan gets an `id` greater than any minted before; a new channel
/// joins the last run of its route with room.
#[test]
fn s027_t10_r10_plan_ids_are_new() {
    let fixture = saved(None);
    let mut device = fixture.open().unwrap();
    let mut before: Vec<ConnectionPlan> = Vec::new();
    let mut highest = 0;
    for k in 1..=20 {
        import(&mut device, k, "wss://example.org");
        let plans = device.connections();
        for plan in &plans {
            match before.iter().find(|old| old.id == plan.id) {
                Some(old) => assert_eq!(old, plan, "{k}"),
                None => {
                    assert!(plan.id > highest, "{k}");
                    highest = plan.id;
                }
            }
        }
        before = plans;
    }
    // The new channel joins the last run with room, not the one the
    // leaver freed.
    let first = device.connections()[0].clone();
    device.leave(first.channels[0]).unwrap();
    let late = import(&mut device, 40, "wss://example.org");
    assert!(device.connections()[1].channels.contains(&late));
}

/// Spec 027, R10: 16 channels found at `open` make one run, minted once.
#[test]
fn s027_t01_r01_open_mints_each_run_once() {
    let fixture = saved(None);
    let mut device = fixture.open().unwrap();
    for k in 1..=16 {
        import(&mut device, k, "wss://example.org");
    }
    drop(device);
    let device = fixture.open().unwrap();
    let plans = device.connections();
    assert_eq!(plans.len(), 1);
    assert_eq!(plans[0].channels.len(), 16);
    assert_eq!(plans[0].id, 1);
}

/// Spec 027, R10: with a proxy each channel is its own run, every `id`
/// changes and each plan has its own username, kept while it is
/// unchanged; a `.onion` channel needs the proxy and is planned once it
/// is set.
#[test]
fn s027_t10_r10_plan_with_a_proxy() {
    let fixture = saved(None);
    let mut device = fixture.open().unwrap();
    let a = import(&mut device, 1, "wss://example.org");
    let b = import(&mut device, 2, "wss://example.org");
    let onion = import(&mut device, 3, &format!("wss://{ONION}"));
    let dotted = import(&mut device, 4, &format!("wss://{ONION}."));
    assert!(unplanned(&device, onion));
    assert!(unplanned(&device, dotted));
    assert!(needs(&device, onion));
    assert!(needs(&device, dotted));
    let before = plan_of(&device, a).id;

    device.set_socks5_proxy(Some(PROXY)).unwrap();
    let plans = device.connections();
    assert_eq!(plans.len(), 4);
    assert!(plans.iter().all(|plan| plan.channels.len() == 1));
    assert!(plans.iter().all(|plan| plan.id > before));
    assert!(!needs(&device, onion));
    let usernames: Vec<String> = plans
        .iter()
        .map(|plan| plan.route.socks_username.clone().unwrap())
        .collect();
    for username in &usernames {
        assert_eq!(username.len(), 8);
        assert!(
            username
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
    }
    let mut distinct = usernames.clone();
    distinct.sort();
    distinct.dedup();
    assert_eq!(distinct.len(), 4);
    assert!(
        plans
            .iter()
            .all(|plan| plan.route.socks5_proxy.as_deref() == Some(PROXY))
    );
    // Unchanged plans keep their `id` and username.
    device.rename_channel(b, "hall").unwrap();
    assert_eq!(device.connections(), plans);

    device.set_socks5_proxy(None).unwrap();
    assert!(unplanned(&device, onion));
    assert_eq!(plan_of(&device, a).channels, [a, b]);
}

/// Spec 027, R10: a `ws://` onion channel is planned, with `tls` false,
/// only behind a loopback IP literal proxy; its `wss://` twin keeps
/// `tls`.
#[test]
fn s027_t10_r10_plain_onion() {
    for (proxy, planned) in [
        (PROXY, true),
        ("192.168.1.10:9050", false),
        ("localhost:9050", false),
    ] {
        let fixture = saved(Some(proxy));
        let mut device = fixture.open().unwrap();
        let plain = import(&mut device, 1, &format!("ws://{ONION}"));
        let tls = import(&mut device, 2, &format!("wss://{ONION}"));
        let public = import(&mut device, 3, "wss://example.org");
        assert_eq!(unplanned(&device, plain), !planned, "{proxy}");
        assert_eq!(needs(&device, plain), !planned, "{proxy}");
        if planned {
            let route = plan_of(&device, plain).route;
            assert!(!route.tls);
            assert_eq!(route.port, 80);
        }
        assert!(plan_of(&device, tls).route.tls);
        assert!(plan_of(&device, public).route.tls);
        let probe = device.probe_plan(&format!("ws://{ONION}"));
        if planned {
            assert!(!probe.unwrap().unwrap().tls);
        } else {
            assert_eq!(probe, Err(Error::BadConfig), "{proxy}");
        }
    }
}

/// Spec 027, R2: while the settings are reset there is no plan and no
/// probe; the acknowledgement or the proxy setter releases the plan.
#[test]
fn s027_t02_r02_gate_holds_the_plan() {
    for with_proxy in [false, true] {
        let fixture = Fixture::new();
        fixture.plant_channel(1, Vec::new());
        let mut device = fixture.open().unwrap();
        assert!(device.status().settings_reset);
        assert!(device.connections().is_empty());
        assert_eq!(device.probe_plan("wss://example.org"), Ok(None));
        assert_eq!(device.probe_plan(&format!("wss://{ONION}")), Ok(None));
        assert_eq!(device.probe_plan("wss://a/b"), Err(Error::BadConfig));
        if with_proxy {
            device.set_socks5_proxy(Some(PROXY)).unwrap();
        } else {
            device.acknowledge_settings(false).unwrap();
        }
        let plans = device.connections();
        assert_eq!(plans.len(), 1);
        assert_eq!(plans[0].channels, [super::config(1).channel_id()]);
        assert!(device.probe_plan("wss://example.org").unwrap().is_some());
    }
}

/// Spec 027, R8: a channel that leaves is no longer named by its run.
#[test]
fn s027_t08_r08_leave_leaves_its_run() {
    let fixture = saved(None);
    let mut device = fixture.open().unwrap();
    let a = import(&mut device, 1, "wss://example.org");
    let b = import(&mut device, 2, "wss://example.org");
    device.leave(a).unwrap();
    assert_eq!(device.connections()[0].channels, [b]);
}

/// Spec 027, R12: `probe_plan` checks the grammar and the proxy, and draws
/// a fresh username at each call behind a proxy; `probe_hello` applies the
/// version rule to a `hello` and refuses any other frame.
#[test]
fn s027_t12_r12_probe() {
    let fixture = saved(None);
    let device = fixture.open().unwrap();
    assert_eq!(
        device.probe_plan("wss://example.org/x"),
        Err(Error::BadConfig)
    );
    assert_eq!(
        device.probe_plan(&format!("wss://{ONION}")),
        Err(Error::BadConfig)
    );
    let route = device
        .probe_plan("wss://example.org:9001")
        .unwrap()
        .unwrap();
    assert_eq!(
        (route.host.as_str(), route.port, route.tls),
        ("example.org", 9001, true)
    );
    assert_eq!(route.socks5_proxy, None);
    assert_eq!(route.socks_username, None);

    let fixture = saved(Some(PROXY));
    let device = fixture.open().unwrap();
    let first = device.probe_plan("wss://example.org").unwrap().unwrap();
    let second = device.probe_plan("wss://example.org").unwrap().unwrap();
    assert_eq!(first.socks5_proxy.as_deref(), Some(PROXY));
    assert_ne!(first.socks_username, second.socks_username);
    assert!(device.probe_plan(&format!("wss://{ONION}")).is_ok());

    let hello = |versions: Vec<u8>| {
        Frame::Hello {
            server_nonce: [7; 32],
            proto_versions: versions,
        }
        .encode()
        .unwrap()
    };
    assert_eq!(probe_hello(&hello(vec![1])), Ok(true));
    assert_eq!(probe_hello(&hello(vec![2, 3])), Ok(false));
    assert_eq!(probe_hello(&hello((1..=9).collect())), Ok(false));
    let push = Frame::Push {
        channel_id: [1; 16],
        server_id: [2; 16],
        received_at: NOW,
        blob: vec![0; 10],
    }
    .encode()
    .unwrap();
    assert_eq!(probe_hello(&push), Err(Error::BadPayload));
    assert_eq!(probe_hello(b"not a frame"), Err(Error::BadPayload));
}

/// Spec 027, R10: the group is the scheme, the host and the port: two
/// hosts on one port, or one host on two ports, are two runs.
#[test]
fn s027_t10_r10_plan_groups_by_host_and_port() {
    let fixture = saved(None);
    let mut device = fixture.open().unwrap();
    let a = import(&mut device, 1, "wss://example.org");
    let b = import(&mut device, 2, "wss://other.example.org");
    let c = import(&mut device, 3, "wss://example.org:9001");
    assert_eq!(device.connections().len(), 3);
    assert_eq!(plan_of(&device, a).channels, [a]);
    assert_eq!(plan_of(&device, b).channels, [b]);
    assert_eq!(plan_of(&device, c).channels, [c]);
}

/// Spec 027, R1: `open` builds the plan of the channels it opened.
#[test]
fn s027_t01_r01_open_builds_the_plan() {
    let fixture = saved(None);
    fixture.plant_channel(1, Vec::new());
    let device = fixture.open().unwrap();
    assert_eq!(
        device.connections()[0].channels,
        [super::config(1).channel_id()]
    );
}

/// Spec 027, R2: a proxy set, or adopted from the stored file after a
/// passing `Io`, while the gate is up is in the route the gate releases.
#[test]
fn s027_t02_r02_released_plan_takes_the_proxy() {
    let fixture = Fixture::new();
    fixture.plant_channel(1, Vec::new());
    let mut device = fixture.open().unwrap();
    assert!(device.status().settings_reset);
    device.set_socks5_proxy(Some(PROXY)).unwrap();
    assert_eq!(
        device.connections()[0].route.socks5_proxy.as_deref(),
        Some(PROXY)
    );

    let fixture = saved(Some(PROXY));
    fixture.plant_channel(1, Vec::new());
    fixture.faults.fail_load_settings(true);
    let mut device = fixture.open().unwrap();
    fixture.faults.fail_load_settings(false);
    device.acknowledge_settings(false).unwrap();
    let route = &device.connections()[0].route;
    assert_eq!(route.socks5_proxy.as_deref(), Some(PROXY));
    assert!(route.socks_username.is_some());
}

/// Spec 027, R14: a channel whose reopen fails leaves its run, from a
/// direct writer and from `leave`; R5: an `Io` entry an import reopens
/// joins one.
#[test]
fn s027_t14_r14_broken_channel_leaves_its_run() {
    let id = super::config(1).channel_id();
    let fixture = saved(None);
    fixture.plant_channel(1, Vec::new());
    let mut device = fixture.open().unwrap();
    fixture.faults.poison_after(1);
    fixture.faults.fail_create(true);
    assert!(device.rename_channel(id, "hall").is_err());
    assert_eq!(device.status().broken.len(), 1);
    assert!(device.connections().is_empty());

    let fixture = saved(None);
    fixture.plant_channel(1, Vec::new());
    let mut device = fixture.open().unwrap();
    fixture.faults.fail_at(1);
    assert!(device.rename_channel(id, "hall").is_err());
    assert!(device.channels()[0].write_failed);
    fixture.faults.fail_at(1);
    fixture.faults.fail_create(true);
    assert_eq!(device.leave(id), Err(Error::Store(StoreError::Io)));
    assert_eq!(device.status().broken.len(), 1);
    assert!(device.connections().is_empty());

    let fixture = saved(None);
    fixture.plant_channel(1, Vec::new());
    fixture.faults.fail_loads(true);
    let mut device = fixture.open().unwrap();
    assert!(device.connections().is_empty());
    fixture.faults.fail_loads(false);
    import(&mut device, 1, "wss://example.org");
    assert_eq!(device.connections()[0].channels, [id]);
}

/// Spec 027, R10, R12: every username is 8 lowercase hex characters, a
/// byte below 16 included.
#[test]
fn s027_t12_r12_probe_username_is_eight_hex() {
    let fixture = saved(Some(PROXY));
    let device = fixture.open().unwrap();
    for _ in 0..64 {
        let route = device.probe_plan("wss://example.org").unwrap().unwrap();
        let username = route.socks_username.unwrap();
        assert_eq!(username.len(), 8, "{username}");
        assert!(
            username
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
    }
}

/// Spec 027, R2: a newer app's `settings.bin`, acknowledged, releases the
/// plan with nothing saved.
#[test]
fn s027_t02_r02_newer_settings_release_the_plan() {
    let fixture = Fixture::new();
    fixture.plant_channel(1, Vec::new());
    fixture.plant_newer_settings();
    let mut device = fixture.open().unwrap();
    assert!(device.connections().is_empty());
    device.acknowledge_settings(false).unwrap();
    let plans = device.connections();
    assert_eq!(plans.len(), 1);
    assert_eq!(plans[0].channels, [super::config(1).channel_id()]);
}
