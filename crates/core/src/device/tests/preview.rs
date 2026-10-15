//! Tests of the preview of an import (spec 027-core-api R25).

use super::{Fixture, NOW, SERVER, config};
use crate::Error;
use crate::crypto::Secret;
use crate::device::{ConfigPreview, Device};
use crate::proto::config::Config;
use crate::storage::{StoreError, Vault};
use crate::testing::settings;
use crate::vectors::{self, Vector};

const OTHER_SERVER: &str = "wss://other.example.org";
const THIRD_SERVER: &str = "wss://third.example.org";
/// The onion host of 011 `config_onion_ws`, served over TLS.
const ONION_WSS: &str = "wss://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion";

/// A one-hour config of key `[k; 32]` on `server_url`, suggesting `name`.
fn named(k: u8, server_url: &str, name: &str) -> Config {
    Config::from_parts(Secret::from_bytes([k; 32]), server_url, 3_600, name, 0).unwrap()
}

/// A device whose settings are saved with `proxy`, holding the channels of
/// `configs`.
fn holding(configs: &[&Config], proxy: Option<&str>) -> Device {
    let fixture = Fixture::new();
    fixture.save_settings(&settings(SERVER, 30, proxy));
    let mut device = fixture.open().unwrap();
    for config in configs {
        device
            .import_qr(&config.export_qr(NOW).unwrap(), false, NOW)
            .unwrap();
    }
    device
}

/// The preview of the QR of `config`.
fn preview(device: &Device, config: &Config) -> ConfigPreview {
    device
        .preview_qr(&config.export_qr(NOW).unwrap(), NOW)
        .unwrap()
}

/// The flags of a preview, in the order of the record.
fn flags(preview: &ConfigPreview) -> [bool; 4] {
    [
        preview.is_open,
        preview.server_known,
        preview.name_collides,
        preview.needs_proxy,
    ]
}

/// The `now` of a vector of 011.
fn now_of(vector: &Vector) -> u64 {
    vector.input("now").u64_hex()
}

/// Spec 027, R25: the preview of each 011 vector answers as the import
/// does before its first store call; the flags, `broken_reason` and the
/// cleaned name follow the device it runs on.
#[test]
fn s027_t25_r25_preview() {
    let reference = vectors::load("011", "config_reference");
    let device = holding(&[], None);
    let shown = device
        .preview_qr(reference.input("qr").bytes(), now_of(&reference))
        .unwrap();
    let parsed = Config::parse_qr(reference.input("qr").bytes(), now_of(&reference)).unwrap();
    assert_eq!(shown.suggested_name, parsed.suggested_name());
    assert_eq!(shown.server_url, parsed.server_url());
    assert_eq!(shown.ttl_seconds, parsed.ttl_seconds());
    assert_eq!((flags(&shown), shown.broken_reason), ([false; 4], None));
    let file = vectors::load("011", "chatcfg_reference");
    let from_file = device
        .preview_file(
            file.expected("file").bytes(),
            file.input("password").bytes(),
            now_of(&file),
        )
        .unwrap();
    assert_eq!(from_file, shown);
    // The file's `now` reaches the parse: past its expiry, it is refused.
    assert_eq!(
        device.preview_file(
            file.expected("file").bytes(),
            file.input("password").bytes(),
            u64::MAX,
        ),
        Err(Error::InviteExpired)
    );

    // Each error vector: the preview's error is the import's.
    for vector in vectors::all("011") {
        if vector.has_expected("error") {
            let now = now_of(&vector);
            let mut device = holding(&[], None);
            let (previewed, imported) = if vector.has_input("file") {
                let (bytes, password) = (
                    vector.input("file").bytes(),
                    vector.input("password").bytes(),
                );
                (
                    device.preview_file(bytes, password, now).map(|_| ()),
                    device.import_file(bytes, password, false, now).map(|_| ()),
                )
            } else {
                let qr = vector.input("qr").bytes();
                (
                    device.preview_qr(qr, now).map(|_| ()),
                    device.import_qr(qr, false, now).map(|_| ()),
                )
            };
            assert!(previewed.is_err(), "{}", vector.name());
            assert_eq!(previewed, imported, "{}", vector.name());
        }
    }

    // The channel open on another server.
    let onion = vectors::load("011", "config_onion_ws");
    let mut device = holding(&[], None);
    device
        .import_qr(reference.input("qr").bytes(), false, now_of(&reference))
        .unwrap();
    assert_eq!(
        device.preview_qr(onion.input("qr").bytes(), now_of(&onion)),
        Err(Error::ConfigMismatch)
    );

    // One device per flag.
    let room = named(1, SERVER, "room");
    let shown = preview(&holding(&[&room], None), &room);
    assert!(shown.is_open);
    let shown = preview(
        &holding(&[&named(2, SERVER, "kitchen")], None),
        &named(1, SERVER, "garden"),
    );
    assert_eq!(flags(&shown), [false, true, false, false]);
    let shown = preview(
        &holding(&[&named(2, OTHER_SERVER, "Alice")], None),
        &named(1, THIRD_SERVER, "ALICE"),
    );
    assert_eq!(flags(&shown), [false, false, true, false]);
    let shown = preview(
        &holding(&[&named(2, OTHER_SERVER, "\u{200B}")], None),
        &named(1, THIRD_SERVER, "\u{200B}"),
    );
    assert_eq!(flags(&shown), [false; 4]);
    assert_eq!(shown.suggested_name, "");
    let shown = preview(
        &holding(&[&named(2, OTHER_SERVER, "kitchen")], None),
        &named(1, THIRD_SERVER, "garden"),
    );
    assert_eq!(flags(&shown), [false; 4]);
    // A local name collides as the suggested one does.
    let mut device = holding(&[&named(2, OTHER_SERVER, "kitchen")], None);
    device
        .rename_channel(named(2, OTHER_SERVER, "kitchen").channel_id(), "Garden")
        .unwrap();
    assert!(preview(&device, &named(1, THIRD_SERVER, "garden")).name_collides);

    // `needs_proxy`, as `ChannelInfo::needs_proxy` would show it.
    let onion_wss = named(1, ONION_WSS, "room");
    assert!(preview(&holding(&[], None), &onion_wss).needs_proxy);
    let qr = onion.input("qr").bytes();
    let proxied = |proxy| {
        holding(&[], Some(proxy))
            .preview_qr(qr, now_of(&onion))
            .unwrap()
            .needs_proxy
    };
    assert!(proxied("localhost:9050"));
    assert!(!proxied("127.0.0.1:9050"));
    let fixture = Fixture::new();
    fixture.plant_channel(2, Vec::new());
    let reset = fixture.open().unwrap();
    assert!(reset.status().settings_reset);
    assert!(!preview(&reset, &named(1, OTHER_SERVER, "room")).needs_proxy);

    // `broken_reason`, with no retry of an `Io` entry.
    let corrupt = Fixture::new();
    corrupt.save_settings(&settings(SERVER, 30, None));
    let dir = corrupt.vault.dir_name(&config(1).channel_id()).unwrap();
    corrupt.vault.put_raw(&dir, Some(b"not a state"), None);
    let newer = Fixture::new();
    newer.save_settings(&settings(SERVER, 30, None));
    newer.plant_newer(1);
    let failing = Fixture::new();
    failing.save_settings(&settings(SERVER, 30, None));
    failing.plant_channel(1, Vec::new());
    failing.faults.fail_loads(true);
    let cases = [
        (corrupt.open().unwrap(), StoreError::Corrupt),
        (newer.open().unwrap(), StoreError::UnsupportedVersion),
        (failing.open().unwrap(), StoreError::Io),
    ];
    failing.faults.fail_loads(false);
    for (device, reason) in cases {
        let shown = preview(&device, &config(1));
        assert_eq!(shown.broken_reason, Some(reason));
        assert!(!shown.is_open);
        // Another channel's preview does not take that entry's reason.
        assert_eq!(preview(&device, &config(2)).broken_reason, None);
        assert_eq!(device.status().broken.len(), 1);
        assert_eq!(device.status().broken[0].channel_id, None);
        assert!(device.channels().is_empty());
    }

    // The suggested name, cleaned.
    let device = holding(&[], None);
    let shown = preview(&device, &named(1, SERVER, "ro\u{202E}om"));
    assert_eq!(shown.suggested_name, "room");
}
