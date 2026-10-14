//! Tests of the channels of the device (spec 027-core-api R4–R8, and R1
//! and R21 for their writes).

use super::{Fixture, NOW, SERVER, config};
use crate::Error;
use crate::crypto::Secret;
use crate::device::{Device, Imported};
use crate::proto::config::Config;
use crate::storage::{Store, StoreError, Vault};
use crate::testing::{MemoryStore, batch, settings, settings_eq};

const OTHER_SERVER: &str = "wss://other.example.org";

/// A fixture whose settings are saved, so that no write of R1 counts.
fn with_settings() -> Fixture {
    let fixture = Fixture::new();
    fixture.save_settings(&settings(SERVER, 30, None));
    fixture
}

/// The QR text of the channel of `config`, as another device exports it.
fn qr_of(config: &Config) -> Vec<u8> {
    config.export_qr(NOW).unwrap()
}

/// A config of key `[k; 32]` on `server_url`.
fn config_on(k: u8, server_url: &str) -> Config {
    Config::from_parts(Secret::from_bytes([k; 32]), server_url, 3_600, "room", 0).unwrap()
}

/// The `channel_id`s `channels()` lists, in order.
fn listed(device: &Device) -> Vec<[u8; 16]> {
    device.channels().iter().map(|info| info.id).collect()
}

/// Spec 027, R4: the new channel is listed, exports, and a reopened
/// device lists it.
#[test]
fn s027_t04_r04_create_channel() {
    let fixture = with_settings();
    let mut device = fixture.open().unwrap();
    let info = device.create_channel(SERVER, 3_600, "room", NOW).unwrap();
    assert_eq!(listed(&device), [info.id]);
    assert_eq!(info.server_url, SERVER);
    assert_eq!(info.suggested_name, "room");
    assert_eq!(info.ttl_seconds, 3_600);
    let qr = device.export_qr(info.id, NOW).unwrap();
    let parsed = Config::parse_qr(&qr, NOW).unwrap();
    assert_eq!(parsed.channel_id(), info.id);
    drop(device);
    assert_eq!(listed(&fixture.open().unwrap()), [info.id]);
    let mut device = fixture.open().unwrap();
    assert_eq!(
        device.create_channel("https://example.org", 3_600, "room", NOW),
        Err(Error::BadConfig)
    );
}

/// Spec 027, R4: a first commit poisoned after its rename → `Ok`, the
/// channel open and listed, and listed once by a reopened device; the same
/// for an import, with `is_new`.
#[test]
fn s027_t04_r04_poisoned_first_commit() {
    let fixture = with_settings();
    let mut device = fixture.open().unwrap();
    fixture.faults.poison_after(1);
    let info = device.create_channel(SERVER, 3_600, "room", NOW).unwrap();
    assert_eq!(listed(&device), [info.id]);
    assert!(device.status().broken.is_empty());
    drop(device);
    assert_eq!(listed(&fixture.open().unwrap()), [info.id]);

    let fixture = with_settings();
    let mut device = fixture.open().unwrap();
    fixture.faults.poison_after(1);
    let imported = device.import_qr(&qr_of(&config(1)), false, NOW).unwrap();
    assert!(imported.is_new);
    assert_eq!(imported.info.id, config(1).channel_id());
    drop(device);
    assert_eq!(listed(&fixture.open().unwrap()), [config(1).channel_id()]);
}

/// Spec 027, R4: a first commit failing before its rename → the original
/// `Io`, nothing listed; a retry whose `Vault::create` fails → the
/// original `Io` and the directory in `broken` with its `channel_id`.
#[test]
fn s027_t04_r04_failed_first_commit() {
    let fixture = with_settings();
    let mut device = fixture.open().unwrap();
    fixture.faults.fail_at(1);
    let result = device.import_qr(&qr_of(&config(1)), false, NOW);
    assert_eq!(result, Err(Error::Store(StoreError::Io)));
    assert!(device.channels().is_empty());
    assert!(device.status().broken.is_empty());
    drop(device);
    assert!(fixture.open().unwrap().channels().is_empty());

    let fixture = with_settings();
    let mut device = fixture.open().unwrap();
    fixture.faults.fail_at(1);
    fixture.faults.fail_create_at(2);
    let result = device.import_qr(&qr_of(&config(1)), false, NOW);
    assert_eq!(result, Err(Error::Store(StoreError::Io)));
    assert!(device.channels().is_empty());
    let broken = device.status().broken;
    assert_eq!(broken.len(), 1);
    assert_eq!(broken[0].reason, StoreError::Io);
    assert_eq!(broken[0].channel_id, Some(config(1).channel_id()));
    assert_eq!(broken[0].channel_name.as_deref(), Some("room"));
    let dir = fixture.vault.dir_name(&config(1).channel_id()).unwrap();
    assert_eq!(broken[0].name, dir.to_hex());
}

/// Spec 027, R1: on a fresh install the first `create_channel` saves the
/// defaults before its channel; that save failing → its error, no
/// channel created.
#[test]
fn s027_t01_r01_first_channel_saves_the_settings() {
    let fixture = Fixture::new();
    let mut device = fixture.open().unwrap();
    fixture.faults.fail_save_settings(true);
    assert_eq!(
        device.create_channel(SERVER, 3_600, "room", NOW),
        Err(Error::Store(StoreError::Io))
    );
    assert!(device.channels().is_empty());
    assert!(fixture.vault.clone().list().unwrap().is_empty());
    assert_eq!(
        device.import_qr(&qr_of(&config(1)), false, NOW),
        Err(Error::Store(StoreError::Io))
    );
    assert!(fixture.vault.clone().list().unwrap().is_empty());
    fixture.faults.fail_save_settings(false);
    device.create_channel(SERVER, 3_600, "room", NOW).unwrap();
    let stored = fixture.stored_settings().unwrap();
    assert!(settings_eq(
        &stored,
        &settings(crate::DEFAULT_SERVER_URL, 60, None)
    ));
    drop(device);
    let device = fixture.open().unwrap();
    assert!(!device.status().settings_reset);
    assert_eq!(device.channels().len(), 1);
}

/// Spec 027, R5: a new QR → new; again → not new, no store touched; the
/// same channel with another server → `ConfigMismatch`; a wrong password
/// → `BadPassword`; each rejection commits nothing.
#[test]
fn s027_t05_r05_import() {
    let fixture = with_settings();
    let mut device = fixture.open().unwrap();
    let first = device.import_qr(&qr_of(&config(1)), false, NOW).unwrap();
    assert!(first.is_new);
    let dir = fixture.vault.dir_name(&config(1).channel_id()).unwrap();
    let handle = MemoryStore::handle(&fixture.vault, dir);
    let commits = handle.all_commits();
    let again = device.import_qr(&qr_of(&config(1)), false, NOW).unwrap();
    assert_eq!(
        again,
        Imported {
            info: first.info.clone(),
            is_new: false
        }
    );
    let other = qr_of(&config_on(1, OTHER_SERVER));
    assert_eq!(
        device.import_qr(&other, false, NOW),
        Err(Error::ConfigMismatch)
    );
    assert_eq!(handle.all_commits(), commits);
    assert_eq!(listed(&device), [config(1).channel_id()]);

    let (file, _) = config(2).export_encrypted(NOW).unwrap();
    assert_eq!(
        device.import_file(&file, b"not the seven words", false, NOW),
        Err(Error::BadPassword)
    );
    assert_eq!(
        device.import_qr(b"not a qr", false, NOW),
        Err(Error::BadConfig)
    );
    assert_eq!(fixture.vault.clone().list().unwrap().len(), 1);
}

/// Spec 027, R5: the QR of a corrupt or a newer channel → its error, and
/// with `replace_broken` a fresh channel and one entry fewer in `broken`.
#[test]
fn s027_t05_r05_import_over_broken() {
    for corrupt in [true, false] {
        let fixture = with_settings();
        let dir = if corrupt {
            let dir = fixture.vault.dir_name(&config(1).channel_id()).unwrap();
            fixture.vault.put_raw(&dir, Some(b"not a state"), None);
            dir
        } else {
            fixture.plant_newer(1)
        };
        let reason = if corrupt {
            StoreError::Corrupt
        } else {
            StoreError::UnsupportedVersion
        };
        let mut device = fixture.open().unwrap();
        assert_eq!(device.status().broken.len(), 1);
        let planted = fixture.vault.get_raw(&dir);
        let qr = qr_of(&config(1));
        assert_eq!(device.import_qr(&qr, false, NOW), Err(Error::Store(reason)));
        assert_eq!(device.status().broken.len(), 1);
        assert!(device.channels().is_empty());
        // A rejection writes nothing and creates no store (T05).
        assert_eq!(fixture.vault.get_raw(&dir), planted);
        assert_eq!(fixture.vault.clone().list().unwrap().len(), 1);

        fixture.faults.fail_remove(true);
        assert_eq!(
            device.import_qr(&qr, true, NOW),
            Err(Error::Store(StoreError::Io))
        );
        assert_eq!(device.status().broken.len(), 1);
        assert_eq!(fixture.vault.get_raw(&dir), planted);
        fixture.faults.fail_remove(false);

        let imported = device.import_qr(&qr, true, NOW).unwrap();
        assert!(imported.is_new);
        assert!(device.status().broken.is_empty());
        assert_eq!(listed(&device), [config(1).channel_id()]);
        let (state, _) = MemoryStore::handle(&fixture.vault, dir)
            .load()
            .unwrap()
            .unwrap();
        assert_eq!(state.channel_id, config(1).channel_id());
    }
}

/// Spec 027, R5: an `Io`-broken channel whose directory reads again opens
/// as existing, one entry fewer in `broken`; one whose retry fails keeps
/// its entry, now with the `channel_id` and the name.
#[test]
fn s027_t05_r05_import_retries_an_io_entry() {
    let fixture = with_settings();
    let dir = fixture.plant_channel(1, Vec::new());
    let planted = fixture.vault.get_raw(&dir);
    fixture.faults.fail_loads(true);
    let mut device = fixture.open().unwrap();
    let qr = qr_of(&config(1));
    assert_eq!(
        device.import_qr(&qr, true, NOW),
        Err(Error::Store(StoreError::Io))
    );
    assert_eq!(fixture.vault.get_raw(&dir), planted);
    let broken = device.status().broken;
    assert_eq!(broken.len(), 1);
    assert_eq!(broken[0].reason, StoreError::Io);
    assert_eq!(broken[0].channel_id, Some(config(1).channel_id()));
    assert_eq!(broken[0].channel_name.as_deref(), Some("room"));
    assert!(device.channels().is_empty());

    fixture.faults.fail_loads(false);
    let imported = device.import_qr(&qr, false, NOW).unwrap();
    assert!(!imported.is_new);
    assert!(device.status().broken.is_empty());
    assert_eq!(listed(&device), [config(1).channel_id()]);
}

/// Spec 027, R5: an `Io`-broken channel that reads again with another
/// server is opened, and the import is `ConfigMismatch`.
#[test]
fn s027_t05_r05_retried_entry_checks_the_server() {
    let fixture = with_settings();
    fixture.plant_channel(1, Vec::new());
    fixture.faults.fail_loads(true);
    let mut device = fixture.open().unwrap();
    fixture.faults.fail_loads(false);
    let other = qr_of(&config_on(1, OTHER_SERVER));
    assert_eq!(
        device.import_qr(&other, false, NOW),
        Err(Error::ConfigMismatch)
    );
    assert_eq!(listed(&device), [config(1).channel_id()]);
    assert!(device.status().broken.is_empty());
}

/// Spec 027, R6: an exported QR and file import on a second device as the
/// same channel.
#[test]
fn s027_t06_r06_export() {
    let fixture = with_settings();
    let mut device = fixture.open().unwrap();
    let info = device.create_channel(SERVER, 3_600, "room", NOW).unwrap();
    let qr = device.export_qr(info.id, NOW).unwrap();
    let exported = device.export_file(info.id, NOW).unwrap();
    assert_eq!(device.export_qr([0; 16], NOW), Err(Error::UnknownChannel));
    assert!(matches!(
        device.export_file([0; 16], NOW),
        Err(Error::UnknownChannel)
    ));

    let other = with_settings();
    let mut second = other.open().unwrap();
    let from_qr = second.import_qr(&qr, false, NOW).unwrap();
    assert!(from_qr.is_new);
    assert_eq!(from_qr.info.id, info.id);
    assert_eq!(from_qr.info.server_url, SERVER);
    let other = with_settings();
    let mut third = other.open().unwrap();
    let from_file = third
        .import_file(&exported.file, &exported.password, false, NOW)
        .unwrap();
    assert_eq!(from_file.info.id, info.id);
}

/// Spec 027, R7: channels in opening order with their fields; rename,
/// clear, and invalid names → `BadPayload` with no commit.
#[test]
fn s027_t07_r07_channels_and_rename() {
    let fixture = with_settings();
    let mut device = fixture.open().unwrap();
    let ids: Vec<[u8; 16]> = (1..=3)
        .map(|k| {
            let imported = device.import_qr(&qr_of(&config(k)), false, NOW).unwrap();
            imported.info.id
        })
        .collect();
    assert_eq!(listed(&device), ids);
    let info = &device.channels()[0];
    assert_eq!(info.local_name, None);
    assert_eq!(info.own_display_name, None);
    assert!(!info.write_failed);
    assert!(!info.needs_proxy);

    let id = ids[0];
    device.rename_channel(id, "kitchen").unwrap();
    assert_eq!(device.channels()[0].local_name.as_deref(), Some("kitchen"));
    let dir = fixture.vault.dir_name(&id).unwrap();
    let handle = MemoryStore::handle(&fixture.vault, dir);
    let commits = handle.commits();
    for bad in [
        "x".repeat(65),
        "a\u{7}b".to_owned(),
        "\u{200b}\u{2060}".to_owned(),
        " ".to_owned(),
    ] {
        assert_eq!(device.rename_channel(id, &bad), Err(Error::BadPayload));
    }
    assert_eq!(handle.commits(), commits);
    assert_eq!(
        device.rename_channel([0; 16], "x"),
        Err(Error::UnknownChannel)
    );
    device.rename_channel(id, &"x".repeat(64)).unwrap();
    device.rename_channel(id, "").unwrap();
    assert_eq!(device.channels()[0].local_name, None);
    device.rename_channel(id, "kit\u{202e}chen").unwrap();
    drop(device);
    let device = fixture.open().unwrap();
    let info = device
        .channels()
        .into_iter()
        .find(|info| info.id == id)
        .unwrap();
    assert_eq!(info.local_name.as_deref(), Some("kitchen"));
}

/// Spec 027, R7: the names of a `ChannelInfo` are cleaned: no U+202E, an
/// invisible-only suggested name `""` and an invisible-only own name
/// `None`.
#[test]
fn s027_t07_r07_names_are_cleaned() {
    let fixture = with_settings();
    let mut device = fixture.open().unwrap();
    let rlo = Config::from_parts(
        Secret::from_bytes([1; 32]),
        SERVER,
        3_600,
        "ro\u{202e}om",
        0,
    )
    .unwrap();
    let blank =
        Config::from_parts(Secret::from_bytes([2; 32]), SERVER, 3_600, "\u{200b}", 0).unwrap();
    let rlo = device.import_qr(&qr_of(&rlo), false, NOW).unwrap().info;
    let blank = device.import_qr(&qr_of(&blank), false, NOW).unwrap().info;
    assert_eq!(rlo.suggested_name, "room");
    assert_eq!(blank.suggested_name, "");
    drop(device);

    for (k, own, shown) in [(1, "me\u{202e}", Some("me")), (2, "\u{200b}\u{3164}", None)] {
        let dir = fixture.vault.dir_name(&config(k).channel_id()).unwrap();
        let mut store = MemoryStore::handle(&fixture.vault, dir);
        let (mut state, _) = store.load().unwrap().unwrap();
        state.own_display_name = Some(own.to_owned());
        store.commit(&batch(state, Vec::new())).unwrap();
        let device = fixture.open().unwrap();
        let info = device
            .channels()
            .into_iter()
            .find(|info| info.id == config(k).channel_id())
            .unwrap();
        assert_eq!(info.own_display_name.as_deref(), shown, "{k}");
    }
}

/// Spec 027, R8: the channel and its directory are gone; a failing
/// `destroy` → the error, the channel still listed and usable.
#[test]
fn s027_t08_r08_leave() {
    let fixture = with_settings();
    let mut device = fixture.open().unwrap();
    let kept = device.import_qr(&qr_of(&config(1)), false, NOW).unwrap();
    let left = device.import_qr(&qr_of(&config(2)), false, NOW).unwrap();

    fixture.faults.fail_at(1);
    assert_eq!(
        device.leave(left.info.id),
        Err(Error::Store(StoreError::Io))
    );
    assert_eq!(listed(&device), [kept.info.id, left.info.id]);
    device.rename_channel(left.info.id, "still here").unwrap();

    device.leave(left.info.id).unwrap();
    assert_eq!(listed(&device), [kept.info.id]);
    assert_eq!(device.leave(left.info.id), Err(Error::UnknownChannel));
    drop(device);
    assert_eq!(listed(&fixture.open().unwrap()), [kept.info.id]);
    assert_eq!(fixture.vault.clone().list().unwrap().len(), 1);
}

/// Spec 027, R21: `create_channel`, the imports, `rename_channel` and
/// `leave` under a failing vault → the state after reopening is the one
/// before.
#[test]
fn s027_t21_r21_failing_channel_writes() {
    let fixture = with_settings();
    let mut device = fixture.open().unwrap();
    let id = device
        .import_qr(&qr_of(&config(1)), false, NOW)
        .unwrap()
        .info
        .id;
    device.rename_channel(id, "kitchen").unwrap();
    let before = device.channels();

    fixture.faults.fail_commits(true);
    assert!(device.create_channel(SERVER, 3_600, "room", NOW).is_err());
    assert!(device.import_qr(&qr_of(&config(2)), false, NOW).is_err());
    let (file, password) = config(3).export_encrypted(NOW).unwrap();
    assert!(device.import_file(&file, &password, false, NOW).is_err());
    assert!(device.rename_channel(id, "hall").is_err());
    fixture.faults.fail_commits(false);
    fixture.faults.fail_create(true);
    assert!(device.create_channel(SERVER, 3_600, "room", NOW).is_err());
    fixture.faults.fail_create(false);
    fixture.faults.fail_at(1);
    assert!(device.leave(id).is_err());
    drop(device);

    let device = fixture.open().unwrap();
    assert_eq!(device.channels(), before);
}

/// Spec 027, R1: a channel created behind the gate of R2, or over a newer
/// app's settings, saves nothing; once a fresh install has saved, the next
/// channel does not save again.
#[test]
fn s027_t01_r01_channels_save_only_fresh_settings() {
    let fixture = Fixture::new();
    fixture.plant_channel(1, Vec::new());
    let mut device = fixture.open().unwrap();
    assert!(device.status().settings_reset);
    device.create_channel(SERVER, 3_600, "room", NOW).unwrap();
    assert!(fixture.vault.settings_raw().is_none());
    assert!(device.status().settings_reset);

    let fixture = Fixture::new();
    fixture.plant_channel(1, Vec::new());
    fixture.plant_newer_settings();
    let planted = fixture.vault.settings_raw();
    let mut device = fixture.open().unwrap();
    device.import_qr(&qr_of(&config(2)), false, NOW).unwrap();
    assert_eq!(fixture.vault.settings_raw(), planted);

    let fixture = Fixture::new();
    let mut device = fixture.open().unwrap();
    device.create_channel(SERVER, 3_600, "room", NOW).unwrap();
    fixture.faults.fail_save_settings(true);
    device.create_channel(SERVER, 3_600, "hall", NOW).unwrap();
}

/// Spec 027, R5: an `Io`-broken entry whose import retry fails with
/// another error takes that error as its reason.
#[test]
fn s027_t05_r05_failed_retry_records_its_reason() {
    let fixture = with_settings();
    let dir = fixture.plant_channel(1, Vec::new());
    fixture.faults.fail_loads(true);
    let mut device = fixture.open().unwrap();
    fixture.faults.fail_loads(false);
    fixture.vault.put_raw(&dir, Some(b"not a state"), None);
    assert_eq!(
        device.import_qr(&qr_of(&config(1)), false, NOW),
        Err(Error::Store(StoreError::Corrupt))
    );
    assert_eq!(device.status().broken[0].reason, StoreError::Corrupt);
}

/// Spec 027, R7: a suggested name of white space alone reads `""`, a fresh
/// channel shows no status flag, and `needs_proxy` follows the proxy.
#[test]
fn s027_t07_r07_info_fields() {
    let fixture = with_settings();
    let mut device = fixture.open().unwrap();
    let blank = Config::from_parts(Secret::from_bytes([1; 32]), SERVER, 3_600, "  ", 0).unwrap();
    let info = device.import_qr(&qr_of(&blank), false, NOW).unwrap().info;
    assert_eq!(info.suggested_name, "");
    assert!(!info.status.read_only);

    let onion = format!(
        "wss://{}.onion",
        "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx"
    );
    let id = device
        .import_qr(&qr_of(&config_on(2, &onion)), false, NOW)
        .unwrap()
        .info
        .id;
    let needs = |device: &Device| {
        device
            .channels()
            .into_iter()
            .find(|info| info.id == id)
            .unwrap()
            .needs_proxy
    };
    assert!(needs(&device));
    device.set_socks5_proxy(Some("127.0.0.1:9050")).unwrap();
    assert!(!needs(&device));
}
