//! Tests of spec 027-core-api over `MemoryVault`, each requirement checked
//! through the calls of `Device` and what a reopened vault holds.

use super::Device;
use crate::Error;
use crate::crypto::Secret;
use crate::proto::config::Config;
use crate::session::channel::Channel;
use crate::storage::{DirName, LogRecord, Settings, Store, StoreError, Vault};
use crate::testing::{FailingVault, Faults, MemoryStore, MemoryVault, batch, record, state_for};

mod channels;
mod dispatch;
mod plan;
mod recovery;
mod scripted;
mod settings;

/// A whole minute.
const NOW: u64 = 1_790_000_040_000;
const SERVER: &str = "wss://example.org";
const DAY_MS: u64 = 86_400_000;

/// A vault in memory, its faults, and a handle to each.
struct Fixture {
    vault: MemoryVault,
    faults: Faults,
}

impl Fixture {
    fn new() -> Fixture {
        Fixture {
            vault: MemoryVault::new(),
            faults: Faults::new(),
        }
    }

    /// A `Device` over this vault, as at an unlock.
    fn open(&self) -> Result<Device, Error> {
        let vault = FailingVault::new(Box::new(self.vault.clone()), self.faults.clone());
        Device::open(Box::new(vault), NOW)
    }

    /// Saves `settings` straight to the vault.
    fn save_settings(&self, settings: &Settings) {
        self.vault.clone().save_settings(settings).unwrap();
    }

    /// The settings the vault holds.
    fn stored_settings(&self) -> Option<Settings> {
        self.vault.clone().load_settings().unwrap()
    }

    /// Commits a one-hour channel of key `k` and `records` to the vault,
    /// and returns its directory.
    fn plant_channel(&self, k: u8, records: Vec<LogRecord>) -> DirName {
        let config = config(k);
        let mut vault = self.vault.clone();
        let store = vault.create(&config.channel_id()).unwrap();
        let name = *store.name();
        let (channel, created) = Channel::create(&config, store).unwrap();
        assert!(created);
        drop(channel);
        if !records.is_empty() {
            let mut store = MemoryStore::handle(&self.vault, name);
            let (state, _) = store.load().unwrap().unwrap();
            store.commit(&batch(state, records)).unwrap();
        }
        name
    }

    /// Plants a directory whose state does not open.
    fn plant_corrupt(&self, n: u8) -> DirName {
        let name = DirName([n; 16]);
        self.vault.put_raw(&name, Some(b"not a state"), None);
        name
    }

    /// Commits a channel whose stored config is of a newer version.
    fn plant_newer(&self, k: u8) -> DirName {
        let config = config(k);
        let mut store = self.vault.clone().create(&config.channel_id()).unwrap();
        let mut state = state_for(config.channel_id());
        let mut record = config.record(None).unwrap().to_vec();
        // Key 0 of the record, `config_version`, is its sixth byte.
        record[5] = 2;
        *state.config = record;
        store.commit(&batch(state, Vec::new())).unwrap();
        *store.name()
    }

    /// Plants a `settings.bin` of `settings_version` 2.
    fn plant_newer_settings(&self) {
        let mut record = crate::testing::settings(SERVER, 30, None)
            .encode()
            .unwrap()
            .to_vec();
        // Key 0 of the record, `settings_version`, is its sixth byte.
        record[5] = 2;
        self.vault.put_settings_record(&record).unwrap();
    }
}

/// A one-hour channel config of key `[k; 32]` on `SERVER`.
fn config(k: u8) -> Config {
    Config::from_parts(Secret::from_bytes([k; 32]), SERVER, 3_600, "room", 0).unwrap()
}

/// The `channel_id`s of the open channels, in order.
fn open_ids(device: &Device) -> Vec<[u8; 16]> {
    device
        .channels
        .iter()
        .map(|channel| channel.config().channel_id())
        .collect()
}

/// Spec 027, R1: good channels open, broken ones are listed with their
/// reasons, a due purge runs, and the settings fall back to the defaults
/// in memory, with the gate up when they were lost on a device with
/// channels.
#[test]
fn s027_t01_r01_open() {
    let fixture = Fixture::new();
    fixture.save_settings(&crate::testing::settings(SERVER, 30, None));
    fixture.plant_channel(1, Vec::new());
    fixture.plant_channel(2, Vec::new());
    let corrupt = fixture.plant_corrupt(0xc0);
    let newer = fixture.plant_newer(3);
    let device = fixture.open().unwrap();
    let mut ids = open_ids(&device);
    ids.sort_unstable();
    let mut expected = vec![config(1).channel_id(), config(2).channel_id()];
    expected.sort_unstable();
    assert_eq!(ids, expected);
    let mut broken = device.status().broken;
    broken.sort_by(|a, b| a.name.cmp(&b.name));
    let mut want = vec![
        (corrupt.to_hex(), StoreError::Corrupt),
        (newer.to_hex(), StoreError::UnsupportedVersion),
    ];
    want.sort_by(|a, b| a.0.cmp(&b.0));
    let got: Vec<_> = broken
        .iter()
        .map(|broken| (broken.name.clone(), broken.reason))
        .collect();
    assert_eq!(got, want);
    assert!(broken.iter().all(|broken| broken.channel_id.is_none()));
    assert!(broken.iter().all(|broken| broken.channel_name.is_none()));
    assert!(broken.iter().any(|broken| broken.name == "c0".repeat(16)));
    let status = device.status();
    assert!(!status.settings_reset);
    assert_eq!(status.settings_reason, None);
    assert_eq!(device.settings().lock_timeout_seconds, 30);
}

/// Spec 027, R1: a channel whose expired records reach a quarter of its
/// log is purged at `open`; one below that threshold is not.
#[test]
fn s027_t01_r01_open_purges_due_channels() {
    let fixture = Fixture::new();
    let expired = NOW - 1;
    let due = fixture.plant_channel(1, vec![record(expired, 1_000), record(NOW + DAY_MS, 100)]);
    let not_due = fixture.plant_channel(2, vec![record(expired, 10), record(NOW + DAY_MS, 10_000)]);
    let due_len = MemoryStore::handle(&fixture.vault, due).log_len();
    let not_due_len = MemoryStore::handle(&fixture.vault, not_due).log_len();
    drop(fixture.open().unwrap());
    assert!(MemoryStore::handle(&fixture.vault, due).log_len() < due_len);
    assert_eq!(
        MemoryStore::handle(&fixture.vault, not_due).log_len(),
        not_due_len
    );
}

/// Spec 027, R1: a purge that fails at `open` does not fail it.
#[test]
fn s027_t01_r01_open_survives_a_failed_purge() {
    let fixture = Fixture::new();
    let due = fixture.plant_channel(1, vec![record(NOW - 1, 1_000)]);
    let len = MemoryStore::handle(&fixture.vault, due).log_len();
    fixture.faults.fail_compactions(true);
    let device = fixture.open().unwrap();
    assert_eq!(open_ids(&device), [config(1).channel_id()]);
    assert_eq!(MemoryStore::handle(&fixture.vault, due).log_len(), len);
}

/// Spec 027, R1: `list` failing with `Io` fails `open`.
#[test]
fn s027_t01_r01_open_fails_when_list_fails() {
    let fixture = Fixture::new();
    fixture.plant_channel(1, Vec::new());
    fixture.faults.fail_list(true);
    assert!(matches!(fixture.open(), Err(Error::Store(StoreError::Io))));
}

/// Spec 027, R1: settings unreadable (`Io`), corrupt or newer, or absent
/// with channels → the defaults in memory, nothing saved, `settings_reset`
/// with the reason; absent on a fresh install → the defaults, no flag,
/// nothing saved.
#[test]
fn s027_t01_r01_open_settings_fallbacks() {
    type Plant = fn(&Fixture);
    let cases: [(Plant, Option<StoreError>); 4] = [
        (
            |fixture| {
                fixture.save_settings(&crate::testing::settings(SERVER, 30, None));
                fixture.faults.fail_load_settings(true);
            },
            Some(StoreError::Io),
        ),
        (
            |fixture| fixture.vault.put_settings_raw(b"not a settings box"),
            Some(StoreError::Corrupt),
        ),
        (
            Fixture::plant_newer_settings,
            Some(StoreError::UnsupportedVersion),
        ),
        (|_| {}, None),
    ];
    for (plant, reason) in cases {
        let fixture = Fixture::new();
        fixture.plant_channel(1, Vec::new());
        plant(&fixture);
        let before = fixture.vault.settings_raw();
        let device = fixture.open().unwrap();
        let status = device.status();
        assert!(status.settings_reset, "{reason:?}");
        assert_eq!(status.settings_reason, reason);
        assert_eq!(device.settings(), defaults_view());
        assert_eq!(fixture.vault.settings_raw(), before, "{reason:?}");
    }

    let fixture = Fixture::new();
    let device = fixture.open().unwrap();
    let status = device.status();
    assert!(!status.settings_reset);
    assert_eq!(status.settings_reason, None);
    assert_eq!(device.settings(), defaults_view());
    assert!(fixture.vault.settings_raw().is_none());
}

/// Spec 027, R1: with `settings.bin` deleted and the channel directories
/// hidden for one unlock, then restored, the next `open` raises the gate:
/// the unlock that saw no channel saved nothing.
#[test]
fn s027_t01_r01_hidden_channels_save_nothing() {
    let fixture = Fixture::new();
    let name = fixture.plant_channel(1, Vec::new());
    let (state, log) = fixture.vault.get_raw(&name);
    fixture.vault.put_raw(&name, None, None);
    let device = fixture.open().unwrap();
    assert!(device.channels.is_empty());
    assert!(!device.status().settings_reset);
    drop(device);
    assert!(fixture.vault.settings_raw().is_none());
    fixture
        .vault
        .put_raw(&name, state.as_deref(), log.as_deref());
    let device = fixture.open().unwrap();
    assert_eq!(open_ids(&device), [config(1).channel_id()]);
    assert!(device.status().settings_reset);
    assert_eq!(device.status().settings_reason, None);
}

/// The defaults of R13 as `settings()` shows them.
fn defaults_view() -> super::SettingsView {
    super::SettingsView {
        default_server_url: crate::DEFAULT_SERVER_URL.to_owned(),
        lock_timeout_seconds: 60,
        socks5_proxy: None,
    }
}

/// Spec 027, R3: the broken name is removed and leaves `broken`; another
/// name is `UnknownChannel` with nothing removed; a failing `remove`
/// returns its error and keeps the entry.
#[test]
fn s027_t03_r03_remove_broken() {
    let fixture = Fixture::new();
    let corrupt = fixture.plant_corrupt(0xc0);
    let newer = fixture.plant_newer(3);
    let mut device = fixture.open().unwrap();
    assert_eq!(device.status().broken.len(), 2);

    let other = DirName([0xee; 16]).to_hex();
    assert_eq!(device.remove_broken(&other), Err(Error::UnknownChannel));
    assert_eq!(device.status().broken.len(), 2);

    fixture.faults.fail_remove(true);
    assert_eq!(
        device.remove_broken(&corrupt.to_hex()),
        Err(Error::Store(StoreError::Io))
    );
    assert_eq!(device.status().broken.len(), 2);
    fixture.faults.fail_remove(false);

    device.remove_broken(&corrupt.to_hex()).unwrap();
    let broken = device.status().broken;
    assert_eq!(broken.len(), 1);
    assert_eq!(broken[0].name, newer.to_hex());
    assert_eq!(
        device.remove_broken(&corrupt.to_hex()),
        Err(Error::UnknownChannel)
    );
    drop(device);
    let device = fixture.open().unwrap();
    let names: Vec<String> = device.status().broken.into_iter().map(|b| b.name).collect();
    assert_eq!(names, [newer.to_hex()]);
}

/// Spec 027, R21: `remove_broken` under a failing vault leaves the
/// directory in place after reopening.
#[test]
fn s027_t21_r21_failing_remove_broken() {
    let fixture = Fixture::new();
    let corrupt = fixture.plant_corrupt(0xc0);
    let mut device = fixture.open().unwrap();
    fixture.faults.fail_remove(true);
    assert!(device.remove_broken(&corrupt.to_hex()).is_err());
    drop(device);
    fixture.faults.fail_remove(false);
    let device = fixture.open().unwrap();
    let names: Vec<String> = device.status().broken.into_iter().map(|b| b.name).collect();
    assert_eq!(names, [corrupt.to_hex()]);
}

/// Spec 027, R3: an `Io` entry from `open`, which carries no
/// `channel_id`, is removed by `remove_broken`.
#[test]
fn s027_t03_r03_remove_io_broken() {
    let fixture = Fixture::new();
    let name = fixture.plant_channel(1, Vec::new());
    fixture.faults.fail_loads(true);
    let mut device = fixture.open().unwrap();
    fixture.faults.fail_loads(false);
    let broken = device.status().broken;
    assert_eq!(broken.len(), 1);
    assert_eq!(broken[0].reason, StoreError::Io);
    assert_eq!(broken[0].channel_id, None);
    assert_eq!(broken[0].channel_name, None);
    // The fault cleared, the next `open` opens it again (R12).
    let reopened = fixture.open().unwrap();
    assert_eq!(open_ids(&reopened), [config(1).channel_id()]);
    drop(reopened);
    device.remove_broken(&name.to_hex()).unwrap();
    assert!(device.status().broken.is_empty());
    drop(device);
    let device = fixture.open().unwrap();
    assert!(device.channels.is_empty());
    assert!(device.status().broken.is_empty());
}

/// The probe time of the first open channel, when it is `write_failed`.
fn first_probe_at(device: &Device) -> Option<u64> {
    let id = device.channels.first()?.config().channel_id();
    device.marks.get(&id).copied()
}
