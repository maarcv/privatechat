//! The `pub` surface of `core` (spec 027-core-api R16, R19): every `pub`
//! function coerced to a function pointer of its exact type, so that a
//! changed or missing signature fails to compile. The records and enums
//! are named by the signatures that carry them.

// The types are written out in full on purpose: they are what is checked.
#![allow(clippy::type_complexity)]

use privatechat_core::{
    ChannelInfo, ChannelState, ChannelStatus, ConfigPreview, ConnectionPlan, DEFAULT_SERVER_URL,
    Device, DeviceStatus, DirName, Error, Event, ExportedFile, Fingerprint, Frame, Gap, Imported,
    LogRecord, MAX_LOG_ENTRY, MAX_LOG_LEN, MAX_SETTINGS_FILE, MAX_STATE_FILE, Message, OldKey,
    Peer, PeerId, Route, Sent, Settings, SettingsView, StorageKey, Store, StoreError, Vault,
    WriteBatch, dir_name, generate_storage_key, init, probe_hello, relay,
};

/// Spec 027, R16: the free functions and the constant of the boundary.
#[test]
fn s027_t16_r16_free_items() {
    let _: fn() -> Result<(), Error> = init;
    let _: fn(&mut [u8; 32]) -> Result<(), Error> = generate_storage_key;
    let _: fn(&[u8]) -> Result<bool, Error> = probe_hello;
    let _: &str = DEFAULT_SERVER_URL;
}

/// Spec 027, R16: the calls of `Device`, opening, settings and channels.
#[test]
fn s027_t16_r16_device_channels() {
    let _: fn(Box<dyn Vault>, u64) -> Result<Device, Error> = Device::open;
    let _: fn(&Device) -> DeviceStatus = Device::status;
    let _: fn(&mut Device, bool) -> Result<(), Error> = Device::acknowledge_settings;
    let _: fn(&mut Device, &str) -> Result<(), Error> = Device::remove_broken;
    let _: fn(&Device) -> Vec<ChannelInfo> = Device::channels;
    let _: fn(&mut Device, &str, u32, &str, u64) -> Result<ChannelInfo, Error> =
        Device::create_channel;
    let _: fn(&mut Device, &[u8], bool, u64) -> Result<Imported, Error> = Device::import_qr;
    let _: fn(&mut Device, [u8; 16], &str) -> Result<(), Error> = Device::rename_channel;
    let _: fn(&mut Device, [u8; 16]) -> Result<(), Error> = Device::leave;
    let _: fn(&Device) -> SettingsView = Device::settings;
    let _: fn(&mut Device, &str) -> Result<(), Error> = Device::set_default_server_url;
    let _: fn(&mut Device, u32) -> Result<(), Error> = Device::set_lock_timeout_seconds;
    let _: fn(&mut Device, Option<&str>) -> Result<(), Error> = Device::set_socks5_proxy;
}

/// Spec 027, R16: the per-channel calls of `Device`.
#[test]
fn s027_t16_r16_device_per_channel() {
    let _: fn(&mut Device, [u8; 16], &str, Option<&str>, u64) -> Result<Sent, Error> = Device::send;
    let _: fn(&Device, [u8; 16], u64) -> Result<Vec<Message>, Error> = Device::messages;
    let _: fn(&mut Device, [u8; 16], u64) -> Result<u32, Error> = Device::purge_expired;
    let _: fn(&Device, [u8; 16]) -> Result<ChannelStatus, Error> = Device::channel_status;
    let _: fn(&Device, [u8; 16]) -> Result<Vec<Gap>, Error> = Device::gaps;
    let _: fn(&Device, [u8; 16]) -> Result<Vec<Peer>, Error> = Device::peers;
    let _: fn(&mut Device, [u8; 16], PeerId, &str, u64) -> Result<(), Error> = Device::label;
    let _: fn(&mut Device, [u8; 16], PeerId, Option<&str>, u64) -> Result<(), Error> =
        Device::verify;
    let _: fn(&mut Device, [u8; 16], &[u8], &str, u64) -> Result<PeerId, Error> =
        Device::verify_scanned;
    let _: fn(&mut Device, [u8; 16], PeerId, bool) -> Result<(), Error> = Device::mute;
    let _: fn(&Device, [u8; 16], PeerId) -> Result<Fingerprint, Error> = Device::fingerprint;
    let _: fn(&Device, [u8; 16]) -> Result<Fingerprint, Error> = Device::own_fingerprint;
    let _: fn(&mut Device, [u8; 16], PeerId, u64) -> Result<(), Error> = Device::retire;
    let _: fn(&mut Device, [u8; 16], u64) -> Result<Vec<Event>, Error> =
        Device::regenerate_identity;
    let _: fn(&Device, [u8; 16]) -> Result<Vec<OldKey>, Error> = Device::own_old_keys;
    let _: fn(&mut Device, [u8; 16], PeerId) -> Result<(), Error> = Device::forget;
}

/// Spec 027, R16: the connections of `Device`.
#[test]
fn s027_t16_r16_device_connections() {
    let _: fn(&Device) -> Vec<ConnectionPlan> = Device::connections;
    let _: fn(&Device, &str) -> Result<Option<Route>, Error> = Device::probe_plan;
    let _: fn(&mut Device, u64, u64) = Device::on_connect;
    let _: fn(&mut Device, u64, &[u8], u64) -> Vec<Event> = Device::on_frame;
    let _: fn(&mut Device, u64) -> Vec<Event> = Device::on_tick;
    let _: fn(&mut Device, u64) -> Vec<Vec<u8>> = Device::outgoing;
    let _: fn(&mut Device, u64) = Device::on_disconnect;
    let _: fn(&mut Device, u64) -> Result<(), Error> = Device::flush;
}

/// Spec 027, R16: the items `pub` for the `store` and `server` crates.
#[test]
fn s027_t16_r16_items_for_other_crates() {
    let _: fn(
        &mut (dyn Store + 'static),
    ) -> Result<Option<(ChannelState, Vec<LogRecord>)>, StoreError> = <dyn Store>::load;
    let _: fn(&mut (dyn Store + 'static), &WriteBatch) -> Result<(), StoreError> =
        <dyn Store>::commit;
    let _: fn(&mut (dyn Store + 'static), &ChannelState, u64) -> Result<u32, StoreError> =
        <dyn Store>::compact;
    let _: fn(&(dyn Store + 'static)) -> u64 = <dyn Store>::log_len;
    let _: fn(&mut (dyn Store + 'static)) -> Result<(), StoreError> = <dyn Store>::destroy;
    let _: fn(&mut (dyn Vault + 'static)) -> Result<Vec<Box<dyn Store>>, StoreError> =
        <dyn Vault>::list;
    let _: fn(&mut (dyn Vault + 'static), &DirName) -> Result<(), StoreError> = <dyn Vault>::remove;
    let _: for<'a> fn(&'a (dyn Store + 'static)) -> &'a DirName = <dyn Store>::name;
    let _: fn(&mut (dyn Vault + 'static), &[u8; 16]) -> Result<Box<dyn Store>, StoreError> =
        <dyn Vault>::create;
    let _: fn(&(dyn Vault + 'static), &[u8; 16]) -> Result<DirName, StoreError> =
        <dyn Vault>::dir_name;
    let _: fn(&mut (dyn Vault + 'static)) -> Result<Option<Settings>, StoreError> =
        <dyn Vault>::load_settings;
    let _: fn(&mut (dyn Vault + 'static), &Settings) -> Result<(), StoreError> =
        <dyn Vault>::save_settings;
    let _: fn(&WriteBatch) -> &ChannelState = WriteBatch::state;
    let _: fn(&WriteBatch) -> &[LogRecord] = WriteBatch::records;
    let _: fn(&StorageKey, &DirName, &[u8]) -> Result<ChannelState, StoreError> =
        ChannelState::open;
    let _: fn(&ChannelState, &StorageKey, &DirName, u64, u32) -> Result<Vec<u8>, StoreError> =
        ChannelState::seal;
    let _: fn(&ChannelState) -> (u64, u32) = ChannelState::log_position;
    let _: fn(&ChannelState) -> [u8; 16] = ChannelState::channel_id;
    let _: fn(&StorageKey, &DirName, &[u8], u32, u64) -> Result<LogRecord, StoreError> =
        LogRecord::open;
    let _: fn(&LogRecord, &StorageKey, &DirName, u32, u64) -> Result<Vec<u8>, StoreError> =
        LogRecord::seal;
    let _: fn(&LogRecord) -> u64 = LogRecord::purge_at;
    let _: fn(&StorageKey, &[u8]) -> Result<Settings, StoreError> = Settings::open;
    let _: fn(&Settings, &StorageKey) -> Result<Vec<u8>, StoreError> = Settings::seal;
    let _: fn(&DirName) -> String = DirName::to_hex;
    let _: fn(&StorageKey, &[u8; 16]) -> Result<DirName, StoreError> = dir_name;
    let _: fn(&Frame) -> Result<Vec<u8>, Error> = Frame::encode;
    let _: fn(&[u8]) -> Result<Frame, Error> = Frame::decode;
    let _: fn() -> Result<[u8; 16], Error> = relay::new_server_id;
    let _: [usize; 3] = [MAX_STATE_FILE, MAX_SETTINGS_FILE, MAX_LOG_ENTRY];
    let _: u64 = MAX_LOG_LEN;
}

/// Spec 027, R25: the previews read the device and take their invitation
/// as bytes.
#[test]
fn s027_t25_r25_preview_signatures() {
    let _: fn(&Device, &[u8], u64) -> Result<ConfigPreview, Error> = Device::preview_qr;
    let _: fn(&Device, &[u8], &[u8], u64) -> Result<ConfigPreview, Error> = Device::preview_file;
}

/// Spec 027, R19: the storage key enters as a mutable array it zeroes, the
/// `.chatcfg` password and the QR text as bytes, in both directions.
#[test]
fn s027_t19_r19_no_secret_as_text() {
    let _: fn(&mut [u8; 32]) -> StorageKey = StorageKey::from_bytes;
    let _: fn(&mut Device, &[u8], &[u8], bool, u64) -> Result<Imported, Error> =
        Device::import_file;
    let _: fn(&Device, [u8; 16], u64) -> Result<Vec<u8>, Error> = Device::export_qr;
    let _: fn(&Device, [u8; 16], u64) -> Result<ExportedFile, Error> = Device::export_file;
    let password: fn(&ExportedFile) -> &Vec<u8> = |exported| &exported.password;
    let _ = password;
    let mut key = [7u8; 32];
    let _ = StorageKey::from_bytes(&mut key);
    assert_eq!(key, [0u8; 32]);
}
