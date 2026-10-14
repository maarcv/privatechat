//! `Device`, the one handle at the core boundary (spec 027-core-api, ADR
//! 0037): it owns the vault, every open channel, the channels that could
//! not be opened and the settings, and every call names a channel by its
//! `channel_id`.
//!
//! This module opens the device and keeps the broken channels (R1, R3);
//! `settings.rs` keeps the settings and their gate (R1, R2, R13),
//! `channels.rs` the channels (R4–R8), `dispatch.rs` the per-channel
//! calls (R9), `recovery.rs` the reopening of a failed store (R14, R15),
//! `plan.rs` the routes (R10), `routing.rs` the connections (R11) and
//! `tick.rs` the tick, the probes and `flush` (R12, R24).

use std::collections::BTreeMap;

use crate::crypto;
use crate::error::Error;
use crate::session::channel::Channel;
use crate::session::connection::Event;
use crate::storage::{DirName, StoreError, Vault};

mod channels;
mod dispatch;
mod plan;
mod recovery;
mod routing;
mod settings;
mod tick;

pub use self::channels::{ChannelInfo, ExportedFile, Imported};
pub use self::dispatch::Sent;
pub use self::plan::{ConnectionPlan, Route, probe_hello};
use self::routing::Link;
use self::settings::SettingsHolder;
pub use self::settings::SettingsView;

#[cfg(test)]
mod tests;

/// What the client shows about the device as a whole (R1, R2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceStatus {
    /// The settings were lost, and nothing connects until the user has seen
    /// it (R2).
    pub settings_reset: bool,
    /// Why: the error `load_settings` returned, `None` for an absent file;
    /// `UnsupportedVersion` stays while the settings of a newer app are
    /// kept unwritten (R2).
    pub settings_reason: Option<StoreError>,
    /// The channel directories that could not be opened.
    pub broken: Vec<BrokenChannel>,
}

/// A channel directory that could not be opened (R1, R3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BrokenChannel {
    /// The directory name, 32 lowercase hex characters.
    pub name: String,
    /// Why it could not be opened.
    pub reason: StoreError,
    /// The channel, when this device knew it before it broke (R4, R5, R14).
    pub channel_id: Option<[u8; 16]>,
    /// The channel's name, when this device knew it before it broke.
    pub channel_name: Option<String>,
}

/// A broken channel and the directory `remove_broken` removes.
struct Broken {
    dir: DirName,
    info: BrokenChannel,
    /// When its reason was last recorded, or `u64::MAX` once a `leave` or
    /// a `remove_broken` made its retry due (R3); it times the retry of an
    /// `Io` entry that carries its `channel_id` (R12).
    recorded_at: u64,
}

/// This device: the vault, the open channels in the order they were opened
/// or created, the broken ones and the settings. Its channels hold their
/// keys, so it is neither copied nor printed (R20):
///
/// ```compile_fail
/// fn copy(device: &privatechat_core::Device) -> privatechat_core::Device {
///     device.clone()
/// }
/// ```
///
/// ```compile_fail
/// fn show(device: &privatechat_core::Device) -> String {
///     format!("{device:?}")
/// }
/// ```
///
/// ```compile_fail
/// fn show(device: &privatechat_core::Device) -> String {
///     device.to_string()
/// }
/// ```
///
/// and the config it holds is not reachable from outside `core` (R17):
///
/// ```compile_fail
/// use privatechat_core::Config;
/// ```
pub struct Device {
    vault: Box<dyn Vault>,
    channels: Vec<Channel>,
    /// The probe time of each `write_failed` channel (R14).
    marks: BTreeMap<[u8; 16], u64>,
    /// When each channel's mark was last cleared (R12, R14).
    cleared: BTreeMap<[u8; 16], u64>,
    broken: Vec<Broken>,
    settings: SettingsHolder,
    /// The events produced outside a call that returns events, for the
    /// next `on_tick` (R14).
    queued: Vec<Event>,
    /// The `now` of the last call that carried one, which times the calls
    /// that take none (R14).
    latest_now: u64,
    /// The runs of the connection plan (R10).
    runs: Vec<ConnectionPlan>,
    /// The last plan `id` minted.
    next_plan_id: u64,
    /// The session of each plan `id` (R11).
    links: BTreeMap<u64, Link>,
}

impl Device {
    /// Opens every channel of `vault` and loads the settings (R1).
    ///
    /// A channel whose store fails to open is listed in
    /// `status().broken`; lost or unreadable settings are replaced in
    /// memory by the defaults and set `settings_reset`, so that nothing
    /// connects before the user has seen it (R2).
    ///
    /// # Errors
    ///
    /// `Store(e)` when the vault cannot list its stores; any error of
    /// opening a channel other than a `Store` one.
    pub fn open(mut vault: Box<dyn Vault>, now: u64) -> Result<Device, Error> {
        let stores = vault.list()?;
        let settings = SettingsHolder::load(vault.as_mut(), !stores.is_empty());
        let mut device = Device {
            vault,
            channels: Vec::new(),
            marks: BTreeMap::new(),
            cleared: BTreeMap::new(),
            broken: Vec::new(),
            settings,
            queued: Vec::new(),
            latest_now: now,
            runs: Vec::new(),
            next_plan_id: 0,
            links: BTreeMap::new(),
        };
        for store in stores {
            let dir = *store.name();
            match Channel::open_stored(store) {
                Ok(channel) => device.channels.push(channel),
                Err(Error::Store(reason)) => device.broken.push(Broken::at_open(dir, reason, now)),
                // R1: any other error fails `open`; `open_stored` returns
                // none today.
                Err(error) => return Err(error),
            }
        }
        let due: Vec<[u8; 16]> = device
            .channels
            .iter()
            .filter(|channel| channel.purge_due(now))
            .map(|channel| channel.config().channel_id())
            .collect();
        for id in due {
            // R15: a failed purge never fails `open`; R14 handles it.
            let (_, events) = device.direct(id, |channel| channel.purge_expired(now), |_| None);
            device.queued.extend(events);
        }
        device.replan();
        Ok(device)
    }

    /// The settings flags and the broken channels (R1, R2).
    pub fn status(&self) -> DeviceStatus {
        DeviceStatus {
            settings_reset: self.settings.is_reset(),
            settings_reason: self.settings.reason(),
            broken: self
                .broken
                .iter()
                .map(|broken| broken.info.clone())
                .collect(),
        }
    }

    /// Removes the directory of the broken channel `name` (R3).
    ///
    /// # Errors
    ///
    /// `UnknownChannel` for a name not in `status().broken`; the error of
    /// `Vault::remove`, the entry kept.
    pub fn remove_broken(&mut self, name: &str) -> Result<(), Error> {
        let (position, dir) = self
            .broken
            .iter()
            .enumerate()
            .find(|(_, broken)| broken.info.name == name)
            .map(|(position, broken)| (position, broken.dir))
            .ok_or(Error::UnknownChannel)?;
        self.vault.remove(&dir)?;
        self.broken.remove(position);
        // Space may have been freed (R3).
        self.make_reopens_due();
        Ok(())
    }
}

/// Initialises libsodium once (R20); every other function works whether or
/// not it was called (spec 010-primitives-wrapper R2).
///
/// # Errors
///
/// `Internal` when libsodium cannot initialise.
pub fn init() -> Result<(), Error> {
    Ok(crypto::init()?)
}

/// Fills `out` with 32 bytes of libsodium's `randombytes_buf`, the storage
/// key `K_db` a client draws (spec 040-uniffi R8).
///
/// # Errors
///
/// `Internal` when libsodium cannot initialise.
pub fn generate_storage_key(out: &mut [u8; 32]) -> Result<(), Error> {
    Ok(crypto::fill_random(out)?)
}

impl Broken {
    /// A directory `open` could not open: nothing is known of its channel.
    fn at_open(dir: DirName, reason: StoreError, now: u64) -> Broken {
        Broken {
            dir,
            info: BrokenChannel {
                name: dir.to_hex(),
                reason,
                channel_id: None,
                channel_name: None,
            },
            recorded_at: now,
        }
    }
}
