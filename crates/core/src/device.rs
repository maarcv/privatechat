//! `Device`, the one handle at the core boundary (spec 027-core-api, ADR
//! 0037): it owns the vault, every open channel, the channels that could
//! not be opened and the settings, and every call names a channel by its
//! `channel_id`.
//!
//! This module opens the device and keeps the broken channels (R1, R3);
//! `settings.rs` keeps the settings and their gate (R1, R2, R13),
//! `channels.rs` the channels (R4–R8) and `plan.rs` the routes (R10).

use crate::error::Error;
use crate::session::channel::Channel;
use crate::storage::{DirName, StoreError, Vault};

mod channels;
mod plan;
mod settings;

pub use self::channels::{ChannelInfo, ExportedFile, Imported};
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
}

/// This device: the vault, the open channels in the order they were opened
/// or created, the broken ones and the settings. It implements neither
/// `Clone`, `Debug` nor `Display` (R20): its channels hold their keys.
pub struct Device {
    vault: Box<dyn Vault>,
    channels: Vec<Channel>,
    broken: Vec<Broken>,
    settings: SettingsHolder,
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
            broken: Vec::new(),
            settings,
        };
        for store in stores {
            let dir = *store.name();
            match Channel::open_stored(store) {
                Ok(channel) => device.channels.push(channel),
                Err(Error::Store(reason)) => device.broken.push(Broken::at_open(dir, reason)),
                // R1: any other error fails `open`; `open_stored` returns
                // none today.
                Err(error) => return Err(error),
            }
        }
        for channel in &mut device.channels {
            if channel.purge_due(now) {
                // R15: a failed purge never fails `open`.
                let _purged = channel.purge_expired(now);
            }
        }
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
        Ok(())
    }
}

impl Broken {
    /// A directory `open` could not open: nothing is known of its channel.
    fn at_open(dir: DirName, reason: StoreError) -> Broken {
        Broken {
            dir,
            info: BrokenChannel {
                name: dir.to_hex(),
                reason,
                channel_id: None,
                channel_name: None,
            },
        }
    }
}
