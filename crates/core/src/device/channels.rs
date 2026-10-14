//! The channels of the device (spec 027-core-api R4–R8): creating,
//! importing, exporting, listing, renaming and leaving them, and the
//! recovery of a first commit that poisoned its store.

use super::{Broken, BrokenChannel, Device, Open, plan};
use crate::error::Error;
use crate::proto::config::Config;
use crate::session::channel::{Channel, ChannelStatus};
use crate::session::connection::Event;
use crate::session::names::shown_name;
use crate::storage::StoreError;

/// What the client shows about one open channel (R7).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelInfo {
    /// The `channel_id`.
    pub id: [u8; 16],
    /// The server the channel lives on.
    pub server_url: String,
    /// The name its creator suggested, cleaned; `""` when nothing is left.
    pub suggested_name: String,
    /// The name this device gave it.
    pub local_name: Option<String>,
    /// The name `send` uses by default.
    pub own_display_name: Option<String>,
    /// The time to live of its messages.
    pub ttl_seconds: u32,
    /// What the channel shows.
    pub status: ChannelStatus,
    /// Its store failed and it waits for a probe (R14).
    pub write_failed: bool,
    /// It needs a SOCKS5 proxy running on this device (R10).
    pub needs_proxy: bool,
}

/// An imported channel, and whether it is new on this device (R5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Imported {
    /// The channel.
    pub info: ChannelInfo,
    /// `false` for a channel this device already had.
    pub is_new: bool,
}

/// A `.chatcfg` file and the password that opens it (R6). Both belong to
/// the caller, who zeroizes the password once it is shown.
pub struct ExportedFile {
    /// The file.
    pub file: Vec<u8>,
    /// The seven words, as bytes.
    pub password: Vec<u8>,
}

impl Device {
    /// The open channels, in the order the device opened or created them
    /// (R7).
    pub fn channels(&self) -> Vec<ChannelInfo> {
        self.channels.iter().map(|open| self.info(open)).collect()
    }

    /// Creates a channel on `server_url` (R4).
    ///
    /// # Errors
    ///
    /// `BadConfig` for a URL, TTL or name out of range; `Store(e)` when
    /// the settings of a fresh install, the directory or the first commit
    /// cannot be written; `Internal` when libsodium fails.
    pub fn create_channel(
        &mut self,
        server_url: &str,
        ttl_seconds: u32,
        name: &str,
        now: u64,
    ) -> Result<ChannelInfo, Error> {
        self.latest_now = now;
        let config = Config::create(server_url, ttl_seconds, name, now)?;
        let (info, _) = self.add(&config)?;
        Ok(info)
    }

    /// Imports the channel of a scanned QR (R5).
    ///
    /// # Errors
    ///
    /// The errors of `Config::parse_qr`; `ConfigMismatch` for a channel
    /// already open with another server; `Store(e)` for a broken channel
    /// not replaced, or a store that cannot be written.
    pub fn import_qr(
        &mut self,
        text: &[u8],
        replace_broken: bool,
        now: u64,
    ) -> Result<Imported, Error> {
        self.latest_now = now;
        let config = Config::parse_qr(text, now)?;
        self.import(&config, replace_broken)
    }

    /// Imports the channel of a `.chatcfg` file (R5).
    ///
    /// # Errors
    ///
    /// The errors of `Config::open_encrypted`, then as
    /// [`Device::import_qr`].
    pub fn import_file(
        &mut self,
        bytes: &[u8],
        password: &[u8],
        replace_broken: bool,
        now: u64,
    ) -> Result<Imported, Error> {
        self.latest_now = now;
        let config = Config::open_encrypted(bytes, password, now)?;
        self.import(&config, replace_broken)
    }

    /// The QR text of `channel`, an invitation that expires 10 minutes
    /// after `now` (R6).
    ///
    /// # Errors
    ///
    /// `UnknownChannel`; `Internal` as `Config::export_qr` says.
    pub fn export_qr(&self, channel: [u8; 16], now: u64) -> Result<Vec<u8>, Error> {
        self.channel(channel)?.config().export_qr(now)
    }

    /// A `.chatcfg` file of `channel` and its password (R6).
    ///
    /// # Errors
    ///
    /// `UnknownChannel`; `Internal` as `Config::export_encrypted` says.
    pub fn export_file(&self, channel: [u8; 16], now: u64) -> Result<ExportedFile, Error> {
        let (file, password) = self.channel(channel)?.config().export_encrypted(now)?;
        Ok(ExportedFile { file, password })
    }

    /// Gives `channel` a local name, or clears it for `""` (R7).
    ///
    /// # Errors
    ///
    /// `UnknownChannel`; `BadPayload` for an invalid name; `Store` when the
    /// commit fails.
    pub fn rename_channel(&mut self, channel: [u8; 16], name: &str) -> Result<(), Error> {
        self.write(channel, |open| open.set_local_name(name))
    }

    /// Deletes `channel` and its directory (R8); on `Err` it stays open and
    /// usable. A `write_failed` channel whose poisoned store refuses is
    /// reopened silently once and asked again, so that the user can free
    /// its space.
    ///
    /// # Errors
    ///
    /// `UnknownChannel`; the store's error.
    pub fn leave(&mut self, channel: [u8; 16]) -> Result<(), Error> {
        let mut position = self.position(channel)?;
        let marked = self
            .channels
            .get(position)
            .is_some_and(|open| open.probe_at.is_some());
        let mut result = self.channel_mut(channel)?.leave();
        if marked && result == Err(Error::Store(StoreError::Io)) {
            if self.reopen(position).is_err() {
                self.queued.push(Event::StorageFailed { channel });
                return result;
            }
            position = self.position(channel)?;
            result = self.channel_mut(channel)?.leave();
        }
        result?;
        self.channels.remove(position);
        Ok(())
    }

    /// The `ChannelInfo` of an open channel (R7), its names cleaned as spec
    /// 022-peers-tofu R6 says.
    fn info(&self, open: &Open) -> ChannelInfo {
        let channel = &open.channel;
        let config = channel.config();
        ChannelInfo {
            id: config.channel_id(),
            server_url: config.server_url().to_owned(),
            suggested_name: shown_name(config.suggested_name()).unwrap_or_default(),
            local_name: channel.local_name().and_then(shown_name),
            own_display_name: channel.own_display_name().and_then(shown_name),
            ttl_seconds: config.ttl_seconds(),
            status: channel.status(),
            write_failed: open.probe_at.is_some(),
            needs_proxy: plan::needs_proxy(
                config.server_url(),
                self.settings.current().socks5_proxy.as_deref(),
            ),
        }
    }

    /// The position of the open channel `channel`.
    pub(super) fn position(&self, channel: [u8; 16]) -> Result<usize, Error> {
        self.channels
            .iter()
            .position(|open| open.channel.config().channel_id() == channel)
            .ok_or(Error::UnknownChannel)
    }

    /// The open channel `channel`.
    pub(super) fn channel(&self, channel: [u8; 16]) -> Result<&Channel, Error> {
        let position = self.position(channel)?;
        self.channels
            .get(position)
            .map(|open| &open.channel)
            .ok_or(Error::UnknownChannel)
    }

    /// The open channel `channel`, to change.
    pub(super) fn channel_mut(&mut self, channel: [u8; 16]) -> Result<&mut Channel, Error> {
        let position = self.position(channel)?;
        self.channels
            .get_mut(position)
            .map(|open| &mut open.channel)
            .ok_or(Error::UnknownChannel)
    }

    /// R5 for a parsed `config`: an open channel answers at once, a broken
    /// one is retried or replaced, and any other is created.
    fn import(&mut self, config: &Config, replace_broken: bool) -> Result<Imported, Error> {
        let id = config.channel_id();
        if self.position(id).is_ok() {
            return self.existing(config);
        }
        let dir = self.vault.dir_name(&id)?;
        if let Some(position) = self.broken.iter().position(|broken| broken.dir == dir) {
            if self.retry_broken(position, config)? {
                return self.existing(config);
            }
            let reason = self
                .broken
                .get(position)
                .map_or(StoreError::Io, |broken| broken.info.reason);
            let replaceable =
                matches!(reason, StoreError::Corrupt | StoreError::UnsupportedVersion);
            if !(replaceable && replace_broken) {
                return Err(Error::Store(reason));
            }
            self.vault.remove(&dir)?;
            self.broken.remove(position);
        }
        let (info, is_new) = self.add(config)?;
        Ok(Imported { info, is_new })
    }

    /// The answer for a channel already open: itself when the server
    /// matches (R5, `docs/spec.md` §5).
    fn existing(&self, config: &Config) -> Result<Imported, Error> {
        let position = self.position(config.channel_id())?;
        let open = self.channels.get(position).ok_or(Error::UnknownChannel)?;
        if open.channel.config().server_url() != config.server_url() {
            return Err(Error::ConfigMismatch);
        }
        Ok(Imported {
            info: self.info(open),
            is_new: false,
        })
    }

    /// Retries opening the broken entry at `position` when its reason is
    /// `Io` (R5): `true` when it opened, its entry dropped; on failure the
    /// entry takes the retry's error, the `channel_id` and the name.
    fn retry_broken(&mut self, position: usize, config: &Config) -> Result<bool, Error> {
        let Some(broken) = self.broken.get(position) else {
            return Ok(false);
        };
        if broken.info.reason != StoreError::Io {
            return Ok(false);
        }
        let opened = self
            .vault
            .create(&config.channel_id())
            .map_err(Error::Store)
            .and_then(Channel::open_stored);
        match opened {
            Ok(channel) => {
                self.broken.remove(position);
                self.channels.push(Open {
                    channel,
                    probe_at: None,
                });
                Ok(true)
            }
            Err(Error::Store(reason)) => {
                if let Some(broken) = self.broken.get_mut(position) {
                    broken.info.reason = reason;
                    broken.info.channel_id = Some(config.channel_id());
                    broken.info.channel_name = shown_name(config.suggested_name());
                }
                Ok(false)
            }
            Err(error) => Err(error),
        }
    }

    /// Creates the store of `config` and its channel, or opens the one it
    /// holds (R4, R5), saving the settings of a fresh install first (R1).
    fn add(&mut self, config: &Config) -> Result<(ChannelInfo, bool), Error> {
        self.settings.save_if_fresh(self.vault.as_mut())?;
        let id = config.channel_id();
        let store = self.vault.create(&id)?;
        let (channel, is_new) = match Channel::create(config, store) {
            Ok(created) => created,
            Err(Error::Store(StoreError::Io)) => (self.recover(config)?, true),
            Err(error) => return Err(error),
        };
        let open = Open {
            channel,
            probe_at: None,
        };
        let info = self.info(&open);
        self.channels.push(open);
        Ok((info, is_new))
    }

    /// R4: a first commit that failed with `Io` may have poisoned its store
    /// after its rename; the state that stands, if any, is opened.
    ///
    /// # Errors
    ///
    /// The original `Io` when no state stands, or when the retry fails, the
    /// directory then listed in `broken`.
    fn recover(&mut self, config: &Config) -> Result<Channel, Error> {
        let original = Error::Store(StoreError::Io);
        let id = config.channel_id();
        let retried = self.vault.create(&id).and_then(|mut store| {
            let loaded = store.load()?;
            Ok(loaded.map(|loaded| (store, loaded)))
        });
        let opened = match retried {
            Ok(None) => return Err(original),
            Ok(Some((store, loaded))) => Channel::loaded(store, loaded),
            Err(reason) => Err(Error::Store(reason)),
        };
        let failure = match opened {
            // `docs/spec.md` §5: a state that stands for another server is
            // not this channel's, as `Channel::create` would have said.
            Ok(channel) if channel.config().server_url() != config.server_url() => {
                return Err(Error::ConfigMismatch);
            }
            Ok(channel) => return Ok(channel),
            Err(Error::Store(reason)) => reason,
            Err(error) => return Err(error),
        };
        let dir = self.vault.dir_name(&id)?;
        self.broken.push(Broken {
            dir,
            info: BrokenChannel {
                name: dir.to_hex(),
                reason: failure,
                channel_id: Some(id),
                channel_name: shown_name(config.suggested_name()),
            },
        });
        Err(original)
    }
}
