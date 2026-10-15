//! The preview of an import (spec 027-core-api R25, spec 054-qr-invite R15
//! and R17): what the user confirms before "Join", read from a parsed
//! config and the open channels, with no store call but `Vault::dir_name`.

use std::fmt;

use super::{Device, plan};
use crate::error::Error;
use crate::proto::config::Config;
use crate::session::names::{names_collide, shown_name};
use crate::storage::StoreError;

/// What the confirmation of an import shows (R25); its `Debug` shows no
/// name or URL (R20).
#[derive(Clone, PartialEq, Eq)]
pub struct ConfigPreview {
    /// The name the creator suggested, cleaned; `""` when nothing is left.
    pub suggested_name: String,
    /// The server the channel lives on.
    pub server_url: String,
    /// The time to live of its messages.
    pub ttl_seconds: u32,
    /// A channel with that `channel_id` is open.
    pub is_open: bool,
    /// An open channel has that `server_url`.
    pub server_known: bool,
    /// The suggested name collides with an open channel's name.
    pub name_collides: bool,
    /// The channel needs a SOCKS5 proxy this device does not have (R10).
    pub needs_proxy: bool,
    /// The reason of the channel's directory when it is in `broken`.
    pub broken_reason: Option<StoreError>,
}

impl fmt::Debug for ConfigPreview {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConfigPreview")
            .field("ttl_seconds", &self.ttl_seconds)
            .field("is_open", &self.is_open)
            .field("server_known", &self.server_known)
            .field("name_collides", &self.name_collides)
            .field("needs_proxy", &self.needs_proxy)
            .field("broken_reason", &self.broken_reason)
            .finish_non_exhaustive()
    }
}

impl Device {
    /// The preview of `import_qr` of `text` (R25): it commits nothing.
    ///
    /// # Errors
    ///
    /// The errors of `Config::parse_qr`; `ConfigMismatch` for a channel
    /// open on another server; the error of `Vault::dir_name`.
    pub fn preview_qr(&self, text: &[u8], now: u64) -> Result<ConfigPreview, Error> {
        self.preview(&Config::parse_qr(text, now)?)
    }

    /// The preview of `import_file` of `bytes` and `password` (R25): it
    /// commits nothing, and derives the password's key as the import does.
    ///
    /// # Errors
    ///
    /// The errors of `Config::open_encrypted`, then as
    /// [`Device::preview_qr`].
    pub fn preview_file(
        &self,
        bytes: &[u8],
        password: &[u8],
        now: u64,
    ) -> Result<ConfigPreview, Error> {
        self.preview(&Config::open_encrypted(bytes, password, now)?)
    }

    /// R25 for a parsed `config`: the checks of R5 before its first store
    /// call, and what the confirmation shows.
    fn preview(&self, config: &Config) -> Result<ConfigPreview, Error> {
        let id = config.channel_id();
        let open = self.channel(id).ok();
        if open.is_some_and(|channel| channel.config().server_url() != config.server_url()) {
            return Err(Error::ConfigMismatch);
        }
        // As the import, which names the directory only for a channel that
        // is not open (R5).
        let broken_reason = match open {
            Some(_) => None,
            None => {
                let dir = self.vault.dir_name(&id)?;
                self.broken
                    .iter()
                    .find(|broken| broken.dir == dir)
                    .map(|broken| broken.info.reason)
            }
        };
        let suggested_name = shown_name(config.suggested_name()).unwrap_or_default();
        let name_collides = self.channels.iter().any(|channel| {
            let names = [
                Some(channel.config().suggested_name()),
                channel.local_name(),
            ];
            names
                .into_iter()
                .flatten()
                .any(|name| names_collide(config.suggested_name(), name))
        });
        Ok(ConfigPreview {
            suggested_name,
            server_url: config.server_url().to_owned(),
            ttl_seconds: config.ttl_seconds(),
            is_open: open.is_some(),
            server_known: self
                .channels
                .iter()
                .any(|channel| channel.config().server_url() == config.server_url()),
            name_collides,
            needs_proxy: plan::needs_proxy(
                config.server_url(),
                self.settings.current().socks5_proxy.as_deref(),
            ),
            broken_reason,
        })
    }
}
