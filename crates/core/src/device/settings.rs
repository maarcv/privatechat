//! The settings of the device and their gate (spec 027-core-api R1, R2,
//! R13): what is in memory, whether `settings.bin` holds it, and, while a
//! lost file has not been seen by the user, the changes made in memory
//! alone.

use std::fmt;

use super::Device;
use crate::DEFAULT_SERVER_URL;
use crate::error::Error;
use crate::proto::config::url;
use crate::storage::{MAX_LOCK_TIMEOUT_SECONDS, Settings, StoreError, Vault};

/// The lock timeout of a fresh install (R13).
const DEFAULT_LOCK_TIMEOUT_SECONDS: u32 = 60;

/// The settings as the client reads them; its `Debug` shows neither the
/// server URL nor the proxy's address.
#[derive(Clone, PartialEq, Eq)]
pub struct SettingsView {
    /// The server a new channel is created on.
    pub default_server_url: String,
    /// Seconds in the background before the app locks; 0 locks at once.
    pub lock_timeout_seconds: u32,
    /// `host:port` of the SOCKS5 proxy every connection goes through.
    pub socks5_proxy: Option<String>,
}

impl fmt::Debug for SettingsView {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SettingsView")
            .field("lock_timeout_seconds", &self.lock_timeout_seconds)
            .field("proxied", &self.socks5_proxy.is_some())
            .finish_non_exhaustive()
    }
}

/// The settings in memory and how they stand against `settings.bin`.
pub(super) struct SettingsHolder {
    current: Settings,
    mode: Mode,
}

/// How the settings in memory stand against `settings.bin`.
enum Mode {
    /// The file holds what memory holds.
    Saved,
    /// A fresh install: the defaults, saved by the first write (R1).
    Fresh,
    /// The file was lost or unreadable: nothing connects, and the setters
    /// change memory alone, until the user has seen it (R2).
    Reset {
        /// What `load_settings` returned, `None` for an absent file.
        reason: Option<StoreError>,
        /// The setter changes made since, in order, applied onto a file
        /// that reads again.
        changes: Vec<Change>,
    },
    /// The file of a newer app, which a downgrade never overwrites unless
    /// the user replaces it: the setters change memory alone (R2).
    Newer,
}

/// One setter's change, already checked against its grammar (R13).
enum Change {
    DefaultServerUrl(String),
    LockTimeoutSeconds(u32),
    Socks5Proxy(Option<String>),
}

impl Change {
    /// `settings` with this change applied.
    fn apply_to(&self, mut settings: Settings) -> Settings {
        match self {
            Change::DefaultServerUrl(url) => settings.default_server_url.clone_from(url),
            Change::LockTimeoutSeconds(seconds) => settings.lock_timeout_seconds = *seconds,
            Change::Socks5Proxy(proxy) => settings.socks5_proxy.clone_from(proxy),
        }
        settings
    }
}

/// The defaults of R13.
fn defaults() -> Settings {
    Settings {
        default_server_url: DEFAULT_SERVER_URL.to_owned(),
        lock_timeout_seconds: DEFAULT_LOCK_TIMEOUT_SECONDS,
        socks5_proxy: None,
    }
}

/// A copy of `settings`, which holds no secret.
fn copy(settings: &Settings) -> Settings {
    Settings {
        default_server_url: settings.default_server_url.clone(),
        lock_timeout_seconds: settings.lock_timeout_seconds,
        socks5_proxy: settings.socks5_proxy.clone(),
    }
}

impl SettingsHolder {
    /// The settings `vault` holds, or the defaults in memory (R1): a fresh
    /// install when it holds none and no channel, the gate up otherwise.
    pub(super) fn load(vault: &mut dyn Vault, has_channels: bool) -> SettingsHolder {
        let (current, mode) = match vault.load_settings() {
            Ok(Some(settings)) => (settings, Mode::Saved),
            Ok(None) if !has_channels => (defaults(), Mode::Fresh),
            Ok(None) => (defaults(), Mode::reset(None)),
            Err(error) => (defaults(), Mode::reset(Some(error))),
        };
        SettingsHolder { current, mode }
    }

    /// Whether the gate of R2 is up.
    pub(super) fn is_reset(&self) -> bool {
        matches!(self.mode, Mode::Reset { .. })
    }

    /// `DeviceStatus::settings_reason` (R1, R2).
    pub(super) fn reason(&self) -> Option<StoreError> {
        match &self.mode {
            Mode::Reset { reason, .. } => *reason,
            Mode::Newer => Some(StoreError::UnsupportedVersion),
            Mode::Saved | Mode::Fresh => None,
        }
    }

    /// The settings in memory.
    pub(super) fn current(&self) -> &Settings {
        &self.current
    }

    /// Applies a checked change as R2 says for the mode, saving through
    /// `vault` when the mode lets it; on a failed save nothing changes.
    fn set(&mut self, vault: &mut dyn Vault, change: Change) -> Result<(), Error> {
        match &mut self.mode {
            Mode::Saved | Mode::Fresh => {
                let next = change.apply_to(copy(&self.current));
                vault.save_settings(&next)?;
                self.current = next;
                self.mode = Mode::Saved;
            }
            Mode::Newer => self.current = change.apply_to(copy(&self.current)),
            Mode::Reset { changes, .. } => {
                self.current = change.apply_to(copy(&self.current));
                changes.push(change);
            }
        }
        Ok(())
    }

    /// Saves the defaults of a fresh install, before the first channel is
    /// created or imported (R1); does nothing otherwise.
    pub(super) fn save_if_fresh(&mut self, vault: &mut dyn Vault) -> Result<(), Error> {
        if matches!(self.mode, Mode::Fresh) {
            vault.save_settings(&self.current)?;
            self.mode = Mode::Saved;
        }
        Ok(())
    }

    /// Lowers the gate of R2 for `acknowledge_settings` (`proxy` `None`)
    /// or `set_socks5_proxy` (`proxy` the value it sets), or, outside the
    /// gate, saves what R1 and R2 say; on a failed save nothing changes.
    fn release(
        &mut self,
        vault: &mut dyn Vault,
        proxy: Option<Option<String>>,
        replace_newer: bool,
    ) -> Result<(), Error> {
        let proxy = proxy.map(Change::Socks5Proxy);
        let Mode::Reset { reason, changes } = &self.mode else {
            return self.acknowledge_outside_gate(vault, replace_newer);
        };
        let mut reason = *reason;
        // `replace_newer` counts only for the reason the user was shown: a
        // re-read that finds a newer file never replaces it unasked (R2).
        let replace = replace_newer && reason == Some(StoreError::UnsupportedVersion);
        if reason == Some(StoreError::Io) {
            // A passing read error must not overwrite a stored proxy (R2).
            match vault.load_settings() {
                Ok(Some(stored)) => {
                    let next = changes
                        .iter()
                        .chain(&proxy)
                        .fold(stored, |settings, change| change.apply_to(settings));
                    if !changes.is_empty() || proxy.is_some() {
                        vault.save_settings(&next)?;
                    }
                    self.current = next;
                    self.mode = Mode::Saved;
                    return Ok(());
                }
                Err(StoreError::UnsupportedVersion) => {
                    reason = Some(StoreError::UnsupportedVersion);
                }
                Ok(None) | Err(_) => {}
            }
        }
        let next = match &proxy {
            Some(proxy) => proxy.apply_to(copy(&self.current)),
            None => copy(&self.current),
        };
        if reason == Some(StoreError::UnsupportedVersion) && !replace {
            // A newer app's file is never overwritten by a downgrade.
            self.current = next;
            self.mode = Mode::Newer;
            return Ok(());
        }
        vault.save_settings(&next)?;
        self.current = next;
        self.mode = Mode::Saved;
        Ok(())
    }

    /// `acknowledge_settings` while the gate is down: a fresh install saves
    /// its defaults (R1), a newer app's file is replaced only on request
    /// (R2), and saved settings stay as they are.
    fn acknowledge_outside_gate(
        &mut self,
        vault: &mut dyn Vault,
        replace_newer: bool,
    ) -> Result<(), Error> {
        let saves = match self.mode {
            Mode::Fresh => true,
            Mode::Newer => replace_newer,
            Mode::Saved | Mode::Reset { .. } => false,
        };
        if saves {
            vault.save_settings(&self.current)?;
            self.mode = Mode::Saved;
        }
        Ok(())
    }
}

impl Mode {
    /// The gate up for `reason`, with no change made yet.
    fn reset(reason: Option<StoreError>) -> Mode {
        Mode::Reset {
            reason,
            changes: Vec::new(),
        }
    }
}

impl Device {
    /// The settings in memory (R13).
    pub fn settings(&self) -> SettingsView {
        let current = self.settings.current();
        SettingsView {
            default_server_url: current.default_server_url.clone(),
            lock_timeout_seconds: current.lock_timeout_seconds,
            socks5_proxy: current.socks5_proxy.clone(),
        }
    }

    /// Sets the server a new channel is created on (R13).
    ///
    /// # Errors
    ///
    /// `BadConfig` for a URL outside the grammar of spec 011-config-format
    /// R5; `Store(e)` for a failed save, nothing changed.
    pub fn set_default_server_url(&mut self, url: &str) -> Result<(), Error> {
        url::parse(url)?;
        let change = Change::DefaultServerUrl(url.to_owned());
        self.settings.set(self.vault.as_mut(), change)
    }

    /// Sets the lock timeout (R13).
    ///
    /// # Errors
    ///
    /// `BadConfig` above 86 400 seconds; `Store(e)` for a failed save,
    /// nothing changed.
    pub fn set_lock_timeout_seconds(&mut self, seconds: u32) -> Result<(), Error> {
        if seconds > MAX_LOCK_TIMEOUT_SECONDS {
            return Err(Error::BadConfig);
        }
        let change = Change::LockTimeoutSeconds(seconds);
        self.settings.set(self.vault.as_mut(), change)
    }

    /// Sets or clears the SOCKS5 proxy (R13); while the settings are reset
    /// it also lowers the gate (R2).
    ///
    /// # Errors
    ///
    /// `BadConfig` for a proxy outside the grammar of spec 020-store-files;
    /// `Store(e)` for a failed save, nothing changed.
    pub fn set_socks5_proxy(&mut self, proxy: Option<&str>) -> Result<(), Error> {
        if proxy.is_some_and(|proxy| !url::is_proxy(proxy)) {
            return Err(Error::BadConfig);
        }
        let proxy = proxy.map(str::to_owned);
        if self.settings.is_reset() {
            self.settings
                .release(self.vault.as_mut(), Some(proxy), false)?;
        } else {
            self.settings
                .set(self.vault.as_mut(), Change::Socks5Proxy(proxy))?;
        }
        // The proxy decides every route and `needs_proxy` (R10).
        self.replan();
        Ok(())
    }

    /// The user has seen that the settings were lost or written by a newer
    /// app (R2): the gate comes down and, but for a newer app's file, the
    /// settings are saved; `replace_newer`, offered only behind a
    /// destructive confirmation, replaces that file too.
    ///
    /// # Errors
    ///
    /// `Store(e)` for a failed save, nothing changed.
    pub fn acknowledge_settings(&mut self, replace_newer: bool) -> Result<(), Error> {
        self.settings
            .release(self.vault.as_mut(), None, replace_newer)?;
        // A file adopted after a passing error may bring its proxy (R2).
        self.replan();
        Ok(())
    }
}
