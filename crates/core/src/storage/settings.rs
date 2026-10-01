//! The settings record of `settings.bin` (spec 020, "Settings record"): the
//! app settings, sealed under `K_settings`. What each setting does belongs
//! to specs 027-core-api and 053-device-security.

use zeroize::Zeroizing;

use super::{StorageKey, StoreError, open_box, required, seal_box, settings_key};
use crate::proto::config::url::{self, MAX_URL};
use crate::proto::record::{Reader, U8_LEN, U32_LEN, UnknownKeys, Writer, record_len};

/// The version of the settings schema, key 0 (R8).
const SETTINGS_VERSION: u8 = 1;

#[cfg(test)]
pub(super) mod tests;

/// The largest settings record (Limits).
pub(crate) const MAX_SETTINGS_RECORD: usize = 1_024;

/// The longest `lock_timeout_seconds`, a day; 0 locks on app switch.
pub(crate) const MAX_LOCK_TIMEOUT_SECONDS: u32 = 86_400;

/// The keys of the settings record, in order.
const KEY_SETTINGS_VERSION: u8 = 0;
const KEY_DEFAULT_SERVER_URL: u8 = 1;
const KEY_LOCK_TIMEOUT_SECONDS: u8 = 2;
const KEY_SOCKS5_PROXY: u8 = 3;

/// The app settings.
pub struct Settings {
    /// A URL of the grammar of spec 011-config-format R5.
    pub(crate) default_server_url: String,
    /// 0..=86 400.
    pub(crate) lock_timeout_seconds: u32,
    /// `host:port`, the host of that grammar.
    pub(crate) socks5_proxy: Option<String>,
}

impl Settings {
    /// Opens the `nonce ‖ box` of `settings.bin`, which `store` has taken out
    /// of its framing (R4, R7).
    ///
    /// # Errors
    ///
    /// `Corrupt` for fewer than 40 bytes, a box that does not open under
    /// `K_settings`, or a record that breaks the schema or its grammars;
    /// `UnsupportedVersion` for a newer `settings_version` (R8).
    pub fn open(key: &StorageKey, sealed: &[u8]) -> Result<Settings, StoreError> {
        let record = open_box(&settings_key(key)?, sealed)?;
        Settings::decode(&record)
    }

    /// Seals the settings as `nonce ‖ box` (R4).
    ///
    /// # Errors
    ///
    /// `Corrupt` for any value `open` would refuse (R8), or when libsodium
    /// fails.
    pub fn seal(&self, key: &StorageKey) -> Result<Vec<u8>, StoreError> {
        let record = self.encode()?;
        seal_box(&settings_key(key)?, &record)
    }

    /// Decodes a settings record under `Reject`, key 0 first (R8).
    pub(crate) fn decode(buf: &[u8]) -> Result<Settings, StoreError> {
        let mut reader = Reader::new(buf, MAX_SETTINGS_RECORD, UnknownKeys::Reject)?;
        if required(reader.u8(KEY_SETTINGS_VERSION))? != SETTINGS_VERSION {
            return Err(StoreError::UnsupportedVersion);
        }
        let settings = Settings {
            default_server_url: required(reader.text(KEY_DEFAULT_SERVER_URL, MAX_URL))?.to_owned(),
            lock_timeout_seconds: required(reader.u32(KEY_LOCK_TIMEOUT_SECONDS))?,
            socks5_proxy: reader.text(KEY_SOCKS5_PROXY, MAX_URL)?.map(str::to_owned),
        };
        reader.end()?;
        settings.check()?;
        Ok(settings)
    }

    /// Encodes the record at its exact length (R25).
    pub(crate) fn encode(&self) -> Result<Zeroizing<Vec<u8>>, StoreError> {
        self.check()?;
        let len = record_len(&[
            Some(U8_LEN),
            Some(self.default_server_url.len()),
            Some(U32_LEN),
            self.socks5_proxy.as_ref().map(String::len),
        ]);
        let mut writer = Writer::with_capacity(len);
        writer.u8(KEY_SETTINGS_VERSION, SETTINGS_VERSION)?;
        writer.text(KEY_DEFAULT_SERVER_URL, &self.default_server_url)?;
        writer.u32(KEY_LOCK_TIMEOUT_SECONDS, self.lock_timeout_seconds)?;
        if let Some(proxy) = &self.socks5_proxy {
            writer.text(KEY_SOCKS5_PROXY, proxy)?;
        }
        Ok(writer.finish())
    }

    /// The grammars and the range of the Limits table (R8), which seal and
    /// open both apply.
    fn check(&self) -> Result<(), StoreError> {
        let url_ok = url::parse(&self.default_server_url).is_ok();
        let proxy_ok = self.socks5_proxy.as_deref().is_none_or(url::is_proxy);
        if !url_ok || !proxy_ok || self.lock_timeout_seconds > MAX_LOCK_TIMEOUT_SECONDS {
            return Err(StoreError::Corrupt);
        }
        Ok(())
    }
}
