//! The server's configuration (spec 035-server-ops R1): the environment
//! variables of the table "Configuration", read once at start-up and from
//! nothing else. Anything in doubt refuses the start, naming the variable and
//! never its value: a value is read as written, with no space trimmed, no
//! sign and no default taken in its place.

use std::collections::HashMap;
use std::ffi::OsString;
use std::fmt;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::ops::RangeInclusive;
use std::path::PathBuf;

use privatechat_core::relay;
use tracing::Level;

use crate::client_addr::IpNet;
use crate::limits::{ChannelLimits, ConnectionLimits};

/// Every variable of the table starts with it; any other with it is a typo.
const PREFIX: &str = "PRIVATECHAT_";

/// The configured URLs (spec 031 R8).
const MAX_URLS: usize = 8;

/// The trusted proxies (R3).
const MAX_TRUSTED_PROXIES: usize = 16;

/// The largest blob (spec 013-wire-message), the least any byte budget may
/// be, so that one blob always fits.
const LARGEST_BLOB: u64 = 64_673;

/// The bounds of `PRIVATECHAT_MAX_DB_BYTES` (spec 032 R8).
const DB_BYTES: RangeInclusive<u64> = 67_108_864..=1 << 62;

/// The bounds of a byte budget or quota (spec 033 R6, R7, R12).
const BUDGET_BYTES: RangeInclusive<u64> = LARGEST_BLOB..=1 << 40;

/// The bounds of a connection count (spec 033 R8, R10).
const CONNECTIONS: RangeInclusive<u64> = 1..=1_000_000;

const DEFAULT_LISTEN: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 8080));
const DEFAULT_DB: &str = "/data/messages.db";
const DEFAULT_MAX_DB_BYTES: u64 = 8_589_934_592;

/// What the server runs with (R1). No `Debug`: its hosts may be an onion
/// name, which no log line ties to the server (Security).
pub struct Settings {
    /// The hosts of the configured URLs (spec 031 R8).
    pub(crate) hosts: Vec<String>,
    pub(crate) listen: SocketAddr,
    /// The onion service's listener (R2).
    pub(crate) onion_listen: Option<SocketAddr>,
    /// Whose `X-Forwarded-For` is believed (R3).
    #[allow(dead_code, reason = "read by the client address of R3, slice (b)")]
    pub(crate) trusted_proxies: Vec<IpNet>,
    pub(crate) db: PathBuf,
    /// The database's ceiling (spec 032 R8).
    pub(crate) max_db_bytes: u64,
    pub(crate) channel: ChannelLimits,
    pub(crate) connections: ConnectionLimits,
    /// The level of the log (R4).
    pub log_level: Level,
}

/// Why the configuration was refused (R1): the variable's name, never its
/// value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    /// A required variable is absent.
    Missing(String),
    /// A value outside the variable's range.
    OutOfRange(String),
    /// Two URLs with the same host.
    SameHost(String),
    /// A name with the prefix that the table does not have.
    Unknown(String),
    /// A name or a value that is not UTF-8.
    NotUtf8(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (variable, problem) = match self {
            ConfigError::Missing(variable) => (variable, "is required"),
            ConfigError::OutOfRange(variable) => (variable, "is out of its range"),
            ConfigError::SameHost(variable) => (variable, "has two URLs with the same host"),
            ConfigError::Unknown(variable) => (variable, "is not a known variable"),
            ConfigError::NotUtf8(variable) => (variable, "is not UTF-8"),
        };
        write!(f, "configuration error: {variable} {problem}")
    }
}

impl Settings {
    /// The settings of the variables `vars`, as `std::env::vars_os` gives
    /// them; those without the prefix are ignored.
    ///
    /// # Errors
    ///
    /// `ConfigError` naming the first variable refused: absent while
    /// required, out of its range, with two URLs of one host, unknown, or
    /// not UTF-8.
    pub fn from_env(
        vars: impl Iterator<Item = (OsString, OsString)>,
    ) -> Result<Settings, ConfigError> {
        let mut env = Env::read(vars)?;
        let channel_defaults = ChannelLimits::default();
        let connection_defaults = ConnectionLimits::default();
        let hosts = env
            .take("PRIVATECHAT_URLS")?
            .ok_or_else(|| ConfigError::Missing("PRIVATECHAT_URLS".to_owned()))
            .and_then(|urls| hosts("PRIVATECHAT_URLS", &urls))?;
        let listen = env.socket("PRIVATECHAT_LISTEN")?.unwrap_or(DEFAULT_LISTEN);
        let onion_listen = env.socket("PRIVATECHAT_ONION_LISTEN")?;
        if onion_listen == Some(listen) {
            return Err(out("PRIVATECHAT_ONION_LISTEN"));
        }
        let settings = Settings {
            hosts,
            listen,
            onion_listen,
            trusted_proxies: env.trusted_proxies("PRIVATECHAT_TRUSTED_PROXIES")?,
            db: env.db("PRIVATECHAT_DB")?,
            max_db_bytes: env.integer(
                "PRIVATECHAT_MAX_DB_BYTES",
                DEFAULT_MAX_DB_BYTES,
                DB_BYTES,
            )?,
            channel: ChannelLimits {
                publish_per_min: env.count(
                    "PRIVATECHAT_CHANNEL_PUBLISH_PER_MIN",
                    channel_defaults.publish_per_min,
                    1..=100_000,
                )?,
                bytes_per_min: env.integer(
                    "PRIVATECHAT_CHANNEL_BYTES_PER_MIN",
                    channel_defaults.bytes_per_min,
                    BUDGET_BYTES,
                )?,
                max_blobs: env.count(
                    "PRIVATECHAT_CHANNEL_MAX_BLOBS",
                    channel_defaults.max_blobs,
                    1..=10_000_000,
                )?,
                max_bytes: env.integer(
                    "PRIVATECHAT_CHANNEL_MAX_BYTES",
                    channel_defaults.max_bytes,
                    BUDGET_BYTES,
                )?,
            },
            connections: ConnectionLimits {
                ip_connections: env.count(
                    "PRIVATECHAT_IP_CONNECTIONS",
                    connection_defaults.ip_connections,
                    1..=100_000,
                )?,
                ip_unauth_connections: env.count(
                    "PRIVATECHAT_IP_UNAUTH_CONNECTIONS",
                    connection_defaults.ip_unauth_connections,
                    1..=10_000,
                )?,
                ip_new_per_min: env.count(
                    "PRIVATECHAT_IP_NEW_PER_MIN",
                    connection_defaults.ip_new_per_min,
                    1..=100_000,
                )?,
                max_connections: env.count(
                    "PRIVATECHAT_MAX_CONNECTIONS",
                    connection_defaults.max_connections,
                    CONNECTIONS,
                )?,
                onion_max_connections: env.count(
                    "PRIVATECHAT_ONION_MAX_CONNECTIONS",
                    connection_defaults.onion_max_connections,
                    CONNECTIONS,
                )?,
                max_unauth_connections: env.count(
                    "PRIVATECHAT_MAX_UNAUTH_CONNECTIONS",
                    connection_defaults.max_unauth_connections,
                    CONNECTIONS,
                )?,
                ip_bytes_per_min: env.integer(
                    "PRIVATECHAT_IP_BYTES_PER_MIN",
                    connection_defaults.ip_bytes_per_min,
                    BUDGET_BYTES,
                )?,
                onion_bytes_per_min: env.integer(
                    "PRIVATECHAT_ONION_BYTES_PER_MIN",
                    connection_defaults.onion_bytes_per_min,
                    BUDGET_BYTES,
                )?,
                ip48_connections: env.count(
                    "PRIVATECHAT_IP48_CONNECTIONS",
                    connection_defaults.ip48_connections,
                    CONNECTIONS,
                )?,
                ip48_unauth_connections: env.count(
                    "PRIVATECHAT_IP48_UNAUTH_CONNECTIONS",
                    connection_defaults.ip48_unauth_connections,
                    CONNECTIONS,
                )?,
                ip48_subnets: env.count(
                    "PRIVATECHAT_IP48_SUBNETS",
                    connection_defaults.ip48_subnets,
                    1..=65_536,
                )?,
                ip48_bytes_per_min: env.integer(
                    "PRIVATECHAT_IP48_BYTES_PER_MIN",
                    connection_defaults.ip48_bytes_per_min,
                    BUDGET_BYTES,
                )?,
            },
            log_level: env.log_level("PRIVATECHAT_LOG")?,
        };
        // Whatever was not taken is not in the table.
        match env.0.into_keys().next() {
            Some(unknown) => Err(ConfigError::Unknown(unknown)),
            None => Ok(settings),
        }
    }
}

/// A value outside the range of `variable`.
fn out(variable: &str) -> ConfigError {
    ConfigError::OutOfRange(variable.to_owned())
}

/// The hosts of `urls`, 1 to 8 URLs of the grammar of spec 011 R5 separated
/// by `,`, each host once.
fn hosts(variable: &str, urls: &str) -> Result<Vec<String>, ConfigError> {
    let mut hosts: Vec<String> = Vec::new();
    for url in urls.split(',') {
        let host = relay::url_host(url).map_err(|_| out(variable))?;
        if hosts.contains(&host) {
            return Err(ConfigError::SameHost(variable.to_owned()));
        }
        hosts.push(host);
    }
    if hosts.len() > MAX_URLS {
        return Err(out(variable));
    }
    Ok(hosts)
}

/// The variables with the prefix, by name, each taken once as it is read.
struct Env(HashMap<String, OsString>);

impl Env {
    /// The variables of `vars` with the prefix; a name with it that is not
    /// UTF-8 cannot be in the table.
    fn read(vars: impl Iterator<Item = (OsString, OsString)>) -> Result<Env, ConfigError> {
        let mut variables = HashMap::new();
        for (name, value) in vars {
            // A replacement character never stands for the prefix's ASCII,
            // so the lossy text starts with it exactly when the bytes do.
            if !name.to_string_lossy().starts_with(PREFIX) {
                continue;
            }
            let name = name
                .into_string()
                .map_err(|name| ConfigError::NotUtf8(name.to_string_lossy().into_owned()))?;
            variables.insert(name, value);
        }
        Ok(Env(variables))
    }

    /// The value of `variable`, if it is set.
    fn take(&mut self, variable: &str) -> Result<Option<String>, ConfigError> {
        self.0
            .remove(variable)
            .map(|value| {
                value
                    .into_string()
                    .map_err(|_| ConfigError::NotUtf8(variable.to_owned()))
            })
            .transpose()
    }

    /// An integer of decimal digits in `range`, or `default`.
    fn integer(
        &mut self,
        variable: &str,
        default: u64,
        range: RangeInclusive<u64>,
    ) -> Result<u64, ConfigError> {
        let Some(text) = self.take(variable)? else {
            return Ok(default);
        };
        // Digits only: `u64::from_str` would also take a sign.
        if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
            return Err(out(variable));
        }
        text.parse()
            .ok()
            .filter(|value| range.contains(value))
            .ok_or_else(|| out(variable))
    }

    /// An integer of `integer` that fits a `u32`, as every count does.
    fn count(
        &mut self,
        variable: &str,
        default: u32,
        range: RangeInclusive<u64>,
    ) -> Result<u32, ConfigError> {
        let value = self.integer(variable, u64::from(default), range)?;
        u32::try_from(value).map_err(|_| out(variable))
    }

    /// An IP socket address, if it is set.
    fn socket(&mut self, variable: &str) -> Result<Option<SocketAddr>, ConfigError> {
        self.take(variable)?
            .map(|text| text.parse().map_err(|_| out(variable)))
            .transpose()
    }

    /// Up to 16 addresses or CIDR blocks separated by `,`; empty or absent,
    /// none.
    fn trusted_proxies(&mut self, variable: &str) -> Result<Vec<IpNet>, ConfigError> {
        let text = self.take(variable)?.unwrap_or_default();
        if text.is_empty() {
            return Ok(Vec::new());
        }
        let proxies = text
            .split(',')
            .map(|net| IpNet::parse(net).ok_or_else(|| out(variable)))
            .collect::<Result<Vec<_>, _>>()?;
        if proxies.len() > MAX_TRUSTED_PROXIES {
            return Err(out(variable));
        }
        Ok(proxies)
    }

    /// A path; empty is none, which would fail at the open as a refused
    /// database (spec 032 R3) rather than as the configuration it is.
    fn db(&mut self, variable: &str) -> Result<PathBuf, ConfigError> {
        match self.take(variable)? {
            None => Ok(PathBuf::from(DEFAULT_DB)),
            Some(path) if path.is_empty() => Err(out(variable)),
            Some(path) => Ok(PathBuf::from(path)),
        }
    }

    /// One of the five level names, in lowercase.
    fn log_level(&mut self, variable: &str) -> Result<Level, ConfigError> {
        match self.take(variable)?.as_deref() {
            None | Some("warn") => Ok(Level::WARN),
            Some("error") => Ok(Level::ERROR),
            Some("info") => Ok(Level::INFO),
            Some("debug") => Ok(Level::DEBUG),
            Some("trace") => Ok(Level::TRACE),
            Some(_) => Err(out(variable)),
        }
    }
}
