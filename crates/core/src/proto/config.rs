//! The channel config of `docs/spec.md` §5 and the channel identity it
//! derives (spec 011-config-format).
//!
//! A config is a record of spec 017 decoded strictly, in the order of R3:
//! size, versions, the rest of the record, ranges, expiry, and only then the
//! derivation of `pk_ch` and `channel_id`. The message keys built on `K_ch`
//! belong to specs 012 and 013; storing a config belongs to spec 020.

use core::ops::RangeInclusive;

use zeroize::Zeroizing;

use super::record::{Reader, RecordError, UnknownKeys, Writer};
use crate::Error;
use crate::crypto::{self, KdfContext, PublicKey, Secret};

#[cfg(test)]
mod tests;

/// Domain tag of the `channel_id` hash (`docs/spec.md` §4, R9).
pub(crate) const CHANNEL_ID_TAG: &[u8; 19] = b"privatechat/chid/v1";

/// KDF context of the channel's Ed25519 seed (`docs/spec.md` §4, R9).
pub(crate) const CHANNEL_AUTH_CONTEXT: KdfContext = KdfContext::new(*b"chauth__");

/// The one `config_version` and `proto_version` this build speaks (R3).
const VERSION: u8 = 1;

/// The largest encoded record (R7).
pub(crate) const MAX_RECORD: usize = 512;

/// The largest `server_url` (R5).
const MAX_SERVER_URL: usize = 256;

/// The largest `suggested_name`, in bytes of UTF-8 (R4).
const MAX_NAME: usize = 64;

/// The TTL range, 1 minute to 30 days (R4, ADR 0014).
const TTL_SECONDS: RangeInclusive<u32> = 60..=2_592_000;

/// The keys of the record, `docs/spec.md` §5 (R1).
const KEY_CONFIG_VERSION: u8 = 0;
const KEY_PROTO_VERSION: u8 = 1;
const KEY_K_CH: u8 = 2;
const KEY_SERVER_URL: u8 = 3;
const KEY_TTL_SECONDS: u8 = 4;
const KEY_CREATED_AT: u8 = 5;
const KEY_INVITE_EXPIRES_AT: u8 = 6;
const KEY_SUGGESTED_NAME: u8 = 7;

/// The public identifier of a channel on the server (R8). Compared only with
/// `ct_eq` (AGENTS 22).
pub(crate) struct ChannelId(pub(crate) [u8; 16]);

/// A channel config: the only secret of the system (`docs/spec.md` §5).
///
/// It holds every field of the record but `invite_expires_at`, which an
/// export writes and an import checks and drops (R10, ADR 0028), so a stored
/// config never expires as an invitation.
pub struct Config {
    k_ch: Secret<32>,
    server_url: String,
    ttl_seconds: u32,
    created_at: u64,
    suggested_name: String,
    id: ChannelId,
}

/// The fields of a decoded record, borrowed from it.
struct Fields<'a> {
    k_ch: &'a [u8; 32],
    server_url: &'a str,
    ttl_seconds: u32,
    created_at: u64,
    invite_expires_at: Option<u64>,
    suggested_name: &'a str,
}

impl Config {
    /// A new channel with a fresh `K_ch`, created at `now` (R23).
    ///
    /// # Errors
    ///
    /// `BadConfig` for a TTL, a name or a server URL out of range, and
    /// `Internal` when libsodium fails.
    pub fn create(
        server_url: &str,
        ttl_seconds: u32,
        suggested_name: &str,
        now: u64,
    ) -> Result<Config, Error> {
        Config::from_parts(
            Secret::random()?,
            server_url,
            ttl_seconds,
            suggested_name,
            now,
        )
    }

    /// The config encoded in `bytes`, the record itself (R1–R4, R7, R10).
    ///
    /// # Errors
    ///
    /// `BadConfig` for a record above 512 bytes, malformed or out of range;
    /// `UnsupportedVersion` for a `config_version` or `proto_version` other
    /// than 1; `InviteExpired` for an invitation that expired before `now`;
    /// `Internal` when libsodium fails.
    pub fn parse(bytes: &[u8], now: u64) -> Result<Config, Error> {
        let fields = decode(bytes)?;
        check_ranges(fields.server_url, fields.ttl_seconds, fields.suggested_name)?;
        if fields.invite_expires_at.is_some_and(|expiry| expiry < now) {
            return Err(Error::InviteExpired);
        }
        Config::build(
            Secret::copy_from(fields.k_ch),
            fields.server_url,
            fields.ttl_seconds,
            fields.suggested_name,
            fields.created_at,
        )
    }

    /// The channel's identifier on the server (R8).
    pub fn channel_id(&self) -> [u8; 16] {
        self.id.0
    }

    /// The exchange server of the channel, fixed at creation.
    pub fn server_url(&self) -> &str {
        &self.server_url
    }

    /// The channel name proposed by its creator.
    pub fn suggested_name(&self) -> &str {
        &self.suggested_name
    }

    /// How long a message of this channel lives.
    pub fn ttl_seconds(&self) -> u32 {
        self.ttl_seconds
    }

    /// A config from fixed inputs, which the tests and `create` share.
    pub(crate) fn from_parts(
        k_ch: Secret<32>,
        server_url: &str,
        ttl_seconds: u32,
        suggested_name: &str,
        created_at: u64,
    ) -> Result<Config, Error> {
        check_ranges(server_url, ttl_seconds, suggested_name)?;
        Config::build(k_ch, server_url, ttl_seconds, suggested_name, created_at)
    }

    /// The canonical record, with `invite_expires_at` when an export writes it.
    /// Every field was checked on the way in, so a writer error is a bug.
    pub(crate) fn record(
        &self,
        invite_expires_at: Option<u64>,
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        let mut writer = Writer::with_capacity(MAX_RECORD);
        self.write_fields(&mut writer, invite_expires_at)
            .map_err(|_| Error::Internal)?;
        Ok(writer.finish())
    }

    /// The channel's identifier, for the specs that compare it.
    pub(crate) fn id(&self) -> &ChannelId {
        &self.id
    }

    /// `(pk_ch, sk_ch)`, the Ed25519 key pair every member holds (R8).
    pub(crate) fn channel_keypair(&self) -> Result<(PublicKey, Secret<64>), Error> {
        channel_keypair(&self.k_ch)
    }

    /// The fields of §5 in key order (R1).
    fn write_fields(&self, writer: &mut Writer, expiry: Option<u64>) -> Result<(), RecordError> {
        writer.u8(KEY_CONFIG_VERSION, VERSION)?;
        writer.u8(KEY_PROTO_VERSION, VERSION)?;
        writer.bytes(KEY_K_CH, self.k_ch.expose())?;
        writer.text(KEY_SERVER_URL, &self.server_url)?;
        writer.u32(KEY_TTL_SECONDS, self.ttl_seconds)?;
        writer.u64(KEY_CREATED_AT, self.created_at)?;
        if let Some(expiry) = expiry {
            writer.u64(KEY_INVITE_EXPIRES_AT, expiry)?;
        }
        writer.text(KEY_SUGGESTED_NAME, &self.suggested_name)
    }

    /// Derives the identity of fields already checked (R3: derivation last).
    fn build(
        k_ch: Secret<32>,
        server_url: &str,
        ttl_seconds: u32,
        suggested_name: &str,
        created_at: u64,
    ) -> Result<Config, Error> {
        let id = channel_id(&k_ch, ttl_seconds)?;
        Ok(Config {
            k_ch,
            server_url: server_url.to_owned(),
            ttl_seconds,
            created_at,
            suggested_name: suggested_name.to_owned(),
            id,
        })
    }
}

/// The strict decode of R2, reading the versions first (R3) and bounding the
/// whole record before any field is framed (R7).
fn decode(bytes: &[u8]) -> Result<Fields<'_>, Error> {
    let mut reader = Reader::new(bytes, MAX_RECORD, UnknownKeys::Reject).map_err(bad_config)?;
    let config_version = required(reader.u8(KEY_CONFIG_VERSION))?;
    let proto_version = required(reader.u8(KEY_PROTO_VERSION))?;
    if config_version != VERSION || proto_version != VERSION {
        return Err(Error::UnsupportedVersion);
    }
    let fields = Fields {
        k_ch: required(reader.bytes_n::<32>(KEY_K_CH))?,
        server_url: required(reader.text(KEY_SERVER_URL, MAX_SERVER_URL))?,
        ttl_seconds: required(reader.u32(KEY_TTL_SECONDS))?,
        created_at: required(reader.u64(KEY_CREATED_AT))?,
        invite_expires_at: reader.u64(KEY_INVITE_EXPIRES_AT).map_err(bad_config)?,
        suggested_name: required(reader.text(KEY_SUGGESTED_NAME, MAX_NAME))?,
    };
    reader.end().map_err(bad_config)?;
    Ok(fields)
}

/// The ranges of R4 and R5, shared by `create` and every import.
fn check_ranges(server_url: &str, ttl_seconds: u32, suggested_name: &str) -> Result<(), Error> {
    // `char::is_control` is exactly the general category Cc.
    let name_ok = suggested_name.len() <= MAX_NAME && !suggested_name.chars().any(char::is_control);
    let url_ok = !server_url.is_empty() && server_url.len() <= MAX_SERVER_URL;
    if TTL_SECONDS.contains(&ttl_seconds) && name_ok && url_ok {
        Ok(())
    } else {
        Err(Error::BadConfig)
    }
}

/// `sign_keypair_from_seed(kdf_derive(K_ch, "chauth__"))` (R8).
fn channel_keypair(k_ch: &Secret<32>) -> Result<(PublicKey, Secret<64>), Error> {
    let seed = crypto::kdf_derive(k_ch, &CHANNEL_AUTH_CONTEXT)?;
    Ok(crypto::sign_keypair_from_seed(&seed)?)
}

/// The first 16 bytes of `BLAKE2b(CHANNEL_ID_TAG ‖ pk_ch ‖ BE32(ttl_seconds))`
/// (R8): self-certifying, and bound to the TTL (ADR 0014).
fn channel_id(k_ch: &Secret<32>, ttl_seconds: u32) -> Result<ChannelId, Error> {
    let (pk_ch, _) = channel_keypair(k_ch)?;
    let input = [
        CHANNEL_ID_TAG.as_slice(),
        &pk_ch.0,
        &ttl_seconds.to_be_bytes(),
    ]
    .concat();
    let digest = crypto::hash(&input)?;
    let (id, _) = digest.split_first_chunk().ok_or(Error::Internal)?;
    Ok(ChannelId(*id))
}

/// A mandatory key: absent or malformed, the record is not a config (R2).
fn required<T>(value: Result<Option<T>, RecordError>) -> Result<T, Error> {
    value.map_err(bad_config)?.ok_or(Error::BadConfig)
}

/// Every `RecordError` of a config is `BadConfig` (R2); it does not leave
/// `proto` (Interface).
fn bad_config(_: RecordError) -> Error {
    Error::BadConfig
}
