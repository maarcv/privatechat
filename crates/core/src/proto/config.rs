//! The channel config of `docs/spec.md` §5 and the channel identity it
//! derives (spec 011-config-format).
//!
//! A config is a record of spec 017 decoded strictly, in the order of R3:
//! size, versions, the rest of the record, ranges, expiry, and only then the
//! derivation of `pk_ch` and `channel_id`. The message keys built on `K_ch`
//! belong to specs 012 and 013; storing a config belongs to spec 020.

use core::ops::{Range, RangeInclusive};

use zeroize::Zeroizing;

use super::record::{Reader, RecordError, UnknownKeys, Writer};
use super::{base64url, wordlist};
use crate::Error;
use crate::crypto::{self, CryptoError, KdfContext, Nonce, PublicKey, Salt, Secret};

#[cfg(test)]
mod tests;
mod url;

/// Domain tag of the `channel_id` hash (`docs/spec.md` §4, R9).
pub(crate) const CHANNEL_ID_TAG: &[u8; 19] = b"privatechat/chid/v1";

/// KDF context of the channel's Ed25519 seed (`docs/spec.md` §4, R9).
pub(crate) const CHANNEL_AUTH_CONTEXT: KdfContext = KdfContext::new(*b"chauth__");

/// The one `config_version` and `proto_version` this build speaks (R3).
const VERSION: u8 = 1;

/// The largest encoded record (R7).
pub(crate) const MAX_RECORD: usize = 512;

/// The largest `suggested_name`, in bytes of UTF-8 (R4).
const MAX_NAME: usize = 64;

/// The largest QR text, the base64url of a record of `MAX_RECORD` bytes (R11).
const MAX_QR: usize = 683;

/// How long a QR invitation lives: 10 minutes, fixed (R18, ADR 0028).
const QR_INVITE_MS: u64 = 600_000;

/// The magic of a `.chatcfg` file, which identifies the app (R13).
const FILE_MAGIC: &[u8; 4] = b"PCFG";

/// The regions of a file (R13): the magic and version, the salt, the nonce,
/// and the sealed record from `SEALED_AT` to the end.
const FILE_HEADER_LEN: usize = 5;
const SALT_RANGE: Range<usize> = 5..21;
const NONCE_RANGE: Range<usize> = 21..45;
const SEALED_AT: usize = 45;

/// The block the record is padded to, one block for any record (ADR 0031).
const FILE_PAD_BLOCK: usize = 1_024;

/// Every file: `SEALED_AT`, the tag and one padded block (R13).
const FILE_LEN: usize = 1_085;

/// How long a file invitation lives: 24 hours, fixed (R18, ADR 0028).
const FILE_INVITE_MS: u64 = 86_400_000;

/// The bounds of a typed password and of its canonical form (R15).
const MAX_TYPED_PASSWORD: usize = 1_024;
const MAX_CANONICAL_PASSWORD: usize = 256;

/// A drawn password: 7 words of 11 bits, 77 bits (R16, ADR 0028), each
/// index the low 11 bits of two random bytes, so every word is equally
/// likely. The longest BIP-39 word is 8 letters: 7 × 8 + 6 spaces.
const PASSWORD_DRAW_LEN: usize = 14;
const WORD_INDEX_MASK: u16 = 0x07ff;
const MAX_DRAWN_PASSWORD: usize = 62;

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

    /// The config of a scanned QR: the base64url of its record, as ASCII
    /// bytes (R11).
    ///
    /// # Errors
    ///
    /// `BadConfig` for a text above 683 bytes or that is not the canonical
    /// base64url of some bytes, and the errors of [`Config::parse`].
    pub fn parse_qr(text: &[u8], now: u64) -> Result<Config, Error> {
        if text.len() > MAX_QR {
            return Err(Error::BadConfig);
        }
        let record = base64url::decode(text).ok_or(Error::BadConfig)?;
        Config::parse(&record, now)
    }

    /// The QR text of this config, an invitation that expires 10 minutes
    /// after `now` (R11, R18). The bytes belong to the caller, who zeroizes
    /// them once the QR is drawn.
    ///
    /// # Errors
    ///
    /// `Internal` when `now` leaves no room for the expiry.
    pub fn export_qr(&self, now: u64) -> Result<Vec<u8>, Error> {
        let expiry = now.checked_add(QR_INVITE_MS).ok_or(Error::Internal)?;
        let record = self.record(Some(expiry))?;
        let mut text = base64url::encode(&record).ok_or(Error::Internal)?;
        // Moved out, not copied, so no unwiped copy is left behind (R19).
        Ok(core::mem::take(&mut *text))
    }

    /// The config of a `.chatcfg` file, opened with the password its sender
    /// spoke (R13–R15).
    ///
    /// # Errors
    ///
    /// In the order of R13: `BadConfig` for a file of the wrong magic or
    /// length, `UnsupportedVersion` for a version byte other than 1,
    /// `BadPassword` for a password out of bounds or that does not open the
    /// box (a corrupted file included), `BadConfig` for a box with no valid
    /// padding, then the errors of [`Config::parse`]; `Internal` when
    /// libsodium fails, the 64 MiB of Argon2id included.
    pub fn open_encrypted(bytes: &[u8], password: &[u8], now: u64) -> Result<Config, Error> {
        parse_file_header(bytes)?;
        let password = canonical_password(password)?;
        let key = crypto::password_key(&password, &Salt(region(bytes, SALT_RANGE)?))?;
        Config::open_file_with_key(bytes, &key, now)
    }

    /// A `.chatcfg` file of this config, an invitation that expires 24 hours
    /// after `now`, and the 7-word password that opens it (R16, R18). Both
    /// belong to the caller, who zeroizes the password once it is shown.
    ///
    /// # Errors
    ///
    /// `Internal` when `now` leaves no room for the expiry or libsodium
    /// fails.
    pub fn export_encrypted(&self, now: u64) -> Result<(Vec<u8>, Vec<u8>), Error> {
        let mut password = draw_password()?;
        let salt = Salt(crypto::random_bytes()?);
        let nonce = Nonce(crypto::random_bytes()?);
        let file = self.seal_file(&password, &salt, &nonce, now)?;
        // Moved out, not copied, so no unwiped copy is left behind (R19).
        Ok((file, core::mem::take(&mut *password)))
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

    /// The file of R13 under the key Argon2id derives from `password`.
    pub(crate) fn seal_file(
        &self,
        password: &[u8],
        salt: &Salt,
        nonce: &Nonce,
        now: u64,
    ) -> Result<Vec<u8>, Error> {
        let key = crypto::password_key(password, salt)?;
        self.seal_file_with_key(&key, salt, nonce, now)
    }

    /// The one place a file is built (R18): header, salt, nonce and the
    /// sealed padded record, 1 085 bytes.
    pub(crate) fn seal_file_with_key(
        &self,
        key: &Secret<32>,
        salt: &Salt,
        nonce: &Nonce,
        now: u64,
    ) -> Result<Vec<u8>, Error> {
        let sealed = crypto::secretbox_seal(key, nonce, &self.padded_record(now)?)?;
        let mut file = Vec::with_capacity(FILE_LEN);
        file.extend_from_slice(FILE_MAGIC);
        file.push(VERSION);
        file.extend_from_slice(&salt.0);
        file.extend_from_slice(&nonce.0);
        file.extend_from_slice(&sealed);
        Ok(file)
    }

    /// Opens a file under a key already derived: the box, the padding, then
    /// the record by R3 (R13, R14).
    pub(crate) fn open_file_with_key(
        bytes: &[u8],
        key: &Secret<32>,
        now: u64,
    ) -> Result<Config, Error> {
        parse_file_header(bytes)?;
        let nonce = Nonce(region(bytes, NONCE_RANGE)?);
        let sealed = bytes.get(SEALED_AT..).ok_or(Error::BadConfig)?;
        // R14: a wrong password and a corrupted file are one error.
        let padded = crypto::secretbox_open(key, &nonce, sealed).map_err(|error| match error {
            CryptoError::Forged => Error::BadPassword,
            other => Error::from(other),
        });
        let padded = Zeroizing::new(padded?);
        let len = crypto::unpad(&padded, FILE_PAD_BLOCK).map_err(|error| match error {
            CryptoError::BadPadding => Error::BadConfig,
            other => Error::from(other),
        })?;
        Config::parse(padded.get(..len).ok_or(Error::BadConfig)?, now)
    }

    /// The record a file seals, with its 24-hour expiry, padded to one
    /// block in a buffer allocated once at that block (R19).
    pub(crate) fn padded_record(&self, now: u64) -> Result<Zeroizing<Vec<u8>>, Error> {
        let expiry = now.checked_add(FILE_INVITE_MS).ok_or(Error::Internal)?;
        let record = self.record(Some(expiry))?;
        let mut padded = Zeroizing::new(Vec::with_capacity(FILE_PAD_BLOCK));
        padded.extend_from_slice(&record);
        crypto::pad(&mut padded, FILE_PAD_BLOCK)?;
        Ok(padded)
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

    /// The host of `server_url`, the string the subscription signature
    /// covers (R6, spec 031). The URL was checked when the config was built.
    pub(crate) fn host(&self) -> &str {
        url::parse(&self.server_url).map_or("", |parts| parts.host)
    }

    /// `K_ch`, for the derivations of specs 012 and 013 (R6).
    pub(crate) fn channel_key(&self) -> &Secret<32> {
        &self.k_ch
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

/// Seven words of the list joined by single spaces, drawn with
/// `random_bytes` (R16).
pub(crate) fn draw_password() -> Result<Zeroizing<Vec<u8>>, Error> {
    let draws = Zeroizing::new(crypto::random_bytes::<PASSWORD_DRAW_LEN>()?);
    let mut password = Zeroizing::new(Vec::with_capacity(MAX_DRAWN_PASSWORD));
    for (high, low) in draws.iter().step_by(2).zip(draws.iter().skip(1).step_by(2)) {
        let index = u16::from_be_bytes([*high, *low]) & WORD_INDEX_MASK;
        let word = wordlist::word(index).ok_or(Error::Internal)?;
        if !password.is_empty() {
            password.push(b' ');
        }
        password.extend_from_slice(word.as_bytes());
    }
    Ok(password)
}

/// The checks of R13 that need no password and no key: the size of the
/// header, the magic, the version byte, then the exact length.
pub(crate) fn parse_file_header(bytes: &[u8]) -> Result<(), Error> {
    let (header, _) = bytes
        .split_first_chunk::<FILE_HEADER_LEN>()
        .ok_or(Error::BadConfig)?;
    let (magic, version) = header.split_last_chunk::<1>().ok_or(Error::BadConfig)?;
    let magic: &[u8; 4] = magic.try_into().map_err(|_| Error::BadConfig)?;
    if !crypto::ct_eq(magic, FILE_MAGIC) {
        return Err(Error::BadConfig);
    }
    if *version != [VERSION] {
        return Err(Error::UnsupportedVersion);
    }
    if bytes.len() != FILE_LEN {
        return Err(Error::BadConfig);
    }
    Ok(())
}

/// The canonical form of a typed password (R15): ASCII letters lowercased,
/// every run of `White_Space` one U+0020, no space at either end. Bounded
/// before it is read, and built in a buffer of the typed length, which it
/// never outgrows.
fn canonical_password(typed: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    if typed.len() > MAX_TYPED_PASSWORD {
        return Err(Error::BadPassword);
    }
    let text = core::str::from_utf8(typed).map_err(|_| Error::BadPassword)?;
    let mut canonical = Zeroizing::new(Vec::with_capacity(typed.len()));
    for word in text
        .split(char::is_whitespace)
        .filter(|word| !word.is_empty())
    {
        if !canonical.is_empty() {
            canonical.push(b' ');
        }
        canonical.extend(word.bytes().map(|byte| byte.to_ascii_lowercase()));
    }
    if canonical.is_empty() || canonical.len() > MAX_CANONICAL_PASSWORD {
        return Err(Error::BadPassword);
    }
    Ok(canonical)
}

/// A fixed region of a file whose length `parse_file_header` checked.
fn region<const N: usize>(bytes: &[u8], range: Range<usize>) -> Result<[u8; N], Error> {
    let region = bytes.get(range).ok_or(Error::BadConfig)?;
    region.try_into().map_err(|_| Error::BadConfig)
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
        server_url: required(reader.text(KEY_SERVER_URL, url::MAX_URL))?,
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
    let url_ok = url::parse(server_url).is_ok();
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
