//! The items of the protocol that only the server uses (`docs/spec.md` §6),
//! `pub` for the `server` crate alone (spec 027-core-api R16): its random
//! identifiers, and the check of a `subscribe` (spec 031-auth-channel-signature)
//! through the same builders the client signs with. Spec 030-ws-protocol adds
//! its items here.

use crate::Error;
use crate::crypto::{self, CryptoError, PublicKey, Signature};
use crate::proto::auth::auth_message;
use crate::proto::config::{ChannelId, TTL_SECONDS, url};

/// The most configured hosts a `subscribe` is checked against (spec 031 R4).
const MAX_HOSTS: usize = 8;

/// A new `server_id`: 16 bytes from libsodium's random source, unique and
/// unordered, so that it reveals no volume (spec 032-storage-ttl R15).
///
/// # Errors
///
/// `Error::Internal` when libsodium cannot initialise.
pub fn new_server_id() -> Result<[u8; 16], Error> {
    Ok(crypto::random_bytes()?)
}

/// A new `server_nonce` for a `hello`: 32 bytes from libsodium's random
/// source (spec 031 R1).
///
/// # Errors
///
/// `Error::Internal` when libsodium cannot initialise.
pub fn new_nonce() -> Result<[u8; 32], Error> {
    Ok(crypto::random_bytes()?)
}

/// The `channel_id` of `(pk_ch, ttl_seconds)`, through the derivation the
/// config uses (spec 031 R3, spec 011-config-format R8).
///
/// # Errors
///
/// `Error::Internal` when libsodium fails.
pub fn channel_id(pk_ch: &[u8; 32], ttl_seconds: u32) -> Result<[u8; 16], Error> {
    Ok(ChannelId::derive(&PublicKey(*pk_ch), ttl_seconds)?.0)
}

/// Checks a `subscribe`: the `channel_id` it opens, when `sig` signs the
/// message of `auth_message` under `pk_ch` for one of `hosts`, tried in
/// order (spec 031 R4).
///
/// # Errors
///
/// `Error::BadConfig` for a TTL outside 60..=2 592 000 or a list of hosts
/// empty or longer than 8, before any signature is checked;
/// `Error::BadSignature` when no host verifies; `Error::Internal` when
/// libsodium fails.
pub fn verify_subscribe(
    pk_ch: &[u8; 32],
    ttl_seconds: u32,
    sig: &[u8; 64],
    server_nonce: &[u8; 32],
    hosts: &[String],
) -> Result<[u8; 16], Error> {
    if !TTL_SECONDS.contains(&ttl_seconds) || hosts.is_empty() || hosts.len() > MAX_HOSTS {
        return Err(Error::BadConfig);
    }
    let public_key = PublicKey(*pk_ch);
    let signature = Signature(*sig);
    let id = ChannelId::derive(&public_key, ttl_seconds)?;
    for host in hosts {
        let message = auth_message(server_nonce, &id, ttl_seconds, host);
        match crypto::verify_detached(&public_key, &message, &signature) {
            Ok(()) => return Ok(id.0),
            Err(CryptoError::Forged) => {}
            Err(_) => return Err(Error::Internal),
        }
    }
    Err(Error::BadSignature)
}

/// The host of `server_url` that a subscription signature covers, through
/// the one URL parser of the workspace (spec 031 R8, spec 011-config-format
/// R5, R6).
///
/// # Errors
///
/// `Error::BadConfig` for a URL outside the grammar.
pub fn url_host(server_url: &str) -> Result<String, Error> {
    Ok(url::parse(server_url)?.to_owned())
}
