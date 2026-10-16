//! The items of the protocol that only the server uses (`docs/spec.md` §6),
//! `pub` for the `server` crate alone (spec 027-core-api R16). Specs
//! 030-ws-protocol and 031-auth-channel-signature add theirs here.

use crate::Error;
use crate::crypto;

/// A new `server_id`: 16 bytes from libsodium's random source, unique and
/// unordered, so that it reveals no volume (spec 032-storage-ttl R15).
///
/// # Errors
///
/// `Error::Internal` when libsodium cannot initialise.
pub fn new_server_id() -> Result<[u8; 16], Error> {
    Ok(crypto::random_bytes()?)
}
