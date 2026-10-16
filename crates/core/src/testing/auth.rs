//! The credential of a `subscribe`, for the tests of the server (spec
//! 031-auth-channel-signature), which cannot sign: it holds no key.

use crate::Error;
use crate::crypto::{self, Secret};
use crate::proto::auth::auth_message;
use crate::proto::config::Config;

/// A URL of the grammar, for the key pair alone: `pk_ch` and `channel_id`
/// depend on `K_ch` and the TTL, never on the server.
const ANY_URL: &str = "wss://h";

/// The `pk_ch` and `sig` a member of the channel `(k_ch, ttl_seconds)` sends
/// under `server_nonce` for `host`, signed as spec 028-session-sans-io R6
/// signs them; `host` is taken as it is, so that a test can sign one no
/// config would give.
///
/// # Errors
///
/// `BadConfig` for a TTL out of range, `Internal` when libsodium fails.
pub fn subscribe_credential(
    k_ch: [u8; 32],
    ttl_seconds: u32,
    server_nonce: &[u8; 32],
    host: &str,
) -> Result<([u8; 32], [u8; 64]), Error> {
    let config = Config::from_parts(Secret::from_bytes(k_ch), ANY_URL, ttl_seconds, "room", 0)?;
    let (pk_ch, sk_ch) = config.channel_keypair()?;
    let message = auth_message(server_nonce, config.id(), ttl_seconds, host);
    let sig = crypto::sign_detached(&sk_ch, &message)?;
    Ok((pk_ch.0, sig.0))
}
