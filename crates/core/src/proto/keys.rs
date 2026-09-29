//! The keys that hang off `K_ch` (`docs/spec.md` §4 "Keys", spec
//! 012-message-keys): `K_msg` and `K_hdr`, derived once per channel, and the
//! key of each message, derived from `K_msg` for one call and dropped.
//!
//! Pure functions only. The envelope that uses these keys is spec
//! 013-wire-message; the counters and the peers are spec 021-channel-session.

use crate::Error;
use crate::crypto::{self, KdfContext, PublicKey, Secret};

#[cfg(test)]
mod tests;

/// KDF context of `K_msg` (`docs/spec.md` §4, R1, R7).
pub(crate) const CONTEXT_MESSAGE: KdfContext = KdfContext::new(*b"msgkey__");

/// KDF context of `K_hdr` (`docs/spec.md` §4, R1, R7).
pub(crate) const CONTEXT_HEADER: KdfContext = KdfContext::new(*b"chhdr___");

/// The two keys every member derives from `K_ch`. `Debug` shows neither: each
/// field is a `Secret`, whose `Debug` is `[REDACTED]`.
#[derive(Debug)]
pub(crate) struct ChannelKeys {
    /// `K_msg`, from which each message key is computed (R2).
    pub(crate) msg: Secret<32>,
    /// `K_hdr`, whose keystream hides the header and the signature (R4).
    pub(crate) hdr: Secret<32>,
}

impl ChannelKeys {
    /// `K_msg = kdf_derive(K_ch, "msgkey__")` and
    /// `K_hdr = kdf_derive(K_ch, "chhdr___")` (R1).
    ///
    /// # Errors
    ///
    /// `Internal` when libsodium fails (R6).
    pub(crate) fn derive(channel_key: &Secret<32>) -> Result<ChannelKeys, Error> {
        Ok(ChannelKeys {
            msg: crypto::kdf_derive(channel_key, &CONTEXT_MESSAGE)?,
            hdr: crypto::kdf_derive(channel_key, &CONTEXT_HEADER)?,
        })
    }
}

/// `mk = keyed_hash(K_msg, pk_u ‖ BE64(counter))` (R2). Returned by value to
/// the one function that seals or opens a message, which keeps it as a local
/// and drops it before returning (R3).
///
/// # Errors
///
/// `Internal` when libsodium fails (R6).
pub(crate) fn message_key(
    keys: &ChannelKeys,
    sender_pk: &PublicKey,
    counter: u64,
) -> Result<Secret<32>, Error> {
    let counter = counter.to_be_bytes();
    let mut input = [0u8; 40];
    for (slot, byte) in input.iter_mut().zip(sender_pk.0.iter().chain(&counter)) {
        *slot = *byte;
    }
    Ok(crypto::keyed_hash(&keys.msg, &input)?)
}
