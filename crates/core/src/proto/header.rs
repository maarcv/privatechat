//! The plaintext header of the envelope and the keystream that hides it
//! (`docs/spec.md` §4, spec 012-message-keys R4, R5, ADR 0018, 0032).
//!
//! The header is `sender_pk ‖ BE64(counter)`, 40 bytes. The keystream is 104
//! bytes of `stream_xor(K_hdr, nonce)` over zeros: the first 40 hide the
//! header, the last 64 the signature. The two XORs and the order of the
//! checks on receive are `envelope.rs` of spec 013-wire-message.

use super::keys::ChannelKeys;
use crate::Error;
use crate::crypto::{self, Nonce, PublicKey};

#[cfg(test)]
mod tests;

/// Bytes of the header, and of `enc_hdr`, the header as it travels (R4).
pub(crate) const ENC_HDR_LEN: usize = 40;

/// Bytes of the keystream: 40 for the header, 64 for the signature mask
/// (ADR 0032).
pub(crate) const HEADER_STREAM_LEN: usize = 104;

/// The plaintext header: who wrote and which of their messages it is. It
/// holds no key and applies no XOR (R4).
#[derive(Debug, PartialEq)]
pub(crate) struct Header {
    /// The sender's `pk_u`.
    pub(crate) sender_pk: PublicKey,
    /// The sender's counter for this message.
    pub(crate) counter: u64,
}

impl Header {
    /// `sender_pk ‖ BE64(counter)` (R4).
    pub(crate) fn to_bytes(&self) -> [u8; ENC_HDR_LEN] {
        let counter = self.counter.to_be_bytes();
        let mut bytes = [0u8; ENC_HDR_LEN];
        for (slot, byte) in bytes
            .iter_mut()
            .zip(self.sender_pk.0.iter().chain(&counter))
        {
            *slot = *byte;
        }
        bytes
    }

    /// The header of 40 bytes. It never fails: under a wrong `K_hdr` it is a
    /// random key and a random counter, which the signature of spec 013
    /// rejects, so that no error tells a holder of a blob whether they
    /// guessed the key (R5, ADR 0018).
    pub(crate) fn from_bytes(bytes: &[u8; ENC_HDR_LEN]) -> Header {
        let [sender_pk @ .., c0, c1, c2, c3, c4, c5, c6, c7] = *bytes;
        Header {
            sender_pk: PublicKey(sender_pk),
            counter: u64::from_be_bytes([c0, c1, c2, c3, c4, c5, c6, c7]),
        }
    }
}

/// `stream_xor(K_hdr, nonce)` over 104 zero bytes, with the nonce the
/// envelope carries: bytes 0..40 for the header, 40..104 for the signature
/// (R4).
///
/// # Errors
///
/// `Internal` when libsodium fails to initialise; the fixed lengths make its
/// other failures unreachable (R5).
pub(crate) fn header_keystream(
    keys: &ChannelKeys,
    nonce: &Nonce,
) -> Result<[u8; HEADER_STREAM_LEN], Error> {
    let mut stream = [0u8; HEADER_STREAM_LEN];
    crypto::stream_xor(&keys.hdr, nonce, &mut stream)?;
    Ok(stream)
}
