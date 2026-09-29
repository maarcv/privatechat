//! The user fingerprint of `docs/spec.md` §4 and its three presentations
//! (spec 014-fingerprint, ADR 0025): the verification QR, 12 words and the
//! short identifier of 4.
//!
//! Pure functions of a `channel_id` and a `pk_u`. What the interface does
//! with them is spec 055-verify-ui; collisions of short identifiers are spec
//! 022-peers-tofu. The word list is spec 011's and the base64url codec spec
//! 010's; neither is copied here.

use super::config::ChannelId;
use super::wordlist;
use crate::Error;
use crate::crypto::{self, CryptoError, PublicKey};

#[cfg(test)]
mod tests;

/// The domain tag of the fingerprint (`docs/spec.md` §4, R1).
pub(crate) const FP_TAG: &[u8; 17] = b"privatechat/fp/v1";

/// The prefix of a verification QR (R3).
pub(crate) const QR_PREFIX: &[u8; 10] = b"verify:v1:";

/// Words of a fingerprint, and of its short identifier (R5, R6).
pub(crate) const WORD_COUNT: usize = 12;
pub(crate) const SHORT_WORD_COUNT: usize = 4;

/// Each word is an 11-bit index into the 2 048 words of the list (R5).
const BITS_PER_WORD: usize = 11;
const WORD_MASK: u32 = 0x07ff;

/// A QR is the prefix and the 64 characters of the 48 bytes
/// `channel_id ‖ pk_u` (R3).
const QR_LEN: usize = 74;

/// The three presentations of one fingerprint, the `Record` of the core
/// boundary (`docs/spec.md` §9). Built only by [`presentation`], which
/// guarantees 12 `words` and 4 `short` (R8).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fingerprint {
    /// The 12 words to read aloud (R5).
    pub words: Vec<String>,
    /// The first 4 words, which tell peers apart and verify nothing (R6).
    pub short: Vec<String>,
    /// The verification QR, as bytes (R3).
    pub qr: Vec<u8>,
}

/// `hash("privatechat/fp/v1" ‖ channel_id ‖ pk_u)`, over 65 bytes (R1).
///
/// # Errors
///
/// `Internal` when libsodium fails to initialise.
pub(crate) fn fingerprint(channel_id: &ChannelId, pk_u: &PublicKey) -> Result<[u8; 32], Error> {
    let input = [FP_TAG.as_slice(), &channel_id.0, &pk_u.0].concat();
    Ok(crypto::hash(&input)?)
}

/// `words[i] = list[bits(fp, 11·i, 11)]`: the first 132 bits of `fp`, most
/// significant bit first, with no checksum; not a BIP-39 mnemonic (R5).
///
/// # Errors
///
/// `Internal` for an index outside the list, which 11 bits make impossible.
pub(crate) fn words(fp: &[u8; 32]) -> Result<[&'static str; WORD_COUNT], Error> {
    let mut words = [""; WORD_COUNT];
    for (position, slot) in words.iter_mut().enumerate() {
        // The 11 bits at `offset` lie within the 3 bytes from `offset / 8`.
        let offset = position.checked_mul(BITS_PER_WORD).ok_or(Error::Internal)?;
        let start = offset.checked_div(8).ok_or(Error::Internal)?;
        let skipped = offset.checked_rem(8).ok_or(Error::Internal)?;
        let [a, b, c] = *fp
            .get(start..)
            .and_then(<[u8]>::first_chunk::<3>)
            .ok_or(Error::Internal)?;
        let shift = (24 - BITS_PER_WORD)
            .checked_sub(skipped)
            .and_then(|shift| u32::try_from(shift).ok())
            .ok_or(Error::Internal)?;
        let bits = u32::from_be_bytes([0, a, b, c])
            .checked_shr(shift)
            .ok_or(Error::Internal)?;
        let index = u16::try_from(bits & WORD_MASK).map_err(|_| Error::Internal)?;
        *slot = wordlist::word(index).ok_or(Error::Internal)?;
    }
    Ok(words)
}

/// The first 4 of the 12 words (R6). Output only: nothing in `core` takes a
/// short identifier as input.
pub(crate) fn short_identifier(
    words: &[&'static str; WORD_COUNT],
) -> [&'static str; SHORT_WORD_COUNT] {
    let [first, second, third, fourth, ..] = *words;
    [first, second, third, fourth]
}

/// `verify:v1:` and the base64url of `channel_id ‖ pk_u`, 74 bytes with no
/// name (R3).
///
/// # Errors
///
/// `Internal` when libsodium fails.
pub(crate) fn verify_qr(channel_id: &ChannelId, pk_u: &PublicKey) -> Result<Vec<u8>, Error> {
    let body = crypto::base64url_encode(&[channel_id.0.as_slice(), &pk_u.0].concat())?;
    Ok([QR_PREFIX.as_slice(), &body].concat())
}

/// The `pk_u` of a verification QR of the open channel (R4).
///
/// # Errors
///
/// `BadPayload` for a QR that is not 74 bytes, whose prefix is not
/// `verify:v1:` or whose body is not strict base64url; `WrongChannel` for a
/// QR of another channel; `Internal` when libsodium fails.
pub(crate) fn parse_verify_qr(bytes: &[u8], channel_id: &ChannelId) -> Result<PublicKey, Error> {
    if bytes.len() != QR_LEN {
        return Err(Error::BadPayload);
    }
    let (prefix, body) = bytes.split_first_chunk::<10>().ok_or(Error::BadPayload)?;
    if !crypto::ct_eq(prefix, QR_PREFIX) {
        return Err(Error::BadPayload);
    }
    let decoded = crypto::base64url_decode(body).map_err(|error| match error {
        CryptoError::BadEncoding => Error::BadPayload,
        other => Error::from(other),
    })?;
    let (id, pk): (&[u8; 16], &[u8]) = decoded.split_first_chunk().ok_or(Error::BadPayload)?;
    let pk: [u8; 32] = pk.try_into().map_err(|_| Error::BadPayload)?;
    if !crypto::ct_eq(id, &channel_id.0) {
        return Err(Error::WrongChannel);
    }
    Ok(PublicKey(pk))
}

/// The three presentations of the fingerprint of `pk_u` in the channel, the
/// only constructor of a [`Fingerprint`] (R8).
///
/// # Errors
///
/// `Internal` when libsodium fails.
pub(crate) fn presentation(channel_id: &ChannelId, pk_u: &PublicKey) -> Result<Fingerprint, Error> {
    let words = words(&fingerprint(channel_id, pk_u)?)?;
    Ok(Fingerprint {
        words: words.map(str::to_owned).to_vec(),
        short: short_identifier(&words).map(str::to_owned).to_vec(),
        qr: verify_qr(channel_id, pk_u)?,
    })
}
