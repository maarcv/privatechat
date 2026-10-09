//! The message envelope of `docs/spec.md` §4 (spec 013-wire-message): a
//! fixed binary layout, not a record, sealed encrypt-then-sign and verified
//! in the normative order of steps 1–4 (ADR 0005, 0018, 0027, 0032).
//!
//! Pure: every input is a parameter and nothing reads or writes state. Steps
//! 5, 6 and 8 of the verification belong to spec 021-channel-session, which
//! calls `verify`, then its state checks, then `open`. Drawing the nonce and
//! reserving the counter are spec 021's too.

use core::ops::Range;

use super::config::{ChannelId, Config};
use super::header::{ENC_HDR_LEN, Header, header_keystream};
use super::keys::{ChannelKeys, message_key};
use super::payload::{PAD_BLOCK, Payload, PayloadHead, is_padded_len};
use crate::Error;
use crate::crypto::{self, CryptoError, Nonce, PublicKey, Secret, Signature, TAG_LEN};

#[cfg(test)]
mod tests;

#[cfg(any(test, fuzzing))]
pub(crate) mod text_k1;

/// Wire protocol version 1 (R2, R15).
pub(crate) const PROTO_V1: u8 = 0x01;

/// The fixed header before the ciphertext, which is also the AEAD's
/// associated data (R1, R3).
pub(crate) const HEADER_LEN: usize = 81;

/// The regions of the fixed header (R1).
const CHANNEL_ID_RANGE: Range<usize> = 1..17;
const ENC_HDR_RANGE: Range<usize> = 17..57;
pub(crate) const NONCE_RANGE: Range<usize> = 57..81;

/// An Ed25519 signature, the last bytes of a blob (R1).
const SIGNATURE_LEN: usize = 64;

/// Everything in a blob but the padded payload: header, tag and signature.
pub(crate) const BLOB_OVERHEAD: usize = HEADER_LEN + TAG_LEN + SIGNATURE_LEN;

/// The domain tag of the message signature (`docs/spec.md` §4, R4).
pub(crate) const MSG_SIGNATURE_TAG: &[u8; 18] = b"privatechat/msg/v1";

/// The margin both expiry checks add to the TTL: five minutes of clock skew
/// and the rounding of `sent_at` to the minute (R13). Spec 021 uses it too.
pub(crate) const EXPIRY_MARGIN_MS: u64 = 360_000;

/// The counter every `key_retired` is sealed with, which no ordinary message
/// can take (R15, ADR 0033). Spec 021 uses it.
pub(crate) const KEY_RETIRED_COUNTER: u64 = u64::MAX;

/// `u64(ttl_seconds) × 1000`, the one conversion of a TTL (R13).
pub(crate) fn ttl_ms(ttl_seconds: u32) -> u64 {
    u64::from(ttl_seconds).saturating_mul(1_000)
}

/// What a channel needs to seal and verify: its identifier, its keys and
/// its TTL, all from one config (R19).
pub(crate) struct ChannelCtx {
    id: ChannelId,
    keys: ChannelKeys,
    ttl_seconds: u32,
}

impl ChannelCtx {
    /// The context of `config`, so that the keys of one channel never go
    /// with the identifier of another (R19).
    ///
    /// # Errors
    ///
    /// `Internal` when libsodium fails to initialise.
    pub(crate) fn from_config(config: &Config) -> Result<ChannelCtx, Error> {
        Ok(ChannelCtx {
            id: ChannelId(config.id().0),
            keys: ChannelKeys::derive(config.channel_key())?,
            ttl_seconds: config.ttl_seconds(),
        })
    }
}

/// `pk_u` and `sk_u` of one sender, always from the same seed (R5). No
/// `Debug`: it holds `sk_u`.
pub(crate) struct SenderKey {
    pk: PublicKey,
    sk: Secret<64>,
}

impl SenderKey {
    /// The key pair of `seed`.
    ///
    /// # Errors
    ///
    /// `Internal` when libsodium fails to initialise.
    pub(crate) fn from_seed(seed: &Secret<32>) -> Result<SenderKey, Error> {
        let (pk, sk) = crypto::sign_keypair_from_seed(seed)?;
        Ok(SenderKey { pk, sk })
    }

    /// `pk_u`, which the header carries.
    pub(crate) fn public(&self) -> &PublicKey {
        &self.pk
    }
}

/// The blob, and its signature before masking, which spec 021 keeps for the
/// own-key echo (R20, ADR 0029).
pub(crate) struct Sealed {
    pub(crate) blob: Vec<u8>,
    pub(crate) signature: [u8; SIGNATURE_LEN],
}

/// Validates, encodes and pads `payload`, then seals it (R16).
///
/// # Errors
///
/// `BadPayload` when `validate` refuses the payload, and `Internal` when
/// libsodium fails.
pub(crate) fn seal(
    ctx: &ChannelCtx,
    sender: &SenderKey,
    counter: u64,
    nonce: &Nonce,
    payload: &Payload,
) -> Result<Sealed, Error> {
    payload.validate()?;
    let mut padded = payload.encode()?;
    crypto::pad(&mut padded, PAD_BLOCK)?;
    seal_padded(ctx, sender, counter, nonce, &padded)
}

/// Seals an already padded payload with no validation of its content: the
/// header hidden, the AEAD over `blob[0..81]`, the signature over the tag
/// and everything before it, then masked (R3, R4, R16). The nonce is the
/// caller's, drawn once per message (R5).
///
/// # Errors
///
/// `BadPayload` for a length that is not 1 024·k with k in 1..=63, and
/// `Internal` when libsodium fails.
pub(crate) fn seal_padded(
    ctx: &ChannelCtx,
    sender: &SenderKey,
    counter: u64,
    nonce: &Nonce,
    padded: &[u8],
) -> Result<Sealed, Error> {
    if !is_padded_len(padded.len()) {
        return Err(Error::BadPayload);
    }
    let (header_mask, signature_mask) = masks(ctx, nonce)?;
    let header = Header {
        sender_pk: sender.pk,
        counter,
    };
    let blob_len = padded
        .len()
        .checked_add(BLOB_OVERHEAD)
        .ok_or(Error::BadPayload)?;
    let mut blob = Vec::with_capacity(blob_len);
    blob.push(PROTO_V1);
    blob.extend_from_slice(&ctx.id.0);
    blob.extend_from_slice(&xor(header.to_bytes(), &header_mask));
    blob.extend_from_slice(&nonce.0);
    let mk = message_key(&ctx.keys, &sender.pk, counter)?;
    let ciphertext = crypto::aead_encrypt(&mk, nonce, &blob, padded)?;
    drop(mk);
    blob.extend_from_slice(&ciphertext);
    let signature = crypto::sign_detached(&sender.sk, &signed_message(&blob))?;
    blob.extend_from_slice(&xor(signature.0, &signature_mask));
    Ok(Sealed {
        blob,
        signature: signature.0,
    })
}

/// Steps 1–4 of `docs/spec.md` §4, in order, each with its own error (R11):
/// length, version and channel; expiry; the header opened and the signature
/// unmasked; the signature. Reads no state and has no effect.
///
/// # Errors
///
/// `BadLength`, `UnsupportedVersion`, `WrongChannel`, `Expired` and
/// `BadSignature`, the first that applies; `Internal` when libsodium fails.
pub(crate) fn verify<'a>(
    blob: &'a [u8],
    ctx: &'a ChannelCtx,
    received_at: u64,
    now: u64,
) -> Result<Verified<'a>, Error> {
    let envelope = Envelope::parse(blob, &ctx.id)?;
    let deadline = received_at
        .min(now)
        .saturating_add(ttl_ms(ctx.ttl_seconds))
        .saturating_add(EXPIRY_MARGIN_MS);
    if deadline < now {
        return Err(Error::Expired);
    }
    let (header_mask, signature_mask) = masks(ctx, &envelope.nonce)?;
    let header = Header::from_bytes(&xor(*envelope.enc_hdr, &header_mask));
    let signature = xor(*envelope.signature, &signature_mask);
    // Step 4 before anything reads the header: a flipped bit of `sender_pk`
    // or `counter` decides nothing (ADR 0027).
    crypto::verify_detached(
        &header.sender_pk,
        &signed_message(envelope.signed),
        &Signature(signature),
    )
    .map_err(bad_signature)?;
    Ok(Verified {
        envelope,
        ctx,
        header,
        signature,
        received_at,
        now,
    })
}

/// A blob whose steps 1–4 passed. It borrows the blob and keeps the times
/// `verify` received, so both expiry checks see the same ones.
pub(crate) struct Verified<'a> {
    envelope: Envelope<'a>,
    ctx: &'a ChannelCtx,
    header: Header,
    signature: [u8; SIGNATURE_LEN],
    received_at: u64,
    now: u64,
}

impl Verified<'_> {
    /// The `sender_pk` of the opened header, which the signature proved.
    pub(crate) fn sender_pk(&self) -> &PublicKey {
        &self.header.sender_pk
    }

    /// The sender's counter for this message.
    pub(crate) fn counter(&self) -> u64 {
        self.header.counter
    }

    /// The unmasked signature, for the own-key echo of spec 021 (R20, ADR
    /// 0029).
    pub(crate) fn signature(&self) -> &[u8; SIGNATURE_LEN] {
        &self.signature
    }

    /// Step 7, with the times `verify` received (R12): the AEAD, after which
    /// the message is consumed whatever it holds; then the padding; then the
    /// record up to `sent_at`, the stale check, and only then the rest of
    /// the record, the `type` and `validate`.
    ///
    /// # Errors
    ///
    /// `BadSignature` when the AEAD does not open, which a valid signature
    /// and the right `K_ch` make impossible, and `Internal` when libsodium
    /// fails. Every other outcome is a `Content`.
    pub(crate) fn open(self) -> Result<Opened, Error> {
        let mk = message_key(&self.ctx.keys, &self.header.sender_pk, self.header.counter)?;
        let envelope = &self.envelope;
        let padded = crypto::aead_decrypt(&mk, &envelope.nonce, envelope.aad, envelope.ciphertext)
            .map_err(bad_signature)?;
        drop(mk);
        let (sent_at, content) = self.read(&padded)?;
        Ok(Opened {
            sender_pk: self.header.sender_pk,
            counter: self.header.counter,
            sent_at,
            content,
        })
    }

    /// The padded payload of a consumed message, and `sent_at` when key 2
    /// was read (R12).
    fn read(&self, padded: &[u8]) -> Result<(Option<u64>, Content), Error> {
        let len = match crypto::unpad(padded, PAD_BLOCK) {
            Ok(len) => len,
            Err(CryptoError::BadPadding) => return Ok((None, Content::Unreadable)),
            Err(other) => return Err(Error::from(other)),
        };
        let Some(record) = padded.get(..len) else {
            return Ok((None, Content::Unreadable));
        };
        let Ok(head) = PayloadHead::read(record) else {
            return Ok((None, Content::Unreadable));
        };
        let sent_at = head.sent_at;
        if self.is_stale(sent_at) {
            return Ok((Some(sent_at), Content::Stale));
        }
        let payload = head
            .finish()
            .and_then(|payload| payload.validate().map(|()| payload));
        let content = payload.map_or(Content::Unreadable, Content::Message);
        Ok((Some(sent_at), content))
    }

    /// Kept past its TTL, minted old, or dated more than one TTL ahead (ADR
    /// 0027, 0030), with saturating arithmetic so that no time overflows
    /// (R13).
    fn is_stale(&self, sent_at: u64) -> bool {
        let window = ttl_ms(self.ctx.ttl_seconds).saturating_add(EXPIRY_MARGIN_MS);
        let received = self.received_at.min(self.now);
        sent_at.saturating_add(window) < received || self.now.saturating_add(window) < sent_at
    }
}

/// What `open` made of a consumed message. `sent_at` is `None` when it could
/// not be read; spec 021 needs it for the own-key rule (ADR 0029).
#[derive(Debug)]
pub(crate) struct Opened {
    pub(crate) sender_pk: PublicKey,
    pub(crate) counter: u64,
    pub(crate) sent_at: Option<u64>,
    pub(crate) content: Content,
}

/// A readable message, one kept as `Unreadable`, or a stale one, which
/// spec 021 discards as `Expired` (R12).
#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub(crate) enum Content {
    Message(Payload),
    Unreadable,
    Stale,
}

/// The fields of a blob that passed step 1, borrowed from it; the offsets
/// exist here only.
struct Envelope<'a> {
    enc_hdr: &'a [u8; ENC_HDR_LEN],
    nonce: Nonce,
    /// `blob[0..81]`, the associated data exactly as it travelled (R3).
    aad: &'a [u8],
    ciphertext: &'a [u8],
    /// The signature as it travels, masked (ADR 0032).
    signature: &'a [u8; SIGNATURE_LEN],
    /// `blob[0..81 + n]`, what the signature covers after the tag (R4).
    signed: &'a [u8],
}

impl<'a> Envelope<'a> {
    /// Step 1: the length class, then the version, then the channel (R2).
    fn parse(blob: &'a [u8], channel: &ChannelId) -> Result<Envelope<'a>, Error> {
        let len = blob.len();
        let padded = len.checked_sub(BLOB_OVERHEAD).ok_or(Error::BadLength)?;
        if !is_padded_len(padded) {
            return Err(Error::BadLength);
        }
        if blob.first() != Some(&PROTO_V1) {
            return Err(Error::UnsupportedVersion);
        }
        // The id is public, but one rule beats a judgement call (AGENTS 22).
        if !crypto::ct_eq(region(blob, CHANNEL_ID_RANGE)?, &channel.0) {
            return Err(Error::WrongChannel);
        }
        // The regions cannot fail after the length class; still `BadLength`.
        let signature_at = len.checked_sub(SIGNATURE_LEN).ok_or(Error::BadLength)?;
        let bytes = |range: Range<usize>| blob.get(range).ok_or(Error::BadLength);
        Ok(Envelope {
            enc_hdr: region(blob, ENC_HDR_RANGE)?,
            nonce: Nonce(*region(blob, NONCE_RANGE)?),
            aad: bytes(0..HEADER_LEN)?,
            ciphertext: bytes(HEADER_LEN..signature_at)?,
            signature: region(blob, signature_at..len)?,
            signed: bytes(0..signature_at)?,
        })
    }
}

/// A fixed region of a blob whose length step 1 checked.
fn region<const N: usize>(blob: &[u8], range: Range<usize>) -> Result<&[u8; N], Error> {
    let bytes = blob.get(range).ok_or(Error::BadLength)?;
    bytes.try_into().map_err(|_| Error::BadLength)
}

/// Bytes 0..40 of the header keystream hide the header and bytes 40..104
/// the signature (spec 012 R4, ADR 0032).
fn masks(
    ctx: &ChannelCtx,
    nonce: &Nonce,
) -> Result<([u8; ENC_HDR_LEN], [u8; SIGNATURE_LEN]), Error> {
    let stream = header_keystream(&ctx.keys, nonce)?;
    let (header_mask, signature_mask) = stream
        .split_first_chunk::<ENC_HDR_LEN>()
        .ok_or(Error::Internal)?;
    let signature_mask = signature_mask.try_into().map_err(|_| Error::Internal)?;
    Ok((*header_mask, signature_mask))
}

/// `"privatechat/msg/v1" ‖ blob[0..81 + n]` in one buffer: the wrapper of
/// spec 010 signs one slice (R4).
fn signed_message(signed: &[u8]) -> Vec<u8> {
    [MSG_SIGNATURE_TAG.as_slice(), signed].concat()
}

/// A signature or an AEAD that does not verify is `BadSignature`, the one
/// verdict of step 4 and of step 7's AEAD (R11, R12); any other failure is
/// libsodium's.
fn bad_signature(error: CryptoError) -> Error {
    match error {
        CryptoError::Forged => Error::BadSignature,
        other => Error::from(other),
    }
}

/// `bytes` XORed with `mask`, byte by byte.
fn xor<const N: usize>(mut bytes: [u8; N], mask: &[u8; N]) -> [u8; N] {
    for (byte, mask) in bytes.iter_mut().zip(mask) {
        *byte ^= mask;
    }
    bytes
}
