//! The entries of the fuzz targets (spec 016-fuzz-harness), compiled only
//! under `cfg(test)` or the `--cfg fuzzing` that `cargo fuzz` sets, so that
//! no product build holds them.
//!
//! Each target has a `pub fn` that takes the fuzzer's bytes and returns
//! nothing, and a crate-internal `_verdict` twin that returns what the input
//! reached, for the tests of this spec. Each calls the real function with the
//! fixed inputs of the 013 vector `text_k1` and adds no logic of its own; the
//! only sealing, for `receive_signed`, is spec 013's `seal_padded`.

use crate::Error;
use crate::crypto::{Nonce, Secret};
use crate::proto::config::{ChannelId, Config};
use crate::proto::envelope::{self, ChannelCtx, Content, SenderKey, text_k1};
use crate::proto::fingerprint;
use crate::proto::payload::{MAX_BLOCKS, PAD_BLOCK, Payload};
use crate::proto::record::UnknownKeys;
use crate::proto::record::test_schema::decode_test_record;

#[cfg(test)]
mod tests;

/// The times before the blob in the input of `receive` (R4).
const RECEIVE_HEADER_LEN: usize = 16;

/// The counter, nonce and times before the plaintext in the input of
/// `receive_signed` (R5).
const RECEIVE_SIGNED_HEADER_LEN: usize = 48;

/// The most a padded plaintext holds: 63 blocks (spec 013 R10).
const MAX_PADDED: usize = PAD_BLOCK * MAX_BLOCKS;

/// The `channel_id` of 011 `config_reference`, which the 014 vectors use,
/// so that the seeds of `verify_qr_parse` pass the channel check.
const QR_CHANNEL: ChannelId = ChannelId([
    0x26, 0xb0, 0x66, 0x31, 0xaa, 0x61, 0xcb, 0x8f, 0x91, 0xc3, 0x49, 0x8b, 0x1c, 0x59, 0xc2, 0xc7,
]);

/// `record_decode`: the test schema of spec 017 under the policy of the
/// first byte (R3).
pub fn record_decode(data: &[u8]) {
    let _ = record_decode_verdict(data);
}

/// `config_parse`: a config record, at `now = 0` so that no seed's
/// invitation has expired.
pub fn config_parse(data: &[u8]) {
    let _ = config_parse_verdict(data);
}

/// `config_parse_qr`: the QR text of a config, at `now = 0`.
pub fn config_parse_qr(data: &[u8]) {
    let _ = config_parse_qr_verdict(data);
}

/// `payload_decode`: a plaintext payload record of spec 013.
pub fn payload_decode(data: &[u8]) {
    let _ = payload_decode_verdict(data);
}

/// `receive`: `BE64(received_at) ‖ BE64(now) ‖ blob`, verified and opened
/// in the channel of `text_k1` (R4).
pub fn receive(data: &[u8]) {
    let _ = receive_verdict(data);
}

/// `receive_signed`: `BE64(counter) ‖ nonce ‖ BE64(received_at) ‖ BE64(now)
/// ‖ plaintext`, sealed by the sender of `text_k1` and then verified and
/// opened, so that every input passes the signature (R5).
pub fn receive_signed(data: &[u8]) {
    let _ = receive_signed_verdict(data);
}

/// `verify_qr_parse`: a verification QR of spec 014, in the channel of 011
/// `config_reference`.
pub fn verify_qr_parse(data: &[u8]) {
    let _ = verify_qr_parse_verdict(data);
}

pub(crate) fn record_decode_verdict(data: &[u8]) -> Option<Result<(), Error>> {
    let (policy, record) = data.split_first()?;
    let policy = if *policy == 0 {
        UnknownKeys::Ignore
    } else {
        UnknownKeys::Reject
    };
    Some(decode_test_record(record, policy))
}

pub(crate) fn config_parse_verdict(data: &[u8]) -> Result<(), Error> {
    Config::parse(data, 0).map(|_| ())
}

pub(crate) fn config_parse_qr_verdict(data: &[u8]) -> Result<(), Error> {
    Config::parse_qr(data, 0).map(|_| ())
}

pub(crate) fn payload_decode_verdict(data: &[u8]) -> Result<(), Error> {
    Payload::decode(data).map(|_| ())
}

pub(crate) fn receive_verdict(data: &[u8]) -> Option<Result<Content, Error>> {
    let (times, blob) = data.split_first_chunk::<RECEIVE_HEADER_LEN>()?;
    let (received_at, now) = times.split_first_chunk::<8>()?;
    let received_at = u64::from_be_bytes(*received_at);
    let now = u64::from_be_bytes(now.try_into().ok()?);
    Some(open(blob, received_at, now))
}

pub(crate) fn receive_signed_verdict(data: &[u8]) -> Option<Result<Content, Error>> {
    let (header, plaintext) = data.split_first_chunk::<RECEIVE_SIGNED_HEADER_LEN>()?;
    let (counter, rest) = header.split_first_chunk::<8>()?;
    let (nonce, rest) = rest.split_first_chunk::<24>()?;
    let (received_at, now) = rest.split_first_chunk::<8>()?;
    let now = u64::from_be_bytes(now.try_into().ok()?);
    // Truncated to 63 blocks, then zeros up to a whole block, one at least.
    let mut padded = plaintext.get(..MAX_PADDED).unwrap_or(plaintext).to_vec();
    let blocks = padded.len().div_ceil(PAD_BLOCK).max(1);
    padded.resize(blocks.saturating_mul(PAD_BLOCK), 0);
    let sealed = context().and_then(|ctx| {
        let sender = SenderKey::from_seed(&Secret::from_bytes(text_k1::SENDER_SEED))?;
        let counter = u64::from_be_bytes(*counter);
        envelope::seal_padded(&ctx, &sender, counter, &Nonce(*nonce), &padded)
    });
    Some(sealed.and_then(|sealed| open(&sealed.blob, u64::from_be_bytes(*received_at), now)))
}

pub(crate) fn verify_qr_parse_verdict(data: &[u8]) -> Result<(), Error> {
    fingerprint::parse_verify_qr(data, &QR_CHANNEL).map(|_| ())
}

/// `verify`, then `open`, in the channel of `text_k1`.
fn open(blob: &[u8], received_at: u64, now: u64) -> Result<Content, Error> {
    let ctx = context()?;
    let opened = envelope::verify(blob, &ctx, received_at, now)?.open()?;
    Ok(opened.content)
}

/// The channel of the 013 vector `text_k1`.
fn context() -> Result<ChannelCtx, Error> {
    let config = Config::from_parts(
        Secret::from_bytes(text_k1::K_CH),
        text_k1::SERVER_URL,
        text_k1::TTL_SECONDS,
        text_k1::SUGGESTED_NAME,
        text_k1::CREATED_AT,
    )?;
    ChannelCtx::from_config(&config)
}
