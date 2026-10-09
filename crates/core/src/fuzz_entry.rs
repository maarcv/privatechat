//! The entries of the fuzz targets (spec 016-fuzz-harness), compiled only
//! under `cfg(test)` or the `--cfg fuzzing` that `cargo fuzz` sets, so that
//! no product build holds them.
//!
//! Each target has a `pub fn` that takes the fuzzer's bytes and returns
//! nothing, and a crate-internal `_verdict` twin that returns what the input
//! reached, for the tests of this spec. Each calls the real function with
//! fixed inputs: the channel and the sender of the 013 vector `text_k1` for
//! the envelope and the channel, `now = 0` for the config, the channel of 011
//! `config_reference` for the verification QR. None adds logic of its own;
//! the only sealing, for `receive_signed`, is spec 013's `seal_padded`.

use crate::Error;
use crate::crypto::{Nonce, Secret};
use crate::proto::config::{ChannelId, Config};
use crate::proto::envelope::{self, ChannelCtx, Content, Opened, SenderKey, text_k1};
use crate::proto::fingerprint;
use crate::proto::payload::{MAX_BLOCKS, PAD_BLOCK, Payload};
use crate::proto::record::UnknownKeys;
use crate::proto::record::test_schema::{TypesRecord, decode_test_record};
use crate::session::channel::{Channel, Received};
use crate::session::connection::{Event, Session};
use crate::session::frames::Frame;
use crate::storage::{ChannelState, LogRecord, Settings, StoreError};

#[cfg(test)]
mod tests;

/// The most a padded plaintext holds: 63 blocks (spec 013 R10).
const MAX_PADDED: usize = PAD_BLOCK * MAX_BLOCKS;

/// The `channel_id` of 011 `config_reference`, which the 014 vectors use,
/// so that the seeds of `verify_qr_parse` pass the channel check; T08 ties
/// it to that config.
const QR_CHANNEL: ChannelId = ChannelId([
    0x26, 0xb0, 0x66, 0x31, 0xaa, 0x61, 0xcb, 0x8f, 0x91, 0xc3, 0x49, 0x8b, 0x1c, 0x59, 0xc2, 0xc7,
]);

/// `record_decode`: the test schema of spec 017 and the codec schema of spec
/// 020, which nests a record and a list, under the policy of the first byte
/// (R3).
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
/// opened, so that every input whose times pass step 2 passes the
/// signature (R5).
pub fn receive_signed(data: &[u8]) {
    let _ = receive_signed_verdict(data);
}

/// `verify_qr_parse`: a verification QR of spec 014, in the channel of 011
/// `config_reference`.
pub fn verify_qr_parse(data: &[u8]) {
    let _ = verify_qr_parse_verdict(data);
}

/// `state_decode`: a plaintext state record of spec 020-store-files, the
/// part of `ChannelState::open` after the box (020 R29).
pub fn state_decode(data: &[u8]) {
    let _ = state_decode_verdict(data);
}

/// `log_record_decode`: a plaintext log record of spec 020, the part of
/// `LogRecord::open` after the box.
pub fn log_record_decode(data: &[u8]) {
    let _ = log_record_decode_verdict(data);
}

/// `settings_decode`: a plaintext settings record of spec 020, the part of
/// `Settings::open` after the box.
pub fn settings_decode(data: &[u8]) {
    let _ = settings_decode_verdict(data);
}

/// `channel_decrypt`: `BE64(received_at) ‖ BE64(now) ‖ server_id ‖ blob`,
/// through `decrypt` of a new channel of `text_k1` whose own key is the
/// sender of `text_k1`, so that the own-key branch is reached (spec
/// 021-channel-session R29).
pub fn channel_decrypt(data: &[u8]) {
    let _ = channel_decrypt_verdict(data);
}

/// `frame_decode`: one frame of spec 028-session-sans-io.
pub fn frame_decode(data: &[u8]) {
    let _ = frame_decode_verdict(data);
}

/// `session_on_frame`: frames of spec 028-session-sans-io, each
/// `BE16(len) ‖ frame`, read by a session subscribed to the channel of
/// `channel_decrypt` (R3).
pub fn session_on_frame(data: &[u8]) {
    let _ = session_on_frame_verdict(data);
}

/// The verdict of `record_decode`; `None` for an input with no policy byte.
pub(crate) fn record_decode_verdict(data: &[u8]) -> Option<Result<(), Error>> {
    let (policy, record) = data.split_first()?;
    let policy = if *policy == 0 {
        UnknownKeys::Ignore
    } else {
        UnknownKeys::Reject
    };
    // The types of spec 020 R1 ride the same bytes; the verdict stays 017's.
    let _ = TypesRecord::decode(record, policy);
    Some(decode_test_record(record, policy))
}

/// The verdict of `config_parse`.
pub(crate) fn config_parse_verdict(data: &[u8]) -> Result<(), Error> {
    Config::parse(data, 0).map(|_| ())
}

/// The verdict of `config_parse_qr`.
pub(crate) fn config_parse_qr_verdict(data: &[u8]) -> Result<(), Error> {
    Config::parse_qr(data, 0).map(|_| ())
}

/// The verdict of `payload_decode`.
pub(crate) fn payload_decode_verdict(data: &[u8]) -> Result<(), Error> {
    Payload::decode(data).map(|_| ())
}

/// The verdict of `receive`; `None` for an input shorter than its two times.
pub(crate) fn receive_verdict(data: &[u8]) -> Option<Result<Content, Error>> {
    let (received_at, rest) = data.split_first_chunk::<8>()?;
    let (now, blob) = rest.split_first_chunk::<8>()?;
    let (received_at, now) = (u64::from_be_bytes(*received_at), u64::from_be_bytes(*now));
    let opened = context().and_then(|ctx| verify_and_open(&ctx, blob, received_at, now));
    Some(opened.map(|opened| opened.content))
}

/// The verdict of `receive_signed`, the whole `Opened` so that the tests see
/// the counter and the sender; `None` for an input shorter than its header.
pub(crate) fn receive_signed_verdict(data: &[u8]) -> Option<Result<Opened, Error>> {
    let (counter, rest) = data.split_first_chunk::<8>()?;
    let (nonce, rest) = rest.split_first_chunk::<24>()?;
    let (received_at, rest) = rest.split_first_chunk::<8>()?;
    let (now, plaintext) = rest.split_first_chunk::<8>()?;
    let (counter, nonce) = (u64::from_be_bytes(*counter), Nonce(*nonce));
    let (received_at, now) = (u64::from_be_bytes(*received_at), u64::from_be_bytes(*now));
    // Truncated to 63 blocks, then zeros up to a whole block, one at least.
    let mut padded = plaintext.get(..MAX_PADDED).unwrap_or(plaintext).to_vec();
    let blocks = padded.len().div_ceil(PAD_BLOCK).max(1);
    padded.resize(blocks.saturating_mul(PAD_BLOCK), 0);
    Some(context().and_then(|ctx| {
        let sender = SenderKey::from_seed(&Secret::from_bytes(text_k1::SENDER_SEED))?;
        let sealed = envelope::seal_padded(&ctx, &sender, counter, &nonce, &padded)?;
        verify_and_open(&ctx, &sealed.blob, received_at, now)
    }))
}

/// The verdict of `verify_qr_parse`.
pub(crate) fn verify_qr_parse_verdict(data: &[u8]) -> Result<(), Error> {
    fingerprint::parse_verify_qr(data, &QR_CHANNEL).map(|_| ())
}

/// The verdict of `state_decode`.
pub(crate) fn state_decode_verdict(data: &[u8]) -> Result<(), StoreError> {
    ChannelState::decode(data).map(|_| ())
}

/// The verdict of `log_record_decode`.
pub(crate) fn log_record_decode_verdict(data: &[u8]) -> Result<(), StoreError> {
    LogRecord::decode(data).map(|_| ())
}

/// The verdict of `settings_decode`.
pub(crate) fn settings_decode_verdict(data: &[u8]) -> Result<(), StoreError> {
    Settings::decode(data).map(|_| ())
}

/// The verdict of `channel_decrypt`; `None` for an input shorter than its
/// two times and its `server_id`.
pub(crate) fn channel_decrypt_verdict(data: &[u8]) -> Option<Result<Option<Received>, Error>> {
    let (received_at, rest) = data.split_first_chunk::<8>()?;
    let (now, rest) = rest.split_first_chunk::<8>()?;
    let (server_id, blob) = rest.split_first_chunk::<16>()?;
    let (received_at, now) = (u64::from_be_bytes(*received_at), u64::from_be_bytes(*now));
    Some(text_k1_config().and_then(|config| {
        let own = Secret::from_bytes(text_k1::SENDER_SEED);
        let mut channel = Channel::for_fuzzing(&config, &own)?;
        channel.decrypt(blob, *server_id, received_at, now)
    }))
}

/// The verdict of `frame_decode`.
pub(crate) fn frame_decode_verdict(data: &[u8]) -> Result<Frame, Error> {
    Frame::decode(data)
}

/// The verdict of `session_on_frame`: the events of the input's frames,
/// read after a fixed `hello` and `ok` at `text_k1`'s `now`; a trailing
/// part shorter than its length is dropped.
pub(crate) fn session_on_frame_verdict(data: &[u8]) -> Result<Vec<Event>, Error> {
    let config = text_k1_config()?;
    let own = Secret::from_bytes(text_k1::SENDER_SEED);
    let mut channels = vec![Channel::for_fuzzing(&config, &own)?];
    let channel_id = config.channel_id();
    let mut session = Session::new(0, vec![channel_id]);
    let now = text_k1::NOW;
    session.on_connect(now, &[]);
    let hello = Frame::Hello {
        server_nonce: [0; 32],
        proto_versions: vec![1],
    };
    session.on_frame(&hello.encode()?, &mut channels, now);
    session.on_frame(&Frame::Ok { channel_id }.encode()?, &mut channels, now);
    let mut events = Vec::new();
    let mut rest = data;
    while let Some((len, tail)) = rest.split_first_chunk::<2>() {
        let Some((frame, tail)) = tail.split_at_checked(usize::from(u16::from_be_bytes(*len)))
        else {
            break;
        };
        events.extend(session.on_frame(frame, &mut channels, now).events);
        session.outgoing();
        rest = tail;
    }
    Ok(events)
}

/// `verify`, then `open`, in the channel `ctx`.
fn verify_and_open(
    ctx: &ChannelCtx,
    blob: &[u8],
    received_at: u64,
    now: u64,
) -> Result<Opened, Error> {
    envelope::verify(blob, ctx, received_at, now)?.open()
}

/// The channel of the 013 vector `text_k1`.
fn context() -> Result<ChannelCtx, Error> {
    ChannelCtx::from_config(&text_k1_config()?)
}

/// The config of the 013 vector `text_k1`.
fn text_k1_config() -> Result<Config, Error> {
    Config::from_parts(
        Secret::from_bytes(text_k1::K_CH),
        text_k1::SERVER_URL,
        text_k1::TTL_SECONDS,
        text_k1::SUGGESTED_NAME,
        text_k1::CREATED_AT,
    )
}
