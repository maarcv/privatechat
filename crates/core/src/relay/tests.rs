//! Spec 030-ws-protocol R2: `relay::check_blob` against the length, version
//! and channel rows of `013.json`, and as a property over sealed blobs.

use proptest::prelude::*;

use super::check_blob;
use crate::Error;
use crate::crypto::{Nonce, Secret};
use crate::proto::config::Config;
use crate::proto::envelope::{self, ChannelCtx, SenderKey, text_k1};
use crate::proto::payload::{Payload, PayloadKind};
use crate::vectors::{self, Kind, Vector};

/// The blob of a 013 vector: an input of a negative, the output of a positive.
fn blob_of(vector: &Vector) -> Vec<u8> {
    if vector.has_input("blob") {
        vector.input("blob").bytes().to_vec()
    } else {
        vector.expected("blob").bytes().to_vec()
    }
}

/// What `check_blob` must say of a 013 vector: the error of `verify`'s first
/// step, or `Ok` for every blob whose fault lies past it.
fn expected(vector: &Vector) -> Result<(), Error> {
    if vector.kind() == Kind::Positive {
        return Ok(());
    }
    match vector.expected("error").text() {
        "BadLength" => Err(Error::BadLength),
        "UnsupportedVersion" => Err(Error::UnsupportedVersion),
        "WrongChannel" => Err(Error::WrongChannel),
        _ => Ok(()),
    }
}

#[test]
fn s030_t02_r02_relay_check_blob() {
    let all = vectors::all("013");
    assert_eq!(all.len(), 30);
    let mut refused = 0;
    for vector in &all {
        let channel_id = vector.input("channel_id").array();
        let verdict = check_blob(&blob_of(vector), &channel_id);
        assert_eq!(verdict, expected(vector), "{}", vector.name());
        refused += usize::from(verdict.is_err());
    }
    // `short_blob`, `long_blob`, `unaligned_blob`, `mutate_version` and
    // `mutate_channel_id`.
    assert_eq!(refused, 5);
}

/// A blob of `text_k1`'s channel with a body of `len` bytes.
fn sealed(len: usize) -> Vec<u8> {
    let config = Config::from_parts(
        Secret::from_bytes(text_k1::K_CH),
        text_k1::SERVER_URL,
        text_k1::TTL_SECONDS,
        text_k1::SUGGESTED_NAME,
        text_k1::CREATED_AT,
    )
    .unwrap();
    let ctx = ChannelCtx::from_config(&config).unwrap();
    let sender = SenderKey::from_seed(&Secret::from_bytes(text_k1::SENDER_SEED)).unwrap();
    let payload = Payload {
        kind: PayloadKind::Text,
        display_name: None,
        sent_at: text_k1::SENT_AT,
        body: vec![b'a'; len],
    };
    envelope::seal(
        &ctx,
        &sender,
        text_k1::COUNTER,
        &Nonce(text_k1::NONCE),
        &payload,
    )
    .unwrap()
    .blob
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Spec 030, R2: a flip in byte 0 is the version, in `1..17` the
    /// channel, and anywhere after them nothing `check_blob` reads (the
    /// mutation table of spec 013).
    #[test]
    fn s030_t02_r02_flips_by_region(len in 0usize..3_000, at in any::<prop::sample::Index>(), bit in 0u8..8) {
        let mut blob = sealed(len);
        let channel_id = blob[1..17].try_into().unwrap();
        prop_assert_eq!(check_blob(&blob, &channel_id), Ok(()));
        let index = at.index(blob.len());
        blob[index] ^= 1 << bit;
        let expected = match index {
            0 => Err(Error::UnsupportedVersion),
            1..17 => Err(Error::WrongChannel),
            _ => Ok(()),
        };
        prop_assert_eq!(check_blob(&blob, &channel_id), expected);
    }
}
