//! Tests of spec 016 R1, R3–R5 and R11: the isolation of the fuzz crate, and
//! what the entries of `fuzz_entry` reach.

use proptest::collection::vec as bytes_of;
use proptest::prelude::{ProptestConfig, any, proptest};

use super::{receive_signed_verdict, receive_verdict, record_decode_verdict};
use crate::Error;
use crate::crypto::{Nonce, Secret};
use crate::proto::envelope::{self, Content, SenderKey, text_k1};
use crate::proto::payload::{Payload, PayloadKind};
use crate::proto::record::UnknownKeys;
use crate::proto::record::test_schema::{TestRecord, decode_test_record};

const ROOT_MANIFEST: &str = include_str!("../../../../Cargo.toml");
const FUZZ_MANIFEST: &str = include_str!("../../fuzz/Cargo.toml");

/// The blob of `text_k1`, sealed from its inputs.
fn text_k1_blob() -> Vec<u8> {
    let ctx = super::context().unwrap();
    let sender = SenderKey::from_seed(&Secret::from_bytes(text_k1::SENDER_SEED)).unwrap();
    let payload = Payload {
        kind: PayloadKind::Text,
        display_name: None,
        sent_at: text_k1::SENT_AT,
        body: text_k1::BODY.to_vec(),
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

/// The input of `receive`: the two times, then the blob (R4).
fn receive_input(received_at: u64, now: u64, blob: &[u8]) -> Vec<u8> {
    [&received_at.to_be_bytes()[..], &now.to_be_bytes(), blob].concat()
}

/// Spec 016, R1: the workspace excludes the fuzz crate and no workspace
/// crate depends on it.
#[test]
fn s016_t01_r01_fuzz_crate_is_isolated() {
    assert!(ROOT_MANIFEST.contains("exclude = [\"crates/core/fuzz\"]"));
    for manifest in [
        include_str!("../../Cargo.toml"),
        include_str!("../../../store/Cargo.toml"),
        include_str!("../../../server/Cargo.toml"),
    ] {
        assert!(!manifest.contains("fuzz"), "{manifest}");
    }
}

/// Spec 016, R3: the test schema decodes a seed with all six fields under
/// both policies, and the first byte chooses the policy for an unknown key.
#[test]
fn s016_t03_r03_record_schema_uses_every_type() {
    let bytes32 = [7; 32];
    let full = TestRecord {
        small: 1,
        medium: Some(2),
        large: Some(3),
        bytes: Some(b"four"),
        bytes32: Some(&bytes32),
        text: Some("six"),
    }
    .encode()
    .unwrap();
    for policy in [UnknownKeys::Ignore, UnknownKeys::Reject] {
        assert_eq!(decode_test_record(&full, policy), Ok(()));
    }
    let unknown = [full.as_slice(), &[9, 0, 0, 0, 0]].concat();
    for (policy, verdict) in [
        (0x00, Ok(())),
        (0x01, Err(Error::BadPayload)),
        (0xff, Err(Error::BadPayload)),
    ] {
        let input = [&[policy][..], &unknown].concat();
        assert_eq!(record_decode_verdict(&input), Some(verdict), "{policy}");
    }
    assert_eq!(record_decode_verdict(&[]), None);
}

/// Spec 016, R4: the blob of `text_k1` is a `Message` at its own times,
/// `Expired` past step 2 and `Stale` when its `sent_at` is too old; 15
/// bytes are too short.
#[test]
fn s016_t04_r04_receive_reaches_expired_and_stale() {
    let blob = text_k1_blob();
    let verdict = |received_at, now| receive_verdict(&receive_input(received_at, now, &blob));
    let message = verdict(text_k1::RECEIVED_AT, text_k1::NOW);
    assert!(
        matches!(message, Some(Ok(Content::Message(_)))),
        "{message:?}"
    );
    let window = envelope::ttl_ms(text_k1::TTL_SECONDS) + envelope::EXPIRY_MARGIN_MS;
    let late = text_k1::SENT_AT + 2 * window;
    assert_eq!(verdict(0, late), Some(Err(Error::Expired)));
    assert_eq!(verdict(late, late), Some(Ok(Content::Stale)));
    assert_eq!(receive_verdict(&[0; 15]), None);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Spec 016, R5: every input of 48 bytes or more is sealed, so it passes
    /// steps 1, 3 and 4 and, when its times pass step 2, reaches `open`.
    #[test]
    fn s016_t05_r05_receive_signed_always_reaches_open(
        header in any::<[u8; 48]>(),
        plaintext in bytes_of(any::<u8>(), 0..=69_952),
    ) {
        let input = [header.as_slice(), &plaintext].concat();
        let verdict = receive_signed_verdict(&input).unwrap();
        assert!(
            !matches!(verdict, Err(Error::BadLength | Error::WrongChannel | Error::BadSignature)),
            "{verdict:?}"
        );
    }
}

/// Spec 016, R5: 47 bytes are too short, and a signed input at fresh times
/// reaches `open`, where an empty plaintext is one block of zeros, which
/// has no padding marker.
#[test]
fn s016_t05_r05_receive_signed_layout() {
    assert_eq!(receive_signed_verdict(&[0; 47]), None);
    let times = [
        text_k1::RECEIVED_AT.to_be_bytes(),
        text_k1::NOW.to_be_bytes(),
    ]
    .concat();
    let input = [&[0; 8][..], &[1; 24], &times].concat();
    assert_eq!(
        receive_signed_verdict(&input),
        Some(Ok(Content::Unreadable))
    );
    let mut padded = Payload {
        kind: PayloadKind::Text,
        display_name: None,
        sent_at: text_k1::SENT_AT,
        body: b"hi".to_vec(),
    }
    .encode()
    .unwrap();
    crate::crypto::pad(&mut padded, 1_024).unwrap();
    let input = [&[0; 8][..], &[1; 24], &times, &padded].concat();
    assert!(matches!(
        receive_signed_verdict(&input),
        Some(Ok(Content::Message(_)))
    ));
}

/// Spec 016, R11: one dependency besides `core`, not published, its own
/// workspace, a committed lockfile and the four ignored paths.
#[test]
fn s016_t11_r11_one_dependency_own_workspace() {
    let dependencies = FUZZ_MANIFEST
        .split("[dependencies]")
        .nth(1)
        .and_then(|rest| rest.split("\n[").next())
        .unwrap();
    let names: Vec<&str> = dependencies
        .lines()
        .filter_map(|line| line.split_once(" = "))
        .map(|(name, _)| name)
        .collect();
    assert_eq!(names, ["libfuzzer-sys", "privatechat-core"]);
    assert!(FUZZ_MANIFEST.contains("privatechat-core = { path = \"..\" }"));
    assert!(FUZZ_MANIFEST.contains("publish = false"));
    assert!(FUZZ_MANIFEST.contains("\n[workspace]\n"));
    assert!(include_str!("../../fuzz/Cargo.lock").contains("name = \"libfuzzer-sys\""));
    let ignored: Vec<&str> = include_str!("../../fuzz/.gitignore").lines().collect();
    assert_eq!(ignored, ["target/", "corpus/", "artifacts/", "coverage/"]);
}
