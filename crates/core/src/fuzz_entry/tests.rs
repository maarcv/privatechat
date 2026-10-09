//! Tests of spec 016 R1, R3–R5, R8, R9 and R11: the isolation of the fuzz
//! crate, what the entries of `fuzz_entry` reach, and the nightly workflow.

use proptest::collection::vec as bytes_of;
use proptest::prelude::{ProptestConfig, any, proptest};

use super::{
    QR_CHANNEL, config_parse_qr_verdict, config_parse_verdict, log_record_decode_verdict,
    payload_decode_verdict, receive_signed_verdict, receive_verdict, record_decode_verdict,
    settings_decode_verdict, state_decode_verdict, verify_qr_parse_verdict,
};
use crate::Error;
use crate::crypto::{self, Nonce, PublicKey, Secret};
use crate::proto::config::{ChannelId, Config};
use crate::proto::envelope::{self, ChannelCtx, Content, SenderKey, text_k1};
use crate::proto::fingerprint;
use crate::proto::payload::{Payload, PayloadKind};
use crate::proto::record::UnknownKeys;
use crate::proto::record::test_schema::{TestRecord, decode_test_record};

const ROOT_MANIFEST: &str = include_str!("../../../../Cargo.toml");
const FUZZ_MANIFEST: &str = include_str!("../../fuzz/Cargo.toml");
const FUZZ_WORKFLOW: &str = include_str!("../../../../.github/workflows/fuzz.yml");

/// The targets of R2: three added by spec 020-store-files, one by spec
/// 021-channel-session, the last by spec 028-session-sans-io.
const TARGETS: [&str; 12] = [
    "record_decode",
    "config_parse",
    "config_parse_qr",
    "payload_decode",
    "receive",
    "receive_signed",
    "verify_qr_parse",
    "state_decode",
    "log_record_decode",
    "settings_decode",
    "channel_decrypt",
    "frame_decode",
];

/// The channel of `text_k1`, built here apart from `fuzz_entry`, so that an
/// entry sealing or opening in another channel fails the tests.
fn text_k1_context() -> ChannelCtx {
    let config = Config::from_parts(
        Secret::from_bytes(text_k1::K_CH),
        text_k1::SERVER_URL,
        text_k1::TTL_SECONDS,
        text_k1::SUGGESTED_NAME,
        text_k1::CREATED_AT,
    )
    .unwrap();
    ChannelCtx::from_config(&config).unwrap()
}

/// The blob of `text_k1`, sealed from its inputs.
fn text_k1_blob() -> Vec<u8> {
    let ctx = text_k1_context();
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
        (0x02, Err(Error::BadPayload)),
        (0x80, Err(Error::BadPayload)),
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
    let bound = text_k1::RECEIVED_AT + window;
    assert!(matches!(
        verdict(text_k1::RECEIVED_AT, bound),
        Some(Ok(Content::Message(_)))
    ));
    assert_eq!(
        verdict(text_k1::RECEIVED_AT, bound + 1),
        Some(Err(Error::Expired))
    );
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
        assert!(matches!(verdict, Ok(_) | Err(Error::Expired)), "{verdict:?}");
    }
}

/// A `text` of `text_k1` whose encoding is `len` bytes.
fn encoded_text(len: usize) -> Vec<u8> {
    Payload {
        kind: PayloadKind::Text,
        display_name: None,
        sent_at: text_k1::SENT_AT,
        body: vec![b'a'; len - 24],
    }
    .encode()
    .unwrap()
}

/// The input of `receive_signed` at the times of `text_k1`.
fn signed_input(counter: u64, plaintext: &[u8]) -> Vec<u8> {
    let times = [
        text_k1::RECEIVED_AT.to_be_bytes(),
        text_k1::NOW.to_be_bytes(),
    ];
    [
        &counter.to_be_bytes()[..],
        &[1; 24],
        &times.concat(),
        plaintext,
    ]
    .concat()
}

/// Spec 016, R5: the layout, the sender and the counter; an empty
/// plaintext is a block of zeros, with no padding marker; 63 blocks are
/// kept and what follows them dropped; a record with its marker is filled
/// with zeros to a whole block.
#[test]
fn s016_t05_r05_receive_signed_layout() {
    assert!(receive_signed_verdict(&[0; 47]).is_none());
    let opened = receive_signed_verdict(&signed_input(0x0102_0304_0506_0708, &[]))
        .unwrap()
        .unwrap();
    assert_eq!(opened.counter, 0x0102_0304_0506_0708);
    let sender = SenderKey::from_seed(&Secret::from_bytes(text_k1::SENDER_SEED)).unwrap();
    assert_eq!(opened.sender_pk.0, sender.public().0);
    assert_eq!(opened.content, Content::Unreadable);
    let late = [&[0; 32][..], &0u64.to_be_bytes(), &u64::MAX.to_be_bytes()].concat();
    assert!(matches!(
        receive_signed_verdict(&late),
        Some(Err(Error::Expired))
    ));

    let mut largest = encoded_text(64_511);
    crypto::pad(&mut largest, 1_024).unwrap();
    assert_eq!(largest.len(), 64_512);
    let marked = [encoded_text(1_500).as_slice(), &[0x80]].concat();
    for (case, plaintext) in [
        ("63 blocks", largest.clone()),
        (
            "63 blocks and more",
            [largest.as_slice(), &[7; 3_000]].concat(),
        ),
        ("1 501 bytes with the marker", marked),
    ] {
        let opened = receive_signed_verdict(&signed_input(1, &plaintext)).unwrap();
        assert!(
            matches!(opened, Ok(ref opened) if matches!(opened.content, Content::Message(_))),
            "{case}"
        );
    }
}

/// Spec 016, R8: the seed `fuzz_seeds.py` writes for `text_k1`, the two
/// times and the blob in the layout of R4, reaches `open` as a `Message`.
#[test]
fn s016_t08_r08_text_k1_seed_reaches_open() {
    let seed = receive_input(text_k1::RECEIVED_AT, text_k1::NOW, &text_k1_blob());
    assert!(matches!(
        receive_verdict(&seed),
        Some(Ok(Content::Message(_)))
    ));
}

/// Spec 016, R8: the seeds of every row reach past the first checks of
/// their entry: a config record and its QR text, whose invitation expired
/// long before the `now = 0` of the entries; the verification QR in the
/// channel of 011 `config_reference`, which `QR_CHANNEL` is; a payload.
#[test]
fn s016_t08_r08_seeds_reach_their_entries() {
    let k_ch: [u8; 32] = core::array::from_fn(|i| 0x40 + u8::try_from(i).unwrap());
    let config = Config::from_parts(
        Secret::from_bytes(k_ch),
        "wss://chat.example.org:9001",
        86_400,
        "Família",
        1_790_000_000_000,
    )
    .unwrap();
    let invited = config.record(Some(1_790_000_600_000)).unwrap();
    assert_eq!(config_parse_verdict(&invited), Ok(()));
    assert_eq!(
        Config::parse(&invited, 1_790_000_600_001).err(),
        Some(Error::InviteExpired)
    );
    assert_eq!(
        config_parse_qr_verdict(&config.export_qr(1_790_000_000_000).unwrap()),
        Ok(())
    );

    assert_eq!(QR_CHANNEL.0, config.channel_id());
    let pk = PublicKey([0x55; 32]);
    let qr = fingerprint::verify_qr(&ChannelId(config.channel_id()), &pk).unwrap();
    assert_eq!(verify_qr_parse_verdict(&qr), Ok(()));
    let other = fingerprint::verify_qr(&ChannelId([0x56; 16]), &pk).unwrap();
    assert_eq!(verify_qr_parse_verdict(&other), Err(Error::WrongChannel));

    assert_eq!(payload_decode_verdict(&encoded_text(40)), Ok(()));
    // The entry adds no logic of its own (R7): a payload `validate` would
    // refuse, its `sent_at` off the minute, still decodes.
    let off_the_minute = Payload {
        kind: PayloadKind::Text,
        display_name: None,
        sent_at: text_k1::SENT_AT + 1,
        body: b"hi".to_vec(),
    };
    let encoded = off_the_minute.encode().unwrap();
    assert!(off_the_minute.validate().is_err());
    assert_eq!(payload_decode_verdict(&encoded), Ok(()));
    assert_eq!(payload_decode_verdict(&[]), Err(Error::BadPayload));
}

/// Spec 016, R9: one nightly job per target, each installing the dated
/// nightly and `cargo-fuzz`, seeding the corpus, building from `crates/core`
/// and running for an hour; no other workflow and not the toolchain file
/// names a nightly.
#[test]
fn s016_t09_r09_nightly_matrix() {
    let matrix: Vec<&str> = FUZZ_WORKFLOW
        .lines()
        .filter_map(|line| line.trim().strip_prefix("- "))
        .filter(|item| TARGETS.contains(item))
        .collect();
    assert_eq!(matrix, TARGETS);
    let date = FUZZ_WORKFLOW
        .split("NIGHTLY: nightly-")
        .nth(1)
        .and_then(|rest| rest.get(..10))
        .unwrap();
    assert!(
        date.bytes().enumerate().all(|(i, b)| if i == 4 || i == 7 {
            b == b'-'
        } else {
            b.is_ascii_digit()
        }),
        "{date}"
    );
    for step in [
        "rustup toolchain install \"$NIGHTLY\" --profile minimal",
        "cargo +\"$NIGHTLY\" install cargo-fuzz",
        "python3 scripts/fuzz_seeds.py",
        "working-directory: crates/core",
        "cargo +\"$NIGHTLY\" fuzz build ${{ matrix.target }}",
        "cargo +\"$NIGHTLY\" fuzz run ${{ matrix.target }} fuzz/corpus/${{ matrix.target }}",
        "-max_total_time=3600 -timeout=10",
        "if: failure()",
        "path: crates/core/fuzz/artifacts/",
        "schedule:",
    ] {
        assert!(FUZZ_WORKFLOW.contains(step), "{step}");
    }
    let seed_at = FUZZ_WORKFLOW.find("fuzz_seeds.py").unwrap();
    assert!(seed_at < FUZZ_WORKFLOW.find("fuzz build").unwrap());
    for other in [
        include_str!("../../../../.github/workflows/ci.yml"),
        include_str!("../../../../.github/workflows/landing.yml"),
        include_str!("../../../../rust-toolchain.toml"),
    ] {
        assert!(!other.contains("nightly"));
    }
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

/// Spec 020, R29: the three storage entries reach their decoders: the
/// seeds `fuzz_seeds.py` writes from the records of `020.json` decode, and
/// the negatives among them are `Corrupt`.
#[test]
fn s020_t29_r29_storage_entries_reach_their_decoders() {
    type Verdict = fn(&[u8]) -> Result<(), crate::StoreError>;
    let entries: [(&str, &str, Verdict); 5] = [
        ("state_reference", "state_unknown_key", state_decode_verdict),
        (
            "log_message_reference",
            "log_unknown_key",
            log_record_decode_verdict,
        ),
        (
            "log_seen_reference",
            "log_unknown_key",
            log_record_decode_verdict,
        ),
        (
            "log_kept_signature_reference",
            "log_unknown_key",
            log_record_decode_verdict,
        ),
        (
            "settings_reference",
            "settings_bad_url",
            settings_decode_verdict,
        ),
    ];
    for (positive, negative, verdict) in entries {
        let record = crate::vectors::load("020", positive);
        assert_eq!(
            verdict(record.input("record").bytes()),
            Ok(()),
            "{positive}"
        );
        let record = crate::vectors::load("020", negative);
        let rejected = verdict(record.input("record").bytes());
        assert_eq!(rejected, Err(crate::StoreError::Corrupt), "{negative}");
    }
    for verdict in [
        state_decode_verdict,
        log_record_decode_verdict,
        settings_decode_verdict,
    ] {
        assert_eq!(verdict(&[]), Err(crate::StoreError::Corrupt));
    }
}
