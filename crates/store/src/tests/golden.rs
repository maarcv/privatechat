//! Spec 020, R31: the three files of `crates/store/tests/golden/v1/`, written
//! once by this version under a fixed test key and never regenerated, still
//! open and decode. A later version that raises a version of R8 proves with
//! them that it reads this one. The CI checks their SHA-256 against
//! `SHA256SUMS` beside them.

use privatechat_core::testing::{record, records_eq, settings, settings_eq, state_eq, state_for};
use privatechat_core::{StorageKey, Vault};

use super::TestDir;
use crate::DataDir;

const STATE: &[u8] = include_bytes!("../../tests/golden/v1/state.bin");
const LOG: &[u8] = include_bytes!("../../tests/golden/v1/messages.log");
const SETTINGS: &[u8] = include_bytes!("../../tests/golden/v1/settings.bin");

/// The test key and channel the golden files were written under.
const GOLDEN_KEY: [u8; 32] = [0x42; 32];
const GOLDEN_CHANNEL: [u8; 16] = [0x6f; 16];

/// Spec 020, R31: the golden state, its three records and the settings load
/// to the values they were written from.
#[test]
fn s020_t31_r31_golden_v1_files() {
    let dir = TestDir::new("t31");
    let key = || StorageKey::from_bytes(&mut GOLDEN_KEY.clone());
    let name = privatechat_core::dir_name(&key(), &GOLDEN_CHANNEL).expect("name");
    let channel = dir.path().join("channels").join(crate::hex(&name));
    std::fs::create_dir_all(&channel).expect("channel directory");
    std::fs::write(channel.join("state.bin"), STATE).expect("state");
    std::fs::write(channel.join("messages.log"), LOG).expect("log");
    std::fs::write(dir.path().join("settings.bin"), SETTINGS).expect("settings");
    let mut data = DataDir::open(dir.path(), key()).expect("open");
    let mut store = data.create(&GOLDEN_CHANNEL).expect("store");
    let (state, records) = store.load().expect("load").expect("committed");
    assert!(state_eq(&state, &state_for(GOLDEN_CHANNEL)));
    assert_eq!(state.log_position(), (585, 0));
    let expected = [record(101, 5), record(102, 6), record(103, 7)];
    assert!(records_eq(&records, &expected));
    let loaded = data.load_settings().expect("load").expect("present");
    assert!(settings_eq(
        &loaded,
        &settings("wss://golden.invalid", 120, Some("127.0.0.1:9050"))
    ));
}
