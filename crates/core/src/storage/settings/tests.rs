//! Tests of spec 020 over the settings record.

use proptest::option::of as maybe;
use proptest::prelude::{any, proptest};

use super::super::StoreError;
use super::super::tests::{field, key, replaced, without};
use super::{MAX_LOCK_TIMEOUT_SECONDS, MAX_SETTINGS_RECORD, Settings};
use crate::proto::config::url::MAX_URL;
use crate::testing::settings_eq;
use crate::vectors::{Kind, Vector};

/// Settings with every key.
fn settings() -> Settings {
    Settings {
        default_server_url: "wss://chat.example.org".to_owned(),
        lock_timeout_seconds: 300,
        socks5_proxy: Some("127.0.0.1:9050".to_owned()),
    }
}

/// Spec 020, R8 (the settings record): an unknown key, a URL outside the
/// grammar, a proxy with port 0 and a timeout over a day are `Corrupt` on
/// open, and seal refuses them too; a newer version is `UnsupportedVersion`
/// even with a key this version does not know.
#[test]
fn s020_t08_r08_settings_schema() {
    let record = settings().encode().unwrap().to_vec();
    assert_eq!(Settings::decode(&record).err(), None);
    let with_unknown = [&record[..], &field(4, &[])].concat();
    assert_eq!(
        Settings::decode(&with_unknown).err(),
        Some(StoreError::Corrupt)
    );
    for version in [0, 2, 255] {
        let mut other = with_unknown.clone();
        other[5] = version;
        let error = Settings::decode(&other).err();
        assert_eq!(error, Some(StoreError::UnsupportedVersion), "{version}");
    }
    // Keys 0 to 2 are mandatory, the proxy is not.
    for key in [0, 1, 2] {
        assert_eq!(
            Settings::decode(&without(&record, key)).err(),
            Some(StoreError::Corrupt)
        );
    }
    assert!(Settings::decode(&without(&record, 3)).is_ok());
    // The proxy's bound holds on seal as on open: 257 bytes is refused.
    let long_proxy = Settings {
        socks5_proxy: Some(format!("{}:9050", "a".repeat(MAX_URL - 4))),
        ..settings()
    };
    assert_eq!(
        long_proxy.socks5_proxy.as_ref().map(String::len),
        Some(MAX_URL + 1)
    );
    assert_eq!(long_proxy.encode().err(), Some(StoreError::Corrupt));
    let bad = [
        Settings {
            default_server_url: "wss://chat.example.org/path".to_owned(),
            ..settings()
        },
        Settings {
            socks5_proxy: Some("127.0.0.1:0".to_owned()),
            ..settings()
        },
        Settings {
            socks5_proxy: Some("127.0.0.1:09050".to_owned()),
            ..settings()
        },
        Settings {
            socks5_proxy: Some("127.0.0.1".to_owned()),
            ..settings()
        },
        Settings {
            lock_timeout_seconds: MAX_LOCK_TIMEOUT_SECONDS + 1,
            ..settings()
        },
    ];
    for settings in bad {
        assert_eq!(settings.encode().err(), Some(StoreError::Corrupt));
        // The same values, planted past `encode`'s check, do not open.
        let mut planted = vec![];
        planted.extend(field(0, &[1]));
        planted.extend(field(1, settings.default_server_url.as_bytes()));
        planted.extend(field(2, &settings.lock_timeout_seconds.to_be_bytes()));
        if let Some(proxy) = &settings.socks5_proxy {
            planted.extend(field(3, proxy.as_bytes()));
        }
        assert_eq!(Settings::decode(&planted).err(), Some(StoreError::Corrupt));
    }
    let edge = Settings {
        lock_timeout_seconds: MAX_LOCK_TIMEOUT_SECONDS,
        socks5_proxy: None,
        ..settings()
    };
    assert!(Settings::decode(&edge.encode().unwrap()).is_ok());
}

/// Spec 020, R3 and R4 (the settings): sealed under `K_settings` with a
/// fresh nonce, opened back, and not opened under another `K_db`.
#[test]
fn s020_t04_r04_settings_seal() {
    let storage_key = key(1);
    let first = settings().seal(&storage_key).unwrap();
    let second = settings().seal(&storage_key).unwrap();
    assert_ne!(first[..24], second[..24]);
    let opened = Settings::open(&storage_key, &first).unwrap();
    assert_eq!(opened.encode().unwrap(), settings().encode().unwrap());
    assert_eq!(
        Settings::open(&key(2), &first).err(),
        Some(StoreError::Corrupt)
    );
    assert_eq!(
        Settings::open(&storage_key, &first[..39]).err(),
        Some(StoreError::Corrupt)
    );
    // The largest settings record is within its limit.
    let longest = Settings {
        default_server_url: format!("wss://{}", "a".repeat(MAX_URL - 6)),
        lock_timeout_seconds: MAX_LOCK_TIMEOUT_SECONDS,
        socks5_proxy: Some(format!("{}:65535", "a".repeat(MAX_URL - 6))),
    };
    let record = longest.encode().unwrap();
    assert!(record.len() <= MAX_SETTINGS_RECORD);
    assert_eq!(record.capacity(), record.len());
}

/// Checks a settings vector of `020.json`: the positive decodes to its values
/// and encodes back to its bytes; the negative is `Corrupt`.
pub(in crate::storage) fn check_vector(vector: &Vector) {
    assert_eq!(vector.input("schema").text(), "settings");
    let buf = vector.input("record").bytes();
    let decoded = Settings::decode(buf);
    if vector.kind() == Kind::Negative {
        let error = format!("{:?}", decoded.err().unwrap());
        assert_eq!(error, vector.expected("error").text(), "{}", vector.name());
        // `Corrupt` says nothing of the rule: the bytes say which one broke.
        let reference = crate::vectors::load("020", "settings_reference");
        let edited = replaced(
            reference.input("record").bytes(),
            1,
            b"wss://chat.example.org/path",
        );
        assert_eq!(buf, edited.as_slice(), "{}", vector.name());
        return;
    }
    let settings = decoded.unwrap();
    let url = vector.expected("default_server_url").bytes();
    assert_eq!(settings.default_server_url.as_bytes(), url);
    let timeout = vector.expected("lock_timeout_seconds").number();
    assert_eq!(settings.lock_timeout_seconds, timeout);
    let proxy = settings.socks5_proxy.as_ref().map(String::as_bytes);
    assert_eq!(proxy, Some(vector.expected("socks5_proxy").bytes()));
    assert_eq!(settings.encode().unwrap().as_slice(), buf);
}

proptest! {
    /// Spec 020, R29 (the settings record): valid settings re-encode to the
    /// bytes they were decoded from, and the decoder never panics.
    #[test]
    fn s020_t29_r29_settings_round_trip(
        host in "[a-z0-9.-]{1,64}",
        port in maybe(1u16..),
        lock_timeout_seconds in 0..=MAX_LOCK_TIMEOUT_SECONDS,
        proxy in maybe(("[a-z0-9.]{1,32}", 1u16..)),
        buf in proptest::collection::vec(any::<u8>(), 0..=512),
    ) {
        let default_server_url = match port {
            Some(port) if port != 443 => format!("wss://{host}:{port}"),
            _ => format!("wss://{host}"),
        };
        let settings = Settings {
            default_server_url,
            lock_timeout_seconds,
            socks5_proxy: proxy.map(|(host, port)| format!("{host}:{port}")),
        };
        let record = settings.encode().unwrap();
        assert_eq!(Settings::decode(&record).unwrap().encode().unwrap(), record);
        // `open(seal(x))` gives `x`, field by field.
        let sealed = settings.seal(&key(1)).unwrap();
        assert!(settings_eq(&Settings::open(&key(1), &sealed).unwrap(), &settings));
        let _ = Settings::decode(&buf);
    }
}
