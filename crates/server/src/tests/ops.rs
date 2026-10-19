//! Spec 035-server-ops: the configuration (R1) and the two listeners (R2).

use std::ffi::OsString;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use futures_util::StreamExt;
use tokio_tungstenite::tungstenite::Message;

use privatechat_core::Frame;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tracing::Level;

use super::TestDir;
use super::ws::{Received, receive};
use crate::clock::ManualClock;
use crate::config::{ConfigError, Settings};
use crate::limits::{ChannelLimits, ConnectionLimits, PING_INTERVAL_MS};
use crate::serve::{Outcome, bind};

const URLS: &str = "PRIVATECHAT_URLS";

/// The settings of `pairs`, as the environment would give them.
fn from(pairs: &[(&str, &str)]) -> Result<Settings, ConfigError> {
    Settings::from_env(
        pairs
            .iter()
            .map(|(name, value)| (OsString::from(name), OsString::from(value))),
    )
}

/// The error of `pairs`, whose message names `variable` and holds no value.
fn refused(pairs: &[(&str, &str)], variable: &str) -> ConfigError {
    let error = from(pairs).err();
    assert!(error.is_some(), "{pairs:?} accepted");
    let error = error.unwrap();
    let message = error.to_string();
    assert!(message.contains(variable), "{message:?} names {variable}");
    for (_, value) in pairs {
        if value.len() > 2 {
            assert!(!message.contains(value), "{message:?} holds {value:?}");
        }
    }
    error
}

/// `PRIVATECHAT_URLS` set to one URL and `name` to `value`.
fn with(name: &'static str, value: &'static str) -> [(&'static str, &'static str); 2] {
    [(URLS, "wss://a.org"), (name, value)]
}

/// Every integer of the table, its least and its greatest value.
const INTEGERS: [(&str, u64, u64); 17] = [
    ("PRIVATECHAT_MAX_DB_BYTES", 67_108_864, 1 << 62),
    ("PRIVATECHAT_MAX_CONNECTIONS", 1, 1_000_000),
    ("PRIVATECHAT_ONION_MAX_CONNECTIONS", 1, 1_000_000),
    ("PRIVATECHAT_MAX_UNAUTH_CONNECTIONS", 1, 1_000_000),
    ("PRIVATECHAT_CHANNEL_PUBLISH_PER_MIN", 1, 100_000),
    ("PRIVATECHAT_CHANNEL_BYTES_PER_MIN", 64_673, 1 << 40),
    ("PRIVATECHAT_CHANNEL_MAX_BLOBS", 1, 10_000_000),
    ("PRIVATECHAT_CHANNEL_MAX_BYTES", 64_673, 1 << 40),
    ("PRIVATECHAT_IP_CONNECTIONS", 1, 100_000),
    ("PRIVATECHAT_IP_UNAUTH_CONNECTIONS", 1, 10_000),
    ("PRIVATECHAT_IP_NEW_PER_MIN", 1, 100_000),
    ("PRIVATECHAT_IP_BYTES_PER_MIN", 64_673, 1 << 40),
    ("PRIVATECHAT_IP48_CONNECTIONS", 1, 1_000_000),
    ("PRIVATECHAT_IP48_UNAUTH_CONNECTIONS", 1, 1_000_000),
    ("PRIVATECHAT_IP48_SUBNETS", 1, 65_536),
    ("PRIVATECHAT_IP48_BYTES_PER_MIN", 64_673, 1 << 40),
    ("PRIVATECHAT_ONION_BYTES_PER_MIN", 64_673, 1 << 40),
];

#[test]
fn s035_t01_r01_configuration_defaults() {
    let settings = from(&[(URLS, "wss://a.org")]).unwrap();
    assert_eq!(settings.hosts, ["a.org"]);
    assert_eq!(settings.listen, "0.0.0.0:8080".parse().unwrap());
    assert_eq!(settings.onion_listen, None);
    assert!(settings.trusted_proxies.is_empty());
    assert_eq!(settings.db, std::path::Path::new("/data/messages.db"));
    assert_eq!(settings.max_db_bytes, 8_589_934_592);
    assert_eq!(settings.channel, ChannelLimits::default());
    assert_eq!(settings.connections, ConnectionLimits::default());
    assert_eq!(settings.log_level, Level::WARN);
}

#[test]
fn s035_t01_r01_configuration_every_value_set() {
    let onion = format!("ws://{}.onion", "a".repeat(56));
    let urls = format!("wss://a.org,{onion}");
    let settings = from(&[
        (URLS, &urls),
        ("PRIVATECHAT_LISTEN", "127.0.0.1:9000"),
        ("PRIVATECHAT_ONION_LISTEN", "[::1]:9001"),
        (
            "PRIVATECHAT_TRUSTED_PROXIES",
            "10.0.0.0/8,192.168.1.7,fd00::/64",
        ),
        ("PRIVATECHAT_DB", "/tmp/x.db"),
        ("PRIVATECHAT_CHANNEL_MAX_BLOBS", "0042"),
        ("PRIVATECHAT_IP48_BYTES_PER_MIN", "70000"),
        ("PRIVATECHAT_LOG", "trace"),
    ])
    .unwrap();
    assert_eq!(
        settings.hosts,
        ["a.org".to_owned(), format!("{}.onion", "a".repeat(56))]
    );
    assert_eq!(settings.listen, "127.0.0.1:9000".parse().unwrap());
    assert_eq!(settings.onion_listen, Some("[::1]:9001".parse().unwrap()));
    assert_eq!(settings.trusted_proxies.len(), 3);
    assert_eq!(settings.db, std::path::Path::new("/tmp/x.db"));
    assert_eq!(settings.channel.max_blobs, 42);
    assert_eq!(settings.connections.ip48_bytes_per_min, 70_000);
    assert_eq!(settings.log_level, Level::TRACE);
    for (level, expected) in [
        ("error", Level::ERROR),
        ("warn", Level::WARN),
        ("info", Level::INFO),
        ("debug", Level::DEBUG),
    ] {
        let settings = from(&with("PRIVATECHAT_LOG", level)).unwrap();
        assert_eq!(settings.log_level, expected);
    }
}

#[test]
fn s035_t01_r01_configuration_ranges() {
    for (name, least, greatest) in INTEGERS {
        for good in [least, greatest] {
            let value = good.to_string();
            let settings = from(&[(URLS, "wss://a.org"), (name, &value)]);
            assert!(settings.is_ok(), "{name}={value}");
        }
        for bad in [least - 1, greatest + 1] {
            let value = bad.to_string();
            let error = refused(&[(URLS, "wss://a.org"), (name, &value)], name);
            assert_eq!(error, ConfigError::OutOfRange(name.to_owned()));
        }
        // Decimal digits only.
        for bad in [
            "",
            "+5",
            " 5",
            "5 ",
            "-5",
            "5_000",
            "0x10",
            "99999999999999999999",
        ] {
            let error = refused(&[(URLS, "wss://a.org"), (name, bad)], name);
            assert_eq!(
                error,
                ConfigError::OutOfRange(name.to_owned()),
                "{name}={bad:?}"
            );
        }
    }
    let error = refused(
        &with("PRIVATECHAT_CHANNEL_MAX_BYTES", "100"),
        "PRIVATECHAT_CHANNEL_MAX_BYTES",
    );
    assert_eq!(
        error,
        ConfigError::OutOfRange("PRIVATECHAT_CHANNEL_MAX_BYTES".to_owned())
    );
}

#[test]
fn s035_t01_r01_configuration_each_variable_its_limit() {
    // Distinct values, so that a variable read into another's limit shows.
    let values: Vec<(&str, String)> = INTEGERS
        .iter()
        .enumerate()
        .map(|(n, (name, least, _))| (*name, (least + 1 + n as u64).to_string()))
        .collect();
    let mut pairs = vec![(URLS, "wss://a.org")];
    pairs.extend(values.iter().map(|(name, value)| (*name, value.as_str())));
    let settings = from(&pairs).unwrap();
    let value = |name: &str| -> u64 {
        values
            .iter()
            .find(|(n, _)| *n == name)
            .unwrap()
            .1
            .parse()
            .unwrap()
    };
    let count = |name: &str| u32::try_from(value(name)).unwrap();
    assert_eq!(settings.max_db_bytes, value("PRIVATECHAT_MAX_DB_BYTES"));
    assert_eq!(
        settings.channel,
        ChannelLimits {
            publish_per_min: count("PRIVATECHAT_CHANNEL_PUBLISH_PER_MIN"),
            bytes_per_min: value("PRIVATECHAT_CHANNEL_BYTES_PER_MIN"),
            max_blobs: count("PRIVATECHAT_CHANNEL_MAX_BLOBS"),
            max_bytes: value("PRIVATECHAT_CHANNEL_MAX_BYTES"),
        }
    );
    assert_eq!(
        settings.connections,
        ConnectionLimits {
            ip_connections: count("PRIVATECHAT_IP_CONNECTIONS"),
            ip_unauth_connections: count("PRIVATECHAT_IP_UNAUTH_CONNECTIONS"),
            ip_new_per_min: count("PRIVATECHAT_IP_NEW_PER_MIN"),
            max_connections: count("PRIVATECHAT_MAX_CONNECTIONS"),
            onion_max_connections: count("PRIVATECHAT_ONION_MAX_CONNECTIONS"),
            max_unauth_connections: count("PRIVATECHAT_MAX_UNAUTH_CONNECTIONS"),
            ip_bytes_per_min: value("PRIVATECHAT_IP_BYTES_PER_MIN"),
            onion_bytes_per_min: value("PRIVATECHAT_ONION_BYTES_PER_MIN"),
            ip48_connections: count("PRIVATECHAT_IP48_CONNECTIONS"),
            ip48_unauth_connections: count("PRIVATECHAT_IP48_UNAUTH_CONNECTIONS"),
            ip48_subnets: count("PRIVATECHAT_IP48_SUBNETS"),
            ip48_bytes_per_min: value("PRIVATECHAT_IP48_BYTES_PER_MIN"),
        }
    );
}

#[test]
fn s035_t01_r01_configuration_urls() {
    assert_eq!(refused(&[], URLS), ConfigError::Missing(URLS.to_owned()));
    let eight = (0..8)
        .map(|n| format!("wss://h{n}.org"))
        .collect::<Vec<_>>()
        .join(",");
    assert_eq!(from(&[(URLS, &eight)]).unwrap().hosts.len(), 8);
    let nine = format!("{eight},wss://h8.org");
    assert_eq!(
        refused(&[(URLS, &nine)], URLS),
        ConfigError::OutOfRange(URLS.to_owned())
    );
    assert_eq!(
        refused(&[(URLS, "wss://a.org,wss://a.org:9001")], URLS),
        ConfigError::SameHost(URLS.to_owned())
    );
    // Separated by `,` alone: a space is outside the grammar of spec 011 R5.
    for bad in [
        "",
        "wss://a.org,",
        "wss://a.org,,wss://b.org",
        "wss://a.org, wss://b.org",
        "https://a.org",
    ] {
        assert_eq!(
            refused(&[(URLS, bad)], URLS),
            ConfigError::OutOfRange(URLS.to_owned()),
            "{bad:?}"
        );
    }
}

#[test]
fn s035_t01_r01_configuration_listeners_db_and_log() {
    let cases = [
        ("PRIVATECHAT_LISTEN", "localhost:80"),
        ("PRIVATECHAT_LISTEN", "127.0.0.1"),
        ("PRIVATECHAT_ONION_LISTEN", ""),
        ("PRIVATECHAT_ONION_LISTEN", "0.0.0.0:8080"),
        ("PRIVATECHAT_DB", ""),
        ("PRIVATECHAT_LOG", "WARN"),
        ("PRIVATECHAT_LOG", "off"),
    ];
    for (name, value) in cases {
        assert_eq!(
            refused(&with(name, value), name),
            ConfigError::OutOfRange(name.to_owned()),
            "{name}={value:?}"
        );
    }
}

#[test]
fn s035_t01_r01_configuration_trusted_proxies() {
    const NAME: &str = "PRIVATECHAT_TRUSTED_PROXIES";
    for good in [
        "",
        "0.0.0.0/0",
        "10.0.0.0/8",
        "10.0.0.1/32",
        "::/0",
        "2001:db8::/32",
        "2001:db8::1",
    ] {
        assert!(from(&with(NAME, good)).is_ok(), "{good:?}");
    }
    let sixteen = (0..16)
        .map(|n| format!("10.0.0.{n}"))
        .collect::<Vec<_>>()
        .join(",");
    assert_eq!(
        from(&[(URLS, "wss://a.org"), (NAME, &sixteen)])
            .unwrap()
            .trusted_proxies
            .len(),
        16
    );
    let seventeen = format!("{sixteen},10.0.0.16");
    assert_eq!(
        refused(&[(URLS, "wss://a.org"), (NAME, &seventeen)], NAME),
        ConfigError::OutOfRange(NAME.to_owned())
    );
    // A host bit past the prefix is refused, never masked into a wider trust.
    for bad in [
        "10.0.0.1/8",
        "10.0.0.1/0",
        "::1/0",
        "10.0.0.0/33",
        "::/129",
        "2001:db8::1/64",
        "10.0.0.0/",
        "10.0.0.0/+8",
        "10.0.0.0/ 8",
        "10.0.0.0/8, 192.168.0.0/16",
        "10.0.0.0/8,",
        "proxy.local",
    ] {
        assert_eq!(
            refused(&with(NAME, bad), NAME),
            ConfigError::OutOfRange(NAME.to_owned()),
            "{bad:?}"
        );
    }
}

#[test]
fn s035_t01_r01_configuration_names() {
    // A misspelt quota stops the start, naming the variable.
    let error = refused(
        &with("PRIVATECHAT_MAX_CONECTIONS", "10"),
        "PRIVATECHAT_MAX_CONECTIONS",
    );
    assert_eq!(
        error,
        ConfigError::Unknown("PRIVATECHAT_MAX_CONECTIONS".to_owned())
    );
    // A variable without the prefix is none of the server's.
    assert!(from(&with("PRIVATECHATURLS", "x")).is_ok());
    assert!(from(&with("HOME", "/root")).is_ok());
}

#[cfg(unix)]
#[test]
fn s035_t01_r01_configuration_not_utf8() {
    use std::os::unix::ffi::OsStringExt;

    let bytes = |text: &str, tail: u8| {
        let mut bytes = text.as_bytes().to_vec();
        bytes.push(tail);
        OsString::from_vec(bytes)
    };
    let urls = (OsString::from(URLS), OsString::from("wss://a.org"));
    let value = (OsString::from("PRIVATECHAT_LOG"), bytes("warn", 0xff));
    let error = Settings::from_env([urls.clone(), value].into_iter()).err();
    assert_eq!(
        error,
        Some(ConfigError::NotUtf8("PRIVATECHAT_LOG".to_owned()))
    );
    let name = (bytes("PRIVATECHAT_LOG", 0xff), OsString::from("warn"));
    let error = Settings::from_env([urls.clone(), name].into_iter()).err();
    assert!(
        matches!(error, Some(ConfigError::NotUtf8(name)) if name.starts_with("PRIVATECHAT_LOG"))
    );
    // On a variable that is not the server's, neither matters.
    let other = (bytes("LANG", 0xff), bytes("C", 0xfe));
    assert!(Settings::from_env([urls, other].into_iter()).is_ok());
}

/// Settings for a server on 127.0.0.1 with both listeners on free ports.
fn local(dir: &TestDir) -> Settings {
    let db = dir.db();
    from(&[
        (URLS, "wss://127.0.0.1"),
        ("PRIVATECHAT_LISTEN", "127.0.0.1:0"),
        ("PRIVATECHAT_ONION_LISTEN", "[::1]:0"),
        ("PRIVATECHAT_DB", db.to_str().unwrap()),
    ])
    .unwrap()
}

/// A WebSocket to `address` with `X-Forwarded-For` set, after its `hello`.
async fn forwarded(address: SocketAddr) -> super::ws::Client {
    let mut request = format!("ws://{address}/").into_client_request().unwrap();
    request
        .headers_mut()
        .insert("x-forwarded-for", "1.2.3.4".parse().unwrap());
    let (mut client, _) = tokio_tungstenite::connect_async(request).await.unwrap();
    assert!(matches!(
        receive(&mut client).await,
        Received::Frame(Frame::Hello { .. })
    ));
    client
}

#[tokio::test]
async fn s035_t02_r02_two_listeners() {
    let dir = TestDir::new("s035_t02");
    let clock = Arc::new(ManualClock::new(1_000));
    let bound = bind(local(&dir), clock.clone()).unwrap();
    let addresses = bound.local_addrs();
    assert_eq!(addresses.len(), 2);
    let (main, onion) = (addresses[0], addresses[1]);
    assert_ne!(main, onion);
    let shared = bound.shared().clone();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(bound.run(async {
        let _ = stopped.await;
    }));
    // The onion listener: an upgrade, and no address counted however the
    // request names one.
    let _onion_client = forwarded(onion).await;
    assert_eq!(shared.gate.entries(), 0);
    // The main listener counts its peer's.
    let mut main_client = forwarded(main).await;
    assert_eq!(shared.gate.entries(), 1);
    // `run` drives the deadlines of spec 033: the ping of R4 comes due.
    clock.advance_mono(PING_INTERVAL_MS);
    let ping = tokio::time::timeout(Duration::from_secs(10), main_client.next()).await;
    assert!(matches!(ping, Ok(Some(Ok(Message::Ping(_))))), "{ping:?}");
    stop.send(()).unwrap();
    assert_eq!(server.await.unwrap(), Outcome::Stopped);
    // Stopped, it listens no more.
    for address in [main, onion] {
        assert!(
            tokio::net::TcpStream::connect(address).await.is_err(),
            "{address}"
        );
    }
}

#[test]
fn s035_t02_r02_one_address_for_both_listeners() {
    const ONION: &str = "PRIVATECHAT_ONION_LISTEN";
    let pairs = [
        (URLS, "wss://a.org"),
        ("PRIVATECHAT_LISTEN", "127.0.0.1:9000"),
        (ONION, "127.0.0.1:9000"),
    ];
    assert_eq!(
        refused(&pairs, ONION),
        ConfigError::OutOfRange(ONION.to_owned())
    );
    let pairs = [(URLS, "wss://a.org"), (ONION, "0.0.0.0:8080")];
    assert_eq!(
        refused(&pairs, ONION),
        ConfigError::OutOfRange(ONION.to_owned())
    );
}
