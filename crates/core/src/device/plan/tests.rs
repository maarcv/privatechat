//! Tests of `needs_proxy` (spec 027-core-api R10).

use super::needs_proxy;

const ONION: &str = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion";

/// Spec 027, R10: with no proxy an onion host, trailing dots removed,
/// needs one; with a proxy a `ws://` URL needs it on a loopback IP
/// literal, never a host name.
#[test]
fn s027_t10_r10_needs_proxy() {
    let onion_wss = format!("wss://{ONION}");
    let onion_dot = format!("wss://{ONION}.");
    let onion_ws = format!("ws://{ONION}");
    assert!(!needs_proxy("wss://example.org", None));
    assert!(needs_proxy(&onion_wss, None));
    assert!(needs_proxy(&onion_dot, None));
    assert!(needs_proxy(&onion_ws, None));
    for proxy in ["127.0.0.1:9050", "127.1.2.3:9150", "127.0.0.0:1"] {
        assert!(!needs_proxy(&onion_ws, Some(proxy)), "{proxy}");
        assert!(!needs_proxy(&onion_wss, Some(proxy)), "{proxy}");
    }
    for proxy in [
        "192.168.1.10:9050",
        "localhost:9050",
        "127.0.0.01:9050",
        "127.0.0:9050",
        "127.0.0.1.1:9050",
        "127.0.0.256:9050",
        "128.0.0.1:9050",
    ] {
        assert!(needs_proxy(&onion_ws, Some(proxy)), "{proxy}");
        assert!(!needs_proxy(&onion_wss, Some(proxy)), "{proxy}");
        assert!(!needs_proxy("wss://example.org", Some(proxy)), "{proxy}");
    }
}
