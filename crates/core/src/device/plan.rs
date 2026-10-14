//! The routes of the connection plan (spec 027-core-api R10): which
//! channels can be reached with the settings as they stand.

use crate::proto::config::url;

/// The scheme of a server reached with no TLS, an onion host (spec
/// 011-config-format R5).
const PLAIN_SCHEME: &str = "ws://";

/// The suffix of an onion host.
const ONION_SUFFIX: &str = ".onion";

/// The first octet of the IPv4 loopback block `127.0.0.0/8`.
const LOOPBACK_OCTET: u8 = 127;

/// Whether the channel of `server_url` needs a SOCKS5 proxy running on
/// this device (R10): an onion host with no proxy, so that no resolver is
/// asked for it, or a `ws://` URL with a proxy that is not a loopback IP
/// literal, so that plain WebSocket never crosses a network.
pub(super) fn needs_proxy(server_url: &str, proxy: Option<&str>) -> bool {
    let Ok(host) = url::parse(server_url) else {
        return true;
    };
    match proxy {
        None => host.trim_end_matches('.').ends_with(ONION_SUFFIX),
        Some(proxy) => server_url.starts_with(PLAIN_SCHEME) && !is_loopback_literal(proxy),
    }
}

/// Whether the host of `proxy` (`host:port`) is an IPv4 literal in
/// `127.0.0.0/8`, written canonically, never a host name (R10).
fn is_loopback_literal(proxy: &str) -> bool {
    let Some((host, _)) = proxy.rsplit_once(':') else {
        return false;
    };
    let octets: Vec<&str> = host.split('.').collect();
    octets.len() == 4
        && octets.iter().all(|octet| parse_octet(octet).is_some())
        && octets.first().and_then(|octet| parse_octet(octet)) == Some(LOOPBACK_OCTET)
}

/// A decimal octet with no leading zero, so each address has one spelling.
fn parse_octet(text: &str) -> Option<u8> {
    let canonical = !text.is_empty()
        && text.bytes().all(|byte| byte.is_ascii_digit())
        && (text == "0" || !text.starts_with('0'));
    canonical.then(|| text.parse().ok()).flatten()
}

#[cfg(test)]
mod tests;
