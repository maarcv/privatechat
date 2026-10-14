//! The routes of the connection plan (spec 027-core-api R10): which
//! channels can be reached with the settings as they stand.

use crate::proto::config::url;

/// The scheme of a server reached with no TLS, an onion host (spec
/// 011-config-format R5).
const PLAIN_SCHEME: &str = "ws://";

/// The suffix of an onion host.
const ONION_SUFFIX: &str = ".onion";

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
/// `127.0.0.0/8`, never a host name, which would trust a resolver (R10);
/// the parser of `core::net` refuses leading zeros, so each address has
/// one spelling.
fn is_loopback_literal(proxy: &str) -> bool {
    proxy.rsplit_once(':').is_some_and(|(host, _)| {
        host.parse::<core::net::Ipv4Addr>()
            .is_ok_and(|address| address.is_loopback())
    })
}

#[cfg(test)]
mod tests;
