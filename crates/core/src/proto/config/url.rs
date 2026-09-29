//! The grammar of `server_url` (spec 011 R5, ADR 0038), the only URL parsing
//! in the workspace.
//!
//! A whitelist: `wss://` ‖ host ‖ optional `:` port, or `ws://` ‖ v3 onion
//! host ‖ optional `:` port, and nothing else. No percent-decoding, no
//! Unicode host, no IPv6, no user, no path and no default port written out.

use crate::Error;

/// The largest `server_url`, which is also the only bound of a `wss://` host.
pub(crate) const MAX_URL: usize = 256;

/// The scheme of a server reached over TLS.
const TLS_SCHEME: &str = "wss://";

/// The scheme of an onion service, reached with no TLS through SOCKS5.
const ONION_SCHEME: &str = "ws://";

/// The port each scheme implies, which the URL never writes out.
const TLS_PORT: u16 = 443;
const ONION_PORT: u16 = 80;

/// A v3 onion address: 56 characters of base32 and the suffix.
const ONION_LABEL_LEN: usize = 56;
const ONION_SUFFIX: &str = ".onion";

/// The host of a `server_url` that matches the grammar of R5, without the
/// scheme or the port (R6).
///
/// # Errors
///
/// `BadConfig` for any text outside the grammar.
pub(crate) fn parse(url: &str) -> Result<&str, Error> {
    if url.len() > MAX_URL {
        return Err(Error::BadConfig);
    }
    let (rest, implied_port, is_host): (&str, u16, fn(&str) -> bool) =
        if let Some(rest) = url.strip_prefix(TLS_SCHEME) {
            (rest, TLS_PORT, is_tls_host)
        } else if let Some(rest) = url.strip_prefix(ONION_SCHEME) {
            (rest, ONION_PORT, is_onion_host)
        } else {
            return Err(Error::BadConfig);
        };
    let (host, port) = match rest.split_once(':') {
        Some((host, port)) => (host, Some(parse_port(port)?)),
        None => (rest, None),
    };
    if !is_host(host) || port == Some(implied_port) {
        return Err(Error::BadConfig);
    }
    Ok(host)
}

/// At least one byte of `a-z`, `0-9`, `-` and `.`.
fn is_tls_host(host: &str) -> bool {
    !host.is_empty()
        && host
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"-.".contains(&byte))
}

/// Exactly 56 bytes of `a-z` and `2-7`, then `.onion`.
fn is_onion_host(host: &str) -> bool {
    host.strip_suffix(ONION_SUFFIX).is_some_and(|label| {
        label.len() == ONION_LABEL_LEN
            && label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || (b'2'..=b'7').contains(&byte))
    })
}

/// A decimal within 1..=65535 with no leading zero, so each port has one
/// spelling.
fn parse_port(text: &str) -> Result<u16, Error> {
    let canonical = !text.starts_with('0') && text.bytes().all(|byte| byte.is_ascii_digit());
    match text.parse::<u16>() {
        Ok(port) if canonical => Ok(port),
        _ => Err(Error::BadConfig),
    }
}
