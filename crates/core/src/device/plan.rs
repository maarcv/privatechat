//! The connection plan (spec 027-core-api R10, R12): which channels can
//! be reached with the settings as they stand, grouped in runs of at most
//! 16 by the route they take, one per channel behind a proxy; and the
//! route of the create-time probe.

use super::Device;
use crate::crypto;
use crate::error::Error;
use crate::proto::config::url;
use crate::session::frames::{Frame, is_supported};

/// The most channels on one connection without a proxy (R10).
const MAX_RUN: usize = 16;

/// Bytes drawn for a SOCKS username, written as 8 lowercase hex
/// characters (R10).
const SOCKS_USERNAME_BYTES: usize = 4;

/// How a connection reaches its server (R10).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Route {
    /// The server's host, as the URL writes it.
    pub host: String,
    /// The port, written or implied by the scheme.
    pub port: u16,
    /// `false` only for a `ws://` URL, an onion host behind a loopback
    /// proxy.
    pub tls: bool,
    /// `host:port` of the SOCKS5 proxy, when one is set.
    pub socks5_proxy: Option<String>,
    /// With a proxy, 8 random lowercase hex characters drawn when the
    /// plan's `id` was minted, so that the proxy's observers learn no
    /// `channel_id` and link no channel across plans.
    pub socks_username: Option<String>,
}

/// One connection the client keeps open: its `id`, its route and its
/// channels (R10).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectionPlan {
    /// An identifier this device never gave another plan.
    pub id: u64,
    /// Where it goes.
    pub route: Route,
    /// The channels it carries, at most 16, one behind a proxy.
    pub channels: Vec<[u8; 16]>,
}

impl Route {
    /// Whether two routes go the same way, the username aside.
    fn same_way(&self, other: &Route) -> bool {
        self.host == other.host
            && self.port == other.port
            && self.tls == other.tls
            && self.socks5_proxy == other.socks5_proxy
    }
}

/// The route of `server_url` with `proxy`, its username not drawn yet.
fn route_of(server_url: &str, proxy: Option<&str>) -> Result<Route, Error> {
    let endpoint = url::endpoint(server_url)?;
    Ok(Route {
        host: endpoint.host.to_owned(),
        port: endpoint.port,
        tls: endpoint.tls,
        socks5_proxy: proxy.map(str::to_owned),
        socks_username: None,
    })
}

/// A fresh SOCKS username: 8 lowercase hex characters from `random_bytes`.
fn socks_username() -> Result<String, Error> {
    let bytes: [u8; SOCKS_USERNAME_BYTES] = crypto::random_bytes()?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// Whether `frame` is a `hello` whose versions this build speaks, by the
/// rule of spec 028-session-sans-io R2, for the create-time probe (R12).
///
/// # Errors
///
/// `BadPayload` for a frame that is not a `hello`; the errors of
/// `Frame::decode`.
pub fn probe_hello(frame: &[u8]) -> Result<bool, Error> {
    match Frame::decode(frame)? {
        Frame::Hello { proto_versions, .. } => Ok(is_supported(&proto_versions)),
        _ => Err(Error::BadPayload),
    }
}

impl Device {
    /// The connections to keep open (R10); none while the settings are
    /// reset (R2).
    pub fn connections(&self) -> Vec<ConnectionPlan> {
        if self.settings.is_reset() {
            return Vec::new();
        }
        self.runs.clone()
    }

    /// The route of the create-time check of `server_url` (R12): `None`
    /// while the settings are reset (R2), so that nothing connects.
    ///
    /// # Errors
    ///
    /// `BadConfig` for a URL outside the grammar, or one the settings
    /// cannot reach (`needs_proxy`, R10); `Internal` when libsodium fails.
    pub fn probe_plan(&self, server_url: &str) -> Result<Option<Route>, Error> {
        url::parse(server_url)?;
        if self.settings.is_reset() {
            return Ok(None);
        }
        let proxy = self.settings.current().socks5_proxy.as_deref();
        if needs_proxy(server_url, proxy) {
            return Err(Error::BadConfig);
        }
        let mut route = route_of(server_url, proxy)?;
        if proxy.is_some() {
            route.socks_username = Some(socks_username()?);
        }
        Ok(Some(route))
    }

    /// Brings the runs in line with the open channels and the settings
    /// (R10): a channel that left or changed route leaves its run, a run
    /// whose channels or route changed gets a new `id`, and a channel in
    /// no run joins the last run of its route with room, or starts one; a
    /// run left empty is removed. A channel whose username cannot be
    /// drawn waits in no run for the next change.
    pub(super) fn replan(&mut self) {
        let proxy = self.settings.current().socks5_proxy.clone();
        let wanted: Vec<([u8; 16], Route)> = self
            .channels
            .iter()
            .filter_map(|open| {
                let config = open.channel.config();
                if needs_proxy(config.server_url(), proxy.as_deref()) {
                    return None;
                }
                let route = route_of(config.server_url(), proxy.as_deref()).ok()?;
                Some((config.channel_id(), route))
            })
            .collect();
        let mut runs = core::mem::take(&mut self.runs);
        for run in &mut runs {
            let before = run.channels.len();
            run.channels.retain(|id| {
                wanted
                    .iter()
                    .any(|(wanted_id, route)| wanted_id == id && route.same_way(&run.route))
            });
            if run.channels.len() != before {
                self.mint(run);
            }
        }
        runs.retain(|run| !run.channels.is_empty());
        for (id, route) in wanted {
            if runs.iter().any(|run| run.channels.contains(&id)) {
                continue;
            }
            let room = runs
                .iter()
                .rposition(|run| run.route.same_way(&route) && run.channels.len() < MAX_RUN)
                .filter(|_| proxy.is_none());
            if let Some(run) = room.and_then(|position| runs.get_mut(position)) {
                run.channels.push(id);
                self.mint(run);
                continue;
            }
            let mut run = ConnectionPlan {
                id: 0,
                route,
                channels: vec![id],
            };
            self.mint(&mut run);
            runs.push(run);
        }
        runs.retain(|run| run.id != 0);
        self.runs = runs;
    }

    /// Gives `run` an `id` this device never used and, behind a proxy, a
    /// fresh username; the `id` 0, which `replan` drops, when the username
    /// cannot be drawn.
    fn mint(&mut self, run: &mut ConnectionPlan) {
        self.next_plan_id = self.next_plan_id.saturating_add(1);
        run.id = self.next_plan_id;
        run.route.socks_username = None;
        if run.route.socks5_proxy.is_some() {
            match socks_username() {
                Ok(username) => run.route.socks_username = Some(username),
                Err(_) => run.id = 0,
            }
        }
    }
}

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
