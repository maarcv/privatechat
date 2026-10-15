//! The connection plan (spec 027-core-api R10, R12): which channels can
//! be reached with the settings as they stand, grouped in runs of at most
//! 16 by the route they take, one per channel behind a proxy; and the
//! route of the create-time probe.

use std::collections::BTreeSet;
use std::fmt;

use super::Device;
use crate::crypto;
use crate::error::Error;
use crate::proto::config::url::{self, ONION_SUFFIX};
use crate::session::channel::key_prefix;
use crate::session::frames::{Frame, is_supported};

/// The most channels on one connection without a proxy (R10).
const MAX_RUN: usize = 16;

/// Bytes drawn for a SOCKS username, written as 8 lowercase hex
/// characters (R10).
const SOCKS_USERNAME_BYTES: usize = 4;

/// How a connection reaches its server (R10); its `Debug` shows neither
/// the host, which names the channels' server, nor the SOCKS username,
/// which unlinks the plan's channels.
#[derive(Clone, PartialEq, Eq)]
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

impl fmt::Debug for Route {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Route")
            .field("port", &self.port)
            .field("tls", &self.tls)
            .field("proxied", &self.socks5_proxy.is_some())
            .finish_non_exhaustive()
    }
}

/// One connection the client keeps open: its `id`, its route and its
/// channels (R10); its `Debug` shows each `channel_id`'s prefix (AGENTS 19).
#[derive(Clone, PartialEq, Eq)]
pub struct ConnectionPlan {
    /// An identifier this device never gave another plan.
    pub id: u64,
    /// Where it goes.
    pub route: Route,
    /// The channels it carries, at most 16, one behind a proxy.
    pub channels: Vec<[u8; 16]>,
}

impl fmt::Debug for ConnectionPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let channels: Vec<String> = self.channels.iter().map(|id| key_prefix(id)).collect();
        f.debug_struct("ConnectionPlan")
            .field("id", &self.id)
            .field("route", &self.route)
            .field("channels", &channels)
            .finish()
    }
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

/// The route of the channel of `server_url` with `proxy`, its username not
/// drawn yet; `None` when it needs a SOCKS5 proxy running on this device
/// (R10): an onion host with no proxy, so that no resolver is asked for
/// it, or a `ws://` URL behind a proxy that is not a loopback IP literal,
/// so that plain WebSocket never crosses a network.
fn reach(server_url: &str, proxy: Option<&str>) -> Option<Route> {
    let endpoint = url::endpoint(server_url).ok()?;
    let reachable = match proxy {
        None => !endpoint.host.trim_end_matches('.').ends_with(ONION_SUFFIX),
        Some(proxy) => endpoint.tls || is_loopback_literal(proxy),
    };
    reachable.then(|| Route {
        host: endpoint.host.to_owned(),
        port: endpoint.port,
        tls: endpoint.tls,
        socks5_proxy: proxy.map(str::to_owned),
        socks_username: None,
    })
}

/// Whether the channel of `server_url` needs a SOCKS5 proxy running on
/// this device (R10), which `ChannelInfo::needs_proxy` shows.
pub(super) fn needs_proxy(server_url: &str, proxy: Option<&str>) -> bool {
    reach(server_url, proxy).is_none()
}

/// A fresh SOCKS username: 8 lowercase hex characters from `random_bytes`.
fn socks_username() -> Result<String, Error> {
    let bytes: [u8; SOCKS_USERNAME_BYTES] = crypto::random_bytes()?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// A SOCKS username no run of `runs` holds, so that a proxy which
/// isolates by username, as Tor does, never puts two channels, or a probe
/// and a channel, on one circuit (R10, R12).
///
/// # Errors
///
/// `Internal` when libsodium fails.
fn fresh_username(runs: &[ConnectionPlan]) -> Result<String, Error> {
    loop {
        let username = socks_username()?;
        let taken = runs
            .iter()
            .any(|run| run.route.socks_username.as_ref() == Some(&username));
        if !taken {
            return Ok(username);
        }
    }
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
        // R11: a plan whose channels have all been refused since it was
        // built is left out.
        self.runs
            .iter()
            .filter(|run| {
                self.links
                    .get(&run.id)
                    .is_none_or(|link| !run.channels.iter().all(|id| link.refused.contains(id)))
            })
            .cloned()
            .collect()
    }

    /// The route of the create-time check of `server_url` (R12): `None`
    /// while the settings are reset (R2), so that nothing connects.
    ///
    /// # Errors
    ///
    /// `BadConfig` for a URL outside the grammar, or one the settings
    /// cannot reach (`needs_proxy`, R10); `Internal` when libsodium fails.
    pub fn probe_plan(&self, server_url: &str) -> Result<Option<Route>, Error> {
        url::endpoint(server_url)?;
        if self.settings.is_reset() {
            return Ok(None);
        }
        let proxy = self.settings.current().socks5_proxy.as_deref();
        let mut route = reach(server_url, proxy).ok_or(Error::BadConfig)?;
        if proxy.is_some() {
            route.socks_username = Some(fresh_username(&self.runs)?);
        }
        Ok(Some(route))
    }

    /// Brings the runs in line with the open channels and the settings
    /// (R10): a channel that left or changed route leaves its run, a run
    /// whose channels changed gets a new `id`, a run left empty is
    /// removed, and a channel in no run joins the last run of its route
    /// with room, or starts one. A channel whose username cannot be drawn
    /// waits in no run for the next change.
    pub(super) fn replan(&mut self) {
        let proxy = self.settings.current().socks5_proxy.clone();
        let wanted: Vec<([u8; 16], Route)> = self
            .channels
            .iter()
            .filter_map(|channel| {
                let config = channel.config();
                let route = reach(config.server_url(), proxy.as_deref())?;
                Some((config.channel_id(), route))
            })
            .collect();
        let mut runs = core::mem::take(&mut self.runs);
        // Each run that changed is minted once, in plan order.
        let mut changed = BTreeSet::new();
        for (position, run) in runs.iter_mut().enumerate() {
            let before = run.channels.len();
            run.channels.retain(|id| {
                wanted
                    .iter()
                    .any(|(wanted_id, route)| wanted_id == id && route.same_way(&run.route))
            });
            if run.channels.len() != before {
                changed.insert(position);
            }
        }
        for (id, route) in wanted {
            if runs.iter().any(|run| run.channels.contains(&id)) {
                continue;
            }
            let room = runs.iter().rposition(|run| {
                proxy.is_none() && run.route.same_way(&route) && run.channels.len() < MAX_RUN
            });
            match room.and_then(|position| runs.get_mut(position).map(|run| (position, run))) {
                Some((position, run)) => {
                    run.channels.push(id);
                    changed.insert(position);
                }
                None => {
                    changed.insert(runs.len());
                    runs.push(ConnectionPlan {
                        id: 0,
                        route,
                        channels: vec![id],
                    });
                }
            }
        }
        for position in changed {
            let minted = match runs.get(position) {
                Some(run) if !run.channels.is_empty() => self.mint(&run.route, &runs),
                _ => continue,
            };
            if let Some(run) = runs.get_mut(position) {
                match minted {
                    Ok((id, username)) => {
                        run.id = id;
                        run.route.socks_username = username;
                    }
                    Err(_) => run.channels.clear(),
                }
            }
        }
        runs.retain(|run| !run.channels.is_empty());
        self.runs = runs;
        self.relink();
    }

    /// An `id` this device never used and, behind a proxy, a username no
    /// run of `runs` holds (R10).
    ///
    /// # Errors
    ///
    /// `Internal` when libsodium fails.
    fn mint(
        &mut self,
        route: &Route,
        runs: &[ConnectionPlan],
    ) -> Result<(u64, Option<String>), Error> {
        let username = match route.socks5_proxy {
            Some(_) => Some(fresh_username(runs)?),
            None => None,
        };
        self.next_plan_id = self.next_plan_id.saturating_add(1);
        Ok((self.next_plan_id, username))
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
