//! The limits of spec 033-rate-limit-quotas. Those of one connection are
//! part of the protocol, since the client paces itself against them (spec
//! 028-session-sans-io R6, R15; spec 027-core-api R10), so they are constants
//! here, the same on every server (R11).

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

/// The limits of one channel, which the operator may change (R6, R7, R11;
/// spec 035-server-ops), checked by the writer before each insert.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ChannelLimits {
    /// Blobs inserted per 60 000 ms (R6).
    pub(crate) publish_per_min: u32,
    /// Bytes inserted per 60 000 ms (R6).
    pub(crate) bytes_per_min: u64,
    /// Blobs held (R7).
    pub(crate) max_blobs: u32,
    /// Bytes held (R7).
    pub(crate) max_bytes: u64,
}

impl Default for ChannelLimits {
    /// The defaults of the table "Limits".
    fn default() -> ChannelLimits {
        ChannelLimits {
            publish_per_min: 120,
            bytes_per_min: 4 * 1024 * 1024,
            max_blobs: 20_000,
            max_bytes: 64 * 1024 * 1024,
        }
    }
}

impl ChannelLimits {
    /// No limit a test reaches, for the tests of other rules ("with the
    /// channel limits raised").
    #[cfg(test)]
    pub(crate) const RAISED: ChannelLimits = ChannelLimits {
        publish_per_min: u32::MAX,
        bytes_per_min: u64::MAX,
        max_blobs: u32::MAX,
        max_bytes: u64::MAX,
    };
}

/// The window of R6: what a channel inserted within it counts.
pub(crate) const CHANNEL_WINDOW_MS: u64 = 60_000;

/// The most `publish`es one connection hands to the writer within
/// `CONN_PUBLISH_WINDOW_MS` (R1).
pub(crate) const CONN_PUBLISH_MAX: usize = 30;

/// The window of R1: the client keeps to 30 in 60 000 ms, and the 3 000 ms
/// less absorb network jitter.
pub(crate) const CONN_PUBLISH_WINDOW_MS: u64 = 57_000;

/// The least time between two `subscribe`s of one connection (R2), below the
/// 1 100 ms the client waits (spec 028 R6).
pub(crate) const SUBSCRIBE_GAP_MS: u64 = 1_000;

/// The most subscriptions of one connection (R3).
pub(crate) const MAX_SUBSCRIPTIONS: usize = 16;

/// How often the server pings a connection, on the monotonic clock (R4).
pub(crate) const PING_INTERVAL_MS: u64 = 30_000;

/// How long a ping may wait, from when it was due, with no pong and no other
/// write completing, before the connection closes with 1001 (R4).
pub(crate) const PONG_TIMEOUT_MS: u64 = 30_000;

/// How long one write or flush may stay pending before the TCP connection is
/// dropped with no close frame (R5).
pub(crate) const WRITE_TIMEOUT_MS: u64 = 30_000;

/// The most frames of one connection's queue not yet written (R5).
pub(crate) const SEND_QUEUE_FRAMES: usize = 256;

/// The most bytes of those frames (R5).
pub(crate) const SEND_QUEUE_BYTES: usize = 4 * 1024 * 1024;

/// Whether the ping that was due at `due` has waited `PONG_TIMEOUT_MS` at
/// `now` with no pong and no other write completing since it was due, the
/// last one having completed at `progress`: the peer is gone (R4). A slow
/// link still taking frames is not.
pub(crate) fn pong_overdue(now: u64, due: Option<u64>, progress: u64) -> bool {
    due.is_some_and(|due| now.saturating_sub(due) >= PONG_TIMEOUT_MS && progress < due)
}

/// The `publish`es of one connection handed to the writer within the
/// window of R1, by the monotonic time they were handed.
#[derive(Debug, Default)]
pub(crate) struct PublishWindow(VecDeque<u64>);

impl PublishWindow {
    /// Whether a `publish` at `now` stays within R1; those older than the
    /// window are forgotten.
    pub(crate) fn allows(&mut self, now: u64) -> bool {
        while self
            .0
            .front()
            .is_some_and(|handed| now.saturating_sub(*handed) > CONN_PUBLISH_WINDOW_MS)
        {
            self.0.pop_front();
        }
        self.0.len() < CONN_PUBLISH_MAX
    }

    /// A `publish` handed to the writer at `now`; a refused one is not.
    pub(crate) fn handed(&mut self, now: u64) {
        self.0.push_back(now);
    }
}

/// The most entries of the IP table, IPv4 addresses, /48s and /64s in all
/// (R8).
pub(crate) const IP_TABLE_MAX: usize = 65_536;

/// The window of R8's new connections and of R12's bytes, and how long
/// either keeps its entry (R9).
const ADDRESS_WINDOW_MS: u64 = 60_000;

/// The listener a connection came through (spec 035-server-ops R2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Listener {
    /// Its connections carry a client address (spec 035 R3).
    Main,
    /// The onion service's: no client address (R9).
    Onion,
}

/// The limits of the listeners and of the client addresses, which the
/// operator may change (R8, R10, R12, R11; spec 035-server-ops).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ConnectionLimits {
    pub(crate) ip_connections: u32,
    pub(crate) ip_unauth_connections: u32,
    pub(crate) ip_new_per_min: u32,
    pub(crate) max_connections: u32,
    pub(crate) onion_max_connections: u32,
    pub(crate) max_unauth_connections: u32,
    pub(crate) ip_bytes_per_min: u64,
    pub(crate) onion_bytes_per_min: u64,
    pub(crate) ip48_connections: u32,
    pub(crate) ip48_unauth_connections: u32,
    pub(crate) ip48_subnets: u32,
    pub(crate) ip48_bytes_per_min: u64,
}

impl Default for ConnectionLimits {
    /// The defaults of the table "Limits".
    fn default() -> ConnectionLimits {
        ConnectionLimits {
            ip_connections: 64,
            ip_unauth_connections: 20,
            ip_new_per_min: 60,
            max_connections: 4_096,
            onion_max_connections: 1_024,
            max_unauth_connections: 1_024,
            ip_bytes_per_min: 8 * 1024 * 1024,
            onion_bytes_per_min: 32 * 1024 * 1024,
            ip48_connections: 256,
            ip48_unauth_connections: 80,
            ip48_subnets: 256,
            ip48_bytes_per_min: 128 * 1024 * 1024,
        }
    }
}

impl ConnectionLimits {
    /// No limit a test reaches, for the tests of other rules.
    #[cfg(test)]
    pub(crate) const RAISED: ConnectionLimits = ConnectionLimits {
        ip_connections: u32::MAX,
        ip_unauth_connections: u32::MAX,
        ip_new_per_min: u32::MAX,
        max_connections: u32::MAX,
        onion_max_connections: u32::MAX,
        max_unauth_connections: u32::MAX,
        ip_bytes_per_min: u64::MAX,
        onion_bytes_per_min: u64::MAX,
        ip48_connections: u32::MAX,
        ip48_unauth_connections: u32::MAX,
        ip48_subnets: u32::MAX,
        ip48_bytes_per_min: u64::MAX,
    };
}

/// Why a connection is refused before its upgrade.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refused {
    /// A bound of its address, HTTP 429 (R8).
    Address,
    /// A cap of its listener, HTTP 503 (R10).
    Listener,
}

/// What an IPv4 address, a /64 or a /48 counts (R8).
#[derive(Debug, Default)]
struct Counts {
    open: u32,
    unauth: u32,
    /// Connections opened within `ADDRESS_WINDOW_MS`.
    opened: u32,
    /// Bytes of the blobs handed to the writer within `ADDRESS_WINDOW_MS`
    /// (R12).
    bytes: u64,
}

impl Counts {
    fn is_empty(&self) -> bool {
        self.open == 0 && self.unauth == 0 && self.opened == 0 && self.bytes == 0
    }
}

/// What the window of the table holds of one node.
#[derive(Clone, Copy)]
enum Event {
    /// A connection opened (R8).
    Opened,
    /// The bytes of a blob handed to the writer (R12).
    Published(u64),
}

/// An entry of the table: an IPv4 address, a /48, or a /64 inside its /48.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Key {
    V4(Ipv4Addr),
    Site([u8; 6]),
    Subnet([u8; 8]),
}

/// Whether one more connection of `key`, which counts `counts`, stays
/// within the bounds of R8.
fn within(key: Key, counts: &Counts, limits: &ConnectionLimits) -> bool {
    match key {
        Key::Site(_) => {
            counts.open < limits.ip48_connections && counts.unauth < limits.ip48_unauth_connections
        }
        Key::V4(_) | Key::Subnet(_) => {
            counts.open < limits.ip_connections
                && counts.unauth < limits.ip_unauth_connections
                && counts.opened < limits.ip_new_per_min
        }
    }
}

/// The bounds of R8 on the first connection of a new entry, which a value
/// of 0 refuses.
fn check_new(key: Key, limits: &ConnectionLimits) -> Result<(), Refused> {
    if within(key, &Counts::default(), limits) {
        Ok(())
    } else {
        Err(Refused::Address)
    }
}

struct Node {
    key: Key,
    /// The /48 of a /64.
    parent: Option<u64>,
    /// The /64s of a /48.
    children: u32,
    counts: Counts,
}

/// The client addresses of the main listener, held only here (R9). A
/// connection holds the id of its node, never its address.
#[derive(Default)]
struct IpTable {
    ids: HashMap<Key, u64>,
    nodes: HashMap<u64, Node>,
    next: u64,
    /// What each node counts within `ADDRESS_WINDOW_MS`, and when, oldest
    /// first.
    recent: VecDeque<(u64, u64, Event)>,
}

impl IpTable {
    /// The node `address` is counted in when the connection is admitted;
    /// `None` when the table is full and its IPv4 address or /48 has no
    /// entry, which leaves it to R10 alone.
    fn admit(
        &mut self,
        address: IpAddr,
        limits: &ConnectionLimits,
        now: u64,
    ) -> Result<Option<u64>, Refused> {
        let id = match address.to_canonical() {
            IpAddr::V4(v4) => match self.ids.get(&Key::V4(v4)).copied() {
                Some(id) => self.check(id, limits).map(|()| id)?,
                None if self.nodes.len() >= IP_TABLE_MAX => return Ok(None),
                None => {
                    check_new(Key::V4(v4), limits)?;
                    self.insert(Key::V4(v4), None)
                }
            },
            IpAddr::V6(v6) => {
                let [a, b, c, d, e, f, g, h, ..] = v6.octets();
                let (site_key, subnet) = (
                    Key::Site([a, b, c, d, e, f]),
                    Key::Subnet([a, b, c, d, e, f, g, h]),
                );
                let Some(site) = self.ids.get(&site_key).copied() else {
                    if self.nodes.len().saturating_add(2) > IP_TABLE_MAX {
                        return Ok(None);
                    }
                    check_new(site_key, limits)?;
                    check_new(subnet, limits)?;
                    if limits.ip48_subnets == 0 {
                        return Err(Refused::Address);
                    }
                    let site = self.insert(site_key, None);
                    let id = self.insert(subnet, Some(site));
                    self.count(id, now);
                    return Ok(Some(id));
                };
                self.check(site, limits)?;
                match self.ids.get(&subnet).copied() {
                    Some(id) => self.check(id, limits).map(|()| id)?,
                    None if self
                        .nodes
                        .get(&site)
                        .is_some_and(|site| site.children >= limits.ip48_subnets) =>
                    {
                        return Err(Refused::Address);
                    }
                    // A full table still checks a known /48, and counts the
                    // connection there with no /64 of its own. A fresh /64
                    // passed `check_new` when its /48 was created.
                    None if self.nodes.len() >= IP_TABLE_MAX => site,
                    None => self.insert(subnet, Some(site)),
                }
            }
        };
        self.count(id, now);
        Ok(Some(id))
    }

    /// The bounds of R8 on one more connection of `id`.
    fn check(&self, id: u64, limits: &ConnectionLimits) -> Result<(), Refused> {
        match self.nodes.get(&id) {
            Some(node) if !within(node.key, &node.counts, limits) => Err(Refused::Address),
            _ => Ok(()),
        }
    }

    fn insert(&mut self, key: Key, parent: Option<u64>) -> u64 {
        let id = self.next;
        self.next = id.saturating_add(1);
        if let Some(parent) = parent.and_then(|parent| self.nodes.get_mut(&parent)) {
            parent.children = parent.children.saturating_add(1);
        }
        self.ids.insert(key, id);
        self.nodes.insert(
            id,
            Node {
                key,
                parent,
                children: 0,
                counts: Counts::default(),
            },
        );
        id
    }

    /// A connection opened at `now`, unauthenticated, in `id` and its /48.
    fn count(&mut self, id: u64, now: u64) {
        self.update(id, |counts, own| {
            counts.open = counts.open.saturating_add(1);
            counts.unauth = counts.unauth.saturating_add(1);
            if own {
                counts.opened = counts.opened.saturating_add(1);
            }
        });
        self.recent.push_back((now, id, Event::Opened));
    }

    /// Whether `bytes` more from `id` stay within R12: those of its address
    /// within `ip_bytes_per_min`, and those of its /48 within
    /// `ip48_bytes_per_min`. A connection a full table counts in its /48
    /// alone has its address's budget on the /48's bytes, which hold its
    /// own.
    fn allows(&self, id: u64, bytes: u64, limits: &ConnectionLimits) -> bool {
        let Some(node) = self.nodes.get(&id) else {
            return true;
        };
        let site = match node.key {
            Key::Site(_) => Some(node),
            Key::V4(_) | Key::Subnet(_) => node.parent.and_then(|parent| self.nodes.get(&parent)),
        };
        node.counts.bytes.saturating_add(bytes) <= limits.ip_bytes_per_min
            && site.is_none_or(|site| {
                site.counts.bytes.saturating_add(bytes) <= limits.ip48_bytes_per_min
            })
    }

    /// `bytes` handed to the writer at `now` from `id`, in it and its /48.
    fn publish(&mut self, id: u64, bytes: u64, now: u64) {
        self.update(id, |counts, _| {
            counts.bytes = counts.bytes.saturating_add(bytes);
        });
        self.recent.push_back((now, id, Event::Published(bytes)));
    }

    /// The first `subscribe` of a connection of `id` accepted.
    fn authenticate(&mut self, id: u64) {
        self.update(id, |counts, _| {
            counts.unauth = counts.unauth.saturating_sub(1);
        });
    }

    /// A connection of `id` closed.
    fn leave(&mut self, id: u64, authenticated: bool) {
        self.update(id, |counts, _| {
            counts.open = counts.open.saturating_sub(1);
            if !authenticated {
                counts.unauth = counts.unauth.saturating_sub(1);
            }
        });
        self.prune(id);
    }

    /// The connections opened and the bytes published more than
    /// `ADDRESS_WINDOW_MS` before `now` forgotten, and the entries left
    /// counting nothing removed (R9).
    fn forget(&mut self, now: u64) {
        while let Some(&(at, id, event)) = self.recent.front() {
            if now.saturating_sub(at) <= ADDRESS_WINDOW_MS {
                break;
            }
            self.recent.pop_front();
            match event {
                Event::Opened => {
                    if let Some(node) = self.nodes.get_mut(&id) {
                        node.counts.opened = node.counts.opened.saturating_sub(1);
                    }
                }
                Event::Published(bytes) => self.update(id, |counts, _| {
                    counts.bytes = counts.bytes.saturating_sub(bytes);
                }),
            }
            self.prune(id);
        }
    }

    /// `change` applied to `id`'s counts (`own`) and to its /48's.
    fn update(&mut self, id: u64, change: impl Fn(&mut Counts, bool)) {
        let Some(node) = self.nodes.get_mut(&id) else {
            return;
        };
        change(&mut node.counts, true);
        if let Some(parent) = node.parent.and_then(|parent| self.nodes.get_mut(&parent)) {
            change(&mut parent.counts, false);
        }
    }

    /// `id` removed when it counts nothing, then its /48 likewise (R9).
    fn prune(&mut self, id: u64) {
        let Some(node) = self.nodes.get(&id) else {
            return;
        };
        if !node.counts.is_empty() || node.children > 0 {
            return;
        }
        let (key, parent) = (node.key, node.parent);
        self.nodes.remove(&id);
        self.ids.remove(&key);
        if let Some(parent) = parent {
            if let Some(site) = self.nodes.get_mut(&parent) {
                site.children = site.children.saturating_sub(1);
            }
            self.prune(parent);
        }
    }
}

/// The connections open on one listener (R10).
#[derive(Default)]
struct Caps {
    open: u32,
    unauth: u32,
}

/// The bytes all onion connections handed to the writer within
/// `ADDRESS_WINDOW_MS` (R12).
#[derive(Default)]
struct OnionBytes {
    total: u64,
    recent: VecDeque<(u64, u64)>,
}

impl OnionBytes {
    fn allows(&self, bytes: u64, limits: &ConnectionLimits) -> bool {
        self.total.saturating_add(bytes) <= limits.onion_bytes_per_min
    }

    fn publish(&mut self, bytes: u64, now: u64) {
        self.total = self.total.saturating_add(bytes);
        self.recent.push_back((now, bytes));
    }

    fn forget(&mut self, now: u64) {
        while let Some(&(at, bytes)) = self.recent.front() {
            if now.saturating_sub(at) <= ADDRESS_WINDOW_MS {
                break;
            }
            self.recent.pop_front();
            self.total = self.total.saturating_sub(bytes);
        }
    }
}

#[derive(Default)]
struct GateState {
    table: IpTable,
    main: Caps,
    onion: Caps,
    onion_bytes: OnionBytes,
}

impl GateState {
    fn caps(&mut self, listener: Listener) -> &mut Caps {
        match listener {
            Listener::Main => &mut self.main,
            Listener::Onion => &mut self.onion,
        }
    }
}

/// Where every connection is admitted or refused before its upgrade: the
/// caps of each listener (R10), then the IP table (R8), under one lock, so
/// that a refused connection counts nowhere.
pub(crate) struct Gate {
    limits: ConnectionLimits,
    state: Mutex<GateState>,
}

impl Gate {
    pub(crate) fn new(limits: ConnectionLimits) -> Arc<Gate> {
        Arc::new(Gate {
            limits,
            state: Mutex::new(GateState::default()),
        })
    }

    fn lock(&self) -> MutexGuard<'_, GateState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// A connection of `listener` from `address` (none on the onion
    /// listener) at `now`, counted until its `Admission` drops.
    ///
    /// # Errors
    ///
    /// `Refused` for the cap or the bound it would pass; nothing is counted.
    pub(crate) fn admit(
        self: &Arc<Gate>,
        listener: Listener,
        address: Option<IpAddr>,
        now: u64,
    ) -> Result<Admission, Refused> {
        let limits = &self.limits;
        let mut state = self.lock();
        state.table.forget(now);
        let max = match listener {
            Listener::Main => limits.max_connections,
            Listener::Onion => limits.onion_max_connections,
        };
        let caps = state.caps(listener);
        if caps.open >= max || caps.unauth >= limits.max_unauth_connections {
            return Err(Refused::Listener);
        }
        let node = match (listener, address) {
            (Listener::Main, Some(address)) => state.table.admit(address, limits, now)?,
            _ => None,
        };
        let caps = state.caps(listener);
        caps.open = caps.open.saturating_add(1);
        caps.unauth = caps.unauth.saturating_add(1);
        Ok(Admission {
            gate: self.clone(),
            listener,
            node,
            authenticated: false,
        })
    }

    /// The deadline task's sweep at `now` (R9).
    pub(crate) fn forget(&self, now: u64) {
        let mut state = self.lock();
        state.table.forget(now);
        // `Admission::publish` forgets them too; this frees their memory
        // when no onion connection publishes.
        state.onion_bytes.forget(now);
    }

    /// How many entries the table holds.
    #[cfg(test)]
    pub(crate) fn entries(&self) -> usize {
        self.lock().table.nodes.len()
    }
}

/// One admitted connection, counted by its listener and its address's
/// entry until it drops. It holds no address (R9).
pub(crate) struct Admission {
    gate: Arc<Gate>,
    listener: Listener,
    node: Option<u64>,
    authenticated: bool,
}

impl fmt::Debug for Admission {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Every field named, so that a new one is a choice: T09 reads this
        // output for the address it must not hold (R9).
        let Admission {
            gate: _,
            listener,
            node,
            authenticated,
        } = self;
        formatter
            .debug_struct("Admission")
            .field("listener", listener)
            .field("node", node)
            .field("authenticated", authenticated)
            .finish()
    }
}

impl Admission {
    /// A blob of `bytes` from this connection at `now`, handed to the
    /// writer by `submit` when the budgets of R12 allow it, and counted in
    /// them only when `submit` takes it. `None` when a budget refuses it.
    /// The check, the hand-over and the count happen under one lock, so
    /// that two connections of one address cannot both slip under it.
    pub(crate) fn publish<E>(
        &self,
        bytes: u64,
        now: u64,
        submit: impl FnOnce() -> Result<(), E>,
    ) -> Option<Result<(), E>> {
        let limits = &self.gate.limits;
        let mut state = self.gate.lock();
        let state = &mut *state;
        state.table.forget(now);
        state.onion_bytes.forget(now);
        let allowed = match (self.listener, self.node) {
            (Listener::Onion, _) => state.onion_bytes.allows(bytes, limits),
            (Listener::Main, Some(node)) => state.table.allows(node, bytes, limits),
            // A connection the full table holds no entry for: R10 alone.
            (Listener::Main, None) => true,
        };
        if !allowed {
            return None;
        }
        let submitted = submit();
        if submitted.is_ok() {
            match (self.listener, self.node) {
                (Listener::Onion, _) => state.onion_bytes.publish(bytes, now),
                (Listener::Main, Some(node)) => state.table.publish(node, bytes, now),
                (Listener::Main, None) => {}
            }
        }
        Some(submitted)
    }

    /// Its first `subscribe` accepted: no longer counted as unauthenticated.
    pub(crate) fn authenticate(&mut self) {
        if std::mem::replace(&mut self.authenticated, true) {
            return;
        }
        let mut state = self.gate.lock();
        let caps = state.caps(self.listener);
        caps.unauth = caps.unauth.saturating_sub(1);
        if let Some(node) = self.node {
            state.table.authenticate(node);
        }
    }
}

impl Drop for Admission {
    fn drop(&mut self) {
        let mut state = self.gate.lock();
        let caps = state.caps(self.listener);
        caps.open = caps.open.saturating_sub(1);
        if !self.authenticated {
            caps.unauth = caps.unauth.saturating_sub(1);
        }
        if let Some(node) = self.node {
            state.table.leave(node, self.authenticated);
        }
    }
}
