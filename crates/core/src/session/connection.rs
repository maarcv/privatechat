//! The client side of one connection (spec 028-session-sans-io R5–R18): a
//! state machine with no I/O, which the `Device` of spec 027-core-api hands
//! every frame its socket received and every tick, and which returns the
//! frames to write and the events to show.
//!
//! This slice holds the connection and the subscription (R1, R2 and R5–R7)
//! and marks a channel subscribed at its `ok`. Later slices of spec 028
//! add truncation and `synced` (R8, R9), traffic and outcomes (R10–R14),
//! the publish rate (R15), the error codes other than `nonce_expired`
//! (R16), and, with `rate_limited`, the one clause of R7 only it can
//! reach: a `subscribe` queued again after it is released however old its
//! nonce.

use core::fmt;
use std::collections::{BTreeMap, VecDeque};

use super::channel::{Channel, key_prefix};
use super::frames::{CODE_NONCE_EXPIRED, Frame, is_supported};
use crate::Error;
use crate::crypto;
use crate::proto::auth::auth_message;
use crate::proto::envelope::ttl_ms;

#[cfg(test)]
mod tests;

/// The least time between two `subscribe`s released on one connection
/// (R6): the server's one authentication attempt a second, with a margin
/// for network jitter.
const SUBSCRIBE_SPACING_MS: u64 = 1_100;

/// How long after its `hello` a `subscribe` may still be released (R7).
const NONCE_WINDOW_MS: u64 = 50_000;

/// How long the session waits for a `hello` after `on_connect` or
/// `error{nonce_expired}` (R7).
const HELLO_WAIT_MS: u64 = 50_000;

/// `since` is the cursor rounded down to the minute (R6).
const MINUTE_MS: u64 = 60_000;

/// What the session tells the client, by channel or by connection. Its
/// `Debug` shows a channel by the 4-byte prefix of its id (AGENTS 19).
#[derive(PartialEq, Eq)]
pub enum Event {
    /// The channel's backlog arrived and live messages follow (R9).
    Subscribed {
        /// The channel.
        channel: [u8; 16],
    },
    /// The server speaks no version of this app (R2).
    UnsupportedServer {
        /// The connection.
        connection: u64,
    },
    /// The client should close the socket and connect again.
    Reconnect {
        /// The connection.
        connection: u64,
    },
}

impl fmt::Debug for Event {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Event::Subscribed { channel } => write!(f, "Subscribed({})", key_prefix(channel)),
            Event::UnsupportedServer { connection } => {
                write!(f, "UnsupportedServer({connection})")
            }
            Event::Reconnect { connection } => write!(f, "Reconnect({connection})"),
        }
    }
}

/// The `Device`'s open channels, found by `channel_id`.
pub(crate) type Channels = Vec<Channel>;

/// What one call produced.
#[derive(Debug, Default)]
pub(crate) struct Step {
    pub(crate) events: Vec<Event>,
}

/// Where a channel's subscription stands on this connection.
enum Subscription {
    AwaitingOk,
    Subscribed,
}

/// The latest `hello` of the connection.
#[derive(Clone, Copy)]
struct Hello {
    server_nonce: [u8; 32],
    at: u64,
}

/// Where the socket stands.
#[derive(Clone, Copy)]
enum Link {
    /// No socket (R5), or a server that failed R2: nothing is queued and
    /// every frame is ignored until the next `on_connect`.
    Closed,
    /// Waiting for a `hello` since this time (R7).
    AwaitingHello { since: u64 },
    /// A `hello` holds the nonce the `subscribe`s sign (R6).
    Ready(Hello),
}

/// One planned connection's protocol state (ADR 0037).
pub(crate) struct Session {
    connection: u64,
    channel_ids: Vec<[u8; 16]>,
    link: Link,
    /// The channels the `Device` refuses to subscribe again (R5).
    skip: Vec<[u8; 16]>,
    /// The `subscribe`s not yet released, in release order (R6).
    queue: VecDeque<[u8; 16]>,
    /// When the last `subscribe` of the connection was released (R6).
    last_release: Option<u64>,
    subscriptions: BTreeMap<[u8; 16], Subscription>,
    outgoing: Vec<Vec<u8>>,
}

impl Session {
    /// The session of connection `connection`, carrying `channel_ids`, not
    /// connected.
    pub(crate) fn new(connection: u64, channel_ids: Vec<[u8; 16]>) -> Session {
        Session {
            connection,
            channel_ids,
            link: Link::Closed,
            skip: Vec::new(),
            queue: VecDeque::new(),
            last_release: None,
            subscriptions: BTreeMap::new(),
            outgoing: Vec::new(),
        }
    }

    /// A new socket is open (R5): everything of the last connection is
    /// forgotten, and the wait for its `hello` starts at `now` (R7).
    pub(crate) fn on_connect(&mut self, now: u64, skip: &[[u8; 16]]) {
        self.forget_connection(Link::AwaitingHello { since: now });
        self.skip = skip.to_vec();
    }

    /// The socket is closed (R5): nothing is queued until `on_connect`.
    pub(crate) fn on_disconnect(&mut self) {
        self.forget_connection(Link::Closed);
    }

    /// One frame the socket received.
    pub(crate) fn on_frame(&mut self, frame: &[u8], channels: &mut Channels, now: u64) -> Step {
        let mut step = Step::default();
        if matches!(self.link, Link::Closed) {
            return step;
        }
        match Frame::decode(frame) {
            // R1: a frame that breaks its schema is dropped.
            Err(_) => self.reconnect(&mut step),
            Ok(Frame::Hello {
                server_nonce,
                proto_versions,
            }) => self.on_hello(server_nonce, &proto_versions, channels, now, &mut step),
            Ok(Frame::Ok { channel_id }) => self.on_ok(channel_id, &mut step),
            Ok(Frame::Error {
                code, channel_id, ..
            }) => self.on_error(&code, channel_id, now, &mut step),
            Ok(_) => {}
        }
        step
    }

    /// The clock moved: check the wait for a `hello` (R7) and release the
    /// next `subscribe` (R6).
    pub(crate) fn on_tick(&mut self, channels: &mut Channels, now: u64) -> Step {
        let mut step = Step::default();
        match self.link {
            Link::AwaitingHello { since } if expired(since, HELLO_WAIT_MS, now) => {
                self.reconnect(&mut step);
            }
            Link::Ready(hello) => self.release(hello, channels, now, &mut step),
            _ => {}
        }
        step
    }

    /// The frames to write, in order; the queue is left empty (R17).
    pub(crate) fn outgoing(&mut self) -> Vec<Vec<u8>> {
        core::mem::take(&mut self.outgoing)
    }

    /// R2, then R6: a fresh nonce, and a `subscribe` queued for every
    /// channel that has none, the one whose history expires first first.
    fn on_hello(
        &mut self,
        server_nonce: [u8; 32],
        proto_versions: &[u8],
        channels: &Channels,
        now: u64,
        step: &mut Step,
    ) {
        if !is_supported(proto_versions) {
            self.forget_connection(Link::Closed);
            step.events.push(Event::UnsupportedServer {
                connection: self.connection,
            });
            return;
        }
        let hello = Hello {
            server_nonce,
            at: now,
        };
        self.link = Link::Ready(hello);
        let mut pending: Vec<(u64, [u8; 16])> = self
            .channel_ids
            .iter()
            .filter(|id| !self.subscriptions.contains_key(*id) && !self.skip.contains(id))
            .filter_map(|id| find(channels, id).map(|channel| (release_order(channel, now), *id)))
            .collect();
        // Stable: equal expiries keep the `Device`'s order.
        pending.sort_by_key(|(order, _)| *order);
        self.queue = pending.into_iter().map(|(_, id)| id).collect();
        self.release(hello, channels, now, step);
    }

    /// An `ok` of a channel awaiting one marks it subscribed (R9); any other
    /// is ignored.
    fn on_ok(&mut self, channel_id: [u8; 16], step: &mut Step) {
        if let Some(state @ Subscription::AwaitingOk) = self.subscriptions.get_mut(&channel_id) {
            *state = Subscription::Subscribed;
            step.events.push(Event::Subscribed {
                channel: channel_id,
            });
        }
    }

    /// `nonce_expired` (R16): the unreleased `subscribe`s are discarded, the
    /// named channel is again not subscribed, and the wait for a fresh
    /// `hello` starts (R7), unless one is already running.
    fn on_error(&mut self, code: &str, channel_id: Option<[u8; 16]>, now: u64, step: &mut Step) {
        if code != CODE_NONCE_EXPIRED {
            return;
        }
        self.queue.clear();
        if let Link::Ready(_) = self.link {
            self.link = Link::AwaitingHello { since: now };
        }
        match channel_id {
            Some(channel_id) => {
                self.subscriptions.remove(&channel_id);
            }
            None => self.reconnect(step),
        }
    }

    /// Releases the next `subscribe` when the spacing of R6 allows it, or
    /// produces `Reconnect` when its `hello` is too old to sign (R7). A time
    /// recorded later than `now` counts as long past, so that a clock set
    /// back cannot hold the queue.
    fn release(&mut self, hello: Hello, channels: &Channels, now: u64, step: &mut Step) {
        let Some(channel_id) = self.queue.front().copied() else {
            return;
        };
        if expired(hello.at, NONCE_WINDOW_MS, now) {
            self.queue.clear();
            self.reconnect(step);
            return;
        }
        let spaced = self
            .last_release
            .is_none_or(|last| last > now || now.saturating_sub(last) >= SUBSCRIBE_SPACING_MS);
        if !spaced {
            return;
        }
        self.queue.pop_front();
        let Some(channel) = find(channels, &channel_id) else {
            return;
        };
        match subscribe(channel, &hello.server_nonce) {
            Ok(frame) => {
                self.outgoing.push(frame);
                self.subscriptions
                    .insert(channel_id, Subscription::AwaitingOk);
                self.last_release = Some(now);
            }
            // Only libsodium failing can get here.
            Err(_) => self.reconnect(step),
        }
    }

    fn reconnect(&self, step: &mut Step) {
        step.events.push(Event::Reconnect {
            connection: self.connection,
        });
    }

    /// Everything that belongs to one socket (R5).
    fn forget_connection(&mut self, link: Link) {
        self.link = link;
        self.skip.clear();
        self.queue.clear();
        self.last_release = None;
        self.subscriptions.clear();
        self.outgoing.clear();
    }
}

/// Whether more than `limit` ms passed from `from` to `now`; a `from` later
/// than `now`, which only a clock set back gives, counts as long past.
fn expired(from: u64, limit: u64, now: u64) -> bool {
    from > now || now.saturating_sub(from) > limit
}

/// The channel of `channel_id` among the `Device`'s.
fn find<'a>(channels: &'a Channels, channel_id: &[u8; 16]) -> Option<&'a Channel> {
    channels
        .iter()
        .find(|channel| channel.config().channel_id() == *channel_id)
}

/// `max(cursor, synced_at)`, a `synced_at` later than `now` ignored (R8).
fn last_complete(channel: &Channel, now: u64) -> Option<u64> {
    let synced_at = channel.synced_at().filter(|synced_at| *synced_at <= now);
    channel.cursor().max(synced_at)
}

/// When the channel's history starts to expire: `last + ttl_ms`, or
/// `created_at + ttl_ms` for a channel with neither (R6).
fn release_order(channel: &Channel, now: u64) -> u64 {
    let config = channel.config();
    last_complete(channel, now)
        .unwrap_or(config.created_at())
        .saturating_add(ttl_ms(config.ttl_seconds()))
}

/// The `subscribe` of `channel` under `server_nonce` (R6).
fn subscribe(channel: &Channel, server_nonce: &[u8; 32]) -> Result<Vec<u8>, Error> {
    let config = channel.config();
    let (pk_ch, sk_ch) = config.channel_keypair()?;
    let message = auth_message(
        server_nonce,
        config.id(),
        config.ttl_seconds(),
        config.host(),
    );
    let sig = crypto::sign_detached(&sk_ch, &message)?;
    // Always present, 0 with no cursor (the server reads it as everything),
    // so that every `subscribe` has one size and a network observer cannot
    // tell a new channel from an old one (R6).
    let since = channel
        .cursor()
        .map_or(0, |cursor| cursor.saturating_sub(cursor % MINUTE_MS));
    Frame::Subscribe {
        pk_ch: pk_ch.0,
        ttl_seconds: config.ttl_seconds(),
        sig: sig.0,
        since: Some(since),
    }
    .encode()
}
