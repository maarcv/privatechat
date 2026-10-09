//! The client side of one connection (spec 028-session-sans-io R5–R18): a
//! state machine with no I/O, which the `Device` of spec 027-core-api hands
//! every frame its socket received and every tick, and which returns the
//! frames to write and the events to show.
//!
//! These slices hold the connection and the subscription (R1, R2 and
//! R5–R7), the truncation (R8) and the `ok` with what follows it (R9).
//! Later slices of spec 028 add traffic, its stalls and the freeze after a
//! store failure (R10), outcomes and the `outbox` on send and tick
//! (R11–R14), the publish rate (R15), the error codes other than
//! `nonce_expired` (R16), and, with `rate_limited`, the one clause of R7
//! only it can reach: a `subscribe` queued again after it is released
//! however old its nonce.

use core::fmt;
use std::collections::{BTreeMap, VecDeque};

use super::channel::{Channel, ClientRef, OutboxStep, key_prefix};
use super::frames::{CODE_NONCE_EXPIRED, Frame, is_supported};
use crate::Error;
use crate::crypto;
use crate::proto::auth::auth_message;
use crate::proto::envelope::ttl_ms;
use crate::storage::StoreError;

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

/// How long a channel may await its `ok` with no frame at all on the
/// connection (R9).
const SILENCE_MS: u64 = 60_000;

/// The longest gap between two calls of a connection with a channel
/// subscribed or awaiting `ok`; a longer one is a suspended process or a
/// dead socket (R9).
const CALL_GAP_MS: u64 = 5_000;

/// The margin on the creator's clock when a channel never synced is judged
/// truncated by its `created_at` (R8).
const CREATED_AT_MARGIN_MS: u64 = 360_000;

/// What the session tells the client, by channel or by connection. Its
/// `Debug` shows a channel by the 4-byte prefix of its id (AGENTS 19).
#[derive(PartialEq, Eq)]
pub enum Event {
    /// The channel's backlog arrived and live messages follow (R9).
    Subscribed {
        /// The channel.
        channel: [u8; 16],
    },
    /// The channel's history before `before` may be missing: the device
    /// was away longer than a TTL (R8, R9).
    HistoryTruncated {
        /// The channel.
        channel: [u8; 16],
        /// `now − ttl_ms` when the session found it.
        before: u64,
    },
    /// An entry left the `outbox` unsent: stale, overtaken or refused
    /// (R9, R14).
    NotDelivered {
        /// The channel.
        channel: [u8; 16],
        /// The entry.
        client_ref: ClientRef,
        /// When it was sealed, so that the client can report a row it no
        /// longer lists.
        sent_at: u64,
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
            Event::HistoryTruncated { channel, before } => {
                write!(f, "HistoryTruncated({}, {before})", key_prefix(channel))
            }
            Event::NotDelivered {
                channel, sent_at, ..
            } => write!(f, "NotDelivered({}, {sent_at})", key_prefix(channel)),
            Event::UnsupportedServer { connection } => {
                write!(f, "UnsupportedServer({connection})")
            }
            Event::Reconnect { connection } => write!(f, "Reconnect({connection})"),
        }
    }
}

/// The `Device`'s open channels, found by `channel_id`.
pub(crate) type Channels = Vec<Channel>;

/// What one call produced. A store failure in one channel goes to
/// `failed`, for the `Device` (spec 027-core-api R14), and the session
/// carries on with the others.
#[derive(Debug, Default)]
pub(crate) struct Step {
    pub(crate) events: Vec<Event>,
    pub(crate) failed: Vec<([u8; 16], StoreError)>,
}

/// Where a channel's subscription stands on this connection.
enum Subscription {
    AwaitingOk,
    Subscribed,
}

/// R8's decision for a channel, taken when its `subscribe` is first queued
/// on the connection and kept until the connection ends.
#[derive(Clone, Copy)]
enum Truncation {
    Found,
    /// None found, with the `last` it was judged by, which the `ok` judges
    /// again (R9).
    NotFound {
        last: Option<u64>,
    },
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
    truncations: BTreeMap<[u8; 16], Truncation>,
    /// When the latest `on_connect`, `on_tick` or `on_frame` came (R9).
    last_call: u64,
    /// When the latest frame, or else `on_connect`, came (R9).
    last_frame: u64,
    /// R9's stop after a gap between calls: no `synced` until the next
    /// connection.
    sync_stopped: bool,
    /// The entries published on this connection and not yet answered, with
    /// their channel.
    in_flight: BTreeMap<ClientRef, [u8; 16]>,
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
            truncations: BTreeMap::new(),
            last_call: 0,
            last_frame: 0,
            sync_stopped: false,
            in_flight: BTreeMap::new(),
            outgoing: Vec::new(),
        }
    }

    /// A new socket is open (R5): everything of the last connection is
    /// forgotten, and the wait for its `hello` starts at `now` (R7).
    pub(crate) fn on_connect(&mut self, now: u64, skip: &[[u8; 16]]) {
        self.forget_connection(Link::AwaitingHello { since: now });
        self.skip = skip.to_vec();
        self.last_call = now;
        self.last_frame = now;
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
        self.check_gap(now, &mut step);
        self.last_frame = now;
        match Frame::decode(frame) {
            // R1: a frame that breaks its schema is dropped.
            Err(_) => self.reconnect(&mut step),
            Ok(Frame::Hello {
                server_nonce,
                proto_versions,
            }) => self.on_hello(server_nonce, &proto_versions, channels, now, &mut step),
            Ok(Frame::Ok { channel_id }) => self.on_ok(channel_id, channels, now, &mut step),
            Ok(Frame::Error {
                code, channel_id, ..
            }) => self.on_error(&code, channel_id, now, &mut step),
            Ok(_) => {}
        }
        step
    }

    /// The clock moved: check the gap since the last call and the silence
    /// before an `ok`, sync the subscribed channels (R9), check the wait
    /// for a `hello` (R7) and release the next `subscribe` (R6).
    pub(crate) fn on_tick(&mut self, channels: &mut Channels, now: u64) -> Step {
        let mut step = Step::default();
        self.check_gap(now, &mut step);
        let awaiting = self
            .subscriptions
            .values()
            .any(|state| matches!(state, Subscription::AwaitingOk));
        if awaiting && expired(self.last_frame, SILENCE_MS, now) {
            self.reconnect(&mut step);
        }
        if !self.sync_stopped {
            for (channel_id, state) in &self.subscriptions {
                if let (Subscription::Subscribed, Some(channel)) =
                    (state, find_mut(channels, channel_id))
                {
                    sync(channel, now, &mut step);
                }
            }
        }
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
        channels: &mut Channels,
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
        for channel_id in self.queue.clone() {
            if let Some(channel) = find_mut(channels, &channel_id) {
                self.decide_truncation(channel, now, step);
            }
        }
        self.release(hello, channels, now, step);
    }

    /// R8, once per channel and connection: the history before a
    /// `subscribe` is truncated when the device was away longer than a TTL,
    /// judged by the local clock alone, before any push of it is decrypted.
    fn decide_truncation(&mut self, channel: &mut Channel, now: u64, step: &mut Step) {
        let channel_id = channel.config().channel_id();
        if self.truncations.contains_key(&channel_id) {
            return;
        }
        let last = last_complete(channel, now);
        let decision = if is_truncated(channel, last, now) {
            truncate(channel, now, step);
            Truncation::Found
        } else {
            Truncation::NotFound { last }
        };
        self.truncations.insert(channel_id, decision);
    }

    /// An `ok` of a channel awaiting one marks it subscribed (R9); any other
    /// is ignored. Unless R8 found it already, the truncation is judged
    /// again by the `last` captured at the `subscribe`, never the cursor
    /// the backlog moved, since a stretch of it may have expired while it
    /// waited; a truncation found here calls no `synced`.
    fn on_ok(&mut self, channel_id: [u8; 16], channels: &mut Channels, now: u64, step: &mut Step) {
        let Some(state @ Subscription::AwaitingOk) = self.subscriptions.get_mut(&channel_id) else {
            return;
        };
        *state = Subscription::Subscribed;
        if let Some(channel) = find_mut(channels, &channel_id) {
            let late = match self.truncations.get(&channel_id) {
                Some(Truncation::NotFound { last }) => is_truncated(channel, *last, now),
                _ => false,
            };
            if late {
                truncate(channel, now, step);
                self.truncations.insert(channel_id, Truncation::Found);
            } else if !self.sync_stopped {
                sync(channel, now, step);
            }
        }
        step.events.push(Event::Subscribed {
            channel: channel_id,
        });
        if let Some(channel) = find_mut(channels, &channel_id) {
            self.publish_outbox(channel, now, step);
        }
    }

    /// Queues a `publish` for each `outbox` entry not in flight and reports
    /// the entries that left it unsent (R9).
    fn publish_outbox(&mut self, channel: &mut Channel, now: u64, step: &mut Step) {
        let channel_id = channel.config().channel_id();
        let in_flight: Vec<ClientRef> = self
            .in_flight
            .iter()
            .filter(|(_, of)| **of == channel_id)
            .map(|(client_ref, _)| *client_ref)
            .collect();
        let OutboxStep {
            publish,
            not_delivered,
        } = match channel.outbox(now, &in_flight, false) {
            Ok(outbox) => outbox,
            Err(Error::Store(error)) => {
                step.failed.push((channel_id, error));
                return;
            }
            // Only libsodium failing can get here.
            Err(_) => return self.reconnect(step),
        };
        for (client_ref, sent_at) in not_delivered {
            step.events.push(Event::NotDelivered {
                channel: channel_id,
                client_ref,
                sent_at,
            });
        }
        for (client_ref, blob) in publish {
            let frame = Frame::Publish {
                channel_id,
                client_ref: client_ref.bytes,
                blob,
            };
            match frame.encode() {
                Ok(frame) => {
                    self.outgoing.push(frame);
                    self.in_flight.insert(client_ref, channel_id);
                }
                // A blob the channel sealed always fits a frame.
                Err(_) => return self.reconnect(step),
            }
        }
    }

    /// R9: a call more than 5 000 ms after the previous one, on a
    /// connection with a channel subscribed or awaiting `ok`, stops every
    /// `synced` of the connection and asks for a new one, since the device
    /// slept or the socket died and pushes may have been missed meanwhile.
    /// A previous call later than `now`, which only a clock set back gives,
    /// counts as past the 5 000 ms: how long the device slept is unknown.
    fn check_gap(&mut self, now: u64, step: &mut Step) {
        let gap = expired(self.last_call, CALL_GAP_MS, now);
        self.last_call = now;
        if gap && !self.subscriptions.is_empty() && !self.sync_stopped {
            self.sync_stopped = true;
            self.reconnect(step);
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

    /// Asks for a new connection, once a step whatever the causes.
    fn reconnect(&self, step: &mut Step) {
        let reconnect = Event::Reconnect {
            connection: self.connection,
        };
        if !step.events.contains(&reconnect) {
            step.events.push(reconnect);
        }
    }

    /// Everything that belongs to one socket (R5).
    fn forget_connection(&mut self, link: Link) {
        self.link = link;
        self.skip.clear();
        self.queue.clear();
        self.last_release = None;
        self.subscriptions.clear();
        self.truncations.clear();
        self.sync_stopped = false;
        self.in_flight.clear();
        self.outgoing.clear();
    }
}

/// Whether more than `limit` ms passed from `from` to `now`; a `from` later
/// than `now`, which only a clock set back gives, counts as long past.
fn expired(from: u64, limit: u64, now: u64) -> bool {
    from > now || now.saturating_sub(from) > limit
}

/// The channel of `channel_id` among the `Device`'s, to change.
fn find_mut<'a>(channels: &'a mut Channels, channel_id: &[u8; 16]) -> Option<&'a mut Channel> {
    channels
        .iter_mut()
        .find(|channel| channel.config().channel_id() == *channel_id)
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

/// R8's rule: away longer than a TTL since `last`, or, with no `last`,
/// since `created_at` with a margin for the creator's clock.
fn is_truncated(channel: &Channel, last: Option<u64>, now: u64) -> bool {
    let config = channel.config();
    let ttl = ttl_ms(config.ttl_seconds());
    let since = last.unwrap_or_else(|| config.created_at().saturating_add(CREATED_AT_MARGIN_MS));
    since.saturating_add(ttl) < now
}

/// The channel's history is complete up to `now` (R9); a store failure
/// goes to `failed`, the value waiting in memory for the next commit.
fn sync(channel: &mut Channel, now: u64, step: &mut Step) {
    if let Err(Error::Store(error)) = channel.synced(now) {
        step.failed.push((channel.config().channel_id(), error));
    }
}

/// Records the truncation in the channel and tells the client at once
/// (R8).
fn truncate(channel: &mut Channel, now: u64, step: &mut Step) {
    channel.history_truncated(now);
    let ttl = ttl_ms(channel.config().ttl_seconds());
    step.events.push(Event::HistoryTruncated {
        channel: channel.config().channel_id(),
        before: now.saturating_sub(ttl),
    });
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
