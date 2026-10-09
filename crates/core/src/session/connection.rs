//! The client side of one connection (spec 028-session-sans-io R5–R18): a
//! state machine with no I/O, which the `Device` of spec 027-core-api hands
//! every frame its socket received and every tick, and which returns the
//! frames to write and the events to show.
//!
//! This slice holds the connection and the subscription (R1, R2 and R5–R7)
//! and marks a channel subscribed at its `ok`; truncation, `synced`,
//! traffic, outcomes, the publish rate and the error codes other than
//! `nonce_expired` are the later slices of spec 028.

use std::collections::{BTreeMap, VecDeque};

use super::channel::{Channel, ClientRef, Received};
use super::frames::{Frame, is_supported};
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
pub(crate) const SUBSCRIBE_SPACING_MS: u64 = 1_100;

/// How long after its `hello` a `subscribe` may still be released (R7).
pub(crate) const NONCE_WINDOW_MS: u64 = 50_000;

/// How long the session waits for a `hello` after `on_connect` or
/// `error{nonce_expired}` (R7).
pub(crate) const HELLO_WAIT_MS: u64 = 50_000;

/// `since` is the cursor rounded down to the minute (R6).
const MINUTE_MS: u64 = 60_000;

/// The `code` of `error` that asks for a fresh `hello` (R16).
const NONCE_EXPIRED: &str = "nonce_expired";

/// What the session tells the client, by channel or by connection.
#[derive(Debug, PartialEq, Eq)]
pub enum Event {
    /// The channel's backlog arrived and live messages follow (R9).
    Subscribed {
        /// The channel.
        channel: [u8; 16],
    },
    /// Messages before `before` may have expired unseen (R8).
    HistoryTruncated {
        /// The channel.
        channel: [u8; 16],
        /// The local time before which history may be missing.
        before: u64,
    },
    /// A message the channel consumed (R10).
    Message {
        /// The channel.
        channel: [u8; 16],
        /// The message.
        received: Received,
    },
    /// The server stored one of the user's messages (R12).
    Delivered {
        /// The channel.
        channel: [u8; 16],
        /// The `outbox` entry.
        client_ref: ClientRef,
        /// The server's identifier.
        server_id: [u8; 16],
        /// When the server stored it, clamped as the outcome carries it.
        received_at: u64,
        /// When it leaves the server.
        expires_at: u64,
    },
    /// One of the user's messages will not be delivered (R12).
    NotDelivered {
        /// The channel.
        channel: [u8; 16],
        /// The `outbox` entry.
        client_ref: ClientRef,
        /// When the user sent it, so that the client can report a row it
        /// no longer lists.
        sent_at: u64,
    },
    /// The channel's status or peers changed (R13).
    StatusChanged {
        /// The channel.
        channel: [u8; 16],
    },
    /// The channel stopped reading for lack of disk (R10).
    StorageFailed {
        /// The channel.
        channel: [u8; 16],
    },
    /// The server refused the channel's subscription (R16).
    SubscribeRefused {
        /// The channel.
        channel: [u8; 16],
    },
    /// The channel is over its quota on the server (R16).
    ChannelFull {
        /// The channel.
        channel: [u8; 16],
    },
    /// The server's disk is full (R16).
    ServerFull {
        /// The connection.
        connection: u64,
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

/// The `Device`'s open channels, found by `channel_id`.
pub(crate) type Channels = Vec<Channel>;

/// What one call produced. It never fails as a whole: a store failure in
/// one channel goes to `failed` and the session carries on with the others.
#[derive(Debug, Default)]
pub(crate) struct Step {
    pub(crate) events: Vec<Event>,
    pub(crate) failed: Vec<([u8; 16], StoreError)>,
}

/// Where a channel's subscription stands on this connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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

/// One planned connection's protocol state (ADR 0037).
pub(crate) struct Session {
    connection: u64,
    channel_ids: Vec<[u8; 16]>,
    connected: bool,
    /// The server failed R2: nothing is sent until the next `on_connect`.
    unsupported: bool,
    /// `Reconnect` was produced on this connection: once is enough.
    reconnect_sent: bool,
    /// The channels the `Device` refuses to subscribe again (R5).
    skip: Vec<[u8; 16]>,
    hello: Option<Hello>,
    /// When the wait for a `hello` started (R7).
    hello_wait_from: Option<u64>,
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
            connected: false,
            unsupported: false,
            reconnect_sent: false,
            skip: Vec::new(),
            hello: None,
            hello_wait_from: None,
            queue: VecDeque::new(),
            last_release: None,
            subscriptions: BTreeMap::new(),
            outgoing: Vec::new(),
        }
    }

    /// A new socket is open (R5): everything of the last connection is
    /// forgotten, and the wait for its `hello` starts at `now` (R7).
    pub(crate) fn on_connect(&mut self, now: u64, skip: &[[u8; 16]]) {
        self.forget_connection();
        self.connected = true;
        self.skip = skip.to_vec();
        self.hello_wait_from = Some(now);
    }

    /// The socket is closed (R5): nothing is queued until `on_connect`.
    pub(crate) fn on_disconnect(&mut self) {
        self.forget_connection();
        self.connected = false;
    }

    /// One frame the socket received.
    pub(crate) fn on_frame(&mut self, frame: &[u8], channels: &mut Channels, now: u64) -> Step {
        let mut step = Step::default();
        if !self.connected || self.unsupported {
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

    /// The clock moved: release the next `subscribe` and check the waits
    /// of R7.
    pub(crate) fn on_tick(&mut self, channels: &mut Channels, now: u64) -> Step {
        let mut step = Step::default();
        if !self.connected || self.unsupported {
            return step;
        }
        let waited_too_long = self
            .hello_wait_from
            .is_some_and(|from| now > from.saturating_add(HELLO_WAIT_MS));
        if waited_too_long {
            self.reconnect(&mut step);
        }
        self.release(channels, now, &mut step);
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
            self.unsupported = true;
            self.queue.clear();
            self.outgoing.clear();
            step.events.push(Event::UnsupportedServer {
                connection: self.connection,
            });
            return;
        }
        self.hello = Some(Hello {
            server_nonce,
            at: now,
        });
        self.hello_wait_from = None;
        let mut pending: Vec<(u64, [u8; 16])> = self
            .channel_ids
            .iter()
            .filter(|id| !self.subscriptions.contains_key(*id) && !self.skip.contains(id))
            .filter_map(|id| find(channels, id).map(|channel| (release_order(channel, now), *id)))
            .collect();
        // Stable: equal expiries keep the `Device`'s order.
        pending.sort_by_key(|(order, _)| *order);
        self.queue = pending.into_iter().map(|(_, id)| id).collect();
        self.release(channels, now, step);
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
    /// `hello` starts (R7).
    fn on_error(&mut self, code: &str, channel_id: Option<[u8; 16]>, now: u64, step: &mut Step) {
        if code != NONCE_EXPIRED {
            return;
        }
        let Some(channel_id) = channel_id else {
            self.reconnect(step);
            return;
        };
        self.queue.clear();
        if self.subscriptions.get(&channel_id) == Some(&Subscription::AwaitingOk) {
            self.subscriptions.remove(&channel_id);
        }
        self.hello = None;
        self.hello_wait_from = Some(now);
    }

    /// Releases the next `subscribe` when the spacing of R6 allows it, or
    /// produces `Reconnect` when its `hello` is too old to sign (R7).
    fn release(&mut self, channels: &Channels, now: u64, step: &mut Step) {
        let (Some(hello), Some(channel_id)) = (self.hello, self.queue.front().copied()) else {
            return;
        };
        if now > hello.at.saturating_add(NONCE_WINDOW_MS) {
            self.queue.clear();
            self.reconnect(step);
            return;
        }
        let spaced = self
            .last_release
            .is_none_or(|last| now >= last.saturating_add(SUBSCRIBE_SPACING_MS));
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

    /// `Event::Reconnect`, once per connection.
    fn reconnect(&mut self, step: &mut Step) {
        if !self.reconnect_sent {
            self.reconnect_sent = true;
            step.events.push(Event::Reconnect {
                connection: self.connection,
            });
        }
    }

    /// Everything that belongs to one socket (R5).
    fn forget_connection(&mut self) {
        self.unsupported = false;
        self.reconnect_sent = false;
        self.skip.clear();
        self.hello = None;
        self.hello_wait_from = None;
        self.queue.clear();
        self.last_release = None;
        self.subscriptions.clear();
        self.outgoing.clear();
    }
}

/// The channel of `channel_id` among the `Device`'s.
fn find<'a>(channels: &'a Channels, channel_id: &[u8; 16]) -> Option<&'a Channel> {
    channels
        .iter()
        .find(|channel| channel.config().channel_id() == *channel_id)
}

/// `max(cursor, synced_at)`, a `synced_at` later than `now` ignored (R8).
pub(crate) fn last_complete(channel: &Channel, now: u64) -> Option<u64> {
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
    let since = channel
        .cursor()
        .map(|cursor| cursor.saturating_sub(cursor % MINUTE_MS));
    Frame::Subscribe {
        pk_ch: pk_ch.0,
        ttl_seconds: config.ttl_seconds(),
        sig: sig.0,
        since,
    }
    .encode()
}
