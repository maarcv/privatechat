//! The publish rate and the `error`s of spec 028-session-sans-io (R15,
//! R16): at most 30 `publish`es a minute, the pauses a quota, a rate limit
//! or a full server asks for, a `subscribe` refused or ended, and a blob
//! refused.

use super::outcomes::Hold;
use super::{
    Channels, Event, Link, MINUTE_MS, Queued, Session, Step, Subscription, find, find_mut,
    release_order,
};
use crate::Error;
use crate::session::channel::ClientRef;
use crate::session::frames::{
    CODE_BAD_AUTH, CODE_BAD_BLOB, CODE_BAD_TTL, CODE_CHANNEL_QUOTA, CODE_NONCE_EXPIRED,
    CODE_NOT_SUBSCRIBED, CODE_RATE_LIMITED, CODE_SERVER_FULL, CODE_UNSUPPORTED_VERSION,
};

/// The most `publish` frames one connection queues in any minute (R15).
const MAX_PUBLISHES: usize = 30;

/// How long a quota, a rate limit or a full server stops publishing (R16).
const PAUSE_MS: u64 = 60_000;

impl Session {
    /// An `error` (R16): the named entry leaves the in-flight set, then the
    /// session acts by its `code`; an unknown code does nothing.
    pub(super) fn on_error(
        &mut self,
        code: &str,
        channel_id: Option<[u8; 16]>,
        client_ref: Option<ClientRef>,
        channels: &mut Channels,
        now: u64,
        step: &mut Step,
    ) {
        let flight = client_ref.and_then(|client_ref| self.in_flight.remove(&client_ref));
        match code {
            CODE_NONCE_EXPIRED => self.nonce_expired(channel_id, now, step),
            CODE_BAD_AUTH | CODE_BAD_TTL => self.refuse(channel_id, step),
            CODE_CHANNEL_QUOTA => {
                let paused = match (flight, channel_id) {
                    (Some(flight), _) => vec![flight.channel],
                    (None, Some(channel_id)) => vec![channel_id],
                    (None, None) => self.channel_ids.clone(),
                };
                for channel_id in paused {
                    if self.channel_ids.contains(&channel_id) {
                        self.paused.insert(channel_id, now);
                        step.events.push(Event::ChannelFull {
                            channel: channel_id,
                        });
                    }
                }
            }
            CODE_RATE_LIMITED => match (channel_id, client_ref) {
                (Some(channel_id), None) => {
                    self.subscribe_again(channel_id, channels, now, step);
                }
                _ => self.paused_all = Some(now),
            },
            CODE_SERVER_FULL => {
                self.paused_all = Some(now);
                step.events.push(Event::ServerFull {
                    connection: self.connection,
                });
            }
            CODE_BAD_BLOB => match (client_ref, flight) {
                (Some(client_ref), Some(flight)) => {
                    self.bad_blob(client_ref, flight.channel, channels, now, step);
                }
                (Some(_), None) => {}
                (None, _) => self.reconnect(step),
            },
            CODE_NOT_SUBSCRIBED => self.reconnect(step),
            CODE_UNSUPPORTED_VERSION => self.unsupported(step),
            _ => {}
        }
    }

    /// `nonce_expired`: the unreleased `subscribe`s are discarded, the
    /// named channel is again not subscribed, and the wait for a fresh
    /// `hello` starts (R7), unless one is already running. One naming a
    /// subscribed channel, which no `subscribe` awaits, is a `Reconnect`:
    /// subscribing it again would judge its truncation by a `last` older
    /// than the ticks' `synced`, and hide a deletion (R8, R9).
    fn nonce_expired(&mut self, channel_id: Option<[u8; 16]>, now: u64, step: &mut Step) {
        let named = channel_id.and_then(|channel_id| self.subscriptions.get(&channel_id));
        if let Some(Subscription::Subscribed) = named {
            return self.reconnect(step);
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

    /// `bad_auth` or `bad_ttl`: the named channel is not subscribed again
    /// on this connection.
    fn refuse(&mut self, channel_id: Option<[u8; 16]>, step: &mut Step) {
        let Some(channel_id) = channel_id else {
            return self.reconnect(step);
        };
        if !self.channel_ids.contains(&channel_id) {
            return;
        }
        self.subscriptions.remove(&channel_id);
        self.queue.retain(|queued| queued.channel_id != channel_id);
        self.refused.insert(channel_id);
        step.events.push(Event::SubscribeRefused {
            channel: channel_id,
        });
    }

    /// A `rate_limited` naming a channel and no entry: a `subscribe`
    /// refused, or a subscription the server ended before its `ok`, is
    /// queued again in R6's order, to be released however old its nonce
    /// (R7); the channel's other traffic goes on. A subscribed channel,
    /// which a server never ends, asks for a new connection.
    fn subscribe_again(
        &mut self,
        channel_id: [u8; 16],
        channels: &Channels,
        now: u64,
        step: &mut Step,
    ) {
        match self.subscriptions.get(&channel_id) {
            Some(Subscription::AwaitingOk { .. }) => {
                self.subscriptions.remove(&channel_id);
                let order =
                    |id: &[u8; 16]| find(channels, id).map(|channel| release_order(channel, now));
                let own = order(&channel_id);
                // Awaiting its `ok`, the channel is not queued already.
                let at = self
                    .queue
                    .iter()
                    .position(|queued| order(&queued.channel_id) > own)
                    .unwrap_or(self.queue.len());
                let queued = Queued {
                    channel_id,
                    again: true,
                };
                self.queue.insert(at, queued);
            }
            Some(Subscription::Subscribed) => self.reconnect(step),
            None => {}
        }
    }

    /// A `bad_blob` of an entry published on this connection: an ordinary
    /// entry leaves the `outbox` unsent; the pending `key_retired` is held
    /// within the minute of `now`, as a late `ack` holds it (R12); a store
    /// error freezes the channel, as a failed `acked` does (R10).
    fn bad_blob(
        &mut self,
        client_ref: ClientRef,
        channel_id: [u8; 16],
        channels: &mut Channels,
        now: u64,
        step: &mut Step,
    ) {
        if self.is_frozen(&channel_id) {
            return;
        }
        let Some(channel) = find_mut(channels, &channel_id) else {
            return;
        };
        self.watch(channel);
        match channel.abandon(client_ref) {
            Ok(Some(sent_at)) => step.events.push(Event::NotDelivered {
                channel: channel_id,
                client_ref,
                sent_at,
            }),
            Ok(None) => {
                let hold = Hold {
                    channel: channel_id,
                    minute: now / MINUTE_MS,
                };
                self.held.insert(client_ref, hold);
            }
            Err(Error::Store(error)) => self.freeze(channel_id, error, step),
            // `abandon` fails only by its commit.
            Err(_) => {}
        }
    }

    /// Whether the channel publishes nothing at `now`: a `channel_quota`
    /// of it, or a `rate_limited` or `server_full` of the connection, less
    /// than a minute ago. A pause recorded later than `now`, which only a
    /// clock set back gives, counts as past.
    pub(super) fn is_paused(&self, channel_id: &[u8; 16], now: u64) -> bool {
        let within = |since: u64| now.checked_sub(since).is_some_and(|age| age < PAUSE_MS);
        self.paused_all.is_some_and(within)
            || self.paused.get(channel_id).copied().is_some_and(within)
    }

    /// How many more `publish` frames R15 lets the connection queue at
    /// `now`. A publish recorded later than `now`, which only a clock set
    /// back gives, counts as past the window, so that such a clock never
    /// holds the queue.
    pub(super) fn publishes_left(&mut self, now: u64) -> usize {
        self.published
            .retain(|at| now.checked_sub(*at).is_some_and(|age| age < MINUTE_MS));
        MAX_PUBLISHES.saturating_sub(self.published.len())
    }
}
