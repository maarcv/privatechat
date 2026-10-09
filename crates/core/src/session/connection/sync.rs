//! The truncation and the `ok` of spec 028-session-sans-io (R8, R9): the
//! history before a `subscribe` judged by the local clock alone, what an
//! `ok` and the ticks after it call, and the two limits that catch a
//! silent server and a suspended process.

use super::{Channels, Event, Session, Step, Subscription, expired, find_mut, last_complete};
use crate::Error;
use crate::proto::envelope::ttl_ms;
use crate::session::channel::{Channel, ClientRef, OutboxStep};
use crate::session::frames::Frame;

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

/// R8's decision for a channel, taken when its `subscribe` is first queued
/// on the connection and kept until the connection ends.
#[derive(Clone, Copy)]
pub(super) enum Truncation {
    Found,
    /// None found, with the `last` it was judged by, which the `ok` judges
    /// again (R9).
    NotFound {
        last: Option<u64>,
    },
}

impl Session {
    /// R9 on a tick: 60 000 ms with no frame while a channel awaits its
    /// `ok` asks for a new connection; the subscribed channels sync, unless
    /// a gap between calls stopped it. A last frame later than `now`, which
    /// only a clock set back gives, counts as past the limit.
    pub(super) fn keep_synced(&mut self, channels: &mut Channels, now: u64, step: &mut Step) {
        let awaiting = self
            .subscriptions
            .values()
            .any(|state| matches!(state, Subscription::AwaitingOk));
        if awaiting && expired(self.last_frame, SILENCE_MS, now) {
            self.reconnect(step);
        }
        if !self.sync_stopped {
            for (channel_id, state) in &self.subscriptions {
                if let (Subscription::Subscribed, Some(channel)) =
                    (state, find_mut(channels, channel_id))
                {
                    sync(channel, now, step);
                }
            }
        }
    }

    /// R8, once per channel and connection: the history before a
    /// `subscribe` is truncated when the device was away longer than a TTL,
    /// judged by the local clock alone, before any push of it is decrypted.
    pub(super) fn decide_truncation(&mut self, channel: &mut Channel, now: u64, step: &mut Step) {
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
    pub(super) fn on_ok(
        &mut self,
        channel_id: [u8; 16],
        channels: &mut Channels,
        now: u64,
        step: &mut Step,
    ) {
        let Some(state @ Subscription::AwaitingOk) = self.subscriptions.get_mut(&channel_id) else {
            return;
        };
        *state = Subscription::Subscribed;
        let Some(channel) = find_mut(channels, &channel_id) else {
            return;
        };
        let (truncated, syncs) = match self.truncations.get(&channel_id) {
            // Found at the `subscribe`: what expired while it waited is
            // truncated too, and the backlog after it is whole.
            Some(Truncation::Found) => (true, true),
            Some(Truncation::NotFound { last }) => {
                let late = is_truncated(channel, *last, now);
                (late, !late)
            }
            // Every queued channel is decided (R8); a missing decision is
            // taken now rather than skipped.
            None => {
                let late = is_truncated(channel, last_complete(channel, now), now);
                (late, !late)
            }
        };
        if truncated {
            truncate(channel, now, step);
        }
        if syncs && !self.sync_stopped {
            sync(channel, now, step);
        }
        step.events.push(Event::Subscribed {
            channel: channel_id,
        });
        self.publish_outbox(channel, now, step);
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
    pub(super) fn check_gap(&mut self, now: u64, step: &mut Step) {
        let gap = expired(self.last_call, CALL_GAP_MS, now);
        self.last_call = now;
        if gap && !self.subscriptions.is_empty() && !self.sync_stopped {
            self.sync_stopped = true;
            self.reconnect(step);
        }
    }
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
