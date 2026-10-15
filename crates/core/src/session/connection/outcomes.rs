//! What became of the entries this device published and what the client
//! re-reads, in spec 028-session-sans-io (R11–R13): an `ack` routed to its
//! channel, the clock samples, the outcomes a channel queued, the hold on
//! a late `key_retired` copy or an entry an `error` names (R16), and
//! `Event::StatusChanged`.

use super::{Channels, Event, MINUTE_MS, Session, Step, find_mut};
use crate::Error;
use crate::proto::envelope::ttl_ms;
use crate::session::channel::{AckOutcome, Channel, ClientRef, Outcome};

/// How soon after its publish an `ack` is a live clock sample (R11).
const LIVE_ACK_MS: u64 = 5_000;

/// One entry published on this connection and not yet answered.
pub(super) struct Flight {
    pub(super) channel: [u8; 16],
    pub(super) published_at: u64,
}

/// An entry not published again on this connection while the minute it
/// was published in lasts: a `key_retired` copy whose `ack` came late
/// (R12), which `outbox` re-seals as another copy the minute after (spec
/// 025-identity-regen R4), or an entry an `error` named (R16).
pub(super) struct Hold {
    pub(super) channel: [u8; 16],
    pub(super) minute: u64,
}

impl Session {
    /// An `ack` of an entry published on this connection (R11, R12): the
    /// entry leaves the in-flight set, the channel takes a clock sample,
    /// and `acked` says what to tell the client. An unknown `client_ref`
    /// is ignored; the `ack` of a frozen channel is dropped, its entry
    /// published again on the next connection (R10).
    pub(super) fn on_ack(
        &mut self,
        client_ref: ClientRef,
        arrival: ([u8; 16], u64),
        channels: &mut Channels,
        now: u64,
        step: &mut Step,
    ) {
        let Some(flight) = self.in_flight.remove(&client_ref) else {
            return;
        };
        if self.is_frozen(&flight.channel) {
            return;
        }
        let Some(channel) = find_mut(channels, &flight.channel) else {
            return;
        };
        let (server_id, received_at) = arrival;
        // A suspension stops every live sample of the connection: an `ack`
        // read late says nothing of the clocks (R9, R11).
        let live = !self.sync_stopped
            && flight.published_at <= now
            && now.saturating_sub(flight.published_at) <= LIVE_ACK_MS;
        self.sample(channel, received_at, now, live);
        match channel.acked(client_ref, server_id, received_at, now) {
            Ok(outcome) => self.report(channel, outcome, step),
            Err(Error::Store(error)) => self.freeze(flight.channel, error, step),
            // `acked` fails only by its commit.
            Err(_) => {}
        }
    }

    /// The channel's clock sample of R11, with its status watched first
    /// (R13).
    pub(super) fn sample(&mut self, channel: &mut Channel, received_at: u64, now: u64, live: bool) {
        self.watch(channel);
        channel.clock_sample(received_at, now, live);
    }

    /// Notes the channel's status before a call that may change it, once a
    /// step (R13).
    pub(super) fn watch(&mut self, channel: &Channel) {
        let channel_id = channel.config().channel_id();
        if !self.watched.iter().any(|(id, _)| *id == channel_id) {
            self.watched.push((channel_id, channel.status()));
        }
    }

    /// At the end of a step, for every channel it called: the outcomes the
    /// channel queued meanwhile (R11), then `Event::StatusChanged` when its
    /// status differs from before or its peers changed (R13).
    pub(super) fn finish(&mut self, channels: &mut Channels, step: &mut Step) {
        for (channel_id, before) in core::mem::take(&mut self.watched) {
            let Some(channel) = find_mut(channels, &channel_id) else {
                continue;
            };
            for outcome in channel.take_outcomes() {
                self.in_flight.remove(&outcome.client_ref);
                self.report(channel, outcome, step);
            }
            let peers_changed = channel.take_peers_changed();
            if peers_changed || channel.status() != before {
                step.events.push(Event::StatusChanged {
                    channel: channel_id,
                });
            }
        }
    }

    /// The event of an entry's outcome (R12): a retirement delivered shows
    /// in the status alone, and a late `ack` of the current `key_retired`
    /// copy holds it, so that an `ack` always late cannot turn into a
    /// publish every tick.
    fn report(&mut self, channel: &Channel, outcome: Outcome, step: &mut Step) {
        let channel_id = channel.config().channel_id();
        let client_ref = outcome.client_ref;
        match (
            outcome.outcome,
            outcome.server_id,
            outcome.received_at,
            outcome.sent_at,
        ) {
            // The row leaves at `sent_at + ttl_ms` (ADR 0044), as the
            // `Message` read back (spec 023-ttl-purge R1).
            (AckOutcome::Delivered, Some(server_id), Some(received_at), Some(sent_at)) => {
                let ttl = ttl_ms(channel.config().ttl_seconds());
                step.events.push(Event::Delivered {
                    channel: channel_id,
                    client_ref,
                    server_id,
                    received_at,
                    expires_at: sent_at.saturating_add(ttl),
                });
            }
            (AckOutcome::NotDelivered, ..) => {
                if let Some(sent_at) = outcome.sent_at {
                    step.events.push(Event::NotDelivered {
                        channel: channel_id,
                        client_ref,
                        sent_at,
                    });
                }
            }
            // Only the current `key_retired` copy carries its `sent_at`
            // when ignored (spec 025-identity-regen R5). Held past its
            // minute, it would block the re-seal that replaces it.
            (AckOutcome::Ignored, ..) => {
                if let Some(sent_at) = outcome.sent_at {
                    let hold = Hold {
                        channel: channel_id,
                        minute: sent_at / MINUTE_MS,
                    };
                    self.held.insert(client_ref, hold);
                }
            }
            _ => {}
        }
    }

    /// The entries of `channel_id` its `outbox` must not hand out at `now`:
    /// in flight, or held within their minute (R12, R14, R16). The holds whose
    /// minute is not `now`'s are forgotten on the way.
    pub(super) fn unanswered(&mut self, channel_id: &[u8; 16], now: u64) -> Vec<ClientRef> {
        let minute = now / MINUTE_MS;
        self.held.retain(|_, hold| hold.minute == minute);
        let held = self
            .held
            .iter()
            .map(|(client_ref, hold)| (client_ref, hold.channel));
        let flying = self
            .in_flight
            .iter()
            .map(|(client_ref, flight)| (client_ref, flight.channel));
        flying
            .chain(held)
            .filter(|(_, of)| of == channel_id)
            .map(|(client_ref, _)| *client_ref)
            .collect()
    }
}
