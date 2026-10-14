//! The device's clock (spec 027-core-api R12, R14, R24): every connected
//! session ticks, the channels with no connected session expire their
//! `outbox` and report what changed, one compaction and one probe run per
//! tick, and `flush` saves what a quiet channel holds in memory at lock.

use super::Device;
use super::routing::link_of;
use crate::error::Error;
use crate::session::channel::{Channel, ChannelStatus};
use crate::session::connection::Event;

/// The wait between two probes of a channel that stays `write_failed`, and
/// the time after a clearing within which a new failure waits that long
/// before its first probe (R12, R14).
pub(super) const LATER_PROBE_MS: u64 = 600_000;

impl Device {
    /// The clock moved (R12): call it at least once every 1 000 ms while
    /// unlocked. Returns the tick's events, with those queued since the
    /// last one (R14).
    pub fn on_tick(&mut self, now: u64) -> Vec<Event> {
        self.latest_now = now;
        // What came before the tick, first, so that a failure and the
        // probe that clears it arrive in that order.
        let mut events = core::mem::take(&mut self.queued);
        let connected: Vec<u64> = self
            .links
            .iter()
            .filter(|(_, link)| link.connected)
            .map(|(id, _)| *id)
            .collect();
        for connection in connected {
            if let Some(link) = self.links.get_mut(&connection) {
                let step = link.session.on_tick(&mut self.channels, now);
                events.extend(self.take_step(connection, step));
            }
        }
        events.extend(self.tick_unconnected(now));
        events.extend(self.compact_one(now));
        events.extend(self.probe_one(now));
        events
    }

    /// Saves what every channel holds in memory, attempting each even
    /// after one fails and reopening nothing (R24); the client calls it
    /// when the app locks, before it drops the `Device`.
    ///
    /// # Errors
    ///
    /// The first channel's error, after every channel was attempted.
    pub fn flush(&mut self, now: u64) -> Result<(), Error> {
        self.latest_now = now;
        let mut first = Ok(());
        for channel in &mut self.channels {
            if let Err(error) = channel.flush(now)
                && first.is_ok()
            {
                first = Err(error);
            }
        }
        first
    }

    /// The channels with no connected session: a channel not marked
    /// expires its stale entries (spec 021-channel-session R23), and each
    /// reports its outcomes and, when its status or peers changed,
    /// `StatusChanged` (R12, R14).
    fn tick_unconnected(&mut self, now: u64) -> Vec<Event> {
        let mut events = Vec::new();
        let ids: Vec<[u8; 16]> = self
            .channels
            .iter()
            .map(|channel| channel.config().channel_id())
            .filter(|id| !self.is_connected(*id))
            .collect();
        for id in ids {
            let marked = self.marks.contains_key(&id);
            let Ok(channel) = self.channel_mut(id) else {
                continue;
            };
            let before = channel.status();
            if !marked {
                match channel.expire_outbox(now, &[]) {
                    Ok(step) => {
                        events.extend(step.not_delivered.into_iter().map(
                            |(client_ref, sent_at)| Event::NotDelivered {
                                channel: id,
                                client_ref,
                                sent_at,
                            },
                        ));
                    }
                    Err(Error::Store(error)) => {
                        events.extend(self.session_failure(id, error));
                        continue;
                    }
                    Err(_) => {}
                }
            }
            if let Ok(channel) = self.channel_mut(id) {
                events.extend(drain(channel, before));
            }
        }
        events
    }

    /// One compaction a tick (R12): the first channel not marked whose
    /// purge is due (spec 023-ttl-purge R5), or else the first whose log
    /// lacks its headroom and whose relief acts (spec 021-channel-session
    /// R18): a relief that compacts nothing touches no store, so one full
    /// channel never holds back another's. A failure goes through R14
    /// (R15).
    fn compact_one(&mut self, now: u64) -> Vec<Event> {
        let due = self.channels.iter().find_map(|channel| {
            let id = channel.config().channel_id();
            (!self.marks.contains_key(&id) && channel.purge_due(now)).then_some(id)
        });
        if let Some(id) = due {
            let (_, events) = self.compact(id, |channel| channel.purge_expired(now).map(|_| true));
            return events;
        }
        let full: Vec<[u8; 16]> = self
            .channels
            .iter()
            .filter(|channel| channel.status().storage_full)
            .map(|channel| channel.config().channel_id())
            .filter(|id| !self.marks.contains_key(id))
            .collect();
        for id in full {
            let (acted, events) = self.compact(id, |channel| channel.relieve_headroom(now));
            if acted {
                return events;
            }
        }
        Vec::new()
    }

    /// Runs one compaction on `id`: whether it compacted or failed, and
    /// its events, `StatusChanged` on a change or R14's.
    fn compact(
        &mut self,
        id: [u8; 16],
        run: impl FnOnce(&mut Channel) -> Result<bool, Error>,
    ) -> (bool, Vec<Event>) {
        let Ok(channel) = self.channel_mut(id) else {
            return (false, Vec::new());
        };
        let before = channel.status();
        match run(channel) {
            Err(Error::Store(error)) => (true, self.session_failure(id, error)),
            Err(_) => (false, Vec::new()),
            Ok(acted) => (acted, self.status_change(id, before)),
        }
    }

    /// One probe a tick (R12): the first marked channel whose probe time
    /// came, or lies more than ten minutes ahead after a clock set back,
    /// is reopened silently and committed once; on success the mark is
    /// cleared with `StatusChanged` and, when its connection is connected
    /// and the log has room, `Reconnect`, so that the pushes it held come
    /// again; on failure the next probe is ten minutes ahead.
    fn probe_one(&mut self, now: u64) -> Vec<Event> {
        let due = self.marks.iter().find_map(|(id, probe_at)| {
            let came = *probe_at <= now || *probe_at > now.saturating_add(LATER_PROBE_MS);
            came.then_some(*id)
        });
        let Some(id) = due else {
            return Vec::new();
        };
        let Ok(position) = self.position(id) else {
            self.marks.remove(&id);
            return Vec::new();
        };
        if self.reopen(position).is_err() {
            return vec![Event::StorageFailed { channel: id }];
        }
        let Some(channel) = self.channels.get_mut(position) else {
            return Vec::new();
        };
        if channel.probe(now).is_err() {
            self.marks.insert(id, now.saturating_add(LATER_PROBE_MS));
            return Vec::new();
        }
        let storage_full = channel.status().storage_full;
        self.marks.remove(&id);
        self.cleared.insert(id, now);
        let mut events = vec![Event::StatusChanged { channel: id }];
        let Some(channel) = self.channels.get(position) else {
            return events;
        };
        if let Some((connection, link)) = link_of(&self.runs, &mut self.links, id) {
            link.session.set_write_failed(channel, false, storage_full);
            if link.connected && !storage_full {
                events.push(Event::Reconnect { connection });
            }
        }
        events
    }

    /// `StatusChanged` for `channel` when its status differs from `before`
    /// or its peers changed (R12, R14).
    fn status_change(&mut self, channel: [u8; 16], before: ChannelStatus) -> Vec<Event> {
        let Ok(open) = self.channel_mut(channel) else {
            return Vec::new();
        };
        if changed(open, before) {
            vec![Event::StatusChanged { channel }]
        } else {
            Vec::new()
        }
    }
}

/// Whether `channel`'s status differs from `before` or its peers changed,
/// the flag taken either way (R13 of spec 028, R14).
pub(super) fn changed(channel: &mut Channel, before: ChannelStatus) -> bool {
    channel.take_peers_changed() | (channel.status() != before)
}

/// A channel's queued outcomes, which are all of entries it removed as
/// not delivered (spec 021-channel-session R17), then `StatusChanged` when
/// its status differs from `before` or its peers changed (R14).
fn drain(channel: &mut Channel, before: ChannelStatus) -> Vec<Event> {
    let id = channel.config().channel_id();
    let mut events: Vec<Event> = channel
        .take_outcomes()
        .into_iter()
        .filter_map(|outcome| {
            outcome.sent_at.map(|sent_at| Event::NotDelivered {
                channel: id,
                client_ref: outcome.client_ref,
                sent_at,
            })
        })
        .collect();
    if changed(channel, before) {
        events.push(Event::StatusChanged { channel: id });
    }
    events
}
