//! The connections of the device (spec 027-core-api R11): one `Session` of
//! spec 028-session-sans-io per plan `id`, to which the socket's calls are
//! routed, and the store failures its steps report (R14).

use std::collections::{BTreeMap, BTreeSet};

use super::{ConnectionPlan, Device};
use crate::session::channel::Channel;
use crate::session::connection::{Event, Session, Step};
use crate::storage::StoreError;

/// One plan's session and what the device keeps beside it.
pub(super) struct Link {
    pub(super) session: Session,
    /// The channels a `SubscribeRefused` named since the plan was built
    /// (R11).
    pub(super) refused: BTreeSet<[u8; 16]>,
    /// Between `on_connect` and `on_disconnect`.
    pub(super) connected: bool,
}

impl Device {
    /// A new socket of plan `connection` is open (R11); an `id` not in the
    /// plan is ignored.
    pub fn on_connect(&mut self, connection: u64, now: u64) {
        self.latest_now = now;
        if let Some(link) = self.links.get_mut(&connection) {
            let refused: Vec<[u8; 16]> = link.refused.iter().copied().collect();
            link.session.on_connect(now, &refused);
            link.connected = true;
        }
    }

    /// One frame the socket of `connection` received (R11); an `id` not in
    /// the plan is ignored, with no event.
    pub fn on_frame(&mut self, connection: u64, frame: &[u8], now: u64) -> Vec<Event> {
        self.latest_now = now;
        let Some(link) = self.links.get_mut(&connection) else {
            return Vec::new();
        };
        let step = link.session.on_frame(frame, &mut self.channels, now);
        self.take_step(connection, step)
    }

    /// The frames to write on `connection`, in order (R11); none for an
    /// `id` not in the plan.
    pub fn outgoing(&mut self, connection: u64) -> Vec<Vec<u8>> {
        self.links
            .get_mut(&connection)
            .map(|link| link.session.outgoing())
            .unwrap_or_default()
    }

    /// The socket of `connection` closed, whoever closed it (R11).
    pub fn on_disconnect(&mut self, connection: u64) {
        if let Some(link) = self.links.get_mut(&connection) {
            link.session.on_disconnect();
            link.connected = false;
        }
    }

    /// The events of a session's step: a refused channel is remembered
    /// for the plan's next connection (R11), and every store failure goes
    /// through R14.
    pub(super) fn take_step(&mut self, connection: u64, step: Step) -> Vec<Event> {
        let Step { mut events, failed } = step;
        if let Some(link) = self.links.get_mut(&connection) {
            for event in &events {
                if let Event::SubscribeRefused { channel } = event {
                    link.refused.insert(*channel);
                }
            }
        }
        for (channel, error) in failed {
            events.extend(self.session_failure(channel, error));
        }
        events
    }

    /// `Session::after_send` of `channel`'s connection, when it has one
    /// (R9): its frames and events, a store failure through R14.
    pub(super) fn after_send(&mut self, channel: [u8; 16], now: u64) -> Vec<Event> {
        let Some((connection, link)) = link_of(&self.runs, &mut self.links, channel) else {
            return Vec::new();
        };
        let step = link.session.after_send(channel, &mut self.channels, now);
        self.take_step(connection, step)
    }

    /// Whether `channel`'s connection is connected.
    pub(super) fn is_connected(&self, channel: [u8; 16]) -> bool {
        self.runs
            .iter()
            .find(|run| run.channels.contains(&channel))
            .and_then(|run| self.links.get(&run.id))
            .is_some_and(|link| link.connected)
    }

    /// Brings the sessions in line with the plan (R11): a plan `id` that
    /// is gone loses its session, and a new one gets a session that holds
    /// every marked channel frozen (R14).
    pub(super) fn relink(&mut self) {
        let ids: BTreeSet<u64> = self.runs.iter().map(|run| run.id).collect();
        self.links.retain(|id, _| ids.contains(id));
        let mut added = BTreeMap::new();
        for run in &self.runs {
            if self.links.contains_key(&run.id) {
                continue;
            }
            let mut session = Session::new(run.id, run.channels.clone());
            for channel in self.marked_in(&run.channels) {
                session.set_write_failed(channel, true, false);
            }
            added.insert(
                run.id,
                Link {
                    session,
                    refused: BTreeSet::new(),
                    connected: false,
                },
            );
        }
        self.links.extend(added);
    }

    /// The open channels of `ids` that are `write_failed`.
    fn marked_in<'a>(&'a self, ids: &'a [[u8; 16]]) -> impl Iterator<Item = &'a Channel> {
        self.channels.iter().filter(move |channel| {
            let id = channel.config().channel_id();
            ids.contains(&id) && self.marks.contains_key(&id)
        })
    }

    /// R14 for a failure a session or the tick met: an `Io` or `Corrupt`
    /// store of a channel not marked is reopened and marked, with
    /// `StorageFailed` and no `Reconnect`; a marked channel's failure
    /// reopens nothing and says nothing; a reopen that fails breaks the
    /// channel.
    pub(super) fn session_failure(&mut self, channel: [u8; 16], error: StoreError) -> Vec<Event> {
        if !matches!(error, StoreError::Io | StoreError::Corrupt)
            || self.marks.contains_key(&channel)
        {
            return Vec::new();
        }
        let Ok(position) = self.position(channel) else {
            return Vec::new();
        };
        if self.reopen(position).is_ok() {
            self.mark(position);
        }
        vec![Event::StorageFailed { channel }]
    }
}

/// The plan `id` and the link of the run that carries `channel`.
pub(super) fn link_of<'a>(
    runs: &[ConnectionPlan],
    links: &'a mut BTreeMap<u64, Link>,
    channel: [u8; 16],
) -> Option<(u64, &'a mut Link)> {
    let id = runs.iter().find(|run| run.channels.contains(&channel))?.id;
    links.get_mut(&id).map(|link| (id, link))
}
