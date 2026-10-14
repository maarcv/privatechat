//! The recovery of a channel whose store failed (spec 027-core-api R14,
//! R15): the store dropped and reopened with the in-session values
//! carried, the channel marked `write_failed` until a probe clears it, or
//! moved to `broken` when the reopen fails; and the status compared around
//! every direct writer.

use super::routing::link_of;
use super::tick::{LATER_PROBE_MS, changed};
use super::{Broken, BrokenChannel, Device};
use crate::error::Error;
use crate::session::channel::Channel;
use crate::session::connection::Event;
use crate::session::names::shown_name;
use crate::storage::StoreError;

/// The wait before the first probe of a channel marked `write_failed`
/// (R14).
const FIRST_PROBE_MS: u64 = 60_000;

impl Device {
    /// Runs the direct writer `call` on `channel` with R14 around it, and
    /// returns its result and the events it produced: `StorageFailed` when
    /// the store failed and was reopened or the channel broke, and
    /// `StatusChanged` when its status or its peers changed, or when a
    /// marked channel's call stood after its silent reopen. After a
    /// reopen, `outcome` reads from what stands whether the call committed
    /// (R9), and its value replaces the error.
    pub(super) fn direct<T>(
        &mut self,
        channel: [u8; 16],
        call: impl FnOnce(&mut Channel) -> Result<T, Error>,
        outcome: impl FnOnce(&Channel) -> Option<T>,
    ) -> (Result<T, Error>, Vec<Event>) {
        let position = match self.position(channel) {
            Ok(position) => position,
            Err(error) => return (Err(error), Vec::new()),
        };
        let Some(open) = self.channels.get_mut(position) else {
            return (Err(Error::UnknownChannel), Vec::new());
        };
        let before = open.status();
        let marked = self.marks.contains_key(&channel);
        let mut result = call(open);
        let mut events = Vec::new();
        let failed = matches!(
            result,
            Err(Error::Store(StoreError::Io | StoreError::Corrupt))
        );
        if failed {
            if self.reopen(position).is_err() {
                events.push(Event::StorageFailed { channel });
                return (result, events);
            }
            if !marked {
                self.mark(position);
                events.push(Event::StorageFailed { channel });
            }
        }
        let Some(open) = self.channels.get_mut(position) else {
            return (result, events);
        };
        if failed {
            if let Some(value) = outcome(open) {
                result = Ok(value);
            }
            // A marked channel reopens with no `StorageFailed`: a call that
            // stood changed what the client shows (a status, a peer, one's
            // own name), which the fresh instance's flag cannot tell.
            if marked && result.is_ok() {
                events.push(Event::StatusChanged { channel });
            }
        } else if changed(open, before) {
            events.push(Event::StatusChanged { channel });
        }
        (result, events)
    }

    /// Drops the store of the channel at `position` and opens it again,
    /// carrying its gaps, ignored keys and `clock_off` and nothing else
    /// (R14); its mark is kept. When the reopen fails the channel moves to
    /// `broken` with its error, its `channel_id` and its name, and leaves
    /// its run.
    pub(super) fn reopen(&mut self, position: usize) -> Result<(), StoreError> {
        if position >= self.channels.len() {
            return Err(StoreError::Io);
        }
        let open = self.channels.remove(position);
        let id = open.config().channel_id();
        let dir = *open.dir_name();
        let carry = open.session_carry();
        let name = open
            .local_name()
            .unwrap_or_else(|| open.config().suggested_name());
        let channel_name = shown_name(name);
        // The store holds its directory until it is dropped.
        drop(open);
        let reopened = self
            .vault
            .create(&id)
            .map_err(Error::Store)
            .and_then(Channel::open_stored);
        match reopened {
            Ok(mut channel) => {
                channel.carry_session(carry);
                // A fresh instance starts with its peers flag set (spec
                // 021-channel-session R1); a reopen tells the client by
                // `StorageFailed` or a call's own result.
                channel.take_peers_changed();
                self.channels.insert(position, channel);
                Ok(())
            }
            Err(error) => {
                let reason = match error {
                    Error::Store(reason) => reason,
                    _ => StoreError::Corrupt,
                };
                self.marks.remove(&id);
                self.cleared.remove(&id);
                self.broken.push(Broken {
                    dir,
                    info: BrokenChannel {
                        name: dir.to_hex(),
                        reason,
                        channel_id: Some(id),
                        channel_name,
                    },
                });
                // The broken channel leaves its run (R14).
                self.replan();
                Err(reason)
            }
        }
    }

    /// Marks the channel at `position` `write_failed`, its first probe a
    /// minute after the latest `now`, or ten minutes when its last clearing
    /// was less than ten minutes before (R14).
    pub(super) fn mark(&mut self, position: usize) {
        let Some(channel) = self.channels.get(position) else {
            return;
        };
        let id = channel.config().channel_id();
        let wait = if self.cleared_recently(id) {
            LATER_PROBE_MS
        } else {
            FIRST_PROBE_MS
        };
        self.marks.insert(id, self.latest_now.saturating_add(wait));
        // Its session holds it frozen (spec 028-session-sans-io R10).
        if let Some((_, link)) = link_of(&self.runs, &mut self.links, id) {
            link.session.set_write_failed(channel, true, false);
        }
    }

    /// Whether `channel`'s mark was cleared less than ten minutes before
    /// the latest `now`, a clearing recorded later counting as older (R12,
    /// R14).
    pub(super) fn cleared_recently(&self, channel: [u8; 16]) -> bool {
        self.cleared.get(&channel).is_some_and(|&at| {
            at <= self.latest_now && self.latest_now.saturating_sub(at) < LATER_PROBE_MS
        })
    }

    /// Every probe due at the next tick, as after a `leave` or a
    /// `remove_broken` that may have freed space (R3).
    pub(super) fn make_probes_due(&mut self) {
        for probe_at in self.marks.values_mut() {
            *probe_at = 0;
        }
    }
}
