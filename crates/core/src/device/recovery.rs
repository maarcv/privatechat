//! The recovery of a channel whose store failed (spec 027-core-api R14,
//! R15): the store dropped and reopened with the in-session values
//! carried, the channel marked `write_failed` until a probe clears it, or
//! moved to `broken` when the reopen fails; and the status compared around
//! every direct writer.

use super::{Broken, BrokenChannel, Device, Open};
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
    /// `StatusChanged` when its status or its peers changed. After a
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
        let before = open.channel.status();
        let marked = open.probe_at.is_some();
        let mut result = call(&mut open.channel);
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
            if let Some(value) = outcome(&open.channel) {
                result = Ok(value);
            }
            // A fresh instance starts with its peers flag set (spec
            // 021-channel-session R1); the failure already asks the client
            // to re-read everything.
            open.channel.take_peers_changed();
        } else if open.channel.take_peers_changed() || open.channel.status() != before {
            events.push(Event::StatusChanged { channel });
        }
        (result, events)
    }

    /// Drops the store of the channel at `position` and opens it again,
    /// carrying its gaps, ignored keys and `clock_off` and nothing else
    /// (R14); its mark is kept. When the reopen fails the channel moves to
    /// `broken` with its error, its `channel_id` and its name.
    pub(super) fn reopen(&mut self, position: usize) -> Result<(), StoreError> {
        if position >= self.channels.len() {
            return Err(StoreError::Io);
        }
        let open = self.channels.remove(position);
        let id = open.channel.config().channel_id();
        let dir = *open.channel.dir_name();
        let carry = open.channel.session_carry();
        let name = open
            .channel
            .local_name()
            .unwrap_or_else(|| open.channel.config().suggested_name());
        let channel_name = shown_name(name);
        let probe_at = open.probe_at;
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
                self.channels.insert(position, Open { channel, probe_at });
                Ok(())
            }
            Err(error) => {
                let reason = match error {
                    Error::Store(reason) => reason,
                    _ => StoreError::Corrupt,
                };
                self.broken.push(Broken {
                    dir,
                    info: BrokenChannel {
                        name: dir.to_hex(),
                        reason,
                        channel_id: Some(id),
                        channel_name,
                    },
                });
                Err(reason)
            }
        }
    }

    /// Marks the channel at `position` `write_failed`, its first probe a
    /// minute after the latest `now` (R14).
    fn mark(&mut self, position: usize) {
        let probe_at = self.latest_now.saturating_add(FIRST_PROBE_MS);
        if let Some(open) = self.channels.get_mut(position) {
            open.probe_at = Some(probe_at);
        }
    }
}
