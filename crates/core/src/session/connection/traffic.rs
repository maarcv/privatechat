//! The traffic of spec 028-session-sans-io R10: a `push` handed to
//! `decrypt`, and the stalls that keep a channel's cursor where a push it
//! could not store can be fetched again.

use super::{Channels, Event, Session, Step, find_mut};
use crate::Error;
use crate::session::channel::Channel;
use crate::storage::StoreError;

/// Why a channel takes no more pushes on this connection (R10).
#[derive(Clone, Copy)]
pub(super) enum Stall {
    /// A push met a full log: later pushes go to `check_own_key` alone;
    /// `asked` once a tick found room again and asked for a new
    /// connection.
    LogFull { stop: Stop, asked: bool },
    /// Another store error: nothing of the channel is called.
    Frozen,
}

/// Whether a `LogFull` stall still publishes the current key's entries.
#[derive(Clone, Copy)]
pub(super) enum Stop {
    Publishing,
    /// One's own key was used elsewhere: only the pending `key_retired`
    /// and the entries `under_retired_key` leave, until a
    /// `regenerate_identity`, told by the epoch it raises (spec
    /// 025-identity-regen R1).
    Stopped {
        epoch: u32,
    },
}

impl Session {
    /// A `push` of a channel awaiting `ok` or subscribed goes to
    /// `decrypt`, or, in a `LogFull` stall, to `check_own_key`; any other
    /// is ignored (R9, R10).
    pub(super) fn on_push(
        &mut self,
        channel_id: [u8; 16],
        arrival: (&[u8], [u8; 16], u64),
        channels: &mut Channels,
        now: u64,
        step: &mut Step,
    ) {
        if !self.subscriptions.contains_key(&channel_id) {
            return;
        }
        let Some(channel) = find_mut(channels, &channel_id) else {
            return;
        };
        let (blob, server_id, received_at) = arrival;
        match self.stalls.get(&channel_id).copied() {
            Some(Stall::Frozen) => {}
            Some(Stall::LogFull { stop, .. }) => {
                self.check_stalled(channel, stop, blob, received_at, now, step);
            }
            None => self.decrypt(channel, blob, server_id, received_at, now, step),
        }
    }

    /// `Event::Message` for a consumed message; a store error stalls the
    /// channel, so that no later push moves its cursor past the one lost.
    fn decrypt(
        &mut self,
        channel: &mut Channel,
        blob: &[u8],
        server_id: [u8; 16],
        received_at: u64,
        now: u64,
        step: &mut Step,
    ) {
        let channel_id = channel.config().channel_id();
        match channel.decrypt(blob, server_id, received_at, now) {
            Ok(Some(received)) => step.events.push(Event::Message {
                channel: channel_id,
                received,
            }),
            Err(Error::Store(StoreError::LogFull)) => {
                // `decrypt` ran the own-key check on this blob but reports
                // only `LogFull`: a flag set now, by it or from before,
                // stops the channel, a key not yet regenerated being one
                // known to be used elsewhere.
                let stop = stop_for(channel);
                let stall = Stall::LogFull { stop, asked: false };
                self.stalls.insert(channel_id, stall);
                step.events.push(Event::StorageFailed {
                    channel: channel_id,
                });
            }
            Err(Error::Store(error)) => self.freeze(channel_id, error, step),
            Ok(None) | Err(_) => {}
        }
    }

    /// A push of a channel in a `LogFull` stall: its own-key alert still
    /// reaches the user, and one's own key used elsewhere stops the
    /// current key's entries (R10).
    fn check_stalled(
        &mut self,
        channel: &mut Channel,
        stop: Stop,
        blob: &[u8],
        received_at: u64,
        now: u64,
        step: &mut Step,
    ) {
        let channel_id = channel.config().channel_id();
        match channel.check_own_key(blob, received_at, now) {
            Ok(true) if matches!(stop, Stop::Publishing) => {
                // Only the stop changes: a `Reconnect` already asked is not
                // asked again.
                if let Some(Stall::LogFull { stop, .. }) = self.stalls.get_mut(&channel_id) {
                    *stop = stopped(channel);
                }
            }
            Err(Error::Store(error)) => self.freeze(channel_id, error, step),
            Ok(_) | Err(_) => {}
        }
    }

    /// R10's stall for a store error other than `LogFull`: the error goes
    /// to `failed` and nothing of the channel is called again on this
    /// connection.
    pub(super) fn freeze(&mut self, channel_id: [u8; 16], error: StoreError, step: &mut Step) {
        self.stalls.insert(channel_id, Stall::Frozen);
        step.failed.push((channel_id, error));
    }

    /// The `Device`'s `write_failed` mark (R10, spec 027-core-api R12,
    /// R14): a marked channel is frozen, a `LogFull` stall included, on
    /// this connection and every later one. Clearing it leaves the channel
    /// frozen until `on_disconnect`, or, with `storage_full`, back in a
    /// `LogFull` stall begun now, its stop read from the flag as it stands.
    pub(crate) fn set_write_failed(&mut self, channel: &Channel, on: bool, storage_full: bool) {
        let channel_id = channel.config().channel_id();
        if on {
            self.write_failed.insert(channel_id);
            self.stalls.insert(channel_id, Stall::Frozen);
            return;
        }
        // A marked channel holds `Frozen` already, which a clearing
        // without `storage_full` keeps.
        if self.write_failed.remove(&channel_id) && storage_full {
            let stop = stop_for(channel);
            self.stalls
                .insert(channel_id, Stall::LogFull { stop, asked: false });
        }
    }

    /// On a tick, a `LogFull` stall whose channel has room again asks
    /// once for a new connection, which fetches the pushes it dropped
    /// (R10).
    pub(super) fn check_room(&mut self, channels: &Channels, step: &mut Step) {
        let mut relieved = false;
        for (channel_id, stall) in &mut self.stalls {
            if let Stall::LogFull { asked, .. } = stall
                && !*asked
                && super::find(channels, channel_id)
                    .is_some_and(|channel| !channel.status().storage_full)
            {
                *asked = true;
                relieved = true;
            }
        }
        if relieved {
            self.reconnect(step);
        }
    }

    /// Whether the channel's pushes are dropped, so that `synced` would
    /// move its history past one it lost (R10).
    pub(super) fn is_stalled(&self, channel_id: &[u8; 16]) -> bool {
        self.stalls.contains_key(channel_id)
    }

    /// Whether the channel publishes only the pending `key_retired` and
    /// the entries `under_retired_key` (R10, spec 021-channel-session R22).
    pub(super) fn withholds_current(&self, channel_id: &[u8; 16]) -> bool {
        matches!(
            self.stalls.get(channel_id),
            Some(Stall::LogFull {
                stop: Stop::Stopped { .. },
                ..
            })
        )
    }

    /// Whether the channel is stopped and has regenerated its key since,
    /// which only a new connection resumes (R10).
    pub(super) fn regenerated(&self, channel: &Channel) -> bool {
        match self.stalls.get(&channel.config().channel_id()) {
            Some(Stall::LogFull {
                stop: Stop::Stopped { epoch },
                ..
            }) => channel.identity_epoch() != *epoch,
            _ => false,
        }
    }

    /// Whether nothing of the channel is called (R10).
    pub(super) fn is_frozen(&self, channel_id: &[u8; 16]) -> bool {
        matches!(self.stalls.get(channel_id), Some(Stall::Frozen))
    }
}

/// The stop of a `LogFull` stall begun now: one's own key known to be
/// used elsewhere stops it (R10).
fn stop_for(channel: &Channel) -> Stop {
    if channel.status().own_key_used_elsewhere {
        stopped(channel)
    } else {
        Stop::Publishing
    }
}

/// The stop of `channel`, with its key as it stands.
fn stopped(channel: &Channel) -> Stop {
    Stop::Stopped {
        epoch: channel.identity_epoch(),
    }
}
