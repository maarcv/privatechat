//! The per-channel calls of the device (spec 027-core-api R9): each finds
//! its channel by `channel_id` and calls the `Channel` method of the spec
//! that defines it; the writers go through R14's recovery.

use super::Device;
use crate::error::Error;
use crate::proto::fingerprint::Fingerprint;
use crate::session::channel::{
    Channel, ChannelStatus, ClientRef, Gap, Message, OldKey, Peer, PeerId,
};
use crate::session::connection::Event;

/// A message `send` sealed and queued (R9).
#[derive(Debug, PartialEq, Eq)]
pub struct Sent {
    /// The `outbox` entry.
    pub client_ref: ClientRef,
    /// The message as the list shows it (spec 023-ttl-purge R7).
    pub message: Message,
    /// The events of the call.
    pub events: Vec<Event>,
}

impl Device {
    /// Seals `body` in `channel` and queues it for publishing (spec
    /// 021-channel-session R7, R8).
    ///
    /// # Errors
    ///
    /// `UnknownChannel`; the errors of `Channel::encrypt`, but `Ok` when a
    /// failed commit stands after the reopen (R9); `Internal` when the
    /// sealed message cannot be read back.
    pub fn send(
        &mut self,
        channel: [u8; 16],
        body: &str,
        display_name: Option<&str>,
        now: u64,
    ) -> Result<Sent, Error> {
        self.latest_now = now;
        let counter = self.channel(channel)?.send_counter();
        let marked = self.marks.contains_key(&channel);
        let (result, events) = self.direct(
            channel,
            |open| open.encrypt(body, display_name, now),
            |reopened| reopened.outbox_ref(counter),
        );
        let client_ref = match result {
            Ok(client_ref) => client_ref,
            Err(error) => {
                self.queued.extend(events);
                return Err(error);
            }
        };
        let Some(message) = self.channel(channel)?.message(client_ref, now) else {
            self.queued.extend(events);
            return Err(Error::Internal);
        };
        // A message on a marked channel may mean room came back (R12); a
        // state-only writer proves nothing.
        if marked && !self.cleared_recently(channel) {
            self.marks.insert(channel, 0);
        }
        let mut events = events;
        events.extend(self.after_send(channel, now));
        Ok(Sent {
            client_ref,
            message,
            events,
        })
    }

    /// The messages on screen (spec 023-ttl-purge R1).
    ///
    /// # Errors
    ///
    /// `UnknownChannel`; the errors of `Channel::messages`.
    pub fn messages(&self, channel: [u8; 16], now: u64) -> Result<Vec<Message>, Error> {
        self.channel(channel)?.messages(now)
    }

    /// Removes the expired records from the disk (spec 023-ttl-purge R4).
    ///
    /// # Errors
    ///
    /// `UnknownChannel`; the compaction's error, handled by R14 and R15.
    pub fn purge_expired(&mut self, channel: [u8; 16], now: u64) -> Result<u32, Error> {
        self.latest_now = now;
        self.write(channel, |open| open.purge_expired(now))
    }

    /// What the client shows about `channel` (spec 021-channel-session
    /// R25).
    ///
    /// # Errors
    ///
    /// `UnknownChannel`.
    pub fn channel_status(&self, channel: [u8; 16]) -> Result<ChannelStatus, Error> {
        Ok(self.channel(channel)?.status())
    }

    /// The senders with messages missing in this session (spec
    /// 021-channel-session R24).
    ///
    /// # Errors
    ///
    /// `UnknownChannel`.
    pub fn gaps(&self, channel: [u8; 16]) -> Result<Vec<Gap>, Error> {
        Ok(self.channel(channel)?.gaps())
    }

    /// The peers of `channel` (spec 022-peers-tofu R13).
    ///
    /// # Errors
    ///
    /// `UnknownChannel`; the errors of `Channel::peers`.
    pub fn peers(&self, channel: [u8; 16]) -> Result<Vec<Peer>, Error> {
        self.channel(channel)?.peers()
    }

    /// Labels `peer` (spec 022-peers-tofu R7).
    ///
    /// # Errors
    ///
    /// `UnknownChannel`; the errors of `Channel::label`.
    pub fn label(
        &mut self,
        channel: [u8; 16],
        peer: PeerId,
        name: &str,
        now: u64,
    ) -> Result<(), Error> {
        self.latest_now = now;
        self.write(channel, |open| open.label(peer, name, now))
    }

    /// Marks `peer` verified (spec 022-peers-tofu R8).
    ///
    /// # Errors
    ///
    /// `UnknownChannel`; the errors of `Channel::verify`.
    pub fn verify(
        &mut self,
        channel: [u8; 16],
        peer: PeerId,
        label: Option<&str>,
        now: u64,
    ) -> Result<(), Error> {
        self.latest_now = now;
        self.write(channel, |open| open.verify(peer, label, now))
    }

    /// Verifies the peer of a scanned fingerprint QR (spec 022-peers-tofu
    /// R9).
    ///
    /// # Errors
    ///
    /// `UnknownChannel`; the errors of `Channel::verify_scanned`.
    pub fn verify_scanned(
        &mut self,
        channel: [u8; 16],
        qr: &[u8],
        label: &str,
        now: u64,
    ) -> Result<PeerId, Error> {
        self.latest_now = now;
        self.write(channel, |open| open.verify_scanned(qr, label, now))
    }

    /// Mutes or unmutes `peer` (spec 022-peers-tofu R10).
    ///
    /// # Errors
    ///
    /// `UnknownChannel`; the errors of `Channel::mute`.
    pub fn mute(&mut self, channel: [u8; 16], peer: PeerId, muted: bool) -> Result<(), Error> {
        self.write(channel, |open| open.mute(peer, muted))
    }

    /// The fingerprint of `pk` in `channel` (spec 022-peers-tofu R11).
    ///
    /// # Errors
    ///
    /// `UnknownChannel`; the errors of `Channel::fingerprint`.
    pub fn fingerprint(&self, channel: [u8; 16], pk: PeerId) -> Result<Fingerprint, Error> {
        self.channel(channel)?.fingerprint(pk)
    }

    /// One's own fingerprint in `channel` (spec 022-peers-tofu R11).
    ///
    /// # Errors
    ///
    /// `UnknownChannel`; the errors of `Channel::own_fingerprint`.
    pub fn own_fingerprint(&self, channel: [u8; 16]) -> Result<Fingerprint, Error> {
        self.channel(channel)?.own_fingerprint()
    }

    /// Retires `peer`'s key (spec 024-key-retired).
    ///
    /// # Errors
    ///
    /// `UnknownChannel`; the errors of `Channel::retire`.
    pub fn retire(&mut self, channel: [u8; 16], peer: PeerId, now: u64) -> Result<(), Error> {
        self.latest_now = now;
        self.write(channel, |open| open.retire(peer, now))
    }

    /// Regenerates one's own identity in `channel` (spec
    /// 025-identity-regen R1), and returns the events of the call.
    ///
    /// # Errors
    ///
    /// `UnknownChannel`; the errors of `Channel::regenerate_identity`, but
    /// `Ok` when a failed commit stands after the reopen (R9).
    pub fn regenerate_identity(
        &mut self,
        channel: [u8; 16],
        now: u64,
    ) -> Result<Vec<Event>, Error> {
        self.latest_now = now;
        let (result, events) = self.direct(
            channel,
            |open| open.regenerate_identity(now),
            |reopened| reopened.status().retirement_pending.then_some(()),
        );
        match result {
            Ok(()) => {
                let mut events = events;
                events.extend(self.after_send(channel, now));
                Ok(events)
            }
            Err(error) => {
                self.queued.extend(events);
                Err(error)
            }
        }
    }

    /// One's own old keys in `channel` (spec 025-identity-regen R6).
    ///
    /// # Errors
    ///
    /// `UnknownChannel`.
    pub fn own_old_keys(&self, channel: [u8; 16]) -> Result<Vec<OldKey>, Error> {
        Ok(self.channel(channel)?.own_old_keys())
    }

    /// Forgets `peer` (spec 026-peer-limits R5).
    ///
    /// # Errors
    ///
    /// `UnknownChannel`; the errors of `Channel::forget`.
    pub fn forget(&mut self, channel: [u8; 16], peer: PeerId) -> Result<(), Error> {
        self.write(channel, |open| open.forget(peer))
    }

    /// A direct writer whose events wait for the next `on_tick` (R14).
    pub(super) fn write<T>(
        &mut self,
        channel: [u8; 16],
        call: impl FnOnce(&mut Channel) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let (result, events) = self.direct(channel, call, |_| None);
        self.queued.extend(events);
        result
    }
}
