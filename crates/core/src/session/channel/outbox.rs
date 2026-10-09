//! The `outbox` after sealing (spec 021 R15–R17, R22, R23, R31): an entry
//! leaves it by its `ack`, by going stale, by a refusal of the server or
//! overtaken, and whichever way it leaves, its signature is kept until no
//! receiver can accept its blob any more.

use super::receive::listed_time;
use super::{ACK_GRACE_MS, AckOutcome, Channel, ClientRef, OutboxStep, Outcome};
use crate::error::Error;
use crate::storage::state::items::{OutboxEntry, OutboxKind};
use crate::storage::{ChannelState, LogEntry, LogRecord};

impl Channel {
    /// The server stored the entry `client_ref` as `server_id` at
    /// `received_at` (R16, R17): one commit removes it, and every ordinary
    /// entry of the same key with a lower counter as not delivered, keeps
    /// its signature, and records whether it was stored in time.
    ///
    /// # Errors
    ///
    /// `Store` when the commit fails, memory unchanged.
    pub(crate) fn acked(
        &mut self,
        client_ref: ClientRef,
        server_id: [u8; 16],
        received_at: u64,
        now: u64,
    ) -> Result<Outcome, Error> {
        self.latest_now = Some(now);
        if let Some(outcome) = self.acked_retirement(client_ref, server_id, received_at)? {
            return Ok(outcome);
        }
        let Some(entry) = self
            .ordinary_outbox()
            .find(|entry| entry.client_ref == client_ref.bytes)
        else {
            return Ok(Outcome {
                client_ref,
                outcome: AckOutcome::Ignored,
                server_id: None,
                received_at: None,
                sent_at: None,
            });
        };
        let kept = self.kept_signature(entry, self.state.identity_epoch);
        let (sent_at, counter, under_retired_key) =
            (entry.sent_at, entry.counter, entry.under_retired_key);
        let mut next = self.next_state();
        next.outbox
            .retain(|other| other.client_ref != client_ref.bytes);
        let mut records = vec![kept];
        // The server stores one connection's publishes in order, so an
        // entry it refused earlier and would store later reaches every
        // receiver as `Replay`.
        let overtaken = self.remove_entries(&mut next, &mut records, |other| {
            other.under_retired_key == under_retired_key && other.counter < counter
        });
        // Checked against the server's own time: a sender clock off by more
        // than the margin cannot hide a loss behind an `ack` (ADR 0034).
        let window = self.accept_window();
        let in_time =
            received_at.abs_diff(sent_at) <= window && sent_at.saturating_add(self.ttl_ms()) >= now;
        let listed_at = listed_time(Some(sent_at), received_at).min(now);
        let (outcome, kind) = if in_time {
            let acked = LogEntry::Acked {
                server_id,
                received_at: listed_at,
                client_ref: client_ref.bytes,
            };
            (AckOutcome::Delivered, acked)
        } else {
            let not_delivered = LogEntry::NotDelivered {
                client_ref: client_ref.bytes,
            };
            (AckOutcome::NotDelivered, not_delivered)
        };
        records.push(LogRecord {
            purge_at: self.own_purge_at(sent_at),
            entry: kind,
        });
        self.commit(next, records)?;
        self.queue_not_delivered(&overtaken);
        Ok(Outcome {
            client_ref,
            outcome,
            server_id: Some(server_id),
            received_at: Some(listed_at),
            sent_at: Some(sent_at),
        })
    }

    /// Re-seals the pending `key_retired` when the minute changed and
    /// removes the stale ordinary entries, in one commit, then hands out
    /// the entries to publish (R22, spec 025-identity-regen R4): those not
    /// in flight, the `key_retired` only once no entry of the old key
    /// waits, and only the `key_retired` and the entries
    /// `under_retired_key` when `withhold_current` is set.
    ///
    /// # Errors
    ///
    /// `Internal` when libsodium fails; `Store` when the commit fails;
    /// either way with nothing handed out.
    pub(crate) fn outbox(
        &mut self,
        now: u64,
        in_flight: &[ClientRef],
        withhold_current: bool,
    ) -> Result<OutboxStep, Error> {
        let not_delivered = self.remove_stale(now, in_flight, true)?;
        // The old key's messages arrive before its retirement.
        let old_key_waits = self.ordinary_outbox().any(|entry| entry.under_retired_key);
        let publish = self
            .state
            .outbox
            .iter()
            .filter(|entry| !in_flight.contains(&ClientRef::of(entry)))
            .filter(|entry| entry.kind != OutboxKind::KeyRetired || !old_key_waits)
            .filter(|entry| {
                !withhold_current || entry.kind == OutboxKind::KeyRetired || entry.under_retired_key
            })
            .map(|entry| (ClientRef::of(entry), entry.blob.clone()))
            .collect();
        Ok(OutboxStep {
            publish,
            not_delivered,
        })
    }

    /// The removal of R22 alone, for a channel that is not subscribed
    /// (R23): `publish` is always empty, and no re-seal, so that a device
    /// offline does not rewrite its state every minute (spec
    /// 025-identity-regen R4).
    ///
    /// # Errors
    ///
    /// `Store` when the commit fails, with nothing reported.
    pub(crate) fn expire_outbox(
        &mut self,
        now: u64,
        in_flight: &[ClientRef],
    ) -> Result<OutboxStep, Error> {
        Ok(OutboxStep {
            publish: Vec::new(),
            not_delivered: self.remove_stale(now, in_flight, false)?,
        })
    }

    /// Removes the ordinary entry the server refused, as not delivered, and
    /// returns its `sent_at`; `None`, with no commit, for a `key_retired`
    /// entry or an unknown `client_ref` (R31).
    ///
    /// # Errors
    ///
    /// `Store` when the commit fails, memory unchanged.
    pub(crate) fn abandon(&mut self, client_ref: ClientRef) -> Result<Option<u64>, Error> {
        let named = |entry: &OutboxEntry| entry.client_ref == client_ref.bytes;
        if !self.ordinary_outbox().any(named) {
            return Ok(None);
        }
        let mut next = self.next_state();
        let mut records = Vec::new();
        let removed = self.remove_entries(&mut next, &mut records, named);
        self.commit(next, records)?;
        Ok(removed.first().map(|(_, sent_at)| *sent_at))
    }

    /// The outcomes queued since the last call (R1).
    pub(crate) fn take_outcomes(&mut self) -> Vec<Outcome> {
        core::mem::take(&mut self.outcomes)
    }

    /// Removes in one commit the ordinary entries no receiver accepts any
    /// more, with a minute of grace for one in flight, and, when `reseal`
    /// is set, re-seals the pending `key_retired` in the same commit; no
    /// commit when neither happens (R22, spec 025-identity-regen R4).
    fn remove_stale(
        &mut self,
        now: u64,
        in_flight: &[ClientRef],
        reseal: bool,
    ) -> Result<Vec<(ClientRef, u64)>, Error> {
        self.latest_now = Some(now);
        let window = self.accept_window();
        let stale = |entry: &OutboxEntry| {
            let grace = if in_flight.contains(&ClientRef::of(entry)) {
                ACK_GRACE_MS
            } else {
                0
            };
            entry.sent_at.saturating_add(window).saturating_add(grace) < now
        };
        let mut next = self.next_state();
        let resealed = reseal && self.reseal_retirement(&mut next, now, in_flight)?;
        if !resealed && !self.ordinary_outbox().any(stale) {
            return Ok(Vec::new());
        }
        let mut records = Vec::new();
        let removed = self.remove_entries(&mut next, &mut records, stale);
        self.commit(next, records)?;
        Ok(removed)
    }

    /// Removes from `next` the ordinary entries `select` picks, never the
    /// `key_retired`, appending for each its kept signature and a
    /// not-delivered record (R15, R22); returns them with their `sent_at`.
    pub(super) fn remove_entries(
        &self,
        next: &mut ChannelState,
        records: &mut Vec<LogRecord>,
        select: impl Fn(&OutboxEntry) -> bool,
    ) -> Vec<(ClientRef, u64)> {
        let (removed, kept): (Vec<OutboxEntry>, Vec<OutboxEntry>) =
            core::mem::take(&mut next.outbox)
                .into_iter()
                .partition(|entry| entry.kind == OutboxKind::Text && select(entry));
        next.outbox = kept;
        let mut gone = Vec::with_capacity(removed.len());
        for entry in &removed {
            records.push(self.kept_signature(entry, next.identity_epoch));
            records.push(LogRecord {
                purge_at: self.own_purge_at(entry.sent_at),
                entry: LogEntry::NotDelivered {
                    client_ref: entry.client_ref,
                },
            });
            gone.push((ClientRef::of(entry), entry.sent_at));
        }
        gone
    }

    /// Queues `NotDelivered` for entries a commit removed (R17).
    pub(super) fn queue_not_delivered(&mut self, removed: &[(ClientRef, u64)]) {
        self.outcomes
            .extend(removed.iter().map(|(client_ref, sent_at)| Outcome {
                client_ref: *client_ref,
                outcome: AckOutcome::NotDelivered,
                server_id: None,
                received_at: None,
                sent_at: Some(*sent_at),
            }));
    }

    /// The kept-signature record of an entry that leaves the `outbox`
    /// (R15): it lasts one `ttl_ms + 360 000` beyond the last moment R14
    /// accepts the blob, so a clock set back by up to that much cannot turn
    /// a replay of it into a false alarm. Its `client_ref` and `epoch` are
    /// written and never read.
    fn kept_signature(&self, entry: &OutboxEntry, epoch: u32) -> LogRecord {
        let window = self.accept_window();
        LogRecord {
            purge_at: entry.sent_at.saturating_add(window.saturating_mul(2)),
            entry: LogEntry::KeptSignature {
                sent_at: entry.sent_at,
                client_ref: entry.client_ref,
                signature: entry.signature,
                epoch,
            },
        }
    }
}

impl ClientRef {
    /// The `client_ref` of an `outbox` entry.
    pub(super) fn of(entry: &OutboxEntry) -> ClientRef {
        ClientRef {
            bytes: entry.client_ref,
        }
    }
}
