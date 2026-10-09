//! Regenerating one's own key (spec 025-identity-regen): the new key, the
//! list of one's old keys (R1, R6), the `key_retired` the old key seals for
//! itself (R2), its re-seal (R4) and its `ack` (R5). The old seed is kept
//! only for that one message (R7); its echoes are spec 021's step 5 (R3).

use super::send::MINUTE_MS;
use super::{AckOutcome, Channel, ClientRef, OldKey, Outcome};
use crate::crypto::{self, Nonce, Secret, Signature};
use crate::error::Error;
use crate::proto::envelope::{self, ChannelCtx, KEY_RETIRED_COUNTER, SenderKey};
use crate::proto::payload::{Payload, PayloadKind};
use crate::storage::state::MAX_OLD_KEYS;
use crate::storage::state::items::{self, OutboxEntry, OutboxKind};
use crate::storage::{ChannelState, StoreError};

impl Channel {
    /// Replaces one's key with a fresh one in one commit, and queues the
    /// old key's `key_retired` behind its entries (R1, R2). No peer limit
    /// and no room in the log can refuse it: it appends no record.
    ///
    /// # Errors
    ///
    /// `RetirementPending` while the previous `key_retired` is pending,
    /// committing nothing; `Internal` when libsodium fails, and for a
    /// `LogFull`, which a commit with no record cannot meet; `Store` when
    /// the commit fails, memory unchanged.
    pub(crate) fn regenerate_identity(&mut self, now: u64) -> Result<(), Error> {
        self.latest_now = Some(now);
        if self.state.retiring_seed.is_some() {
            return Err(Error::RetirementPending);
        }
        let retirement = self.seal_retirement(&self.state.identity_seed, now)?;
        let old_pk = *SenderKey::from_seed(&self.state.identity_seed)?.public();
        let mut next = self.next_state();
        self.make_room_for_old_key(&mut next, now);
        next.own_old_keys.push(items::OldKey {
            pk: old_pk,
            retired_at: now,
        });
        let old_seed = core::mem::replace(&mut next.identity_seed, Secret::random()?);
        next.retiring_seed = Some(old_seed);
        next.identity_epoch = next.identity_epoch.checked_add(1).ok_or(Error::Internal)?;
        next.send_counter = 0;
        next.own_key_used_elsewhere = false;
        next.read_only = false;
        // No `key_retired` is in the `outbox`: its seed is gone with it (R5).
        for entry in &mut next.outbox {
            entry.under_retired_key = true;
        }
        next.outbox.push(retirement);
        self.commit(next, Vec::new()).map_err(|error| match error {
            Error::Store(StoreError::LogFull) => Error::Internal,
            other => other,
        })
    }

    /// One's own old keys, oldest first, each with its `retired_at` (R6).
    pub(crate) fn own_old_keys(&self) -> Vec<OldKey> {
        self.state
            .own_old_keys
            .iter()
            .map(|old| OldKey {
                pk: old.pk.0,
                retired_at: old.retired_at,
            })
            .collect()
    }

    /// The `ack` of the pending `key_retired` (R5): stored in time, it
    /// removes the entry and the old seed in one commit, keeping no
    /// signature; late, it changes nothing, so that a server answering late
    /// cannot make the device drop the old key before the retirement has
    /// arrived. `None` when `client_ref` is not its current copy.
    ///
    /// # Errors
    ///
    /// `Store` when the commit fails, memory unchanged.
    pub(super) fn acked_retirement(
        &mut self,
        client_ref: ClientRef,
        server_id: [u8; 16],
        received_at: u64,
    ) -> Result<Option<Outcome>, Error> {
        let Some(entry) = self.state.outbox.iter().find(|entry| {
            entry.kind == OutboxKind::KeyRetired && entry.client_ref == client_ref.bytes
        }) else {
            return Ok(None);
        };
        let sent_at = entry.sent_at;
        if received_at.abs_diff(sent_at) > self.accept_window() {
            return Ok(Some(Outcome {
                client_ref,
                outcome: AckOutcome::Ignored,
                server_id: None,
                received_at: None,
                sent_at: None,
            }));
        }
        let mut next = self.next_state();
        next.outbox
            .retain(|entry| entry.kind != OutboxKind::KeyRetired);
        next.retiring_seed = None;
        self.commit(next, Vec::new())?;
        Ok(Some(Outcome {
            client_ref,
            outcome: AckOutcome::RetirementDelivered,
            server_id: Some(server_id),
            received_at: None,
            sent_at: Some(sent_at),
        }))
    }

    /// Re-seals in `next` the pending `key_retired` when the minute of
    /// `now` differs from its `sent_at`, earlier or later, in place and
    /// unless a copy is in flight (R4); `true` when it did.
    ///
    /// # Errors
    ///
    /// `Internal` when libsodium fails.
    pub(super) fn reseal_retirement(
        &self,
        next: &mut ChannelState,
        now: u64,
        in_flight: &[ClientRef],
    ) -> Result<bool, Error> {
        let Some(seed) = &self.state.retiring_seed else {
            return Ok(false);
        };
        let minute = now.saturating_sub(now % MINUTE_MS);
        let Some(slot) = next.outbox.iter_mut().find(|entry| {
            entry.kind == OutboxKind::KeyRetired
                && entry.sent_at != minute
                && !in_flight.contains(&ClientRef::of(entry))
        }) else {
            return Ok(false);
        };
        *slot = self.seal_retirement(seed, now)?;
        Ok(true)
    }

    /// With sixteen old keys, drops the first one whose blobs no member
    /// accepts any more, or else the first (R1): the list is in the order
    /// of regeneration, which a clock set back does not change.
    fn make_room_for_old_key(&self, next: &mut ChannelState, now: u64) {
        if next.own_old_keys.len() < MAX_OLD_KEYS {
            return;
        }
        let reach = self.accept_window().saturating_mul(2);
        let index = next
            .own_old_keys
            .iter()
            .position(|old| old.retired_at.saturating_add(reach) < now)
            .unwrap_or(0);
        if index < next.own_old_keys.len() {
            next.own_old_keys.remove(index);
        }
    }

    /// The `key_retired` of the key of `seed`, dated at the minute of
    /// `now`, as the `outbox` entry kept for it (R2, R4).
    ///
    /// # Errors
    ///
    /// `Internal` when libsodium fails.
    fn seal_retirement(&self, seed: &Secret<32>, now: u64) -> Result<OutboxEntry, Error> {
        let payload = Payload {
            kind: PayloadKind::KeyRetired,
            display_name: None,
            sent_at: now.saturating_sub(now % MINUTE_MS),
            body: Vec::new(),
        };
        let sender = SenderKey::from_seed(seed)?;
        let nonce = Nonce(crypto::random_bytes()?);
        let ctx = ChannelCtx::from_config(&self.config)?;
        let sealed = envelope::seal(&ctx, &sender, KEY_RETIRED_COUNTER, &nonce, &payload)?;
        let client_ref = ClientRef {
            bytes: crypto::random_bytes()?,
        };
        Ok(OutboxEntry {
            client_ref: client_ref.bytes,
            kind: OutboxKind::KeyRetired,
            sent_at: payload.sent_at,
            blob: sealed.blob,
            signature: Signature(sealed.signature),
            under_retired_key: true,
            counter: KEY_RETIRED_COUNTER,
        })
    }
}
