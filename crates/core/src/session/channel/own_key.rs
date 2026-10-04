//! Messages from one's own key (spec 021 R13–R15, R19, ADR 0029): an echo
//! is told by the signature this device kept, never by a counter.

use super::{Channel, Received};
use crate::error::Error;
use crate::proto::envelope::Verified;

impl Channel {
    /// Step 6 and on for a blob from one's own `pk_u` (R13, R14).
    ///
    /// # Errors
    ///
    /// `Replay` for every such blob until slice (d1) of spec 021 brings
    /// the echo rule and the own-key event; nothing is committed.
    pub(super) fn receive_own(
        &mut self,
        _verified: Verified<'_>,
        _server_id: [u8; 16],
        _received_at: u64,
        _now: u64,
    ) -> Result<Option<Received>, Error> {
        Err(Error::Replay)
    }
}
