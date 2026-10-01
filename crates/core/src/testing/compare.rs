//! Comparisons of states and records for the tests, which cannot use `==`:
//! `ChannelState` and `LogRecord` implement neither `PartialEq` nor `Debug`,
//! since they hold secrets.

use crate::storage::{ChannelState, LogRecord};

/// Whether `a` and `b` hold the same state, field by field, the seeds
/// compared in constant time through `Secret`'s `PartialEq`. The store's own
/// `log_committed_len` and `log_generation` are ignored: a store sets them
/// at each commit. A list item is compared by its canonical encoding, which
/// holds each field at its own key.
pub fn state_eq(a: &ChannelState, b: &ChannelState) -> bool {
    let items =
        |a: Result<Vec<_>, _>, b: Result<Vec<_>, _>| matches!((a, b), (Ok(a), Ok(b)) if a == b);
    a.channel_id == b.channel_id
        && a.config.as_slice() == b.config.as_slice()
        && a.identity_seed == b.identity_seed
        && a.identity_epoch == b.identity_epoch
        && a.send_counter == b.send_counter
        && a.cursor == b.cursor
        && a.own_display_name == b.own_display_name
        && a.local_name == b.local_name
        && items(
            a.peers.iter().map(|peer| peer.encode()).collect(),
            b.peers.iter().map(|peer| peer.encode()).collect(),
        )
        && items(
            a.outbox.iter().map(|entry| entry.encode()).collect(),
            b.outbox.iter().map(|entry| entry.encode()).collect(),
        )
        && a.retiring_seed == b.retiring_seed
        && items(
            a.own_old_keys.iter().map(|key| key.encode()).collect(),
            b.own_old_keys.iter().map(|key| key.encode()).collect(),
        )
        && a.own_key_used_elsewhere == b.own_key_used_elsewhere
        && a.read_only == b.read_only
        && a.synced_at == b.synced_at
        && a.truncated_at == b.truncated_at
}

/// Whether `a` and `b` hold the same records in the same order, each
/// compared by its canonical encoding at one fixed place, so that where a
/// store put it does not count.
pub fn records_eq(a: &[LogRecord], b: &[LogRecord]) -> bool {
    a.len() == b.len()
        && a.iter()
            .zip(b)
            .all(|(a, b)| match (a.encode(0, 0), b.encode(0, 0)) {
                (Ok(a), Ok(b)) => a == b,
                _ => false,
            })
}
