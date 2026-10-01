//! Tests of the comparisons the storage tests rely on (spec 020 T29).

use super::{batch, record, records_eq, state_eq, state_for};
use crate::crypto::{PublicKey, Secret};
use crate::storage::state::items::PeerRecord;

/// A peer seen once.
fn peer() -> PeerRecord {
    PeerRecord {
        pk: PublicKey([3; 32]),
        label: None,
        verified: false,
        muted: false,
        retired_at: None,
        first_seen: 1,
        last_seen: 1,
        max_counter: None,
        last_display_name: None,
    }
}

/// Spec 020, R29: `state_eq` sees a change in every field but the store's
/// log position, and `records_eq` a change in any record or in their order,
/// so that "`open(seal(x))` gives `x` under `state_eq`" means what it says.
#[test]
fn s020_t29_r29_comparisons_see_every_field() {
    let state = state_for([1; 16]);
    assert!(state_eq(&state, &state.duplicate().unwrap()));
    let mut moved = state.duplicate().unwrap();
    moved.log_committed_len = 99;
    moved.log_generation = 7;
    assert!(state_eq(&state, &moved));
    let changes: [fn(&mut crate::storage::ChannelState); 8] = [
        |s| s.channel_id = [2; 16],
        |s| s.config.push(0),
        |s| s.identity_seed = Secret::from_bytes([0x12; 32]),
        |s| s.send_counter = 1,
        |s| s.cursor = Some(0),
        |s| s.retiring_seed = Some(Secret::from_bytes([0x11; 32])),
        |s| s.read_only = true,
        |s| s.peers.push(peer()),
    ];
    for (at, change) in changes.iter().enumerate() {
        let mut changed = state.duplicate().unwrap();
        change(&mut changed);
        assert!(!state_eq(&state, &changed), "change {at}");
    }
    let records = [record(1, 10), record(2, 10)];
    let same = [record(1, 10), record(2, 10)];
    assert!(records_eq(&records, &same));
    assert!(!records_eq(&records, &[record(2, 10), record(1, 10)]));
    assert!(!records_eq(&records, &[record(1, 10), record(2, 11)]));
    assert!(!records_eq(&records, &records[..1]));
    let batch = batch(state, vec![record(3, 1)]);
    assert!(state_eq(batch.state(), &state_for([1; 16])));
    assert_eq!(batch.records().len(), 1);
}
