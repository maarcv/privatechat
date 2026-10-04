//! Tests of the values that move without a message: R20 without its cursor
//! half, and the R32 clauses of `synced`, `flush` and `probe`.

use super::{SERVER, config_on, config_with, failing_channel, new_channel, reopened};
use crate::Error;
use crate::storage::StoreError;
use crate::testing::state_eq;

const T0: u64 = 1_000_000;

/// Spec 021, R20: `synced` sets `synced_at` and leaves the cursor; a
/// `synced`-only commit happens once per `min(ttl_ms / 2, 3 600 000)` and
/// at once when the committed value is ahead; `flush` commits the pending
/// values, `probe` commits even with nothing pending.
#[test]
fn s021_t20_r20_synced_flush_probe() {
    let (mut channel, handle) = new_channel();
    channel.synced(T0).unwrap();
    assert_eq!(channel.synced_at(), Some(T0));
    assert_eq!(channel.cursor(), None);
    // A `synced_at`-only commit is not one of AGENTS 23's.
    assert_eq!((handle.commits(), handle.all_commits()), (1, 2));
    // A one-hour channel: one commit per half hour.
    channel.synced(T0 + 1_800_000).unwrap();
    assert_eq!(handle.all_commits(), 2);
    channel.synced(T0 + 1_800_001).unwrap();
    assert_eq!(handle.all_commits(), 3);
    assert_eq!(reopened(&handle).synced_at(), Some(T0 + 1_800_001));
    // A clock set back lowers it, committed at once.
    channel.synced(T0).unwrap();
    assert_eq!(channel.synced_at(), Some(T0));
    assert_eq!(handle.all_commits(), 4);

    // A day-long channel: one commit per hour.
    let (mut day, _, _) = failing_channel(&config_with(86_400));
    day.synced(T0).unwrap();
    day.synced(T0 + 3_600_000).unwrap();
    assert_eq!(day.state.synced_at, Some(T0));
    day.synced(T0 + 3_600_001).unwrap();
    assert_eq!(day.state.synced_at, Some(T0 + 3_600_001));

    let (mut channel, handle) = new_channel();
    channel.flush(T0).unwrap();
    assert_eq!(handle.all_commits(), 1);
    channel.cursor = Some(5_000);
    channel.truncated_at = Some(4_000);
    channel.synced_at = Some(T0);
    channel.flush(T0).unwrap();
    assert_eq!(handle.all_commits(), 2);
    let stored = reopened(&handle);
    assert_eq!(stored.cursor(), Some(5_000));
    assert_eq!(stored.synced_at(), Some(T0));
    assert_eq!(stored.truncated_at, Some(4_000));
    channel.probe(T0).unwrap();
    assert_eq!(handle.all_commits(), 3);
}

/// Spec 021, R32: `synced`, `flush` and `probe` under a failing commit
/// leave the stored state as before.
#[test]
fn s021_t32_r32_failing_sync_methods() {
    let (mut channel, handle, faults) = failing_channel(&config_on(SERVER));
    let before = channel.state.duplicate();
    faults.fail_commits(true);
    let io = Err(Error::Store(StoreError::Io));
    assert_eq!(channel.synced(T0), io);
    channel.cursor = Some(5_000);
    assert_eq!(channel.flush(T0), io);
    assert_eq!(channel.probe(T0), io);
    assert!(state_eq(&channel.state, &before));
    assert!(state_eq(&reopened(&handle).state, &before));
}
