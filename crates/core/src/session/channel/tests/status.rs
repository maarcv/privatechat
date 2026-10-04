//! Tests of the reads and the clock sample (R25), of leaving (R27), and of
//! the R32 clause of `leave`.

use super::{
    DAY_MS, HOUR_MS, NOW, SERVER, config_on, config_with, failing_channel, new_channel, reopened,
};
use crate::Error;
use crate::storage::{Store, StoreError};

/// A clock sample `(received_at, now, live)` and `clock_off` after it.
type Sample = (u64, u64, bool, bool);

/// Spec 021, R25: the six reads commit nothing; the clock sample sets and
/// clears `clock_off` as its kind allows; `truncated_before` follows the
/// latest `now`.
#[test]
fn s021_t25_r25_reads_do_not_commit() {
    let (channel, handle) = new_channel();
    let _ = (channel.cursor(), channel.synced_at(), channel.status());
    let _ = (
        channel.gaps(),
        channel.config().channel_id(),
        channel.dir_name(),
    );
    assert_eq!(handle.all_commits(), 1);
    let status = channel.status();
    assert!(!status.storage_full && !status.retirement_pending && !status.clock_off);
    assert_eq!((status.ignored_keys, status.truncated_before), (0, None));

    // (TTL, samples as (received_at, now, live, `clock_off` after it)); a
    // backlog sample never clears a live sample's flag.
    let cases: [(u32, &[Sample]); 9] = [
        // Behind by the margin and one more millisecond.
        (
            3_600,
            &[
                (NOW + 360_000, NOW, true, false),
                (NOW + 360_001, NOW, true, true),
            ],
        ),
        // Ahead in a 60-second channel: half its TTL.
        (
            60,
            &[
                (NOW - 30_000, NOW, true, false),
                (NOW - 30_001, NOW, true, true),
            ],
        ),
        // A backlog sample changes no flag a live sample set.
        (
            3_600,
            &[
                (NOW + 360_001, NOW, true, true),
                (NOW + HOUR_MS, NOW, false, true),
                (NOW + HOUR_MS, NOW + HOUR_MS, false, true),
            ],
        ),
        (
            3_600,
            &[(NOW + DAY_MS, NOW, true, true), (NOW, NOW, true, false)],
        ),
        (3_600, &[(NOW - HOUR_MS, NOW, false, false)]),
        (
            3_600,
            &[
                (NOW + HOUR_MS, NOW, false, true),
                (NOW - 1_000, NOW + 1_000, false, true),
                (NOW, NOW, true, false),
            ],
        ),
        (
            3_600,
            &[
                (NOW - 360_000, NOW, true, false),
                (NOW - 360_001, NOW, true, true),
            ],
        ),
        (
            60,
            &[
                (NOW - 120_000, NOW, true, true),
                (NOW - 120_000, NOW, false, true),
            ],
        ),
        (
            3_600,
            &[
                (NOW + HOUR_MS, NOW, false, true),
                (NOW + HOUR_MS, NOW + HOUR_MS, false, false),
            ],
        ),
    ];
    for (ttl, samples) in cases {
        let (mut channel, _, _) = failing_channel(&config_with(ttl));
        for &(received_at, now, live, off) in samples {
            channel.clock_sample(received_at, now, live);
            assert_eq!(
                channel.status().clock_off,
                off,
                "{ttl} {received_at} {now} {live}"
            );
        }
    }
    // A push 120 000 ms behind is legitimately old.
    let (mut channel, _, _) = failing_channel(&config_with(60));
    channel.clock_sample(NOW - 120_000, NOW, false);
    assert!(!channel.status().clock_off);

    // Before any timed call, then until `truncated_at + ttl_ms + 360 000`.
    let (mut fresh, _) = new_channel();
    fresh.truncated_at = Some(NOW);
    assert_eq!(fresh.status().truncated_before, Some(NOW - HOUR_MS));
    fresh.synced(NOW + HOUR_MS + 360_000).unwrap();
    assert_eq!(fresh.status().truncated_before, Some(NOW - HOUR_MS));
    fresh.synced(NOW + HOUR_MS + 360_001).unwrap();
    assert_eq!(fresh.status().truncated_before, None);
    // A `truncated_at` a day ahead is read as `now`.
    fresh.truncated_at = Some(NOW + 2 * DAY_MS);
    fresh.synced(NOW + DAY_MS).unwrap();
    assert_eq!(
        fresh.status().truncated_before,
        Some(NOW + DAY_MS - HOUR_MS)
    );
}

/// Spec 021, R27 and R32: `leave` destroys the store; a failing `destroy`
/// returns its error and the channel still works.
#[test]
fn s021_t27_r27_leave() {
    let (mut channel, handle) = new_channel();
    channel.leave().unwrap();
    assert!(handle.reopen().load().unwrap().is_none());

    let (mut channel, handle, faults) = failing_channel(&config_on(SERVER));
    faults.fail_at(1);
    assert_eq!(channel.leave(), Err(Error::Store(StoreError::Io)));
    channel.encrypt("still here", None, NOW).unwrap();
    assert_eq!(reopened(&handle).send_counter(), 1);
}
