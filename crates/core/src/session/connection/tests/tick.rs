//! Tests of spec 028 R14 on a tick: a subscribed channel publishes its
//! `outbox`, every other channel of the session drops its stale entries,
//! and a failed `expire_outbox` freezes the channel (R10).

use super::traffic::{alice, published};
use super::{T0, channel, connected, hello, ids, ok, reconnect};
use crate::session::connection::Event;
use crate::storage::StoreError;

/// A minute-long channel.
const MINUTE: u32 = 60;

/// When an entry sealed at `T0` in a one-minute channel is stale: past
/// its `ttl_ms + 360 000` window.
const STALE: u64 = T0 + 60_000 + 360_000 + 1;

/// Spec 028, R14: a tick publishes what a subscribed channel's `outbox`
/// holds, once; a stale entry found on a tick → `NotDelivered`, for a
/// subscribed channel and for one of the session not subscribed, also
/// between connections, which queue nothing.
#[test]
fn s028_t14_r14_tick() {
    let mut channels = vec![channel(1, MINUTE, T0), channel(2, MINUTE, T0)];
    let [one, two]: [[u8; 16]; 2] = ids(&channels).try_into().unwrap();
    let mut session = connected(&channels, T0);
    session.on_frame(&hello(1, &[1]), &mut channels, T0);
    session.on_frame(&ok(one), &mut channels, T0 + 100);
    session.outgoing();
    // Sealed without `after_send`: the tick publishes it.
    let sent = channels[0].encrypt("hi", None, T0 + 100).unwrap();
    session.on_tick(&mut channels, T0 + 1_000);
    assert_eq!(published(&mut session), [sent]);
    session.on_tick(&mut channels, T0 + 2_000);
    assert_eq!(published(&mut session), []);

    let mut stale = vec![channels[0].encrypt("late", None, T0).unwrap()];
    stale.push(channels[1].encrypt("waiting", None, T0).unwrap());
    let step = session.on_tick(&mut channels, STALE);
    let reported: Vec<_> = step
        .events
        .iter()
        .filter_map(|event| match event {
            Event::NotDelivered {
                channel,
                client_ref,
                sent_at: T0,
            } => Some((*channel, *client_ref)),
            _ => None,
        })
        .collect();
    assert_eq!(reported, [(one, stale[0]), (two, stale[1])]);
    assert!(step.failed.is_empty());

    session.on_disconnect();
    // Out of flight, the first publish has no grace any more.
    let offline = channels[1].encrypt("offline", None, T0).unwrap();
    let step = session.on_tick(&mut channels, STALE + 1_000);
    let expected = [(one, sent), (two, offline)].map(|(channel, client_ref)| Event::NotDelivered {
        channel,
        client_ref,
        sent_at: T0,
    });
    assert_eq!(step.events, expected);
    assert!(session.outgoing().is_empty());
}

/// Spec 028, R14 and R10: an `expire_outbox` whose commit fails → the
/// channel in `failed` and frozen, called no more on this connection; a
/// marked channel not subscribed with a stale entry → no `expire_outbox`
/// and no `NotDelivered` while marked.
#[test]
fn s028_t14_r14_expire_failure_freezes() {
    let (mut channels, handle, faults) = alice();
    let id = ids(&channels)[0];
    channels[0].encrypt("stale", None, T0).unwrap();
    let mut session = connected(&channels, T0);
    let day_later = T0 + 86_400_000 + 360_001;

    // No `hello` came: each tick asks for a new connection (R7).
    faults.fail_commits(true);
    let step = session.on_tick(&mut channels, day_later);
    faults.fail_commits(false);
    assert_eq!(step.failed, [(id, StoreError::Io)]);
    assert_eq!(step.events, [reconnect()]);
    let commits = handle.all_commits();
    let step = session.on_tick(&mut channels, day_later + 1_000);
    assert_eq!(step.events, [reconnect()]);
    assert!(step.failed.is_empty());
    assert_eq!(handle.all_commits(), commits);

    // Marked, across connections: still not called.
    session.set_write_failed(&channels[0], true, false);
    session.on_disconnect();
    session.on_connect(day_later + 2_000, &[]);
    let step = session.on_tick(&mut channels, day_later + 3_000);
    assert!(
        step.events.is_empty() && step.failed.is_empty(),
        "{:?}",
        step.events
    );
    assert_eq!(handle.all_commits(), commits);

    // Cleared, on a new connection: the entry leaves.
    session.set_write_failed(&channels[0], false, false);
    session.on_disconnect();
    session.on_connect(day_later + 4_000, &[]);
    let step = session.on_tick(&mut channels, day_later + 5_000);
    assert!(
        matches!(step.events[..], [Event::NotDelivered { channel, .. }] if channel == id),
        "{:?}",
        step.events
    );
}
