//! Tests of spec 028 R14 on a tick: a subscribed channel publishes its
//! `outbox`, every other channel of the session drops its stale entries,
//! a failed `expire_outbox` freezes the channel (R10), and a truncation
//! banner that lapses on a tick shows (R13).

use super::traffic::{alice, published};
use super::{DAY, SERVER, T0, channel, connected, hello, ids, ok, reconnect};
use crate::crypto::Secret;
use crate::proto::config::Config;
use crate::session::channel::Channel;
use crate::session::connection::Event;
use crate::storage::{StoreError, Vault};
use crate::testing::MemoryVault;

/// A minute-long channel.
const MINUTE: u32 = 60;

/// When an entry sealed at `T0` in a one-minute channel is stale: past
/// its `ttl_ms + 360 000` window.
const STALE: u64 = T0 + 60_000 + 360_000 + 1;

/// Spec 028, R14: a tick publishes what a subscribed channel's `outbox`
/// holds, once, and nothing of a channel awaiting its `ok`; a stale entry
/// found on a tick → `NotDelivered`, for a subscribed channel and for one
/// of the session not subscribed, also between connections, which queue
/// nothing.
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

    // Awaiting its `ok`, a channel publishes nothing: its backlog may hold
    // the own-key message that stops it (R10).
    let mut channels = vec![channel(3, MINUTE, T0)];
    let id = ids(&channels)[0];
    let mut session = connected(&channels, T0);
    session.on_frame(&hello(1, &[1]), &mut channels, T0);
    session.outgoing();
    let early = channels[0].encrypt("early", None, T0).unwrap();
    session.on_tick(&mut channels, T0 + 50);
    assert_eq!(published(&mut session), []);
    session.on_frame(&ok(id), &mut channels, T0 + 100);
    assert_eq!(published(&mut session), [early]);
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

/// Spec 028, R13: a truncation banner that lapses on a tick, or at the
/// `synced` of an `ok`, → `StatusChanged` once; a channel of another connection among the
/// `Device`'s, its peers changed, is not reported by this session's ticks.
#[test]
fn s028_t13_r13_banner_lapses_on_tick() {
    let k_ch = Secret::from_bytes([9; 32]);
    let config = Config::from_parts(k_ch, SERVER, DAY, "other", T0).unwrap();
    let store = MemoryVault::new().create(&config.channel_id()).unwrap();
    // Not read by the `Device` yet: its peers count as changed.
    let other = Channel::create(&config, store).unwrap().0;
    let mut channels = vec![channel(1, MINUTE, T0 - 10 * 86_400_000)];
    let id = ids(&channels)[0];
    let mut session = connected(&channels, T0);
    channels.push(other);
    session.on_frame(&hello(1, &[1]), &mut channels, T0);
    session.on_frame(&ok(id), &mut channels, T0);
    assert!(channels[0].status().truncated_before.is_some());
    let mut changes = Vec::new();
    for at in (1..=430).map(|second| T0 + second * 1_000) {
        for event in session.on_tick(&mut channels, at).events {
            changes.push((at, event));
        }
    }
    let status = Event::StatusChanged { channel: id };
    assert!(
        matches!(&changes[..], [(_, event)] if *event == status),
        "{changes:?}"
    );
    assert!(channels[1].take_peers_changed());

    // Ticks up to a second before the banner lapses, then a new connection
    // whose `ok` comes after it: that `ok` reports it.
    let mut channels = vec![channel(1, MINUTE, T0 - 10 * 86_400_000)];
    let mut session = connected(&channels, T0);
    session.on_frame(&hello(1, &[1]), &mut channels, T0);
    session.on_frame(&ok(id), &mut channels, T0);
    for at in (1..=418).map(|second| T0 + second * 1_000) {
        session.on_tick(&mut channels, at);
    }
    session.on_disconnect();
    session.on_connect(T0 + 419_000, &[]);
    session.on_frame(&hello(2, &[1]), &mut channels, T0 + 419_000);
    assert!(channels[0].status().truncated_before.is_some());
    let step = session.on_frame(&ok(id), &mut channels, T0 + 420_500);
    assert!(channels[0].status().truncated_before.is_none());
    assert_eq!(step.events, [Event::Subscribed { channel: id }, status]);
}
