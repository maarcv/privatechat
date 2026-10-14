//! The exit test of phase 2 (spec 027-core-api R23, `docs/spec.md` §10):
//! two `Device`s over data directories on disk, one shared channel, an
//! exchange server in memory, 10 000 messages with duplicated pushes and a
//! failed commit on each side; then a process killed between the append to
//! the log and the write of the state, reopened and resumed.

use std::collections::BTreeMap;
use std::path::Path;

use privatechat_core::testing::{FailingVault, Faults, MemoryServer, state_eq};
use privatechat_core::{Device, Error, Event, LogRecord, MessageContent, StoreError, Vault};
use proptest::test_runner::{Config, TestRunner};

use super::{TestDir, open_with, run_helper};
use crate::fs::Io;
use crate::fs::test::{CRASH_STATUS, CRASH_VAR};

/// The host of the channel and of the server.
const HOST: &str = "example.org";
/// The start of the simulated time, a whole minute.
const T0: u64 = 1_790_000_040_000;
/// Messages sent by each device.
const PER_SIDE: usize = 5_000;
/// The time between two sends of one device.
const SEND_EVERY: u64 = 3_000;
/// The time between two ticks.
const TICK: u64 = 1_000;
/// The channel's TTL: an hour, far above the queueing delay, and short
/// enough that the four-hour run compacts.
const TTL_SECONDS: u32 = 3_600;
/// The quiet time after the last send, for the last messages to arrive.
const DRAIN: u64 = 600_000;
/// The socket number of the second device, apart from the first's plan ids.
const SECOND_SOCKETS: u64 = 1_000;
/// One push in this many is delivered twice.
const DUPLICATE_ONE_IN: u64 = 100;
/// The append the crash run stops at, counted over both sides: past the
/// first compaction, so that the reopen reads a compacted log.
const CRASH_APPEND: u64 = 26_000;
/// The most `Reconnect`s a side may see: none but the probe's after the
/// injected failure, and a session's after its socket was refused.
const MAX_RECONNECTS: u32 = 2;
/// The environment variables of the crash run's child.
const DIR_VAR: &str = "PRIVATECHAT_PHASE2_DIR";

/// One side of the exchange: its device, its faults, and what it saw.
struct Side {
    device: Device,
    faults: Faults,
    /// The socket number added to each plan `id` on the server.
    sockets: u64,
    /// The plan ids with an open socket.
    connected: Vec<u64>,
    /// The bodies received, with how many times each came.
    received: BTreeMap<String, u32>,
    /// The errors the calls returned.
    errors: u32,
    /// The `StorageFailed` events, each a store reopened (R14).
    storage_failed: u32,
    /// The `Reconnect`s asked for.
    reconnects: u32,
    /// The events no run of R23 should see, by kind.
    unexpected: Vec<&'static str>,
    /// The side's one failed commit, not yet armed.
    fault: Option<Fault>,
}

/// Where a side's one failed commit lands: the first of its kind from a
/// time on, so that each recovery path of R14 runs in every run.
#[derive(Clone, Copy)]
enum Fault {
    /// The commit of a `send`, recovered by the call (R9).
    Send(u64),
    /// The commit of a received frame, recovered through the session's
    /// step.
    Receive(u64),
}

impl Side {
    /// Fails the next commit when the side's fault is of this kind, a
    /// received frame or a `send`, and its time came.
    fn arm(&mut self, now: u64, receive: bool) {
        let due = match self.fault {
            Some(Fault::Send(at)) => !receive && at <= now,
            Some(Fault::Receive(at)) => receive && at <= now,
            None => false,
        };
        if due {
            self.faults.fail_at(1);
            self.fault = None;
        }
    }

    /// A device over a fast data directory at `path`, behind `faults`.
    fn open(path: &Path, faults: &Faults, sockets: u64, now: u64) -> Side {
        let data = open_with(path, Io::fast).expect("fast data directory");
        let vault = FailingVault::new(Box::new(data), faults.clone());
        Side {
            device: Device::open(Box::new(vault), now).expect("open"),
            faults: faults.clone(),
            sockets,
            connected: Vec::new(),
            received: BTreeMap::new(),
            errors: 0,
            storage_failed: 0,
            reconnects: 0,
            unexpected: Vec::new(),
            fault: None,
        }
    }

    /// Opens a socket for every plan without one and forgets the plans that
    /// are gone (spec 027-core-api R11).
    fn reconcile(&mut self, server: &mut MemoryServer, now: u64) {
        let plans: Vec<u64> = self
            .device
            .connections()
            .iter()
            .map(|plan| plan.id)
            .collect();
        for id in self.connected.clone() {
            if !plans.contains(&id) {
                server.disconnect(id + self.sockets);
                self.connected.retain(|open| *open != id);
            }
        }
        for id in plans {
            if !self.connected.contains(&id) {
                server.connect(id + self.sockets, now);
                self.device.on_connect(id, now);
                self.connected.push(id);
            }
        }
    }

    /// Takes the events: a message counted by its body, a `Reconnect`
    /// closing its socket for the next `reconcile`.
    fn take(&mut self, events: Vec<Event>, server: &mut MemoryServer) {
        for event in events {
            match event {
                Event::Message { received, .. } => {
                    if let MessageContent::Text { body, .. } = received.content {
                        *self.received.entry(body).or_default() += 1;
                    }
                }
                Event::StorageFailed { .. } => self.storage_failed += 1,
                Event::Reconnect { connection } => {
                    self.reconnects += 1;
                    self.device.on_disconnect(connection);
                    server.disconnect(connection + self.sockets);
                    self.connected.retain(|open| *open != connection);
                }
                Event::NotDelivered { .. } => self.unexpected.push("NotDelivered"),
                Event::HistoryTruncated { .. } => self.unexpected.push("HistoryTruncated"),
                Event::SubscribeRefused { .. } => self.unexpected.push("SubscribeRefused"),
                Event::ChannelFull { .. } => self.unexpected.push("ChannelFull"),
                Event::ServerFull { .. } => self.unexpected.push("ServerFull"),
                Event::UnsupportedServer { .. } => self.unexpected.push("UnsupportedServer"),
                Event::Subscribed { .. }
                | Event::Delivered { .. }
                | Event::StatusChanged { .. } => {}
            }
        }
    }

    /// Moves frames both ways until quiet; a push whose index `duplicate`
    /// names is delivered twice.
    fn pump(&mut self, server: &mut MemoryServer, now: u64, duplicate: &mut Duplicates) {
        self.arm(now, true);
        for _ in 0..20 {
            let mut moved = false;
            for id in self.connected.clone() {
                for frame in self.device.outgoing(id) {
                    server.receive(id + self.sockets, &frame, now);
                    moved = true;
                }
                for frame in server.read(id + self.sockets, 200) {
                    let twice = duplicate.next(&frame);
                    let events = self.device.on_frame(id, &frame, now);
                    self.take(events, server);
                    if twice {
                        let events = self.device.on_frame(id, &frame, now);
                        let message = |event: &Event| matches!(event, Event::Message { .. });
                        duplicate.rejected += u32::from(!events.iter().any(message));
                        self.take(events, server);
                    }
                    moved = true;
                }
            }
            if !moved {
                break;
            }
        }
    }

    /// Sends `body`; an error, which only the injected commit may cause, is
    /// counted and the send tried again on the reopened store.
    fn send(&mut self, channel: [u8; 16], body: &str, now: u64, server: &mut MemoryServer) {
        self.arm(now, false);
        match self.device.send(channel, body, None, now) {
            Ok(sent) => self.take(sent.events, server),
            Err(error) => {
                // The injected fault fails a commit with `Io`, and only so.
                assert_eq!(error, Error::Store(StoreError::Io));
                self.errors += 1;
                let sent = self
                    .device
                    .send(channel, body, None, now)
                    .expect("send again");
                self.take(sent.events, server);
            }
        }
    }
}

/// Which pushes are delivered twice, from a seed the proptest draws.
struct Duplicates {
    seed: u64,
    next: u64,
    /// Pushes delivered twice.
    count: u32,
    /// Second deliveries that produced no message.
    rejected: u32,
}

impl Duplicates {
    /// The pushes `seed` marks, none delivered yet; `None` marks none.
    fn new(seed: Option<u64>) -> Duplicates {
        Duplicates {
            seed: seed.unwrap_or(0),
            next: if seed.is_some() { 0 } else { u64::MAX },
            count: 0,
            rejected: 0,
        }
    }

    /// Whether this frame, a push, is the next one marked.
    fn next(&mut self, frame: &[u8]) -> bool {
        let push = matches!(
            privatechat_core::Frame::decode(frame),
            Ok(privatechat_core::Frame::Push { .. })
        );
        if !push {
            return false;
        }
        if self.next == u64::MAX {
            return false;
        }
        // SplitMix64 of the seed and the push's index: one in a hundred.
        let mut z = self
            .seed
            .wrapping_add(self.next.wrapping_mul(0x9e37_79b9_7f4a_7c15));
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        let marked = (z ^ (z >> 31)).is_multiple_of(DUPLICATE_ONE_IN);
        self.next += 1;
        self.count += u32::from(marked);
        marked
    }
}

/// The two sides, the channel they share, and the server, at `now`.
fn start(dir: &Path, faults: [&Faults; 2], now: u64) -> (Side, Side, [u8; 16]) {
    let mut first = Side::open(&dir.join("a"), faults[0], 0, now);
    let mut second = Side::open(&dir.join("b"), faults[1], SECOND_SOCKETS, now);
    let channel = match first.device.channels().first() {
        Some(info) => info.id,
        None => {
            let info = first
                .device
                .create_channel("wss://example.org", TTL_SECONDS, "exit", now)
                .expect("create");
            let qr = first.device.export_qr(info.id, now).expect("export");
            second.device.import_qr(&qr, false, now).expect("import");
            info.id
        }
    };
    (first, second, channel)
}

/// Runs the exchange from `from`, each side sending `count` messages
/// numbered from `offset`, then `DRAIN` of quiet; returns the time it ended.
fn exchange(
    sides: &mut [Side; 2],
    server: &mut MemoryServer,
    channel: [u8; 16],
    (from, offset, count): (u64, usize, usize),
    duplicate: &mut Duplicates,
) -> u64 {
    let end = from + count as u64 * SEND_EVERY + DRAIN;
    let mut now = from;
    while now <= end {
        for side in sides.iter_mut() {
            side.reconcile(server, now);
            let events = side.device.on_tick(now);
            side.take(events, server);
        }
        let step = (now - from) / SEND_EVERY;
        if (now - from) % SEND_EVERY == 0 && (step as usize) < count {
            for (name, side) in ["a", "b"].iter().zip(sides.iter_mut()) {
                let body = format!("{name}-{}", offset + step as usize);
                side.send(channel, &body, now, server);
            }
        }
        for side in sides.iter_mut() {
            side.pump(server, now, duplicate);
        }
        now += TICK;
    }
    end
}

/// Checks that each side received every message of the other once, and
/// nothing else: none of its own, whose echo is not a message.
fn check_delivered(sides: &[Side; 2], range: std::ops::Range<usize>) {
    for (from, to) in [("a", &sides[1]), ("b", &sides[0])] {
        for n in range.clone() {
            let body = format!("{from}-{n}");
            assert_eq!(to.received.get(&body), Some(&1), "{body}");
        }
        assert_eq!(to.received.len(), range.len(), "a message not sent");
    }
}

/// Spec 027, R23: two devices exchange 10 000 messages, 5 000 each, one
/// every 3 s, with 1 % of the pushes delivered twice and one commit failed
/// on each side: no error but the injected ones, every message delivered
/// once, every duplicate rejected, each reopened state equal to the last
/// committed, and the log compacted.
#[test]
fn s027_t23_r23_phase2_exit() {
    let mut runner = TestRunner::new(Config {
        cases: 1,
        max_shrink_iters: 0,
        failure_persistence: None,
        ..Config::default()
    });
    // The step from which each side's failed commit is armed.
    let draws = (0u64..1_000, 0u64..1_000, proptest::num::u64::ANY);
    runner
        .run(&draws, |(fail_a, fail_b, seed)| {
            exit_run(fail_a, fail_b, seed);
            Ok(())
        })
        .expect("the run");
}

/// One run of R23's first half.
fn exit_run(fail_a: u64, fail_b: u64, seed: u64) {
    let dir = TestDir::new("phase2-exit");
    let faults = [Faults::new(), Faults::new()];
    let (mut first, mut second, channel) = start(dir.path(), [&faults[0], &faults[1]], T0);
    first.fault = Some(Fault::Send(T0 + TICK + fail_a * SEND_EVERY));
    second.fault = Some(Fault::Receive(T0 + TICK + fail_b * SEND_EVERY));
    let mut sides = [first, second];
    let mut server = MemoryServer::new(&[HOST]);
    let mut duplicate = Duplicates::new(Some(seed));
    let end = exchange(
        &mut sides,
        &mut server,
        channel,
        (T0 + TICK, 0, PER_SIDE),
        &mut duplicate,
    );
    check_delivered(&sides, 0..PER_SIDE);
    assert!(duplicate.count > 0, "no push was duplicated");
    assert_eq!(
        duplicate.rejected, duplicate.count,
        "a duplicate was not rejected"
    );
    // Each injected commit reopened its store once: the first side's
    // failed its `send`, the second's a session's step, and no other call
    // failed.
    for (side, errors) in sides.iter().zip([1, 0]) {
        assert!(side.fault.is_none(), "the fault was never armed");
        assert_eq!(side.errors, errors);
        assert_eq!(side.storage_failed, 1);
        assert!(side.unexpected.is_empty(), "{:?}", side.unexpected);
        assert!(
            side.reconnects <= MAX_RECONNECTS,
            "{} reconnects",
            side.reconnects
        );
        assert!(side.device.status().broken.is_empty());
        assert!(side.device.channels().iter().all(|info| !info.write_failed));
    }
    let [first, second] = sides;
    for (side, path) in [(first, "a"), (second, "b")] {
        let faults = side.faults.clone();
        let mut device = side.device;
        device.flush(end).expect("flush");
        drop(device);
        check_reopened(&dir.path().join(path), &faults);
    }
}

/// Each store of the data directory at `path` reloads the state its last
/// commit wrote, and its log was compacted: no record is left that expired
/// in the first two hours of the run.
fn check_reopened(path: &Path, faults: &Faults) {
    let mut data = open_with(path, Io::fast).expect("reopen");
    let stores = data.list().expect("list");
    assert_eq!(stores.len(), 1);
    for mut store in stores {
        let (state, records) = store.load().expect("load").expect("a state");
        let last = faults.last_committed(store.name()).expect("a commit");
        assert!(state_eq(&state, &last));
        let (_, generation) = state.log_position();
        assert!(generation > 0, "no compaction ran");
        let oldest = records.iter().map(LogRecord::purge_at).min();
        assert!(
            oldest.is_some_and(|at| at > T0 + 2 * 3_600_000),
            "{oldest:?}"
        );
    }
}

/// Spec 027, R23: a run killed by a crash point after an append to the log
/// reopens both directories without `Corrupt`, the log cut back to its
/// committed length, and the exchange resumes on the same channel with a
/// fresh server.
#[test]
fn s027_t23_r23_phase2_exit_after_a_crash() {
    let dir = TestDir::new("phase2-crash");
    let path = dir.path().to_str().expect("a UTF-8 path");
    let crash = format!("after_append:{CRASH_APPEND}");
    let status = run_helper(
        "tests::phase2_exit::s027_t23_r23_crash_child",
        &[(DIR_VAR, path), (CRASH_VAR, &crash)],
    );
    assert_eq!(status, Some(CRASH_STATUS));
    let mut cut = false;
    let mut compacted = false;
    let mut ids = Vec::new();
    for side in ["a", "b"] {
        let channels = dir.path().join(side).join("channels");
        let mut data = open_with(&dir.path().join(side), Io::fast).expect("reopen");
        let stores = data.list().expect("list");
        assert_eq!(stores.len(), 1);
        for mut store in stores {
            let log = channels.join(store.name().to_hex()).join("messages.log");
            let before = std::fs::metadata(&log).expect("the log").len();
            let (state, _) = store
                .load()
                .map_err(|error| assert_ne!(error, StoreError::Corrupt))
                .expect("load")
                .expect("a state");
            let (committed, generation) = state.log_position();
            let after = std::fs::metadata(&log).expect("the log").len();
            assert_eq!(after, committed);
            cut |= before > committed;
            compacted |= generation > 0;
            ids.push(state.channel_id());
        }
    }
    assert!(cut, "no append was left past the committed length");
    assert!(compacted, "the crash came before any compaction");
    assert_eq!(ids.first(), ids.get(1));

    let now = T0 + 7_200_000;
    let faults = [Faults::new(), Faults::new()];
    let (first, second, channel) = start(dir.path(), [&faults[0], &faults[1]], now);
    for side in [&first, &second] {
        let listed: Vec<[u8; 16]> = side.device.channels().iter().map(|info| info.id).collect();
        assert_eq!(listed, [channel]);
        assert_eq!(Some(&channel), ids.first());
        assert!(side.device.status().broken.is_empty());
    }
    let mut sides = [first, second];
    let mut server = MemoryServer::new(&[HOST]);
    let mut duplicate = Duplicates::new(None);
    exchange(
        &mut sides,
        &mut server,
        channel,
        (now, 100_000, 20),
        &mut duplicate,
    );
    check_delivered(&sides, 100_000..100_020);
}

/// The child of the crash run: the exchange in the directory of
/// `DIR_VAR`, until the crash point stops the process; returns at once in a
/// normal run.
#[test]
fn s027_t23_r23_crash_child() {
    let Ok(path) = std::env::var(DIR_VAR) else {
        return;
    };
    let path = Path::new(&path);
    let faults = [Faults::new(), Faults::new()];
    let (first, second, channel) = start(path, [&faults[0], &faults[1]], T0);
    let mut sides = [first, second];
    let mut server = MemoryServer::new(&[HOST]);
    let mut duplicate = Duplicates::new(None);
    exchange(
        &mut sides,
        &mut server,
        channel,
        (T0 + TICK, 0, PER_SIDE),
        &mut duplicate,
    );
}
