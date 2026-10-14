//! The exit test of phase 2 (spec 027-core-api R23, `docs/spec.md` §10):
//! two `Device`s over data directories on disk, one shared channel, an
//! exchange server in memory, 10 000 messages with duplicated pushes and a
//! failed commit on each side; then a process killed between the append to
//! the log and the write of the state, reopened and resumed.

use std::collections::BTreeMap;
use std::path::Path;

use privatechat_core::testing::{FailingVault, Faults, MemoryServer, records_eq, state_eq};
use privatechat_core::{
    ChannelStatus, Delivery, Device, Error, Event, LogRecord, MessageContent, Sender, StoreError,
    Vault,
};
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
/// first compaction, so that the reopen reads a compacted log, and the
/// append of a `send` while the other side's last send is still pending, so
/// that the resume delivers it.
const CRASH_APPEND: u64 = 26_000;
/// The most `Reconnect`s a side may see: none but the probe's after the
/// injected failure, and a session's after its socket was refused.
const MAX_RECONNECTS: u32 = 2;
/// The rounds of frames a `pump` may take before it must be quiet.
const PUMP_ROUNDS: usize = 20;
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
    /// The numbers of the bodies received, in the order they came.
    order: Vec<usize>,
    /// The errors the calls returned.
    errors: u32,
    /// The `StorageFailed` events, each a store reopened (R14).
    storage_failed: u32,
    /// The `Reconnect`s asked for.
    reconnects: u32,
    /// The `Subscribed` events.
    subscribed: u32,
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

/// The call whose commit is about to run.
#[derive(Clone, Copy)]
enum Step {
    /// A `send`.
    Send,
    /// The frames of a `pump`.
    Receive,
}

impl Side {
    /// Fails the next commit when the side's fault is of this step's kind
    /// and its time came.
    fn arm(&mut self, now: u64, step: Step) {
        let due = match (self.fault, step) {
            (Some(Fault::Send(at)), Step::Send) | (Some(Fault::Receive(at)), Step::Receive) => {
                at <= now
            }
            _ => false,
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
            order: Vec::new(),
            errors: 0,
            storage_failed: 0,
            reconnects: 0,
            subscribed: 0,
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
                    // Only the other side's messages arrive.
                    assert!(matches!(received.sender, Sender::Peer { .. }));
                    if let MessageContent::Text { body, .. } = received.content {
                        if let Some(n) = body.split_once('-').and_then(|(_, n)| n.parse().ok()) {
                            self.order.push(n);
                        }
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
                Event::Subscribed { .. } => self.subscribed += 1,
                Event::Delivered { .. } | Event::StatusChanged { .. } => {}
            }
        }
    }

    /// Moves frames both ways until quiet, in at most `PUMP_ROUNDS`; a push
    /// whose index `duplicate` marks, and that brought a message, is
    /// delivered twice.
    fn pump(&mut self, server: &mut MemoryServer, now: u64, duplicate: &mut Duplicates) {
        self.arm(now, Step::Receive);
        for round in 0..=PUMP_ROUNDS {
            let mut moved = false;
            for id in self.connected.clone() {
                for frame in self.device.outgoing(id) {
                    server.receive(id + self.sockets, &frame, now);
                    moved = true;
                }
                for frame in server.read(id + self.sockets, 200) {
                    let twice = duplicate.is_marked(&frame);
                    let events = self.device.on_frame(id, &frame, now);
                    let message = events
                        .iter()
                        .any(|event| matches!(event, Event::Message { .. }));
                    self.take(events, server);
                    // An echo of one's own message brings none: its second
                    // delivery would prove nothing.
                    if twice && message {
                        let events = self.device.on_frame(id, &frame, now);
                        duplicate.count += 1;
                        duplicate.rejected += u32::from(events.is_empty());
                        self.take(events, server);
                    }
                    moved = true;
                }
            }
            if !moved {
                break;
            }
            assert!(round < PUMP_ROUNDS, "frames still moving at {now}");
        }
    }

    /// Sends `body`; an error, which only the injected commit may cause, is
    /// counted and the send tried again on the reopened store.
    fn send(&mut self, channel: [u8; 16], body: &str, now: u64, server: &mut MemoryServer) {
        self.arm(now, Step::Send);
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
    /// The seed; `None` marks no push.
    seed: Option<u64>,
    /// The index of the next push.
    index: u64,
    /// Pushes of a message delivered twice.
    count: u32,
    /// Second deliveries that produced no event.
    rejected: u32,
}

impl Duplicates {
    /// The pushes `seed` marks, none delivered yet.
    fn new(seed: Option<u64>) -> Duplicates {
        Duplicates {
            seed,
            index: 0,
            count: 0,
            rejected: 0,
        }
    }

    /// Whether this frame, a push, is the next one marked.
    fn is_marked(&mut self, frame: &[u8]) -> bool {
        let push = matches!(
            privatechat_core::Frame::decode(frame),
            Ok(privatechat_core::Frame::Push { .. })
        );
        let Some(seed) = self.seed.filter(|_| push) else {
            return false;
        };
        // SplitMix64 of the seed and the push's index: one in a hundred.
        let mut z = seed.wrapping_add(self.index.wrapping_mul(0x9e37_79b9_7f4a_7c15));
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        let marked = (z ^ (z >> 31)).is_multiple_of(DUPLICATE_ONE_IN);
        self.index += 1;
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

/// Checks that each side received every message of the other once, those
/// of `range` and the bodies of `extra` it sent, in the order they were
/// sent, and nothing else: none of its own, whose echo is not a message.
fn check_delivered(sides: &[Side; 2], range: std::ops::Range<usize>, extra: &[Vec<String>; 2]) {
    for (from, extra, to) in [("a", &extra[0], &sides[1]), ("b", &extra[1], &sides[0])] {
        let bodies = range.clone().map(|n| format!("{from}-{n}"));
        for body in bodies.chain(extra.iter().cloned()) {
            assert_eq!(to.received.get(&body), Some(&1), "{body}");
        }
        assert_eq!(
            to.received.len(),
            range.len() + extra.len(),
            "a message not sent"
        );
        assert!(to.order.is_sorted_by(|a, b| a < b), "out of order");
    }
}

/// Checks a side's counters: `errors` failed calls and `storage_failed`
/// stores reopened, nothing else; a bounded number of reconnects and of
/// subscriptions, one per session; no channel broken or failing to write.
fn check_counters(side: &Side, errors: u32, storage_failed: u32) {
    assert!(side.fault.is_none(), "the fault was never armed");
    assert_eq!(side.errors, errors);
    assert_eq!(side.storage_failed, storage_failed);
    assert!(side.unexpected.is_empty(), "{:?}", side.unexpected);
    assert!(
        side.reconnects <= MAX_RECONNECTS,
        "{} reconnects",
        side.reconnects
    );
    assert!(
        side.subscribed <= side.reconnects + storage_failed + 1,
        "{} subscriptions",
        side.subscribed
    );
    assert!(side.device.status().broken.is_empty());
    assert!(side.device.channels().iter().all(|info| !info.write_failed));
}

/// Checks that `device` raises no alarm in `channel` at `now`: a clean
/// status, no gap, and every own message it shows delivered.
fn check_clean(device: &Device, channel: [u8; 16], now: u64) {
    let clean = ChannelStatus {
        own_key_used_elsewhere: false,
        read_only: false,
        retirement_pending: false,
        storage_full: false,
        ignored_keys: 0,
        unknown_limit_reached: false,
        labelled_limit_reached: false,
        clock_off: false,
        truncated_before: None,
    };
    assert_eq!(device.channel_status(channel), Ok(clean));
    assert_eq!(device.gaps(channel), Ok(Vec::new()));
    let shown = device.messages(channel, now).expect("messages");
    let own: Vec<_> = shown
        .iter()
        .filter(|message| matches!(message.sender, Sender::Own))
        .collect();
    assert!(!own.is_empty(), "no own message shown");
    for message in own {
        assert_eq!(message.delivery, Some(Delivery::Delivered));
    }
}

/// Checks a list a device shows: not empty, each body once, and each
/// sender's in the order it sent them.
fn check_shown(shown: &[String]) {
    assert!(!shown.is_empty(), "nothing shown");
    for from in ["a", "b"] {
        let numbers: Vec<usize> = shown
            .iter()
            .filter_map(|body| body.strip_prefix(from)?.strip_prefix('-')?.parse().ok())
            .collect();
        assert!(numbers.is_sorted_by(|a, b| a < b), "{from}: {numbers:?}");
    }
}

/// The bodies of one's own messages `device` shows in `channel` at `now`,
/// those the server acked when `acked`, the others when not.
fn own(device: &Device, channel: [u8; 16], now: u64, acked: bool) -> Vec<String> {
    let shown = device.messages(channel, now).expect("messages");
    shown
        .into_iter()
        .filter(|message| {
            matches!(message.sender, Sender::Own) && message.server_id.is_some() == acked
        })
        .filter_map(|message| match message.content {
            MessageContent::Text { body, .. } => Some(body),
            _ => None,
        })
        .collect()
}

/// The bodies the device of side `me` shows in `channel` at `now`, in its
/// order, each checked to come from its sender: its own as `Own`, the other
/// side's from a known peer.
fn bodies(device: &Device, me: &str, channel: [u8; 16], now: u64) -> Vec<String> {
    let shown = device.messages(channel, now).expect("messages");
    shown
        .into_iter()
        .filter_map(|message| match message.content {
            MessageContent::Text { body, .. } => {
                let own = body.strip_prefix(me).is_some_and(|n| n.starts_with('-'));
                let sender = match message.sender {
                    Sender::Own => own,
                    Sender::Peer { .. } => !own && message.stranger.is_none(),
                    Sender::OwnKeyElsewhere { .. } => false,
                };
                assert!(sender, "{body} shown from the wrong sender");
                Some(body)
            }
            _ => None,
        })
        .collect()
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
    let steps = 0..PER_SIDE as u64;
    let draws = (steps.clone(), steps, proptest::num::u64::ANY);
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
    check_delivered(&sides, 0..PER_SIDE, &[Vec::new(), Vec::new()]);
    assert!(duplicate.count > 0, "no push was duplicated");
    assert_eq!(
        duplicate.rejected, duplicate.count,
        "a duplicate was not rejected"
    );
    // Each injected commit reopened its store once: the first side's
    // failed its `send`, the second's a session's step, and no other call
    // failed.
    for (side, errors) in sides.iter().zip([1, 0]) {
        check_counters(side, errors, 1);
    }
    let [first, second] = sides;
    for (side, name) in [(first, "a"), (second, "b")] {
        let faults = side.faults.clone();
        let mut device = side.device;
        device.flush(end).expect("flush");
        check_clean(&device, channel, end);
        let shown = bodies(&device, name, channel, end);
        check_shown(&shown);
        drop(device);
        let path = dir.path().join(name);
        check_reopened(&path, &faults, end);
        // The reopened device shows what the closed one showed.
        let data = open_with(&path, Io::fast).expect("reopen");
        let device = Device::open(Box::new(data), end).expect("open");
        assert_eq!(bodies(&device, name, channel, end), shown);
    }
}

/// Each store of the data directory at `path` reloads the state its last
/// commit wrote, and its log was compacted: no record is left that expired
/// a TTL before `end`, the most a compaction run when a quarter of the log
/// has expired keeps (spec 023-ttl-purge R5).
fn check_reopened(path: &Path, faults: &Faults, end: u64) {
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
            oldest.is_some_and(|at| at > end - u64::from(TTL_SECONDS) * 1_000),
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
    let mut cut = Vec::new();
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
            let (state, records) = store
                .load()
                .expect("load without Corrupt")
                .expect("a state");
            let (committed, generation) = state.log_position();
            let after = std::fs::metadata(&log).expect("the log").len();
            assert_eq!(after, committed);
            // The load that cut the log returned only the committed records.
            let (_, again) = store.load().expect("load again").expect("a state");
            assert!(records_eq(&records, &again), "an uncommitted record");
            cut.push(before > committed);
            compacted |= generation > 0;
            ids.push(state.channel_id());
        }
    }
    // The process stopped in one append: one side's log runs past its
    // committed length, the other's does not.
    assert_eq!(
        cut.iter().filter(|cut| **cut).count(),
        1,
        "no append, or two, past the committed length: {cut:?}"
    );
    assert!(compacted, "the crash came before any compaction");
    assert_eq!(ids.first(), ids.get(1));

    // The resume comes after the end the full run would have had, so after
    // the crash whatever append it stops at, and the clock never goes back.
    let now = T0 + TICK + PER_SIDE as u64 * SEND_EVERY + DRAIN;
    let faults = [Faults::new(), Faults::new()];
    let (first, second, channel) = start(dir.path(), [&faults[0], &faults[1]], now);
    for side in [&first, &second] {
        let listed: Vec<[u8; 16]> = side.device.channels().iter().map(|info| info.id).collect();
        assert_eq!(listed, [channel]);
        assert_eq!(Some(&channel), ids.first());
        assert!(side.device.status().broken.is_empty());
    }
    let shown =
        [(&first, "a"), (&second, "b")].map(|(side, me)| bodies(&side.device, me, channel, now));
    shown.iter().for_each(|shown| check_shown(shown));
    // One's own messages the server never acked, still in the outbox.
    let pending = [&first, &second].map(|side| own(&side.device, channel, now, false));
    // Every message one side's server acked is held by the other: the
    // stopped append is a send (`CRASH_APPEND`), so no committed receive may
    // be missing, and an older state reloaded would miss one.
    let acked = [&first, &second].map(|side| own(&side.device, channel, now, true));
    for (from, to) in [(0, 1), (1, 0)] {
        let missing: Vec<&String> = acked[from]
            .iter()
            .filter(|body| !shown[to].contains(body))
            .collect();
        assert!(missing.is_empty(), "{missing:?} lost");
    }
    // A pending message the other side already holds is not shown twice.
    let extra = [
        pending[0]
            .iter()
            .filter(|body| !shown[1].contains(body))
            .cloned()
            .collect(),
        pending[1]
            .iter()
            .filter(|body| !shown[0].contains(body))
            .cloned()
            .collect(),
    ];
    // `CRASH_APPEND` stops a send, so that the resume has one to deliver.
    assert!(
        extra.iter().any(|bodies: &Vec<String>| !bodies.is_empty()),
        "no message was pending at the crash"
    );
    let mut sides = [first, second];
    let mut server = MemoryServer::new(&[HOST]);
    let mut duplicate = Duplicates::new(None);
    let end = exchange(
        &mut sides,
        &mut server,
        channel,
        (now, 100_000, 20),
        &mut duplicate,
    );
    check_delivered(&sides, 100_000..100_020, &extra);
    for (side, me) in sides.iter().zip(["a", "b"]) {
        check_counters(side, 0, 0);
        check_clean(&side.device, channel, end);
        check_shown(&bodies(&side.device, me, channel, end));
    }
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
