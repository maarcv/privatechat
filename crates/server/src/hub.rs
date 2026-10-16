//! The subscriptions of every connection, per channel (spec 030-ws-protocol
//! R7–R10, R12, R15): the single path from the writer's results to a
//! connection's queue. A subscription catches up before it is subscribed,
//! and the live pushes of its channel are held for it meanwhile, in order,
//! within one bound per connection.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use axum::body::Bytes;
use tokio::sync::mpsc;

use crate::frames::{self, ErrorCode};
use crate::limits::{SEND_QUEUE_BYTES, SEND_QUEUE_FRAMES};
use crate::store::writer::WriteOutcome;

/// The most pushes all the catching-up subscriptions of one connection may
/// hold before their `ok` (R8).
pub(crate) const HOLD_FRAMES: usize = 256;

/// The most blob bytes they may hold (R8).
pub(crate) const HOLD_BYTES: usize = 4 * 1024 * 1024;

/// The most blob bytes of held pushes handed out at once, like a backlog
/// page; the rest stay held and counted (R8).
const HELD_CHUNK_BYTES: usize = 256 * 1024;

/// A frame encoded once, shared by every queue and hold it enters.
pub(crate) type Encoded = Bytes;

/// A live push, held for a catching-up subscription.
#[derive(Clone)]
struct Held {
    received_at: u64,
    frame: Encoded,
    blob_bytes: usize,
}

/// Where a subscription stands.
enum Stage {
    /// Its backlog is being sent; the live pushes of its channel wait here.
    CatchingUp { held: VecDeque<Held>, bytes: usize },
    /// Its `ok` is queued: live pushes go straight to the queue, but for
    /// those its backlog already sent, at or below `floor` (R8).
    Subscribed { floor: Option<u64> },
}

/// One subscription of one connection.
struct Subscription {
    /// Which subscription of the channel on this connection this is: a step
    /// of an earlier one, ended by R8, must not act for it.
    generation: u64,
    /// The TTL its `subscribe` was signed for, which its `publish`es take
    /// (R11).
    ttl_seconds: u32,
    stage: Stage,
}

/// The frames of one connection's queue not yet written, the one being
/// written included, and their bytes (spec 033-rate-limit-quotas R5): the hub
/// adds what it queues, the connection takes off what it has written.
#[derive(Debug, Default)]
pub(crate) struct Pending {
    frames: AtomicUsize,
    bytes: AtomicUsize,
    /// Set when a frame would have passed a bound: the connection closes.
    overflowed: AtomicBool,
}

impl Pending {
    /// Whether a frame was dropped: the connection closes with 1013.
    pub(crate) fn overflowed(&self) -> bool {
        self.overflowed.load(Ordering::SeqCst)
    }

    /// A frame of `bytes` bytes taken from the queue has been written.
    pub(crate) fn written(&self, bytes: usize) {
        self.frames.fetch_sub(1, Ordering::SeqCst);
        self.bytes.fetch_sub(bytes, Ordering::SeqCst);
    }
}

/// What the hub keeps of a connection: its queue and what the queue holds.
struct Connection {
    queue: mpsc::UnboundedSender<Encoded>,
    pending: Arc<Pending>,
    subscriptions: HashMap<[u8; 16], Subscription>,
}

/// Every subscription, by connection; the channels index them.
#[derive(Default)]
pub(crate) struct Hub {
    connections: HashMap<u64, Connection>,
    channels: HashMap<[u8; 16], HashSet<u64>>,
    next_generation: u64,
    /// The stored blobs the writer handed to the hub, per channel, for the
    /// tests that wait for them.
    #[cfg(test)]
    committed: HashMap<[u8; 16], u64>,
}

impl Hub {
    /// A connection and its queue.
    pub(crate) fn connect(
        &mut self,
        id: u64,
        queue: mpsc::UnboundedSender<Encoded>,
        pending: Arc<Pending>,
    ) {
        self.connections.insert(
            id,
            Connection {
                queue,
                pending,
                subscriptions: HashMap::new(),
            },
        );
    }

    /// Forgets the connection and every subscription of it (R15).
    pub(crate) fn disconnect(&mut self, id: u64) {
        if let Some(connection) = self.connections.remove(&id) {
            for channel_id in connection.subscriptions.keys() {
                self.forget_channel(channel_id, id);
            }
        }
    }

    /// A frame of the connection itself, an answer to its `subscribe`, put
    /// in its queue (R10).
    pub(crate) fn enqueue(&self, id: u64, frame: Encoded) {
        if let Some(connection) = self.connections.get(&id) {
            queue(connection, frame);
        }
    }

    /// Registers an accepted subscription as catching up, before any stored
    /// blob is read (R7), and returns its generation; `None` when the channel
    /// is already here (R9), or the connection is not.
    pub(crate) fn subscribe(
        &mut self,
        id: u64,
        channel_id: [u8; 16],
        ttl_seconds: u32,
    ) -> Option<u64> {
        let connection = self.connections.get_mut(&id)?;
        if connection.subscriptions.contains_key(&channel_id) {
            return None;
        }
        let generation = self.next_generation;
        self.next_generation = self.next_generation.saturating_add(1);
        connection.subscriptions.insert(
            channel_id,
            Subscription {
                generation,
                ttl_seconds,
                stage: Stage::CatchingUp {
                    held: VecDeque::new(),
                    bytes: 0,
                },
            },
        );
        self.channels.entry(channel_id).or_default().insert(id);
        Some(generation)
    }

    /// How many channels are subscribed or catching up on this connection.
    pub(crate) fn subscriptions(&self, id: u64) -> usize {
        self.connections
            .get(&id)
            .map_or(0, |connection| connection.subscriptions.len())
    }

    /// The TTL of a channel subscribed or catching up on this connection.
    pub(crate) fn ttl_seconds(&self, id: u64, channel_id: &[u8; 16]) -> Option<u32> {
        self.connections
            .get(&id)?
            .subscriptions
            .get(channel_id)
            .map(|subscription| subscription.ttl_seconds)
    }

    /// Whether the subscription is still catching up (R8 may have ended it).
    pub(crate) fn is_catching_up(&self, id: u64, channel_id: &[u8; 16], generation: u64) -> bool {
        matches!(
            self.connections
                .get(&id)
                .and_then(|connection| connection.subscriptions.get(channel_id)),
            Some(Subscription {
                generation: current,
                stage: Stage::CatchingUp { .. },
                ..
            }) if *current == generation
        )
    }

    /// After the backlog, whose last push was at `after` (`None` for none):
    /// the held pushes past it to write now, or, when none is left, nothing,
    /// and the `ok` queued and the subscription marked subscribed, in this one
    /// step under the lock (R7, R8). A subscription of another generation, or
    /// gone, gets nothing and is left as it is.
    pub(crate) fn after_backlog(
        &mut self,
        id: u64,
        channel_id: [u8; 16],
        generation: u64,
        after: Option<u64>,
    ) -> Vec<Encoded> {
        let Ok(ok) = frames::ok(channel_id).encode() else {
            // Never for 16 bytes; if it were, the subscription ends rather
            // than staying in turn for an `ok` that cannot be sent.
            self.end(id, channel_id, generation);
            return Vec::new();
        };
        let Some(connection) = self.connections.get_mut(&id) else {
            return Vec::new();
        };
        let Some(subscription) = connection.subscriptions.get_mut(&channel_id) else {
            return Vec::new();
        };
        if subscription.generation != generation {
            return Vec::new();
        }
        let Stage::CatchingUp { held, bytes } = &mut subscription.stage else {
            return Vec::new();
        };
        // One chunk at a time, the rest still held and counted; pushes at
        // or below the last backlog push are dropped as already sent.
        let mut pushes = Vec::new();
        let mut chunk = 0usize;
        while let Some(push) = held.front() {
            if !pushes.is_empty() && chunk.saturating_add(push.blob_bytes) > HELD_CHUNK_BYTES {
                break;
            }
            let Some(push) = held.pop_front() else {
                break;
            };
            *bytes = bytes.saturating_sub(push.blob_bytes);
            if after.is_none_or(|after| push.received_at > after) {
                chunk = chunk.saturating_add(push.blob_bytes);
                pushes.push(push.frame);
            }
        }
        if pushes.is_empty() {
            subscription.stage = Stage::Subscribed { floor: after };
            queue(connection, Encoded::from(ok));
        }
        pushes
    }

    /// Ends the subscription of `generation`, if it is still here.
    fn end(&mut self, id: u64, channel_id: [u8; 16], generation: u64) {
        let Some(connection) = self.connections.get_mut(&id) else {
            return;
        };
        if connection
            .subscriptions
            .get(&channel_id)
            .is_some_and(|subscription| subscription.generation == generation)
        {
            connection.subscriptions.remove(&channel_id);
            self.forget_channel(&channel_id, id);
        }
    }

    /// The results of one transaction of the writer, in its order (R12):
    /// each stored blob acknowledged to its publisher, then pushed to every
    /// subscription of its channel, held for those catching up (R8); each
    /// refusal answered to its publisher. A publisher gone gets nothing.
    pub(crate) fn on_commit(&mut self, outcomes: Vec<WriteOutcome>) {
        for outcome in outcomes {
            let answer = match &outcome.result {
                Ok(row) => frames::ack(outcome.client_ref, row),
                Err(refusal) => frames::error(
                    ErrorCode::from(*refusal),
                    Some(outcome.channel_id),
                    Some(outcome.client_ref),
                ),
            };
            if let Ok(answer) = answer.encode() {
                self.enqueue(outcome.connection, Encoded::from(answer));
            }
            let Ok(row) = outcome.result else {
                continue;
            };
            #[cfg(test)]
            {
                let committed = self.committed.entry(outcome.channel_id).or_default();
                *committed = committed.saturating_add(1);
            }
            let received_at = row.received_at;
            let blob_bytes = row.blob.len();
            let Ok(frame) = frames::push(outcome.channel_id, row).encode() else {
                continue;
            };
            let held = Held {
                received_at,
                frame: Encoded::from(frame),
                blob_bytes,
            };
            let subscribers = self
                .channels
                .get(&outcome.channel_id)
                .cloned()
                .unwrap_or_default();
            for id in subscribers {
                self.push(id, outcome.channel_id, &held);
            }
        }
    }

    /// One push for one subscription.
    fn push(&mut self, id: u64, channel_id: [u8; 16], push: &Held) {
        let Some(connection) = self.connections.get_mut(&id) else {
            return;
        };
        let Some(subscription) = connection.subscriptions.get_mut(&channel_id) else {
            return;
        };
        match &mut subscription.stage {
            Stage::Subscribed { floor } => {
                // A blob the backlog read before the writer reached the hub.
                if floor.is_none_or(|floor| push.received_at > floor) {
                    queue(connection, push.frame.clone());
                }
            }
            Stage::CatchingUp { held, bytes } => {
                held.push_back(push.clone());
                *bytes = bytes.saturating_add(push.blob_bytes);
                self.bound_holds(id);
            }
        }
    }

    /// When the holds of one connection pass `HOLD_BYTES` or `HOLD_FRAMES`,
    /// ends, alone, the subscription holding the most of the bound passed:
    /// bytes first, then frames (R8). A flood of small pushes on some
    /// channels ends one of them, not a channel of a few large blobs. One
    /// end is enough: the holds were within both bounds before this push,
    /// and the one ended holds at least one push and, past 4 MiB, at least
    /// the bytes of this one.
    fn bound_holds(&mut self, id: u64) {
        let Some(connection) = self.connections.get_mut(&id) else {
            return;
        };
        let holds: Vec<([u8; 16], usize, usize)> = connection
            .subscriptions
            .iter()
            .filter_map(|(channel_id, subscription)| match &subscription.stage {
                Stage::CatchingUp { held, bytes } => Some((*channel_id, held.len(), *bytes)),
                Stage::Subscribed { .. } => None,
            })
            .collect();
        let frames: usize = holds.iter().map(|(_, frames, _)| frames).sum();
        let bytes: usize = holds.iter().map(|(_, _, bytes)| bytes).sum();
        let largest = if bytes > HOLD_BYTES {
            holds.iter().max_by_key(|(_, _, bytes)| *bytes)
        } else if frames > HOLD_FRAMES {
            holds.iter().max_by_key(|(_, frames, _)| *frames)
        } else {
            return;
        };
        let Some(&(channel_id, _, _)) = largest else {
            return;
        };
        connection.subscriptions.remove(&channel_id);
        let error = frames::error(ErrorCode::RateLimited, Some(channel_id), None).encode();
        if let Ok(error) = error {
            queue(connection, Encoded::from(error));
        }
        self.forget_channel(&channel_id, id);
    }

    fn forget_channel(&mut self, channel_id: &[u8; 16], id: u64) {
        if let Some(ids) = self.channels.get_mut(channel_id) {
            ids.remove(&id);
            if ids.is_empty() {
                self.channels.remove(channel_id);
            }
        }
    }

    /// The stored blobs of `channel_id` the writer handed to the hub.
    #[cfg(test)]
    pub(crate) fn committed(&self, channel_id: &[u8; 16]) -> u64 {
        self.committed.get(channel_id).copied().unwrap_or(0)
    }

    /// The channels in the index, empty entries included.
    #[cfg(test)]
    pub(crate) fn indexed_channels(&self) -> usize {
        self.channels.len()
    }

    /// The subscriptions the hub holds of a connection, for the tests of R15.
    #[cfg(test)]
    pub(crate) fn subscriptions_of(&self, id: u64) -> usize {
        self.connections
            .get(&id)
            .map_or(0, |connection| connection.subscriptions.len())
            .saturating_add(
                self.channels
                    .values()
                    .filter(|ids| ids.contains(&id))
                    .count(),
            )
    }
}

/// Puts `frame` in the connection's queue. One that would take the frames
/// not yet written past `SEND_QUEUE_FRAMES` or `SEND_QUEUE_BYTES` marks the
/// connection for closing (spec 033-rate-limit-quotas R5) and is dropped, and
/// every frame after it: none may reach the client past a dropped one, whose
/// cursor would skip it. Only the hub adds, under its lock, so the check and
/// the add do not race; the connection only takes off.
fn queue(connection: &Connection, frame: Encoded) {
    let pending = &connection.pending;
    if pending.overflowed() {
        return;
    }
    let frames = pending.frames.load(Ordering::SeqCst);
    let bytes = pending.bytes.load(Ordering::SeqCst);
    if frames >= SEND_QUEUE_FRAMES || bytes.saturating_add(frame.len()) > SEND_QUEUE_BYTES {
        pending.overflowed.store(true, Ordering::SeqCst);
        return;
    }
    pending.frames.fetch_add(1, Ordering::SeqCst);
    pending.bytes.fetch_add(frame.len(), Ordering::SeqCst);
    // A connection gone has dropped its receiver; it hears nothing more.
    let _ = connection.queue.send(frame);
}
