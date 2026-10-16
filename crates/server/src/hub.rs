//! The subscriptions of every connection, per channel (spec 030-ws-protocol
//! R7–R10, R12, R15): the single path from the writer's results to a
//! connection's queue. A subscription catches up before it is subscribed,
//! and the live pushes of its channel are held for it meanwhile, in order,
//! within one bound per connection.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use axum::body::Bytes;
use privatechat_core::Frame;
use tokio::sync::mpsc;

use crate::frames::{self, ErrorCode};
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
    ttl_seconds: u32,
    stage: Stage,
}

/// What the hub keeps of a connection: its queue and whether it overflowed.
struct Connection {
    queue: mpsc::Sender<Encoded>,
    /// Set when its queue could not take a frame: the connection closes
    /// (spec 033-rate-limit-quotas R5).
    overflowed: Arc<AtomicBool>,
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
        queue: mpsc::Sender<Encoded>,
        overflowed: Arc<AtomicBool>,
    ) {
        self.connections.insert(
            id,
            Connection {
                queue,
                overflowed,
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
        let Ok(ok) = Frame::Ok { channel_id }.encode() else {
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

    /// The results of one transaction of the writer, in its order: each
    /// stored blob pushed to every subscription of its channel, held for
    /// those catching up (R8, R12).
    pub(crate) fn on_commit(&mut self, outcomes: Vec<WriteOutcome>) {
        for outcome in outcomes {
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
            let push = Frame::Push {
                channel_id: outcome.channel_id,
                server_id: row.server_id,
                received_at: row.received_at,
                blob: row.blob,
            };
            let Ok(frame) = push.encode() else {
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

    /// Ends the subscription holding the most bytes, alone, while the holds of
    /// one connection pass `HOLD_FRAMES` or `HOLD_BYTES` (R8).
    fn bound_holds(&mut self, id: u64) {
        loop {
            let Some(connection) = self.connections.get_mut(&id) else {
                return;
            };
            let (mut frames, mut bytes) = (0usize, 0usize);
            let mut largest: Option<([u8; 16], usize)> = None;
            for (channel_id, subscription) in &connection.subscriptions {
                if let Stage::CatchingUp {
                    held,
                    bytes: held_bytes,
                } = &subscription.stage
                {
                    frames = frames.saturating_add(held.len());
                    bytes = bytes.saturating_add(*held_bytes);
                    if largest.is_none_or(|(_, most)| *held_bytes > most) {
                        largest = Some((*channel_id, *held_bytes));
                    }
                }
            }
            if frames <= HOLD_FRAMES && bytes <= HOLD_BYTES {
                return;
            }
            let Some((channel_id, _)) = largest else {
                return;
            };
            connection.subscriptions.remove(&channel_id);
            let error = frames::error(ErrorCode::RateLimited, Some(channel_id), None).encode();
            if let Ok(error) = error {
                queue(connection, Encoded::from(error));
            }
            self.forget_channel(&channel_id, id);
        }
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

/// Puts `frame` in the connection's queue; a full queue marks it for closing
/// (spec 033-rate-limit-quotas R5) and drops the frame.
fn queue(connection: &Connection, frame: Encoded) {
    if connection.queue.try_send(frame).is_err() {
        connection.overflowed.store(true, Ordering::SeqCst);
    }
}
