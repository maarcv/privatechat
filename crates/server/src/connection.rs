//! One task per WebSocket (spec 030-ws-protocol R4–R10, R15, R16): it sends
//! the `hello`, reads the client's frames, answers each `subscribe` with the
//! verdicts of spec 031-auth-channel-signature, streams the backlog of each
//! accepted channel one page at a time, writes what the hub queues for it,
//! and closes on anything a client of spec 028 never sends. The deadline task
//! wakes it every 100 ms of real time to check its deadlines on the monotonic
//! clock (spec 032-storage-ttl R14).

use std::collections::VecDeque;
use std::sync::Arc;
#[cfg(test)]
use std::sync::atomic::Ordering;
use std::time::Duration;

use axum::extract::ws::{CloseFrame, Message, WebSocket};
use privatechat_core::{Error, Frame, relay};
use tokio::sync::{broadcast, mpsc};

use crate::auth::{AuthState, Verdict};
use crate::clock::Clock;
use crate::frames::{self, ErrorCode};
use crate::http::Shared;
use crate::hub::{Encoded, Pending};
use crate::limits::{
    Admission, Gate, MAX_SUBSCRIPTIONS, PING_INTERVAL_MS, PublishWindow, SEND_QUEUE_FRAMES,
    SUBSCRIBE_GAP_MS, WRITE_TIMEOUT_MS, pong_overdue,
};
use crate::store::reader::read_page;
use crate::store::writer::WriteRequest;

/// How often the deadline task wakes, in real time (spec 032 R14).
pub(crate) const TICK: Duration = Duration::from_millis(100);

/// The close codes the server sends (RFC 6455 §7.4.1).
const GOING_AWAY: u16 = 1001;
const UNSUPPORTED_DATA: u16 = 1003;
const POLICY_VIOLATION: u16 = 1008;
const TOO_BIG: u16 = 1009;
const INTERNAL_ERROR: u16 = 1011;
const TRY_AGAIN_LATER: u16 = 1013;

/// The one server-wide deadline task: a tick to every connection every 100 ms
/// of real time, each of which then checks its own deadlines (spec 032 R14),
/// and the sweep of the IP table (spec 033 R9).
pub(crate) fn spawn_deadline_task(
    ticks: broadcast::Sender<()>,
    gate: Arc<Gate>,
    clock: Arc<dyn Clock>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(TICK);
        loop {
            interval.tick().await;
            gate.forget(clock.mono_ms());
            // No connection listening is no reason to stop.
            let _ = ticks.send(());
        }
    })
}

/// What the task does next.
enum Flow {
    Continue,
    Close(u16),
    /// The socket failed: nothing more can be said on it (R15).
    Gone,
}

/// A subscription whose backlog is being streamed (R7).
struct CatchUp {
    channel_id: [u8; 16],
    /// The subscription it streams; a step of an earlier one, ended by R8,
    /// finds the hub's generation changed and stops.
    generation: u64,
    /// The next `received_at` to read from.
    from: u64,
    /// The `received_at` of the last backlog push sent, if any.
    last: Option<u64>,
    done: bool,
}

/// The state of one connection's task.
struct Connection {
    id: u64,
    socket: WebSocket,
    shared: Arc<Shared>,
    auth: AuthState,
    queue: mpsc::Receiver<Encoded>,
    /// What the queue holds not yet written (spec 033-rate-limit-quotas R5).
    pending: Arc<Pending>,
    /// The ticks of the deadline task (spec 032-storage-ttl R14).
    ticks: broadcast::Receiver<()>,
    /// When the next ping is due, on the monotonic clock (spec 033 R4).
    next_ping: u64,
    /// When the ping awaiting its pong was due.
    ping_due: Option<u64>,
    /// When a write other than a ping last completed (spec 033 R4).
    progress: u64,
    /// The subscriptions catching up, streamed in turn.
    catching: VecDeque<CatchUp>,
    /// The `publish`es handed to the writer (spec 033-rate-limit-quotas R1).
    publishes: PublishWindow,
    /// When the last `subscribe` came, on the monotonic clock (spec 033 R2).
    last_subscribe: Option<u64>,
    /// Its count on its listener and its address (spec 033 R8, R10).
    admission: Admission,
}

/// Forgets the connection in the hub however the task ends (R15).
struct Registration {
    id: u64,
    shared: Arc<Shared>,
}

impl Drop for Registration {
    fn drop(&mut self) {
        self.shared.hub().disconnect(self.id);
    }
}

/// The connection of `socket`, admitted as `admission`, until either side
/// closes it.
pub(crate) async fn run(mut socket: WebSocket, shared: Arc<Shared>, admission: Admission) {
    #[cfg(test)]
    let _task = shared.hooks.task();
    let ticks = shared.ticks.subscribe();
    let now = shared.clock.mono_ms();
    let Ok((auth, hello)) = AuthState::new(now) else {
        close(&mut socket, &shared, INTERNAL_ERROR).await;
        return;
    };
    #[cfg(test)]
    let auth = {
        let mut auth = auth;
        let failing = shared.hooks.fail_relay.load(Ordering::SeqCst);
        auth.fail_relay(failing.then_some(crate::auth::RelayCall::ChannelId));
        auth
    };
    let id = shared.next_connection();
    // `Pending` holds the bound of spec 033 R5, the frame being written
    // included; the channel's own bound is the same, a backstop.
    let (sender, queue) = mpsc::channel(SEND_QUEUE_FRAMES);
    let pending = Arc::new(Pending::default());
    shared.hub().connect(id, sender, pending.clone());
    let registration = Registration {
        id,
        shared: shared.clone(),
    };
    let mut connection = Connection {
        id,
        socket,
        shared,
        auth,
        queue,
        pending,
        ticks,
        next_ping: now.saturating_add(PING_INTERVAL_MS),
        ping_due: None,
        progress: now,
        catching: VecDeque::new(),
        publishes: PublishWindow::default(),
        last_subscribe: None,
        admission,
    };
    let flow = match connection.send(&hello).await {
        Flow::Continue => connection.serve().await,
        stopped => stopped,
    };
    // Forgotten at once, not after the close frame has been sent (R15):
    // the hub's registration, and the nonce, the queue and the catch-ups.
    drop(registration);
    let (mut socket, shared, admission) = connection.into_socket();
    if let Flow::Close(code) = flow {
        close(&mut socket, &shared, code).await;
    }
    // Counted until the socket is done with (spec 033 R10).
    drop(admission);
}

impl Connection {
    /// Its socket, with what a close needs and its admission; the rest of
    /// its state dropped here.
    fn into_socket(self) -> (WebSocket, Arc<Shared>, Admission) {
        (self.socket, self.shared, self.admission)
    }

    async fn serve(&mut self) -> Flow {
        loop {
            let catching_up = !self.catching.is_empty();
            let flow = tokio::select! {
                // In this order: the tick first, so that neither the client
                // nor the queue puts off a close; the catch-up, always ready,
                // last, so that a frame already read is never left behind a
                // page, and every frame of the queue is written before each
                // page and each batch of held pushes (R7).
                biased;
                tick = self.ticks.recv() => match tick {
                    // A lagging receiver missed ticks, which only delays the check.
                    Ok(()) | Err(broadcast::error::RecvError::Lagged(_)) => self.on_tick().await,
                    Err(broadcast::error::RecvError::Closed) => Flow::Gone,
                },
                message = self.socket.recv() => match message {
                    None | Some(Ok(Message::Close(_))) => Flow::Gone,
                    Some(Ok(Message::Binary(bytes))) => self.on_frame(&bytes).await,
                    Some(Ok(Message::Text(_))) => Flow::Close(UNSUPPORTED_DATA),
                    Some(Ok(Message::Pong(_))) => {
                        self.ping_due = None;
                        Flow::Continue
                    }
                    // axum answers it.
                    Some(Ok(Message::Ping(_))) => Flow::Continue,
                    Some(Err(error)) => read_error(error).map_or(Flow::Gone, Flow::Close),
                },
                frame = self.queue.recv() => match frame {
                    Some(frame) => self.write_queued(frame).await,
                    None => Flow::Gone,
                },
                () = std::future::ready(()), if catching_up => self.catch_up().await,
            };
            if !matches!(flow, Flow::Continue) {
                return flow;
            }
        }
    }

    async fn on_tick(&mut self) -> Flow {
        // At every tick and before every write: once a frame was dropped,
        // nothing more is written (spec 033 R5).
        if self.pending.overflowed() {
            return Flow::Close(TRY_AGAIN_LATER);
        }
        let now = self.shared.clock.mono_ms();
        if self.auth.deadline_passed(now) {
            return Flow::Close(POLICY_VIOLATION);
        }
        if pong_overdue(now, self.ping_due, self.progress) {
            return Flow::Close(GOING_AWAY);
        }
        if now >= self.next_ping {
            let due = self.next_ping;
            self.next_ping = due.saturating_add(PING_INTERVAL_MS);
            self.ping_due = Some(due);
            let ping = Message::Ping(Vec::new().into());
            if !send_within(&mut self.socket, &self.shared, ping).await {
                return Flow::Gone;
            }
        }
        Flow::Continue
    }

    /// One binary message from the client (R6).
    async fn on_frame(&mut self, bytes: &[u8]) -> Flow {
        match Frame::decode(bytes) {
            Ok(Frame::Subscribe {
                pk_ch,
                ttl_seconds,
                sig,
                since,
            }) => {
                let now = self.shared.clock.mono_ms();
                // Past the first-subscribe deadline nothing is answered, not
                // even a refusal of spec 033 (spec 031 R7).
                if self.auth.deadline_passed(now) {
                    return Flow::Close(POLICY_VIOLATION);
                }
                if let Some(flow) = self.limit_subscribe(&pk_ch, ttl_seconds, now).await {
                    return flow;
                }
                let hosts = &self.shared.hosts;
                match self
                    .auth
                    .on_subscribe(&pk_ch, ttl_seconds, &sig, hosts, now)
                {
                    Ok(verdicts) => self.answer(verdicts, ttl_seconds, since).await,
                    Err(_) => Flow::Close(INTERNAL_ERROR),
                }
            }
            Ok(Frame::Publish {
                channel_id,
                client_ref,
                blob,
            }) => self.publish(channel_id, client_ref, blob),
            // A frame no client sends, or none at all.
            Ok(_) | Err(_) => Flow::Close(POLICY_VIOLATION),
        }
    }

    /// The frames of `verdicts`, in order (spec 031 R5, R6).
    async fn answer(
        &mut self,
        verdicts: Vec<Verdict>,
        ttl_seconds: u32,
        since: Option<u64>,
    ) -> Flow {
        for verdict in verdicts {
            let flow = match verdict {
                Verdict::Accept { channel_id } => {
                    self.admission.authenticate();
                    self.accept(channel_id, ttl_seconds, since)
                }
                Verdict::NonceExpired { channel_id, hello } => {
                    let error = frames::error(ErrorCode::NonceExpired, Some(channel_id), None);
                    match self.enqueue(&error) {
                        Flow::Continue => self.enqueue(&hello),
                        stopped => stopped,
                    }
                }
                Verdict::BadTtl { channel_id } => {
                    self.enqueue(&frames::error(ErrorCode::BadTtl, Some(channel_id), None))
                }
                Verdict::BadAuth { channel_id } => {
                    self.enqueue(&frames::error(ErrorCode::BadAuth, Some(channel_id), None))
                }
                // The frames queued before it go out first (spec 031 R6).
                Verdict::Close => match self.flush().await {
                    Flow::Continue => Flow::Close(POLICY_VIOLATION),
                    stopped => stopped,
                },
            };
            if !matches!(flow, Flow::Continue) {
                return flow;
            }
        }
        Flow::Continue
    }

    /// An accepted channel: registered as catching up before anything is
    /// read (R7), or nothing at all when it is already here (R9).
    fn accept(&mut self, channel_id: [u8; 16], ttl_seconds: u32, since: Option<u64>) -> Flow {
        let registered = self
            .shared
            .hub()
            .subscribe(self.id, channel_id, ttl_seconds);
        let Some(generation) = registered else {
            return Flow::Continue;
        };
        // `since` past the server's clock reads as now (R7).
        let now = self.shared.clock.wall_ms();
        self.catching.push_back(CatchUp {
            channel_id,
            generation,
            from: since.unwrap_or(0).min(now),
            last: None,
            done: false,
        });
        Flow::Continue
    }

    /// The limits of spec 033-rate-limit-quotas on a `subscribe`, before any
    /// check of spec 031: one per `SUBSCRIBE_GAP_MS` (R2), which is not a
    /// failed attempt, and `MAX_SUBSCRIPTIONS` channels (R3), past which the
    /// connection closes. `None` lets it through.
    async fn limit_subscribe(
        &mut self,
        pk_ch: &[u8; 32],
        ttl_seconds: u32,
        now: u64,
    ) -> Option<Flow> {
        let previous = self.last_subscribe.replace(now);
        let too_soon = previous.is_some_and(|at| now.saturating_sub(at) < SUBSCRIBE_GAP_MS);
        let held = self.shared.hub().subscriptions(self.id);
        if !too_soon && held < MAX_SUBSCRIPTIONS {
            return None;
        }
        let Ok(channel_id) = relay::channel_id(pk_ch, ttl_seconds) else {
            return Some(Flow::Close(INTERNAL_ERROR));
        };
        let refusal = frames::error(ErrorCode::RateLimited, Some(channel_id), None);
        // A 17th channel closes the connection, even when it also came too
        // soon: one refusal answers both rules.
        let past_cap = held >= MAX_SUBSCRIPTIONS
            && self
                .shared
                .hub()
                .ttl_seconds(self.id, &channel_id)
                .is_none();
        if !past_cap {
            // Too soon; or a channel already here, which spec 030 R9 ignores.
            return too_soon.then(|| self.enqueue(&refusal));
        }
        Some(match self.enqueue(&refusal) {
            Flow::Continue => match self.flush().await {
                Flow::Continue => Flow::Close(POLICY_VIOLATION),
                stopped => stopped,
            },
            stopped => stopped,
        })
    }

    /// A `publish`: refused at once, in the order of R11, or handed to the
    /// writer with the subscription's TTL; its `ack` or the writer's refusal
    /// comes back through the hub (R12).
    fn publish(&mut self, channel_id: [u8; 16], client_ref: [u8; 16], blob: Vec<u8>) -> Flow {
        let refuse = |code| frames::error(code, Some(channel_id), Some(client_ref));
        let Some(ttl_seconds) = self.shared.hub().ttl_seconds(self.id, &channel_id) else {
            return self.enqueue(&refuse(ErrorCode::NotSubscribed));
        };
        match relay::check_blob(&blob, &channel_id) {
            Ok(()) => {}
            Err(Error::Internal) => return Flow::Close(INTERNAL_ERROR),
            Err(_) => return self.enqueue(&refuse(ErrorCode::BadBlob)),
        }
        let now = self.shared.clock.mono_ms();
        if !self.publishes.allows(now) {
            return self.enqueue(&refuse(ErrorCode::RateLimited));
        }
        let bytes = u64::try_from(blob.len()).unwrap_or(u64::MAX);
        let request = WriteRequest {
            connection: self.id,
            client_ref,
            channel_id,
            ttl_seconds,
            blob,
        };
        // The byte budgets of the address, its /48 or the onion listener
        // (spec 033 R12), checked and counted with the hand-over.
        let writer = &self.shared.writer;
        match self
            .admission
            .publish(bytes, now, || writer.submit(request))
        {
            None => self.enqueue(&refuse(ErrorCode::RateLimited)),
            Some(Ok(())) => {
                self.publishes.handed(now);
                Flow::Continue
            }
            Some(Err(refusal)) => self.enqueue(&refuse(ErrorCode::from(refusal))),
        }
    }

    /// One step of the catch-up of the next subscription in turn: one backlog
    /// page, or once the backlog is done its held pushes, or its `ok` (R7,
    /// R8). The order of `serve` has written the queue before it.
    async fn catch_up(&mut self) -> Flow {
        let Some(mut step) = self.catching.pop_front() else {
            return Flow::Continue;
        };
        if !self
            .shared
            .hub()
            .is_catching_up(self.id, &step.channel_id, step.generation)
        {
            // Ended by R8: its stream stops, and nothing more of it is sent.
            return Flow::Continue;
        }
        let flow = if step.done {
            self.after_backlog(&step).await
        } else {
            self.backlog_page(&mut step).await
        };
        // In turn again; once its `ok` is queued or it ended, the check
        // above drops it at its next turn.
        if matches!(flow, Flow::Continue) {
            self.catching.push_back(step);
        }
        flow
    }

    /// One page of the backlog of `step` (R7).
    async fn backlog_page(&mut self, step: &mut CatchUp) -> Flow {
        let now = self.shared.clock.wall_ms();
        #[cfg(test)]
        {
            self.shared.hooks.reads.fetch_add(1, Ordering::SeqCst);
        }
        let read = read_page(&self.shared.pool, step.channel_id, step.from, now)
            .await
            .map_err(drop);
        #[cfg(test)]
        let read = read.and_then(|page| {
            if self.shared.hooks.fail_reads.load(Ordering::SeqCst) {
                Err(())
            } else {
                Ok(page)
            }
        });
        let page = match read {
            Ok(page) => page,
            Err(_) => return Flow::Close(INTERNAL_ERROR),
        };
        let Some(last) = page.last().map(|row| row.received_at) else {
            step.done = true;
            return Flow::Continue;
        };
        for row in page {
            let flow = self.send(&frames::push(step.channel_id, row)).await;
            if !matches!(flow, Flow::Continue) {
                return flow;
            }
        }
        step.from = last.saturating_add(1);
        step.last = Some(last);
        Flow::Continue
    }

    /// After the backlog: the held pushes, or the `ok` (R7, R8).
    async fn after_backlog(&mut self, step: &CatchUp) -> Flow {
        #[cfg(test)]
        {
            let mut paused = self.shared.hooks.catch_up_paused.subscribe();
            let _ = paused.wait_for(|paused| !paused).await;
        }
        let pushes =
            self.shared
                .hub()
                .after_backlog(self.id, step.channel_id, step.generation, step.last);
        for push in pushes {
            let flow = self.write(push).await;
            if !matches!(flow, Flow::Continue) {
                return flow;
            }
        }
        Flow::Continue
    }

    /// Writes every frame of the queue.
    async fn flush(&mut self) -> Flow {
        while let Ok(frame) = self.queue.try_recv() {
            let flow = self.write_queued(frame).await;
            if !matches!(flow, Flow::Continue) {
                return flow;
            }
        }
        Flow::Continue
    }

    /// Writes a frame of the queue, then takes it off what waits; `write`
    /// closes instead once the queue overflowed (spec 033-rate-limit-quotas
    /// R5).
    async fn write_queued(&mut self, frame: Encoded) -> Flow {
        let bytes = frame.len();
        let flow = self.write(frame).await;
        // Written, or the connection is gone: either way no longer waiting.
        self.pending.written(bytes);
        flow
    }

    /// Encodes `frame` into the connection's queue, where it counts toward
    /// the bound (R10) and keeps its place after the frames queued before.
    fn enqueue(&self, frame: &Frame) -> Flow {
        match frame.encode() {
            Ok(bytes) => {
                self.shared.hub().enqueue(self.id, bytes.into());
                Flow::Continue
            }
            Err(_) => Flow::Close(INTERNAL_ERROR),
        }
    }

    /// Encodes and writes `frame`.
    async fn send(&mut self, frame: &Frame) -> Flow {
        match frame.encode() {
            Ok(bytes) => self.write(bytes.into()).await,
            Err(_) => Flow::Close(INTERNAL_ERROR),
        }
    }

    /// Writes an encoded frame; a socket that fails, or whose write is still
    /// pending `WRITE_TIMEOUT_MS` after it began, is gone (spec 033 R5). The
    /// checks of a tick run first: a catch-up writes page after page without
    /// coming back to `serve`, and a ping is due all the same (spec 033 R4).
    async fn write(&mut self, frame: Encoded) -> Flow {
        let flow = self.on_tick().await;
        if !matches!(flow, Flow::Continue) {
            return flow;
        }
        let message = Message::Binary(frame);
        if !send_within(&mut self.socket, &self.shared, message).await {
            return Flow::Gone;
        }
        self.progress = self.shared.clock.mono_ms();
        Flow::Continue
    }
}

/// Sends `message`, false when the socket fails or the write is still pending
/// `WRITE_TIMEOUT_MS` of the monotonic clock after it began, measured at each
/// tick of the deadline task; progress within the write does not restart that
/// time (spec 033-rate-limit-quotas R5). It hears the ticks on a receiver of
/// its own, so that the connection's are left for its other checks.
async fn send_within(socket: &mut WebSocket, shared: &Shared, message: Message) -> bool {
    let mut ticks = shared.ticks.subscribe();
    let began = shared.clock.mono_ms();
    let send = async {
        #[cfg(test)]
        {
            let mut paused = shared.hooks.writes_paused.subscribe();
            let _ = paused.wait_for(|paused| !paused).await;
        }
        socket.send(message).await
    };
    tokio::pin!(send);
    loop {
        tokio::select! {
            biased;
            sent = &mut send => return sent.is_ok(),
            tick = ticks.recv() => match tick {
                Ok(()) | Err(broadcast::error::RecvError::Lagged(_)) => {
                    if shared.clock.mono_ms().saturating_sub(began) >= WRITE_TIMEOUT_MS {
                        return false;
                    }
                }
                Err(broadcast::error::RecvError::Closed) => return false,
            },
        }
    }
}

/// The close a failed read gets: 1009 past `MAX_MESSAGE`, 1003 for text
/// that is not UTF-8, which tungstenite refuses before it is a message (R4);
/// any other failure ends the connection with no close.
fn read_error(error: axum::Error) -> Option<u16> {
    match error.into_inner().downcast_ref::<tungstenite::Error>() {
        Some(tungstenite::Error::Capacity(_)) => Some(TOO_BIG),
        Some(tungstenite::Error::Utf8(_)) => Some(UNSUPPORTED_DATA),
        _ => None,
    }
}

/// Sends a close frame of `code` with no reason, within the deadline of a
/// write; a socket already gone has nothing to hear it.
async fn close(socket: &mut WebSocket, shared: &Shared, code: u16) {
    let frame = CloseFrame {
        code,
        reason: "".into(),
    };
    send_within(socket, shared, Message::Close(Some(frame))).await;
}
