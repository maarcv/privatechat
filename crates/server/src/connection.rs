//! One task per WebSocket (spec 030-ws-protocol R4–R10, R15, R16): it sends
//! the `hello`, reads the client's frames, answers each `subscribe` with the
//! verdicts of spec 031-auth-channel-signature, streams the backlog of each
//! accepted channel one page at a time, writes what the hub queues for it,
//! and closes on anything a client of spec 028 never sends. The deadline task
//! wakes it every 100 ms of real time to check its deadlines on the monotonic
//! clock (spec 032-storage-ttl R14).

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use axum::extract::ws::{CloseFrame, Message, WebSocket};
use privatechat_core::Frame;
use tokio::sync::{broadcast, mpsc};

use crate::auth::{AuthState, Verdict};
use crate::frames::{self, ErrorCode};
use crate::http::Shared;
use crate::hub::{Encoded, Next, Registered};
use crate::store::reader::read_page;

/// How often the deadline task wakes, in real time (spec 032 R14).
pub(crate) const TICK: Duration = Duration::from_millis(100);

/// How long one write may take before the connection is dropped. Until spec
/// 033-rate-limit-quotas R5 measures the pending write on the monotonic clock
/// from the deadline task, this bounds it in real time, so that a peer that
/// stops reading cannot hold the task, the first-subscribe deadline included.
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// The frames of the queue the hub fills for a connection; spec
/// 033-rate-limit-quotas R5 adds its byte bound.
pub(crate) const QUEUE_FRAMES: usize = 256;

/// The close codes the server sends (RFC 6455 §7.4.1).
const UNSUPPORTED_DATA: u16 = 1003;
const POLICY_VIOLATION: u16 = 1008;
const TOO_BIG: u16 = 1009;
const INTERNAL_ERROR: u16 = 1011;
const TRY_AGAIN_LATER: u16 = 1013;

/// The one server-wide deadline task: a tick to every connection every 100 ms
/// of real time, each of which then checks its own deadlines (spec 032 R14).
pub(crate) fn spawn_deadline_task(ticks: broadcast::Sender<()>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(TICK);
        loop {
            interval.tick().await;
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
    overflowed: Arc<AtomicBool>,
    /// The subscriptions catching up, streamed in turn.
    catching: VecDeque<CatchUp>,
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

/// The connection of `socket`, until either side closes it.
pub(crate) async fn run(mut socket: WebSocket, shared: Arc<Shared>) {
    let mut ticks = shared.ticks.subscribe();
    let Ok((auth, hello)) = AuthState::new(shared.clock.mono_ms()) else {
        close(&mut socket, INTERNAL_ERROR).await;
        return;
    };
    let id = shared.next_connection();
    let (sender, queue) = mpsc::channel(QUEUE_FRAMES);
    let overflowed = Arc::new(AtomicBool::new(false));
    shared.hub().connect(id, sender, overflowed.clone());
    let _registration = Registration {
        id,
        shared: shared.clone(),
    };
    let mut connection = Connection {
        id,
        socket,
        shared,
        auth,
        queue,
        overflowed,
        catching: VecDeque::new(),
    };
    let flow = match connection.send(&hello).await {
        Flow::Continue => connection.serve(&mut ticks).await,
        stopped => stopped,
    };
    if let Flow::Close(code) = flow {
        close(&mut connection.socket, code).await;
    }
}

impl Connection {
    async fn serve(&mut self, ticks: &mut broadcast::Receiver<()>) -> Flow {
        loop {
            let catching_up = !self.catching.is_empty();
            let flow = tokio::select! {
                message = self.socket.recv() => match message {
                    None | Some(Ok(Message::Close(_))) => Flow::Gone,
                    Some(Ok(Message::Binary(bytes))) => self.on_frame(&bytes).await,
                    Some(Ok(Message::Text(_))) => Flow::Close(UNSUPPORTED_DATA),
                    Some(Ok(Message::Ping(_) | Message::Pong(_))) => Flow::Continue,
                    Some(Err(error)) => read_error(error).map_or(Flow::Gone, Flow::Close),
                },
                frame = self.queue.recv() => match frame {
                    Some(frame) => self.write(frame).await,
                    None => Flow::Gone,
                },
                tick = ticks.recv() => match tick {
                    // A lagging receiver missed ticks, which only delays the check.
                    Ok(()) | Err(broadcast::error::RecvError::Lagged(_)) => self.on_tick(),
                    Err(broadcast::error::RecvError::Closed) => Flow::Gone,
                },
                () = std::future::ready(()), if catching_up => self.catch_up().await,
            };
            if !matches!(flow, Flow::Continue) {
                return flow;
            }
        }
    }

    fn on_tick(&self) -> Flow {
        if self.overflowed.load(Ordering::SeqCst) {
            return Flow::Close(TRY_AGAIN_LATER);
        }
        if self.auth.deadline_passed(self.shared.clock.mono_ms()) {
            return Flow::Close(POLICY_VIOLATION);
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
                #[cfg(test)]
                if self.shared.hooks.fail_relay.load(Ordering::SeqCst) {
                    return Flow::Close(INTERNAL_ERROR);
                }
                let now = self.shared.clock.mono_ms();
                let hosts = &self.shared.hosts;
                match self
                    .auth
                    .on_subscribe(&pk_ch, ttl_seconds, &sig, hosts, now)
                {
                    Ok(verdicts) => self.answer(verdicts, ttl_seconds, since).await,
                    Err(_) => Flow::Close(INTERNAL_ERROR),
                }
            }
            // Spec 030 R11 stores a publish; until then it changes nothing.
            Ok(Frame::Publish { .. }) => Flow::Continue,
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
                Verdict::Accept { channel_id } => self.accept(channel_id, ttl_seconds, since),
                Verdict::NonceExpired { channel_id, hello } => {
                    let error = frames::error(ErrorCode::NonceExpired, Some(channel_id), None);
                    match self.send(&error).await {
                        Flow::Continue => self.send(&hello).await,
                        stopped => stopped,
                    }
                }
                Verdict::BadTtl { channel_id } => {
                    let error = frames::error(ErrorCode::BadTtl, Some(channel_id), None);
                    self.send(&error).await
                }
                Verdict::BadAuth { channel_id } => {
                    let error = frames::error(ErrorCode::BadAuth, Some(channel_id), None);
                    self.send(&error).await
                }
                Verdict::Close => Flow::Close(POLICY_VIOLATION),
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
        if self
            .shared
            .hub()
            .subscribe(self.id, channel_id, ttl_seconds)
            == Registered::Already
        {
            return Flow::Continue;
        }
        // `since` past the server's clock reads as now (R7).
        let now = self.shared.clock.wall_ms();
        self.catching.push_back(CatchUp {
            channel_id,
            from: since.unwrap_or(0).min(now),
            last: None,
            done: false,
        });
        Flow::Continue
    }

    /// One step of the catch-up of the next subscription in turn: the queue
    /// written first, then one backlog page, or once the backlog is done its
    /// held pushes, or its `ok` (R7, R8).
    async fn catch_up(&mut self) -> Flow {
        while let Ok(frame) = self.queue.try_recv() {
            let flow = self.write(frame).await;
            if !matches!(flow, Flow::Continue) {
                return flow;
            }
        }
        let Some(mut step) = self.catching.pop_front() else {
            return Flow::Continue;
        };
        if !self.shared.hub().is_catching_up(self.id, &step.channel_id) {
            // Ended by R8: its stream stops, and nothing more of it is sent.
            return Flow::Continue;
        }
        let flow = if step.done {
            self.after_backlog(&step).await
        } else {
            self.backlog_page(&mut step).await
        };
        // Over once its `ok` is queued or the subscription ended; in turn
        // again otherwise.
        let over = step.done && !self.shared.hub().is_catching_up(self.id, &step.channel_id);
        if matches!(flow, Flow::Continue) && !over {
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
            if self.shared.hooks.fail_reads.load(Ordering::SeqCst) {
                return Flow::Close(INTERNAL_ERROR);
            }
        }
        let page = match read_page(&self.shared.pool, step.channel_id, step.from, now).await {
            Ok(page) => page,
            Err(_) => return Flow::Close(INTERNAL_ERROR),
        };
        let Some(last) = page.last().map(|row| row.received_at) else {
            step.done = true;
            return Flow::Continue;
        };
        for row in page {
            let push = Frame::Push {
                channel_id: step.channel_id,
                server_id: row.server_id,
                received_at: row.received_at,
                blob: row.blob,
            };
            let flow = self.send(&push).await;
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
        let next = self
            .shared
            .hub()
            .after_backlog(self.id, step.channel_id, step.last);
        let Next::Held(pushes) = next else {
            return Flow::Continue;
        };
        for push in pushes {
            let flow = self.write(push).await;
            if !matches!(flow, Flow::Continue) {
                return flow;
            }
        }
        Flow::Continue
    }

    /// Encodes and writes `frame`.
    async fn send(&mut self, frame: &Frame) -> Flow {
        match frame.encode() {
            Ok(bytes) => self.write(bytes.into()).await,
            Err(_) => Flow::Close(INTERNAL_ERROR),
        }
    }

    /// Writes an encoded frame; a socket that fails or stalls past
    /// `WRITE_TIMEOUT` is gone.
    async fn write(&mut self, frame: Encoded) -> Flow {
        #[cfg(test)]
        {
            let mut paused = self.shared.hooks.writes_paused.subscribe();
            let _ = paused.wait_for(|paused| !paused).await;
        }
        let sent = tokio::time::timeout(WRITE_TIMEOUT, self.socket.send(Message::Binary(frame)));
        match sent.await {
            Ok(Ok(())) => Flow::Continue,
            Ok(Err(_)) | Err(_) => Flow::Gone,
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

/// Sends a close frame of `code` with no reason; a socket already gone has
/// nothing to hear it.
async fn close(socket: &mut WebSocket, code: u16) {
    let frame = CloseFrame {
        code,
        reason: "".into(),
    };
    let _ = tokio::time::timeout(WRITE_TIMEOUT, socket.send(Message::Close(Some(frame)))).await;
}
