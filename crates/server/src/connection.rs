//! One task per WebSocket (spec 030-ws-protocol R4–R6): it sends the
//! `hello`, reads the client's frames, answers each `subscribe` with the
//! verdicts of spec 031-auth-channel-signature, and closes on anything a
//! client of spec 028 never sends. The deadline task wakes it every 100 ms of
//! real time to check its deadlines on the monotonic clock (spec
//! 032-storage-ttl R14).

use std::sync::Arc;
use std::time::Duration;

use axum::extract::ws::{CloseFrame, Message, WebSocket};
use privatechat_core::Frame;
use tokio::sync::broadcast;

use crate::auth::{AuthState, Verdict};
use crate::frames::{self, ErrorCode};
use crate::http::Shared;

/// How often the deadline task wakes, in real time (spec 032 R14).
const TICK: Duration = Duration::from_millis(100);

/// How long one write may take before the connection is dropped. Until spec
/// 033-rate-limit-quotas R5 measures the pending write on the monotonic clock
/// from the deadline task, this bounds it in real time, so that a peer that
/// stops reading cannot hold the task, the first-subscribe deadline included.
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// The close codes the server sends (RFC 6455 §7.4.1).
const UNSUPPORTED_DATA: u16 = 1003;
const POLICY_VIOLATION: u16 = 1008;
const TOO_BIG: u16 = 1009;
const INTERNAL_ERROR: u16 = 1011;

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

/// What the task does after a frame.
enum Flow {
    Continue,
    Close(u16),
    /// The socket failed: nothing more can be said on it (spec 030 R15).
    Gone,
}

/// The connection of `socket`, until either side closes it.
pub(crate) async fn run(mut socket: WebSocket, shared: Arc<Shared>) {
    let mut ticks = shared.ticks.subscribe();
    let Ok((mut auth, hello)) = AuthState::new(shared.clock.mono_ms()) else {
        close(&mut socket, INTERNAL_ERROR).await;
        return;
    };
    match send(&mut socket, &hello).await {
        Flow::Continue => {}
        Flow::Close(code) => return close(&mut socket, code).await,
        Flow::Gone => return,
    }
    loop {
        let flow = tokio::select! {
            message = socket.recv() => match message {
                None | Some(Ok(Message::Close(_))) => return,
                Some(Ok(Message::Binary(bytes))) => on_frame(&mut socket, &mut auth, &shared, &bytes).await,
                Some(Ok(Message::Text(_))) => Flow::Close(UNSUPPORTED_DATA),
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => Flow::Continue,
                Some(Err(error)) => match read_error(error) {
                    Some(code) => Flow::Close(code),
                    None => return,
                },
            },
            tick = ticks.recv() => match tick {
                // A lagging receiver missed ticks, which only delays the check.
                Ok(()) | Err(broadcast::error::RecvError::Lagged(_)) => {
                    if auth.deadline_passed(shared.clock.mono_ms()) {
                        Flow::Close(POLICY_VIOLATION)
                    } else {
                        Flow::Continue
                    }
                }
                Err(broadcast::error::RecvError::Closed) => return,
            },
        };
        match flow {
            Flow::Continue => {}
            Flow::Close(code) => return close(&mut socket, code).await,
            Flow::Gone => return,
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

/// One binary message from the client (R6).
async fn on_frame(
    socket: &mut WebSocket,
    auth: &mut AuthState,
    shared: &Shared,
    bytes: &[u8],
) -> Flow {
    match Frame::decode(bytes) {
        Ok(Frame::Subscribe {
            pk_ch,
            ttl_seconds,
            sig,
            since: _,
        }) => {
            let now = shared.clock.mono_ms();
            match auth.on_subscribe(&pk_ch, ttl_seconds, &sig, &shared.hosts, now) {
                Ok(verdicts) => answer(socket, verdicts).await,
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
async fn answer(socket: &mut WebSocket, verdicts: Vec<Verdict>) -> Flow {
    for verdict in verdicts {
        let flow = match verdict {
            // Spec 030 R7 sends the backlog first; until then the `ok` comes alone.
            Verdict::Accept { channel_id } => send(socket, &Frame::Ok { channel_id }).await,
            Verdict::NonceExpired { channel_id, hello } => {
                let error = frames::error(ErrorCode::NonceExpired, Some(channel_id), None);
                match send(socket, &error).await {
                    Flow::Continue => send(socket, &hello).await,
                    stopped => stopped,
                }
            }
            Verdict::BadTtl { channel_id } => {
                send(
                    socket,
                    &frames::error(ErrorCode::BadTtl, Some(channel_id), None),
                )
                .await
            }
            Verdict::BadAuth { channel_id } => {
                send(
                    socket,
                    &frames::error(ErrorCode::BadAuth, Some(channel_id), None),
                )
                .await
            }
            Verdict::Close => Flow::Close(POLICY_VIOLATION),
        };
        if !matches!(flow, Flow::Continue) {
            return flow;
        }
    }
    Flow::Continue
}

/// Writes `frame`; a frame that cannot be encoded closes with 1011, and a
/// socket that fails or stalls past `WRITE_TIMEOUT` is gone.
async fn send(socket: &mut WebSocket, frame: &Frame) -> Flow {
    let Ok(bytes) = frame.encode() else {
        return Flow::Close(INTERNAL_ERROR);
    };
    match tokio::time::timeout(WRITE_TIMEOUT, socket.send(Message::Binary(bytes.into()))).await {
        Ok(Ok(())) => Flow::Continue,
        Ok(Err(_)) | Err(_) => Flow::Gone,
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
