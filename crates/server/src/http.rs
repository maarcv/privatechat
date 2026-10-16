//! The one route of the server (spec 030-ws-protocol R3, R4): `GET /`
//! upgraded to a WebSocket of at most 70 000-byte messages, with no
//! extension and no subprotocol. Any other path or method gets 404, and a
//! request with an `Origin` header 403, both with an empty body.

use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::extract::ws::{WebSocketUpgrade, rejection::WebSocketUpgradeRejection};
use axum::http::header::ORIGIN;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use tokio::sync::broadcast;

use crate::clock::Clock;
use crate::connection;

/// The largest WebSocket message or frame the server reads (R4).
pub(crate) const MAX_MESSAGE: usize = 70_000;

/// What every connection shares.
pub(crate) struct Shared {
    pub(crate) clock: Arc<dyn Clock>,
    /// The hosts of the configured URLs, which a `subscribe` must sign
    /// (spec 031-auth-channel-signature R8).
    pub(crate) hosts: Vec<String>,
    /// The ticks of the deadline task (spec 032-storage-ttl R14).
    pub(crate) ticks: broadcast::Sender<()>,
}

/// The router of `Shared`.
pub(crate) fn router(shared: Arc<Shared>) -> Router {
    Router::new()
        .route("/", get(upgrade).fallback(not_found))
        .fallback(not_found)
        .with_state(shared)
}

async fn upgrade(
    State(shared): State<Arc<Shared>>,
    headers: HeaderMap,
    upgrade: Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
) -> Response {
    // No browser client in v1 (ADR 0017): a page of another origin gets
    // nothing, not even the upgrade.
    if headers.contains_key(ORIGIN) {
        return StatusCode::FORBIDDEN.into_response();
    }
    match upgrade {
        Ok(upgrade) => upgrade
            .max_message_size(MAX_MESSAGE)
            .max_frame_size(MAX_MESSAGE)
            .on_upgrade(move |socket| connection::run(socket, shared)),
        // Not an upgrade: nothing is served, and no text names the framework.
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn not_found() -> Response {
    StatusCode::NOT_FOUND.into_response()
}
