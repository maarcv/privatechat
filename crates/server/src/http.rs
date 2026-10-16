//! The one route of the server (spec 030-ws-protocol R3, R4): `GET /`
//! upgraded to a WebSocket of at most 70 000-byte messages, with no
//! extension and no subprotocol. Any other path or method, and a `GET /`
//! that is not an upgrade, gets 404; a `GET /` with an `Origin` header gets
//! 403; both with an empty body. The path and the method are checked first,
//! then the `Origin`, then the upgrade.

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

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
use crate::hub::Hub;
use crate::store::reader::ReadPool;
use crate::store::writer::Writer;
use crate::{DbCause, StartError, StartReason};

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
    /// The backlog reads (spec 032 R9).
    pub(crate) pool: ReadPool,
    /// The one writer (spec 032 R4), whose results the hub hands out.
    pub(crate) writer: Writer,
    hub: Arc<Mutex<Hub>>,
    next_id: AtomicU64,
    /// The database file, for the tests that plant rows in it.
    #[cfg(test)]
    db: std::path::PathBuf,
    #[cfg(test)]
    pub(crate) hooks: test::Hooks,
}

impl Shared {
    /// Opens the database at `db`, starts its writer, whose results go to the
    /// hub, and opens the read pool.
    ///
    /// # Errors
    ///
    /// `StartError` as `Writer::spawn` refuses the database, or of cause
    /// `Open` when the read pool cannot open it.
    pub(crate) fn open(
        db: &Path,
        clock: Arc<dyn Clock>,
        hosts: Vec<String>,
        max_db_bytes: u64,
    ) -> Result<Arc<Shared>, StartError> {
        let hub = Arc::new(Mutex::new(Hub::default()));
        let results = hub.clone();
        let on_commit = Box::new(move |outcomes| {
            results
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .on_commit(outcomes);
        });
        let writer = Writer::spawn(db, clock.clone(), on_commit, max_db_bytes)?;
        let pool = ReadPool::open(db).map_err(|_| StartError {
            reason: StartReason::Database(DbCause::Open),
        })?;
        let (ticks, _) = broadcast::channel(16);
        Ok(Arc::new(Shared {
            clock,
            hosts,
            ticks,
            pool,
            writer,
            hub,
            next_id: AtomicU64::new(0),
            #[cfg(test)]
            db: db.to_path_buf(),
            #[cfg(test)]
            hooks: test::Hooks::default(),
        }))
    }

    /// The hub, locked; a lock poisoned by a panic still holds its state.
    pub(crate) fn hub(&self) -> MutexGuard<'_, Hub> {
        self.hub.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The database file.
    #[cfg(test)]
    pub(crate) fn db_path(&self) -> &Path {
        &self.db
    }

    /// A new connection's id, never reused.
    pub(crate) fn next_connection(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::SeqCst)
    }
}

/// The router of `Shared`.
pub(crate) fn router(shared: Arc<Shared>) -> Router {
    Router::new()
        // axum's `get` also answers `HEAD`, which must get the 404 too.
        .route("/", get(upgrade).head(not_found).fallback(not_found))
        // Written out, so that the empty 404 does not rest on axum's default.
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

#[cfg(test)]
pub(crate) mod test {
    //! The points where the tests of specs 030, 033 and 035 watch or steer a
    //! connection: the backlog reads, a pause of its socket writes, a failing
    //! read and a failing `relay` call.

    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use tokio::sync::watch;

    pub(crate) struct Hooks {
        /// How many `read_page` calls the connections made.
        pub(crate) reads: AtomicUsize,
        /// While `true`, no connection writes to its socket.
        pub(crate) writes_paused: watch::Sender<bool>,
        /// `read_page` fails.
        pub(crate) fail_reads: AtomicBool,
        /// While `true`, no catch-up goes past its backlog (to its held
        /// pushes or its `ok`).
        pub(crate) catch_up_paused: watch::Sender<bool>,
        /// The first `relay` call of a `subscribe` fails as `Internal`; the
        /// others are made to fail in the tests of `AuthState`.
        pub(crate) fail_relay: AtomicBool,
    }

    impl Default for Hooks {
        fn default() -> Hooks {
            Hooks {
                reads: AtomicUsize::new(0),
                writes_paused: watch::channel(false).0,
                fail_reads: AtomicBool::new(false),
                catch_up_paused: watch::channel(false).0,
                fail_relay: AtomicBool::new(false),
            }
        }
    }

    impl Hooks {
        pub(crate) fn pause_writes(&self, paused: bool) {
            self.writes_paused.send_replace(paused);
        }

        pub(crate) fn reads(&self) -> usize {
            self.reads.load(Ordering::SeqCst)
        }
    }
}
