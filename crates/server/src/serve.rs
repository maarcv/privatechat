//! The entry points of spec 035-server-ops R10: `bind` opens the database
//! and binds the listeners, so that the caller learns the ports before any
//! connection; `Bound::run` serves the route of spec 030 on each listener
//! (R2) until its shutdown future resolves, and never exits the process.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::task::JoinSet;

use crate::clock::Clock;
use crate::config::Settings;
use crate::connection::spawn_deadline_task;
use crate::http::{Shared, router};
use crate::limits::Listener;
use crate::{StartError, StartReason};

/// How `run` ended (R7, R8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Stopped by its shutdown future: exit code 0.
    Stopped,
    /// Anything else: exit code 1.
    Fatal,
}

/// A server whose database is open and whose listeners are bound, not yet
/// serving.
pub struct Bound {
    shared: Arc<Shared>,
    main: std::net::TcpListener,
    onion: Option<std::net::TcpListener>,
}

/// Opens the database of `settings` and binds its listeners, the main one
/// first (R2, R10).
///
/// # Errors
///
/// `StartError` of reason `Database` for a database refused at start-up
/// (spec 032-storage-ttl R3), or `Bind` for a listener that cannot bind.
pub fn bind(settings: Settings, clock: Arc<dyn Clock>) -> Result<Bound, StartError> {
    let shared = Shared::open(
        &settings.db,
        clock,
        settings.hosts,
        settings.max_db_bytes,
        settings.channel,
        settings.connections,
    )?;
    let main = listen(settings.listen)?;
    let onion = settings.onion_listen.map(listen).transpose()?;
    Ok(Bound {
        shared,
        main,
        onion,
    })
}

/// A listener on `address`, non-blocking, as tokio takes it.
fn listen(address: SocketAddr) -> Result<std::net::TcpListener, StartError> {
    let refused = |_| StartError {
        reason: StartReason::Bind,
    };
    #[allow(
        clippy::disallowed_methods,
        reason = "the one place the server binds its listeners (spec 035 R10)"
    )]
    let listener = std::net::TcpListener::bind(address).map_err(refused)?;
    listener.set_nonblocking(true).map_err(refused)?;
    Ok(listener)
}

impl Bound {
    /// The bound addresses: the main listener's, then the onion listener's
    /// when it is on.
    pub fn local_addrs(&self) -> Vec<SocketAddr> {
        std::iter::once(&self.main)
            .chain(&self.onion)
            .filter_map(|listener| listener.local_addr().ok())
            .collect()
    }

    /// Serves both listeners until `shutdown` resolves.
    pub async fn run(self, shutdown: impl Future<Output = ()> + Send) -> Outcome {
        let Bound {
            shared,
            main,
            onion,
        } = self;
        let mut listeners = JoinSet::new();
        let Ok(main) = tokio::net::TcpListener::from_std(main) else {
            return Outcome::Fatal;
        };
        // The main listener's connections carry the peer's address (R3).
        let service = router(shared.clone(), Listener::Main)
            .into_make_service_with_connect_info::<SocketAddr>();
        listeners.spawn(axum::serve(main, service).into_future());
        if let Some(onion) = onion {
            let Ok(onion) = tokio::net::TcpListener::from_std(onion) else {
                return Outcome::Fatal;
            };
            listeners
                .spawn(axum::serve(onion, router(shared.clone(), Listener::Onion)).into_future());
        }
        let deadlines = spawn_deadline_task(
            shared.ticks.clone(),
            shared.gate.clone(),
            shared.clock.clone(),
        );
        let outcome = tokio::select! {
            () = shutdown => Outcome::Stopped,
            // A listener serves until it is stopped: one that ends is fatal.
            _ = listeners.join_next() => Outcome::Fatal,
        };
        listeners.abort_all();
        deadlines.abort();
        outcome
    }

    /// What every connection shares, for the tests that look inside.
    #[cfg(test)]
    pub(crate) fn shared(&self) -> &Arc<Shared> {
        &self.shared
    }
}
