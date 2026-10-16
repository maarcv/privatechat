//! The hooks of the tests: a pause before each batch, a call with the
//! connection before each transaction and before each commit, and a
//! source of `server_id`s.

use std::path::Path;
use std::sync::{Arc, Condvar, Mutex};

use rusqlite::Connection;

use super::purge::Counters;
use super::{Clock, OnCommit, StartError, Writer};
use crate::limits::ChannelLimits;

/// A pause the test releases, and can set again once the writer has
/// stopped at it.
#[derive(Default)]
pub(crate) struct Pause {
    state: Mutex<PauseState>,
    changed: Condvar,
}

#[derive(Default)]
struct PauseState {
    paused: bool,
    /// The writer is waiting at the pause.
    parked: bool,
}

impl Pause {
    pub(crate) fn paused() -> Arc<Pause> {
        let pause = Pause::default();
        pause.state.lock().unwrap().paused = true;
        Arc::new(pause)
    }

    pub(crate) fn release(&self) {
        self.state.lock().unwrap().paused = false;
        self.changed.notify_all();
    }

    /// Pauses the writer again and returns once it waits at the pause, so
    /// that what is submitted next is one batch.
    pub(crate) fn hold(&self) {
        let mut state = self.state.lock().unwrap();
        state.paused = true;
        // Bounded, so that a writer that stopped fails the test, not hangs it.
        let (state, waited) = self
            .changed
            .wait_timeout_while(state, std::time::Duration::from_secs(30), |state| {
                !state.parked
            })
            .unwrap();
        assert!(!waited.timed_out(), "the writer never reached the pause");
        drop(state);
    }
}

pub(crate) type ConnectionHook = Box<dyn FnMut(&Connection) + Send>;

pub(crate) type StepHook = Box<dyn FnMut(&Connection, &Counters) + Send>;

#[derive(Default)]
pub(crate) struct Hooks {
    pub(crate) pause: Option<Arc<Pause>>,
    pub(crate) before_transaction: Option<ConnectionHook>,
    pub(crate) before_commit: Option<ConnectionHook>,
    pub(crate) server_id: Option<Box<dyn FnMut() -> [u8; 16] + Send>>,
    /// Hears how many rows each purge round deleted.
    pub(crate) purge_round: Option<Box<dyn FnMut(usize) + Send>>,
    /// Sees the connection and the counters after each batch and each purge.
    pub(crate) after_step: Option<StepHook>,
}

impl super::Hooks {
    pub(super) fn wait_while_paused(&self) {
        if let Some(pause) = &self.test.pause {
            let mut state = pause.state.lock().unwrap();
            while state.paused {
                state.parked = true;
                pause.changed.notify_all();
                state = pause.changed.wait(state).unwrap();
            }
            state.parked = false;
        }
    }

    pub(super) fn before_transaction(&mut self, connection: &Connection) {
        if let Some(hook) = &mut self.test.before_transaction {
            hook(connection);
        }
    }

    pub(super) fn before_commit(&mut self, connection: &Connection) {
        if let Some(hook) = &mut self.test.before_commit {
            hook(connection);
        }
    }

    pub(super) fn purge_round(&mut self, rows: usize) {
        if let Some(hook) = &mut self.test.purge_round {
            hook(rows);
        }
    }

    pub(super) fn after_step(&mut self, connection: &Connection, counters: &Counters) {
        if let Some(hook) = &mut self.test.after_step {
            hook(connection, counters);
        }
    }

    pub(super) fn server_id(&mut self) -> Option<[u8; 16]> {
        match &mut self.test.server_id {
            Some(next) => Some(next()),
            None => privatechat_core::relay::new_server_id().ok(),
        }
    }
}

/// `Writer::spawn` with hooks.
pub(crate) fn spawn(
    db: &Path,
    clock: Arc<dyn Clock>,
    on_commit: OnCommit,
    max_db_bytes: u64,
    limits: ChannelLimits,
    hooks: Hooks,
) -> Result<Writer, StartError> {
    Writer::start(
        db,
        clock,
        on_commit,
        max_db_bytes,
        limits,
        super::Hooks { test: hooks },
    )
}
