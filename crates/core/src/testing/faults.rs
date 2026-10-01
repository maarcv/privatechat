//! `Faults`, `FailingStore` and `FailingVault`: a `Store` and a `Vault` that
//! fail on command, for the `FailingStore` test every stateful spec has
//! (AGENTS 23).
//!
//! A fault fails a call with `Io` before it reaches the wrapped store, so
//! the store keeps the previous commit, except `poison_after`, which lets
//! its call through and then fails it, as a store poisoned after its rename
//! (spec 020 R11).

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use crate::storage::{
    ChannelState, DirName, LogRecord, Settings, Store, StoreError, Vault, WriteBatch,
};

/// What the faults are armed with, shared by the test and every double.
#[derive(Default)]
struct Armed {
    /// `fail_at` and `poison_after`, each with the calls of `commit`,
    /// `compact` and `destroy` counted since it was armed.
    fail_at: Option<Countdown>,
    poison_after: Option<Countdown>,
    fail_commits: bool,
    fail_compactions: bool,
    /// Calls of `create` since `fail_create_at` was armed.
    creates: u32,
    fail_create_at: Option<u32>,
    fail_create: bool,
    fail_remove: bool,
    fail_list: bool,
    fail_load_settings: bool,
    fail_save_settings: bool,
    /// The last state each directory's store let through.
    last_committed: BTreeMap<DirName, ChannelState>,
}

/// A fault armed for the `at`-th counted call, and the calls counted since.
#[derive(Clone, Copy)]
struct Countdown {
    at: u32,
    calls: u32,
}

impl Countdown {
    /// Counts one call; whether it is the armed one.
    fn tick(countdown: &mut Option<Countdown>) -> bool {
        countdown.as_mut().is_some_and(|countdown| {
            countdown.calls = countdown.calls.saturating_add(1);
            countdown.calls == countdown.at
        })
    }
}

/// A handle to the faults, `Clone` so that the test keeps one after giving
/// the doubles theirs.
#[derive(Clone, Default)]
pub struct Faults {
    armed: Arc<Mutex<Armed>>,
}

/// Which of the counted calls a store is making.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Call {
    Commit,
    Compact,
    Destroy,
}

/// What a counted call does.
enum Verdict {
    Fail,
    Pass,
    PassThenPoison,
}

impl Faults {
    /// No fault armed.
    pub fn new() -> Faults {
        Faults::default()
    }

    /// The armed faults; a test that panicked while holding them leaves them
    /// as they were.
    fn armed(&self) -> MutexGuard<'_, Armed> {
        self.armed.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Fails the `n`-th `commit`, `compact` or `destroy` from now, across
    /// every store sharing this handle.
    pub fn fail_at(&self, n: u32) {
        self.armed().fail_at = Some(Countdown { at: n, calls: 0 });
    }

    /// Lets the `n`-th `commit`, `compact` or `destroy` from now through,
    /// then fails it and every later call of that one store.
    pub fn poison_after(&self, n: u32) {
        self.armed().poison_after = Some(Countdown { at: n, calls: 0 });
    }

    /// Fails every `commit` while on.
    pub fn fail_commits(&self, on: bool) {
        self.armed().fail_commits = on;
    }

    /// Fails every `compact` while on.
    pub fn fail_compactions(&self, on: bool) {
        self.armed().fail_compactions = on;
    }

    /// Fails every `Vault::create` while on.
    pub fn fail_create(&self, on: bool) {
        self.armed().fail_create = on;
    }

    /// Fails the `n`-th `Vault::create` from now.
    pub fn fail_create_at(&self, n: u32) {
        let mut armed = self.armed();
        armed.creates = 0;
        armed.fail_create_at = Some(n);
    }

    /// Fails every `Vault::remove` while on.
    pub fn fail_remove(&self, on: bool) {
        self.armed().fail_remove = on;
    }

    /// Fails every `Vault::list` while on.
    pub fn fail_list(&self, on: bool) {
        self.armed().fail_list = on;
    }

    /// Fails every `Vault::load_settings` while on.
    pub fn fail_load_settings(&self, on: bool) {
        self.armed().fail_load_settings = on;
    }

    /// Fails every `Vault::save_settings` while on.
    pub fn fail_save_settings(&self, on: bool) {
        self.armed().fail_save_settings = on;
    }

    /// A duplicate of the last state a store of `name` let through.
    pub fn last_committed(&self, name: &DirName) -> Option<ChannelState> {
        let armed = self.armed();
        armed.last_committed.get(name).map(ChannelState::duplicate)
    }

    /// Counts a call and says what it does.
    fn verdict(&self, call: Call) -> Verdict {
        let mut armed = self.armed();
        let failing = Countdown::tick(&mut armed.fail_at);
        let poisoning = Countdown::tick(&mut armed.poison_after);
        let blocked = match call {
            Call::Commit => armed.fail_commits,
            Call::Compact => armed.fail_compactions,
            Call::Destroy => false,
        };
        if blocked || failing {
            Verdict::Fail
        } else if poisoning {
            Verdict::PassThenPoison
        } else {
            Verdict::Pass
        }
    }

    /// Whether a `create` fails, counting it.
    fn create_fails(&self) -> bool {
        let mut armed = self.armed();
        armed.creates = armed.creates.saturating_add(1);
        armed.fail_create || armed.fail_create_at == Some(armed.creates)
    }
}

/// A `Store` that fails as its `Faults` say.
pub struct FailingStore {
    inner: Box<dyn Store>,
    faults: Faults,
    poisoned: bool,
}

impl FailingStore {
    /// Wraps `inner`.
    pub fn new(inner: Box<dyn Store>, faults: Faults) -> FailingStore {
        FailingStore {
            inner,
            faults,
            poisoned: false,
        }
    }

    /// Runs a counted call through the faults.
    fn counted<T>(
        &mut self,
        call: Call,
        run: impl FnOnce(&mut dyn Store) -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        if self.poisoned {
            return Err(StoreError::Io);
        }
        match self.faults.verdict(call) {
            Verdict::Fail => Err(StoreError::Io),
            Verdict::Pass => run(self.inner.as_mut()),
            Verdict::PassThenPoison => {
                let _ = run(self.inner.as_mut());
                self.poisoned = true;
                Err(StoreError::Io)
            }
        }
    }
}

impl Store for FailingStore {
    fn name(&self) -> &DirName {
        self.inner.name()
    }

    fn load(&mut self) -> Result<Option<(ChannelState, Vec<LogRecord>)>, StoreError> {
        if self.poisoned {
            return Err(StoreError::Io);
        }
        self.inner.load()
    }

    fn commit(&mut self, batch: &WriteBatch) -> Result<(), StoreError> {
        let name = *self.inner.name();
        let faults = self.faults.clone();
        self.counted(Call::Commit, |store| {
            store.commit(batch)?;
            let state = batch.state().duplicate();
            faults.armed().last_committed.insert(name, state);
            Ok(())
        })
    }

    fn compact(&mut self, state: &ChannelState, now: u64) -> Result<u32, StoreError> {
        self.counted(Call::Compact, |store| store.compact(state, now))
    }

    fn log_len(&self) -> u64 {
        self.inner.log_len()
    }

    fn destroy(&mut self) -> Result<(), StoreError> {
        self.counted(Call::Destroy, |store| store.destroy())
    }
}

/// A `Vault` that fails as its `Faults` say, and hands out `FailingStore`s
/// that share them.
pub struct FailingVault {
    inner: Box<dyn Vault>,
    faults: Faults,
}

impl FailingVault {
    /// Wraps `inner`.
    pub fn new(inner: Box<dyn Vault>, faults: Faults) -> FailingVault {
        FailingVault { inner, faults }
    }

    /// `Io` when `failing`.
    fn check(failing: bool) -> Result<(), StoreError> {
        if failing {
            return Err(StoreError::Io);
        }
        Ok(())
    }

    /// `store` wrapped with this vault's faults.
    fn wrap(&self, store: Box<dyn Store>) -> Box<dyn Store> {
        Box::new(FailingStore::new(store, self.faults.clone()))
    }
}

impl Vault for FailingVault {
    fn list(&mut self) -> Result<Vec<Box<dyn Store>>, StoreError> {
        FailingVault::check(self.faults.armed().fail_list)?;
        let stores = self.inner.list()?;
        Ok(stores.into_iter().map(|store| self.wrap(store)).collect())
    }

    fn create(&mut self, channel_id: &[u8; 16]) -> Result<Box<dyn Store>, StoreError> {
        FailingVault::check(self.faults.create_fails())?;
        let store = self.inner.create(channel_id)?;
        Ok(self.wrap(store))
    }

    fn remove(&mut self, name: &DirName) -> Result<(), StoreError> {
        FailingVault::check(self.faults.armed().fail_remove)?;
        self.inner.remove(name)
    }

    fn dir_name(&self, channel_id: &[u8; 16]) -> Result<DirName, StoreError> {
        self.inner.dir_name(channel_id)
    }

    fn load_settings(&mut self) -> Result<Option<Settings>, StoreError> {
        FailingVault::check(self.faults.armed().fail_load_settings)?;
        self.inner.load_settings()
    }

    fn save_settings(&mut self, settings: &Settings) -> Result<(), StoreError> {
        FailingVault::check(self.faults.armed().fail_save_settings)?;
        self.inner.save_settings(settings)
    }
}
