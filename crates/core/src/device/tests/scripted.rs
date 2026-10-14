//! Doubles whose created stores fail their first load as a test scripts
//! it, so that the retry of spec 027-core-api R4 reads what the first
//! attempt could not; `Faults::fail_loads` fails every load alike.

use super::{Fixture, NOW};
use crate::device::Device;
use crate::storage::{
    ChannelState, DirName, LogRecord, Settings, Store, StoreError, Vault, WriteBatch,
};
use crate::testing::FailingVault;

/// A store whose first `load` fails with `fail`, when set.
struct ScriptedStore {
    inner: Box<dyn Store>,
    fail: Option<StoreError>,
}

impl Store for ScriptedStore {
    fn name(&self) -> &DirName {
        self.inner.name()
    }

    fn load(&mut self) -> Result<Option<(ChannelState, Vec<LogRecord>)>, StoreError> {
        match self.fail.take() {
            Some(error) => Err(error),
            None => self.inner.load(),
        }
    }

    fn commit(&mut self, batch: &WriteBatch) -> Result<(), StoreError> {
        self.inner.commit(batch)
    }

    fn compact(&mut self, state: &ChannelState, now: u64) -> Result<u32, StoreError> {
        self.inner.compact(state, now)
    }

    fn log_len(&self) -> u64 {
        self.inner.log_len()
    }

    fn destroy(&mut self) -> Result<(), StoreError> {
        self.inner.destroy()
    }
}

/// A vault whose `n`-th created store fails its first load with
/// `loads[n]`, so that a retry can read what the first attempt could not.
struct ScriptedVault {
    inner: Box<dyn Vault>,
    loads: Vec<Option<StoreError>>,
}

impl Vault for ScriptedVault {
    fn list(&mut self) -> Result<Vec<Box<dyn Store>>, StoreError> {
        self.inner.list()
    }

    fn create(&mut self, channel_id: &[u8; 16]) -> Result<Box<dyn Store>, StoreError> {
        let fail = if self.loads.is_empty() {
            None
        } else {
            self.loads.remove(0)
        };
        let inner = self.inner.create(channel_id)?;
        Ok(Box::new(ScriptedStore { inner, fail }))
    }

    fn remove(&mut self, name: &DirName) -> Result<(), StoreError> {
        self.inner.remove(name)
    }

    fn dir_name(&self, channel_id: &[u8; 16]) -> Result<DirName, StoreError> {
        self.inner.dir_name(channel_id)
    }

    fn load_settings(&mut self) -> Result<Option<Settings>, StoreError> {
        self.inner.load_settings()
    }

    fn save_settings(&mut self, settings: &Settings) -> Result<(), StoreError> {
        self.inner.save_settings(settings)
    }
}

/// A `Device` over `fixture` whose created stores fail their first load
/// as `loads` says.
pub(super) fn open_scripted(fixture: &Fixture, loads: Vec<Option<StoreError>>) -> Device {
    let failing = FailingVault::new(Box::new(fixture.vault.clone()), fixture.faults.clone());
    let vault = ScriptedVault {
        inner: Box::new(failing),
        loads,
    };
    Device::open(Box::new(vault), NOW).unwrap()
}
