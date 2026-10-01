//! Tests of the doubles and comparisons the storage tests rely on (spec 020).

use super::{
    FailingVault, Faults, MemoryStore, MemoryVault, batch, record, records_eq, state_eq, state_for,
};
use crate::crypto::{PublicKey, Secret};
use crate::storage::state::items::PeerRecord;
use crate::storage::{DirName, MAX_LOG_LEN, Settings, Store, StoreError, Vault};

/// A peer seen once.
fn peer() -> PeerRecord {
    PeerRecord {
        pk: PublicKey([3; 32]),
        label: None,
        verified: false,
        muted: false,
        retired_at: None,
        first_seen: 1,
        last_seen: 1,
        max_counter: None,
        last_display_name: None,
    }
}

/// Spec 020, R29: `state_eq` sees a change in every field but the store's
/// log position, and `records_eq` a change in any record or in their order,
/// so that "`open(seal(x))` gives `x` under `state_eq`" means what it says.
#[test]
fn s020_t29_r29_comparisons_see_every_field() {
    let state = state_for([1; 16]);
    assert!(state_eq(&state, &state.duplicate()));
    let mut moved = state.duplicate();
    moved.log_committed_len = 99;
    moved.log_generation = 7;
    assert!(state_eq(&state, &moved));
    let changes: [fn(&mut crate::storage::ChannelState); 8] = [
        |s| s.channel_id = [2; 16],
        |s| s.config.push(0),
        |s| s.identity_seed = Secret::from_bytes([0x12; 32]),
        |s| s.send_counter = 1,
        |s| s.cursor = Some(0),
        |s| s.retiring_seed = Some(Secret::from_bytes([0x11; 32])),
        |s| s.read_only = true,
        |s| s.peers.push(peer()),
    ];
    for (at, change) in changes.iter().enumerate() {
        let mut changed = state.duplicate();
        change(&mut changed);
        assert!(!state_eq(&state, &changed), "change {at}");
    }
    let records = [record(1, 10), record(2, 10)];
    let same = [record(1, 10), record(2, 10)];
    assert!(records_eq(&records, &same));
    assert!(!records_eq(&records, &[record(2, 10), record(1, 10)]));
    assert!(!records_eq(&records, &[record(1, 10), record(2, 11)]));
    assert!(!records_eq(&records, &records[..1]));
    let batch = batch(state, vec![record(3, 1)]);
    assert!(state_eq(batch.state(), &state_for([1; 16])));
    assert_eq!(batch.records().len(), 1);
}

/// A vault and the store of channel `[1; 16]` in it.
fn memory() -> (MemoryVault, Box<dyn Store>) {
    let mut vault = MemoryVault::new();
    let store = vault.create(&[1; 16]).unwrap();
    (vault, store)
}

/// Spec 020, R10 (`MemoryStore`): a commit gives the new state and log, the
/// records at their offsets, and the counts of AGENTS 23: a commit that only
/// moves `cursor` or `synced_at` is not one of `commits`.
#[test]
fn s020_t10_r10_memory_commit() {
    let (vault, mut store) = memory();
    let name = *store.name();
    let handle = MemoryStore::handle(&vault, name);
    store
        .commit(&batch(state_for([1; 16]), vec![record(5, 10)]))
        .unwrap();
    store
        .commit(&batch(state_for([1; 16]), vec![record(6, 20)]))
        .unwrap();
    let (state, records) = store.load().unwrap().unwrap();
    assert!(state_eq(&state, &state_for([1; 16])));
    assert!(records_eq(&records, &[record(5, 10), record(6, 20)]));
    // 9 bytes of header, then 4 + 24 + 16 + the record per entry.
    let first = 4 + 24 + 16 + record(5, 10).encode(0, 9).unwrap().len();
    let second = 4 + 24 + 16 + record(6, 20).encode(0, 9).unwrap().len();
    assert_eq!(store.log_len(), u64::try_from(9 + first + second).unwrap());
    assert_eq!(state.log_position(), (store.log_len(), 0));
    let mut moved = state_for([1; 16]);
    moved.cursor = Some(7);
    moved.synced_at = Some(8);
    store.commit(&batch(moved, vec![])).unwrap();
    assert_eq!((handle.commits(), handle.all_commits()), (2, 3));
    let mut changed = state_for([1; 16]);
    changed.send_counter = 1;
    store.commit(&batch(changed, vec![])).unwrap();
    assert_eq!((handle.commits(), handle.all_commits()), (3, 4));
    let reopened = handle.reopen();
    assert_eq!(reopened.log_len(), store.log_len());
}

/// Spec 020, R13 (`MemoryStore`): a directory that no commit made durable
/// loads as `None` and `list` skips it; a log with an entry and no state is
/// `Corrupt`; the first commit writes the header of generation 0.
#[test]
fn s020_t13_r13_memory_first_commit() {
    let (vault, mut store) = memory();
    let name = *store.name();
    assert!(store.load().unwrap().is_none());
    let header =
        |magic: &[u8; 4], generation: u32| [&magic[..], &[1], &generation.to_be_bytes()].concat();
    let unborn: [Option<Vec<u8>>; 5] = [
        None,
        Some(vec![]),
        Some(vec![0; 5]),
        Some(header(b"PLOG", 0)),
        Some(header(b"XLOG", 1)),
    ];
    let mut listing = vault.clone();
    for log in unborn {
        vault.put_raw(&name, None, log.as_deref());
        assert!(store.load().unwrap().is_none(), "{log:?}");
        assert!(listing.list().unwrap().is_empty(), "{log:?}");
    }
    for log in [
        header(b"PLOG", 1),
        [header(b"PLOG", 0), vec![0; 4]].concat(),
    ] {
        vault.put_raw(&name, None, Some(&log));
        assert!(matches!(store.load(), Err(StoreError::Corrupt)));
        assert_eq!(listing.list().unwrap().len(), 1);
    }
    vault.put_raw(&name, None, None);
    store.commit(&batch(state_for([1; 16]), vec![])).unwrap();
    assert_eq!(store.log_len(), 9);
    let (state, records) = store.load().unwrap().unwrap();
    assert_eq!((state.log_position(), records.len()), ((9, 0), 0));
}

/// Spec 020, R15 (`MemoryStore`): compaction drops the records below `now`,
/// keeps the others in order under the next generation, and with nothing
/// to drop writes nothing.
#[test]
fn s020_t15_r15_memory_compaction() {
    let (_, mut store) = memory();
    let records = vec![record(1, 5), record(10, 6), record(2, 7), record(20, 8)];
    store.commit(&batch(state_for([1; 16]), records)).unwrap();
    let (state, _) = store.load().unwrap().unwrap();
    assert_eq!(store.compact(&state, 1).unwrap(), 0);
    assert_eq!(store.load().unwrap().unwrap().0.log_position().1, 0);
    assert_eq!(store.compact(&state, 10).unwrap(), 2);
    let (state, kept) = store.load().unwrap().unwrap();
    assert!(records_eq(&kept, &[record(10, 6), record(20, 8)]));
    assert_eq!(state.log_position(), (store.log_len(), 1));
}

/// Spec 020, R16 (`MemoryStore`): a commit past 67 108 864 bytes writes
/// nothing and is `LogFull`.
#[test]
fn s020_t16_r16_memory_log_full() {
    assert_eq!(MAX_LOG_LEN, 67_108_864);
    let (_, mut store) = memory();
    let big: Vec<_> = (0..1_000).map(|at| record(at, 64_000)).collect();
    store.commit(&batch(state_for([1; 16]), big)).unwrap();
    let before = store.log_len();
    let more: Vec<_> = (0..60).map(|at| record(at, 64_000)).collect();
    assert!(matches!(
        store.commit(&batch(state_for([1; 16]), more)),
        Err(StoreError::LogFull)
    ));
    assert_eq!(store.log_len(), before);
}

/// Spec 020, R22 (`MemoryVault`): no settings until saved, then the saved
/// ones; planted bytes that do not open are `Corrupt`.
#[test]
fn s020_t22_r22_memory_settings() {
    let mut vault = MemoryVault::new();
    assert!(vault.load_settings().unwrap().is_none());
    let settings = settings();
    vault.save_settings(&settings).unwrap();
    let loaded = vault.load_settings().unwrap().unwrap();
    assert_eq!(loaded.encode().unwrap(), settings.encode().unwrap());
    vault.put_settings_raw(&[0; 45]);
    assert!(matches!(vault.load_settings(), Err(StoreError::Corrupt)));
}

/// Spec 020, R11 (the doubles): `fail_at` fails one call before it touches
/// the store, which keeps the previous commit; `poison_after` lets its call
/// through, then fails it and every later call of that store only; the
/// switches fail their calls while on.
#[test]
fn s020_t11_r11_failing_doubles() {
    let faults = Faults::new();
    let mut vault = FailingVault::new(Box::new(MemoryVault::new()), faults.clone());
    let mut store = vault.create(&[1; 16]).unwrap();
    let name = *store.name();
    let first = batch(state_for([1; 16]), vec![record(1, 1)]);
    store.commit(&first).unwrap();
    assert!(state_eq(
        &faults.last_committed(&name).unwrap(),
        first.state()
    ));
    faults.fail_at(2);
    store.commit(&first).unwrap();
    let mut second = state_for([1; 16]);
    second.send_counter = 2;
    let second = batch(second, vec![record(2, 1)]);
    assert!(matches!(store.commit(&second), Err(StoreError::Io)));
    let (state, records) = store.load().unwrap().unwrap();
    assert_eq!((state.send_counter, records.len()), (0, 2));
    store.commit(&second).unwrap();
    // Poisoned after its commit went through: the next load sees it, the
    // poisoned store refuses everything, a store handed out later works.
    faults.poison_after(1);
    let mut third = state_for([1; 16]);
    third.send_counter = 3;
    assert!(matches!(
        store.commit(&batch(third, vec![])),
        Err(StoreError::Io)
    ));
    assert!(matches!(store.load(), Err(StoreError::Io)));
    assert!(matches!(store.destroy(), Err(StoreError::Io)));
    let mut again = vault.create(&[1; 16]).unwrap();
    assert_eq!(again.load().unwrap().unwrap().0.send_counter, 3);
    faults.fail_commits(true);
    assert!(matches!(again.commit(&second), Err(StoreError::Io)));
    let (state, _) = again.load().unwrap().unwrap();
    assert_eq!(again.compact(&state, 0).unwrap(), 0);
    faults.fail_commits(false);
    faults.fail_compactions(true);
    assert!(matches!(again.compact(&state, 5), Err(StoreError::Io)));
    again.commit(&second).unwrap();
    faults.fail_compactions(false);
    type Switch = fn(&Faults, bool);
    type Fails = fn(&mut FailingVault) -> bool;
    let switches: [(Switch, Fails); 5] = [
        (Faults::fail_create, |vault| vault.create(&[2; 16]).is_err()),
        (Faults::fail_remove, |vault| {
            vault.remove(&DirName([0; 16])).is_err()
        }),
        (Faults::fail_list, |vault| vault.list().is_err()),
        (Faults::fail_load_settings, |vault| {
            vault.load_settings().is_err()
        }),
        (Faults::fail_save_settings, |vault| {
            vault.save_settings(&settings()).is_err()
        }),
    ];
    for (at, (switch, fails)) in switches.into_iter().enumerate() {
        switch(&faults, true);
        assert!(fails(&mut vault), "switch {at}");
        switch(&faults, false);
        assert!(!fails(&mut vault), "switch {at}");
    }
    faults.fail_create_at(2);
    assert!(vault.create(&[3; 16]).is_ok());
    assert!(vault.create(&[4; 16]).is_err());
    assert!(vault.create(&[4; 16]).is_ok());
}

/// Valid settings.
fn settings() -> Settings {
    Settings {
        default_server_url: "wss://chat.example.org".to_owned(),
        lock_timeout_seconds: 0,
        socks5_proxy: None,
    }
}
