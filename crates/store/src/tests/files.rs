//! Tests of spec 020 over the layout of the files and the data directory:
//! R4–R7 on the store's side, R13, R16 and R18–R22, R28.

use std::path::Path;

use privatechat_core::testing::{batch, record, settings, settings_eq, state_for};
use privatechat_core::{ChannelState, DirName, MAX_STATE_FILE, Store, StoreError, Vault};

use super::{TestDir, channel_dir, commit, dir_name, id, key, loaded, open, reopen};
use crate::DataDir;
use crate::frame::{self, LOG_HEADER_LEN};
use crate::fs::Io;

fn read(path: &Path) -> Vec<u8> {
    std::fs::read(path).expect("read a test file")
}

fn write(path: &Path, bytes: &[u8]) {
    std::fs::write(path, bytes).expect("write a test file")
}

/// A sealed state of channel `n` naming the log position `(len, generation)`,
/// framed as `state.bin`.
fn state_file(n: u8, len: u64, generation: u32) -> Vec<u8> {
    let sealed = state_for(id(n))
        .seal(&key(), &dir_name(n), len, generation)
        .expect("seal");
    frame::frame(frame::STATE_MAGIC, &sealed)
}

/// Spec 020, R4: `state.bin` and `settings.bin` begin with their magic and
/// version 1.
#[test]
fn s020_t04_r04_file_layouts() {
    let dir = TestDir::new("t04");
    let mut data = open(dir.path());
    let mut store = data.create(&id(1)).expect("create");
    commit(store.as_mut(), 1, &[]).expect("commit");
    data.save_settings(&settings("wss://example.org", 60, None))
        .expect("save");
    let state = read(&channel_dir(dir.path(), 1).join("state.bin"));
    assert_eq!(state.get(..5), Some(&b"PSTA\x01"[..]));
    let saved = read(&dir.path().join("settings.bin"));
    assert_eq!(saved.get(..5), Some(&b"PSET\x01"[..]));
}

/// Spec 020, R5: the log header, then each entry's `len` equal to its nonce
/// and box, back to back.
#[test]
fn s020_t05_r05_log_layout() {
    let dir = TestDir::new("t05");
    let mut data = open(dir.path());
    let mut store = data.create(&id(1)).expect("create");
    commit(store.as_mut(), 1, &[1, 2, 3]).expect("commit");
    let log = read(&channel_dir(dir.path(), 1).join("messages.log"));
    assert_eq!(log.get(..LOG_HEADER_LEN), Some(&frame::log_header(0)[..]));
    let mut at = LOG_HEADER_LEN;
    let mut entries = 0;
    while at < log.len() {
        let len: [u8; 4] = log[at..at + 4].try_into().expect("len");
        let len = u32::from_be_bytes(len) as usize;
        // A nonce of 24, a tag of 16 and a record.
        assert!(len > 40);
        at += 4 + len;
        entries += 1;
    }
    assert_eq!((at, entries), (log.len(), 3));
    assert_eq!(store.log_len(), log.len() as u64);
}

/// Spec 020, R6: a read stops one byte past the limit, and a `state.bin` one
/// byte over its limit is `Corrupt`.
#[test]
fn s020_t06_r06_size_before_read() {
    let dir = TestDir::new("t06");
    std::fs::create_dir(dir.path()).expect("test directory");
    let big = dir.path().join("big");
    write(&big, &vec![0u8; 1000]);
    let bytes = Io::new()
        .read_limited(&big, 100)
        .expect("read")
        .expect("present");
    assert_eq!(bytes.len(), 101);
    assert!(bytes.capacity() <= 101);
    let over = [&state_file(1, 9, 0)[..], &vec![0u8; MAX_STATE_FILE]].concat();
    let over = &over[..MAX_STATE_FILE + 1];
    assert!(matches!(
        frame::open_state(over, &key(), &dir_name(1)),
        Err(StoreError::Corrupt)
    ));
}

/// Spec 020, R7, the store's checks: the minimum size, the magic, the
/// version before the size, a forged version byte, and the log's header.
#[test]
fn s020_t07_r07_open_check_order() {
    let name = dir_name(1);
    let valid = state_file(1, 9, 0);
    let open_state = |bytes: &[u8]| frame::open_state(bytes, &key(), &name).map(|_| ());
    assert_eq!(open_state(&valid[..44]), Err(StoreError::Corrupt));
    let mut magic = valid.clone();
    magic[0] = b'X';
    assert_eq!(open_state(&magic), Err(StoreError::Corrupt));
    // Version 2 whose box does not open as version 1, short and over the
    // limit alike: the version is checked before the size.
    let newer = [&b"PSTA\x02"[..], &[0x5a; 60]].concat();
    assert_eq!(open_state(&newer), Err(StoreError::UnsupportedVersion));
    let newer_big = [&b"PSTA\x02"[..], &vec![0x5a; MAX_STATE_FILE]].concat();
    assert_eq!(open_state(&newer_big), Err(StoreError::UnsupportedVersion));
    let big = [&valid[..], &vec![0u8; MAX_STATE_FILE]].concat();
    assert_eq!(open_state(&big), Err(StoreError::Corrupt));
    // A version-1 file whose header byte says 2: forged outside the box.
    let mut forged = valid.clone();
    forged[4] = 2;
    assert_eq!(open_state(&forged), Err(StoreError::Corrupt));
    let sealed = settings("wss://example.org", 60, None)
        .seal(&key())
        .expect("seal");
    let mut forged = frame::frame(frame::SETTINGS_MAGIC, &sealed);
    forged[4] = 2;
    assert!(matches!(
        frame::open_settings(&forged, &key()),
        Err(StoreError::Corrupt)
    ));
    // The log next to a version-1 state: 8 bytes, or its version byte 2.
    let dir = TestDir::new("t07");
    let mut data = open(dir.path());
    let mut store = data.create(&id(1)).expect("create");
    commit(store.as_mut(), 1, &[1]).expect("commit");
    drop(store);
    let log = channel_dir(dir.path(), 1).join("messages.log");
    let committed = read(&log);
    write(&log, &committed[..8]);
    assert_eq!(reopen_in(&mut data, 1), Err(StoreError::Corrupt));
    let mut newer = committed.clone();
    newer[4] = 2;
    write(&log, &newer);
    assert_eq!(reopen_in(&mut data, 1), Err(StoreError::Corrupt));
}

/// Loads test channel `n` from a fresh store of `data`.
fn reopen_in(data: &mut DataDir, n: u8) -> Result<(), StoreError> {
    let mut store = data.create(&id(n))?;
    store.load().map(|_| ())
}

/// Spec 020, R13: a channel whose first commit never became durable loads as
/// `None`, and the first commit leaves a log of generation 0 and no entry.
#[test]
fn s020_t13_r13_first_commit() {
    let dir = TestDir::new("t13");
    let mut data = open(dir.path());
    let mut store = data.create(&id(1)).expect("create");
    assert!(store.load().expect("load").is_none());
    let log = channel_dir(dir.path(), 1).join("messages.log");
    let mut wrong_magic = frame::log_header(1).to_vec();
    wrong_magic[0] = b'X';
    for unborn in [
        &b""[..],
        &b"PLOG\x01"[..],
        &frame::log_header(0)[..],
        &wrong_magic[..],
    ] {
        write(&log, unborn);
        assert!(store.load().expect("load").is_none(), "{unborn:?}");
    }
    std::fs::remove_file(&log).expect("remove");
    commit(store.as_mut(), 1, &[]).expect("first commit");
    assert_eq!(read(&log), frame::log_header(0));
    assert_eq!(store.log_len(), LOG_HEADER_LEN as u64);
}

/// Spec 020, R16: an append past the limit writes nothing and is `LogFull`,
/// and `log_len` follows each commit.
#[test]
fn s020_t16_r16_log_full() {
    let dir = TestDir::new("t16");
    let mut data = open(dir.path());
    let mut store = data.create(&id(1)).expect("create");
    commit(store.as_mut(), 1, &[1]).expect("commit");
    let channel = channel_dir(dir.path(), 1);
    let before = (
        read(&channel.join("state.bin")),
        read(&channel.join("messages.log")),
    );
    assert_eq!(store.log_len(), before.1.len() as u64);
    // 1 100 records of the largest body pass 67 108 864 bytes.
    let records = (0..1_100).map(|at| record(at, 64_511)).collect();
    assert_eq!(
        store.commit(&batch(state_for(id(1)), records)),
        Err(StoreError::LogFull)
    );
    let after = (
        read(&channel.join("state.bin")),
        read(&channel.join("messages.log")),
    );
    assert_eq!(before, after);
    commit(store.as_mut(), 1, &[1, 2]).expect("commit");
    assert_eq!(
        store.log_len(),
        read(&channel.join("messages.log")).len() as u64
    );
}

/// Spec 020, R18: 32 lowercase hex characters, keyed, and not the
/// `channel_id`.
#[test]
fn s020_t18_r18_directory_name_is_keyed() {
    let dir = TestDir::new("t18");
    let mut data = open(dir.path());
    drop(data.create(&id(0xab)).expect("create"));
    let names: Vec<String> = std::fs::read_dir(dir.path().join("channels"))
        .expect("list")
        .map(|entry| {
            entry
                .expect("entry")
                .file_name()
                .into_string()
                .expect("utf-8")
        })
        .collect();
    assert_eq!(names.len(), 1);
    let name = &names[0];
    assert_eq!(name.len(), 32);
    assert!(
        name.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    );
    assert!(!name.contains("abababab"));
    assert_eq!(name, &crate::hex(&data.dir_name(&id(0xab)).expect("name")));
    let other = privatechat_core::dir_name(&StorageKeyOther::key(), &id(0xab)).expect("name");
    assert_ne!(crate::hex(&other), *name);
}

/// A second key, for R18.
struct StorageKeyOther;

impl StorageKeyOther {
    fn key() -> privatechat_core::StorageKey {
        privatechat_core::StorageKey::from_bytes(&mut [8u8; 32])
    }
}

/// Spec 020, R19: `open` deletes `.leaving` directories and channels whose
/// first commit never became durable, and keeps a channel that lost its
/// `state.bin`, which then loads as `Corrupt`.
#[test]
fn s020_t19_r19_open_cleans_leftovers() {
    let dir = TestDir::new("t19");
    let mut data = open(dir.path());
    for (n, log) in [
        (1, frame::log_header(0).to_vec()),
        (2, b"PLOG\x01".to_vec()),
        (3, frame::log_header(1).to_vec()),
    ] {
        drop(data.create(&id(n)).expect("create"));
        write(&channel_dir(dir.path(), n).join("messages.log"), &log);
    }
    let mut store = data.create(&id(4)).expect("create");
    commit(store.as_mut(), 4, &[1]).expect("commit");
    drop(store);
    std::fs::remove_file(channel_dir(dir.path(), 4).join("state.bin")).expect("lose the state");
    let leaving = dir.path().join("channels").join("x.leaving");
    std::fs::create_dir_all(leaving.join("inside")).expect("leaving");
    drop(data);
    let mut data = open(dir.path());
    assert!(!channel_dir(dir.path(), 1).exists());
    assert!(!channel_dir(dir.path(), 2).exists());
    assert!(!leaving.exists());
    let listed: Vec<DirName> = data
        .list()
        .expect("list")
        .iter()
        .map(|store| *store.name())
        .collect();
    let mut expected = vec![dir_name(3), dir_name(4)];
    expected.sort();
    let mut listed = listed;
    listed.sort();
    assert_eq!(listed, expected);
    for n in [3, 4] {
        assert_eq!(reopen_in(&mut data, n), Err(StoreError::Corrupt), "n={n}");
    }
}

/// Spec 020, R19: a `.leaving` directory that cannot be deleted does not
/// fail `open`, and `list` skips it.
#[cfg(unix)]
#[test]
fn s020_t19_r19_failed_cleanup_is_ignored() {
    use std::os::unix::fs::PermissionsExt;
    let dir = TestDir::new("t19b");
    drop(open(dir.path()));
    let leaving = dir
        .path()
        .join("channels")
        .join(format!("{}.leaving", crate::hex(&dir_name(1))));
    std::fs::create_dir_all(leaving.join("inside")).expect("leaving");
    std::fs::set_permissions(&leaving, std::fs::Permissions::from_mode(0o500)).expect("chmod");
    let mut data = open(dir.path());
    assert!(data.list().expect("list").is_empty());
    std::fs::set_permissions(&leaving, std::fs::Permissions::from_mode(0o700)).expect("chmod");
}

/// Spec 020, R20: one store per directory alive, stray entries ignored.
#[test]
fn s020_t20_r20_one_store_per_directory() {
    let dir = TestDir::new("t20");
    let mut data = open(dir.path());
    for n in 1..=3 {
        let mut store = data.create(&id(n)).expect("create");
        commit(store.as_mut(), n, &[]).expect("commit");
    }
    write(&dir.path().join("channels").join("stray"), b"x");
    std::fs::create_dir(dir.path().join("channels").join("backup")).expect("backup");
    let stores = data.list().expect("list");
    assert_eq!(stores.len(), 3);
    assert!(matches!(data.create(&id(1)), Err(StoreError::Locked)));
    assert!(matches!(data.list(), Err(StoreError::Locked)));
    drop(stores);
    let mut store = data.create(&id(1)).expect("create after drop");
    assert!(store.load().expect("load").is_some());
}

/// Spec 020, R21: `destroy` and `remove` delete a directory; a fault before
/// the rename leaves the store usable, one after it is `Ok`.
#[test]
fn s020_t21_r21_destroy_and_remove() {
    let dir = TestDir::new("t21");
    let mut data = open(dir.path());
    let mut store = data.create(&id(1)).expect("create");
    commit(store.as_mut(), 1, &[1]).expect("commit");
    store.destroy().expect("destroy");
    assert!(!channel_dir(dir.path(), 1).exists());
    drop(store);
    assert_eq!(data.dir_name(&id(1)), Ok(dir_name(1)));
    // A fault at each call of a destroy: the leftover delete, the rename,
    // then the directory's sync and the final delete.
    for k in 1..=4 {
        let mut store = data.create(&id(2)).expect("create");
        commit(store.as_mut(), 2, &[1]).expect("commit");
        drop(store);
        let mut faulty = data
            .store_with(dir_name(2), Io::failing_at(k))
            .expect("store");
        let result = faulty.destroy();
        let channel = channel_dir(dir.path(), 2);
        if k <= 2 {
            assert_eq!(result, Err(StoreError::Io), "k={k}");
            assert!(channel.exists());
            assert!(loaded(&mut faulty).expect("usable").is_some(), "k={k}");
        } else {
            assert_eq!(result, Ok(()), "k={k}");
            assert!(!channel.exists());
        }
        drop(faulty);
        drop(data);
        data = open(dir.path());
        let leaving = dir
            .path()
            .join("channels")
            .join(format!("{}.leaving", crate::hex(&dir_name(2))));
        assert!(!leaving.exists(), "k={k}");
        if channel.exists() {
            data.remove(&dir_name(2)).expect("remove");
        }
    }
    // A channel that does not load is removed by name.
    let mut store = data.create(&id(3)).expect("create");
    commit(store.as_mut(), 3, &[1]).expect("commit");
    drop(store);
    write(&channel_dir(dir.path(), 3).join("state.bin"), b"garbage");
    assert_eq!(reopen_in(&mut data, 3), Err(StoreError::Corrupt));
    data.remove(&dir_name(3)).expect("remove");
    assert!(!channel_dir(dir.path(), 3).exists());
    // A `.leaving` left behind does not stop the next destroy.
    let leaving = dir
        .path()
        .join("channels")
        .join(format!("{}.leaving", crate::hex(&dir_name(4))));
    std::fs::create_dir_all(&leaving).expect("leaving");
    let mut store = data.create(&id(4)).expect("create");
    commit(store.as_mut(), 4, &[]).expect("commit");
    store.destroy().expect("destroy");
    assert!(!leaving.exists());
}

/// Spec 020, R22: absent settings are `None`; saved settings load equal.
#[test]
fn s020_t22_r22_settings_file() {
    let dir = TestDir::new("t22");
    let mut data = open(dir.path());
    assert!(data.load_settings().expect("load").is_none());
    let saved = settings("wss://example.org", 300, Some("127.0.0.1:9050"));
    data.save_settings(&saved).expect("save");
    drop(data);
    let mut data = open(dir.path());
    let loaded = data.load_settings().expect("load").expect("present");
    assert!(settings_eq(&loaded, &saved));
    assert!(!dir.path().join("settings.bin.tmp").exists());
}

/// Spec 020, R28: the data directory and its stores can move between
/// threads.
#[test]
fn s020_t28_r28_send() {
    fn send<T: Send + ?Sized>() {}
    send::<DataDir>();
    send::<crate::channel::ChannelFiles>();
    send::<Box<dyn Store>>();
    let _: fn(&ChannelState) = |_| {};
    let _ = reopen;
}
