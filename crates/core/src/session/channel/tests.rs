//! Tests of spec 021 over `MemoryStore`, each requirement checked through the
//! calls of `Channel` and the state a reopened store holds.

use super::{Channel, ClientRef, ClockOff, Gap, SessionCarry};
use crate::Error;
use crate::crypto::{Nonce, PublicKey, Secret, Signature};
use crate::proto::config::Config;
use crate::proto::envelope::{self, ChannelCtx, SenderKey, text_k1};
use crate::proto::payload::{Payload, PayloadKind};
use crate::storage::state::items::{OldKey, OutboxEntry, OutboxKind};
use crate::storage::{Store, StoreError, Vault};
use crate::testing::{
    FailingStore, Faults, MemoryStore, MemoryVault, batch, record, state_eq, state_for,
};

mod gaps;
mod headroom;
mod outbox;
mod own_key;
mod receive;
mod send;
mod stall;
mod status;
mod sync;

const K_CH: [u8; 32] = [0xa5; 32];
/// A whole minute, the time of the planted retirement.
const NOW: u64 = 1_790_000_040_000;
const SERVER: &str = "wss://example.org";

/// A one-hour channel on `server_url`; its `channel_id` does not depend on
/// the URL.
fn config_on(server_url: &str) -> Config {
    Config::from_parts(Secret::from_bytes(K_CH), server_url, 3_600, "room", 0).unwrap()
}

/// A channel of `ttl_seconds` on `SERVER`.
fn config_with(ttl_seconds: u32) -> Config {
    Config::from_parts(Secret::from_bytes(K_CH), SERVER, ttl_seconds, "room", 0).unwrap()
}

/// A new store for the channel of `config_on(SERVER)`, and a handle to it.
fn new_store() -> (Box<dyn Store>, MemoryStore) {
    store_for(&config_on(SERVER))
}

/// A new store for the channel of `config`, and a handle to it.
fn store_for(config: &Config) -> (Box<dyn Store>, MemoryStore) {
    let mut vault = MemoryVault::new();
    let store = vault.create(&config.channel_id()).unwrap();
    let handle = MemoryStore::handle(&vault, *store.name());
    (store, handle)
}

/// A new channel and a handle to its store.
fn new_channel() -> (Channel, MemoryStore) {
    let (store, handle) = new_store();
    let (channel, created) = Channel::create(&config_on(SERVER), store).unwrap();
    assert!(created);
    (channel, handle)
}

/// A new channel of `config` over a `FailingStore`, a handle to its store
/// and its faults.
fn failing_channel(config: &Config) -> (Channel, MemoryStore, Faults) {
    let (store, handle) = store_for(config);
    let faults = Faults::new();
    let failing = Box::new(FailingStore::new(store, faults.clone()));
    let (channel, _) = Channel::create(config, failing).unwrap();
    (channel, handle, faults)
}

/// The channel of the 013 vectors, with `ttl_seconds`.
fn vector_config(ttl_seconds: u32) -> Config {
    let k_ch = Secret::from_bytes(text_k1::K_CH);
    let name = text_k1::SUGGESTED_NAME;
    Config::from_parts(
        k_ch,
        text_k1::SERVER_URL,
        ttl_seconds,
        name,
        text_k1::CREATED_AT,
    )
    .unwrap()
}

/// A new channel of the 013 vectors with `ttl_seconds`, over a
/// `FailingStore`; a handle to its store and its faults.
fn receiver(ttl_seconds: u32) -> (Channel, MemoryStore, Faults) {
    let config = vector_config(ttl_seconds);
    let (store, handle) = store_for(&config);
    let faults = Faults::new();
    let failing = Box::new(FailingStore::new(store, faults.clone()));
    let (channel, _) = Channel::create(&config, failing).unwrap();
    (channel, handle, faults)
}

/// A text from the sender of `seed`, sealed for `channel`.
fn text_from(channel: &Channel, seed: [u8; 32], counter: u64, sent_at: u64) -> Vec<u8> {
    let payload = Payload {
        kind: PayloadKind::Text,
        display_name: Some("Bea".to_owned()),
        sent_at,
        body: b"hello".to_vec(),
    };
    seal(channel, seed, |ctx, sender, nonce| {
        envelope::seal(ctx, sender, counter, nonce, &payload)
    })
}

/// A blob of `seed` for `channel`, built by `build`.
fn seal(
    channel: &Channel,
    seed: [u8; 32],
    build: impl Fn(&ChannelCtx, &SenderKey, &Nonce) -> Result<envelope::Sealed, Error>,
) -> Vec<u8> {
    let ctx = ChannelCtx::from_config(channel.config()).unwrap();
    let sender = SenderKey::from_seed(&Secret::from_bytes(seed)).unwrap();
    build(&ctx, &sender, &Nonce([0x31; 24])).unwrap().blob
}

/// The `n`-th `server_id`.
fn sid(n: u8) -> [u8; 16] {
    [n; 16]
}

/// The largest body a log record holds (spec 020-store-files Limits).
const MAX_BODY: u64 = 64_511;

/// Commits records of `purge_at` until the log is exactly `target` bytes.
fn fill(channel: &mut Channel, purge_at: u64, target: u64) {
    let base = record(0, 0).entry_len();
    let mut remaining = target - channel.store.log_len();
    let mut records = Vec::new();
    while remaining > 0 {
        let mut len = remaining.min(base + MAX_BODY);
        if remaining > len && remaining - len < base {
            len -= base;
        }
        records.push(record(purge_at, usize::try_from(len - base).unwrap()));
        remaining -= len;
    }
    channel.commit(channel.next_state(), records).unwrap();
}

/// `pk_u` of `seed`.
fn pk_of(seed: [u8; 32]) -> [u8; 32] {
    SenderKey::from_seed(&Secret::from_bytes(seed))
        .unwrap()
        .public()
        .0
}

/// The seed of one's key before a regeneration, planted with the
/// retirement spec 025-identity-regen commits: the old key among one's old
/// keys, a new seed, the entries marked and a pending `key_retired`.
fn plant_retirement(channel: &mut Channel) -> [u8; 32] {
    let old_seed = *channel.state.identity_seed.expose();
    let mut next = channel.next_state();
    next.own_old_keys.push(OldKey {
        pk: PublicKey(pk_of(old_seed)),
        retired_at: NOW,
    });
    next.retiring_seed = Some(Secret::from_bytes(old_seed));
    next.identity_seed = Secret::from_bytes([0x99; 32]);
    for entry in &mut next.outbox {
        entry.under_retired_key = true;
    }
    next.outbox.push(OutboxEntry {
        client_ref: [0xee; 16],
        kind: OutboxKind::KeyRetired,
        sent_at: NOW,
        blob: vec![1; 10],
        signature: Signature([2; 64]),
        under_retired_key: true,
        counter: u64::MAX,
    });
    channel.commit(next, Vec::new()).unwrap();
    old_seed
}

/// A channel with entries 300 and 301 under the key being retired.
fn retiring() -> (Channel, MemoryStore, Faults, [u8; 32], Vec<ClientRef>) {
    let (mut channel, handle, faults) = receiver(3_600);
    let mut next = channel.next_state();
    next.send_counter = 300;
    channel.commit(next, Vec::new()).unwrap();
    let entries = (0..2)
        .map(|_| channel.encrypt("old", None, NOW).unwrap())
        .collect();
    let old_seed = plant_retirement(&mut channel);
    (channel, handle, faults, old_seed, entries)
}

/// The channel the store of `handle` holds now.
fn reopened(handle: &MemoryStore) -> Channel {
    Channel::open_stored(Box::new(handle.reopen())).unwrap()
}

/// Spec 021, R1: the expiry index gives the bytes expired and the oldest
/// expiry at any `now`, extended at each commit and built again at load;
/// the session values cross to a new instance through `carry_session`.
#[test]
fn s021_t01_r01_in_session_values() {
    let (mut channel, handle) = new_channel();
    assert_eq!(channel.expiry.oldest_expiry(), None);
    let before = handle.reopen().log_len();
    let records = vec![record(10, 100), record(5, 50), record(20, 0)];
    let lens: Vec<u64> = records.iter().map(|r| r.entry_len()).collect();
    channel.commit(channel.next_state(), records).unwrap();
    // The entry lengths are the bytes the store appended.
    assert_eq!(handle.reopen().log_len() - before, lens.iter().sum::<u64>());
    for index in [&channel.expiry, &reopened(&handle).expiry] {
        assert_eq!(index.oldest_expiry(), Some(5));
        assert_eq!(index.expired_bytes(5), 0);
        assert_eq!(index.expired_bytes(6), lens[1]);
        assert_eq!(index.expired_bytes(11), lens[0] + lens[1]);
        assert_eq!(index.expired_bytes(u64::MAX), lens.iter().sum::<u64>());
    }

    let gap = Gap {
        peer: [3; 32],
        missing: 4,
        anomalous: false,
        spans_truncation: true,
    };
    channel.carry.gaps.insert(gap.peer, gap);
    channel.carry.ignored_keys.insert([9; 32]);
    channel.carry.clock_off = ClockOff::Live;
    let carry = channel.session_carry();
    drop(channel);
    let mut next = reopened(&handle);
    assert_eq!(next.session_carry(), SessionCarry::default());
    next.carry_session(carry.clone());
    assert_eq!(next.session_carry(), carry);
}

/// Spec 021, R2: memory takes the batch only after `Ok`; after a failed
/// commit, memory and the reopened store both hold the state before.
#[test]
fn s021_t02_r02_install_after_ok() {
    let (store, handle) = new_store();
    let faults = Faults::new();
    let failing = Box::new(FailingStore::new(store, faults.clone()));
    let (mut channel, _) = Channel::create(&config_on(SERVER), failing).unwrap();

    let mut next = channel.next_state();
    next.send_counter = 1;
    channel.commit(next, vec![record(7, 10)]).unwrap();
    assert!(state_eq(&channel.state, &reopened(&handle).state));
    assert_eq!(channel.records.len(), 1);

    let before = channel.state.duplicate();
    faults.fail_commits(true);
    let mut next = channel.next_state();
    next.send_counter = 2;
    let result = channel.commit(next, vec![record(8, 10)]);
    assert_eq!(result, Err(Error::Store(StoreError::Io)));
    assert!(state_eq(&channel.state, &before));
    assert_eq!(channel.records.len(), 1);
    assert_eq!(channel.expiry.oldest_expiry(), Some(7));
    let stored = reopened(&handle);
    assert!(state_eq(&stored.state, &before));
    assert_eq!(stored.records.len(), 1);
}

/// Spec 021, R4: a new store gets one commit of a fresh identity; two new
/// channels draw different seeds.
#[test]
fn s021_t04_r04_create_draws_identity() {
    let (channel, handle) = new_channel();
    assert_eq!(handle.commits(), 1);
    let state = &reopened(&handle).state;
    assert_eq!(state.send_counter, 0);
    assert_eq!(state.identity_epoch, 0);
    assert_eq!(state.cursor, None);
    assert!(state.peers.is_empty() && state.outbox.is_empty());
    assert_eq!(*state.config, *config_on(SERVER).record(None).unwrap());
    let (other, _) = new_channel();
    assert_ne!(
        channel.state.identity_seed.expose(),
        other.state.identity_seed.expose()
    );
}

/// Spec 021, R5: the same config gives the stored channel back with no
/// commit; another server for the same `channel_id` is refused.
#[test]
fn s021_t05_r05_create_existing() {
    let (channel, handle) = new_channel();
    let seed = *channel.state.identity_seed.expose();
    drop(channel);
    let (again, created) = Channel::create(&config_on(SERVER), Box::new(handle.reopen())).unwrap();
    assert!(!created);
    assert_eq!(again.state.identity_seed.expose(), &seed);
    assert_eq!(handle.all_commits(), 1);
    drop(again);
    let other = config_on("wss://elsewhere.example");
    assert_eq!(other.channel_id(), config_on(SERVER).channel_id());
    let result = Channel::create(&other, Box::new(handle.reopen()));
    assert!(matches!(result, Err(Error::ConfigMismatch)));
    assert_eq!(handle.all_commits(), 1);
}

/// Spec 021, R6: a stored channel reopens with its config and its
/// directory; an empty store, a newer config and a malformed one are store
/// errors, with no commit.
#[test]
fn s021_t06_r06_open_stored() {
    let (channel, handle) = new_channel();
    drop(channel);
    let channel = reopened(&handle);
    assert_eq!(
        channel.config().channel_id(),
        config_on(SERVER).channel_id()
    );
    assert_eq!(channel.config().server_url(), SERVER);
    assert_eq!(channel.dir_name(), handle.name());
    drop(channel);

    let (empty, empty_handle) = new_store();
    let result = Channel::open_stored(empty);
    assert!(matches!(result, Err(Error::Store(StoreError::Corrupt))));
    assert_eq!(empty_handle.all_commits(), 0);

    // Key 0 of the record, `config_version`, is its sixth byte.
    let mut newer = config_on(SERVER).record(None).unwrap().to_vec();
    newer[5] = 2;
    let mut malformed = newer.clone();
    malformed[5] = 1;
    malformed.push(0);
    for (config, error) in [
        (newer, StoreError::UnsupportedVersion),
        (malformed, StoreError::Corrupt),
    ] {
        let (mut store, handle) = new_store();
        let mut state = state_for(config_on(SERVER).channel_id());
        *state.config = config;
        store.commit(&batch(state, Vec::new())).unwrap();
        let result = Channel::open_stored(store);
        assert!(matches!(result, Err(Error::Store(e)) if e == error));
        assert_eq!(handle.all_commits(), 1);
    }
}

/// Spec 021, R32: a `create` whose first commit fails leaves the store
/// empty.
#[test]
fn s021_t32_r32_failing_store_per_method() {
    let (store, handle) = new_store();
    let faults = Faults::new();
    faults.fail_commits(true);
    let result = Channel::create(
        &config_on(SERVER),
        Box::new(FailingStore::new(store, faults)),
    );
    assert!(matches!(result, Err(Error::Store(StoreError::Io))));
    assert!(handle.reopen().load().unwrap().is_none());
}
