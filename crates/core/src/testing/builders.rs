//! Builders of chosen content, with which the tests of `store` commit
//! states and records without knowing what their fields mean.

use zeroize::Zeroizing;

use crate::crypto::{PublicKey, Secret};
use crate::storage::{ChannelState, Content, LogEntry, LogRecord, Message, Settings, WriteBatch};

/// A fresh state of `channel_id`: no peer, nothing waiting, no optional
/// field, a fixed seed and a stand-in config.
pub fn state_for(channel_id: [u8; 16]) -> ChannelState {
    ChannelState {
        channel_id,
        config: Zeroizing::new(b"config of the store tests".to_vec()),
        identity_seed: Secret::from_bytes([0x11; 32]),
        identity_epoch: 0,
        send_counter: 0,
        cursor: None,
        own_display_name: None,
        local_name: None,
        peers: Vec::new(),
        outbox: Vec::new(),
        retiring_seed: None,
        own_old_keys: Vec::new(),
        own_key_used_elsewhere: false,
        read_only: false,
        log_committed_len: 0,
        log_generation: 0,
        synced_at: None,
        truncated_at: None,
    }
}

/// A received text message of `body_len` bytes that may be dropped from
/// `purge_at` on.
pub fn record(purge_at: u64, body_len: usize) -> LogRecord {
    LogRecord {
        purge_at,
        entry: LogEntry::Message(Message {
            server_id: Some([0x22; 16]),
            received_at: purge_at,
            sender_pk: PublicKey([0x33; 32]),
            counter: purge_at,
            content: Content::Text(Zeroizing::new(vec![b'm'; body_len])),
            display_name: None,
            sent_at: None,
            own_client_ref: None,
        }),
    }
}

/// A batch of `state` and `records`.
pub fn batch(state: ChannelState, records: Vec<LogRecord>) -> WriteBatch {
    WriteBatch::new(state, records)
}

/// Settings of these values, which spec 027-core-api will let the app set;
/// `seal` refuses them if they break the grammars of spec 020 R8.
pub fn settings(
    default_server_url: &str,
    lock_timeout_seconds: u32,
    socks5_proxy: Option<&str>,
) -> Settings {
    Settings {
        default_server_url: default_server_url.to_owned(),
        lock_timeout_seconds,
        socks5_proxy: socks5_proxy.map(str::to_owned),
    }
}
