//! What the session tells the client (spec 028-session-sans-io, Interface).

use core::fmt;

use crate::session::channel::{ClientRef, key_prefix};

/// What the session tells the client, by channel or by connection. Its
/// `Debug` shows a channel by the 4-byte prefix of its id (AGENTS 19).
#[derive(PartialEq, Eq)]
pub enum Event {
    /// The channel's backlog arrived and live messages follow (R9).
    Subscribed {
        /// The channel.
        channel: [u8; 16],
    },
    /// The channel's history before `before` may be missing: the device
    /// was away longer than a TTL (R8, R9).
    HistoryTruncated {
        /// The channel.
        channel: [u8; 16],
        /// `now − ttl_ms` when the session found it.
        before: u64,
    },
    /// An entry left the `outbox` unsent: stale, overtaken or refused
    /// (R9, R14).
    NotDelivered {
        /// The channel.
        channel: [u8; 16],
        /// The entry.
        client_ref: ClientRef,
        /// When it was sealed, so that the client can report a row it no
        /// longer lists.
        sent_at: u64,
    },
    /// The server speaks no version of this app (R2).
    UnsupportedServer {
        /// The connection.
        connection: u64,
    },
    /// The client should close the socket and connect again.
    Reconnect {
        /// The connection.
        connection: u64,
    },
}

impl fmt::Debug for Event {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Event::Subscribed { channel } => write!(f, "Subscribed({})", key_prefix(channel)),
            Event::HistoryTruncated { channel, before } => {
                write!(f, "HistoryTruncated({}, {before})", key_prefix(channel))
            }
            Event::NotDelivered {
                channel, sent_at, ..
            } => write!(f, "NotDelivered({}, {sent_at})", key_prefix(channel)),
            Event::UnsupportedServer { connection } => {
                write!(f, "UnsupportedServer({connection})")
            }
            Event::Reconnect { connection } => write!(f, "Reconnect({connection})"),
        }
    }
}
