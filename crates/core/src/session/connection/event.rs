//! What the session tells the client (spec 028-session-sans-io, Interface).

use core::fmt;

use crate::session::channel::{ClientRef, Received, key_prefix};

/// What the session tells the client, by channel or by connection. Its
/// `Debug` shows a channel by the 4-byte prefix of its id (AGENTS 19).
#[derive(PartialEq, Eq)]
pub enum Event {
    /// The channel's backlog arrived and live messages follow (R9).
    Subscribed {
        /// The channel.
        channel: [u8; 16],
    },
    /// A message `decrypt` consumed (R10).
    Message {
        /// The channel.
        channel: [u8; 16],
        /// What it holds.
        received: Received,
    },
    /// A push met a full log: the channel takes no more on this
    /// connection, and asks for one once there is room (R10).
    StorageFailed {
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
    /// The server stored an entry in time (R12).
    Delivered {
        /// The channel.
        channel: [u8; 16],
        /// The entry.
        client_ref: ClientRef,
        /// The server's identifier of the message.
        server_id: [u8; 16],
        /// When it is listed, clamped (spec 021-channel-session R17).
        received_at: u64,
        /// When its row leaves the screen: `sent_at + ttl_ms`, as the
        /// `Message` of spec 023-ttl-purge R1 (ADR 0044).
        expires_at: u64,
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
    /// The client should re-read the channel's status and peers (R13).
    StatusChanged {
        /// The channel.
        channel: [u8; 16],
    },
    /// The server refused the channel's `subscribe`: it is not subscribed
    /// again on this connection (R16).
    SubscribeRefused {
        /// The channel.
        channel: [u8; 16],
    },
    /// The channel is over its quota on the server: it publishes nothing
    /// for a minute (R16).
    ChannelFull {
        /// The channel.
        channel: [u8; 16],
    },
    /// The server is full: nothing is published for a minute (R16).
    ServerFull {
        /// The connection.
        connection: u64,
    },
    /// The server speaks no version of this app (R2, R16).
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
            Event::Message { channel, .. } => write!(f, "Message({})", key_prefix(channel)),
            Event::StorageFailed { channel } => {
                write!(f, "StorageFailed({})", key_prefix(channel))
            }
            Event::HistoryTruncated { channel, before } => {
                write!(f, "HistoryTruncated({}, {before})", key_prefix(channel))
            }
            Event::Delivered {
                channel,
                received_at,
                ..
            } => write!(f, "Delivered({}, {received_at})", key_prefix(channel)),
            Event::NotDelivered {
                channel, sent_at, ..
            } => write!(f, "NotDelivered({}, {sent_at})", key_prefix(channel)),
            Event::StatusChanged { channel } => {
                write!(f, "StatusChanged({})", key_prefix(channel))
            }
            Event::SubscribeRefused { channel } => {
                write!(f, "SubscribeRefused({})", key_prefix(channel))
            }
            Event::ChannelFull { channel } => write!(f, "ChannelFull({})", key_prefix(channel)),
            Event::ServerFull { connection } => write!(f, "ServerFull({connection})"),
            Event::UnsupportedServer { connection } => {
                write!(f, "UnsupportedServer({connection})")
            }
            Event::Reconnect { connection } => write!(f, "Reconnect({connection})"),
        }
    }
}
