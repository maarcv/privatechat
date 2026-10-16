//! The frames the server writes (spec 030-ws-protocol R13): the error codes
//! of `docs/spec.md` §6 with their fixed texts, and nothing that came from a
//! client but the `channel_id` and `client_ref` an error names.

use privatechat_core::Frame;

use crate::store::writer::{Refusal, Row};

/// The error codes the server sends; `unsupported_version` is reserved for a
/// later `proto_version` and is not one of them (R13).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ErrorCode {
    BadAuth,
    NonceExpired,
    BadTtl,
    NotSubscribed,
    BadBlob,
    RateLimited,
    ChannelQuota,
    ServerFull,
}

impl ErrorCode {
    /// The code as the frame carries it.
    pub(crate) fn code(self) -> &'static str {
        match self {
            ErrorCode::BadAuth => "bad_auth",
            ErrorCode::NonceExpired => "nonce_expired",
            ErrorCode::BadTtl => "bad_ttl",
            ErrorCode::NotSubscribed => "not_subscribed",
            ErrorCode::BadBlob => "bad_blob",
            ErrorCode::RateLimited => "rate_limited",
            ErrorCode::ChannelQuota => "channel_quota",
            ErrorCode::ServerFull => "server_full",
        }
    }

    /// The fixed text of the code (R13, the Interface of spec 030).
    pub(crate) fn message(self) -> &'static str {
        match self {
            ErrorCode::BadAuth => "subscription signature rejected",
            ErrorCode::NonceExpired => "server nonce expired",
            ErrorCode::BadTtl => "ttl out of range",
            ErrorCode::NotSubscribed => "channel not subscribed on this connection",
            ErrorCode::BadBlob => "blob rejected",
            ErrorCode::RateLimited => "rate limited",
            ErrorCode::ChannelQuota => "channel full",
            ErrorCode::ServerFull => "server full",
        }
    }
}

impl From<Refusal> for ErrorCode {
    /// The code of a refusal of the writer (spec 032-storage-ttl).
    fn from(refusal: Refusal) -> ErrorCode {
        match refusal {
            Refusal::RateLimited => ErrorCode::RateLimited,
            Refusal::ChannelQuota => ErrorCode::ChannelQuota,
            Refusal::ServerFull => ErrorCode::ServerFull,
        }
    }
}

/// The `ok` of a subscription (R7).
pub(crate) fn ok(channel_id: [u8; 16]) -> Frame {
    Frame::Ok { channel_id }
}

/// The `ack` of a stored `publish` (R12).
pub(crate) fn ack(client_ref: [u8; 16], row: &Row) -> Frame {
    Frame::Ack {
        client_ref,
        server_id: row.server_id,
        received_at: row.received_at,
    }
}

/// The `push` of a stored blob (R7, R12).
pub(crate) fn push(channel_id: [u8; 16], row: Row) -> Frame {
    Frame::Push {
        channel_id,
        server_id: row.server_id,
        received_at: row.received_at,
        blob: row.blob,
    }
}

/// An `error` frame of `code`, naming the channel and the `publish` it
/// answers when there is one.
pub(crate) fn error(
    code: ErrorCode,
    channel_id: Option<[u8; 16]>,
    client_ref: Option<[u8; 16]>,
) -> Frame {
    Frame::Error {
        code: code.code().to_owned(),
        message: code.message().to_owned(),
        channel_id,
        client_ref,
    }
}
