//! The server half of the subscription signature (spec
//! 031-auth-channel-signature R1, R5–R7, R9): one `AuthState` per
//! connection, holding its nonces, its failed attempts and its first-subscribe
//! deadline, with no socket. The signature itself is checked by
//! `relay::verify_subscribe` of `core`; nothing of the credential is kept.

use std::fmt;

use privatechat_core::{Error, Frame, relay};

/// How long a nonce is valid from its `hello`, on the monotonic clock (R1).
pub(crate) const NONCE_LIFETIME_MS: u64 = 60_000;

/// How long after the first `hello` of the latest nonce a `subscribe` signed
/// under the one before it is a late one, not a forgery (R5).
pub(crate) const PREVIOUS_NONCE_MS: u64 = 10_000;

/// A connection with no accepted `subscribe` this long after its first
/// `hello` is closed (R7).
pub(crate) const FIRST_SUBSCRIBE_MS: u64 = 60_000;

/// The failed attempt that closes the connection (R6).
pub(crate) const MAX_FAILED: u8 = 3;

/// The only protocol version of v1 (`docs/spec.md` §6 "Version").
const PROTO_VERSION: u8 = 1;

/// What the connection answers a `subscribe` with, in order (R5, R6). It
/// derives no `Debug`: a full `channel_id` must not reach a log (AGENTS 19).
pub(crate) enum Verdict {
    /// Accepted: spec 030-ws-protocol R7 takes the channel.
    Accept { channel_id: [u8; 16] },
    /// `error{nonce_expired, channel_id}`, then this `hello`.
    NonceExpired { channel_id: [u8; 16], hello: Frame },
    /// `error{bad_ttl, channel_id}`, a failed attempt.
    BadTtl { channel_id: [u8; 16] },
    /// `error{bad_auth, channel_id}`, a failed attempt.
    BadAuth { channel_id: [u8; 16] },
    /// Close with status 1008, after the error of the third failed attempt,
    /// or with no frame when the first-subscribe deadline has passed (R7).
    Close,
}

/// The authentication of one connection (R1, R5–R7, R9). It keeps the
/// latest nonce and the one before it, and never `pk_ch` or `sig`.
pub(crate) struct AuthState {
    nonce: [u8; 32],
    previous: Option<[u8; 32]>,
    /// When the first `hello` of the latest nonce was queued.
    hello_at: u64,
    /// When the connection's first `hello` was queued (R7). It equals
    /// `hello_at` until an accept, since both windows are 60 000 ms; kept
    /// apart so that R1 and R7 stay independent if one of them changes.
    first_hello_at: u64,
    failed: u8,
    accepted_any: bool,
}

/// No nonce in the output: a `Debug` reaches no log, but a nonce never
/// should (spec 035-server-ops R4).
impl fmt::Debug for AuthState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthState")
            .field("hello_at", &self.hello_at)
            .field("first_hello_at", &self.first_hello_at)
            .field("failed", &self.failed)
            .field("accepted_any", &self.accepted_any)
            .finish_non_exhaustive()
    }
}

impl AuthState {
    /// The state of a new connection at `now` and its first `hello` (R1).
    ///
    /// # Errors
    ///
    /// `Error::Internal` when libsodium fails, which closes the connection
    /// (spec 030-ws-protocol R16).
    pub(crate) fn new(now: u64) -> Result<(AuthState, Frame), Error> {
        let nonce = relay::new_nonce()?;
        let state = AuthState {
            nonce,
            previous: None,
            hello_at: now,
            first_hello_at: now,
            failed: 0,
            accepted_any: false,
        };
        Ok((state, hello(nonce)))
    }

    /// Checks a `subscribe` at `now` against `hosts` (R5, R6).
    ///
    /// # Errors
    ///
    /// `Error::Internal` when a `relay` call fails, which closes the
    /// connection (spec 030-ws-protocol R16).
    pub(crate) fn on_subscribe(
        &mut self,
        pk_ch: &[u8; 32],
        ttl_seconds: u32,
        sig: &[u8; 64],
        hosts: &[String],
        now: u64,
    ) -> Result<Vec<Verdict>, Error> {
        // Checked here as well as by the deadline task, so that no subscribe
        // is answered past the deadline, whatever the task's period (R7).
        if self.deadline_passed(now) {
            return Ok(vec![Verdict::Close]);
        }
        let channel_id = relay::channel_id(pk_ch, ttl_seconds)?;
        if now.saturating_sub(self.hello_at) > NONCE_LIFETIME_MS {
            self.previous = Some(self.nonce);
            self.nonce = relay::new_nonce()?;
            self.hello_at = now;
            return Ok(vec![Verdict::NonceExpired {
                channel_id,
                hello: hello(self.nonce),
            }]);
        }
        let verdict = match relay::verify_subscribe(pk_ch, ttl_seconds, sig, &self.nonce, hosts) {
            Ok(channel_id) => {
                self.accepted_any = true;
                return Ok(vec![Verdict::Accept { channel_id }]);
            }
            Err(Error::BadConfig) => Verdict::BadTtl { channel_id },
            Err(Error::BadSignature) if self.is_late(pk_ch, ttl_seconds, sig, hosts, now)? => {
                // A repeat of the latest nonce, whose validity it does not extend.
                return Ok(vec![Verdict::NonceExpired {
                    channel_id,
                    hello: hello(self.nonce),
                }]);
            }
            Err(Error::BadSignature) => Verdict::BadAuth { channel_id },
            Err(error) => return Err(error),
        };
        self.failed = self.failed.saturating_add(1);
        let mut verdicts = vec![verdict];
        if self.failed >= MAX_FAILED {
            verdicts.push(Verdict::Close);
        }
        Ok(verdicts)
    }

    /// Whether a `subscribe` that failed under the latest nonce was signed
    /// under the one before it, within `PREVIOUS_NONCE_MS` of the latest
    /// nonce's first `hello`: the client released it before it read that
    /// `hello` (R5).
    fn is_late(
        &self,
        pk_ch: &[u8; 32],
        ttl_seconds: u32,
        sig: &[u8; 64],
        hosts: &[String],
        now: u64,
    ) -> Result<bool, Error> {
        let Some(previous) = self.previous else {
            return Ok(false);
        };
        if now.saturating_sub(self.hello_at) > PREVIOUS_NONCE_MS {
            return Ok(false);
        }
        match relay::verify_subscribe(pk_ch, ttl_seconds, sig, &previous, hosts) {
            Ok(_) => Ok(true),
            Err(Error::BadSignature) => Ok(false),
            Err(error) => Err(error),
        }
    }

    /// Whether the connection has gone `FIRST_SUBSCRIBE_MS` since its first
    /// `hello` with no accepted `subscribe` (R7).
    pub(crate) fn deadline_passed(&self, now: u64) -> bool {
        !self.accepted_any && now.saturating_sub(self.first_hello_at) > FIRST_SUBSCRIBE_MS
    }
}

/// The `hello` that carries `nonce` (R1).
fn hello(nonce: [u8; 32]) -> Frame {
    Frame::Hello {
        server_nonce: nonce,
        proto_versions: vec![PROTO_VERSION],
    }
}
