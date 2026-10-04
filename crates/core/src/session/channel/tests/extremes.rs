//! Times at both ends of `u64` through every method (R21).

use super::{receiver, sid, text_from};
use crate::session::channel::ClientRef;

const PEER: [u8; 32] = [0x77; 32];
/// The last whole minute.
const LAST_MINUTE: u64 = u64::MAX - u64::MAX % 60_000;

/// Spec 021, R21: `now`, `received_at` and `sent_at` of 0 and `2^64 − 1`
/// in every method give a verdict, never a panic.
#[test]
fn s021_t21_r21_time_saturates() {
    let times = [0, u64::MAX];
    for received_at in times {
        for now in times {
            for sent_at in [0, LAST_MINUTE] {
                let (mut channel, _, _) = receiver(3_600);
                let sent = channel.encrypt("edge", Some("Ann"), now);
                let client_ref = sent.unwrap_or(ClientRef { bytes: [3; 16] });
                let peer = text_from(&channel, PEER, 1, sent_at);
                let own = text_from(&channel, *channel.state.identity_seed.expose(), 9, sent_at);
                let _ = channel.decrypt(&peer, sid(1), received_at, now);
                let _ = channel.decrypt(&own, sid(2), received_at, now);
                let _ = channel.check_own_key(&own, received_at, now);
                let _ = channel.acked(client_ref, sid(3), received_at, now);
                let _ = channel.outbox(now, &[client_ref], false);
                let _ = channel.expire_outbox(now, &[]);
                let _ = channel.abandon(client_ref);
                channel.clock_sample(received_at, now, true);
                channel.clock_sample(received_at, now, false);
                channel.history_truncated(now);
                let _ = channel.synced(now);
                let _ = channel.relieve_headroom(now);
                let _ = (channel.status(), channel.gaps(), channel.take_outcomes());
                let _ = channel.flush(now);
                let _ = channel.probe(now);
            }
        }
    }
}
