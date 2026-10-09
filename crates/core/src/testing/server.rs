//! An exchange server in memory, over the frames of spec 028-session-sans-io,
//! for the tests of the session and of the `Device`: it keeps the server
//! contract of R4 (the backlog in order, then the live pushes held behind
//! it, then `ok`; publishes stored and acknowledged in the order received)
//! and checks every subscription signature as spec 031 does. It holds no
//! quota and no rate limit; time is a parameter, as everywhere in `core`.

use std::collections::{BTreeMap, VecDeque};

use crate::crypto::{self, PublicKey, Signature};
use crate::proto::auth::auth_message;
use crate::proto::config::{self, ChannelId};
use crate::proto::envelope::ttl_ms;
use crate::session::frames::{CODE_BAD_AUTH, CODE_NONCE_EXPIRED, CODE_NOT_SUBSCRIBED, Frame};

/// How long a `hello`'s nonce is valid (`docs/spec.md` §6).
const NONCE_VALIDITY_MS: u64 = 60_000;

/// One stored blob.
#[derive(Clone)]
struct Stored {
    server_id: [u8; 16],
    received_at: u64,
    blob: Vec<u8>,
}

/// A subscription that has not yet sent its `ok`, or one that has.
enum Subscription {
    CatchingUp {
        backlog: VecDeque<Stored>,
        held: Vec<Stored>,
    },
    Live,
}

/// One socket.
struct Connection {
    server_nonce: [u8; 32],
    hello_at: u64,
    subscriptions: BTreeMap<[u8; 16], Subscription>,
    /// Frames ready to be written, ahead of any backlog.
    ready: VecDeque<Vec<u8>>,
}

/// The server: blobs per channel, connections by number.
pub struct MemoryServer {
    hosts: Vec<String>,
    channels: BTreeMap<[u8; 16], Vec<Stored>>,
    connections: BTreeMap<u64, Connection>,
    last_received_at: u64,
    /// Numbers the `server_id`s and the nonces, so that runs repeat.
    drawn: u64,
}

impl MemoryServer {
    /// A server whose configured URLs have these hosts (spec 031 R8).
    pub fn new(hosts: &[&str]) -> MemoryServer {
        MemoryServer {
            hosts: hosts.iter().map(|host| (*host).to_owned()).collect(),
            channels: BTreeMap::new(),
            connections: BTreeMap::new(),
            last_received_at: 0,
            drawn: 0,
        }
    }

    /// A new socket, numbered `connection`, which gets its `hello`.
    pub fn connect(&mut self, connection: u64, now: u64) {
        let server_nonce = self.draw();
        let mut socket = Connection {
            server_nonce,
            hello_at: now,
            subscriptions: BTreeMap::new(),
            ready: VecDeque::new(),
        };
        socket.ready.push_back(hello(server_nonce));
        self.connections.insert(connection, socket);
    }

    /// The socket closed.
    pub fn disconnect(&mut self, connection: u64) {
        self.connections.remove(&connection);
    }

    /// The blobs stored for `channel_id`, as `(server_id, received_at)`, in
    /// order.
    pub fn stored(&self, channel_id: &[u8; 16]) -> Vec<([u8; 16], u64)> {
        self.channels
            .get(channel_id)
            .map(|blobs| {
                blobs
                    .iter()
                    .map(|stored| (stored.server_id, stored.received_at))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// One frame the client wrote on `connection`; a frame that does not
    /// decode, or of a type a client does not send, is dropped.
    pub fn receive(&mut self, connection: u64, frame: &[u8], now: u64) {
        match Frame::decode(frame) {
            Ok(Frame::Subscribe {
                pk_ch,
                ttl_seconds,
                sig,
                since,
            }) => self.subscribe(connection, &pk_ch, ttl_seconds, &sig, since, now),
            Ok(Frame::Publish {
                channel_id,
                client_ref,
                blob,
            }) => self.publish(connection, channel_id, client_ref, blob, now),
            _ => {}
        }
    }

    /// Up to `max` frames the socket of `connection` takes, in the order of
    /// R4: what is ready first, then each subscription's backlog, then the
    /// pushes held behind it, then its `ok`.
    pub fn read(&mut self, connection: u64, max: usize) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let Some(socket) = self.connections.get_mut(&connection) else {
            return out;
        };
        while out.len() < max {
            if let Some(frame) = socket.ready.pop_front() {
                out.push(frame);
            } else if !socket.stream_next() {
                break;
            }
        }
        out
    }

    /// Checks a `subscribe` as spec 031 R5 does: the nonce's age, then the
    /// signature over each configured host.
    fn subscribe(
        &mut self,
        connection: u64,
        pk_ch: &[u8; 32],
        ttl_seconds: u32,
        sig: &[u8; 64],
        since: Option<u64>,
        now: u64,
    ) {
        let Ok(ChannelId(channel_id)) = config::channel_id_of(&PublicKey(*pk_ch), ttl_seconds)
        else {
            return;
        };
        let fresh_nonce = self.draw();
        let channels = &mut self.channels;
        let hosts = &self.hosts;
        let Some(socket) = self.connections.get_mut(&connection) else {
            return;
        };
        if now > socket.hello_at.saturating_add(NONCE_VALIDITY_MS) {
            socket
                .ready
                .push_back(error(CODE_NONCE_EXPIRED, channel_id, None));
            socket.server_nonce = fresh_nonce;
            socket.hello_at = now;
            socket.ready.push_back(hello(fresh_nonce));
            return;
        }
        let signed = hosts.iter().any(|host| {
            let message = auth_message(
                &socket.server_nonce,
                &ChannelId(channel_id),
                ttl_seconds,
                host,
            );
            crypto::verify_detached(&PublicKey(*pk_ch), &message, &Signature(*sig)).is_ok()
        });
        if !signed {
            socket
                .ready
                .push_back(error(CODE_BAD_AUTH, channel_id, None));
            return;
        }
        let ttl = ttl_ms(ttl_seconds);
        let blobs = channels.entry(channel_id).or_default();
        let from = since.unwrap_or(0).min(now);
        let backlog = blobs
            .iter()
            .filter(|stored| stored.received_at >= from)
            .filter(|stored| stored.received_at.saturating_add(ttl) > now)
            .cloned()
            .collect();
        socket.subscriptions.insert(
            channel_id,
            Subscription::CatchingUp {
                backlog,
                held: Vec::new(),
            },
        );
    }

    /// Stores a blob, acknowledges it to its publisher, then pushes it to
    /// every subscription of its channel, held while one catches up (R4).
    fn publish(
        &mut self,
        connection: u64,
        channel_id: [u8; 16],
        client_ref: [u8; 16],
        blob: Vec<u8>,
        now: u64,
    ) {
        let subscribed = self
            .connections
            .get(&connection)
            .is_some_and(|socket| socket.subscriptions.contains_key(&channel_id));
        if !subscribed {
            if let Some(socket) = self.connections.get_mut(&connection) {
                let refusal = error(CODE_NOT_SUBSCRIBED, channel_id, Some(client_ref));
                socket.ready.push_back(refusal);
            }
            return;
        }
        let received_at = now.max(self.last_received_at.saturating_add(1));
        self.last_received_at = received_at;
        let stored = Stored {
            server_id: self.draw_id(),
            received_at,
            blob,
        };
        if let Some(blobs) = self.channels.get_mut(&channel_id) {
            blobs.push(stored.clone());
        }
        if let Some(socket) = self.connections.get_mut(&connection) {
            socket.ready.push_back(encoded(&Frame::Ack {
                client_ref,
                server_id: stored.server_id,
                received_at,
            }));
        }
        for socket in self.connections.values_mut() {
            match socket.subscriptions.get_mut(&channel_id) {
                Some(Subscription::Live) => socket.ready.push_back(push(channel_id, &stored)),
                Some(Subscription::CatchingUp { held, .. }) => held.push(stored.clone()),
                None => {}
            }
        }
    }

    /// 32 bytes no other call of this server draws.
    fn draw(&mut self) -> [u8; 32] {
        self.drawn = self.drawn.saturating_add(1);
        let mut bytes = [0; 32];
        if let Some(head) = bytes.first_chunk_mut::<8>() {
            *head = self.drawn.to_be_bytes();
        }
        bytes
    }

    /// A `server_id` no other blob has.
    fn draw_id(&mut self) -> [u8; 16] {
        let drawn = self.draw();
        drawn.first_chunk::<16>().copied().unwrap_or_default()
    }
}

impl Connection {
    /// Moves the next frame of the first subscription still catching up to
    /// `ready`: a backlog push, or, once the backlog is out, the held
    /// pushes and the `ok`. `false` when none is catching up.
    fn stream_next(&mut self) -> bool {
        let Some((channel_id, subscription)) = self
            .subscriptions
            .iter_mut()
            .find(|(_, subscription)| matches!(subscription, Subscription::CatchingUp { .. }))
        else {
            return false;
        };
        let Subscription::CatchingUp { backlog, held } = subscription else {
            return false;
        };
        if let Some(stored) = backlog.pop_front() {
            self.ready.push_back(push(*channel_id, &stored));
            return true;
        }
        for stored in held.iter() {
            self.ready.push_back(push(*channel_id, stored));
        }
        self.ready.push_back(encoded(&Frame::Ok {
            channel_id: *channel_id,
        }));
        *subscription = Subscription::Live;
        true
    }
}

fn hello(server_nonce: [u8; 32]) -> Vec<u8> {
    encoded(&Frame::Hello {
        server_nonce,
        proto_versions: vec![config::VERSION],
    })
}

fn push(channel_id: [u8; 16], stored: &Stored) -> Vec<u8> {
    encoded(&Frame::Push {
        channel_id,
        server_id: stored.server_id,
        received_at: stored.received_at,
        blob: stored.blob.clone(),
    })
}

fn error(code: &str, channel_id: [u8; 16], client_ref: Option<[u8; 16]>) -> Vec<u8> {
    encoded(&Frame::Error {
        code: code.to_owned(),
        message: String::new(),
        channel_id: Some(channel_id),
        client_ref,
    })
}

/// A frame this server builds, which always encodes: its fields are bounded.
fn encoded(frame: &Frame) -> Vec<u8> {
    frame.encode().unwrap_or_default()
}
