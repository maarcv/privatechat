# ADR 0001 — Pre-shared channel key exchanged out of band

Date: 2026-09-19 · Status: accepted

## Context
A group of people needs to share an encrypted channel without the server knowing anything about the members.

## Decision
Access to a channel is granted with a root key `K_ch` (32 random bytes) that travels inside a config shared out of band: QR in person, password-encrypted file or link with a fragment.

## Alternatives considered
- X3DH with prekeys on the server (Signal): requires the server to store public keys per user and to know the group topology.
- MLS (RFC 9420): solves online key agreement and member management, which this model does not need.

## Consequences
- The server cannot know who is a member of what.
- The config is the only secret: if it leaks, the whole channel is readable until a new one is created (see ADR 0004 and 0008).
- The UX of sharing the config is critical for security.
