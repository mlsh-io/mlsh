+++
title = "Cryptography"
description = "TLS 1.3, X25519Kyber768 hybrid post-quantum KEM, Ed25519 identities."
weight = 1
+++

## Transport

All MLSH traffic (both signal control and peer-to-peer data) rides on [QUIC (RFC 9000)](https://datatracker.ietf.org/doc/rfc9000/) with [TLS 1.3](https://datatracker.ietf.org/doc/rfc8446/) provided by [rustls](https://github.com/rustls/rustls) with the `aws-lc-rs` backend.

## Key exchange: X25519Kyber768

Every TLS handshake uses [X25519Kyber768](https://datatracker.ietf.org/doc/draft-tls-westerbaan-xyber768d00/), a hybrid KEM combining:

- **X25519**: classical elliptic-curve Diffie-Hellman ([RFC 7748](https://datatracker.ietf.org/doc/rfc7748/)).
- **ML-KEM 768**: post-quantum KEM ([NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final)).

Both must be broken for the session key to be compromised. This protects against an adversary who records traffic today and attempts decryption once a cryptographically relevant quantum computer exists.

## Identity

Each node generates an [Ed25519](https://datatracker.ietf.org/doc/rfc8032/) keypair on first run and wraps the public half in a self-signed X.509 certificate. The private key never leaves the machine. Trust is not rooted in a CA: peers verify each other's SHA-256 certificate fingerprint against the registry held by the signal server (conceptually like SSH's `known_hosts`, but centrally managed).

## Server fingerprint pinning

The signal server's TLS certificate is verified by fingerprint. During setup or adoption, the client learns the server's SHA-256 fingerprint (either from the setup token or from the signed invite) and stores it in the cluster file. On every subsequent connection, the client rejects the server if the presented certificate's fingerprint does not match. No CA is required.

## Invite signatures

Invites are signed by the sponsor's Ed25519 private key. The signal server verifies the signature against the sponsor's public key in its registry before admitting the new node. See [trust model](@/security/trust-model.md).

## Node tokens

After adoption, the signal server issues a **node token**: an HMAC-SHA256 value derived from a server-held signing key, bound to the cluster ID and node ID. Tokens do not expire, so a node can reconnect across reboots without re-adopting. Revoking a node server-side invalidates its token even if the bytes still live on disk.
