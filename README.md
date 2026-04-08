# mlsh

mlsh is a mesh networking tool that creates encrypted overlay networks between machines. You run a lightweight signaling server, register your nodes, and mlsh establishes direct peer-to-peer QUIC tunnels between them with post-quantum key exchange. Each node gets a stable overlay IP and a DNS name, so you can `ssh nas.homelab` from anywhere without exposing ports or configuring VPN gateways.

## Why mlsh

I wanted something dead simple to connect machines in my homelab. I tried OpenVPN, gave up on the PKI ceremony. I tried WireGuard, got it working but managing keys and endpoints across machines behind NAT was tedious. The most reliable and painless solution I found was Tailscale — it just works. Headscale gave me the self-hosted version and it ran great.

But I wanted to experiment with [QUIC](https://datatracker.ietf.org/doc/rfc9000/) as a tunnel transport. QUIC runs over UDP, handles multiplexing and congestion control natively, and the connection setup is fast. On top of that, the TLS 1.3 layer in QUIC gave me a natural place to plug in [X25519Kyber768](https://datatracker.ietf.org/doc/draft-tls-westerbaan-xyber768d00/) — a hybrid post-quantum key exchange that protects against harvest-now-decrypt-later attacks without sacrificing performance today. Quantum computers capable of breaking classical key exchange may be years away, but encrypted traffic recorded now could be decrypted later. For a tool designed to carry SSH sessions and private traffic between personal machines, that felt worth addressing from day one.

So mlsh is the result: a lightweight mesh VPN built on QUIC with post-quantum encryption, designed to be as easy to set up as Tailscale but fully self-hosted, with a single static binary for the client and a single container for the signal server.

The core design decisions:

- **Direct peer-to-peer tunnels.** No central gateway routing all traffic. The signal server handles registration and peer discovery, then gets out of the way. It only relays packets as a last resort when direct connectivity fails.
- **Zero key distribution.** Each node generates its own Ed25519 identity. Trust is established through a sponsorship model — existing members vouch for new ones by signing invites. No shared secrets, no certificate authorities to manage.
- **Post-quantum by default.** Every tunnel uses X25519Kyber768, a hybrid scheme combining classical elliptic curve Diffie-Hellman with ML-KEM 768. Both must be broken for the session key to be compromised.
- **Minimal configuration.** One command to bootstrap, one command to invite, one command to join. Cluster configs are plain TOML files in `~/.config/mlsh/`.

## Project structure

```
mlsh-cli/        Rust — CLI client + tunnel daemon (mlsh / mlshtund)
mlsh-signal/     Rust — signaling server (Linux container)
mlsh-crypto/     Rust — shared cryptographic primitives
mlsh-protocol/   Rust — shared wire format
mlsh-menubar/    Swift — macOS menu bar app (SwiftUI)
```

`mlsh` and `mlshtund` are the same binary — the name at invocation selects CLI mode or daemon mode (argv[0] dispatch, like busybox).

## Building

You need Rust 1.88+ and (for macOS) Swift 5.9+. A Makefile at the root provides all build targets:

```
make help
```

| Target | Description |
|--------|-------------|
| `make app` | Build `MLSH.app` for current arch (Rust CLI + Swift menu bar) |
| `make app-universal` | Build `MLSH.app` as universal binary (x86_64 + arm64) |
| `make cli` | Build `mlsh` + `mlshtund` for current arch |
| `make cli-universal` | Build `mlsh` + `mlshtund` universal (x86_64 + arm64) |
| `make windows` | Cross-compile `mlsh.exe` + `mlshtund.exe` for Windows (via cargo-xwin) |
| `make signal` | Build `mlsh-signal` for current arch |
| `make signal-image` | Build `mlsh-signal` Docker image (linux/amd64 + arm64) |
| `make menubar` | Build Swift menu bar app only (current arch) |
| `make menubar-universal` | Build Swift menu bar app only (x86_64 + arm64) |
| `make clean` | Remove all build artifacts |

The macOS `.app` bundle contains the Swift menu bar GUI, the Rust CLI binary, and a `mlshtund` symlink:

```
MLSH.app/Contents/MacOS/
  MLSHMenuBar    Swift GUI
  mlsh           Rust CLI + daemon
  mlshtund       symlink → mlsh
```

To build just the signal server container image:

```
podman build -t mlsh-signal -f mlsh-signal/Containerfile .
```

The Containerfile uses a multi-stage Alpine build with musl for a static binary, producing a scratch-based image with nothing but the binary inside. Docker works too — the commands are interchangeable.

## Deploying mlsh-signal

The signal server needs a single UDP port and a directory for its SQLite database. It is configured through environment variables or a TOML config file at `/etc/mlsh-signal/config.toml`.

```
podman run -d \
  -p 4433:4433/udp \
  -v mlsh-signal-data:/var/lib/mlsh-signal \
  ghcr.io/<owner>/mlsh-signal
```

On first startup, the server generates a cluster secret and a signing key, stores them in the database, and prints a setup token to stdout in the format `XXXX-XXXX-XXXX@<fingerprint>`. The first part is the cluster secret, the second is the SHA-256 fingerprint of the server's TLS certificate. You will need this token to bootstrap your first node.

The main environment variables are:

| Variable | Default | Description |
|----------|---------|-------------|
| `MLSH_SIGNAL_DB` | `/var/lib/mlsh-signal/signal.db` | SQLite database path |
| `MLSH_CLUSTER_SECRET` | auto-generated | Cluster secret for initial setup |
| `MLSH_OVERLAY_SUBNET` | `100.64.0.0/10` | Overlay IP range (CIDR) |
| `RUST_LOG` | `mlsh_signal=info` | Log level filter |

If you provide your own TLS certificates, set `quic.cert_path` and `quic.key_path` in the config file. Otherwise, the server generates a self-signed Ed25519 certificate automatically, which is fine since clients verify the server by fingerprint, not by CA chain.

## Using the CLI

The four main commands follow the lifecycle of a node: setup the first one, invite others, adopt the invite on the new machine, then connect.

### Setup

Setup bootstraps the first node in a cluster. You need the setup token from the signal server's startup output.

```
mlsh setup homelab \
  --signal-host signal.example.com \
  --token XXXX-XXXX-XXXX@abc123def456
```

This connects to the signal server, verifies the TLS certificate fingerprint, registers the node as an admin, and receives an overlay IP. The cluster configuration is saved to `~/.config/mlsh/clusters/homelab.toml`. The node also generates an Ed25519 identity keypair stored in `~/.config/mlsh/identity/` if one does not already exist.

### Invite

Once the first node is set up, you can invite other machines to join the cluster.

```
mlsh invite homelab --ttl 3600 --role node
```

This generates a signed invite URL that looks like `mlsh://signal.example.com/adopt/eyJ...`. The invite is signed with your node's Ed25519 private key and includes the cluster ID, your node ID as sponsor, the target role, an expiration timestamp, and the signal server's fingerprint. A QR code is also displayed for convenience. The TTL is in seconds, defaulting to one hour.

### Adopt

On the new machine, run the invite URL through adopt.

```
mlsh adopt "mlsh://signal.example.com/adopt/eyJwYXl..." --name nas
```

The CLI decodes the invite, extracts the signal server's fingerprint, connects to the server, and presents the signed invite for verification. The signal server checks the sponsor's Ed25519 signature against the public key in its registry, verifies the invite has not expired, and registers the new node. The new node receives an overlay IP and a node token for future reconnections.

### Connect

With the cluster configured, activate the overlay tunnel.

```
mlsh connect homelab
```

This tells the tunnel daemon (`mlshtund`) to establish the signal session and create the TUN device. In the background, the daemon authenticates to the signal server, receives the peer list, gathers local network candidates, and begins establishing direct QUIC tunnels to every peer. You can also run in foreground mode for debugging with `mlsh connect homelab --foreground`.

To check the status of active tunnels:

```
mlsh status
```

This shows each connected cluster with its state, overlay IP, uptime, and traffic counters.

## Sponsorship and adoption

mlsh does not use a shared secret for ongoing cluster membership. The cluster secret is only used once, during the initial setup of the first admin node. After that, new nodes join through sponsorship.

An admin generates a signed invite using `mlsh invite`. The invite payload contains the sponsor's node ID, the target cluster, the intended role, and an expiration timestamp. This payload is signed with the sponsor's Ed25519 private key. When the new node presents this invite during adoption, the signal server verifies the signature against the sponsor's public key from its node registry. If the signature is valid, the sponsor is an active admin, and the invite has not expired, the node is admitted.

This creates a verifiable chain of trust. Every node in the cluster was either the original admin (authenticated via the cluster secret) or was explicitly vouched for by an existing admin. The signal server records who sponsored each node, which provides an audit trail of how the cluster grew.

Node tokens are issued after adoption and are used for reconnection. They are HMAC-SHA256 values derived from a signing key held by the signal server, bound to the cluster ID and node ID. They do not expire, so a node can reconnect after reboots without re-adopting. Revoking a node invalidates its registration server-side, making the token useless even if it is still present on disk.

## Tunnels and encryption

All communication in mlsh uses [QUIC (RFC 9000)](https://datatracker.ietf.org/doc/rfc9000/), which runs over UDP and provides multiplexed streams with built-in congestion control. There are two distinct QUIC connections per peer relationship: one to the signal server (for coordination) and one directly to each peer (for data).

The [TLS 1.3](https://datatracker.ietf.org/doc/rfc8446/) layer uses rustls with the aws-lc-rs cryptographic backend. Key exchange is [X25519Kyber768](https://datatracker.ietf.org/doc/draft-tls-westerbaan-xyber768d00/), a hybrid scheme that combines classical elliptic curve Diffie-Hellman ([X25519](https://datatracker.ietf.org/doc/rfc7748/)) with a post-quantum KEM ([ML-KEM 768](https://csrc.nist.gov/pubs/fips/203/final)). Both must be broken for the session key to be compromised. This protects against an adversary who records traffic today and attempts decryption once a cryptographically relevant quantum computer exists.

Each node's identity is an [Ed25519](https://datatracker.ietf.org/doc/rfc8032/) keypair wrapped in a self-signed X.509 certificate. Trust is not based on certificate authorities. Instead, the signal server maintains a registry of node fingerprints (SHA-256 of the DER-encoded certificate), and peers verify each other's fingerprint during the TLS handshake. This is conceptually similar to SSH's known_hosts, but managed centrally by the signal server rather than per-machine.

The signal server connection is verified by fingerprint pinning. During setup or adoption, the client receives the signal server's certificate fingerprint (either from the setup token or from the signed invite) and stores it in the cluster configuration. On every subsequent connection, the client computes the SHA-256 of the server's presented certificate and rejects the connection if it does not match.

## Overlay network

When a node connects to the cluster, the tunnel daemon creates a TUN device named `mlsh0` with the node's overlay IP. The overlay subnet defaults to `100.64.0.0/10`, which is the IANA shared address space, providing roughly 4 million usable addresses. Each node receives a unique IP within this range, allocated sequentially by the signal server and persisted in the database.

Packets written to the TUN device are read by the daemon, which looks up the destination IP in an in-memory routing table. If a direct QUIC connection exists to the target peer, the packet is sent over a unidirectional QUIC stream. If no direct connection is available, the packet is forwarded through the signal server as a relay.

Direct connections are established using a strategy inspired by [ICE](https://datatracker.ietf.org/doc/rfc8445/). When a node connects to the signal server, it gathers its local network addresses (filtering out loopback, link-local, Docker bridges, and overlay IPs to prevent routing loops) and reports them as candidates. When a new peer appears, the daemon probes the peer's candidates using a [happy-eyeballs](https://datatracker.ietf.org/doc/rfc8305/) algorithm: it tries each address with staggered 100ms delays and takes the first connection that succeeds. If all candidates fail, it falls back to relaying through the signal server. A deterministic tiebreaker (the node with the lower overlay IP initiates) prevents both sides from opening duplicate relay streams.

The TUN device MTU is set to 1400 bytes to account for QUIC and UDP encapsulation overhead. Packets arriving from peers are validated (IPv4 header check, loopback/broadcast filtering) before being written to the TUN device.

## DNS

Each node runs a lightweight DNS resolver that maps `<node-id>.<cluster-name>` to overlay IPs. When you set up a cluster called `homelab` and a node called `nas`, you can reach it at `nas.homelab` from any other node in the cluster.

The resolver is a minimal UDP server that listens on the overlay IP (port 53 on Linux, port 53535 on localhost on macOS). It only handles A record queries. Lookups are performed against the in-memory peer table, which is kept in sync with the signal server's peer list. Responses have a 60-second TTL. Queries for unknown nodes return NXDOMAIN. Querying the bare cluster name (just `homelab`) returns the local node's own overlay IP.

DNS integration is platform-specific. On macOS, the daemon writes a resolver file to `/etc/resolver/<cluster>`, which the system's mDNSResponder picks up automatically for split DNS. Only queries matching the cluster name are routed to the mlsh resolver; all other DNS queries go through the normal system resolver. On Linux, the daemon configures systemd-resolved via D-Bus, setting the `mlsh0` interface as the DNS server for the cluster zone with `routing_only=true`, which achieves the same split DNS behavior.

## License

This project uses a dual-license model:

| Component | License |
|-----------|---------|
| `mlsh-cli` | MIT |
| `mlsh-crypto` | MIT |
| `mlsh-protocol` | MIT |
| `mlsh-menubar` | MIT |
| `mlsh-signal` | AGPL-3.0 |

Client-side tooling (CLI, daemon, menu bar app) and shared libraries (crypto, protocol) are MIT-licensed. The signal server is AGPL-3.0.

See [LICENSE-MIT](LICENSE-MIT) and [LICENSE-AGPL](LICENSE-AGPL) for full texts.
