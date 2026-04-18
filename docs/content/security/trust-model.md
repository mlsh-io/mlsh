+++
title = "Trust Model"
description = "How MLSH establishes and verifies cluster membership without a shared secret."
weight = 2
+++

MLSH does not use a shared secret for ongoing membership. The cluster secret is used **once**, during the initial setup of the first admin. After that, new nodes join through sponsorship.

## The chain of trust

1. **Genesis.** The signal server generates a cluster secret on first boot and prints it as a setup token (`XXXX-XXXX-XXXX@<fingerprint>`). The first admin uses this token exactly once, via `mlsh setup`, to register itself. The token is then burned.

2. **Sponsored adoption.** To add a node, an existing admin runs `mlsh invite`, which produces a payload signed with the admin's Ed25519 private key. The payload contains:
   - the cluster ID,
   - the sponsor's node ID,
   - the target role (`admin` or `node`),
   - an expiration timestamp,
   - the signal server's fingerprint.

3. **Signature verification.** When the new node runs `mlsh adopt <url>`, the CLI presents the signed invite to the signal server, which verifies the signature against the sponsor's public key in its registry. If the signature is valid, the sponsor is still an active admin, and the invite has not expired, the node is admitted.

Every node in a cluster is therefore either the original admin (authenticated via the cluster secret) or was explicitly vouched for by an existing admin. The signal server records the sponsor of each node, providing an audit trail of how the cluster grew.

## Revocation

An admin can revoke any node:

```sh
mlsh revoke homelab --node nas
```

Revocation invalidates the node's token on the signal server. The node can no longer re-authenticate, even if its local cluster file is untouched. Existing direct peer-to-peer connections remain up until their next rekey (~minutes) because peers verify each other by fingerprint, not through the server on every packet. The revoked node will, however, be unable to re-discover or re-adopt.

## Threats this model addresses

- **Leaked cluster secret**: the secret is only accepted once, so a later leak is harmless.
- **Compromised admin key**: revoke the node. Future invites signed by that key are rejected because the server checks that the sponsor is still active.
- **Impersonated signal server**: fingerprint pinning prevents substitution. An attacker would need both the real server's private key and the ability to redirect DNS/UDP.
