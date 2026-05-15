+++
title = "Admin UI"
description = "The browser-based admin console served by the cluster's control-plane node."
weight = 3
sort_by = "weight"
+++

Each cluster has a single **control-plane node** (the one with the `control` role) that hosts the admin REST API and serves a browser-based UI. The UI is a Vue 3 SPA bundled inside the `mlshtund` binary on control-plane builds — no separate service to deploy.

## Open it

From any node in the cluster:

```sh
mlsh ui <cluster>
```

`mlsh ui` starts a localhost proxy on a random port, prints the URL, and opens it in your default browser. The proxy forwards each request to `https://<cluster>:8443` over the overlay, authenticated with this node's identity certificate (mTLS). The browser only ever sees `http://127.0.0.1:<port>`, so there is no cluster CA to trust, no public DNS to set up, and cookies stay scoped to localhost.

The overlay tunnel must be up for the proxy to reach the control node. Use `--no-open` to print the URL without launching a browser (useful over SSH).

## Exposing the UI on the Internet

By default, the admin UI is only reachable over the overlay (via `mlsh ui`). The **Preferences → Expose admin UI** toggle publishes the UI on `<cluster>.<zone>` through the signal server's TLS ingress, using a Let's Encrypt certificate. Once enabled, anyone who knows the URL can hit the login page — protect it with strong credentials (password + TOTP or WebAuthn) before flipping the toggle.

The `zone` is the public DNS zone configured on the signal server. It must be a domain you control, with a wildcard delegation to the signal server's ingress.