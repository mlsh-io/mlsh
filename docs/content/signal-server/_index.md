+++
title = "Signal Server"
description = "Deploy, configure, and operate the MLSH signal server."
weight = 3
sort_by = "weight"
+++

The signal server is a single Linux binary that handles node registration, peer discovery, and relay fallback. It ships as a ~10 MB scratch container.

The server is designed to run on a **publicly reachable host**, with **UDP/443 and TCP/443 open inbound from the internet**. The server is reached by its domain name. That hostname is embedded in every invite the admins issue to new nodes and is pinned into each node's local cluster configuration at adoption. Changing it later requires re-issuing cluster configs, so choose a stable domain you control.
