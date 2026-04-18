+++
title = "MLSH Documentation"
sort_by = "weight"
+++

MLSH is a self-hosted mesh VPN that creates encrypted overlay networks between machines. Traffic flows peer-to-peer over QUIC with post-quantum key exchange. A lightweight signal server handles registration and peer discovery, and relays traffic only when a direct connection cannot be established. Each node is assigned a stable overlay IP and a DNS name inside the cluster, so peers can be addressed by name without exposing ports or configuring gateways.
