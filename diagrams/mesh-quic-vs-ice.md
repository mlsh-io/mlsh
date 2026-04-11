# mlsh Mesh Network — QUIC vs STUN/TURN/ICE

## 1. Architecture traditionnelle : WebRTC / STUN / TURN / ICE

```
                        ┌──────────────┐
                        │  STUN Server │  (candidats srflx)
                        └──────┬───────┘
                               │
         ┌─────────────────────┼──────────────────────┐
         │                     │                      │
    ┌────▼────┐          ┌─────▼─────┐          ┌─────▼────┐
    │ Node A  │◄────?────► Node B    │◄────?────► Node C   │
    └────┬────┘  direct  └─────┬─────┘  direct  └─────┬────┘
         │       (maybe)        │       (maybe)       │
         │                      │                     │
         │    ┌──────────────┐  │                     │
         └────► TURN Server  ◄──┘─────────────────────┘
              │  (relay)     │
              └──────────────┘

    Signaling Server (WebSocket/HTTP)
    ├─ Échange de SDP (Session Description Protocol)
    ├─ Échange de candidats ICE
    └─ Pas de transport de données
```

### Flux de connexion ICE (par paire de peers)

```
  Node A                  STUN           TURN          Signaling         Node B
    │                      │              │               │                │
    │── Gather candidates ─►              │               │                │
    │◄── srflx candidate ──┤              │               │                │
    │── Allocate relay ────────────────── ►               │                │
    │◄── relay candidate ──────────────── ┤               │                │
    │                                                     │                │
    │──────── SDP Offer + candidates ────────────────────►│                │
    │                                                     │──── forward ──►│
    │                                                     │                │
    │                                                     │◄── SDP Answer ─┤
    │◄─────── SDP Answer + candidates ───────────────────┤                │
    │                                                                      │
    │── STUN Binding (connectivity check) ────────────────────────────────►│
    │◄── STUN Binding Response ───────────────────────────────────────────┤│
    │                                                                      │
    │   ... répété pour CHAQUE paire de candidats ...                      │
    │   ... nomination du meilleur chemin ...                              │
    │                                                                      │
    │══ DTLS handshake (sur UDP) ═════════════════════════════════════════►│
    │══ SRTP media / SCTP data ═══════════════════════════════════════════►│
```

**Problemes :**
- 4+ serveurs a deployer et maintenir (Signaling, STUN, TURN, parfois TURN/TLS)
- SDP : format texte complexe, fragile, difficile a debugger
- ICE : negociation lente (centaines de ms a secondes), teste toutes les paires
- TURN : relay couteux (media transite en clair cote serveur, allocation par session)
- DTLS sur UDP : reimplemente la fiabilite (retransmissions manuelles, pas de congestion control natif)
- Pas de multiplexage natif : 1 association SCTP ou 1 flux SRTP par "canal"
- Certificats ephemeres : fingerprint echange via SDP, pas de PKI

---

## 2. Architecture mlsh : QUIC natif + Signal hybride

```
                        ┌─────────────────────────────────┐
                        │         mlsh-signal :4433       │
                        │    (QUIC + TLS 1.3 + PQ KEM)    │
                        │                                 │
                        │  ┌───────────┐ ┌──────────────┐ │
                        │  │ SessionDB │ │ Relay Splice │ │
                        │  │ (SQLite)  │ │ (bi-stream)  │ │
                        │  └───────────┘ └──────────────┘ │
                        └──┬──────────┬──────────┬────────┘
                     QUIC  │    QUIC  │    QUIC  │
                  (session)│ (session)│ (session)│
                           │          │          │
                     ┌─────▼──┐  ┌────▼───┐  ┌──▼──────┐
                     │ Node A │  │ Node B │  │ Node C  │
                     │ .0.1   │  │ .0.2   │  │ .0.3    │
                     └───┬──┬─┘  └──┬──┬──┘  └──┬──────┘
                         │  │       │  │        │
                         │  └───────┘  │        │    QUIC direct
                         │   direct    └────────┘    (mlsh-overlay)
                         │  (QUIC P2P)  direct
                         │
                         └──── relay via signal ────► Node C
                              (si direct echoue)

    Overlay Network: 100.64.0.0/10 (TUN device, 1400 MTU)
```

### Flux de connexion mlsh (par paire de peers)

```
  Node A                         Signal                           Node B
    │                               │                                │
    │══ QUIC connect (mlsh-signal) ═►                                │
    │── NodeAuth { fp, token } ────►│                                │
    │◄── NodeAuthOk { ip, peers } ──┤                                │
    │                               │                                │
    │   Signal observe l'IP publique de A (srflx, prio 200)         │
    │   Signal broadcast: PeerJoined { A, candidates }              │
    │                               │── PeerJoined(A) ─────────────►│
    │                               │                                │
    │◄── PeerJoined(B) ────────────┤   (B etait deja connecte)     │
    │                               │                                │
    │   Probe candidates de B (Happy Eyeballs, 100ms stagger):      │
    │── QUIC connect srflx:203.0.113.5:5432 ───────────────────────►│
    │── QUIC connect host:192.168.1.10:5432 ──────(100ms later)────►│
    │                                                                │
    │◄══ TLS 1.3 handshake (X25519Kyber768) ═══════════════════════►│
    │   Verify fingerprint SHA-256 ✓                                 │
    │                                                                │
    │══ QUIC bi-stream (mlsh-overlay) ══════════════════════════════►│
    │   TUN ◄──► QUIC ◄──► TUN                                      │
    │                                                                │
    ╔══════════════════════════════════════════════════════════════╗
    ║  TOTAL : 1 RTT (QUIC 0/1-RTT) vs 4-location RTT pour ICE  ║
    ╚══════════════════════════════════════════════════════════════╝
```

### Fallback Relay (quand le direct echoue)

```
  Node A                         Signal                           Node C
    │                               │                                │
    │   Direct probe timeout (3s)   │                                │
    │   A.ip < C.ip → A initie     │                                │
    │                               │                                │
    │── RelayOpen { target: C } ───►│                                │
    │                               │── RelayIncoming { from: A } ──►│
    │                               │◄── RelayAccepted ──────────────┤
    │◄── RelayReady ────────────────┤                                │
    │                               │                                │
    │══ Splice bidirectionnel ══════╪════════════════════════════════►│
    │   (signal forward les bytes,  │  transparent, pas de decode)   │
    │    buffer 256 paquets)        │                                │
```

---

## 3. Comparaison directe

```
┌──────────────────────┬────────────────────────────┬─────────────────────────────┐
│                      │   STUN/TURN/ICE (WebRTC)   │     mlsh (QUIC natif)       │
├──────────────────────┼────────────────────────────┼─────────────────────────────┤
│ Serveurs requis      │ Signaling + STUN + TURN    │ Signal uniquement           │
│                      │ (3-4 composants)           │ (1 binaire)                 │
├──────────────────────┼────────────────────────────┼─────────────────────────────┤
│ Protocole signal     │ WebSocket + SDP (texte)    │ QUIC + JSON frames          │
│                      │ format complexe/fragile    │ (4B len prefix, typed)      │
├──────────────────────┼────────────────────────────┼─────────────────────────────┤
│ Decouverte NAT       │ STUN Binding Request       │ Signal observe remote_addr  │
│                      │ (serveur dedie)            │ (zero infra supplementaire) │
├──────────────────────┼────────────────────────────┼─────────────────────────────┤
│ Connectivity check   │ ICE: teste toutes les      │ Happy Eyeballs: parallel    │
│                      │ paires de candidats        │ probe, 100ms stagger,       │
│                      │ (O(n*m) checks)            │ first-wins                  │
├──────────────────────┼────────────────────────────┼─────────────────────────────┤
│ Temps de connexion   │ 2-10s (gather + check +    │ ~1 RTT (QUIC 0/1-RTT        │
│                      │ DTLS handshake)            │ + TLS 1.3 integre)          │
├──────────────────────┼────────────────────────────┼─────────────────────────────┤
│ Relay                │ TURN: allocation/session,   │ Signal splice: zero-copy   │
│                      │ serveur voit le media,     │ bi-stream forwarding,       │
│                      │ protocole complexe         │ signal ne decode rien       │
├──────────────────────┼────────────────────────────┼─────────────────────────────┤
│ Chiffrement          │ DTLS (UDP) + SRTP          │ TLS 1.3 natif dans QUIC     │
│                      │ (reimplemente fiabilite)   │ (0-RTT possible)            │
├──────────────────────┼────────────────────────────┼─────────────────────────────┤
│ Post-quantique       │ Non (DTLS 1.2 standard)    │ X25519Kyber768 (PQ KEM)     │
│                      │                            │ natif via rustls            │
├──────────────────────┼────────────────────────────┼─────────────────────────────┤
│ Multiplexage         │ SCTP sur DTLS              │ QUIC streams natifs         │
│                      │ (complexite en couches)    │ (multiplexe par design)     │
├──────────────────────┼────────────────────────────┼─────────────────────────────┤
│ Congestion control   │ Pas natif (UDP brut),      │ Natif dans QUIC (NewReno/   │
│                      │ SCTP a le sien mais        │ BBR), applique a chaque     │
│                      │ empile sur DTLS            │ connexion                   │
├──────────────────────┼────────────────────────────┼─────────────────────────────┤
│ Auth des peers       │ Fingerprint dans SDP       │ mTLS + HMAC-SHA256 tokens   │
│                      │ (confiance dans signaling) │ + fingerprint pinning       │
├──────────────────────┼────────────────────────────┼─────────────────────────────┤
│ Complexite proto     │ ~location RFC (location    │ ~1500 lignes Rust           │
│                      │ lignes, ICE/DTLS/SCTP/     │ (quinn + rustls + serde)    │
│                      │ SRTP/SDP)                  │                             │
└──────────────────────┴────────────────────────────┴─────────────────────────────┘
```

---

## 4. Vue mesh complete (5 nodes)

```
                            ┌──────────────┐
                            │ mlsh-signal  │
                            │   :4433/UDP  │
                            │              │
                            │ - Auth       │
                            │ - Discovery  │
                            │ - Relay      │
                            └──┬─┬─┬─┬─┬──┘
                 QUIC sessions │ │ │ │ │
            ┌──────────────────┘ │ │ │ └──────────────────┐
            │           ┌────────┘ │ └────────┐           │
            │           │          │          │           │
       ┌────▼───┐  ┌────▼───┐ ┌───▼────┐ ┌───▼────┐ ┌───▼────┐
       │  DC-1  │  │  DC-2  │ │ Home-1 │ │ Home-2 │ │ Cloud  │
       │ .0.1   │  │ .0.2   │ │ .0.3   │ │ .0.4   │ │ .0.5   │
       └──┬──┬──┘  └──┬──┬──┘ └──┬──┬──┘ └──┬─────┘ └──┬─────┘
          │  │        │  │       │  │        │          │
          │  └────────┘  │       │  └────────┘          │
          │   direct     │       │   direct             │
          │  (same LAN)  └───────┘  (same LAN)          │
          │               direct                        │
          │             (WAN, srflx)                    │
          │                                             │
          └─────────── relay via signal ────────────────┘
                    (Cloud derriere NAT strict)

    Legende:
    ═══  QUIC direct (mlsh-overlay, TLS 1.3, PQ)
    ───  QUIC session vers signal (mlsh-signal)
    - -  relay splice via signal (fallback)
```

---

## 5. Pourquoi QUIC > STUN/TURN/ICE pour un mesh overlay

### Simplicite operationnelle
```
  ICE stack:                          mlsh stack:
  ┌─────────────┐                     ┌─────────────┐
  │ Application │                     │ Application │
  ├─────────────┤                     ├─────────────┤
  │    SCTP     │                     │ QUIC Stream │ ◄── multiplexage natif
  ├─────────────┤                     ├─────────────┤
  │    DTLS     │                     │   TLS 1.3   │ ◄── integre dans QUIC
  ├─────────────┤                     ├─────────────┤
  │     ICE     │ ◄── connectivity    │    QUIC     │ ◄── transport + crypto
  ├─────────────┤     checks          ├─────────────┤     + mux + CC
  │    STUN     │ ◄── NAT discovery   │     UDP     │
  ├─────────────┤                     └─────────────┘
  │    TURN     │ ◄── relay              4 couches
  ├─────────────┤
  │     UDP     │
  └─────────────┘
     7 couches
```

### Latence de connexion
```
  ICE (worst case):                   mlsh:
  
  t=0     STUN request ──►            t=0     QUIC ClientHello ──►
  t=1 RTT ◄── srflx candidate                (TLS 1.3 integre)
  t=1 RTT SDP offer via signaling     
  t=2 RTT ◄── SDP answer             t=1 RTT ◄── Handshake done
  t=2 RTT ICE check pair 1 ──►               ══ Data flows ══
  t=3 RTT ◄── check response
  t=3 RTT ICE check pair 2 ──►       Gain: 3-9 RTT economises
  ...     (repeat per pair)
  t=N RTT DTLS handshake ──►
  t=N+1   ◄── DTLS done
          ══ Data flows ══
```

### Securite post-quantique
```
  WebRTC/ICE:                         mlsh/QUIC:
  ┌─────────────────┐                 ┌──────────────────────┐
  │ X25519 (ECDH)   │                 │ X25519Kyber768Draft00│
  │                 │                 │                      │
  │ Vulnerable a    │                 │ Hybride:             │
  │ "harvest now,   │                 │ X25519 (classique)   │
  │  decrypt later" │                 │    + Kyber768 (PQ)   │
  │                 │                 │                      │
  │ Pas de migration│                 │ Resistant meme si    │
  │ simple vers PQ  │                 │ un des deux casse    │
  └─────────────────┘                 └──────────────────────┘
```
