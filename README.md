# Unison

> Proof of Concept - expect bugs and breaking changes.

Flexible UDP transport layer designed for bi-directional multi-path delivery.

## Features

- Packet duplication across multiple interfaces for redundancy
- Packet deduplication, with out-of-order handling
- Packet fragmentation across multiple interfaces for parallel transmission and reassembly
- Seamless bidirectional handling of UDP traffic
- Source IP masquerading and restoration for single-source IP–dependent protocols like SRT

## Planned Features

- Configurable heuristics for adaptive multi-path delivery
- Packet retransmissions for lost packets/fragments

## Installation

```bash
cargo install --git https://github.com/usagi-coffee/unison --locked
```

## Client

This configirations duplicates the UDP traffic that targets port `8888` through `eth0` and `eth1`.

```bash
unison --ports 8888 --interfaces eth0 eth1
```

## Server

Usually server needs only one interface, in this case we just use`eth0` for receiving and sending the packets back if needed, the duplicated traffic comes over port `8888`.

```bash
unison --server --ports 8888 --interfaces eth0
```

## Consistent Source IP/Port

Some protocols like SRT, RTP, or other connection-oriented UDP protocols require all packets to originate from a single consistent source IP and port by reading the ip and udp header. When using multi-path transport, this consistency can be lost and can lead to session instability or rejections.

Unison supports "snat-like" source address and port rewriting to preserve consistency. This is done at the ip/udp header level and ensures that the target socket sees all packets as coming from the same source.

```bash
# Packets will appear as to come from 10.64.0.1:1337 to sockets on the server
unison --server --snat 10.64.0.1:1337 --ports 8888 --interfaces eth0
```

