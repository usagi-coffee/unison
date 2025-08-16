# 🔗 Unison

> Proof of Concept - expect bugs and breaking changes.

Flexible UDP transport layer designed for bi-directional multi-path delivery.

## ✨ Features

- 📋 Packet duplication across multiple interfaces for redundancy
- 🔍 Packet deduplication, with out-of-order handling
- ✂️ Packet fragmentation across multiple interfaces for parallel transmission and reassembly
- 🔁 Seamless bidirectional handling of UDP traffic
- 🔐 HMAC-based authentication for automatic iptables whitelisting
- 🎭 Source IP masquerading and restoration for single-source IP–dependent protocols like SRT
- 🛡️ Anti-traffic-shaping (self-jitter & source-port rotation)

## 🚧 Planned Features

- 🧠 Configurable heuristics for adaptive multi-path delivery
- 🔁 Packet retransmissions for lost packets/fragments

## ⚙️ Installation

```bash
cargo install --git https://github.com/usagi-coffee/unison --locked
```

## 📡 Client

This example assumes two interfaces `stream0` and `stream1` for sending and receiving packets, duplicates the UDP traffic that targets port `8888` of the server, port 8888 is opened on the server side.

```bash
unison --ports 8888 --interfaces stream0 stream1
```

## 🖥️ Server

This configuration assumes one interface `eth0` for receiving and sending the packets back, the traffic goes over port `8888`.

```bash
# Accept ports
iptables -A INPUT -i recv0 -p udp --dport 8888 -j ACCEPT
iptables -A INPUT -i recv1 -p udp --dport 8888 -j ACCEPT

# Launch unison
unison --server --ports 8888 --interfaces eth0
```

## 🎭 Consistent Source IP/Port

Some protocols—like SRT, RTP, or other connection-oriented UDP systems—require all packets to originate from a single consistent source IP and port. When using multi-path transport, this consistency can be lost, leading to session instability or rejections.

Unison supports source address and port rewriting (SNAT) to preserve consistency. This is done at the packet level and ensures that the receiver sees all packets as coming from the same source.

```bash
# Packets will appear as to come from 10.64.0.1:1337 to sockets on the server
unison --server --snat 10.64.0.1:1337 --ports 8888 --interfaces eth0
```

## 🔐 HMAC Authentication and IP Whitelisting

To prevent unauthorized traffic injection, Unison supports HMAC-based authentication using a shared secret. This ensures that only clients who know the secret can send packets, and their IPs are automatically whitelisted via iptables on the receiver.

```bash
# Client
unison --remote 1.2.3.4 --secret mysecret --ports 8888 --interfaces stream0 stream1

# Server
unison --server --secret mysecret --ports 8888 --interfaces eth0
```

## 🛡️ Avoiding Traffic Shaping

Network operators such as mobile networks sometimes detect perfectly periodic packet streams and apply shaping or rate-limiting, unison currently provides two complementary features to reduce shaping risk:

- Self-Jitter
  - `--jitter <ms>`: maximum jitter in milliseconds to sleep before sending a packet/fragment. The actual sleep is sampled uniformly in `[1, jitter]`.
  - `--jitter-budget <ms>`: maximum total jitter sleep allowed per 1-second window (milliseconds). Default: `100`. Set to `0` to disable the budget cap (i.e., allow up to `jitter` per packet).
  - Jitter is applied once per outgoing packet per interface; the budget is tracked per sender thread and resets every second.

- Flow diversity
  - `--source-port <port>`: use a fixed source port when specified (e.g. `443`).
  - `--source-port 0`: use a random source port per packet.
  - `--source-port 0 --source-rotate-ms <ms>`: pick a random high-numbered source port and replace it every `<ms>` milliseconds (rotating strategy that balances stability and port diversity).

Examples:

```bash
# Jitter: up to 10ms per packet, but no more than 100ms total jitter per second
unison --ports 8888 --interfaces stream0 stream1 --jitter 10 --jitter-budget 100

# Rotate source port every 500ms
unison --ports 8888 --interfaces stream0 stream1 --source-port 0 --source-rotate-ms 500
```
