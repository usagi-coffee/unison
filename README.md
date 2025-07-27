# 🔗 Unison

> Proof of Concept - expect bugs and breaking changes.

Flexible UDP transport layer designed for bi-directional multi-path delivery.

## ✨ Features

- 📋 Packet duplication across multiple interfaces for redundancy
- 🔍 Packet deduplication, with out-of-order handling
- 🔁 Seamless bidirectional handling of UDP traffic
- 🔐 HMAC-based authentication for automatic iptables whitelisting

## 🚧 Planned Features

- 🎭 Source IP masquerading and restoration for single-source IP–dependent protocols like SRT
- 🧠 Configurable heuristics for adaptive multi-path delivery

## ⚙️ Installation

```bash
cargo install --git https://github.com/usagi-coffee/unison --locked
```

## 📡 Client

This configuration assumes two interfaces `stream0` and `stream1` for sending and receiving packets, duplicates the UDP traffic that targets port `8888` of the server.

```bash
unison --ports 8888 --interfaces stream0 stream1

# Optional: If your traffic is bi-directional then you might need to allow the port on the client.
iptables -A INPUT -i stream -p udp --dport 8888 -j ACCEPT
iptables -A INPUT -i stream -p udp --dport 8888 -j ACCEPT
```

## 🖥️ Server

This configuration assumes two interfaces `recv0` and `recv1` for receiving and sending the packets back, client is `192.168.50.31` and traffic goes over port `8888`.

```bash
# Optional: If you want to use HMAC-based authentication
iptables -A INPUT -p udp --dport 7566 -j ACCEPT

# Accept ports
iptables -A INPUT -i recv0 -p udp --dport 8888 -j ACCEPT
iptables -A INPUT -i recv1 -p udp --dport 8888 -j ACCEPT

# Launch unison
unison --server --ports 8888 --interfaces recv0 recv1
```
