# Unison

Lightweight UDP redundancy transport layer with a TUN-based duplicator and a NFQUEUE-driven deduplicator. Supports low-level routing, per-packet ID tagging, and out-of-order filtering. Designed to evolve into a transparent bonded multi-interface transport.

## Installation

```bash
cargo install --git https://github.com/usagi-coffee/unison --locked
```

## Client

This configuration assumes two interfaces `stream0` and `stream1` for sending and receiving packets, duplicates the UDP traffic that targets port `8888` of the server.

```bash
unison --ports 8888 --interfaces stream0 stream1

# Optional: If your traffic is bi-directional then you might need to allow the port on the client.
iptables -A INPUT -i stream -p udp --dport 8888 -j ACCEPT
iptables -A INPUT -i stream -p udp --dport 8888 -j ACCEPT
```

## Server

This configuration assumes two interfaces `recv0` and `recv1` for receiving and sending the packets back, client is `192.168.50.31` and traffic goes over port `8888`.

```bash
# Accept port
iptables -A INPUT -i recv0 -p udp --dport 8888 -j ACCEPT
iptables -A INPUT -i recv1 -p udp --dport 8888 -j ACCEPT

# Launch unison
unison --server --ports 8888 --interfaces recv0 recv1
```
