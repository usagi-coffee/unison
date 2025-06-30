# Unison

Lightweight UDP redundancy stack with a TUN-based tagger and a NFQUEUE-driven deduplicator. Supports low-level routing, per-packet ID tagging, and out-of-order filtering. Designed to evolve into a transparent bonded multi-interface transport.

## Client

This configuration assumes two interfaces `stream0` and `stream1` for sending packets, and a TUN interface `tun0` for tagging, traffic goes over port `8888`.

```
# Enable NFQUEUE
sudo modprobe nfnetlink_queue

# Forwarding
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv6.conf.all.forwarding=1

# Tagging
ip tuntap add dev tun0 mode tun
ip addr add 10.10.1.0/24 dev tun0
ip link set tun0 up

# Route traffic to the tagger
iptables -t mangle -A OUTPUT -p udp --dport 8888 -j MARK --set-mark 123
ip rule add fwmark 123 table 200
ip route add default dev tun0 table 200

# Deduplication
iptables -I INPUT -i stream0 -j NFQUEUE --queue-num 0
iptables -I INPUT -i stream1 -j NFQUEUE --queue-num 0
```

## Server

This configuration assumes two interfaces `recv0` and `recv1` for receiving packets, and a TUN interface `tun0` for tagging, client is `192.168.50.31` and traffic goes over port `8888`.

```
# Enable NFQUEUE
sudo modprobe nfnetlink_queue

# Forwarding
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv6.conf.all.forwarding=1

# Deduplication
iptables -I INPUT -i recv0 -j NFQUEUE --queue-num 0
iptables -I INPUT -i recv1 -j NFQUEUE --queue-num 0

# Accept port
iptables -A INPUT -i recv0 -p udp --dport 8888 -j ACCEPT
iptables -A INPUT -i recv1 -p udp --dport 8888 -j ACCEPT

# Set mark depending on interface
iptables -t mangle -A PREROUTING -i recv0 -j MARK --set-mark 151
iptables -t mangle -A PREROUTING -i recv0 -j CONNMARK --save-mark
iptables -t mangle -A PREROUTING -i recv1 -j MARK --set-mark 152
iptables -t mangle -A PREROUTING -i recv1 -j CONNMARK --save-mark

# Restore on going out
iptables -t mangle -A OUTPUT -d 192.168.50.31 -j CONNMARK --restore-mark
iptables -t mangle -A POSTROUTING -d 192.168.50.31 -j CONNMARK --restore-mark

# Route interfaces to the tagger
ip rule add to 192.168.50.31 table tun0table
ip route add default dev tun0 table tun0table

# Tagger
ip tuntap add dev tun0 mode tun
ip addr add 10.10.0.0/24 dev tun0
ip link set tun0 up
```
