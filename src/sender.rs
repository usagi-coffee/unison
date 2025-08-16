use nfq::{Queue, Verdict};
use parking_lot::RwLock;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::udp::MutableUdpPacket;
use rand::Rng;
use socket2::SockAddr;
use std::collections::HashMap;
use std::net::{SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::types::{Interface, Payload, SenderConfiguration, Source, Stats};
use crate::utils::CommandGuard;

enum SourceStrategy {
    Original,
    Fixed(u16),
    Random,
    Rotating {
        current: u16,
        interval: Duration,
        last: Instant,
    },
}

pub fn listen(
    configuration: SenderConfiguration,
    interfaces: Arc<Vec<Interface>>,
    sources: Arc<RwLock<HashMap<u16, Source>>>,
    running: Arc<AtomicBool>,
    stats: Arc<Stats>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let _rules = iptables(&configuration);

    let mut queue = Queue::open()?;
    queue.bind(configuration.queue)?;
    queue.set_queue_max_len(configuration.queue, configuration.queue_max_len)?;
    queue.set_nonblocking(true);

    let mut id = 0u32;

    let mut src_strategy = match configuration.source_port {
        Some(0) => match configuration.source_rotate_ms {
            Some(ms) => SourceStrategy::Rotating {
                current: rand::thread_rng().gen_range(10000..=65535),
                interval: Duration::from_millis(ms as u64),
                last: Instant::now(),
            },
            None => SourceStrategy::Random,
        },
        Some(p) => SourceStrategy::Fixed(p),
        None => SourceStrategy::Original,
    };

    stats.send_ready.store(true, Ordering::Relaxed);
    while running.load(Ordering::Relaxed) {
        let mut msg = match queue.recv() {
            Ok(msg) => msg,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                // Evict old addresses from sources
                for (_, source) in sources.read().iter() {
                    let mut evict = false;
                    'addrs: for (_, addr) in source.addrs.read().iter() {
                        if addr.last.load(Ordering::Relaxed).elapsed().as_millis()
                            > configuration.ttl
                        {
                            evict = true;
                            break 'addrs;
                        }
                    }

                    if evict {
                        source.addrs.write().retain(|_, addr| {
                            addr.last.load(Ordering::Relaxed).elapsed().as_millis()
                                <= configuration.ttl
                        });
                    }
                }

                std::thread::sleep(Duration::from_millis(10));
                continue;
            }
            Err(error) => {
                println!("sender: {}", error);
                break;
            }
        };

        const UDP_HEADER: usize = 8;

        let payload = msg.get_payload_mut();
        if let Some(ip_packet) = Ipv4Packet::new(&payload)
            && ip_packet.get_next_level_protocol() == IpNextHeaderProtocols::Udp
            && let ip_header_len = 4 * ip_packet.get_header_length() as usize
            && let (ip_header, udp_packet) = payload.split_at_mut(ip_header_len)
            && let (udp_header, udp_payload) = udp_packet.split_at_mut(UDP_HEADER)
            && let Some(mut ip_packet) = MutableIpv4Packet::new(ip_header)
            && let Some(mut udp_packet) = MutableUdpPacket::new(udp_header)
        {
            let fragments = if udp_payload.len() >= configuration.fragment_threshold as usize {
                u8::min(configuration.fragments, interfaces.len() as u8)
            } else {
                1
            };

            let fragment_len = udp_payload.len() / fragments as usize;
            let fragment_remainder = udp_payload.len() % fragments as usize;

            let src_port = match &mut src_strategy {
                SourceStrategy::Original => udp_packet.get_source(),
                SourceStrategy::Fixed(p) => *p,
                SourceStrategy::Random => rand::thread_rng().gen_range(10000..=65535),
                SourceStrategy::Rotating {
                    current,
                    interval,
                    last,
                } => {
                    if last.elapsed() >= *interval {
                        *current = rand::thread_rng().gen_range(10000..=65535);
                        *last = Instant::now();
                    }
                    *current
                }
            };
            let dst_port = udp_packet.get_destination();
            let dst = {
                if let Some(destination) = configuration.destination {
                    let destination = destination.ip().clone();
                    ip_packet.set_destination(destination);
                    destination
                } else {
                    ip_packet.get_destination()
                }
            };

            udp_packet.set_checksum(0);
            ip_packet.set_checksum(0);

            stats
                .send_bytes
                .fetch_add(ip_packet.get_total_length() as u64, Ordering::Relaxed);

            for (fragment, interface) in interfaces.iter().enumerate() {
                let fragment = fragment % fragments as usize;
                let last = fragment == fragments as usize - 1;
                let udp_len = UDP_HEADER
                    + fragment_len
                    + if fragments > 1 && last {
                        fragment_remainder
                    } else {
                        0
                    }
                    + Payload::len();

                let mut packet = Vec::with_capacity(ip_header_len + udp_len);
                // IP Header
                packet.extend_from_slice(ip_header);
                packet[2..4].copy_from_slice(&((ip_header_len + udp_len) as u16).to_be_bytes());

                // UDP Header
                packet.extend_from_slice(udp_header);
                packet[ip_header_len + 4..ip_header_len + 6]
                    .copy_from_slice(&(udp_len as u16).to_be_bytes());

                // UDP Payload
                if fragments > 1 {
                    if last {
                        packet.extend_from_slice(&udp_payload[fragment * fragment_len..]);
                    } else {
                        packet.extend_from_slice(
                            &udp_payload[fragment * fragment_len..(1 + fragment) * fragment_len],
                        );
                    }
                } else {
                    packet.extend_from_slice(&udp_payload);
                }

                // Extra
                packet.extend_from_slice(
                    &Payload::new()
                        .with_sequence(id)
                        .with_fragments(fragments)
                        .with_fragment(fragment as u8 % fragments)
                        .into_bytes(),
                );

                let socket = interface.socket.write();
                socket.set_mark(configuration.fwmark)?;
                socket.set_header_included_v4(true)?;

                if let Some(_) = configuration.snat {
                    if let Some(source) = sources.read().get(&src_port) {
                        let addrs = &source.addrs.read();
                        for (dst, _) in addrs.iter() {
                            let dst_addr = dst.as_socket_ipv4().unwrap();
                            packet[12..16].copy_from_slice(&source.ip.octets());
                            packet[ip_header_len..ip_header_len + 2]
                                .copy_from_slice(&source.port.to_be_bytes());
                            packet[16..20].copy_from_slice(&dst_addr.ip().octets());
                            packet[ip_header_len + 2..ip_header_len + 4]
                                .copy_from_slice(&dst_addr.port().to_be_bytes());

                            if let Err(error) = socket.send_to(&packet, &dst) {
                                eprintln!(
                                    "sender: {}: failed to send with {}",
                                    interface.name, error
                                );
                            }
                        }
                    }
                } else {
                    packet[12..16].copy_from_slice(&interface.ip.octets());
                    packet[ip_header_len + 0..ip_header_len + 2]
                        .copy_from_slice(&src_port.to_be_bytes());

                    socket.set_header_included_v4(true)?;
                    if let Err(error) = socket.send_to(
                        &packet,
                        &SockAddr::from(SocketAddr::V4(SocketAddrV4::new(dst, dst_port))).into(),
                    ) {
                        eprintln!("sender: {}: failed to send with {}", interface.name, error);
                    }
                }

                // Reset mark on going out
                socket.set_mark(0)?;

                interface.send_packets.fetch_add(1, Ordering::Relaxed);
                interface
                    .send_bytes
                    .fetch_add(packet.len() as u64, Ordering::Relaxed);
            }

            id += 1;

            stats.send_total.fetch_add(1, Ordering::Relaxed);
            stats.send_current.store(id as u64, Ordering::Relaxed);
        }

        msg.set_verdict(Verdict::Drop);
        queue.verdict(msg)?;
    }

    Ok(())
}

fn iptables(configuration: &SenderConfiguration) -> Vec<CommandGuard<'_>> {
    let mut rules = vec![];

    if !configuration.server {
        // On client redirect packets coming from the client to nfqueue
        if let Some(ports) = &configuration.ports {
            for port in ports {
                rules.push(
                    CommandGuard::new("iptables")
                        .call(format!(
                            "-t mangle -A OUTPUT -p udp --dport {} -m mark ! --mark {} -j NFQUEUE --queue-num {}",
                            port, configuration.fwmark, configuration.queue
                        ))
                        .cleanup(format!(
                            "-t mangle -D OUTPUT -p udp --dport {} -m mark ! --mark {} -j NFQUEUE --queue-num {}",
                            port, configuration.fwmark, configuration.queue
                        )),
                );
            }
        }
    } else {
        // On server redirect packets coming from the client to nfqueue
        if let Some(ports) = &configuration.ports {
            for port in ports {
                rules.push(
                    CommandGuard::new("iptables")
                        .call(format!(
                            "-t mangle -A OUTPUT -p udp --sport {} -m mark ! --mark {} -j NFQUEUE --queue-num {}",
                            port, configuration.fwmark, configuration.queue
                        ))
                        .cleanup(format!(
                            "-t mangle -D OUTPUT -p udp --sport {} -m mark ! --mark {} -j NFQUEUE --queue-num {}",
                            port, configuration.fwmark, configuration.queue
                        )),
                );
            }
        }
    }

    rules
}
