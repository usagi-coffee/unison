use std::collections::{BTreeMap, HashMap, btree_map};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use nfq::{Queue, Verdict};
use parking_lot::{RwLock, RwLockUpgradableReadGuard};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::udp::MutableUdpPacket;
use socket2::SockAddr;

use crate::types::{Interface, Payload, ReceiverConfiguration, Source, Stats};
use crate::utils::CommandGuard;

pub struct ReassembledPacket {
    pub id: u32,
    pub payload: Vec<u8>,
    pub ip_header_length: usize,
    pub fragments: Box<[Option<Box<[u8]>>]>,
    pub destination: SocketAddrV4,
    pub completed: bool,
    pub msg: Option<nfq::Message>,
}

pub fn listen(
    configuration: ReceiverConfiguration,
    _interfaces: Arc<Vec<Interface>>,
    sources: Arc<RwLock<HashMap<u16, Source>>>,
    running: Arc<AtomicBool>,
    stats: Arc<Stats>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let _rules = iptables(&configuration);

    let mut queue = Queue::open()?;
    queue.bind(configuration.recv_queue)?;
    queue.set_queue_max_len(configuration.recv_queue, configuration.recv_queue_max_len)?;
    queue.set_nonblocking(true);

    let mut packets: BTreeMap<u32, ReassembledPacket> = BTreeMap::new();
    let mut current: u32 = 0;

    let mut last = Instant::now();

    stats.recv_ready.store(true, Ordering::Relaxed);
    while running.load(Ordering::Relaxed) {
        let mut msg = match queue.recv() {
            Ok(msg) => msg,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(10));
                continue;
            }
            Err(error) => {
                eprintln!("receiver: {}", error);
                break;
            }
        };

        let bytes = msg.get_original_len();
        let payload = msg.get_payload_mut();

        // Invalid packets are dropped
        if payload.len() < 28 {
            msg.set_verdict(Verdict::Drop);
            queue.verdict(msg)?;
            stats.recv_dropped.fetch_add(1, Ordering::Relaxed);
            continue;
        }

        const UDP_HEADER: usize = 8;

        if let Some(ip_packet) = Ipv4Packet::new(&payload)
            && ip_packet.get_next_level_protocol() == IpNextHeaderProtocols::Udp
            && let ip_header_len = 4 * ip_packet.get_header_length() as usize
            && let (ip_header, udp_packet) = payload.split_at_mut(ip_header_len)
            && let (udp_header, udp_full_payload) = udp_packet.split_at_mut(UDP_HEADER)
            && let udp_payload = &udp_full_payload[..udp_full_payload.len() - Payload::len()]
            && let Ok(mut extra_payload) = udp_full_payload[udp_payload.len()..].try_into()
            && let Some(mut ip_packet) = MutableIpv4Packet::new(ip_header)
            && let Some(mut udp_packet) = MutableUdpPacket::new(udp_header)
            && let extra = Payload::from_bytes(extra_payload)
            && extra.sequence() >= current
        {
            let source = ip_packet.get_source();
            let port = udp_packet.get_source();
            let destination_ip = ip_packet.get_destination();
            let destination_port = udp_packet.get_destination();

            if let Some(snat) = &configuration.snat {
                ip_packet.set_source(*snat.ip());
                udp_packet.set_source(snat.port());

                let sources = sources.upgradable_read();
                if sources.contains_key(&destination_port) {
                    let src = sources.get(&destination_port).unwrap();
                    src.attach(SockAddr::from(SocketAddrV4::new(source, port)));
                } else {
                    let mut write = RwLockUpgradableReadGuard::upgrade(sources);
                    let src = Source::new(destination_ip, destination_port, *snat)
                        .expect("Failed to bind SNAT port");
                    src.attach(SockAddr::from(SocketAddrV4::new(source, port)));
                    write.insert(destination_port, src);
                }
            }

            // Zero out the extra payload
            for byte in &mut extra_payload {
                *byte = 0;
            }

            match packets.entry(extra.sequence()) {
                // Add a new packet
                btree_map::Entry::Vacant(entry) => {
                    let mut fragments = vec![None; extra.fragments() as usize].into_boxed_slice();

                    let mut header_or_payload: Vec<u8>;

                    // Fragmented
                    if fragments.len() > 1 {
                        let approx_udp_length = UDP_HEADER
                            + udp_payload.len()
                            + (udp_payload.len() * extra.fragments() as usize);

                        header_or_payload = Vec::with_capacity(ip_header.len() + approx_udp_length);
                        fragments[extra.fragment() as usize] =
                            Some(udp_payload.to_vec().into_boxed_slice());
                        header_or_payload.extend_from_slice(ip_header);
                        header_or_payload.extend_from_slice(udp_header);
                    } else {
                        let udp_length = UDP_HEADER + udp_payload.len();
                        header_or_payload = Vec::with_capacity(ip_header_len + udp_length);
                        header_or_payload.extend_from_slice(&payload[..ip_header_len + udp_length]);
                    }

                    entry.insert(ReassembledPacket {
                        id: extra.sequence(),
                        ip_header_length: ip_header_len,
                        payload: header_or_payload,
                        destination: SocketAddrV4::new(destination_ip, destination_port),
                        completed: fragments.len() < 2,
                        fragments,
                        msg: if configuration.snat.is_none() {
                            Some(msg)
                        } else {
                            msg.set_verdict(Verdict::Drop);
                            queue.verdict(msg)?;
                            None
                        },
                    });
                }
                // Add fragments
                btree_map::Entry::Occupied(mut entry) if extra.fragments() > 1 => {
                    let packet = entry.get_mut();
                    if packet.fragments[extra.fragment() as usize].is_none() {
                        packet.fragments[extra.fragment() as usize] =
                            Some(udp_payload.to_vec().into_boxed_slice());
                        packet.completed = packet.fragments.iter().all(|f| f.is_some());
                    }

                    msg.set_verdict(Verdict::Drop);
                    queue.verdict(msg)?;
                }
                // Duplicate
                btree_map::Entry::Occupied(_) => {
                    msg.set_verdict(Verdict::Drop);
                    queue.verdict(msg)?;
                }
            }
        } else {
            // Not compatible UDP packet
            msg.set_verdict(Verdict::Drop);
            queue.verdict(msg)?;
            stats.recv_dropped.fetch_add(1, Ordering::Relaxed);
            continue;
        }

        // Drop messages that have been buffered for too long
        if Instant::now().duration_since(last).as_millis() > configuration.timeout {
            if let Some((first, _)) = packets.first_key_value() {
                stats
                    .recv_dropped
                    .fetch_add((*first - current) as u64, Ordering::Relaxed);
                current = *first;
            }
        }

        while let Some(packet) = match packets.entry(current) {
            btree_map::Entry::Occupied(entry) if !entry.get().completed => None,
            btree_map::Entry::Occupied(mut entry) => {
                let packet = entry.get_mut();
                let payload = &mut packet.payload;

                let mut udp_length = payload.len() - packet.ip_header_length;

                // Reassemble the packet payload
                if packet.fragments.len() > 1 {
                    for fragment in packet.fragments.iter_mut() {
                        if let Some(data) = fragment.take() {
                            payload.extend_from_slice(&data);
                            udp_length += data.len();
                        }
                    }
                }

                let (ip_buf, udp_buf) = payload.split_at_mut(packet.ip_header_length);
                let mut ip_packet = MutableIpv4Packet::new(ip_buf).unwrap();
                let mut udp_packet = MutableUdpPacket::new(udp_buf).unwrap();

                udp_packet.set_length(udp_length as u16);
                ip_packet.set_total_length((packet.ip_header_length + udp_length) as u16);
                udp_packet.set_checksum(0);
                ip_packet.set_checksum(0);

                // Send from the SNAT source
                if let Some(_) = &configuration.snat {
                    if let Some(src) = sources.read().get(&packet.destination.port()) {
                        let socket = src.socket.read();
                        socket.set_header_included_v4(true)?;
                        socket.send_to(&payload, &packet.destination.into())?;
                    }
                }
                // Forward
                else if let Some(mut msg) = packet.msg.take() {
                    msg.set_payload(&**payload);
                    msg.set_verdict(Verdict::Accept);
                    queue.verdict(msg)?;
                }

                Some(entry.remove())
            }
            btree_map::Entry::Vacant(_) => None,
        } {
            current = packet.id;
            last = Instant::now();
        }

        stats.recv_total.fetch_add(1, Ordering::Relaxed);
        stats.recv_bytes.fetch_add(bytes as u64, Ordering::Relaxed);
        stats.recv_current.store(current as u64, Ordering::Relaxed);
    }

    Ok(())
}

fn iptables(configuration: &ReceiverConfiguration) -> Vec<CommandGuard<'_>> {
    let mut rules = vec![];

    if !configuration.server {
        // On client redirect packets coming from the server to nfqueue
        if let Some(ports) = &configuration.ports {
            for port in ports {
                rules.push(
                    CommandGuard::new("iptables")
                        .call(format!(
                            "-t mangle -A PREROUTING -p udp --sport {} -j NFQUEUE --queue-num {}",
                            port, configuration.recv_queue
                        ))
                        .cleanup(format!(
                            "-t mangle -D PREROUTING -p udp --sport {} -j NFQUEUE --queue-num {}",
                            port, configuration.recv_queue
                        )),
                );
            }
        }
    }
    // On server redirect packets coming from the client to nfqueue
    else {
        if let Some(ports) = &configuration.ports {
            for port in ports {
                rules.push(
                      CommandGuard::new("iptables")
                          .call(format!(
                              "-t mangle -A INPUT -p udp --dport {} ! -s {} -m mark --mark 0 -j NFQUEUE --queue-num {}",
                              port,
                              if configuration.snat.is_some() { configuration.snat.unwrap().ip().clone() } else { Ipv4Addr::new(1, 2, 3, 4) },
                              configuration.recv_queue
                          ))
                          .cleanup(format!(
                              "-t mangle -D INPUT -p udp --dport {} ! -s {} -m mark --mark 0 -j NFQUEUE --queue-num {}",
                              port,
                              if configuration.snat.is_some() { configuration.snat.unwrap().ip().clone() } else { Ipv4Addr::new(1, 2, 3, 4) },
                              configuration.recv_queue
                          ))
                    );
            }
        }
    }

    rules
}
