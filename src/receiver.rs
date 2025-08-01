use std::collections::{BTreeMap, HashMap};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use nfq::{Queue, Verdict};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::udp::MutableUdpPacket;
use pnet::packet::{MutablePacket, Packet};
use socket2::SockAddr;

use crate::types::{Interface, ReceiverConfiguration, Source, Stats};
use crate::utils::CommandGuard;

enum MessageStatus {
    Forwarded(u32),
    Proxied(u32, SocketAddrV4, SocketAddrV4),
    Invalid,
}

pub fn listen(
    configuration: ReceiverConfiguration,
    _interfaces: Arc<Vec<Interface>>,
    sources: Arc<Mutex<HashMap<u16, Source>>>,
    running: Arc<AtomicBool>,
    stats: Arc<Stats>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let _rules = iptables(&configuration);

    let mut queue = Queue::open()?;
    queue.bind(configuration.recv_queue)?;
    queue.set_queue_max_len(configuration.recv_queue, configuration.recv_queue_max_len)?;
    queue.set_nonblocking(true);

    let mut map: BTreeMap<u32, (nfq::Message, MessageStatus)> = BTreeMap::new();
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

        // Pretty-print the message
        let status = process_message(&mut msg, &configuration);
        match status {
            MessageStatus::Forwarded(id) if current == 0 || id == current => {
                if let Some((mut buffered, _)) = map.remove(&id) {
                    buffered.set_verdict(Verdict::Drop);
                    queue.verdict(buffered)?;
                }

                // Forward the message
                msg.set_verdict(Verdict::Accept);
                queue.verdict(msg)?;
                current = id + 1;
                last = Instant::now();
            }
            MessageStatus::Forwarded(id) if id > current => {
                // If there already was a buffered message with the same ID, drop it
                if let Some((mut buffered, _)) = map.insert(id, (msg, status)) {
                    buffered.set_verdict(Verdict::Drop);
                    queue.verdict(buffered)?;
                };

                stats.recv_out_of_order.fetch_add(1, Ordering::Relaxed);
            }
            MessageStatus::Proxied(id, source, destination) if current == 0 || id == current => {
                // SAFETY: Proxied messages are only created when SNAT is configured
                let snat = unsafe { configuration.snat.unwrap_unchecked() };

                // We do not forward so drop the messages
                msg.set_verdict(Verdict::Drop);
                if let Some((mut buffered, _)) = map.remove(&id) {
                    buffered.set_verdict(Verdict::Drop);
                    queue.verdict(buffered)?;
                }

                if let Ok(socket) = sources
                    .lock()
                    .unwrap()
                    .entry(destination.port())
                    .or_insert_with(|| {
                        Source::new(*destination.ip(), destination.port(), snat)
                            .expect("Failed to bind SNAT port")
                    })
                    .attach(SockAddr::from(SocketAddrV4::new(
                        *source.ip(),
                        source.port(),
                    )))
                    .socket
                    .read()
                {
                    socket.set_header_included_v4(true)?;
                    socket.send_to(msg.get_payload(), &destination.into())?;
                }

                queue.verdict(msg)?;
                current = id + 1;
                last = Instant::now();
            }
            MessageStatus::Proxied(id, _, _) if id > current => {
                if let Some((mut buffered, _)) = map.insert(id, (msg, status)) {
                    buffered.set_verdict(Verdict::Drop);
                    queue.verdict(buffered)?;
                };

                stats.recv_out_of_order.fetch_add(1, Ordering::Relaxed);
            }
            // Already processed, drop it
            MessageStatus::Forwarded(id) | MessageStatus::Proxied(id, _, _) if id < current => {
                msg.set_verdict(Verdict::Drop);
                queue.verdict(msg)?;
            }
            // Invalid, drop it
            MessageStatus::Invalid => {
                msg.set_verdict(Verdict::Drop);
                queue.verdict(msg)?;
                stats.recv_dropped.fetch_add(1, Ordering::Relaxed);
            }
            _ => unreachable!("Unexpected message status"),
        }

        // Drop messages that have been buffered for too long
        if Instant::now().duration_since(last).as_millis() > configuration.timeout {
            if let Some((first, _)) = map.first_key_value() {
                stats
                    .recv_dropped
                    .fetch_add((*first - current) as u64, Ordering::Relaxed);
                current = *first;
            }
        }

        // Drain the queue of buffered messages if possible
        while let Some((_, (mut msg, status))) = map.remove_entry(&current) {
            match status {
                MessageStatus::Forwarded(id) => {
                    msg.set_verdict(Verdict::Accept);
                    queue.verdict(msg)?;
                    current = id + 1;
                    last = Instant::now();
                }
                MessageStatus::Proxied(id, source, destination) => {
                    // SAFETY: Proxied messages are only created when SNAT is configured
                    let snat = unsafe { configuration.snat.unwrap_unchecked() };

                    if let Ok(socket) = sources
                        .lock()
                        .unwrap()
                        .entry(destination.port())
                        .or_insert_with(|| {
                            Source::new(*destination.ip(), destination.port(), snat)
                                .expect("Failed to bind SNAT port")
                        })
                        .attach(SockAddr::from(SocketAddrV4::new(
                            *source.ip(),
                            source.port(),
                        )))
                        .socket
                        .read()
                    {
                        socket.set_header_included_v4(true)?;
                        socket.send_to(msg.get_payload(), &destination.into())?;
                    }

                    // We do not forward so drop the message
                    msg.set_verdict(Verdict::Drop);
                    queue.verdict(msg)?;
                    current = id + 1;
                    last = Instant::now();
                }
                MessageStatus::Invalid => {
                    msg.set_verdict(Verdict::Drop);
                    queue.verdict(msg)?;
                    stats.recv_dropped.fetch_add(1, Ordering::Relaxed);
                }
            }
        }

        stats.recv_total.fetch_add(1, Ordering::Relaxed);
        stats.recv_bytes.fetch_add(bytes as u64, Ordering::Relaxed);
        stats.recv_current.store(current as u64, Ordering::Relaxed);
    }

    Ok(())
}

fn process_message(msg: &mut nfq::Message, configuration: &ReceiverConfiguration) -> MessageStatus {
    let mut payload = msg.get_payload().to_vec();
    if let Some(ip_packet) = Ipv4Packet::new(&payload)
        && ip_packet.get_next_level_protocol() == IpNextHeaderProtocols::Udp
    {
        let ip_header_len = (ip_packet.get_header_length() * 4) as usize;
        let (ip_buf, udp_packet_buf) = payload.split_at_mut(ip_header_len);

        const UDP_HEADER: u16 = 8;
        if let Some(mut udp_packet) = MutableUdpPacket::new(udp_packet_buf) {
            // Extract the ID
            let id = u32::from_be_bytes(
                udp_packet.payload()[udp_packet.payload().len() - 4..]
                    .try_into()
                    .unwrap(),
            );

            let full_packet = udp_packet.packet_mut();
            let (_, rest) = full_packet.split_at_mut(UDP_HEADER as usize);

            // Zero out the last 4 bytes of the UDP payload
            let len = rest.len() - 4;
            for b in &mut rest[len..] {
                *b = 0;
            }

            udp_packet.set_length(UDP_HEADER + len as u16);
            udp_packet.set_checksum(0);

            if let Some(mut ip_packet) = MutableIpv4Packet::new(ip_buf) {
                let new_ip_len = ip_header_len as u16 + UDP_HEADER + len as u16;
                ip_packet.set_total_length(new_ip_len);
                ip_packet.set_checksum(0);

                if let Some(snat) = &configuration.snat {
                    let source = ip_packet.get_source();
                    let port = udp_packet.get_source();
                    let destination = ip_packet.get_destination();
                    let destination_port = udp_packet.get_destination();

                    ip_packet.set_source(*snat.ip());
                    udp_packet.set_source(snat.port());
                    msg.set_payload(payload);

                    return MessageStatus::Proxied(
                        id,
                        SocketAddrV4::new(source, port),
                        SocketAddrV4::new(destination, destination_port),
                    );
                }

                msg.set_payload(payload);
                return MessageStatus::Forwarded(id);
            }
        }
    }

    MessageStatus::Invalid
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
