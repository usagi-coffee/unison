use std::collections::HashMap;
use std::net::{SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use nfq::{Queue, Verdict};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::udp::MutableUdpPacket;
use socket2::SockAddr;

use crate::types::{Interface, SenderConfiguration, Source, Stats};
use crate::utils::CommandGuard;

pub fn listen(
    configuration: SenderConfiguration,
    interfaces: Arc<Vec<Interface>>,
    sources: Arc<Mutex<HashMap<u16, Source>>>,
    running: Arc<AtomicBool>,
    stats: Arc<Stats>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let _rules = iptables(&configuration);

    let mut queue = Queue::open()?;
    queue.bind(configuration.queue)?;
    queue.set_queue_max_len(configuration.queue, configuration.queue_max_len)?;
    queue.set_nonblocking(true);

    let mut id = 0u32;

    stats.send_ready.store(true, Ordering::Relaxed);
    while running.load(Ordering::Relaxed) {
        let mut msg = match queue.recv() {
            Ok(msg) => msg,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(10));
                continue;
            }
            Err(error) => {
                println!("sender: {}", error);
                break;
            }
        };

        let mut packet = msg.get_payload().to_vec();
        packet.extend_from_slice(&id.to_be_bytes());

        if let Some(ip_packet) = Ipv4Packet::new(&packet)
            && ip_packet.get_next_level_protocol() == IpNextHeaderProtocols::Udp
        {
            let ip_header_len = (ip_packet.get_header_length() * 4) as usize;
            let src_port = {
                let udp_header = &packet[ip_header_len..ip_header_len + 4];
                (udp_header[0] as u16) << 8 | (udp_header[1] as u16)
            };
            let dst = ip_packet.get_destination();
            let dst_port = {
                let udp_header = &packet[ip_header_len..ip_header_len + 4];
                (udp_header[2] as u16) << 8 | (udp_header[3] as u16)
            };

            let (ip_buf, udp_packet) = packet.split_at_mut(ip_header_len);

            if let Some(mut udp_packet) = MutableUdpPacket::new(udp_packet) {
                udp_packet.set_length(udp_packet.get_length() + 4);
                udp_packet.set_checksum(0);

                if let Some(mut ip_packet) = MutableIpv4Packet::new(ip_buf) {
                    let new_ip_len = (ip_header_len as u16 + udp_packet.get_length()) as u16;
                    ip_packet.set_total_length(new_ip_len);
                    ip_packet.set_checksum(0);

                    for interface in interfaces.iter() {
                        let socket = interface.socket.write().unwrap();
                        socket.set_mark(configuration.fwmark)?;

                        let mut packet = packet.clone();

                        if let Some(_) = configuration.snat {
                            if let Some(source) = sources.lock().unwrap().get(&src_port) {
                                for addr in &source.addrs {
                                    let sock_addr = addr.as_socket_ipv4().unwrap();
                                    packet[12..16].copy_from_slice(&source.ip.octets());
                                    packet[20..22].copy_from_slice(&source.port.to_be_bytes());
                                    packet[16..20].copy_from_slice(&sock_addr.ip().octets());
                                    packet[22..24].copy_from_slice(&sock_addr.port().to_be_bytes());

                                    if let Err(error) = socket.send_to(&packet, &addr) {
                                        eprintln!(
                                            "sender: {}: failed to send with {}",
                                            interface.name, error
                                        );
                                    }
                                }
                            }
                        } else {
                            packet[12..16].copy_from_slice(&interface.ip.octets());
                            socket.set_header_included_v4(true)?;
                            let addr =
                                SockAddr::from(SocketAddr::V4(SocketAddrV4::new(dst, dst_port)));
                            if let Err(error) = socket.send_to(&packet, &addr.into()) {
                                eprintln!(
                                    "sender: {}: failed to send with {}",
                                    interface.name, error
                                );
                            }
                        }

                        socket.set_mark(0)?;

                        interface.send_packets.fetch_add(1, Ordering::Relaxed);
                        interface
                            .send_bytes
                            .fetch_add(packet.len() as u64, Ordering::Relaxed);
                    }

                    id += 1;
                }
            }
        }

        msg.set_verdict(Verdict::Drop);
        queue.verdict(msg)?;

        stats.send_total.fetch_add(1, Ordering::Relaxed);
        stats
            .send_bytes
            .fetch_add(packet.len() as u64, Ordering::Relaxed);
        stats.send_current.store(id as u64, Ordering::Relaxed);
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
