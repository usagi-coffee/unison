use std::net::{SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use nfq::{Queue, Verdict};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::udp::MutableUdpPacket;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use crate::types::SenderConfiguration;
use crate::utils::{CommandGuard, bind_to_device, set_header_included, set_mark};

pub fn listen(
    configuration: SenderConfiguration,
    running: Arc<AtomicBool>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let _rules = iptables(&configuration);

    let mut queue = Queue::open()?;
    queue.bind(configuration.queue)?;
    queue.set_queue_max_len(configuration.queue, configuration.queue_max_len)?;

    queue.set_nonblocking(true);

    let mut id = 0u32;

    println!("sender: listening for packets");
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

                    for ifname in &configuration.interfaces {
                        let socket = Socket::new(
                            Domain::IPV4,
                            Type::from(libc::SOCK_RAW),
                            Some(Protocol::from(libc::IPPROTO_RAW)),
                        )?;
                        bind_to_device(&socket, &ifname)?;
                        set_header_included(&socket)?;
                        set_mark(&socket, configuration.fwmark)?;

                        let dst_sock =
                            SockAddr::from(SocketAddr::V4(SocketAddrV4::new(dst, dst_port)));

                        if let Err(error) = socket.send_to(&packet, &dst_sock.into()) {
                            eprintln!("sender: {}: failed to send with {}", ifname, error);
                        }
                    }

                    id += 1;
                }
            }

            msg.set_verdict(Verdict::Drop);
            queue.verdict(msg)?;
        }
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
