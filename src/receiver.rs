use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use nfq::{Queue, Verdict};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::udp::MutableUdpPacket;
use pnet::packet::{MutablePacket, Packet};

use crate::types::ReceiverConfiguration;
use crate::utils::CommandGuard;

enum MessageStatus {
    Processed(u32),
    Invalid,
}

pub fn listen(
    configuration: ReceiverConfiguration,
    running: Arc<AtomicBool>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let _rules = iptables(&configuration);

    let mut queue = Queue::open()?;
    queue.bind(configuration.recv_queue)?;
    queue.set_queue_max_len(configuration.recv_queue, configuration.recv_queue_max_len)?;
    queue.set_nonblocking(true);

    let mut map: BTreeMap<u32, (nfq::Message, MessageStatus)> = BTreeMap::new();
    let mut current: u32 = 0;

    let last = Instant::now();

    println!("receiver: listening on queue {}", configuration.recv_queue);
    while running.load(Ordering::Relaxed) {
        let mut msg = match queue.recv() {
            Ok(msg) => msg,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(10));
                continue;
            }
            Err(error) => {
                println!("receiver: {}", error);
                break;
            }
        };

        // Pretty-print the message
        let status = process_message(&mut msg);

        match status {
            MessageStatus::Processed(id) if current == 0 || id == current => {
                if let Some((mut buffered, _)) = map.remove(&id) {
                    buffered.set_verdict(Verdict::Drop);
                    queue.verdict(buffered)?;
                }

                msg.set_verdict(Verdict::Accept);

                queue.verdict(msg)?;
                current = id + 1;
            }
            // Replace buffered message if it's newer or set new current
            MessageStatus::Processed(id) if id > current => {
                if Instant::now().duration_since(last).as_millis() > configuration.timeout {
                    if let Some((first, _)) = map.first_key_value() {
                        println!("receiver: timeout, skipping until {}", first);
                        current = *first;
                    }
                }

                if let Some((mut buffered, _)) = map.insert(id, (msg, status)) {
                    buffered.set_verdict(Verdict::Drop);
                    queue.verdict(buffered)?;
                };
            }
            // Already processed, drop it
            MessageStatus::Processed(id) if id < current => {
                msg.set_verdict(Verdict::Drop);
                queue.verdict(msg)?;
            }
            // Invalid, drop it
            MessageStatus::Invalid => {
                msg.set_verdict(Verdict::Drop);
                queue.verdict(msg)?;
            }
            MessageStatus::Processed(_) => unreachable!("Should have matched above"),
        }

        // Drain the queue of buffered messages if possible
        while let Some((_, (mut msg, status))) = map.remove_entry(&current) {
            match status {
                MessageStatus::Processed(id) => {
                    msg.set_verdict(Verdict::Accept);

                    queue.verdict(msg)?;
                    current = id + 1;
                }
                MessageStatus::Invalid => {
                    msg.set_verdict(Verdict::Drop);
                    queue.verdict(msg)?;
                }
            }
        }
    }

    Ok(())
}

fn process_message(msg: &mut nfq::Message) -> MessageStatus {
    let mut id = None;

    let mut payload = msg.get_payload().to_vec();
    if let Some(ip_packet) = Ipv4Packet::new(&payload)
        && ip_packet.get_next_level_protocol() == IpNextHeaderProtocols::Udp
    {
        let ip_header_len = (ip_packet.get_header_length() * 4) as usize;
        let (ip_buf, udp_packet_buf) = payload.split_at_mut(ip_header_len);

        const UDP_HEADER: u16 = 8;
        if let Some(mut udp_packet) = MutableUdpPacket::new(udp_packet_buf) {
            // Extract the ID
            id = Some(u32::from_be_bytes(
                udp_packet.payload()[udp_packet.payload().len() - 4..]
                    .try_into()
                    .unwrap(),
            ));

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
            }
        }
    }

    if let Some(id_value) = id {
        msg.set_payload(payload);
        return MessageStatus::Processed(id_value);
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
                            "-t mangle -A INPUT -p udp --sport {} -j NFQUEUE --queue-num {}",
                            port, configuration.recv_queue
                        ))
                        .cleanup(format!(
                            "-t mangle -D INPUT -p udp --sport {} -j NFQUEUE --queue-num {}",
                            port, configuration.recv_queue
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
                            "-t mangle -A INPUT -p udp --dport {} -j NFQUEUE --queue-num {}",
                            port, configuration.recv_queue
                        ))
                        .cleanup(format!(
                            "-t mangle -D INPUT -p udp --dport {} -j NFQUEUE --queue-num {}",
                            port, configuration.recv_queue
                        )),
                );
            }
        }
    }

    rules
}
