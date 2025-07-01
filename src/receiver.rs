use crate::Cli;

use std::collections::BTreeMap;

use nfq::{Queue, Verdict};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::udp::MutableUdpPacket;
use pnet::packet::{MutablePacket, Packet};

pub struct ReceiverConfiguration {
    socket: u16,
    max_len: u32,
}

enum MessageStatus {
    Processed(u32),
    Invalid,
}

pub fn listen(
    configuration: ReceiverConfiguration,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut queue = Queue::open()?;
    queue.bind(configuration.socket)?;
    queue.set_queue_max_len(0, configuration.max_len)?;

    let mut map: BTreeMap<u32, (nfq::Message, MessageStatus)> = BTreeMap::new();
    let mut current: u32 = 0;

    println!("receiver: listening on queue {}", configuration.socket);
    loop {
        let mut msg = queue.recv()?;

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
}

fn process_message(msg: &mut nfq::Message) -> MessageStatus {
    let mut payload = msg.get_payload().to_vec();
    if let Some(ip_packet) = Ipv4Packet::new(&payload)
        && ip_packet.get_next_level_protocol() == IpNextHeaderProtocols::Udp
    {
        let ip_header_len = (ip_packet.get_header_length() * 4) as usize;
        let (ip_buf, udp_packet_buf) = payload.split_at_mut(ip_header_len);

        const UDP_HEADER: usize = 8;
        if let Some(mut udp_packet) = MutableUdpPacket::new(udp_packet_buf) {
            let id = u32::from_be_bytes(
                udp_packet.payload()[udp_packet.payload().len() - 4..]
                    .try_into()
                    .unwrap(),
            );

            let len = udp_packet.get_length() as usize - UDP_HEADER;
            let full_packet = udp_packet.packet_mut();
            let (_, rest) = full_packet.split_at_mut(UDP_HEADER);

            for b in &mut rest[len..] {
                *b = 0;
            }

            let new_udp_len = UDP_HEADER + len - 4;
            udp_packet.set_length(new_udp_len as u16);
            udp_packet.set_checksum(0);

            if let Some(mut ip_packet) = MutableIpv4Packet::new(ip_buf) {
                let new_ip_len = (ip_header_len + new_udp_len) as u16;
                ip_packet.set_total_length(new_ip_len);
                ip_packet.set_checksum(0);
                return MessageStatus::Processed(id);
            }
        }
    }

    MessageStatus::Invalid
}

impl From<&Cli> for ReceiverConfiguration {
    fn from(cli: &Cli) -> Self {
        ReceiverConfiguration {
            socket: cli.queue.clone(),
            max_len: cli.queue_max_len.clone(),
        }
    }
}
