use nfq::{Queue, Verdict};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::udp::MutableUdpPacket;
use pnet::packet::{MutablePacket, Packet};
use std::collections::BTreeMap;

enum MessageStatus {
    Processed(u32),
    Invalid,
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

fn main() {
    let mut queue = Queue::open().expect("Failed to open NFQUEUE 0");
    queue.bind(0).expect("Failed to bind to NFQUEUE 0");
    queue
        .set_queue_max_len(0, 65535 * 4) // ~256MB
        .expect("Failed to set queue max length");

    let mut map: BTreeMap<u32, (nfq::Message, MessageStatus)> = BTreeMap::new();
    let mut current: u32 = 0;

    loop {
        let mut msg = queue
            .recv()
            .expect("Failed to receive message from NFQUEUE");
        println!("Received message with ID: {:?}", msg);

        let status = process_message(&mut msg);
        match status {
            MessageStatus::Processed(id) if current == 0 || id == current => {
                if let Some((mut buffered, _)) = map.remove(&id) {
                    buffered.set_verdict(Verdict::Drop);
                    queue.verdict(buffered).expect("Failed to set verdict");
                }

                msg.set_verdict(Verdict::Accept);
                queue.verdict(msg).expect("Failed to set verdict");
                current = id + 1;
            }
            // Replace buffered message if it's newer or set new current
            MessageStatus::Processed(id) if id > current => {
                if let Some((mut buffered, _)) = map.insert(id, (msg, status)) {
                    buffered.set_verdict(Verdict::Drop);
                    queue.verdict(buffered).expect("Failed to set verdict");
                };
            }
            // Already processed, drop it
            MessageStatus::Processed(id) if id < current => {
                msg.set_verdict(Verdict::Drop);
                queue.verdict(msg).expect("Failed to set verdict");
            }
            // Invalid, drop it
            MessageStatus::Invalid => {
                msg.set_verdict(Verdict::Drop);
                queue.verdict(msg).expect("Failed to set verdict");
            }
            MessageStatus::Processed(_) => unreachable!("Should have matched above"),
        }

        // Drain the queue of buffered messages if possible
        while let Some((_, (mut msg, status))) = map.remove_entry(&current) {
            match status {
                MessageStatus::Processed(id) => {
                    println!("Processed buffered: {}", id);
                    msg.set_verdict(Verdict::Accept);
                    queue.verdict(msg).expect("failed to set verdict ");
                    current = id + 1;
                }
                MessageStatus::Invalid => {
                    msg.set_verdict(Verdict::Drop);
                    queue.verdict(msg).expect("failed to set verdict ");
                }
            }
        }
    }
}
