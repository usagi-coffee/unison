use clap::{Parser, arg, command};
use std::io::{self, Read};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::unix::io::AsRawFd;

use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tun::{Configuration, Device};

use libc::{IP_HDRINCL, IPPROTO_IP, SO_BINDTODEVICE, SOL_SOCKET, setsockopt};

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Cli {
    /// Output interfaces (e.g., wg0 wg1)
    #[arg(required = true)]
    interfaces: Vec<String>,
}

fn bind_to_device(sock: &Socket, ifname: &str) -> io::Result<()> {
    let fd = sock.as_raw_fd();
    let ifname_cstr = std::ffi::CString::new(ifname).unwrap();
    let res = unsafe {
        setsockopt(
            fd,
            SOL_SOCKET,
            SO_BINDTODEVICE,
            ifname_cstr.as_ptr() as *const _,
            ifname.len() as u32,
        )
    };
    if res != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn set_header_included(sock: &Socket) -> io::Result<()> {
    let fd = sock.as_raw_fd();
    let hdrincl: i32 = 1;
    let res = unsafe {
        setsockopt(
            fd,
            IPPROTO_IP,
            IP_HDRINCL,
            &hdrincl as *const _ as *const _,
            std::mem::size_of::<i32>() as u32,
        )
    };
    if res != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn main() -> io::Result<()> {
    let cli = Cli::parse();

    let mut config = Configuration::default();
    config.name("tun0").layer(tun::Layer::L3);
    let mut dev = tun::create(&config).expect("Failed to create TUN device");
    println!("Attached to {}", dev.name());

    // Create one raw socket per interface
    let mut outputs: Vec<(String, Socket)> = Vec::new();
    for ifname in &cli.interfaces {
        let sock = Socket::new(
            Domain::IPV4,
            Type::from(libc::SOCK_RAW),
            Some(Protocol::from(libc::IPPROTO_RAW)),
        )?;
        bind_to_device(&sock, ifname)?;
        set_header_included(&sock)?;
        outputs.push((ifname.to_owned(), sock));
    }

    let mut id = 0u32;
    let mut buf = [0u8; 1504];
    loop {
        let n = dev.read(&mut buf)?;
        let packet = &buf[..n];

        // Filter out non-IPv4 packets
        if packet[0] >> 4 != 4 {
            continue;
        }

        // Destination IP is at offset 16..20 in IPv4 header
        let dst_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
        let dst = SockAddr::from(SocketAddr::new(IpAddr::V4(dst_ip), 0));

        let mut tagged: Vec<u8> = packet.into();
        tagged.extend_from_slice(&id.to_be_bytes());

        id = id + 1;

        for (name, sock) in &outputs {
            if let Err(e) = sock.send_to(&tagged, &dst) {
                eprintln!("Error sending to {}: {}", name, e);
            }
        }
    }
}
