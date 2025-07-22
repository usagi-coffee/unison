use crate::Cli;

use std::io::{self, Read};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::unix::io::AsRawFd;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use libc::{IP_HDRINCL, IPPROTO_IP, SO_BINDTODEVICE, SOL_SOCKET, setsockopt};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tun::{Configuration, Device};

pub struct SenderConfiguration {
    tun: Option<String>,
    interfaces: Vec<String>,
}

pub struct Tunnel {
    dev: tun::platform::Device,
    iface: String,
    custom: bool,
}

pub fn listen(
    configuration: SenderConfiguration,
    running: Arc<AtomicBool>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut tun = Tunnel::new(&configuration)?;

    // Create one raw socket per interface
    let mut outputs: Vec<(String, Socket)> = Vec::new();
    for ifname in &configuration.interfaces {
        println!("sender: binding to interface {}", ifname);
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

    println!("sender: listening for packets on {}", tun.dev.name());
    while running.load(Ordering::Relaxed) {
        let n = tun.dev.read(&mut buf)?;
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

        // Increment the ID for the next packet
        id = id + 1;

        for (name, sock) in &outputs {
            if let Err(error) = sock.send_to(&tagged, &dst) {
                eprintln!("sender: {}: failed to send with {}", name, error);
            }
        }
    }

    Ok(())
}

impl Tunnel {
    pub fn new(
        configuration: &SenderConfiguration,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let custom = configuration.tun.is_some();
        let iface = {
            if let Some(name) = &configuration.tun {
                name.clone()
            } else {
                let interfaces = interfaces();
                let n = 0;
                loop {
                    let name = format!("tun{}", n);
                    if !interfaces.contains(&name) {
                        break name;
                    }
                }
            }
        };

        if !custom {
            Command::new("ip")
                .args(vec!["tuntap", "add", "dev", iface.as_str(), "mode", "tun"])
                .status()
                .expect("Failed to execute `ip` command");

            Command::new("ip")
                .args(vec!["addr", "add", "10.10.1.0/24", "dev", iface.as_str()])
                .status()
                .expect("Failed to execute `ip` command");

            Command::new("ip")
                .args(vec!["link", "set", iface.as_str(), "up"])
                .status()
                .expect("Failed to execute `ip` command");

            println!("sender: created tunnel interface {}", iface);
        } else {
            println!("sender: attaching to tunnel interface {}", iface);
        }

        let dev = tun::create(Configuration::default().name(&iface).layer(tun::Layer::L3))?;
        Ok(Tunnel { dev, custom, iface })
    }
}

impl Drop for Tunnel {
    fn drop(&mut self) {
        if !self.custom {
            println!("sender: deleting tunnel interface {}", self.iface);

            Command::new("ip")
                .args(vec!["link", "delete", self.iface.as_str()])
                .status()
                .expect("Failed to execute `ip` command");
        }
    }
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

fn interfaces() -> Vec<String> {
    let mut interfaces = vec![];

    let output = Command::new("ip")
        .args(&["-o", "link", "show"])
        .output()
        .expect("Failed to execute ip");

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        if let Some(field) = line.splitn(3, ':').nth(1) {
            interfaces.push(field.replace(char::is_whitespace, ""));
        }
    }

    interfaces
}

impl From<&Cli> for SenderConfiguration {
    fn from(cli: &Cli) -> Self {
        SenderConfiguration {
            tun: cli.tun.clone(),
            interfaces: cli.interfaces.clone(),
        }
    }
}
