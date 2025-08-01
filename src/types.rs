use std::{
    marker::{Send, Sync},
    net::{IpAddr, Ipv4Addr, SocketAddrV4},
    sync::{
        Arc, RwLock,
        atomic::{AtomicBool, AtomicU64},
    },
    time::Instant,
};

use clap::{Parser, arg, command};
use o2o::o2o;
use socket2::SockAddr;

use crate::utils::interface_ip;

#[derive(Clone, Parser, Debug)]
#[command(author, version, about)]
pub struct Cli {
    #[arg(long, default_value = "false")]
    pub server: bool,

    #[arg(long, action, default_value = "false")]
    pub silent: bool,

    /// Receiver
    /// NFQUEUE socket number
    #[arg(long, default_value = "1")]
    pub recv_queue: u16,

    /// Maximum number of packets in the queue
    #[arg(long, default_value = "1310712")] // ~128MB
    pub recv_queue_max_len: u32,

    /// Timeout for receiving packet in milliseconds
    #[arg(long, default_value = "100")]
    pub timeout: u128,

    /// Sender
    /// Tunnel name
    #[arg(long, default_value = "0")]
    pub queue: u16,

    /// Maximum number of packets in the queue
    #[arg(long, default_value = "1310712")] // ~128MB
    pub queue_max_len: u32,

    /// Ports to intercept
    #[arg(long, num_args = 0..)]
    pub ports: Option<Vec<u16>>,

    // Firewall mark for packets
    #[arg(long, default_value = "1970170112")] // 0x756E6900..+N (interfaces)
    pub fwmark: u32,

    // Routing table to use for the sender
    #[arg(long, default_value = "230")]
    pub table: u32,

    /// Sender interfaces (e.g., wg0 wg1)
    #[arg(long, required = true, num_args = 1..)]
    pub interfaces: Vec<String>,

    /// SNAT address that should the packets appear to be sent FROM
    #[arg(long)]
    pub snat: Option<SocketAddrV4>,

    /// Extra features, might be removed in the future

    // Remote address
    #[arg(long)]
    pub remote: Option<SocketAddrV4>,

    // Secret used for HMAC whitelisting
    #[arg(long)]
    pub secret: Option<String>,
}

#[derive(o2o)]
#[from_owned(Cli)]
pub struct SenderConfiguration {
    pub server: bool,
    pub queue: u16,
    pub fwmark: u32,
    pub queue_max_len: u32,
    pub ports: Option<Vec<u16>>,

    pub snat: Option<SocketAddrV4>,
}

#[derive(o2o)]
#[from_owned(Cli)]
pub struct ReceiverConfiguration {
    pub server: bool,
    pub ports: Option<Vec<u16>>,
    pub recv_queue: u16,
    pub recv_queue_max_len: u32,
    pub timeout: u128,

    pub snat: Option<SocketAddrV4>,
}

#[derive(o2o)]
#[from_owned(Cli)]
pub struct WhitelistConfiguration {
    pub server: bool,
    pub remote: Option<SocketAddrV4>,
    pub secret: Option<String>,
}

#[derive(o2o)]
#[from_owned(Cli)]
pub struct StatusConfiguration {
    pub server: bool,
    pub interfaces: Vec<String>,
}

pub struct Interface {
    pub name: String,
    pub ip: Ipv4Addr,
    pub socket: RwLock<socket2::Socket>,

    pub send_packets: AtomicU64,
    pub send_bytes: AtomicU64,
}

impl Interface {
    pub fn raw(name: String) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::from(libc::SOCK_RAW),
            Some(socket2::Protocol::from(libc::IPPROTO_RAW)),
        )?;
        socket.bind_device(Some(name.as_bytes()))?;
        socket.set_header_included_v4(true)?;
        Ok(Self {
            ip: interface_ip(name.as_str()).unwrap(),
            name,
            socket: RwLock::new(socket),
            send_packets: AtomicU64::new(0),
            send_bytes: AtomicU64::new(0),
        })
    }

    pub fn udp(name: String) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::from(libc::SOCK_DGRAM),
            Some(socket2::Protocol::from(libc::IPPROTO_UDP)),
        )?;
        socket.bind_device(Some(name.as_bytes()))?;
        Ok(Self {
            ip: interface_ip(name.as_str()).unwrap(),
            name,
            socket: RwLock::new(socket),
            send_packets: AtomicU64::new(0),
            send_bytes: AtomicU64::new(0),
        })
    }
}

impl Clone for Interface {
    fn clone(&self) -> Self {
        Self {
            name: self.name.clone(),
            ip: self.ip,
            socket: RwLock::new(self.socket.read().unwrap().try_clone().unwrap()),
            send_packets: AtomicU64::new(0),
            send_bytes: AtomicU64::new(0),
        }
    }
}

pub struct Source {
    pub ip: Ipv4Addr,
    pub port: u16,
    pub socket: RwLock<socket2::Socket>,
    pub addrs: Vec<SockAddr>,
}

impl Source {
    pub fn new(
        ip: Ipv4Addr,
        port: u16,
        snat: SocketAddrV4,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::from(libc::SOCK_RAW),
            Some(socket2::Protocol::from(libc::IPPROTO_UDP)),
        )?;
        socket.bind(&SockAddr::from(snat))?;
        Ok(Self {
            ip,
            port,
            socket: RwLock::new(socket),
            addrs: vec![],
        })
    }

    pub fn attach(&mut self, ip: SockAddr) -> &mut Self {
        if !self.addrs.contains(&ip) {
            self.addrs.push(ip);
        }

        self
    }
}

pub struct Stats {
    pub start_time: Instant,

    pub send_ready: AtomicBool,
    pub send_total: AtomicU64,
    pub send_current: AtomicU64,
    pub send_bytes: AtomicU64,

    pub recv_ready: AtomicBool,
    pub recv_total: AtomicU64,
    pub recv_dropped: AtomicU64,
    pub recv_current: AtomicU64,
    pub recv_bytes: AtomicU64,
    pub recv_out_of_order: AtomicU64,

    pub whitelisted: Arc<RwLock<Vec<IpAddr>>>,
}

impl Stats {
    pub fn new() -> Self {
        Self {
            start_time: Instant::now(),

            send_ready: AtomicBool::new(false),
            send_total: AtomicU64::new(0),
            send_current: AtomicU64::new(0),
            send_bytes: AtomicU64::new(0),

            recv_ready: AtomicBool::new(false),
            recv_total: AtomicU64::new(0),
            recv_current: AtomicU64::new(0),
            recv_dropped: AtomicU64::new(0),
            recv_bytes: AtomicU64::new(0),
            recv_out_of_order: AtomicU64::new(0),

            whitelisted: Arc::new(RwLock::new(Vec::new())),
        }
    }
}
