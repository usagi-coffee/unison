use std::{
    net::IpAddr,
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicU64},
    },
    time::Instant,
};

use clap::{Parser, arg, command};
use o2o::o2o;

#[derive(Clone, Parser, Debug)]
#[command(author, version, about)]
pub struct Cli {
    #[arg(long, default_value = "false")]
    pub server: bool,

    // Password used for the remote
    #[arg(
        long,
        default_value = "f9e5996d942a307decbd7d43f20eb4a85b80e1e044f2cfa33f5110f01a4d52b0"
    )]
    pub secret: String,

    #[arg(long)]
    pub remote: Option<String>,

    #[arg(long, action, default_value = "false")]
    pub silent: bool,

    // Whitelist service port
    #[arg(long, default_value = "7566")]
    pub port: u16,

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
}

#[derive(o2o)]
#[from_owned(Cli)]
pub struct SenderConfiguration {
    pub server: bool,
    pub queue: u16,
    pub fwmark: u32,
    pub queue_max_len: u32,
    pub interfaces: Vec<String>,
    pub ports: Option<Vec<u16>>,
}

#[derive(o2o)]
#[from_owned(Cli)]
pub struct ReceiverConfiguration {
    pub server: bool,
    pub ports: Option<Vec<u16>>,
    pub recv_queue: u16,
    pub recv_queue_max_len: u32,
    pub timeout: u128,
}

#[derive(o2o)]
#[from_owned(Cli)]
pub struct WhitelistConfiguration {
    pub server: bool,
    pub remote: Option<String>,
    pub port: u16,
    pub secret: String,
    pub interfaces: Vec<String>,
}

#[derive(o2o)]
#[from_owned(Cli)]
pub struct StatusConfiguration {
    pub server: bool,
    pub interfaces: Vec<String>,
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

    pub whitelisted: Mutex<Vec<IpAddr>>,
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

            whitelisted: Mutex::new(Vec::new()),
        }
    }
}
