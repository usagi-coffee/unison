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

    // Whitelist service port
    #[arg(long, default_value = "7566")]
    pub port: u16,

    /// Receiver
    /// NFQUEUE socket number
    #[arg(long, default_value = "0")]
    pub queue: u16,

    /// Maximum number of packets in the queue
    #[arg(long, default_value = "1310712")] // ~128MB
    pub queue_max_len: u32,

    /// Timeout for receiving packet in milliseconds
    #[arg(long, default_value = "100")]
    pub timeout: u128,

    /// Sender
    /// Tunnel name
    #[arg(long)]
    pub tun: Option<String>,

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
    pub fwmark: u32,
    pub table: u32,
    pub interfaces: Vec<String>,
    pub ports: Option<Vec<u16>>,
    pub tun: Option<String>,
}

#[derive(o2o)]
#[from_owned(Cli)]
pub struct ReceiverConfiguration {
    pub server: bool,
    pub ports: Option<Vec<u16>>,
    pub queue: u16,
    pub queue_max_len: u32,
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
