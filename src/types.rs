use clap::{Parser, arg, command};
use o2o::o2o;

#[derive(Clone, Parser, Debug)]
#[command(author, version, about)]
pub struct Cli {
    #[arg(long, default_value = "false")]
    pub server: bool,

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

pub struct CommandGuard<'a> {
    command: &'a str,
    cleanup: Option<Box<dyn FnOnce() + 'a>>,
    server: bool,
}

impl<'a> CommandGuard<'a> {
    pub fn new(command: &'a str) -> Self {
        let guard = CommandGuard {
            command,
            server: false,
            cleanup: None,
        };
        guard
    }

    pub fn server(command: &'a str) -> Self {
        let guard = CommandGuard {
            command,
            server: true,
            cleanup: None,
        };
        guard
    }

    pub fn call(self, args: String) -> Self {
        println!(
            "[+{}] {} {}",
            if self.server { "!" } else { "" },
            self.command,
            &args
        );

        let status = std::process::Command::new(self.command)
            .args(args.split(' '))
            .stdout(std::process::Stdio::null())
            .status()
            .expect("Failed to execute command");

        assert!(status.success(), "Command failed");

        self
    }

    pub fn cleanup(mut self, args: String) -> Self {
        let command = self.command.to_owned();

        self.cleanup = Some(Box::new(move || {
            println!(
                "[-{}] {} {}",
                if self.server { "!" } else { "" },
                command,
                args
            );

            let status = std::process::Command::new(command)
                .args(args.split(' '))
                .status()
                .expect("Failed to execute command");

            assert!(status.success(), "Command failed");
        }));

        self
    }
}

impl<'a> Drop for CommandGuard<'a> {
    fn drop(&mut self) {
        if let Some(cleanup) = self.cleanup.take() {
            cleanup();
        }
    }
}
