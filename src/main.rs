use clap::{Parser, arg, command};
use receiver::ReceiverConfiguration;
use sender::SenderConfiguration;

mod receiver;
mod sender;

#[derive(Parser, Debug)]
#[command(author, version, about)]
pub struct Cli {
    /// Receiver
    /// NFQUEUE socket number
    #[arg(long, default_value = "0")]
    queue: u16,

    /// Maximum number of packets in the queue
    #[arg(long, default_value = "1310712")] // ~128MB
    queue_max_len: u32,

    /// Sender
    /// Tunnel name
    #[arg(long, default_value = "tun0")]
    tun: String,

    /// Sender interfaces (e.g., wg0 wg1)
    #[arg(long, required = true, num_args = 1..)]
    interfaces: Vec<String>,
}

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let cli = Cli::parse();

    std::thread::scope(|scope| {
        let (tx, rx) = std::sync::mpsc::channel();

        let receiver_config = ReceiverConfiguration::from(&cli);
        let receiver_tx = tx.clone();

        let sender_config = SenderConfiguration::from(&cli);
        let sender_tx = tx.clone();

        scope.spawn(move || receiver_tx.send(receiver::listen(receiver_config)));
        scope.spawn(move || sender_tx.send(sender::listen(sender_config)));

        rx.recv()?
    })?;

    Ok(())
}
