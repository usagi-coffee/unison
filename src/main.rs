use std::process::Command;
use std::sync::atomic::Ordering;
use std::sync::{Arc, atomic::AtomicBool};

use clap::Parser;

use types::{Cli, ReceiverConfiguration, SenderConfiguration, WhitelistConfiguration};
use utils::CommandGuard;

mod receiver;
mod sender;
mod types;
mod utils;
mod whitelist;

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if sudo::check() != sudo::RunningAs::Root {
        panic!("This program must be run as root");
    }

    let cli = Cli::parse();

    forwarding();
    netfilter();

    let running = Arc::new(AtomicBool::new(true));

    let running_tx = running.clone();
    ctrlc::set_handler(move || {
        println!("");
        println!("Received CTRL+C, stopping...");
        running_tx.store(false, Ordering::Relaxed);
    })?;

    std::thread::scope(|scope| {
        let (tx, rx) = std::sync::mpsc::channel();

        let receiver_running = running.clone();
        let receiver_config = ReceiverConfiguration::from(cli.clone());
        let receiver_tx = tx.clone();

        let sender_running = running.clone();
        let sender_config = SenderConfiguration::from(cli.clone());
        let sender_tx = tx.clone();

        let whitelist_running = running.clone();
        let whitelist_config = WhitelistConfiguration::from(cli.clone());
        let whitelist_tx = tx.clone();

        scope.spawn(move || {
            let running = receiver_running.clone();
            let result = receiver_tx.send(receiver::listen(receiver_config, receiver_running));
            running.store(false, Ordering::Relaxed);
            result
        });

        scope.spawn(move || {
            let running = sender_running.clone();
            let result = sender_tx.send(sender::listen(sender_config, sender_running));
            running.store(false, Ordering::Relaxed);
            result
        });

        scope.spawn(move || {
            let running = running.clone();
            let result = whitelist_tx.send(whitelist::listen(whitelist_config, whitelist_running));
            running.store(false, Ordering::Relaxed);
            result
        });

        rx.recv()?
    })?;

    Ok(())
}

pub fn forwarding<'a>() -> CommandGuard<'a> {
    CommandGuard::new("sysctl").call("-w net.ipv4.ip_forward=1".into())
}

pub fn netfilter() {
    let status = Command::new("modprobe")
        .arg("nfnetlink_queue")
        .status()
        .expect("Failed to load netfilter_queue module");

    assert!(status.success(), "Failed to load netfilter_queue module");
}
