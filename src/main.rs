use std::collections::HashMap;
use std::process::Command;
use std::sync::Mutex;
use std::sync::atomic::Ordering;
use std::sync::{Arc, atomic::AtomicBool};

use clap::Parser;

use types::{
    Cli, Interface, ReceiverConfiguration, SenderConfiguration, Stats, StatusConfiguration,
    WhitelistConfiguration,
};
use utils::CommandGuard;

mod receiver;
mod sender;
mod status;
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
    let _interfaces = interfaces(&cli);

    let intefaces = Arc::new(
        cli.interfaces
            .iter()
            .map(|name| Interface::raw(name.clone()))
            .collect::<Result<Vec<_>, _>>()?,
    );
    let sources = Arc::new(Mutex::new(HashMap::new()));
    let running = Arc::new(AtomicBool::new(true));
    let stats = Arc::new(Stats::new());

    let running_tx = running.clone();
    ctrlc::set_handler(move || {
        println!("");
        println!("Received CTRL+C, stopping...");
        running_tx.store(false, Ordering::Relaxed);
    })?;

    std::thread::scope(|scope| {
        let (tx, rx) = std::sync::mpsc::channel();

        let receiver_running = running.clone();
        let receiver_stats = stats.clone();
        let receiver_interfaces = intefaces.clone();
        let receiver_sources = sources.clone();
        let receiver_config = ReceiverConfiguration::from(cli.clone());
        let receiver_tx = tx.clone();

        let sender_running = running.clone();
        let sender_stats = stats.clone();
        let sender_interfaces = intefaces.clone();
        let sender_sources = sources.clone();
        let sender_config = SenderConfiguration::from(cli.clone());
        let sender_tx = tx.clone();

        let whitelist_running = running.clone();
        let whitelist_stats = stats.clone();
        let whitelist_interfaces = intefaces.clone();
        let whitelist_sources = sources.clone();
        let whitelist_config = WhitelistConfiguration::from(cli.clone());
        let whitelist_tx = tx.clone();

        let status_running = running.clone();
        let status_config = StatusConfiguration::from(cli.clone());
        let status_tx = tx.clone();

        scope.spawn(move || {
            let running = receiver_running.clone();
            let result = receiver_tx.send(receiver::listen(
                receiver_config,
                receiver_interfaces,
                receiver_sources,
                receiver_running,
                receiver_stats,
            ));
            running.store(false, Ordering::Relaxed);
            result
        });

        scope.spawn(move || {
            let running = sender_running.clone();
            let result = sender_tx.send(sender::listen(
                sender_config,
                sender_interfaces,
                sender_sources,
                sender_running,
                sender_stats,
            ));
            running.store(false, Ordering::Relaxed);
            result
        });

        scope.spawn(move || {
            let running = running.clone();
            let result = whitelist_tx.send(whitelist::listen(
                whitelist_config,
                whitelist_interfaces,
                whitelist_sources,
                whitelist_running,
                whitelist_stats,
            ));
            running.store(false, Ordering::Relaxed);
            result
        });

        if !cli.silent {
            scope.spawn(move || {
                let running = status_running.clone();
                let result = status_tx.send(status::listen(status_config, status_running, stats));
                running.store(false, Ordering::Relaxed);
                result
            });
        }

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

pub fn interfaces(cli: &Cli) -> Vec<CommandGuard> {
    let mut rules = Vec::new();
    if let Some(snat) = cli.snat {
        rules.push(
            CommandGuard::new("ip")
                .call(format!("addr add {}/32 dev lo", snat))
                .cleanup(format!("addr del {}/32 dev lo", snat)),
        );
    }

    rules
}
