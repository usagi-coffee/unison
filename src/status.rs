use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use crate::{
    types::{Interface, Source, Stats, StatusConfiguration},
    utils::tc_backlog,
};

use indicatif::{MultiProgress, ProgressBar};
use parking_lot::RwLock;
use std::{thread, time::Duration};

pub fn listen(
    progress: Arc<MultiProgress>,
    configuration: StatusConfiguration,
    interfaces: Arc<Vec<Interface>>,
    sources: Arc<RwLock<HashMap<u16, Source>>>,
    running: Arc<AtomicBool>,
    stats: Arc<Stats>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let extra = progress.add(ProgressBar::new_spinner());
    let tx = progress.add(ProgressBar::new_spinner());
    for interface in interfaces.iter() {
        interface
            .send_progress
            .get_or_init(|| Arc::new(progress.add(ProgressBar::new_spinner())));
    }

    let rx = progress.add(ProgressBar::new_spinner());
    tx.enable_steady_tick(Duration::from_millis(100));
    rx.enable_steady_tick(Duration::from_millis(100));
    extra.enable_steady_tick(Duration::from_millis(100));

    let mut send_last_bytes = 0;
    let mut send_peak_throughput = 0.0;

    let mut recv_last_bytes = 0;
    let mut recv_peak_throughput = 0.0;

    while running.load(Ordering::Relaxed) {
        if stats.send_ready.load(Ordering::Relaxed) && stats.recv_ready.load(Ordering::Relaxed) {
            break;
        }

        thread::sleep(Duration::from_millis(100));
    }

    while running.load(Ordering::Relaxed) {
        let elapsed = stats.start_time.elapsed();
        let uptime = format!(
            "{:02}:{:02}:{:02}",
            elapsed.as_secs() / 3600,
            (elapsed.as_secs() / 60) % 60,
            elapsed.as_secs() % 60
        );

        let send_bytes = stats.send_bytes.load(Ordering::Relaxed);
        let send_total = (send_bytes * 8) / 1_000_000;
        let send_throughput = ((send_bytes - send_last_bytes) * 8) as f64 / 1_000_000.0;
        if send_throughput > send_peak_throughput {
            send_peak_throughput = send_throughput;
        }

        let recv_bytes = stats.recv_bytes.load(Ordering::Relaxed);
        let recv_total = (recv_bytes * 8) / 1_000_000;
        let recv_throughput = ((recv_bytes - recv_last_bytes) * 8) as f64 / 1_000_000.0;
        if recv_throughput > recv_peak_throughput {
            recv_peak_throughput = recv_throughput;
        }

        let whitelisted = {
            stats
                .whitelisted
                .read()
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        };

        extra.set_message(format!(
            "🕒 {} | 🌐 {} | {}",
            uptime,
            configuration.interfaces.join(", "),
            if configuration.server {
                format!("✅ {}", whitelisted)
            } else {
                "".into()
            }
        ));

        tx.set_message(format!(
            "[TX] ---------------- {:.2} ({:.2}) Mbps | 🧮 {:.3} MB | 📦 {:>6} |",
            send_throughput,
            send_peak_throughput,
            send_total,
            format!("{}", stats.send_current.load(Ordering::Relaxed)),
        ));

        for interface in interfaces.iter() {
            let send_last_bytes = interface.send_last_bytes.load(Ordering::Relaxed);
            let send_bytes = interface.send_bytes.load(Ordering::Relaxed);
            let send_total = (send_bytes * 8) / 1_000_000;
            let send_throughput = ((send_bytes - send_last_bytes) * 8) as f64 / 1_000_000.0;
            if send_throughput > send_peak_throughput {
                send_peak_throughput = send_throughput;
            }

            let bytes = tc_backlog(interface.name.as_str()).unwrap_or(0);

            let interface_tx = unsafe { interface.send_progress.get().unwrap_unchecked() };
            interface_tx.set_message(format!(
                "|--- {} {} {:.2} ({:.2}) Mbps | 🧮 {:.3} MB | ⏳ {:>6} |",
                interface.name,
                " ".repeat(usize::max(0, 15 - interface.name.len())),
                send_throughput,
                send_peak_throughput,
                send_total,
                bytes / 1_000_000
            ));

            interface
                .send_last_bytes
                .store(send_bytes, Ordering::Relaxed);
        }

        rx.set_message(format!(
            "[RX] ---------------- {:.2} ({:.2}) Mbps | 🧮 {:.3} MB | 📦 {:>6} | ❌ {:>4}",
            recv_throughput,
            recv_peak_throughput,
            recv_total,
            format!("{}", stats.recv_current.load(Ordering::Relaxed)),
            stats.recv_dropped.load(Ordering::Relaxed),
        ));

        for source in sources.read().iter() {
            for (dst, addr) in source.1.addrs.read().iter() {
                let source_rx = addr
                    .progress
                    .get_or_init(|| Arc::new(progress.add(ProgressBar::new_spinner())));

                let label = format!("{}:{}", dst.as_socket_ipv4().unwrap().port(), source.0);
                source_rx.set_message(format!(
                    "|--- {} {} {}",
                    label,
                    " ".repeat(usize::max(0, 10 - label.len())),
                    addr.last.load(Ordering::Relaxed).elapsed().as_millis(),
                ));
            }
        }

        recv_last_bytes = recv_bytes;
        send_last_bytes = send_bytes;
        thread::sleep(Duration::from_millis(1000));
    }

    Ok(())
}
