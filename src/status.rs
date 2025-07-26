use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use crate::types::{Stats, StatusConfiguration};

use indicatif::ProgressBar;
use std::{thread, time::Duration};

pub fn listen(
    configuration: StatusConfiguration,
    running: Arc<AtomicBool>,
    stats: Arc<Stats>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let pb = ProgressBar::new_spinner();
    pb.enable_steady_tick(Duration::from_millis(100));

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
                .lock()
                .unwrap()
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        };

        let line = format!(
            "✈️ {:.2} ({:.2}) Mbps | 🧮 {:.3} MB | 📦 {:>6} | 📥 {:.2} ({:.2}) Mbps | 🧮 {:.3} MB | ❌ {:>4} | 📦 {:>6} | 🌐 [{}] | ⏰ {} {}",
            send_throughput,
            send_peak_throughput,
            send_total,
            format!("{}", stats.send_current.load(Ordering::Relaxed)),
            recv_throughput,
            recv_peak_throughput,
            recv_total,
            stats.recv_dropped.load(Ordering::Relaxed),
            format!("{}", stats.recv_current.load(Ordering::Relaxed)),
            configuration.interfaces.join(", "),
            uptime,
            if configuration.server {
                format!("✅ {}", whitelisted)
            } else {
                "".into()
            }
        );

        pb.set_message(line);

        recv_last_bytes = recv_bytes;
        send_last_bytes = send_bytes;
        thread::sleep(Duration::from_millis(1000));
    }

    Ok(())
}
