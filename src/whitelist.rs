use std::collections::HashMap;
use std::net::{SocketAddrV4, UdpSocket};
use std::sync::Mutex;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac, digest::FixedOutput};
use sha2::Sha256;
use socket2::SockAddr;

type HmacSha256 = Hmac<Sha256>;

use crate::types::{Interface, Source, Stats, WhitelistConfiguration};
use crate::utils::CommandGuard;

pub fn listen(
    configuration: WhitelistConfiguration,
    interfaces: Arc<Vec<Interface>>,
    sources: Arc<Mutex<HashMap<u16, Source>>>,
    running: Arc<AtomicBool>,
    stats: Arc<Stats>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if configuration.server {
        server(configuration, sources, running, stats)
    } else {
        client(configuration, interfaces, running, stats)
    }
}

fn server(
    configuration: WhitelistConfiguration,
    _sources: Arc<Mutex<HashMap<u16, Source>>>,
    running: Arc<AtomicBool>,
    stats: Arc<Stats>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut rules = vec![];

    let socket = UdpSocket::bind(format!("0.0.0.0:{}", configuration.port))?;
    socket.set_nonblocking(true)?;

    const WINDOW_SIZE: usize = 60;
    let mut minimum = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs();
    let mut buf = [0u8; 32];

    while running.load(Ordering::Relaxed) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards");

        let whitelisted = {
            stats
                .whitelisted
                .read()
                .unwrap()
                .iter()
                .cloned()
                .collect::<Vec<_>>()
        };

        match socket.recv_from(&mut buf) {
            Ok((amt, src))
                if amt == 32 && !whitelisted.iter().any(|&source| source == src.ip()) =>
            {
                for i in 0..WINDOW_SIZE {
                    let current = now.as_secs() - i as u64;
                    let mut mac = HmacSha256::new_from_slice(configuration.secret.as_bytes())?;
                    mac.update(format!("{}", current).as_bytes());

                    if mac.verify_slice(&buf[..amt]).is_ok() {
                        if current > minimum {
                            minimum = current;

                            rules.push(
                                CommandGuard::new("iptables")
                                    .call(format!("-I INPUT -s {} -j ACCEPT", src.ip()))
                                    .cleanup(format!("-D INPUT -s {} -j ACCEPT", src.ip())),
                            );

                            stats.whitelisted.write().unwrap().push(src.ip());
                        }
                    }
                }
            }
            Err(ref error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_millis(1000));
            }
            _ => {}
        }
    }

    Ok(())
}

fn client(
    configuration: WhitelistConfiguration,
    interfaces: Arc<Vec<Interface>>,
    running: Arc<AtomicBool>,
    _stats: Arc<Stats>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    while running.load(Ordering::Relaxed) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards");

        if let Some(remote) = configuration.remote {
            let addr = SockAddr::from(SocketAddrV4::new(remote, configuration.port));

            for interface in interfaces.iter() {
                let interface =
                    Interface::udp(interface.name.clone()).expect("Failed to create UDP interface");

                let mut mac = HmacSha256::new_from_slice(configuration.secret.as_bytes())?;
                mac.update(format!("{}", now.as_secs()).as_bytes());

                let mut buf = [0u8; 32];
                mac.finalize_into((&mut buf).into());

                if let Err(error) = interface.socket.write().unwrap().send_to(&buf, &addr) {
                    println!("Failed to send data: {}", error);
                }
            }
        }

        std::thread::sleep(std::time::Duration::from_secs(1));
    }

    Ok(())
}
