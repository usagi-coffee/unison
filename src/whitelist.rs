use std::net::{ToSocketAddrs, UdpSocket};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac, digest::FixedOutput};
use sha2::Sha256;
use socket2::{Domain, Protocol, Socket, Type};

type HmacSha256 = Hmac<Sha256>;

use crate::types::WhitelistConfiguration;
use crate::utils::{CommandGuard, bind_to_device};

pub fn listen(
    configuration: WhitelistConfiguration,
    running: Arc<AtomicBool>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if configuration.server {
        server(configuration, running)
    } else {
        client(configuration, running)
    }
}

fn server(
    configuration: WhitelistConfiguration,
    running: Arc<AtomicBool>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut rules = vec![];
    let mut whitelisted = vec![];

    let socket = UdpSocket::bind(format!("0.0.0.0:{}", configuration.port))?;
    socket.set_nonblocking(true)?;

    const WINDOW_SIZE: usize = 60;
    let mut minimum = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs();
    let mut buf = [0u8; 32];

    println!("whitelist: Listening on 0.0.0.0:{}", configuration.port);
    while running.load(Ordering::Relaxed) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards");

        match socket.recv_from(&mut buf) {
            Ok((amt, src)) if amt == 32 && !whitelisted.contains(&src.ip()) => {
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

                            whitelisted.push(src.ip());
                            println!("whitelist: whitelisted {}", src.ip());
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
    running: Arc<AtomicBool>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    while running.load(Ordering::Relaxed) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards");

        if let Some(ref remote) = configuration.remote {
            for ifname in configuration.interfaces.iter() {
                if let Ok(sock) = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
                    && bind_to_device(&sock, ifname).is_ok()
                    && let Ok(mut addrs) =
                        format!("{}:{}", remote, configuration.port).to_socket_addrs()
                    && let Some(addr) = addrs.next()
                {
                    let mut mac = HmacSha256::new_from_slice(configuration.secret.as_bytes())?;
                    mac.update(format!("{}", now.as_secs()).as_bytes());

                    let mut buf = [0u8; 32];
                    mac.finalize_into((&mut buf).into());

                    if let Ok(_) = sock.connect(&addr.into())
                        && let Ok(_) = sock.send(&buf)
                    {}
                }
            }
        }

        std::thread::sleep(std::time::Duration::from_secs(5));
    }

    Ok(())
}
