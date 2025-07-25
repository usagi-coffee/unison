use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tun::Device;

use crate::types::SenderConfiguration;
use crate::utils::interfaces;
use crate::utils::{CommandGuard, bind_to_device, set_header_included, set_mark};

pub struct Tunnel<'a> {
    pub dev: tun::platform::Device,
    pub iface: String,
    pub custom: bool,
    _rules: Vec<CommandGuard<'a>>,
}

pub fn listen(
    configuration: SenderConfiguration,
    running: Arc<AtomicBool>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut tun = Tunnel::new(&configuration)?;
    tun.dev.set_nonblock()?;

    // Create one raw socket per interface
    let mut outputs: Vec<(String, Socket)> = Vec::new();

    for ifname in &configuration.interfaces {
        println!("sender: binding to interface {}", ifname);
        let socket = Socket::new(
            Domain::IPV4,
            Type::from(libc::SOCK_RAW),
            Some(Protocol::from(libc::IPPROTO_RAW)),
        )?;
        bind_to_device(&socket, ifname)?;
        set_header_included(&socket)?;

        outputs.push((ifname.to_owned(), socket));
    }

    let mut id = 0u32;
    let mut buf = [0u8; 1504];

    println!("sender: listening for packets on {}", tun.dev.name());
    while running.load(Ordering::Relaxed) {
        let n = match tun.dev.read(&mut buf) {
            Ok(n) => n,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(10));
                continue;
            }
            Err(error) => {
                println!("sender: {}", error);
                break;
            }
        };

        let packet = &buf[..n];

        // Filter out non-IPv4 packets
        if packet[0] >> 4 != 4 {
            continue;
        }

        // Destination IP is at offset 16..20 in IPv4 header
        let dst_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
        let dst = SockAddr::from(SocketAddr::new(IpAddr::V4(dst_ip), 0));

        let mut tagged: Vec<u8> = packet.into();
        tagged.extend_from_slice(&id.to_be_bytes());

        // Increment the ID for the next packet
        id = id + 1;

        for (name, socket) in &outputs {
            if let Err(error) = socket.send_to(&tagged, &dst) {
                eprintln!("sender: {}: failed to send with {}", name, error);
            }
        }
    }

    Ok(())
}

impl<'a> Tunnel<'a> {
    pub fn new(
        configuration: &SenderConfiguration,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let custom = configuration.tun.is_some();
        let iface = {
            if let Some(name) = &configuration.tun {
                name.clone()
            } else {
                let interfaces = interfaces();
                let mut n = 0;
                loop {
                    let name = format!("tun{}", n);
                    if !interfaces.contains(&name) {
                        break name;
                    }

                    n = n + 1;
                }
            }
        };

        let mut rules = vec![];
        if !custom {
            rules.push(
                CommandGuard::new("ip")
                    .call(format!("tuntap add dev {} mode tun", &iface))
                    .cleanup(format!("tuntap del dev {} mode tun", &iface)),
            );

            rules.push(CommandGuard::new("ip").call(format!("link set {} up", &iface)));
        }

        // Mark packets so they are routed through the tunnel
        if !configuration.server {
            if let Some(ports) = &configuration.ports {
                for port in ports {
                    rules.push(
                        CommandGuard::new("iptables")
                            .call(format!(
                                "-t mangle -A OUTPUT -p udp --dport {} -j MARK --set-mark 0x{:X}",
                                port, configuration.fwmark
                            ))
                            .cleanup(format!(
                                "-t mangle -D OUTPUT -p udp --dport {} -j MARK --set-mark 0x{:X}",
                                port, configuration.fwmark
                            )),
                    );
                }
            }
        } else {
            if let Some(ports) = &configuration.ports {
                for port in ports {
                    rules.push(
                        CommandGuard::new("iptables")
                            .call(format!(
                                "-t mangle -A OUTPUT -p udp --sport {} -j MARK --set-mark 0x{:X}",
                                port, configuration.fwmark
                            ))
                            .cleanup(format!(
                                "-t mangle -D OUTPUT -p udp --sport {} -j MARK --set-mark 0x{:X}",
                                port, configuration.fwmark
                            )),
                    );
                }
            }
        }

        rules.push(
            CommandGuard::new("ip")
                .call(format!(
                    "rule add fwmark 0x{:X} table {}",
                    configuration.fwmark, configuration.table
                ))
                .cleanup(format!(
                    "rule del fwmark 0x{:X} table {}",
                    configuration.fwmark, configuration.table
                )),
        );

        rules.push(CommandGuard::new("ip").call(format!(
            "route add default dev {} table {}",
            &iface, configuration.table
        )));

        Ok(Tunnel {
            dev: tun::create(
                tun::Configuration::default()
                    .name(&iface)
                    .layer(tun::Layer::L3),
            )?,
            iface: iface.clone(),
            custom,
            _rules: rules,
        })
    }
}

impl<'a> Drop for Tunnel<'a> {
    fn drop(&mut self) {
        if !self.custom {
            Command::new("ip")
                .args(vec!["link", "delete", self.iface.as_str()])
                .status()
                .expect("Failed to execute `ip` command");
        }
    }
}
