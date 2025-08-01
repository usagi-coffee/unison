use std::{net::Ipv4Addr, process::Command};

#[allow(dead_code)]
pub fn interfaces() -> Vec<String> {
    let mut interfaces = vec![];

    let output = Command::new("ip")
        .args(&["-o", "link", "show"])
        .output()
        .expect("Failed to execute ip");

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        if let Some(field) = line.splitn(3, ':').nth(1) {
            interfaces.push(field.replace(char::is_whitespace, ""));
        }
    }

    interfaces
}

pub fn interface_ip(iface: &str) -> Option<Ipv4Addr> {
    let output = Command::new("ip")
        .args(&["-o", "-4", "addr", "show", "dev", iface])
        .output()
        .expect("Failed to execute ip");

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    for line in stdout.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if let Some(cidr) = fields.get(3) {
            if let Some(ip) = cidr.split('/').next() {
                return Some(ip.parse().expect("Invalid IP address"));
            }
        }
    }

    None
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
