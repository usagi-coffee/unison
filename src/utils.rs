use libc::{IP_HDRINCL, IPPROTO_IP, SO_BINDTODEVICE, SO_MARK, SOL_SOCKET, setsockopt};
use socket2::Socket;
use std::io;
use std::os::unix::io::AsRawFd;
use std::process::Command;

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

pub fn bind_to_device(sock: &Socket, ifname: &str) -> io::Result<()> {
    let fd = sock.as_raw_fd();
    let ifname_cstr = std::ffi::CString::new(ifname).unwrap();
    let res = unsafe {
        setsockopt(
            fd,
            SOL_SOCKET,
            SO_BINDTODEVICE,
            ifname_cstr.as_ptr() as *const _,
            ifname.len() as u32,
        )
    };
    if res != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub fn set_mark(sock: &Socket, mark: u32) -> io::Result<()> {
    let fd = sock.as_raw_fd();
    let res = unsafe {
        setsockopt(
            fd,
            SOL_SOCKET,
            SO_MARK,
            &mark as *const u32 as *const libc::c_void,
            std::mem::size_of::<u32>() as libc::socklen_t,
        )
    };

    if res != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[allow(dead_code)]
pub fn set_header_included(sock: &Socket) -> io::Result<()> {
    let fd = sock.as_raw_fd();
    let hdrincl: i32 = 1;
    let res = unsafe {
        setsockopt(
            fd,
            IPPROTO_IP,
            IP_HDRINCL,
            &hdrincl as *const _ as *const _,
            std::mem::size_of::<i32>() as u32,
        )
    };
    if res != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
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
