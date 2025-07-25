use std::process::Command;

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
