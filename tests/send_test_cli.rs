use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

const GOOD: &str = r#"hostname = "mx.example.com"
listen = "0.0.0.0:25"
spool_dir = "/var/lib/mxhop/spool"

[domains."example.com".aliases]
hi = "me@gmail.com"
"#;

fn config() -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("send_test_cli");
    fs::create_dir_all(&dir).expect("temp dir");
    let path = dir.join("mxhop.toml");
    fs::write(&path, GOOD).expect("write config");
    path
}

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_mxhop"))
        .arg("--config")
        .arg(config())
        .args(args)
        .output()
        .expect("run mxhop")
}

#[test]
fn an_unusable_destination_is_reported_before_anything_is_dialled() {
    let out = run(&["send-test", "not-an-address", "hello"]);

    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("not-an-address") && stderr.contains("no @"),
        "the reason has to be in it: {stderr}"
    );
    assert!(
        !String::from_utf8_lossy(&out.stdout).contains("delivering to"),
        "nothing should have been attempted: {}",
        String::from_utf8_lossy(&out.stdout)
    );
}

#[test]
fn a_bad_configuration_stops_send_test_too() {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("send_test_cli");
    fs::create_dir_all(&dir).expect("temp dir");
    let path = dir.join("broken.toml");
    fs::write(&path, GOOD.replace("mx.example.com", "localhost")).expect("write config");

    let out = Command::new(env!("CARGO_BIN_EXE_mxhop"))
        .arg("--config")
        .arg(&path)
        .args(["send-test", "me@example.com", "hello"])
        .output()
        .expect("run mxhop");

    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("hostname"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn send_test_is_not_advertised_in_the_help() {
    let out = run(&["--help"]);
    let help = String::from_utf8_lossy(&out.stdout);

    assert!(help.contains("check") && help.contains("run"), "{help}");
    assert!(
        !help.contains("send-test"),
        "it is hidden on purpose: {help}"
    );
}
