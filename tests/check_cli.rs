//! `mxhop check` as an operator runs it: a real binary, a real file, an exit
//! code a CI job can read.

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

fn write_config(name: &str, body: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("check_cli");
    fs::create_dir_all(&dir).expect("temp dir");
    let path = dir.join(name);
    fs::write(&path, body).expect("write config");
    path
}

fn run_check(path: &PathBuf) -> Output {
    Command::new(env!("CARGO_BIN_EXE_mxhop"))
        .arg("--config")
        .arg(path)
        .arg("check")
        .output()
        .expect("run mxhop check")
}

const GOOD: &str = r#"hostname = "mx.example.com"
listen = "0.0.0.0:25"
spool_dir = "/var/lib/mxhop/spool"

[domains."example.com".aliases]
hi = "me@gmail.com"
"*" = "catch@gmail.com"
"#;

/// `hi` and `loop` point at each other: the table is a trap, and `check` is
/// the only thing standing between it and a mail loop in production.
const CYCLIC: &str = r#"hostname = "mx.example.com"
listen = "0.0.0.0:25"
spool_dir = "/var/lib/mxhop/spool"

[domains."example.com".aliases]
hi = "loop@example.com"
loop = "hi@example.com"
"#;

#[test]
fn a_good_configuration_exits_zero_and_says_what_it_read() {
    let path = write_config("good.toml", GOOD);
    let out = run_check(&path);

    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("example.com"), "{stdout}");
    assert!(stdout.contains("ok"), "{stdout}");
}

#[test]
fn a_cyclic_alias_table_exits_non_zero_and_names_the_line() {
    let path = write_config("cyclic.toml", CYCLIC);
    let out = run_check(&path);

    assert!(!out.status.success(), "a loop must not pass `check`");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("loop"), "{stderr}");
    assert!(
        stderr.contains(":6:"),
        "the offending line should be clickable: {stderr}"
    );
}

#[test]
fn a_missing_file_is_reported_as_such() {
    let path = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("check_cli/not-here.toml");
    let out = run_check(&path);

    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("not-here.toml"),
        "the path has to be in the message: {stderr}"
    );
}

/// Without a `[tls]` block mxhop speaks plaintext only, and the ok line has to
/// say so: an operator who thinks TLS is on and is wrong finds out from
/// somebody else's deferral log.
#[test]
fn check_says_whether_there_is_a_certificate() {
    let path = write_config("no-tls.toml", GOOD);
    let out = run_check(&path);
    let stdout = String::from_utf8_lossy(&out.stdout);

    assert!(stdout.contains("no TLS"), "{stdout}");
}

/// `check` answers "would `run` start?", and `run` refuses to start on a
/// certificate it cannot read. A `check` that only looked at the paths would
/// pass a configuration that then fails to boot.
#[test]
fn check_reads_the_certificate_and_fails_at_the_tls_line() {
    let body = format!(
        "{GOOD}\n[tls]\ncertificate = \"/nonexistent/mx.crt\"\nkey = \"/nonexistent/mx.key\"\n"
    );
    let path = write_config("broken-tls.toml", &body);
    let out = run_check(&path);

    assert!(
        !out.status.success(),
        "a certificate that is not there must not pass check"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("/nonexistent/mx.crt"), "{stderr}");
    assert!(
        stderr.contains(":9:"),
        "reported at the [tls] line, which is where the fix is typed: {stderr}"
    );
}
