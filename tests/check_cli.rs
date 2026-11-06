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

/// A certificate the admin can read and the service user may not is the
/// ordinary case — Caddy writes the key 0600 — so the ok line has to say
/// whose permissions were used. Without it, "ok" reads as a promise about the
/// service user that `check` never made.
#[test]
fn the_ok_line_names_the_user_that_read_the_certificate() {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("check_cli");
    fs::create_dir_all(&dir).expect("temp dir");
    let generated = rcgen::generate_simple_self_signed(["mx.example.com".to_string()])
        .expect("generate a certificate");
    let crt = dir.join("ok-line.crt");
    let key = dir.join("ok-line.key");
    fs::write(&crt, generated.cert.pem()).expect("write certificate");
    fs::write(&key, generated.signing_key.serialize_pem()).expect("write key");

    let body = format!(
        "{GOOD}\n[tls]\ncertificate = {:?}\nkey = {:?}\n",
        crt.display().to_string(),
        key.display().to_string()
    );
    let path = write_config("ok-tls.toml", &body);
    let out = run_check(&path);

    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let user = std::env::var("USER").unwrap_or_default();
    assert!(!user.is_empty(), "this test needs USER to be set");
    assert!(
        stdout.contains(&user),
        "the ok line has to say which user read the files: {stdout}"
    );
}

/// `check` answers "would `run` start?", and `run` cannot sign an envelope
/// sender with a key that is not there. A `check` that only looked at the
/// path would pass a configuration whose every forwarded message then went
/// out with the original sender and failed SPF.
#[test]
fn check_reads_the_srs_secret_and_fails_at_the_srs_line() {
    let body = format!(
        "{GOOD}\n[srs]\ndomain = \"srs.example.com\"\nsecret_file = \"/nonexistent/srs.key\"\n"
    );
    let path = write_config("missing-srs-key.toml", &body);
    let out = run_check(&path);

    assert!(
        !out.status.success(),
        "a signing key that is not there must not pass check"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("/nonexistent/srs.key"), "{stderr}");
    assert!(
        stderr.contains(":9:"),
        "reported at the [srs] line, which is where the fix is typed: {stderr}"
    );
}

/// A short key is guessable offline from one SRS address found in a
/// `Received` header, and a guessed key makes this host an open relay. The
/// refusal has to say what to type instead, because "too short" on its own
/// invites a slightly longer guess.
#[test]
fn check_refuses_a_secret_file_too_short_to_sign_with() {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("check_cli");
    fs::create_dir_all(&dir).expect("temp dir");
    let key = dir.join("short-srs.key");
    fs::write(&key, "nowherenear\n").expect("write key");

    let body = format!(
        "{GOOD}\n[srs]\ndomain = \"srs.example.com\"\nsecret_file = {:?}\n",
        key.display().to_string()
    );
    let path = write_config("short-srs-key.toml", &body);
    let out = run_check(&path);

    assert!(
        !out.status.success(),
        "an 11-byte signing key must not pass"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("at least 16"), "{stderr}");
    assert!(
        stderr.contains("/dev/urandom"),
        "the refusal has to say what to type: {stderr}"
    );
}

/// The ok line is what an operator reads after a deploy, and whether the
/// envelope sender is being rewritten is the single fact that decides whether
/// forwarded mail passes SPF at the destination.
#[test]
fn the_ok_line_says_whether_the_envelope_sender_is_rewritten() {
    let plain = run_check(&write_config("no-srs.toml", GOOD));
    let stdout = String::from_utf8_lossy(&plain.stdout);
    assert!(stdout.contains("no SRS"), "{stdout}");

    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("check_cli");
    fs::create_dir_all(&dir).expect("temp dir");
    let key = dir.join("ok-srs.key");
    // Generated here rather than written down: a key-shaped literal in a
    // source file is a key in a source file.
    fs::write(
        &key,
        format!(
            "{:032x}\n",
            u128::from(std::process::id()).wrapping_mul(0x9e37_79b9_7f4a_7c15)
        ),
    )
    .expect("write key");

    let body = format!(
        "{GOOD}\n[srs]\ndomain = \"srs.example.com\"\nsecret_file = {:?}\n",
        key.display().to_string()
    );
    let out = run_check(&write_config("ok-srs.toml", &body));

    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("srs.example.com"),
        "the ok line has to name the SRS domain: {stdout}"
    );
}
