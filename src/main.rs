use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use tokio::net::TcpListener;
use tracing::{error, info, warn};

use mxhop::config::{self, Config, Problem};
use mxhop::server::accept_loop;
use mxhop::smtp::session::SessionConfig;
use mxhop::spool::Spool;
use mxhop::telemetry;
use mxhop::tls::Holder;

/// Where the file lives when nobody says otherwise.
const DEFAULT_CONFIG: &str = "/etc/mxhop/mxhop.toml";

#[derive(Debug, Parser)]
#[command(name = "mxhop", version, about = "A headless SMTP forwarder", long_about = None)]
struct Cli {
    /// Path to the configuration file.
    #[arg(long, short, global = true, env = "MXHOP_CONFIG", default_value = DEFAULT_CONFIG)]
    config: PathBuf,

    /// Log filter, in the `tracing` form: `info`, `mxhop::spool=debug`, …
    #[arg(long, global = true, env = "MXHOP_LOG")]
    log: Option<String>,

    /// Log as JSON lines instead of for a human reader.
    #[arg(long, global = true, env = "MXHOP_LOG_JSON")]
    log_json: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Check the configuration and say what is wrong with it, without
    /// starting anything. Exits non-zero if anything is wrong, so CI can run
    /// it.
    Check,
    /// Accept mail.
    Run,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    match cli.command {
        Command::Check => check(&cli),
        Command::Run => run(&cli).await,
    }
}

/// Loads the configuration, printing every problem the way an editor can
/// follow.
fn load(cli: &Cli) -> Option<Config> {
    let shown = cli.config.display();
    match config::load_file(&cli.config) {
        Ok(config) => Some(config),
        Err(problems) => {
            report(cli, &problems);
            eprintln!(
                "{shown}: {} {} found",
                problems.len(),
                plural(problems.len(), "problem", "problems")
            );
            None
        }
    }
}

fn check(cli: &Cli) -> ExitCode {
    let Some(config) = load(cli) else {
        return ExitCode::FAILURE;
    };

    // `check` answers "would `run` start?", and `run` refuses to start on a
    // certificate it cannot read — so the files are read here too, not just
    // their paths inspected.
    let tls = match open_tls(&config) {
        Ok(tls) => tls,
        Err(problem) => {
            report(cli, &[problem]);
            return ExitCode::FAILURE;
        }
    };

    let domains: Vec<&str> = config.router.domains().collect();
    println!(
        "{}: ok — {} on {}, {} {} for {}{}",
        cli.config.display(),
        config.hostname,
        config.listen,
        config.router.alias_count(),
        plural(config.router.alias_count(), "alias", "aliases"),
        domains.join(", "),
        match &tls {
            // The user is part of the answer: the files were read with this
            // user's permissions, and `run` will read them with the service
            // user's. Printing it is what lets an operator notice that the
            // two are not the same before mail is involved.
            Some(holder) => format!(
                ", STARTTLS with {} (read as {})",
                holder.paths().certificate.display(),
                mxhop::tls::current_user()
            ),
            None => ", no TLS".to_string(),
        },
    );
    ExitCode::SUCCESS
}

/// Reads the certificate, if one is configured, and turns a file problem into
/// a [`Problem`] at the line of the `[tls]` table.
fn open_tls(config: &Config) -> Result<Option<Arc<Holder>>, Problem> {
    let Some(paths) = config.tls.clone() else {
        return Ok(None);
    };
    let line = paths.line;
    Holder::open(paths).map(Some).map_err(|e| Problem {
        line,
        message: e.to_string(),
    })
}

fn report(cli: &Cli, problems: &[Problem]) {
    let shown = cli.config.display();
    for problem in problems {
        match problem.line {
            Some(line) => eprintln!("{shown}:{line}: {}", problem.message),
            None => eprintln!("{shown}: {}", problem.message),
        }
    }
}

async fn run(cli: &Cli) -> ExitCode {
    let Some(config) = load(cli) else {
        return ExitCode::FAILURE;
    };
    telemetry::init(cli.log.as_deref(), cli.log_json);

    // A `[tls]` block whose files cannot be read stops the service. There is
    // no previous certificate to fall back to, and starting plaintext-only
    // would downgrade every sender silently for months — the outage that
    // looks like silence. An MX that is down for a minute loses nothing:
    // senders retry.
    let tls = match open_tls(&config) {
        Ok(tls) => tls,
        Err(problem) => {
            error!("{}", problem.message);
            return ExitCode::FAILURE;
        }
    };

    let spool = match Spool::open(&config.spool_dir).await {
        Ok(spool) => Arc::new(spool),
        Err(e) => {
            error!(path = %config.spool_dir.display(), "cannot open the spool: {e}");
            return ExitCode::FAILURE;
        }
    };

    let listener = match TcpListener::bind(config.listen).await {
        Ok(listener) => listener,
        Err(e) => {
            // The usual cause is port 25 without the capability to bind it.
            error!(address = %config.listen, "cannot listen: {e}");
            return ExitCode::FAILURE;
        }
    };

    let session_config = Arc::new(SessionConfig::from_config(&config));
    let router = Arc::new(config.router.clone());
    let queued = spool.queued().await.map(|q| q.len()).unwrap_or(0);
    // The address the listener actually got, not the one that was asked for:
    // with port 0 they differ, and the honest one is the one a client can
    // connect to.
    let address = listener
        .local_addr()
        .map_or_else(|_| config.listen.to_string(), |a| a.to_string());
    info!(
        %address,
        hostname = %config.hostname,
        domains = config.router.domains().count(),
        aliases = config.router.alias_count(),
        queued,
        tls = tls.is_some(),
        "mxhop is accepting mail"
    );

    if let Some(holder) = tls.clone() {
        spawn_reload_on_hangup(holder);
    } else {
        spawn_reload_on_hangup_without_tls();
    }

    accept_loop(listener, session_config, router, spool, tls).await;
    ExitCode::SUCCESS
}

/// Rereads the certificate on every SIGHUP. Shaped as one call so that the
/// alias table can join it later: that needs the `Router` behind its own
/// `ArcSwap` and a policy for a changed `listen` or `spool_dir` mid-run,
/// which is a task of its own.
fn spawn_reload_on_hangup(holder: Arc<Holder>) {
    let Some(mut hangups) = hangups() else {
        return;
    };
    tokio::spawn(async move {
        while hangups.recv().await.is_some() {
            match holder.reload() {
                Ok(fingerprint) => info!(
                    certificate = %holder.paths().certificate.display(),
                    sha256 = %fingerprint,
                    "TLS certificate reloaded; new connections use it"
                ),
                // The running service keeps serving: `reload` never stores a
                // half-built configuration, and a renewal caught mid-write is
                // a file that will be whole in a second.
                Err(e) => warn!("TLS reload failed: {e}; keeping the certificate loaded before"),
            }
        }
    });
}

fn spawn_reload_on_hangup_without_tls() {
    let Some(mut hangups) = hangups() else {
        return;
    };
    tokio::spawn(async move {
        while hangups.recv().await.is_some() {
            info!("SIGHUP: nothing to reload, no [tls] block");
        }
    });
}

fn hangups() -> Option<tokio::signal::unix::Signal> {
    match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) {
        Ok(signal) => Some(signal),
        Err(e) => {
            // Without the handler the default action for SIGHUP would kill the
            // process, so this is worth saying out loud rather than ignoring.
            warn!("cannot listen for SIGHUP, so the certificate cannot be reloaded: {e}");
            None
        }
    }
}

fn plural(n: usize, one: &'static str, many: &'static str) -> &'static str {
    if n == 1 { one } else { many }
}
