use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use tokio::net::TcpListener;
use tracing::{error, info, warn};

use mxhop::config::{self, Config};
use mxhop::smtp::session::{self, SessionConfig};
use mxhop::spool::Spool;
use mxhop::telemetry;

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
            for problem in &problems {
                match problem.line {
                    Some(line) => eprintln!("{shown}:{line}: {}", problem.message),
                    None => eprintln!("{shown}: {}", problem.message),
                }
            }
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

    let domains: Vec<&str> = config.router.domains().collect();
    println!(
        "{}: ok — {} on {}, {} {} for {}",
        cli.config.display(),
        config.hostname,
        config.listen,
        config.router.alias_count(),
        plural(config.router.alias_count(), "alias", "aliases"),
        domains.join(", "),
    );
    ExitCode::SUCCESS
}

async fn run(cli: &Cli) -> ExitCode {
    let Some(config) = load(cli) else {
        return ExitCode::FAILURE;
    };
    telemetry::init(cli.log.as_deref(), cli.log_json);

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
    info!(
        address = %config.listen,
        hostname = %config.hostname,
        domains = config.router.domains().count(),
        aliases = config.router.alias_count(),
        queued,
        "mxhop is accepting mail"
    );

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(e) => {
                // One failed accept is not a reason to stop serving.
                warn!("accept failed: {e}");
                continue;
            }
        };

        let session_config = Arc::clone(&session_config);
        let router = Arc::clone(&router);
        let spool = Arc::clone(&spool);
        tokio::spawn(async move {
            let peer = peer.to_string();
            match session::serve(stream, peer.clone(), &session_config, &router, &spool).await {
                Ok(outcome) => info!(
                    %peer,
                    accepted = outcome.accepted,
                    quit = outcome.quit,
                    "session ended"
                ),
                Err(e) => warn!(%peer, "session failed: {e}"),
            }
        });
    }
}

fn plural(n: usize, one: &'static str, many: &'static str) -> &'static str {
    if n == 1 { one } else { many }
}
