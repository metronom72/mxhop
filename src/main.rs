use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use tokio::net::TcpListener;
use tracing::{error, info, warn};

use mxhop::config::{self, Config};
use mxhop::dns::Hickory;
use mxhop::routing::Mailbox;
use mxhop::smtp::client::{self, Delivery, Outbound, Tcp, Verdict};
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
    /// Hand one message to a real address and print what the destination
    /// said, word for word.
    ///
    /// Hidden because it is not part of running a forwarder: it exists so
    /// that a deployment can be verified from the host it runs on, where the
    /// things that go wrong are reverse DNS, the outbound port and the
    /// destination's opinion of us — none of which a unit test can reach.
    #[command(hide = true)]
    SendTest {
        /// The address to deliver to.
        to: String,
        /// The body, as one line.
        body: String,
        /// The envelope sender. Defaults to postmaster at the configured
        /// hostname, which is the address a bounce should come back to.
        #[arg(long)]
        from: Option<String>,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    match &cli.command {
        Command::Check => check(&cli),
        Command::Run => run(&cli).await,
        Command::SendTest { to, body, from } => send_test(&cli, to, body, from.as_deref()).await,
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

/// Delivers one message and prints the whole exchange's result.
///
/// Everything is printed rather than logged, and the destination's reply is
/// printed exactly as it came back: when this is run over ssh to find out why
/// mail is not arriving, a paraphrase is worse than nothing.
async fn send_test(cli: &Cli, to: &str, body: &str, from: Option<&str>) -> ExitCode {
    let Some(config) = load(cli) else {
        return ExitCode::FAILURE;
    };
    telemetry::init(cli.log.as_deref(), cli.log_json);

    let mailbox = match Mailbox::parse(to) {
        Ok(mailbox) => mailbox,
        Err(e) => {
            eprintln!("{to:?} {e}");
            return ExitCode::FAILURE;
        }
    };

    let sender = from
        .map(ToString::to_string)
        .unwrap_or_else(|| format!("postmaster@{}", config.hostname));

    // Enough of a message to arrive in a mailbox and be recognisable there.
    // There is deliberately no Date: header — the headers mxhop adds to a
    // forwarded message are a separate piece of work, and inventing one here
    // would be a second implementation of it.
    let head = format!(
        "From: <{sender}>\r\n\
         To: <{mailbox}>\r\n\
         Subject: mxhop send-test from {}\r\n\
         Message-ID: <{}@{}>\r\n\
         \r\n",
        config.hostname,
        mxhop::spool::new_id(),
        config.hostname
    );
    let body = format!("{body}\r\n");

    let resolver = match Hickory::from_system() {
        Ok(resolver) => resolver,
        Err(e) => {
            eprintln!("cannot build a DNS resolver: {e}");
            return ExitCode::FAILURE;
        }
    };

    let out = Outbound::new(&config.hostname, config.outbound.ipv6);
    let delivery = Delivery::new(
        Some(sender),
        vec![mailbox],
        head.into_bytes(),
        body.into_bytes().into(),
    );

    println!(
        "delivering to {} as {} over port {}",
        delivery.to[0], out.hostname, out.port
    );
    let outcome = client::deliver(&resolver, &Tcp, &out, &delivery).await;

    match &outcome.host {
        Some(host) => println!("{host} answered:"),
        None => println!("no mail exchanger answered:"),
    }
    let mut accepted = true;
    for result in &outcome.results {
        match &result.verdict {
            Verdict::Accepted => println!("  {}: accepted", result.mailbox),
            Verdict::Refused(reply) => {
                accepted = false;
                println!("  {}: refused — {reply}", result.mailbox);
            }
            Verdict::Deferred(reply) => {
                accepted = false;
                println!("  {}: deferred — {reply}", result.mailbox);
            }
        }
    }

    if accepted {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn plural(n: usize, one: &'static str, many: &'static str) -> &'static str {
    if n == 1 { one } else { many }
}
