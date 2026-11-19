use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use tokio::net::TcpListener;
use tracing::{error, info, warn};

use mxhop::config::{self, Config, Problem};
use mxhop::dns::{Hickory, Resolve};
use mxhop::routing::Mailbox;
use mxhop::server::accept_loop;
use mxhop::smtp::client::{self, Delivery, Direct, Outbound, Tcp, Verdict};
use mxhop::smtp::session::SessionConfig;
use mxhop::spool::Spool;
use mxhop::srs::{self, Srs};
use mxhop::telemetry;
use mxhop::tls::Holder;

const DEFAULT_CONFIG: &str = "/etc/mxhop/mxhop.toml";

#[derive(Debug, Parser)]
#[command(name = "mxhop", version, about = "A headless SMTP forwarder", long_about = None)]
struct Cli {
    #[arg(long, short, global = true, env = "MXHOP_CONFIG", default_value = DEFAULT_CONFIG)]
    config: PathBuf,

    #[arg(long, global = true, env = "MXHOP_LOG")]
    log: Option<String>,

    #[arg(long, global = true, env = "MXHOP_LOG_JSON")]
    log_json: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Check,
    Run,
    #[command(hide = true)]
    SendTest {
        to: String,
        body: String,
        #[arg(long)]
        from: Option<String>,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    match &cli.command {
        Command::Check => check(&cli).await,
        Command::Run => run(&cli).await,
        Command::SendTest { to, body, from } => send_test(&cli, to, body, from.as_deref()).await,
    }
}

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

async fn check(cli: &Cli) -> ExitCode {
    let Some(config) = load(cli) else {
        return ExitCode::FAILURE;
    };

    let tls = match open_tls(&config) {
        Ok(tls) => tls,
        Err(problem) => {
            report(cli, &[problem]);
            return ExitCode::FAILURE;
        }
    };

    let srs = match open_srs(&config) {
        Ok(srs) => srs,
        Err(problem) => {
            report(cli, &[problem]);
            return ExitCode::FAILURE;
        }
    };

    if let Some(settings) = config.srs.as_ref() {
        warn_about_secret_mode(&settings.secret_file);
    }

    let via = config.router.via_hosts();
    if !via.is_empty() {
        let resolver = match Hickory::from_system() {
            Ok(resolver) => resolver,
            Err(e) => {
                report(
                    cli,
                    &[Problem {
                        line: None,
                        message: format!(
                            "an alias delivers via a named host, and the system resolver \
                             could not be opened to check that the name exists: {e}"
                        ),
                    }],
                );
                return ExitCode::FAILURE;
            }
        };
        let mut unresolved = Vec::new();
        for (host, aliases) in &via {
            match resolver.addrs(host).await {
                Ok(addrs) if !addrs.is_empty() => {}
                Ok(_) | Err(mxhop::dns::DnsError::NotFound) => unresolved.push(Problem {
                    line: None,
                    message: format!(
                        "via = {host:?} has no address, so mail for {} would have \
                         nowhere to go and nothing in DNS would say so",
                        aliases.join(", ")
                    ),
                }),
                Err(e) => unresolved.push(Problem {
                    line: None,
                    message: format!(
                        "via = {host:?} could not be resolved, so whether mail for {} \
                         can be delivered is unknown: {e}",
                        aliases.join(", ")
                    ),
                }),
            }
        }
        if !unresolved.is_empty() {
            report(cli, &unresolved);
            return ExitCode::FAILURE;
        }
    }

    let domains: Vec<&str> = config.router.domains().collect();
    let retries = format!(
        ", a deferred message retried after {} minutes and then every {}, given up on \
         after {} hours",
        config
            .queue
            .retries
            .iter()
            .map(|w| (w.as_secs() / 60).to_string())
            .collect::<Vec<_>>()
            .join(", "),
        match config.queue.retries.last().map_or(0, |w| w.as_secs() / 60) {
            60 => "hour".to_string(),
            minutes if minutes % 60 == 0 => format!("{} hours", minutes / 60),
            minutes => format!("{minutes} minutes"),
        },
        config.queue.lifetime.as_secs() / 3_600,
    );
    println!(
        "{}: ok — {} on {}, {} {} for {}{}{}{}{}",
        cli.config.display(),
        config.hostname,
        config.listen,
        config.router.alias_count(),
        plural(config.router.alias_count(), "alias", "aliases"),
        domains.join(", "),
        match &srs {
            Some(srs) => format!(
                ", SRS at {} ({} {}, {} day window)",
                srs.domain(),
                srs.key_count(),
                plural(srs.key_count(), "key", "keys"),
                srs.max_age_days()
            ),
            None => ", no SRS — forwarded mail keeps the original envelope sender \
                      and will fail SPF"
                .to_string(),
        },
        match &tls {
            Some(holder) => format!(
                ", STARTTLS with {} (read as {})",
                holder.paths().certificate.display(),
                mxhop::tls::current_user()
            ),
            None => ", no TLS".to_string(),
        },
        match (config.auth.enabled, config.auth.enforce) {
            (false, _) => ", no SPF/DKIM/DMARC check at all".to_string(),
            (true, mxhop::policy::Enforce::Dmarc) =>
                ", SPF/DKIM/DMARC checked, and a p=reject failure refused".to_string(),
            (true, mxhop::policy::Enforce::Off) =>
                ", SPF/DKIM/DMARC checked and stamped, never refused".to_string(),
        },
        retries,
    );
    ExitCode::SUCCESS
}

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

fn warn_about_secret_mode(path: &std::path::Path) {
    let _ = path;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let Ok(mode) = std::fs::metadata(path).map(|m| m.permissions().mode()) else {
            return;
        };
        let extra = mode & 0o077;
        if extra != 0 {
            eprintln!(
                "{}: warning: mode {:04o} — the srs signing key is readable by {}; \
                 anyone who can read it can forge an address this host will relay. \
                 `chmod 600 {}`",
                path.display(),
                mode & 0o7777,
                if mode & 0o007 != 0 {
                    "everyone on this host"
                } else {
                    "its group"
                },
                path.display()
            );
        }
    }
}

fn open_srs(config: &Config) -> Result<Option<Srs>, Problem> {
    let Some(settings) = config.srs.as_ref() else {
        return Ok(None);
    };
    srs::open(settings).map(Some).map_err(|message| Problem {
        line: settings.line,
        message,
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
            error!(address = %config.listen, "cannot listen: {e}");
            return ExitCode::FAILURE;
        }
    };

    let verifier = if config.auth.enabled {
        match mxhop::auth::Verifier::from_system(&config.hostname) {
            Ok(verifier) => Some(verifier),
            Err(e) => {
                error!("cannot build a resolver for SPF, DKIM and DMARC: {e}");
                return ExitCode::FAILURE;
            }
        }
    } else {
        None
    };

    let relay = match Hickory::from_system() {
        Ok(resolver) => Arc::new(Direct::new(
            resolver,
            Outbound::new(&config.hostname, config.outbound.ipv6),
            verifier,
        )),
        Err(e) => {
            error!("cannot build a DNS resolver: {e}");
            return ExitCode::FAILURE;
        }
    };

    let srs = match open_srs(&config) {
        Ok(srs) => srs.map(Arc::new),
        Err(problem) => {
            error!("{}", problem.message);
            return ExitCode::FAILURE;
        }
    };

    let session_config = Arc::new(SessionConfig::from_config(&config));
    let router = Arc::new(config.router.clone());
    let queued = spool.queued().await.map(|q| q.len()).unwrap_or(0);
    let address = listener
        .local_addr()
        .map_or_else(|_| config.listen.to_string(), |a| a.to_string());
    info!(
        %address,
        hostname = %config.hostname,
        domains = config.router.domains().count(),
        aliases = config.router.alias_count(),
        srs = srs.as_ref().map_or("none".to_string(), |s| s.domain().to_string()),
        queued,
        auth = if !config.auth.enabled {
            "off"
        } else if config.auth.enforce == mxhop::policy::Enforce::Off {
            "stamp only"
        } else {
            "dmarc"
        },
        tls = tls.is_some(),
        "mxhop is accepting mail"
    );

    if let Some(holder) = tls.clone() {
        spawn_reload_on_hangup(holder);
    } else {
        spawn_reload_on_hangup_without_tls();
    }

    tokio::spawn(
        mxhop::queue::Runner::new(
            Arc::clone(&spool),
            Arc::clone(&relay),
            srs.clone(),
            config.queue.clone(),
        )
        .run(),
    );

    accept_loop(listener, session_config, router, srs, spool, relay, tls).await;
    ExitCode::SUCCESS
}

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
            warn!("cannot listen for SIGHUP, so the certificate cannot be reloaded: {e}");
            None
        }
    }
}

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
