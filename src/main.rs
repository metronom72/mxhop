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
    Health,
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
        Command::Health => health(&cli).await,
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

    let arc = match open_arc(&config) {
        Ok(arc) => arc,
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
    let observe = match config.observe {
        Some(address) => format!(", /metrics and /healthz on {address}"),
        None => ", no metrics or health endpoint".to_string(),
    };
    let sealing = match &arc {
        Some(sealer) => format!(", ARC sealed as {}", sealer.domain()),
        None => ", no ARC seal".to_string(),
    };
    println!(
        "{}: ok — {} on {}, {} {} for {}{}{}{}{}{}{}",
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
        sealing,
        observe,
    );

    if let Some(sealer) = &arc {
        println!(
            "{}: publish the ARC public key as a TXT record at {}",
            cli.config.display(),
            sealer.record_name()
        );
    }
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

fn open_arc(config: &Config) -> Result<Option<Arc<mxhop::arc::Sealer>>, Problem> {
    let Some(settings) = config.arc.as_ref() else {
        return Ok(None);
    };
    mxhop::arc::Sealer::open(&settings.domain, &settings.selector, &settings.key_file)
        .map(|sealer| Some(Arc::new(sealer)))
        .map_err(|e| Problem {
            line: settings.line,
            message: e.to_string(),
        })
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

    let listener = match inherited_or_bound(config.listen).await {
        Ok(listener) => listener,
        Err(e) => {
            error!(address = %config.listen, "cannot listen: {e}");
            return ExitCode::FAILURE;
        }
    };

    let arc = match open_arc(&config) {
        Ok(arc) => arc,
        Err(problem) => {
            error!("{}", problem.message);
            return ExitCode::FAILURE;
        }
    };
    if let Some(sealer) = &arc {
        info!(
            domain = sealer.domain(),
            selector = sealer.selector(),
            record = sealer.record_name(),
            "sealing forwarded mail with ARC"
        );
    }

    let verifier = if config.auth.enabled {
        match mxhop::auth::Verifier::from_system(&config.hostname) {
            Ok(verifier) => Some(verifier.sealing_with(arc.clone())),
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
            config.hostname.clone(),
        )
        .run(),
    );

    let (trigger, shutdown) = mxhop::shutdown::channel();
    let (tracker, idle) = mxhop::shutdown::tracker();
    spawn_stop_on_signal(trigger);

    let health = mxhop::observe::Health::new(QUEUE_LIMIT);
    health.listening(true);
    health.queue_depth(queued as u64);
    if let Some(address) = config.observe {
        match TcpListener::bind(address).await {
            Ok(listener) => {
                let shown = listener
                    .local_addr()
                    .map_or_else(|_| address.to_string(), |a| a.to_string());
                info!(address = %shown, "serving /metrics and /healthz");
                tokio::spawn(mxhop::observe::serve(
                    listener,
                    Arc::clone(&health),
                    shutdown.clone(),
                ));
            }
            Err(e) => {
                error!(%address, "cannot listen for metrics and health: {e}");
                return ExitCode::FAILURE;
            }
        }
    }
    spawn_watch_spool(Arc::clone(&health), Arc::clone(&spool));

    accept_loop(
        listener,
        session_config,
        router,
        srs,
        spool,
        relay,
        tls,
        shutdown,
        tracker,
    )
    .await;
    health.listening(false);

    if idle.wait(GRACE).await {
        info!("every open session finished; exiting");
    } else {
        warn!(
            seconds = GRACE.as_secs(),
            "some sessions were still open when the grace period ran out; exiting              anyway"
        );
    }
    ExitCode::SUCCESS
}

const GRACE: std::time::Duration = std::time::Duration::from_secs(25);

const QUEUE_LIMIT: u64 = 100_000;

async fn inherited_or_bound(address: std::net::SocketAddr) -> std::io::Result<TcpListener> {
    use mxhop::activation::{Offer, offer, take_first};

    let listen_fds = std::env::var("LISTEN_FDS").ok();
    let listen_pid = std::env::var("LISTEN_PID").ok();

    match offer(
        listen_fds.as_deref(),
        listen_pid.as_deref(),
        std::process::id(),
    ) {
        Offer::Sockets(count) => {
            if count > 1 {
                warn!(
                    count,
                    "more than one socket was handed over; using the first"
                );
            }
            let inherited = take_first()?;
            let shown = inherited
                .local_addr()
                .map_or_else(|_| "an inherited socket".to_string(), |a| a.to_string());
            info!(address = %shown, "listening on the socket systemd handed over");
            unsafe { std::env::remove_var("LISTEN_FDS") };
            unsafe { std::env::remove_var("LISTEN_PID") };
            TcpListener::from_std(inherited)
        }
        Offer::NotForUs { pid } => {
            warn!(
                pid,
                "LISTEN_FDS names another process, so the socket in the environment \
                 is not ours; binding the configured address instead"
            );
            TcpListener::bind(address).await
        }
        Offer::Malformed => {
            warn!(
                "LISTEN_FDS or LISTEN_PID could not be read; binding the configured \
                 address instead"
            );
            TcpListener::bind(address).await
        }
        Offer::None => TcpListener::bind(address).await,
    }
}

async fn health(cli: &Cli) -> ExitCode {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let Some(config) = load(cli) else {
        return ExitCode::FAILURE;
    };
    let Some(address) = config.observe else {
        eprintln!("there is no [observe] block, so there is no endpoint to ask");
        return ExitCode::FAILURE;
    };

    let answered = async {
        let mut stream = tokio::net::TcpStream::connect(address).await?;
        stream
            .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await?;
        let mut whole = String::new();
        stream.read_to_string(&mut whole).await?;
        Ok::<String, std::io::Error>(whole)
    };

    match tokio::time::timeout(std::time::Duration::from_secs(5), answered).await {
        Ok(Ok(whole)) => {
            let ok = whole.starts_with("HTTP/1.1 200");
            print!("{}", whole.split_once("\r\n\r\n").map_or("", |(_, b)| b));
            if ok {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Ok(Err(e)) => {
            eprintln!("{address}: {e}");
            ExitCode::FAILURE
        }
        Err(_) => {
            eprintln!("{address}: no answer in five seconds");
            ExitCode::FAILURE
        }
    }
}

fn spawn_watch_spool(health: Arc<mxhop::observe::Health>, spool: Arc<Spool>) {
    tokio::spawn(async move {
        loop {
            match spool.queued().await {
                Ok(queued) => {
                    health.queue_writable(true);
                    health.queue_depth(queued.len() as u64);
                }
                Err(e) => {
                    warn!("the spool could not be read, so health is reporting it: {e}");
                    health.queue_writable(false);
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        }
    });
}

fn spawn_stop_on_signal(trigger: mxhop::shutdown::Trigger) {
    use tokio::signal::unix::{SignalKind, signal};

    let mut terminate = match signal(SignalKind::terminate()) {
        Ok(signal) => signal,
        Err(e) => {
            warn!("cannot listen for SIGTERM, so a stop will not be graceful: {e}");
            return;
        }
    };
    let mut interrupt = match signal(SignalKind::interrupt()) {
        Ok(signal) => signal,
        Err(e) => {
            warn!("cannot listen for SIGINT: {e}");
            return;
        }
    };

    tokio::spawn(async move {
        let name = tokio::select! {
            _ = terminate.recv() => "SIGTERM",
            _ = interrupt.recv() => "SIGINT",
        };
        info!(
            signal = name,
            seconds = GRACE.as_secs(),
            "stopping: no new connections, open sessions have until the grace              period to finish, and anyone waiting for a command gets 421"
        );
        trigger.fire();
    });
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
