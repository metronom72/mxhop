use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tracing::{debug, warn};

use crate::auth::{Auth, Probe, Verifier};
use crate::dns::{Resolve, targets};
use crate::routing::Mailbox;
use crate::smtp::wire::{self, WireError};

pub const SMTP_PORT: u16 = 25;

const MAX_REPLY_BYTES: usize = 16 * 1024;

const BODY_CHUNK_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone)]
pub struct Delivery {
    pub from: Option<String>,
    pub to: Vec<Mailbox>,
    pub head: Vec<u8>,
    pub body: Arc<[u8]>,
    pub eight_bit: bool,
    pub deadline: Option<Instant>,
    pub via: Option<String>,
}

impl Delivery {
    pub fn new(from: Option<String>, to: Vec<Mailbox>, head: Vec<u8>, body: Arc<[u8]>) -> Self {
        let eight_bit = head.iter().chain(body.iter()).any(|b| *b >= 0x80);
        Self {
            from,
            to,
            head,
            body,
            eight_bit,
            deadline: None,
            via: None,
        }
    }

    #[must_use]
    pub fn due_by(mut self, deadline: Instant) -> Self {
        self.deadline = Some(deadline);
        self
    }

    #[must_use]
    pub fn via(mut self, host: Option<&str>) -> Self {
        self.via = host.map(str::to_string);
        self
    }

    pub fn size(&self) -> u64 {
        (self.head.len() + self.body.len()) as u64
    }

    fn domain(&self) -> Option<&str> {
        self.to.first().map(Mailbox::domain)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Reply {
    pub code: u16,
    pub enhanced: Option<String>,
    pub text: String,
    pub lines: Vec<String>,
}

impl Reply {
    fn is_positive(&self) -> bool {
        (200..300).contains(&self.code)
    }

    fn is_permanent(&self) -> bool {
        self.code >= 500
    }

    fn ours(code: u16, enhanced: &str, text: impl fmt::Display) -> Self {
        Self {
            code,
            enhanced: Some(enhanced.to_string()),
            text: format!("mxhop: {text}"),
            lines: Vec::new(),
        }
    }

    #[must_use]
    pub fn attributed_to(mut self, host: &str) -> Self {
        self.text = format!("{host} said: {}", self.text);
        if let Some(first) = self.lines.first_mut() {
            *first = format!("{host} said: {first}");
        }
        self
    }

    #[must_use]
    pub fn wire(&self) -> Vec<String> {
        let enhanced = match &self.enhanced {
            Some(enhanced) => format!("{enhanced} "),
            None => String::new(),
        };
        if self.lines.len() < 2 {
            return vec![clamp(format!("{} {enhanced}{}", self.code, self.text))];
        }
        let last = self.lines.len() - 1;
        self.lines
            .iter()
            .enumerate()
            .map(|(at, line)| {
                let sep = if at == last { ' ' } else { '-' };
                clamp(format!("{}{sep}{enhanced}{line}", self.code))
            })
            .collect()
    }
}

fn clamp(mut line: String) -> String {
    const LIMIT: usize = 512 - 2;
    if line.len() <= LIMIT {
        return line;
    }
    while !line.is_char_boundary(LIMIT) {
        line.truncate(line.len() - 1);
    }
    line.truncate(LIMIT);
    line
}

impl fmt::Display for Reply {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.enhanced {
            Some(enhanced) => write!(f, "{} {} {}", self.code, enhanced, self.text),
            None => write!(f, "{} {}", self.code, self.text),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Accepted,
    Refused(Reply),
    Deferred(Reply),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientResult {
    pub mailbox: Mailbox,
    pub verdict: Verdict,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub host: Option<String>,
    pub results: Vec<RecipientResult>,
}

impl Outcome {
    fn all(to: &[Mailbox], verdict: Verdict) -> Vec<RecipientResult> {
        to.iter()
            .map(|mailbox| RecipientResult {
                mailbox: mailbox.clone(),
                verdict: verdict.clone(),
            })
            .collect()
    }
}

#[derive(Debug, Clone)]
pub struct Budget {
    pub connect: Duration,
    pub command: Duration,
    pub body: Duration,
    pub end_of_data: Duration,
    pub overall: Duration,
}

impl Default for Budget {
    fn default() -> Self {
        Self {
            connect: Duration::from_secs(10),
            command: Duration::from_secs(30),
            body: Duration::from_secs(60),
            end_of_data: Duration::from_secs(120),
            overall: Duration::from_secs(180),
        }
    }
}

#[derive(Clone)]
pub struct Outbound {
    pub hostname: String,
    pub ipv6: bool,
    pub tls: Option<Arc<TlsConnector>>,
    pub port: u16,
    pub budget: Budget,
}

impl Outbound {
    pub fn new(hostname: impl Into<String>, ipv6: bool) -> Self {
        Self {
            hostname: hostname.into(),
            ipv6,
            tls: Some(Arc::new(webpki_connector())),
            port: SMTP_PORT,
            budget: Budget::default(),
        }
    }
}

impl fmt::Debug for Outbound {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Outbound")
            .field("hostname", &self.hostname)
            .field("ipv6", &self.ipv6)
            .field("tls", &self.tls.is_some())
            .field("port", &self.port)
            .field("budget", &self.budget)
            .finish()
    }
}

pub fn webpki_connector() -> TlsConnector {
    let roots = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let config = ClientConfig::builder_with_provider(Arc::new(
        tokio_rustls::rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("ring supports the default protocol versions")
    .with_root_certificates(roots)
    .with_no_client_auth();
    TlsConnector::from(Arc::new(config))
}

#[derive(Debug)]
pub enum Fail {
    Connect(io::Error),
    Wire(WireError),
    Timeout(&'static str),
    Spent,
    Garbled(String),
    Tls(String),
    Rejected(Reply),
    Unsettled(Box<Fail>),
}

impl Fail {
    fn worth(&self) -> u8 {
        match self {
            Fail::Unsettled(_) => 3,
            Fail::Rejected(_) => 2,
            Fail::Timeout(_) | Fail::Spent => 0,
            _ => 1,
        }
    }
}

impl fmt::Display for Fail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Fail::Connect(e) => write!(f, "cannot connect: {e}"),
            Fail::Wire(e) => write!(f, "{e}"),
            Fail::Timeout(phase) => write!(f, "timed out waiting for {phase}"),
            Fail::Spent => f.write_str("the message's delivery budget is spent"),
            Fail::Garbled(line) => write!(f, "not an SMTP reply: {line:?}"),
            Fail::Tls(e) => write!(f, "TLS failed: {e}"),
            Fail::Rejected(reply) => write!(f, "{reply}"),
            Fail::Unsettled(e) => write!(f, "{e}, and the message was already sent"),
        }
    }
}

impl From<WireError> for Fail {
    fn from(e: WireError) -> Self {
        Fail::Wire(e)
    }
}

impl From<io::Error> for Fail {
    fn from(e: io::Error) -> Self {
        Fail::Wire(WireError::Io(e))
    }
}

pub trait Connect {
    type Stream: AsyncRead + AsyncWrite + Unpin + Send;

    fn connect(
        &self,
        addr: SocketAddr,
    ) -> impl std::future::Future<Output = io::Result<Self::Stream>> + Send;
}

pub struct Tcp;

impl Connect for Tcp {
    type Stream = TcpStream;

    async fn connect(&self, addr: SocketAddr) -> io::Result<TcpStream> {
        TcpStream::connect(addr).await
    }
}

pub async fn deliver<R, C>(
    resolver: &R,
    connector: &C,
    out: &Outbound,
    delivery: &Delivery,
) -> Outcome
where
    R: Resolve,
    C: Connect,
{
    let deadline = delivery
        .deadline
        .unwrap_or_else(|| Instant::now() + out.budget.overall);

    let Some(domain) = delivery.domain() else {
        return Outcome {
            host: None,
            results: Vec::new(),
        };
    };

    let hosts = match &delivery.via {
        Some(host) => vec![crate::dns::Target {
            host: host.clone(),
            pref: 0,
        }],
        None => match clocked(out.budget.command, deadline, targets(resolver, domain)).await {
            Err(_) => {
                return Outcome {
                    host: None,
                    results: Outcome::all(
                        &delivery.to,
                        Verdict::Deferred(Reply::ours(
                            451,
                            "4.4.3",
                            format_args!("the MX lookup for {domain} did not finish in time"),
                        )),
                    ),
                };
            }
            Ok(Ok(hosts)) => hosts,
            Ok(Err(e)) => {
                let verdict = if e.is_permanent() {
                    Verdict::Refused(Reply::ours(550, "5.1.2", &e))
                } else {
                    Verdict::Deferred(Reply::ours(451, "4.4.3", &e))
                };
                return Outcome {
                    host: None,
                    results: Outcome::all(&delivery.to, verdict),
                };
            }
        },
    };

    let mut last: Option<Last> = None;
    let mut examined = 0usize;
    let mut missing_names = 0usize;

    'hosts: for target in &hosts {
        if Instant::now() >= deadline {
            warn!(
                domain,
                host = %target.host,
                "the delivery budget ran out before this host was tried"
            );
            break;
        }

        let addrs = match clocked(out.budget.command, deadline, resolver.addrs(&target.host)).await
        {
            Err(_) => {
                examined += 1;
                debug!(host = %target.host, "the address lookup did not finish in time");
                last = Last::keep(last, &target.host, Fail::Timeout("the address lookup"));
                continue;
            }
            Ok(Ok(addrs)) if addrs.is_empty() => {
                examined += 1;
                missing_names += 1;
                debug!(host = %target.host, "the name resolves to nothing");
                last = Last::keep(
                    last,
                    &target.host,
                    Fail::Connect(io::Error::other(format!("{} has no address", target.host))),
                );
                continue;
            }
            Ok(Ok(addrs)) => addrs,
            Ok(Err(e)) => {
                examined += 1;
                debug!(host = %target.host, "no address: {e}");
                if matches!(e, crate::dns::DnsError::NotFound) {
                    missing_names += 1;
                }
                last = Last::keep(
                    last,
                    &target.host,
                    Fail::Connect(io::Error::other(e.to_string())),
                );
                continue;
            }
        };
        examined += 1;

        for addr in usable(&addrs, out.ipv6) {
            if Instant::now() >= deadline {
                break;
            }
            let addr = SocketAddr::new(addr, out.port);

            match attempt(connector, out, delivery, &target.host, addr, deadline, true).await {
                Ok(results) => {
                    return Outcome {
                        host: Some(target.host.clone()),
                        results,
                    };
                }
                Err(Fail::Tls(e)) => {
                    warn!(
                        host = %target.host,
                        %addr,
                        "STARTTLS failed, retrying in plaintext: {e}"
                    );
                    match attempt(
                        connector,
                        out,
                        delivery,
                        &target.host,
                        addr,
                        deadline,
                        false,
                    )
                    .await
                    {
                        Ok(results) => {
                            return Outcome {
                                host: Some(target.host.clone()),
                                results,
                            };
                        }
                        Err(e) => last = Last::keep(last, &target.host, e),
                    }
                }
                Err(Fail::Unsettled(e)) => {
                    warn!(
                        host = %target.host,
                        %addr,
                        "the destination never answered the final dot, so the message \
                         may already have been delivered; deferring rather than \
                         resending it to another host: {e}"
                    );
                    last = Last::keep(last, &target.host, Fail::Unsettled(e));
                    break 'hosts;
                }
                Err(Fail::Spent) => {
                    last = Last::keep(last, &target.host, Fail::Spent);
                    break 'hosts;
                }
                Err(e) => {
                    warn!(host = %target.host, %addr, "attempt failed: {e}");
                    last = Last::keep(last, &target.host, e);
                }
            }
        }
    }

    if examined > 0 && examined == missing_names {
        return Outcome {
            host: None,
            results: Outcome::all(
                &delivery.to,
                Verdict::Refused(Reply::ours(
                    550,
                    "5.1.2",
                    format_args!("no mail exchanger of {domain} has an address"),
                )),
            ),
        };
    }

    let reason = match last {
        Some(Last {
            host,
            fail: Fail::Rejected(reply),
        }) => Reply::ours(
            451,
            "4.4.1",
            format_args!("{host} refused the connection: {reply}"),
        ),
        Some(Last { fail, .. }) => Reply::ours(
            451,
            "4.4.1",
            format_args!("no mail exchanger answered: {fail}"),
        ),
        None => Reply::ours(451, "4.4.1", "no mail exchanger could be tried"),
    };
    Outcome {
        host: None,
        results: Outcome::all(&delivery.to, Verdict::Deferred(reason)),
    }
}

struct Last {
    host: String,
    fail: Fail,
}

impl Last {
    fn keep(current: Option<Last>, host: &str, fail: Fail) -> Option<Last> {
        match current {
            Some(old) if old.fail.worth() > fail.worth() => Some(old),
            _ => Some(Last {
                host: host.to_string(),
                fail,
            }),
        }
    }
}

async fn clocked<F: std::future::Future>(
    want: Duration,
    deadline: Instant,
    task: F,
) -> Result<F::Output, Fail> {
    match left(want, deadline) {
        Ok(budget) => timeout(budget, task).await.map_err(|_| Fail::Spent),
        Err(e) => Err(e),
    }
}

fn usable(addrs: &[IpAddr], ipv6: bool) -> Vec<IpAddr> {
    let v4: Vec<IpAddr> = addrs.iter().copied().filter(IpAddr::is_ipv4).collect();
    if !ipv6 && !v4.is_empty() {
        return v4;
    }
    let v6 = addrs.iter().copied().filter(|a| a.is_ipv6());
    v4.into_iter().chain(v6).collect()
}

#[allow(clippy::too_many_arguments)]
async fn attempt<C>(
    connector: &C,
    out: &Outbound,
    delivery: &Delivery,
    host: &str,
    addr: SocketAddr,
    deadline: Instant,
    may_use_tls: bool,
) -> Result<Vec<RecipientResult>, Fail>
where
    C: Connect,
{
    let stream = match timeout(left(out.budget.connect, deadline)?, connector.connect(addr)).await {
        Err(_) => return Err(Fail::Timeout("the connection")),
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => return Err(Fail::Connect(e)),
    };

    let tls = if may_use_tls {
        out.tls.as_deref()
    } else {
        None
    };
    dialog(stream, host, out, delivery, tls, deadline).await
}

pub async fn dialog<S>(
    stream: S,
    host: &str,
    out: &Outbound,
    delivery: &Delivery,
    tls: Option<&TlsConnector>,
    deadline: Instant,
) -> Result<Vec<RecipientResult>, Fail>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let mut chat = Chat::new(stream, host, out.budget.clone(), deadline);
    chat.greet().await?;
    let caps = chat.ehlo(&out.hostname).await?;

    match tls {
        Some(connector) if caps.starttls => {
            let plain = chat.starttls().await?;
            let name = ServerName::try_from(host.to_string()).map_err(|e| {
                Fail::Tls(format!(
                    "{host} is not a name a certificate can be for: {e}"
                ))
            })?;
            let encrypted =
                match clocked(out.budget.command, deadline, connector.connect(name, plain)).await {
                    Err(_) => return Err(Fail::Tls("the handshake timed out".into())),
                    Ok(Ok(encrypted)) => encrypted,
                    Ok(Err(e)) => return Err(Fail::Tls(e.to_string())),
                };

            let mut chat = Chat::new(encrypted, host, out.budget.clone(), deadline);
            let caps = chat.ehlo(&out.hostname).await?;
            chat.send(&caps, delivery).await
        }
        _ => chat.send(&caps, delivery).await,
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Caps {
    pub starttls: bool,
    pub eight_bit: bool,
    pub size: Option<u64>,
}

struct Chat<S> {
    io: BufReader<S>,
    host: String,
    budget: Budget,
    deadline: Instant,
}

impl<S> Chat<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    fn new(stream: S, host: &str, budget: Budget, deadline: Instant) -> Self {
        Self {
            io: BufReader::new(stream),
            host: host.to_string(),
            budget,
            deadline,
        }
    }

    async fn greet(&mut self) -> Result<(), Fail> {
        let (greeting, _) = self.reply("the greeting", self.budget.command).await?;
        if !greeting.is_positive() {
            return Err(Fail::Rejected(greeting));
        }
        Ok(())
    }

    async fn ehlo(&mut self, me: &str) -> Result<Caps, Fail> {
        self.say(&format!("EHLO {me}")).await?;
        let (reply, lines) = self.reply("EHLO", self.budget.command).await?;
        if !reply.is_positive() {
            return Err(Fail::Rejected(reply));
        }
        Ok(caps_from(&lines))
    }

    async fn starttls(mut self) -> Result<S, Fail> {
        self.say("STARTTLS").await?;
        let (reply, _) = self.reply("STARTTLS", self.budget.command).await?;
        if reply.code != 220 {
            return Err(Fail::Tls(format!("STARTTLS was refused: {reply}")));
        }

        if !self.io.buffer().is_empty() {
            return Err(Fail::Tls(
                "the destination sent data after 220 and before the handshake".into(),
            ));
        }

        Ok(self.io.into_inner())
    }

    async fn send(
        &mut self,
        caps: &Caps,
        delivery: &Delivery,
    ) -> Result<Vec<RecipientResult>, Fail> {
        if let Some(limit) = caps.size.filter(|limit| *limit > 0)
            && delivery.size() > limit
        {
            return Ok(Outcome::all(
                &delivery.to,
                Verdict::Refused(Reply::ours(
                    552,
                    "5.3.4",
                    format_args!(
                        "the destination advertised SIZE {limit} and the message is {} bytes",
                        delivery.size()
                    ),
                )),
            ));
        }

        let eight_bit = delivery.eight_bit && caps.eight_bit;
        if delivery.eight_bit && !caps.eight_bit {
            warn!(
                host = %self.host,
                "the destination does not announce 8BITMIME; sending the message unchanged \
                 anyway, because re-encoding it would invalidate the sender's DKIM signature"
            );
        }

        let from = delivery.from.as_deref().unwrap_or("");
        let mail = if eight_bit {
            format!("MAIL FROM:<{from}> BODY=8BITMIME")
        } else {
            format!("MAIL FROM:<{from}>")
        };
        self.say(&mail).await?;
        let (reply, _) = self.reply("MAIL FROM", self.budget.command).await?;
        if !reply.is_positive() {
            return Ok(Outcome::all(&delivery.to, verdict_of(reply)));
        }

        let mut results = Vec::with_capacity(delivery.to.len());
        for mailbox in &delivery.to {
            self.say(&format!("RCPT TO:<{mailbox}>")).await?;
            let (reply, _) = self.reply("RCPT TO", self.budget.command).await?;
            let verdict = if reply.is_positive() {
                Verdict::Accepted
            } else {
                verdict_of(reply)
            };
            results.push(RecipientResult {
                mailbox: mailbox.clone(),
                verdict,
            });
        }

        if !results.iter().any(|r| r.verdict == Verdict::Accepted) {
            let _ = self.say("QUIT").await;
            return Ok(results);
        }

        if self.deadline.saturating_duration_since(Instant::now()) < self.budget.end_of_data {
            let _ = self.say("QUIT").await;
            return Ok(settle(
                results,
                Verdict::Deferred(Reply::ours(
                    451,
                    "4.4.2",
                    format_args!(
                        "the message's delivery budget has less than {:?} left, which is \
                         not enough to hear whether {} took it",
                        self.budget.end_of_data, self.host
                    ),
                )),
            ));
        }

        self.say("DATA").await?;
        let (reply, _) = self.reply("DATA", self.budget.command).await?;
        if reply.code != 354 {
            let verdict = verdict_of(reply);
            return Ok(settle(results, verdict));
        }

        self.write_body(delivery).await?;

        let (reply, _) = match self
            .reply("the reply to the final dot", self.budget.end_of_data)
            .await
        {
            Ok(got) => got,
            Err(Fail::Spent) => return Err(Fail::Spent),
            Err(e) => return Err(Fail::Unsettled(Box::new(e))),
        };
        let verdict = if reply.is_positive() {
            Verdict::Accepted
        } else {
            verdict_of(reply)
        };

        let _ = self.say("QUIT").await;
        Ok(settle(results, verdict))
    }

    async fn write_body(&mut self, delivery: &Delivery) -> Result<(), Fail> {
        let mut out = Vec::with_capacity(delivery.head.len() + delivery.body.len() + 64);
        let at_line_start = stuff(&delivery.head, true, &mut out);
        stuff(&delivery.body, at_line_start, &mut out);
        if !out.is_empty() && !out.ends_with(b"\r\n") {
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b".\r\n");

        for chunk in out.chunks(BODY_CHUNK_BYTES) {
            let budget = left(self.budget.body, self.deadline)?;
            match timeout(budget, self.io.write_all(chunk)).await {
                Err(_) => return Err(Fail::Timeout("the body to be accepted")),
                Ok(r) => r?,
            }
        }

        let budget = left(self.budget.body, self.deadline)?;
        match timeout(budget, self.io.flush()).await {
            Err(_) => Err(Fail::Timeout("the body to be accepted")),
            Ok(r) => r.map_err(Fail::from),
        }
    }

    async fn say(&mut self, line: &str) -> Result<(), Fail> {
        let budget = left(self.budget.command, self.deadline)?;
        match timeout(budget, async {
            self.io.write_all(line.as_bytes()).await?;
            self.io.write_all(b"\r\n").await?;
            self.io.flush().await
        })
        .await
        {
            Err(_) => Err(Fail::Timeout("a command to be accepted")),
            Ok(r) => r.map_err(Fail::from),
        }
    }

    async fn reply(
        &mut self,
        phase: &'static str,
        want: Duration,
    ) -> Result<(Reply, Vec<String>), Fail> {
        let budget = left(want, self.deadline)?;
        let mut lines: Vec<String> = Vec::new();
        let mut bytes = 0usize;

        loop {
            let line = match timeout(budget, wire::read_line(&mut self.io)).await {
                Err(_) => return Err(Fail::Timeout(phase)),
                Ok(Ok(line)) => line,
                Ok(Err(e)) => return Err(Fail::Wire(e)),
            };

            bytes += line.len();
            if bytes > MAX_REPLY_BYTES {
                return Err(Fail::Garbled(format!(
                    "a reply longer than {MAX_REPLY_BYTES} bytes"
                )));
            }

            let bare = line.as_bytes();
            if bare.len() < 3 || !bare[..3].iter().all(u8::is_ascii_digit) {
                return Err(Fail::Garbled(line));
            }
            let continues = bare.len() > 3 && bare[3] == b'-';
            lines.push(line);
            if !continues {
                break;
            }
        }

        Ok((flatten(&lines), lines))
    }
}

fn flatten(lines: &[String]) -> Reply {
    let code = lines[0][..3].parse::<u16>().unwrap_or(0);
    let mut kept: Vec<String> = Vec::with_capacity(lines.len());
    for line in lines {
        let rest = line.get(4..).unwrap_or("").trim();
        if rest.is_empty() {
            continue;
        }
        kept.push(rest.to_string());
    }

    let enhanced = kept.first().and_then(|first| match first.split_once(' ') {
        Some((head, _)) if is_enhanced(head) => Some(head.to_string()),
        _ if is_enhanced(first) => Some(first.clone()),
        _ => None,
    });
    if let Some(enhanced) = &enhanced {
        for line in &mut kept {
            if let Some(rest) = line.strip_prefix(enhanced.as_str()) {
                *line = rest.trim_start().to_string();
            }
        }
    }
    kept.retain(|line| !line.is_empty());

    Reply {
        code,
        enhanced,
        text: kept.join(" "),
        lines: if kept.len() > 1 { kept } else { Vec::new() },
    }
}

fn is_enhanced(token: &str) -> bool {
    let mut parts = token.split('.');
    let classes = [parts.next(), parts.next(), parts.next()];
    parts.next().is_none()
        && matches!(classes[0], Some("2" | "4" | "5"))
        && classes[1..]
            .iter()
            .all(|p| p.is_some_and(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit())))
}

fn caps_from(lines: &[String]) -> Caps {
    let mut caps = Caps::default();
    for line in lines.iter().skip(1) {
        let keyword = line.get(4..).unwrap_or("").trim();
        let (name, rest) = keyword.split_once(' ').unwrap_or((keyword, ""));
        match name.to_ascii_uppercase().as_str() {
            "STARTTLS" => caps.starttls = true,
            "8BITMIME" => caps.eight_bit = true,
            "SIZE" => caps.size = Some(rest.trim().parse().unwrap_or(0)),
            _ => {}
        }
    }
    caps
}

fn verdict_of(reply: Reply) -> Verdict {
    if reply.is_permanent() {
        Verdict::Refused(reply)
    } else {
        Verdict::Deferred(reply)
    }
}

fn settle(results: Vec<RecipientResult>, verdict: Verdict) -> Vec<RecipientResult> {
    results
        .into_iter()
        .map(|r| match r.verdict {
            Verdict::Accepted => RecipientResult {
                verdict: verdict.clone(),
                ..r
            },
            _ => r,
        })
        .collect()
}

fn stuff(src: &[u8], at_line_start: bool, out: &mut Vec<u8>) -> bool {
    let mut at_line_start = at_line_start;
    for byte in src {
        if at_line_start && *byte == b'.' {
            out.push(b'.');
        }
        out.push(*byte);
        at_line_start = *byte == b'\n';
    }
    at_line_start
}

fn left(want: Duration, deadline: Instant) -> Result<Duration, Fail> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(Fail::Spent);
    }
    Ok(want.min(remaining))
}

pub trait Relay {
    fn deliver(&self, delivery: Delivery) -> impl std::future::Future<Output = Outcome> + Send;

    fn ptr(&self, ip: IpAddr) -> impl std::future::Future<Output = Option<String>> + Send;

    fn verify(
        &self,
        probe: Probe<'_>,
        budget: crate::auth::Budget,
    ) -> impl std::future::Future<Output = Auth> + Send;
}

pub struct Direct<R> {
    pub resolver: R,
    pub out: Outbound,
    pub verifier: Option<Verifier>,
}

impl<R> Direct<R> {
    pub fn new(resolver: R, out: Outbound, verifier: Option<Verifier>) -> Self {
        Self {
            resolver,
            out,
            verifier,
        }
    }
}

impl<R> Relay for Direct<R>
where
    R: Resolve + Sync,
{
    async fn deliver(&self, delivery: Delivery) -> Outcome {
        deliver(&self.resolver, &Tcp, &self.out, &delivery).await
    }

    async fn ptr(&self, ip: IpAddr) -> Option<String> {
        self.resolver.ptr(ip).await.ok()
    }

    async fn verify(&self, probe: Probe<'_>, budget: crate::auth::Budget) -> Auth {
        match &self.verifier {
            Some(verifier) => verifier.check(probe, budget).await,
            None => Auth::not_checked(),
        }
    }
}

#[doc(hidden)]
#[derive(Debug, Default, Clone)]
pub struct Blackhole;

impl Relay for Blackhole {
    async fn deliver(&self, delivery: Delivery) -> Outcome {
        Outcome {
            host: Some("blackhole.invalid".to_string()),
            results: Outcome::all(&delivery.to, Verdict::Accepted),
        }
    }

    async fn ptr(&self, _ip: IpAddr) -> Option<String> {
        None
    }

    async fn verify(&self, _probe: Probe<'_>, _budget: crate::auth::Budget) -> Auth {
        Auth::not_checked()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::{DnsError, Table};

    #[test]
    fn a_multi_line_reply_keeps_its_lines() {
        let reply = flatten(&[
            "550-5.1.1 The email account that you tried to reach does not exist.".to_string(),
            "550-5.1.1 Please try double-checking the recipient's email address".to_string(),
            "550 5.1.1 for typos or unnecessary spaces.".to_string(),
        ]);

        assert_eq!(reply.code, 550);
        assert_eq!(reply.enhanced.as_deref(), Some("5.1.1"));
        assert_eq!(
            reply.lines,
            vec![
                "The email account that you tried to reach does not exist.",
                "Please try double-checking the recipient's email address",
                "for typos or unnecessary spaces.",
            ],
            "the enhanced code is lifted off every line it repeats on, and what is \
             left is the destination's three sentences"
        );
    }

    #[test]
    fn a_multi_line_reply_goes_back_out_as_continuation_lines() {
        let reply = flatten(&[
            "550-5.1.1 does not exist.".to_string(),
            "550 5.1.1 check for typos.".to_string(),
        ]);

        assert_eq!(
            reply.wire(),
            vec!["550-5.1.1 does not exist.", "550 5.1.1 check for typos."],
            "the last line is the only one with a space after the code, which is \
             what tells the sender the reply has ended"
        );
    }

    #[test]
    fn a_reply_that_lost_its_lines_is_not_the_same_reply() {
        let kept = flatten(&[
            "550-5.1.1 does not exist.".to_string(),
            "550 5.1.1 check for typos.".to_string(),
        ]);
        let forgotten = Reply {
            lines: Vec::new(),
            ..kept.clone()
        };

        assert_ne!(
            kept.wire(),
            forgotten.wire(),
            "the premise: these two put different bytes on the wire"
        );
        assert_ne!(
            kept, forgotten,
            "so they are not the same reply, and equality has to be able to \
             tell a test that"
        );
    }

    #[test]
    fn a_single_line_reply_is_still_one_line() {
        assert_eq!(
            Reply::ours(451, "4.4.1", "nobody answered").wire(),
            vec!["451 4.4.1 mxhop: nobody answered"]
        );
    }

    #[test]
    fn a_reply_line_longer_than_the_rfc_allows_is_cut() {
        let long = format!("550 5.7.1 {}", "x".repeat(900));
        let reply = flatten(&[long]);

        for line in reply.wire() {
            assert!(
                line.len() + 2 <= 512,
                "{} octets, and the CRLF still has to fit",
                line.len()
            );
        }
    }

    use std::collections::{BTreeMap, VecDeque};
    use std::sync::Mutex;
    use tokio::io::duplex;
    use tokio_rustls::TlsAcceptor;
    use tokio_rustls::rustls::ServerConfig;

    trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
    impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

    #[derive(Debug, Default, Clone)]
    struct Log {
        commands: Vec<String>,
        body: Option<Vec<u8>>,
        raw: Option<Vec<u8>>,
        encrypted: bool,
    }

    #[derive(Clone)]
    struct Mta {
        greeting: String,
        keywords: Vec<String>,
        mail: String,
        rcpt: Vec<String>,
        data: String,
        dot: String,
        silent: bool,
        tls: Option<Arc<TlsAcceptor>>,
        inject_after_starttls: bool,
        stall_after_starttls: bool,
        stall_at_dot: bool,
        resumed: bool,
        read_delay: Option<Duration>,
    }

    impl Default for Mta {
        fn default() -> Self {
            Self {
                greeting: "220 mx.example.com ESMTP".into(),
                keywords: vec![
                    "SIZE 10485760".into(),
                    "8BITMIME".into(),
                    "PIPELINING".into(),
                ],
                mail: "250 2.1.0 ok".into(),
                rcpt: vec!["250 2.1.5 ok".into()],
                data: "354 go ahead".into(),
                dot: "250 2.0.0 queued as 4abc".into(),
                silent: false,
                tls: None,
                inject_after_starttls: false,
                stall_after_starttls: false,
                stall_at_dot: false,
                resumed: false,
                read_delay: None,
            }
        }
    }

    impl Mta {
        fn keywords(mut self, keywords: &[&str]) -> Self {
            self.keywords = keywords.iter().map(|k| (*k).to_string()).collect();
            self
        }

        fn rcpt(mut self, replies: &[&str]) -> Self {
            self.rcpt = replies.iter().map(|r| (*r).to_string()).collect();
            self
        }

        async fn serve(self, stream: Box<dyn Stream>, log: Arc<Mutex<Log>>) {
            if self.silent {
                tokio::time::sleep(Duration::from_secs(30)).await;
                return;
            }

            let mut io = BufReader::new(stream);
            if !self.resumed {
                let _ = say(&mut io, &self.greeting).await;
            }
            let mut rcpts = 0usize;

            loop {
                let Ok(line) = wire::read_line(&mut io).await else {
                    return;
                };
                log.lock().unwrap().commands.push(line.clone());
                let word = line.split(' ').next().unwrap_or("").to_ascii_uppercase();

                match word.as_str() {
                    "EHLO" => {
                        let mut reply = String::new();
                        if self.keywords.is_empty() {
                            reply.push_str("250 mx.example.com greets you\r\n");
                        } else {
                            reply.push_str("250-mx.example.com greets you\r\n");
                            for (i, keyword) in self.keywords.iter().enumerate() {
                                let sep = if i + 1 == self.keywords.len() {
                                    ' '
                                } else {
                                    '-'
                                };
                                reply.push_str(&format!("250{sep}{keyword}\r\n"));
                            }
                        }
                        let _ = io.write_all(reply.as_bytes()).await;
                        let _ = io.flush().await;
                    }
                    "STARTTLS" => {
                        let Some(acceptor) = self.tls.clone() else {
                            let _ = say(&mut io, "502 5.5.1 not supported").await;
                            continue;
                        };
                        let _ = say(&mut io, "220 2.0.0 go ahead").await;
                        if self.inject_after_starttls {
                            let _ = say(&mut io, "250 injected").await;
                        }
                        if self.stall_after_starttls {
                            tokio::time::sleep(Duration::from_secs(30)).await;
                            return;
                        }
                        let Ok(encrypted) = acceptor.accept(io.into_inner()).await else {
                            return;
                        };
                        log.lock().unwrap().encrypted = true;
                        let mut again = self.clone();
                        again.tls = None;
                        again.resumed = true;
                        Box::pin(again.serve(Box::new(encrypted), log)).await;
                        return;
                    }
                    "MAIL" => {
                        let _ = say(&mut io, &self.mail).await;
                    }
                    "RCPT" => {
                        let reply = self
                            .rcpt
                            .get(rcpts)
                            .or_else(|| self.rcpt.last())
                            .cloned()
                            .unwrap_or_else(|| "250 ok".into());
                        rcpts += 1;
                        let _ = say(&mut io, &reply).await;
                    }
                    "DATA" => {
                        let _ = say(&mut io, &self.data).await;
                        if !self.data.starts_with("354") {
                            continue;
                        }
                        let mut raw = Vec::new();
                        let read = read_body_recording(&mut io, &mut raw, self.read_delay).await;
                        {
                            let mut log = log.lock().unwrap();
                            log.raw = Some(raw);
                            log.body = read;
                        }
                        if self.stall_at_dot {
                            tokio::time::sleep(Duration::from_secs(30)).await;
                            return;
                        }
                        let _ = say(&mut io, &self.dot).await;
                    }
                    "QUIT" => {
                        let _ = say(&mut io, "221 2.0.0 bye").await;
                        return;
                    }
                    "RSET" => {
                        let _ = say(&mut io, "250 2.0.0 ok").await;
                    }
                    _ => {
                        let _ = say(&mut io, "500 5.5.2 what?").await;
                    }
                }
            }
        }
    }

    async fn say<W>(io: &mut W, line: &str) -> io::Result<()>
    where
        W: AsyncWrite + Unpin,
    {
        io.write_all(line.as_bytes()).await?;
        io.write_all(b"\r\n").await?;
        io.flush().await
    }

    async fn read_body_recording<R>(
        io: &mut R,
        raw: &mut Vec<u8>,
        per_line: Option<Duration>,
    ) -> Option<Vec<u8>>
    where
        R: tokio::io::AsyncBufRead + Unpin,
    {
        use tokio::io::AsyncReadExt;
        let mut unstuffed = Vec::new();
        loop {
            if let Some(delay) = per_line {
                tokio::time::sleep(delay).await;
            }
            let mut line = Vec::new();
            loop {
                let mut byte = [0u8; 1];
                if io.read_exact(&mut byte).await.is_err() {
                    return None;
                }
                line.push(byte[0]);
                if line.ends_with(b"\r\n") {
                    break;
                }
            }
            raw.extend_from_slice(&line);
            let content = &line[..line.len() - 2];
            if content == b"." {
                return Some(unstuffed);
            }
            let content = if content.first() == Some(&b'.') {
                &content[1..]
            } else {
                content
            };
            unstuffed.extend_from_slice(content);
            unstuffed.extend_from_slice(b"\r\n");
        }
    }

    #[derive(Clone)]
    enum Script {
        Serve(Mta),
        Refuse,
    }

    struct Pipes {
        scripts: Mutex<BTreeMap<IpAddr, VecDeque<Script>>>,
        logs: Mutex<Vec<(IpAddr, Arc<Mutex<Log>>)>>,
    }

    impl Pipes {
        fn new(scripts: &[(&str, Script)]) -> Self {
            let mut map: BTreeMap<IpAddr, VecDeque<Script>> = BTreeMap::new();
            for (addr, script) in scripts {
                map.entry(addr.parse().expect("an address"))
                    .or_default()
                    .push_back(script.clone());
            }
            Self {
                scripts: Mutex::new(map),
                logs: Mutex::new(Vec::new()),
            }
        }

        fn connections(&self) -> Vec<(IpAddr, Log)> {
            self.logs
                .lock()
                .unwrap()
                .iter()
                .map(|(addr, log)| (*addr, log.lock().unwrap().clone()))
                .collect()
        }
    }

    impl Connect for Pipes {
        type Stream = tokio::io::DuplexStream;

        async fn connect(&self, addr: SocketAddr) -> io::Result<Self::Stream> {
            let script = self
                .scripts
                .lock()
                .unwrap()
                .get_mut(&addr.ip())
                .and_then(VecDeque::pop_front);

            match script {
                None | Some(Script::Refuse) => Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    format!("nothing is listening on {addr}"),
                )),
                Some(Script::Serve(mta)) => {
                    let log = Arc::new(Mutex::new(Log::default()));
                    self.logs
                        .lock()
                        .unwrap()
                        .push((addr.ip(), Arc::clone(&log)));
                    let (client, server) = duplex(256 * 1024);
                    tokio::spawn(mta.serve(Box::new(server), log));
                    Ok(client)
                }
            }
        }
    }

    #[derive(Default, Clone)]
    struct Capture(Arc<std::sync::Mutex<Vec<Delivery>>>);

    impl Relay for Capture {
        async fn deliver(&self, delivery: Delivery) -> Outcome {
            let results = Outcome::all(&delivery.to, Verdict::Accepted);
            self.0.lock().unwrap().push(delivery);
            Outcome {
                host: Some("mx.gmail.test".to_string()),
                results,
            }
        }

        async fn ptr(&self, _ip: IpAddr) -> Option<String> {
            Some("sender.test".to_string())
        }

        async fn verify(&self, _probe: Probe<'_>, _budget: crate::auth::Budget) -> Auth {
            Auth::not_checked()
        }
    }

    struct Slow {
        inner: Table,
        delay: Duration,
    }

    impl Resolve for Slow {
        async fn mx(&self, domain: &str) -> Result<Vec<crate::dns::Target>, DnsError> {
            tokio::time::sleep(self.delay).await;
            Resolve::mx(&self.inner, domain).await
        }

        async fn addrs(&self, host: &str) -> Result<Vec<IpAddr>, DnsError> {
            tokio::time::sleep(self.delay).await;
            Resolve::addrs(&self.inner, host).await
        }

        async fn ptr(&self, ip: IpAddr) -> Result<String, DnsError> {
            tokio::time::sleep(self.delay).await;
            Resolve::ptr(&self.inner, ip).await
        }
    }

    fn to(addresses: &[&str]) -> Vec<Mailbox> {
        addresses
            .iter()
            .map(|a| Mailbox::parse(a).expect("a mailbox"))
            .collect()
    }

    const HEAD: &[u8] = b"Received: by mx.test; Thu, 6 Nov 2026 00:00:00 +0000\r\n";

    fn message(body: &[u8]) -> Delivery {
        Delivery::new(
            Some("sender@elsewhere.test".into()),
            to(&["hi@example.com"]),
            HEAD.to_vec(),
            Arc::from(body),
        )
    }

    fn outbound() -> Outbound {
        Outbound {
            hostname: "mx.test".into(),
            ipv6: false,
            tls: None,
            port: 2525,
            budget: Budget {
                connect: Duration::from_secs(2),
                command: Duration::from_secs(2),
                body: Duration::from_secs(2),
                end_of_data: Duration::from_secs(2),
                overall: Duration::from_secs(10),
            },
        }
    }

    fn two_exchangers() -> Table {
        Table::default()
            .mx(
                "example.com",
                &[(20, "mx2.example.com"), (10, "mx1.example.com")],
            )
            .addr("mx1.example.com", "203.0.113.1".parse().unwrap())
            .addr("mx2.example.com", "203.0.113.2".parse().unwrap())
    }

    fn verdicts(outcome: &Outcome) -> Vec<String> {
        outcome
            .results
            .iter()
            .map(|r| match &r.verdict {
                Verdict::Accepted => format!("{}: accepted", r.mailbox),
                Verdict::Refused(reply) => format!("{}: refused {reply}", r.mailbox),
                Verdict::Deferred(reply) => format!("{}: deferred {reply}", r.mailbox),
            })
            .collect()
    }

    #[tokio::test]
    async fn mx_records_are_tried_in_preference_order() {
        let pipes = Pipes::new(&[
            ("203.0.113.1", Script::Serve(Mta::default())),
            ("203.0.113.2", Script::Serve(Mta::default())),
        ]);

        let outcome = deliver(&two_exchangers(), &pipes, &outbound(), &message(b"hi\r\n")).await;

        assert_eq!(outcome.host.as_deref(), Some("mx1.example.com"));
        assert_eq!(
            pipes.connections().len(),
            1,
            "the better exchanger answered, so there was nothing else to try"
        );
    }

    #[tokio::test]
    async fn a_domain_without_mx_falls_back_to_its_own_address() {
        let table = Table::default().addr("example.com", "203.0.113.9".parse().unwrap());
        let pipes = Pipes::new(&[("203.0.113.9", Script::Serve(Mta::default()))]);

        let outcome = deliver(&table, &pipes, &outbound(), &message(b"hi\r\n")).await;

        assert_eq!(outcome.host.as_deref(), Some("example.com"));
        assert_eq!(verdicts(&outcome), vec!["hi@example.com: accepted"]);
    }

    #[tokio::test]
    async fn a_null_mx_is_a_permanent_failure() {
        let table = Table::default().mx("example.com", &[(0, ".")]);
        let pipes = Pipes::new(&[]);

        let outcome = deliver(&table, &pipes, &outbound(), &message(b"hi\r\n")).await;

        assert!(
            matches!(outcome.results[0].verdict, Verdict::Refused(_)),
            "{:?}",
            verdicts(&outcome)
        );
        assert!(pipes.connections().is_empty(), "and nothing was dialled");
    }

    #[tokio::test]
    async fn a_domain_with_neither_an_exchanger_nor_an_address_is_refused() {
        let table = Table::default();

        let outcome = deliver(&table, &Pipes::new(&[]), &outbound(), &message(b"hi\r\n")).await;

        assert!(
            matches!(outcome.results[0].verdict, Verdict::Refused(_)),
            "{:?}",
            verdicts(&outcome)
        );
    }

    #[tokio::test]
    async fn a_via_delivery_asks_for_no_mx_at_all() {
        let table = Table::default()
            .mx_error("example.com", DnsError::Failed("never ask me".into()))
            .addr("aspmx.l.google.test", "203.0.113.9".parse().unwrap());
        let pipes = Pipes::new(&[("203.0.113.9", Script::Serve(Mta::default()))]);

        let outcome = deliver(
            &table,
            &pipes,
            &outbound(),
            &message(b"hi\r\n").via(Some("aspmx.l.google.test")),
        )
        .await;

        assert_eq!(outcome.host.as_deref(), Some("aspmx.l.google.test"));
        assert!(
            matches!(outcome.results[0].verdict, Verdict::Accepted),
            "{:?}",
            verdicts(&outcome)
        );
    }

    #[tokio::test]
    async fn the_same_delivery_without_a_via_defers_on_the_mx_lookup() {
        let table = Table::default()
            .mx_error("example.com", DnsError::Failed("never ask me".into()))
            .addr("aspmx.l.google.test", "203.0.113.9".parse().unwrap());
        let pipes = Pipes::new(&[("203.0.113.9", Script::Serve(Mta::default()))]);

        let outcome = deliver(&table, &pipes, &outbound(), &message(b"hi\r\n")).await;

        assert!(
            matches!(outcome.results[0].verdict, Verdict::Deferred(_)),
            "{:?}",
            verdicts(&outcome)
        );
    }

    #[tokio::test]
    async fn a_via_host_with_no_address_is_refused_and_names_the_domain() {
        let table = Table::default().addr_error("typo.l.google.test", DnsError::NotFound);

        let outcome = deliver(
            &table,
            &Pipes::new(&[]),
            &outbound(),
            &message(b"hi\r\n").via(Some("typo.l.google.test")),
        )
        .await;

        assert!(
            matches!(outcome.results[0].verdict, Verdict::Refused(_)),
            "{:?}",
            verdicts(&outcome)
        );
    }

    #[tokio::test]
    async fn an_exchanger_whose_address_will_not_resolve_is_only_deferred() {
        let table = Table::default()
            .mx("example.com", &[(10, "mx1.example.com")])
            .addr_error("mx1.example.com", DnsError::Failed("timeout".into()));

        let outcome = deliver(&table, &Pipes::new(&[]), &outbound(), &message(b"hi\r\n")).await;

        assert!(
            matches!(outcome.results[0].verdict, Verdict::Deferred(_)),
            "{:?}",
            verdicts(&outcome)
        );
    }

    #[tokio::test]
    async fn a_dead_exchanger_is_deferred_rather_than_refused() {
        let table = Table::default()
            .mx("example.com", &[(10, "mx1.example.com")])
            .addr("mx1.example.com", "203.0.113.1".parse().unwrap());
        let pipes = Pipes::new(&[("203.0.113.1", Script::Refuse)]);

        let outcome = deliver(&table, &pipes, &outbound(), &message(b"hi\r\n")).await;

        assert!(
            matches!(outcome.results[0].verdict, Verdict::Deferred(_)),
            "{:?}",
            verdicts(&outcome)
        );
    }

    #[tokio::test]
    async fn a_resolver_that_does_not_answer_defers_rather_than_bounces() {
        let table = Table::default().mx_error("example.com", DnsError::Failed("SERVFAIL".into()));

        let outcome = deliver(&table, &Pipes::new(&[]), &outbound(), &message(b"hi\r\n")).await;

        assert!(
            matches!(outcome.results[0].verdict, Verdict::Deferred(_)),
            "a resolver of ours being broken must not bounce other people's \
             mail: {:?}",
            verdicts(&outcome)
        );
    }

    #[tokio::test]
    async fn a_host_that_refuses_the_connection_is_skipped_for_the_next() {
        let pipes = Pipes::new(&[
            ("203.0.113.1", Script::Refuse),
            ("203.0.113.2", Script::Serve(Mta::default())),
        ]);

        let outcome = deliver(&two_exchangers(), &pipes, &outbound(), &message(b"hi\r\n")).await;

        assert_eq!(
            outcome.host.as_deref(),
            Some("mx2.example.com"),
            "{:?}",
            verdicts(&outcome)
        );
        assert_eq!(verdicts(&outcome), vec!["hi@example.com: accepted"]);
    }

    #[tokio::test]
    async fn the_body_goes_out_byte_for_byte_with_dots_restuffed() {
        let body: &[u8] =
            b"Subject: caf\xc3\xa9\r\n\r\n.hidden\r\n..already\r\ntrailing  \r\n\xff\xfe\r\n";
        let pipes = Pipes::new(&[("203.0.113.1", Script::Serve(Mta::default()))]);

        let outcome = deliver(&two_exchangers(), &pipes, &outbound(), &message(body)).await;
        assert_eq!(verdicts(&outcome), vec!["hi@example.com: accepted"]);

        let connections = pipes.connections();
        let log = &connections[0].1;
        let received = log.body.as_ref().expect("a body");
        assert_eq!(
            received,
            &[HEAD, body].concat(),
            "the round trip changed the message"
        );

        let raw = log.raw.as_ref().expect("the wire bytes");
        assert!(
            raw.windows(10).any(|w| w == b"..hidden\r\n"),
            "a line beginning with a dot has to be stuffed on the way out, or \
             the destination reads it as the end of the message"
        );
        assert!(
            raw.windows(12).any(|w| w == b"...already\r\n"),
            "and a line beginning with two dots gets a third"
        );
    }

    #[tokio::test]
    async fn each_recipient_gets_its_own_verdict() {
        let mta = Mta::default().rcpt(&[
            "550 5.1.1 <a@example.com>: no such user",
            "250 2.1.5 ok",
            "452 4.2.2 over quota",
        ]);
        let pipes = Pipes::new(&[("203.0.113.1", Script::Serve(mta))]);
        let delivery = Delivery::new(
            Some("sender@elsewhere.test".into()),
            to(&["a@example.com", "b@example.com", "c@example.com"]),
            Vec::new(),
            Arc::from(b"hi\r\n".as_slice()),
        );

        let outcome = deliver(&two_exchangers(), &pipes, &outbound(), &delivery).await;

        assert_eq!(
            verdicts(&outcome),
            vec![
                "a@example.com: refused 550 5.1.1 <a@example.com>: no such user",
                "b@example.com: accepted",
                "c@example.com: deferred 452 4.2.2 over quota",
            ],
            "and each one carries the destination's own words"
        );
        assert!(
            pipes.connections()[0].1.body.is_some(),
            "one refusal must not stop the message reaching the recipient that \
             was accepted"
        );
    }

    #[tokio::test]
    async fn a_multi_line_reply_is_flattened_into_one() {
        let mta = Mta::default().rcpt(&[
            "550-5.7.1 [203.0.113.1] Our system has detected that this message is\r\n\
             550-5.7.1 not RFC 5322 compliant. To review our policies, see\r\n\
             550 5.7.1 https://support.google.com/mail/answer/81126",
        ]);
        let pipes = Pipes::new(&[("203.0.113.1", Script::Serve(mta))]);

        let outcome = deliver(&two_exchangers(), &pipes, &outbound(), &message(b"hi\r\n")).await;

        let Verdict::Refused(reply) = &outcome.results[0].verdict else {
            panic!("expected a refusal, got {:?}", verdicts(&outcome));
        };
        assert_eq!(reply.code, 550);
        assert_eq!(reply.enhanced.as_deref(), Some("5.7.1"));
        assert!(
            reply.to_string().contains("support.google.com"),
            "the part of a refusal that says what to do about it is the part \
             worth relaying: {reply}"
        );
        assert!(
            !reply.text.contains('\n') && !reply.text.contains('\r'),
            "it goes inside one reply line of ours, so it cannot carry line \
             endings: {reply:?}"
        );
    }

    #[tokio::test]
    async fn a_size_advertised_below_the_message_is_refused_before_the_body() {
        let mta = Mta::default().keywords(&["SIZE 100", "8BITMIME"]);
        let pipes = Pipes::new(&[("203.0.113.1", Script::Serve(mta))]);
        let body = vec![b'x'; 4096];

        let outcome = deliver(&two_exchangers(), &pipes, &outbound(), &message(&body)).await;

        assert!(
            matches!(outcome.results[0].verdict, Verdict::Refused(_)),
            "{:?}",
            verdicts(&outcome)
        );
        let commands = pipes.connections()[0].1.commands.clone();
        assert!(
            !commands.iter().any(|c| c == "DATA"),
            "the destination said it will not take this; sending it anyway is \
             four kilobytes spent to be told so: {commands:?}"
        );
    }

    #[tokio::test]
    async fn a_zero_size_is_no_stated_limit_rather_than_a_limit_of_nothing() {
        let mta = Mta::default().keywords(&["SIZE 0"]);
        let pipes = Pipes::new(&[("203.0.113.1", Script::Serve(mta))]);

        let outcome = deliver(&two_exchangers(), &pipes, &outbound(), &message(b"hi\r\n")).await;

        assert_eq!(verdicts(&outcome), vec!["hi@example.com: accepted"]);
    }

    #[tokio::test]
    async fn missing_8bitmime_does_not_re_encode() {
        let mta = Mta::default().keywords(&["SIZE 10485760", "PIPELINING"]);
        let pipes = Pipes::new(&[("203.0.113.1", Script::Serve(mta))]);
        let body: &[u8] = b"Subject: caf\xc3\xa9\r\n\r\n\xd0\xbf\xd1\x80\xd0\xb8\xd0\xb2\r\n";

        let outcome = deliver(&two_exchangers(), &pipes, &outbound(), &message(body)).await;

        assert_eq!(verdicts(&outcome), vec!["hi@example.com: accepted"]);
        let log = pipes.connections()[0].1.clone();
        assert_eq!(
            log.body.as_deref(),
            Some([HEAD, body].concat().as_slice()),
            "re-encoding would rewrite the bytes the sender signed, which is \
             worse than breaking a rule no deployed MTA enforces"
        );
        assert!(
            log.commands
                .iter()
                .any(|c| c == "MAIL FROM:<sender@elsewhere.test>"),
            "and BODY=8BITMIME must not be claimed to a host that did not \
             offer it: {:?}",
            log.commands
        );
    }

    #[tokio::test]
    async fn eight_bitmime_is_announced_when_the_destination_offers_it() {
        let pipes = Pipes::new(&[("203.0.113.1", Script::Serve(Mta::default()))]);

        deliver(
            &two_exchangers(),
            &pipes,
            &outbound(),
            &message(b"caf\xc3\xa9\r\n"),
        )
        .await;

        let commands = pipes.connections()[0].1.commands.clone();
        assert!(
            commands.iter().any(|c| c.ends_with("BODY=8BITMIME")),
            "a destination that offers it has to be told, or it is entitled to \
             assume 7-bit and convert the message itself: {commands:?}"
        );
    }

    #[tokio::test]
    async fn a_silent_host_hits_the_phase_timeout_not_the_total() {
        let mta = Mta {
            silent: true,
            ..Mta::default()
        };
        let pipes = Pipes::new(&[
            ("203.0.113.1", Script::Serve(mta)),
            ("203.0.113.2", Script::Serve(Mta::default())),
        ]);
        let mut out = outbound();
        out.budget.command = Duration::from_millis(80);
        out.budget.overall = Duration::from_secs(30);

        let started = Instant::now();
        let outcome = deliver(&two_exchangers(), &pipes, &out, &message(b"hi\r\n")).await;

        assert!(
            started.elapsed() < Duration::from_secs(5),
            "a destination that never greets must cost one phase, not the whole \
             message's budget — took {:?}",
            started.elapsed()
        );
        assert_eq!(
            outcome.host.as_deref(),
            Some("mx2.example.com"),
            "and the next exchanger still gets its turn: {:?}",
            verdicts(&outcome)
        );
    }

    #[tokio::test]
    async fn the_overall_budget_ends_the_attempt() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::time::sleep(Duration::from_secs(30)).await;
                drop(stream);
            }
        });

        let table = Table::default()
            .mx("example.com", &[(10, "mx1.example.com")])
            .addr("mx1.example.com", "127.0.0.1".parse().unwrap());
        let mut out = outbound();
        out.port = port;
        out.budget.command = Duration::from_secs(30);
        out.budget.overall = Duration::from_millis(200);

        let started = Instant::now();
        let outcome = deliver(&table, &Tcp, &out, &message(b"hi\r\n")).await;

        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the inbound sender is holding its own connection open while we do \
             this; 200ms of budget has to mean 200ms — took {:?}",
            started.elapsed()
        );
        assert!(
            matches!(outcome.results[0].verdict, Verdict::Deferred(_)),
            "nothing was settled, so nothing may be refused: {:?}",
            verdicts(&outcome)
        );
    }

    #[tokio::test]
    async fn ipv6_is_left_alone_unless_it_is_asked_for() {
        let table = Table::default()
            .mx("example.com", &[(10, "mx1.example.com")])
            .addr("mx1.example.com", "2001:db8::1".parse().unwrap())
            .addr("mx1.example.com", "203.0.113.1".parse().unwrap());
        let pipes = Pipes::new(&[
            ("203.0.113.1", Script::Refuse),
            ("2001:db8::1", Script::Serve(Mta::default())),
        ]);

        let outcome = deliver(&table, &pipes, &outbound(), &message(b"hi\r\n")).await;

        assert!(
            matches!(outcome.results[0].verdict, Verdict::Deferred(_)),
            "{:?}",
            verdicts(&outcome)
        );
        assert!(
            pipes.connections().is_empty(),
            "the IPv6 address was dialled: {:?}",
            pipes.connections()
        );
    }

    #[tokio::test]
    async fn a_host_with_only_ipv6_is_still_tried() {
        let table = Table::default()
            .mx("example.com", &[(10, "mx1.example.com")])
            .addr("mx1.example.com", "2001:db8::1".parse().unwrap());
        let pipes = Pipes::new(&[("2001:db8::1", Script::Serve(Mta::default()))]);

        let outcome = deliver(&table, &pipes, &outbound(), &message(b"hi\r\n")).await;

        assert_eq!(verdicts(&outcome), vec!["hi@example.com: accepted"]);
    }

    fn tls_pair() -> (Arc<TlsAcceptor>, Arc<TlsConnector>) {
        use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};

        let signed = rcgen::generate_simple_self_signed(vec!["mx1.example.com".to_string()])
            .expect("a certificate");
        let cert = CertificateDer::from(signed.cert.der().to_vec());
        let key = PrivateKeyDer::try_from(signed.signing_key.serialize_der()).expect("a key");

        let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
        let server = ServerConfig::builder_with_provider(Arc::clone(&provider))
            .with_safe_default_protocol_versions()
            .expect("the default versions")
            .with_no_client_auth()
            .with_single_cert(vec![cert.clone()], key)
            .expect("a server config");

        let mut roots = RootCertStore::empty();
        roots.add(cert).expect("a trusted root");
        let client = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("the default versions")
            .with_root_certificates(roots)
            .with_no_client_auth();

        (
            Arc::new(TlsAcceptor::from(Arc::new(server))),
            Arc::new(TlsConnector::from(Arc::new(client))),
        )
    }

    #[tokio::test]
    async fn starttls_is_used_when_offered_and_skipped_when_not() {
        let (acceptor, connector) = tls_pair();

        let offering = Mta {
            tls: Some(acceptor),
            ..Mta::default().keywords(&["SIZE 10485760", "8BITMIME", "STARTTLS"])
        };
        let pipes = Pipes::new(&[("203.0.113.1", Script::Serve(offering))]);
        let mut out = outbound();
        out.tls = Some(connector);

        let outcome = deliver(&two_exchangers(), &pipes, &out, &message(b"hi\r\n")).await;
        assert_eq!(verdicts(&outcome), vec!["hi@example.com: accepted"]);

        let log = pipes.connections()[0].1.clone();
        assert!(log.encrypted, "the handshake should have happened");
        assert_eq!(
            log.commands
                .iter()
                .filter(|c| c.starts_with("EHLO"))
                .count(),
            2,
            "RFC 3207 §4.2: EHLO is asked again inside TLS, because what was \
             said in the clear does not count: {:?}",
            log.commands
        );
        assert!(
            log.body.is_some(),
            "and the message went over the encrypted session"
        );

        let pipes = Pipes::new(&[("203.0.113.1", Script::Serve(Mta::default()))]);
        let outcome = deliver(&two_exchangers(), &pipes, &out, &message(b"hi\r\n")).await;

        assert_eq!(verdicts(&outcome), vec!["hi@example.com: accepted"]);
        let log = pipes.connections()[0].1.clone();
        assert!(!log.encrypted);
        assert!(
            !log.commands.iter().any(|c| c == "STARTTLS"),
            "asking for an extension that was not advertised is how a session \
             gets dropped: {:?}",
            log.commands
        );
    }

    #[tokio::test]
    async fn a_failed_handshake_falls_back_to_plaintext() {
        let (acceptor, _) = tls_pair();
        let broken = Mta {
            tls: Some(acceptor),
            ..Mta::default().keywords(&["SIZE 10485760", "STARTTLS"])
        };

        let pipes = Pipes::new(&[
            ("203.0.113.1", Script::Serve(broken.clone())),
            ("203.0.113.1", Script::Serve(broken)),
        ]);
        let mut out = outbound();
        out.tls = Some(Arc::new(webpki_connector()));

        let outcome = deliver(&two_exchangers(), &pipes, &out, &message(b"hi\r\n")).await;

        assert_eq!(verdicts(&outcome), vec!["hi@example.com: accepted"]);
        let connections = pipes.connections();
        assert_eq!(connections.len(), 2, "the handshake consumed the first one");
        assert!(
            connections[0].1.commands.iter().any(|c| c == "STARTTLS"),
            "{:?}",
            connections[0].1.commands
        );
        assert!(
            !connections[1].1.commands.iter().any(|c| c == "STARTTLS"),
            "the second attempt has to stay in plaintext, or it fails the same \
             way forever: {:?}",
            connections[1].1.commands
        );
        assert!(
            connections[1].1.body.is_some() && !connections[1].1.encrypted,
            "and the message goes over it unencrypted"
        );
    }

    #[tokio::test]
    async fn a_line_sent_before_the_handshake_is_not_read_back_as_the_servers_words() {
        let (acceptor, connector) = tls_pair();
        let injecting = Mta {
            tls: Some(acceptor),
            inject_after_starttls: true,
            ..Mta::default().keywords(&["STARTTLS"])
        };

        let pipes = Pipes::new(&[
            ("203.0.113.1", Script::Serve(injecting)),
            ("203.0.113.1", Script::Serve(Mta::default())),
        ]);
        let mut out = outbound();
        out.tls = Some(connector);

        let outcome = deliver(&two_exchangers(), &pipes, &out, &message(b"hi\r\n")).await;

        assert_eq!(
            verdicts(&outcome),
            vec!["hi@example.com: accepted"],
            "the poisoned connection is abandoned and the fallback delivers"
        );
        let connections = pipes.connections();
        assert!(
            !connections[0].1.encrypted,
            "the handshake must not be started on a connection that has unread \
             plaintext behind it"
        );
    }

    #[tokio::test]
    async fn the_client_sends_ehlo_after_the_handshake_without_waiting_for_a_greeting() {
        let (acceptor, connector) = tls_pair();
        let offering = Mta {
            tls: Some(acceptor),
            ..Mta::default().keywords(&["SIZE 10485760", "8BITMIME", "STARTTLS"])
        };
        let pipes = Pipes::new(&[("203.0.113.1", Script::Serve(offering))]);
        let mut out = outbound();
        out.tls = Some(connector);
        out.budget.command = Duration::from_millis(300);

        let outcome = deliver(&two_exchangers(), &pipes, &out, &message(b"hi\r\n")).await;

        assert_eq!(
            verdicts(&outcome),
            vec!["hi@example.com: accepted"],
            "the message has to go out inside TLS, not time out waiting to be \
             greeted twice"
        );
        let log = pipes.connections()[0].1.clone();
        assert!(log.encrypted);
        assert!(
            log.commands.iter().any(|c| c.starts_with("MAIL FROM:")),
            "MAIL FROM is never sent when the client waits for a second \
             greeting: {:?}",
            log.commands
        );
    }

    #[tokio::test]
    async fn the_client_delivers_to_this_projects_own_inbound_server() {
        use crate::routing::Route;
        use crate::spool::Spool;

        let dir = std::env::temp_dir()
            .join("mxhop-tests")
            .join(format!("client-to-session-{}", crate::spool::new_id()));
        std::fs::create_dir_all(&dir).expect("a scratch dir");
        let spool = Spool::open(&dir).await.expect("a spool");

        let mut router = crate::routing::Router::default();
        router.insert(
            "example.com",
            "hi",
            Route::Forward(vec![Mailbox::parse("onward@gmail.test").unwrap()]),
        );

        let config = crate::smtp::session::SessionConfig {
            hostname: "mx.inbound.test".into(),
            max_message_bytes: 1024 * 1024,
            max_recipients: 10,
            max_errors: 4,
            command_timeout: Duration::from_secs(5),
            data_timeout: Duration::from_secs(5),
            handshake_timeout: Duration::from_secs(5),
            ptr_timeout: Duration::from_secs(5),
            relay_budget: crate::smtp::session::RELAY_BUDGET,
            queue: crate::queue::Schedule::default(),
            limits: crate::policy::Limits::default(),
            auth_enabled: true,
        };

        let relay = Capture::default();
        let (client, server) = duplex(256 * 1024);
        let served = {
            let spool = spool.clone();
            let relay = relay.clone();
            tokio::spawn(async move {
                crate::smtp::session::serve(
                    server,
                    "203.0.113.5:40000".to_string(),
                    &config,
                    &router,
                    None,
                    &spool,
                    &relay,
                    None,
                    &mut crate::shutdown::Shutdown::never(),
                )
                .await
            })
        };

        let body: &[u8] = b"Subject: across the pipe\r\n\r\n.dotted\r\nbody\r\n";
        let delivery = message(body);
        let out = outbound();
        let results = dialog(
            client,
            "mx.inbound.test",
            &out,
            &delivery,
            None,
            Instant::now() + out.budget.overall,
        )
        .await
        .expect("the two halves should agree");

        assert!(
            results.iter().all(|r| r.verdict == Verdict::Accepted),
            "{results:?}"
        );
        let _ = served.await.expect("the task");

        assert!(
            spool.queued().await.expect("the queue").is_empty(),
            "a message handed on is not stored: the queue is for what is left over"
        );
        let relayed = relay.0.lock().unwrap().clone();
        assert_eq!(relayed.len(), 1, "exactly one message should have landed");
        assert!(
            relayed[0].body.ends_with(&[HEAD, body].concat()),
            "the message has to arrive byte for byte, dot-stuffing undone at \
             the far end"
        );
        assert!(
            relayed[0].head.starts_with(b"Received: from "),
            "and leave with our own trace in front of it"
        );
    }

    #[tokio::test]
    async fn a_handshake_that_never_finishes_falls_back_instead_of_hanging() {
        let (acceptor, connector) = tls_pair();
        let stalling = Mta {
            tls: Some(acceptor),
            stall_after_starttls: true,
            ..Mta::default().keywords(&["SIZE 10485760", "STARTTLS"])
        };
        let pipes = Pipes::new(&[
            ("203.0.113.1", Script::Serve(stalling)),
            ("203.0.113.1", Script::Serve(Mta::default())),
        ]);
        let mut out = outbound();
        out.tls = Some(connector);
        out.budget.command = Duration::from_millis(150);
        out.budget.overall = Duration::from_secs(20);

        let started = Instant::now();
        let outcome = deliver(&two_exchangers(), &pipes, &out, &message(b"hi\r\n")).await;

        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the handshake has to be inside the budget — took {:?}",
            started.elapsed()
        );
        assert_eq!(
            verdicts(&outcome),
            vec!["hi@example.com: accepted"],
            "and a stalled handshake is a TLS failure, so the plaintext \
             fallback delivers: {:?}",
            verdicts(&outcome)
        );
    }

    #[tokio::test]
    async fn a_destination_that_never_answers_the_final_dot_is_not_tried_again() {
        let stalling = Mta {
            stall_at_dot: true,
            ..Mta::default()
        };
        let pipes = Pipes::new(&[
            ("203.0.113.1", Script::Serve(stalling)),
            ("203.0.113.2", Script::Serve(Mta::default())),
        ]);
        let mut out = outbound();
        out.budget.end_of_data = Duration::from_millis(120);
        out.budget.overall = Duration::from_secs(20);

        let outcome = deliver(&two_exchangers(), &pipes, &out, &message(b"hi\r\n")).await;

        assert_eq!(
            pipes.connections().len(),
            1,
            "the second exchanger must not be handed a copy of a message the \
             first one may already have queued"
        );
        assert!(
            matches!(outcome.results[0].verdict, Verdict::Deferred(_)),
            "nothing was settled, so nothing may be refused: {:?}",
            verdicts(&outcome)
        );
    }

    #[tokio::test]
    async fn a_group_that_cannot_outlast_the_final_dot_never_starts_its_data() {
        let pipes = Pipes::new(&[
            ("203.0.113.1", Script::Serve(Mta::default())),
            ("203.0.113.1", Script::Serve(Mta::default())),
        ]);
        let mut out = outbound();
        out.budget.end_of_data = Duration::from_secs(1);
        let deadline = Instant::now() + Duration::from_secs(2);

        let first = deliver(
            &two_exchangers(),
            &pipes,
            &out,
            &message(b"hi\r\n").due_by(deadline),
        )
        .await;
        assert_eq!(
            verdicts(&first),
            vec!["hi@example.com: accepted"],
            "the first group had the budget it needed"
        );

        tokio::time::sleep(Duration::from_millis(1_500)).await;

        let second = deliver(
            &two_exchangers(),
            &pipes,
            &out,
            &message(b"the second group's body\r\n").due_by(deadline),
        )
        .await;

        assert!(
            matches!(second.results[0].verdict, Verdict::Deferred(_)),
            "half a second of budget cannot answer for a final dot that is \
             allowed a second: {:?}",
            verdicts(&second)
        );
        let connections = pipes.connections();
        assert_eq!(connections.len(), 2, "one connection per group");
        let (_, second_log) = &connections[1];
        assert!(
            second_log.body.is_none(),
            "the body must not be on the wire: once it is, the deferral is a \
             lie the destination can contradict by having queued it"
        );
        assert!(
            !second_log.commands.iter().any(|c| c == "DATA"),
            "and DATA is the point of no return, so it is never sent: {:?}",
            second_log.commands
        );
    }

    #[tokio::test]
    async fn a_refusing_greeting_reaches_the_sender_in_the_destinations_own_words() {
        let blocked = Mta {
            greeting: "554-5.7.1 Service unavailable; Client host [203.0.113.7] blocked\r\n\
                       554 5.7.1 using Spamhaus; see https://check.spamhaus.org/"
                .into(),
            ..Mta::default()
        };
        let pipes = Pipes::new(&[
            ("203.0.113.1", Script::Serve(blocked)),
            ("203.0.113.2", Script::Refuse),
        ]);

        let outcome = deliver(&two_exchangers(), &pipes, &outbound(), &message(b"hi\r\n")).await;

        let Verdict::Deferred(reply) = &outcome.results[0].verdict else {
            panic!(
                "a 5xx greeting is a host that will not talk, not mail that is \
                 refused — Postfix's smtp_skip_5xx_greeting = yes: {:?}",
                verdicts(&outcome)
            );
        };
        let said = reply.to_string();
        assert!(
            said.contains("check.spamhaus.org"),
            "the destination's own words and its URL are the whole value of \
             this reply: {said}"
        );
        assert!(
            said.contains("mx1.example.com refused the connection"),
            "and the sender needs to know which host said it: {said}"
        );
    }

    #[tokio::test]
    async fn a_deadline_that_passes_before_any_host_is_examined_is_not_a_refusal() {
        let slow = Slow {
            inner: two_exchangers(),
            delay: Duration::from_millis(200),
        };
        let mut out = outbound();
        out.budget.command = Duration::from_millis(60);
        out.budget.overall = Duration::from_millis(60);

        let outcome = deliver(&slow, &Pipes::new(&[]), &out, &message(b"hi\r\n")).await;

        assert!(
            matches!(outcome.results[0].verdict, Verdict::Deferred(_)),
            "nothing was asked of any host, so nothing may be concluded about \
             them: {:?}",
            verdicts(&outcome)
        );
    }

    #[tokio::test]
    async fn a_dns_lookup_that_does_not_answer_stays_inside_the_budget() {
        let slow = Slow {
            inner: two_exchangers(),
            delay: Duration::from_secs(30),
        };
        let mut out = outbound();
        out.budget.command = Duration::from_millis(100);
        out.budget.overall = Duration::from_secs(20);

        let started = Instant::now();
        let outcome = deliver(&slow, &Pipes::new(&[]), &out, &message(b"hi\r\n")).await;

        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the MX lookup has to be under the clock — took {:?}",
            started.elapsed()
        );
        assert!(
            matches!(outcome.results[0].verdict, Verdict::Deferred(_)),
            "{:?}",
            verdicts(&outcome)
        );
    }

    #[tokio::test]
    async fn a_head_that_does_not_end_a_line_does_not_get_a_dot_in_the_middle_of_one() {
        let pipes = Pipes::new(&[("203.0.113.1", Script::Serve(Mta::default()))]);
        let head: &[u8] = b"X-Forwarded-For: 203.0.113.9";
        let body: &[u8] = b".hidden\r\nbody\r\n";
        let delivery = Delivery::new(
            Some("sender@elsewhere.test".into()),
            to(&["hi@example.com"]),
            head.to_vec(),
            Arc::from(body),
        );

        let outcome = deliver(&two_exchangers(), &pipes, &outbound(), &delivery).await;
        assert_eq!(verdicts(&outcome), vec!["hi@example.com: accepted"]);

        let log = pipes.connections()[0].1.clone();
        assert_eq!(
            log.body.as_deref(),
            Some([head, body].concat().as_slice()),
            "the dot here is data, not a line's first byte"
        );
    }

    #[tokio::test]
    async fn a_slow_but_progressing_destination_is_not_cut_off_mid_body() {
        let slow_reader = Mta {
            read_delay: Some(Duration::from_millis(2)),
            ..Mta::default()
        };
        let pipes = Pipes::new(&[("203.0.113.1", Script::Serve(slow_reader))]);
        let line = [vec![b'x'; 1022].as_slice(), b"\r\n"].concat();
        let body: Vec<u8> = line.repeat(600);
        let mut out = outbound();
        out.budget.body = Duration::from_millis(600);
        out.budget.overall = Duration::from_secs(30);

        let outcome = deliver(&two_exchangers(), &pipes, &out, &message(&body)).await;

        assert_eq!(
            verdicts(&outcome),
            vec!["hi@example.com: accepted"],
            "every chunk made progress, so nothing stalled"
        );
    }

    #[test]
    fn dot_stuffing_touches_only_the_dot() {
        let mut out = Vec::new();
        let ended_a_line = stuff(b".a\r\nb.\r\n..c\r\n\xffd\r\n", true, &mut out);
        assert_eq!(out, b"..a\r\nb.\r\n...c\r\n\xffd\r\n");
        assert!(ended_a_line);
    }

    #[test]
    fn dot_stuffing_carries_the_line_state_between_chunks() {
        let mut out = Vec::new();
        let at_line_start = stuff(b"X-Spam-Status: No", true, &mut out);
        assert!(!at_line_start);
        stuff(b".hidden\r\n", at_line_start, &mut out);
        assert_eq!(out, b"X-Spam-Status: No.hidden\r\n");
    }

    #[test]
    fn a_reply_without_an_enhanced_code_keeps_all_of_its_text() {
        let reply = flatten(&["250 2 messages queued".to_string()]);
        assert_eq!(reply.enhanced, None);
        assert_eq!(reply.text, "2 messages queued");
    }

    #[test]
    fn a_three_part_code_is_read_as_the_enhanced_status() {
        let reply = flatten(&["451 4.7.1 try again later".to_string()]);
        assert_eq!(reply.enhanced.as_deref(), Some("4.7.1"));
        assert_eq!(reply.text, "try again later");
    }

    #[test]
    fn the_extensions_are_read_from_the_lines_after_the_greeting() {
        let caps = caps_from(&[
            "250-mx.example.com at your service".to_string(),
            "250-SIZE 35882577".to_string(),
            "250-8BITMIME".to_string(),
            "250-starttls".to_string(),
            "250 CHUNKING".to_string(),
        ]);

        assert_eq!(
            caps,
            Caps {
                starttls: true,
                eight_bit: true,
                size: Some(35_882_577)
            },
            "keywords are case insensitive, and CHUNKING is not something we do"
        );
    }

    #[test]
    fn a_greeting_line_that_looks_like_a_keyword_is_still_the_greeting() {
        let caps = caps_from(&[
            "250-starttls.example.com at your service".to_string(),
            "250 PIPELINING".to_string(),
        ]);
        assert!(!caps.starttls);
    }

    #[test]
    fn a_reply_mxhop_invented_says_so() {
        let reply = Reply::ours(451, "4.4.1", "nothing answered");
        assert!(
            reply.to_string().starts_with("451 4.4.1 mxhop:"),
            "a sender has to be able to tell our words from the destination's: \
             {reply}"
        );
    }
}
