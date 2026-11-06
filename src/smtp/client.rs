//! Handing a message to somebody else's mail server.
//!
//! This is the other half of [`crate::smtp::session`]: the same state machine
//! read from the other end, written over any stream so the tests drive it
//! against a fake MTA on a pipe rather than against Gmail.
//!
//! Two things shape everything here. The first is that the body is not ours
//! to touch: it goes out byte for byte, and the single exception is putting
//! back the dot that SMTP requires in front of a line that begins with one.
//! The second is that a forwarder's most valuable output is the destination's
//! own words. When Gmail refuses a recipient, the sender needs to read
//! Gmail's reason, not ours — so every recipient carries its own verdict with
//! the destination's text inside it, which is the thing no submission client
//! crate will give you.

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

use crate::dns::{Resolve, targets};
use crate::routing::Mailbox;
use crate::smtp::wire::{self, WireError};

/// The port mail is handed over on. Configurable only because the tests need
/// an unprivileged one; submission ports are not what a forwarder uses.
pub const SMTP_PORT: u16 = 25;

/// The longest reply mxhop will read from a destination. Replies are text for
/// a human to read; a destination that sends more than this is not answering
/// a question.
const MAX_REPLY_BYTES: usize = 16 * 1024;

// ------------------------------------------------------------------- the message

/// One message on its way to one domain.
#[derive(Debug, Clone)]
pub struct Delivery {
    /// The envelope sender to announce. `None` is the null sender.
    pub from: Option<String>,
    /// The recipients, all in the same domain — grouping is the caller's job,
    /// because one connection serves one domain.
    pub to: Vec<Mailbox>,
    /// Headers to put in front of the stored message, `Received` among them.
    /// Bytes rather than a structure: whatever is in here is written to the
    /// wire untouched, exactly like the body.
    pub head: Vec<u8>,
    /// The message as it arrived.
    pub body: Arc<[u8]>,
    /// Whether the message carries bytes with the high bit set.
    pub eight_bit: bool,
}

impl Delivery {
    /// Builds a delivery, working out for itself whether the message needs
    /// 8BITMIME.
    pub fn new(from: Option<String>, to: Vec<Mailbox>, head: Vec<u8>, body: Arc<[u8]>) -> Self {
        let eight_bit = head.iter().chain(body.iter()).any(|b| *b >= 0x80);
        Self {
            from,
            to,
            head,
            body,
            eight_bit,
        }
    }

    /// What `SIZE` is compared against: the bytes that will be written,
    /// before dot-stuffing.
    pub fn size(&self) -> u64 {
        (self.head.len() + self.body.len()) as u64
    }

    /// The domain every recipient is in.
    fn domain(&self) -> Option<&str> {
        self.to.first().map(Mailbox::domain)
    }
}

// --------------------------------------------------------------------- replies

/// One SMTP reply, however many lines it arrived on.
///
/// The lines are flattened because the reply has one destination: the single
/// line mxhop says back to the sending server. A reply that arrives as four
/// lines and is relayed as the first one only loses the half that says what
/// to do about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    pub code: u16,
    /// The enhanced status code (RFC 3463), when the destination sent one.
    pub enhanced: Option<String>,
    pub text: String,
}

impl Reply {
    fn is_positive(&self) -> bool {
        (200..300).contains(&self.code)
    }

    /// Whether the destination said to stop rather than to come back.
    fn is_permanent(&self) -> bool {
        self.code >= 500
    }

    /// A reply mxhop made up itself, for the cases where there is no reply
    /// from the destination to pass on. Everything that reaches a sender is
    /// marked, so nobody reads mxhop's own words as the destination's.
    fn ours(code: u16, enhanced: &str, text: impl fmt::Display) -> Self {
        Self {
            code,
            enhanced: Some(enhanced.to_string()),
            text: format!("mxhop: {text}"),
        }
    }
}

impl fmt::Display for Reply {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.enhanced {
            Some(enhanced) => write!(f, "{} {} {}", self.code, enhanced, self.text),
            None => write!(f, "{} {}", self.code, self.text),
        }
    }
}

/// What became of one recipient.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// The destination took it.
    Accepted,
    /// The destination refused it and will keep refusing it.
    Refused(Reply),
    /// Nothing is settled: try again later.
    Deferred(Reply),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientResult {
    pub mailbox: Mailbox,
    pub verdict: Verdict,
}

/// The result of one delivery attempt for one domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// The host that answered, if one did.
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

// --------------------------------------------------------------------- the clock

/// How long each phase may take.
///
/// These are small on purpose. The inbound sending server is holding its own
/// connection open while mxhop does this, and Postfix allows 600 seconds
/// after its final dot; spending all of it on one unresponsive destination
/// turns one slow domain into a queue of stuck inbound sessions.
#[derive(Debug, Clone)]
pub struct Budget {
    pub connect: Duration,
    /// Greeting, EHLO, STARTTLS, MAIL and each RCPT.
    pub command: Duration,
    /// A body write that stops being accepted.
    pub body: Duration,
    /// The reply to the final dot, which is where a destination does its
    /// spam scanning and takes its time.
    pub end_of_data: Duration,
    /// Everything, including DNS and every host tried.
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

/// What delivery needs to know about itself.
#[derive(Clone)]
pub struct Outbound {
    /// The name mxhop announces in EHLO. The destination checks it against
    /// our PTR record.
    pub hostname: String,
    /// Whether to connect over IPv6 when a host has an AAAA record. Off by
    /// default: Gmail refuses IPv6 senders whose PTR does not match with
    /// `550-5.7.25`, and a VPS's IPv6 reverse DNS is the thing nobody sets
    /// up. A host with only AAAA records is still tried over IPv6, because
    /// the alternative is not delivering at all.
    pub ipv6: bool,
    /// The TLS client, or `None` to stay in plaintext. Opportunistic: used
    /// when the destination offers STARTTLS, abandoned when the handshake
    /// fails.
    pub tls: Option<Arc<TlsConnector>>,
    pub port: u16,
    pub budget: Budget,
}

impl Outbound {
    /// The configuration the service runs with: TLS verified against the
    /// webpki trust anchors.
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

/// A TLS client that trusts what browsers trust.
///
/// Verification is on, and a failure falls back to plaintext rather than
/// refusing to deliver — see [`deliver`]. That is what opportunistic TLS
/// means for an MTA, and pretending otherwise by disabling verification would
/// make the successful case meaningless too.
pub fn webpki_connector() -> TlsConnector {
    let roots = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    TlsConnector::from(Arc::new(config))
}

// ---------------------------------------------------------------------- failure

/// Why an attempt against one host ended without a verdict from it.
#[derive(Debug)]
pub enum Fail {
    /// The host could not be reached.
    Connect(io::Error),
    /// The stream broke.
    Wire(WireError),
    /// A phase took longer than its budget.
    Timeout(&'static str),
    /// The whole message's budget is gone.
    Spent,
    /// Something arrived that is not an SMTP reply.
    Garbled(String),
    /// STARTTLS was offered and did not work.
    Tls(String),
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

// ------------------------------------------------------------------ connecting

/// Opening a connection, as a trait so the tests can hand the client a pipe
/// where a socket would be. Host selection — which MX, which address, what to
/// do when one refuses — is the part worth testing, and it cannot be tested
/// over a real socket without binding a port per host.
pub trait Connect {
    type Stream: AsyncRead + AsyncWrite + Unpin + Send;

    fn connect(
        &self,
        addr: SocketAddr,
    ) -> impl std::future::Future<Output = io::Result<Self::Stream>> + Send;
}

/// The real one.
pub struct Tcp;

impl Connect for Tcp {
    type Stream = TcpStream;

    async fn connect(&self, addr: SocketAddr) -> io::Result<TcpStream> {
        TcpStream::connect(addr).await
    }
}

// ------------------------------------------------------------------- delivering

/// Hands one message to one domain, trying its mail exchangers in turn.
///
/// Never returns an error: every recipient comes back with a verdict, because
/// a message with no verdict is a message nobody knows what to do with.
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
    let deadline = Instant::now() + out.budget.overall;

    let Some(domain) = delivery.domain() else {
        return Outcome {
            host: None,
            results: Vec::new(),
        };
    };

    let hosts = match targets(resolver, domain).await {
        Ok(hosts) => hosts,
        Err(e) => {
            // A domain with no route is the one case decided without talking
            // to anybody, and the permanence of it comes from DNS: a null MX
            // is a refusal, a resolver that did not answer is not.
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
    };

    // The reason the last host failed, so that the deferral says something
    // other than "it did not work".
    let mut last: Option<Fail> = None;

    for target in &hosts {
        if Instant::now() >= deadline {
            warn!(
                domain,
                host = %target.host,
                "the delivery budget ran out before this host was tried"
            );
            break;
        }

        let addrs = match resolver.addrs(&target.host).await {
            Ok(addrs) => addrs,
            Err(e) => {
                debug!(host = %target.host, "no address: {e}");
                last = Some(Fail::Connect(io::Error::other(e.to_string())));
                continue;
            }
        };

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
                    // Opportunistic means exactly this: a destination with a
                    // broken or expired certificate still gets its mail,
                    // because the alternative is not delivering it at all,
                    // and plaintext is what we would have used had it never
                    // offered STARTTLS. The connection cannot be reused —
                    // the handshake consumed it — so this is a second one.
                    warn!(
                        host = %target.host,
                        %addr,
                        "STARTTLS failed, delivering in plaintext instead: {e}"
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
                        Err(e) => last = Some(e),
                    }
                }
                Err(Fail::Spent) => {
                    last = Some(Fail::Spent);
                    break;
                }
                Err(e) => {
                    debug!(host = %target.host, %addr, "attempt failed: {e}");
                    last = Some(e);
                }
            }
        }
    }

    // Nobody answered. Deferred rather than refused, always: a host that
    // cannot be reached has said nothing, and inventing a refusal on its
    // behalf throws away mail it would have taken.
    let reason = match last {
        Some(e) => Reply::ours(
            451,
            "4.4.1",
            format_args!("no mail exchanger answered: {e}"),
        ),
        None => Reply::ours(451, "4.4.1", "no mail exchanger could be tried"),
    };
    Outcome {
        host: None,
        results: Outcome::all(&delivery.to, Verdict::Deferred(reason)),
    }
}

/// The addresses worth trying, in the order to try them.
///
/// IPv4 first and IPv6 only when asked for, except when there is nothing
/// else: see [`Outbound::ipv6`].
fn usable(addrs: &[IpAddr], ipv6: bool) -> Vec<IpAddr> {
    let v4: Vec<IpAddr> = addrs.iter().copied().filter(IpAddr::is_ipv4).collect();
    if !ipv6 && !v4.is_empty() {
        return v4;
    }
    let v6 = addrs.iter().copied().filter(|a| a.is_ipv6());
    v4.into_iter().chain(v6).collect()
}

/// One connection to one address, from the connect to the final reply.
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

/// The whole SMTP exchange over one already-open stream.
///
/// Generic over the stream, like [`crate::smtp::session::serve`], so the fake
/// MTA in the tests is a pipe. When STARTTLS is taken up the exchange starts
/// again over the encrypted stream, which is a second instantiation of the
/// same code rather than a second copy of it.
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
    let mut chat = Chat::new(stream, out.budget.clone(), deadline);
    let caps = chat.open(&out.hostname).await?;

    match tls {
        Some(connector) if caps.starttls => {
            let plain = chat.starttls().await?;
            let name = ServerName::try_from(host.to_string()).map_err(|e| {
                Fail::Tls(format!(
                    "{host} is not a name a certificate can be for: {e}"
                ))
            })?;
            let encrypted = connector
                .connect(name, plain)
                .await
                .map_err(|e| Fail::Tls(e.to_string()))?;

            // RFC 3207 §4.2: everything either side learned before the
            // handshake is discarded, so EHLO is asked again. The second
            // answer is the one that counts — a destination may well offer
            // 8BITMIME or a larger SIZE only once the session is private.
            let mut chat = Chat::new(encrypted, out.budget.clone(), deadline);
            let caps = chat.open(&out.hostname).await?;
            chat.send(&caps, delivery).await
        }
        _ => chat.send(&caps, delivery).await,
    }
}

/// What the destination said it can do.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Caps {
    pub starttls: bool,
    pub eight_bit: bool,
    /// The advertised `SIZE`. `Some(0)` means "no stated limit", which is
    /// what the extension says a zero means, and is not a limit of nothing.
    pub size: Option<u64>,
}

// ------------------------------------------------------------------ the dialogue

struct Chat<S> {
    io: BufReader<S>,
    budget: Budget,
    deadline: Instant,
}

impl<S> Chat<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    fn new(stream: S, budget: Budget, deadline: Instant) -> Self {
        Self {
            // BufReader passes writes straight through, so one wrapper is
            // both halves of the conversation and the stream stays whole —
            // which it has to be, because STARTTLS hands it to rustls.
            io: BufReader::new(stream),
            budget,
            deadline,
        }
    }

    /// Reads the greeting and announces ourselves.
    async fn open(&mut self, me: &str) -> Result<Caps, Fail> {
        let (greeting, _) = self.reply("the greeting", self.budget.command).await?;
        if !greeting.is_positive() {
            // A destination that greets with 4xx or 5xx is telling us to go
            // away before we have said anything; the usual cause is a block
            // list, and its text is the only useful thing we will get.
            return Err(Fail::Garbled(greeting.to_string()));
        }

        self.say(&format!("EHLO {me}")).await?;
        let (reply, lines) = self.reply("EHLO", self.budget.command).await?;
        if !reply.is_positive() {
            return Err(Fail::Garbled(reply.to_string()));
        }
        Ok(caps_from(&lines))
    }

    /// Asks for STARTTLS and gives the bare stream back for the handshake.
    async fn starttls(mut self) -> Result<S, Fail> {
        self.say("STARTTLS").await?;
        let (reply, _) = self.reply("STARTTLS", self.budget.command).await?;
        if reply.code != 220 {
            return Err(Fail::Tls(format!("STARTTLS was refused: {reply}")));
        }

        // CVE-2011-0411: anything already in the buffer arrived in the clear
        // and would otherwise be read back as though the server had said it
        // inside the session. There is nothing to salvage here, so the
        // connection is abandoned and the plaintext fallback takes over.
        if !self.io.buffer().is_empty() {
            return Err(Fail::Tls(
                "the destination sent data after 220 and before the handshake".into(),
            ));
        }

        Ok(self.io.into_inner())
    }

    /// MAIL, RCPT, DATA, the body, and the reply to the final dot.
    async fn send(
        &mut self,
        caps: &Caps,
        delivery: &Delivery,
    ) -> Result<Vec<RecipientResult>, Fail> {
        if let Some(limit) = caps.size.filter(|limit| *limit > 0)
            && delivery.size() > limit
        {
            // Refused here rather than after the body: the destination told
            // us it will not take this, and sending it anyway is megabytes
            // spent to be told so.
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
            // A judgement call, and the one place this client knowingly
            // breaks a rule. The RFC's answer is to encode the message to
            // 7-bit, but re-encoding rewrites the bytes the sender signed and
            // turns a forwarded message into a DKIM failure, which receivers
            // treat as forgery. Bouncing instead loses real mail over a rule
            // that no deployed MTA actually enforces on the wire. So the
            // bytes go out as they are, and the warning is here so that an
            // operator reading the log knows what was decided for them.
            warn!(
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
            // The destination refused the sender, so no recipient of this
            // message has a chance here. Another mail exchanger of the same
            // domain almost always enforces the same policy, so this ends the
            // attempt rather than moving on.
            return Ok(Outcome::all(&delivery.to, verdict_of(reply)));
        }

        let mut results = Vec::with_capacity(delivery.to.len());
        for mailbox in &delivery.to {
            self.say(&format!("RCPT TO:<{mailbox}>")).await?;
            let (reply, _) = self.reply("RCPT TO", self.budget.command).await?;
            // One recipient's refusal is one recipient's refusal. This is the
            // whole reason for a hand-written client: a submission crate
            // fails the send on the first bad RCPT and the other recipient
            // never gets the message.
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
            // Nothing to send to. DATA would be answered 554 and tell us
            // nothing we do not already know.
            let _ = self.say("QUIT").await;
            return Ok(results);
        }

        self.say("DATA").await?;
        let (reply, _) = self.reply("DATA", self.budget.command).await?;
        if reply.code != 354 {
            let verdict = verdict_of(reply);
            return Ok(settle(results, verdict));
        }

        self.write_body(delivery).await?;

        let (reply, _) = self
            .reply("the reply to the final dot", self.budget.end_of_data)
            .await?;
        let verdict = if reply.is_positive() {
            Verdict::Accepted
        } else {
            verdict_of(reply)
        };

        let _ = self.say("QUIT").await;
        Ok(settle(results, verdict))
    }

    /// Writes the headers, the message and the terminator.
    ///
    /// The only transformation is dot-stuffing; see [`stuff`].
    async fn write_body(&mut self, delivery: &Delivery) -> Result<(), Fail> {
        let mut out = Vec::with_capacity(delivery.head.len() + delivery.body.len() + 64);
        stuff(&delivery.head, &mut out);
        stuff(&delivery.body, &mut out);
        // The terminator is a dot on a line of its own, so the message has to
        // have ended a line first. A stored body always has; an empty one has
        // not.
        if !out.is_empty() && !out.ends_with(b"\r\n") {
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b".\r\n");

        let budget = left(self.budget.body, self.deadline)?;
        match timeout(budget, async {
            self.io.write_all(&out).await?;
            self.io.flush().await
        })
        .await
        {
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

    /// Reads one reply, however many lines it spans, and the lines it spanned.
    ///
    /// `want` is this phase's budget; what is actually waited for is that or
    /// whatever is left of the message's, whichever is shorter. A phase
    /// timeout that could outlast the whole budget would make the overall
    /// limit a suggestion.
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

/// Turns however many lines arrived into the one reply mxhop will quote.
fn flatten(lines: &[String]) -> Reply {
    let code = lines[0][..3].parse::<u16>().unwrap_or(0);
    let mut text = String::new();
    for line in lines {
        let rest = line.get(4..).unwrap_or("").trim();
        if rest.is_empty() {
            continue;
        }
        if !text.is_empty() {
            text.push(' ');
        }
        text.push_str(rest);
    }

    // RFC 3463: the enhanced code is the first token of the text, and it is
    // lifted out so that mxhop's own reply can carry the destination's class
    // rather than a made-up one.
    let (enhanced, text) = match text.split_once(' ') {
        Some((head, rest)) if is_enhanced(head) => (Some(head.to_string()), rest.to_string()),
        _ if is_enhanced(&text) => (Some(text.clone()), String::new()),
        _ => (None, text),
    };

    Reply {
        code,
        enhanced,
        text,
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
    // The first line of an EHLO reply is the greeting, not a keyword.
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

/// Applies the verdict of the message to the recipients that got as far as
/// being accepted, and leaves the ones already refused alone — their own
/// reply is the one worth keeping.
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

/// Copies bytes to the wire, putting back the dot in front of any line that
/// starts with one.
///
/// This is the only change made to a message on its way out, and it is not
/// really a change: the extra dot is removed again by the destination. Every
/// other byte, including a line ending that is not CRLF and anything above
/// 0x7f, is written exactly as it was stored, because the sender's DKIM
/// signature covers all of it.
///
/// `src` is assumed to begin at a line boundary, which is true of a stored
/// body and of the headers mxhop prepends to it.
fn stuff(src: &[u8], out: &mut Vec<u8>) {
    let mut at_line_start = true;
    for byte in src {
        if at_line_start && *byte == b'.' {
            out.push(b'.');
        }
        out.push(*byte);
        at_line_start = *byte == b'\n';
    }
}

/// This phase's budget, clipped to what is left of the message's.
fn left(want: Duration, deadline: Instant) -> Result<Duration, Fail> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(Fail::Spent);
    }
    Ok(want.min(remaining))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::{DnsError, Table};
    use std::collections::{BTreeMap, VecDeque};
    use std::sync::Mutex;
    use tokio::io::duplex;
    use tokio_rustls::TlsAcceptor;
    use tokio_rustls::rustls::ServerConfig;

    // ------------------------------------------------------------ the fake MTA

    /// Anything the fake destination can talk over, so that the stream can be
    /// boxed; see [`Mta::serve`].
    trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
    impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

    /// What one connection to the fake destination said and heard.
    #[derive(Debug, Default, Clone)]
    struct Log {
        /// Every command line the client sent, in order.
        commands: Vec<String>,
        /// The message as the destination received it, after undoing the
        /// dot-stuffing — so a test comparing it to what was stored is
        /// comparing the whole round trip rather than one side of it.
        body: Option<Vec<u8>>,
        /// The body exactly as it arrived on the wire, stuffing included.
        raw: Option<Vec<u8>>,
        /// Whether the dialogue happened inside TLS.
        encrypted: bool,
    }

    /// A destination that answers from a script. Replies are written as whole
    /// SMTP lines so a test can use the exact text a real server sends,
    /// multi-line replies included.
    #[derive(Clone)]
    struct Mta {
        greeting: String,
        /// EHLO keyword lines, without their code.
        keywords: Vec<String>,
        mail: String,
        /// One reply per RCPT, in order; the last one repeats.
        rcpt: Vec<String>,
        data: String,
        /// The reply to the final dot.
        dot: String,
        /// Say nothing at all, ever.
        silent: bool,
        /// Accept a STARTTLS handshake with this certificate.
        tls: Option<Arc<TlsAcceptor>>,
        /// Reply 220 to STARTTLS and then send a line before the handshake.
        inject_after_starttls: bool,
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

        /// Serves one connection, recording what happened into `log`.
        ///
        /// The stream is boxed rather than generic: STARTTLS makes this
        /// function call itself over a wrapped stream, and a generic
        /// parameter would ask the compiler to instantiate it for
        /// `TlsStream<TlsStream<...>>` without end.
        async fn serve(self, stream: Box<dyn Stream>, log: Arc<Mutex<Log>>) {
            if self.silent {
                // Holds the connection open and says nothing, which is what a
                // phase timeout exists for.
                tokio::time::sleep(Duration::from_secs(30)).await;
                return;
            }

            let mut io = BufReader::new(stream);
            let _ = say(&mut io, &self.greeting).await;
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
                        let Ok(encrypted) = acceptor.accept(io.into_inner()).await else {
                            return;
                        };
                        log.lock().unwrap().encrypted = true;
                        // RFC 3207: the session starts over, so the same
                        // script serves it again.
                        let mut again = self.clone();
                        again.tls = None;
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
                        let read = read_body_recording(&mut io, &mut raw).await;
                        {
                            let mut log = log.lock().unwrap();
                            log.raw = Some(raw);
                            log.body = read;
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

    /// Reads the body as it arrives on the wire, and separately with the
    /// stuffing undone. [`wire::read_body`] cannot be used for this because
    /// it is the code under test's own counterpart: a test of byte fidelity
    /// that trusted it would pass on a symmetric mistake.
    async fn read_body_recording<R>(io: &mut R, raw: &mut Vec<u8>) -> Option<Vec<u8>>
    where
        R: tokio::io::AsyncBufRead + Unpin,
    {
        use tokio::io::AsyncReadExt;
        let mut unstuffed = Vec::new();
        loop {
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

    // ---------------------------------------------------------- the connector

    #[derive(Clone)]
    enum Script {
        Serve(Mta),
        /// The connection is refused, as a dead host does.
        Refuse,
    }

    /// A connector that hands out pipes instead of sockets, one script per
    /// connection. Which exchanger is tried, in what order, and what happens
    /// when one refuses is the part worth testing, and it cannot be driven
    /// over real sockets without a privileged port per mail exchanger.
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

        /// Every connection that was made, in the order it was made.
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

    // --------------------------------------------------------------- fixtures

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

    /// `example.com` has two exchangers, and the better one is `mx1`.
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

    // ------------------------------------------------------------------ tests

    #[tokio::test]
    async fn mx_records_are_tried_in_preference_order() {
        // DNS listed the worse one first. Taking the list as it came would
        // send every message for the domain to the backup exchanger, which is
        // usually the one that only spools.
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
        // RFC 5321 §5.1. Without it every small domain that publishes only an
        // A record is undeliverable.
        let table = Table::default().addr("example.com", "203.0.113.9".parse().unwrap());
        let pipes = Pipes::new(&[("203.0.113.9", Script::Serve(Mta::default()))]);

        let outcome = deliver(&table, &pipes, &outbound(), &message(b"hi\r\n")).await;

        assert_eq!(outcome.host.as_deref(), Some("example.com"));
        assert_eq!(verdicts(&outcome), vec!["hi@example.com: accepted"]);
    }

    #[tokio::test]
    async fn a_null_mx_is_a_permanent_failure() {
        // Otherwise the message is retried for five days against a domain
        // that said, in the only way DNS has, that it takes no mail.
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
        // Every byte here is inside somebody's DKIM signature: the trailing
        // spaces, the bytes above 0x7f, and the lines that begin with a dot.
        // The dot is the only thing allowed to change on the wire, and it has
        // to come back off at the far end.
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
        // This is the whole reason the client is written by hand: a
        // submission crate fails the send on the first bad RCPT, and the
        // recipient that was accepted never gets the message.
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
        // mxhop relays this inside a single reply line of its own, so a
        // refusal whose instructions are on lines two and three would reach
        // the sender as the useless first line alone.
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
        // RFC 1870 §6: SIZE 0 means the destination declares no fixed
        // maximum. Reading it as a limit refuses every message to a host that
        // advertises it that way, which a few do.
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
        // A real listener that accepts and then says nothing, so what is being
        // tested is the message's clock rather than the phase's: the phase
        // budget here is longer than the whole attempt is allowed to take.
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
        // Gmail answers an IPv6 sender whose PTR does not match with
        // 550-5.7.25, and a VPS's IPv6 reverse DNS is the thing nobody sets
        // up. So when a host has both, the AAAA record is not merely second —
        // it is not tried, not even after the A record refuses, because
        // succeeding over IPv6 is how mail gets refused for a reason the
        // operator cannot see in the queue.
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
        // Preferring IPv4 is a preference, not a refusal: a destination that
        // publishes nothing else would otherwise be undeliverable.
        let table = Table::default()
            .mx("example.com", &[(10, "mx1.example.com")])
            .addr("mx1.example.com", "2001:db8::1".parse().unwrap());
        let pipes = Pipes::new(&[("2001:db8::1", Script::Serve(Mta::default()))]);

        let outcome = deliver(&table, &pipes, &outbound(), &message(b"hi\r\n")).await;

        assert_eq!(verdicts(&outcome), vec!["hi@example.com: accepted"]);
    }

    // ---------------------------------------------------------------- STARTTLS

    /// A self-signed certificate for `mx1.example.com`, and a client that
    /// trusts exactly it. Real verification against a real certificate: a
    /// test that switched verification off would not exercise the thing that
    /// matters.
    fn tls_pair() -> (Arc<TlsAcceptor>, Arc<TlsConnector>) {
        use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};

        let signed = rcgen::generate_simple_self_signed(vec!["mx1.example.com".to_string()])
            .expect("a certificate");
        let cert = CertificateDer::from(signed.cert.der().to_vec());
        let key = PrivateKeyDer::try_from(signed.signing_key.serialize_der()).expect("a key");

        let server = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert.clone()], key)
            .expect("a server config");

        let mut roots = RootCertStore::empty();
        roots.add(cert).expect("a trusted root");
        let client = ClientConfig::builder()
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

        // The same client, against a destination that does not offer it.
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
        // The destination offers STARTTLS and then presents a certificate
        // nobody trusts, which is what an expired or self-signed MTA
        // certificate looks like. Refusing to deliver would lose real mail
        // over a connection that would have been plaintext anyway.
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
        // The real trust anchors, which do not include a self-signed test
        // certificate — so the handshake fails for the usual reason.
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
        // CVE-2011-0411. A line injected between the 220 and the handshake
        // sits in the read buffer, and a client that carried the buffer into
        // the encrypted session would read it there as something the
        // destination had said inside TLS.
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

    // ------------------------------------------------------- the small pieces

    #[test]
    fn dot_stuffing_touches_only_the_dot() {
        let mut out = Vec::new();
        stuff(b".a\r\nb.\r\n..c\r\n\xffd\r\n", &mut out);
        assert_eq!(out, b"..a\r\nb.\r\n...c\r\n\xffd\r\n");
    }

    #[test]
    fn a_reply_without_an_enhanced_code_keeps_all_of_its_text() {
        // Plenty of MTAs send none, and dropping the first word of their text
        // because it was mistaken for one loses the reason.
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
        // Gmail's greeting line is "250-mx.google.com at your service"; a
        // destination whose own name contained a keyword would otherwise set
        // it.
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
