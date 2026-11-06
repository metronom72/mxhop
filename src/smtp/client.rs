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

use crate::auth::{Auth, Probe, Verifier};
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

/// How much of the body is written under one go of [`Budget::body`]. Small
/// enough that a destination which has stopped reading is noticed inside one
/// budget, large enough that the budget is not re-armed per syscall.
const BODY_CHUNK_BYTES: usize = 64 * 1024;

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
    /// When this message's whole delivery has to be over, shared by every
    /// destination group of one inbound message. `None` means "start one from
    /// `Budget::overall` now", which is right for a single delivery and wrong
    /// for a group of them.
    ///
    /// It lives on the delivery rather than in [`Outbound`] because
    /// [`Outbound`] is configuration, shared by every message and every
    /// connection, and this is one message's clock.
    pub deadline: Option<Instant>,
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
            deadline: None,
        }
    }

    /// The same delivery, due by a deadline the caller already holds.
    ///
    /// The caller is the inbound session, which delivers one message's
    /// destination groups one after another: it sets this once so that the
    /// groups divide one budget instead of each starting a fresh one.
    #[must_use]
    pub fn due_by(mut self, deadline: Instant) -> Self {
        self.deadline = Some(deadline);
        self
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
/// `text` is every line joined, which is what a log line and an envelope's
/// `last_reply` want. `lines` keeps them apart, which is what the wire wants:
/// a reply relayed as one flattened line strands the enhanced code in the
/// middle of the sentence — `... Please try 5.1.1 double-checking ...` —
/// because mxhop writes its own code in front of a text that already had one
/// lifted out of it, and a verbose destination's single line can exceed RFC
/// 5321's 512-octet limit outright.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Reply {
    pub code: u16,
    /// The enhanced status code (RFC 3463), when the destination sent one.
    pub enhanced: Option<String>,
    pub text: String,
    /// The destination's own lines, enhanced code and reply code stripped
    /// from each. Empty for a reply mxhop wrote itself, and for one that
    /// arrived on a single line: both of those are one line on the way out
    /// too, so there is nothing to keep.
    pub lines: Vec<String>,
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
            lines: Vec::new(),
        }
    }

    /// The same reply, said by someone and attributed to them.
    ///
    /// Without the host name the sending server cannot tell our sentence from
    /// the destination's. The attribution goes on the first line as well as
    /// on `text`, because the first line is what the sender reads first.
    #[must_use]
    pub fn attributed_to(mut self, host: &str) -> Self {
        self.text = format!("{host} said: {}", self.text);
        if let Some(first) = self.lines.first_mut() {
            *first = format!("{host} said: {first}");
        }
        self
    }

    /// The reply as it goes on the wire to the sending server: one line, or
    /// RFC 5321 continuation lines for a reply that arrived as several.
    ///
    /// The enhanced code is repeated on every line, which is what RFC 3463
    /// §2 asks for, and the last line is the only one with a space rather
    /// than a hyphen after the code — that is what tells the sender the reply
    /// has ended.
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

/// A reply line cut to what RFC 5321 §4.5.3.1.5 allows: 512 octets, CRLF
/// included. A destination that writes one enormous line — Microsoft's 5.7.1
/// texts get close — is not a reason to write an illegal one back, and a
/// sender that reads 512 octets and then looks for CRLF finds the next line's
/// digits instead and calls the whole reply garbled.
fn clamp(mut line: String) -> String {
    const LIMIT: usize = 512 - 2;
    if line.len() <= LIMIT {
        return line;
    }
    // On a character boundary, so the truncation cannot leave half a UTF-8
    // sequence on the wire.
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
    /// How long one chunk of the body may sit unaccepted. A stall timeout,
    /// not a limit on the whole body: a big message to a slow destination is
    /// normal, and a destination that has stopped reading is not.
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
    // The provider is named rather than looked up, exactly as `crate::tls`
    // does for the server side. `ClientConfig::builder()` takes — and
    // *installs* — the process-wide default, which both makes the choice a
    // dependency's to change and defeats the check in `crate::tls` that the
    // choice was made here.
    let config = ClientConfig::builder_with_provider(Arc::new(
        tokio_rustls::rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("ring supports the default protocol versions")
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
    /// The destination answered the greeting or EHLO with a refusal. Its own
    /// words are the whole value of this: a block list's text and its URL are
    /// what tells the sender what to do, and "the budget is spent" is not.
    Rejected(Reply),
    /// The message was written in full and the destination never said what it
    /// did with it. Retrying this against another host risks a second copy,
    /// so it ends the delivery instead of continuing it.
    Unsettled(Box<Fail>),
}

impl Fail {
    /// How much this failure is worth saying to the sender, so that the
    /// reason in the deferral is the most informative one rather than the
    /// last one. A phase timeout and a spent budget say nothing about the
    /// destination; a reply from it says everything.
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
    // The caller's deadline when it has one: one inbound message's groups are
    // delivered in turn and share the sender's patience, so each one taking a
    // whole `Budget::overall` would multiply it by the number of destination
    // domains.
    let deadline = delivery
        .deadline
        .unwrap_or_else(|| Instant::now() + out.budget.overall);

    let Some(domain) = delivery.domain() else {
        return Outcome {
            host: None,
            results: Vec::new(),
        };
    };

    // Inside the clock. hickory will spend 5 seconds twice per query against
    // an unresponsive resolver, and an MX lookup plus one address lookup per
    // exchanger is enough of that to push a 180 second ceiling well past
    // three minutes while the inbound sender waits on us.
    let hosts = match clocked(out.budget.command, deadline, targets(resolver, domain)).await {
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

    // The reason the best-informed host failed, so that the deferral says
    // something other than "it did not work", and the name of the host that
    // said it.
    let mut last: Option<Last> = None;
    // How many exchangers were actually examined, and how many of those
    // failed because DNS said the name has no address. All of them being the
    // second is an answer rather than a silence — the commonest cause is a
    // misspelled domain, which belongs back with the sender now rather than
    // after five days of retries — but *none* of them having been examined is
    // not an answer at all, so the count matters as much as the reason.
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
                    // Opportunistic means exactly this: a destination with a
                    // broken or expired certificate still gets its mail,
                    // because the alternative is not delivering it at all,
                    // and plaintext is what we would have used had it never
                    // offered STARTTLS. The connection cannot be reused —
                    // the handshake consumed it — so this is a second one.
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
                    // The message is on the wire in full and this host never
                    // said what it did with it. It may well have queued it —
                    // a content scan that outran our patience, or a reply
                    // lost to a reset — so trying the next host would be
                    // asking a second mail server to deliver a copy. Stop,
                    // and defer: a duplicate is worse than a delay.
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

    // Otherwise: deferred, never refused. A host that could not be reached
    // has said nothing, and inventing a refusal on its behalf throws away
    // mail it would have taken.
    let reason = match last {
        // The destination's own refusal, relayed with its text intact. In the
        // next milestone this sentence goes straight back to a stranger's
        // mail server, so it has to be the destination's words and not ours.
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

/// The failure worth telling the sender about, and who said it.
struct Last {
    host: String,
    fail: Fail,
}

impl Last {
    /// Keeps whichever of the two failures says more; see [`Fail::worth`]. On
    /// a tie the newer one wins, so that the ordinary case is still "what
    /// happened last".
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

/// Runs something that is not SMTP — a DNS lookup, a TLS handshake — under
/// this phase's budget clipped to what is left of the message's, so that the
/// overall ceiling covers everything and not only the parts we speak.
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
    let mut chat = Chat::new(stream, host, out.budget.clone(), deadline);
    // A fresh TCP connection, so the destination speaks first.
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
            // Under the clock, and classified as a TLS failure rather than a
            // timeout. A middlebox that answers 220 to STARTTLS and then
            // sends nothing would otherwise hang here until TCP gave up,
            // which with no data flowing can be never — and the inbound
            // session waiting on us hangs with it. Calling it `Tls` is what
            // puts it through the plaintext fallback, which is the right
            // answer for exactly that middlebox.
            let encrypted =
                match clocked(out.budget.command, deadline, connector.connect(name, plain)).await {
                    Err(_) => return Err(Fail::Tls("the handshake timed out".into())),
                    Ok(Ok(encrypted)) => encrypted,
                    Ok(Err(e)) => return Err(Fail::Tls(e.to_string())),
                };

            // RFC 3207 §4.2: the session returns to the state it was in
            // immediately *after* the greeting, so EHLO is asked again and
            // there is no second greeting to wait for. Postfix, Exim and
            // Gmail all send nothing here and wait for EHLO — as does this
            // project's own inbound server — so a client that reads a 220
            // first waits out its whole command budget against every real
            // destination that offers STARTTLS. The second EHLO answer is
            // the one that counts: a destination may well offer 8BITMIME or
            // a larger SIZE only once the session is private.
            let mut chat = Chat::new(encrypted, host, out.budget.clone(), deadline);
            let caps = chat.ehlo(&out.hostname).await?;
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
    /// Who we are talking to, so that every line this file logs names the
    /// host. A delivery tries five of them, and a warning that does not say
    /// which one is a warning an operator cannot act on.
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
            // BufReader passes writes straight through, so one wrapper is
            // both halves of the conversation and the stream stays whole —
            // which it has to be, because STARTTLS hands it to rustls.
            io: BufReader::new(stream),
            host: host.to_string(),
            budget,
            deadline,
        }
    }

    /// Reads the greeting the destination sends unprompted.
    ///
    /// Separate from [`Chat::ehlo`] because only a new connection has one: a
    /// session resumed after a STARTTLS handshake has already had its
    /// greeting and goes straight to EHLO.
    async fn greet(&mut self) -> Result<(), Fail> {
        let (greeting, _) = self.reply("the greeting", self.budget.command).await?;
        if !greeting.is_positive() {
            // A destination that greets with 4xx or 5xx is telling us to go
            // away before we have said anything; the usual cause is a block
            // list, and its text is the only useful thing we will get — so it
            // is kept as a reply and not filed as noise. Deferring on a 5xx
            // greeting is deliberate, and matches Postfix's
            // `smtp_skip_5xx_greeting = yes`: a host that will not talk has
            // not refused the mail.
            return Err(Fail::Rejected(greeting));
        }
        Ok(())
    }

    /// Announces ourselves and reads back what the destination can do.
    async fn ehlo(&mut self, me: &str) -> Result<Caps, Fail> {
        self.say(&format!("EHLO {me}")).await?;
        let (reply, lines) = self.reply("EHLO", self.budget.command).await?;
        if !reply.is_positive() {
            return Err(Fail::Rejected(reply));
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

        // The last moment at which a deferral is honest. Everything after
        // DATA is past the point of no return: the body goes on the wire, and
        // if what is left of this message's shared deadline then runs out
        // before the final dot is answered, `Fail::Spent` defers a message
        // the destination may already have queued — and the sending server's
        // retry delivers a second copy. A deferral costs a retry; a duplicate
        // cannot be undone.
        //
        // Checked here rather than in `deliver` before dialling, although
        // that would save the connection: DNS and the handshake spend budget
        // too, so an answer worked out before them can be stale by the time
        // it matters. This is the only place where "enough time left to hear
        // the answer" is still true when DATA is sent.
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

        // Past this point the message is on the wire in full, so an error is
        // no longer a reason to try another host: the destination may have
        // queued it and lost only the reply. `Unsettled` says so, and
        // [`deliver`] stops rather than sending a second copy somewhere else.
        // A spent overall budget is left alone — it already ends the delivery
        // for the same reason.
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

    /// Writes the headers, the message and the terminator.
    ///
    /// The only transformation is dot-stuffing; see [`stuff`].
    async fn write_body(&mut self, delivery: &Delivery) -> Result<(), Fail> {
        let mut out = Vec::with_capacity(delivery.head.len() + delivery.body.len() + 64);
        // The line state carries from the head into the body: they are one
        // byte stream, and a head that does not end in CRLF leaves the body's
        // first byte in the middle of a line. Treating the body as a fresh
        // start there inserts a dot inside a line that did not begin with
        // one, which is a changed byte under the sender's signature.
        let at_line_start = stuff(&delivery.head, true, &mut out);
        stuff(&delivery.body, at_line_start, &mut out);
        // The terminator is a dot on a line of its own, so the message has to
        // have ended a line first. A stored body always has; an empty one has
        // not.
        if !out.is_empty() && !out.ends_with(b"\r\n") {
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b".\r\n");

        // A chunk at a time, with the budget applied to each. As one timeout
        // over the whole body it was a throughput floor dressed up as a
        // stall timeout: 60 seconds for a 25 MiB message demands about
        // 3.5 Mbit/s of a destination, and a slow but perfectly healthy one
        // would have the message cut off mid-body and sent again from the
        // start. What wants a timeout is a destination that stops reading,
        // and that is what no chunk making progress means.
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
    let mut kept: Vec<String> = Vec::with_capacity(lines.len());
    for line in lines {
        let rest = line.get(4..).unwrap_or("").trim();
        if rest.is_empty() {
            continue;
        }
        kept.push(rest.to_string());
    }

    // RFC 3463: the enhanced code is the first token of the text, and it is
    // lifted out so that mxhop's own reply can carry the destination's class
    // rather than a made-up one. A destination that repeats it on every line
    // — which is what the RFC asks of it — has it taken off every line, or
    // re-emitting them would say it twice.
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
        // One line on the way in is one line on the way out, so there is
        // nothing worth keeping apart.
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
/// `at_line_start` says whether `src` begins a line, and the return value
/// says whether the next chunk would: the head and the body are written by
/// two calls and are one byte stream, so the state has to cross between them.
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

/// This phase's budget, clipped to what is left of the message's.
fn left(want: Duration, deadline: Instant) -> Result<Duration, Fail> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(Fail::Spent);
    }
    Ok(want.min(remaining))
}

// ------------------------------------------------------- the session's view of us

/// Delivery as the inbound session needs it: hand this message on, and tell
/// me what the peer's address is called.
///
/// A trait because a session test cannot be allowed near the network, and
/// because the two questions the session asks are the whole of what it needs
/// — no resolver, no connector and no budget reach [`crate::smtp::session`].
pub trait Relay {
    fn deliver(&self, delivery: Delivery) -> impl std::future::Future<Output = Outcome> + Send;

    /// The peer's reverse DNS, or `None` when it has none or DNS did not say.
    /// A trace with `unknown` in it is honest; a session that waits on a
    /// broken resolver is not, so the caller puts this under a clock.
    fn ptr(&self, ip: IpAddr) -> impl std::future::Future<Output = Option<String>> + Send;

    /// What the message's own domains say about it: SPF, DKIM, DMARC.
    ///
    /// A third method on `Relay` rather than a ninth argument to
    /// `session::serve`, and that is a judgement call. `Relay` is already
    /// "the outside world as the session sees it" — it owns `ptr`, which is
    /// also a DNS lookup made on the session's behalf and decided nothing on
    /// — the session's test double already exists and is already the one
    /// place a test swaps the outside world out, and `serve` has eight
    /// arguments as it is. The alternative, a separate trait threaded through
    /// `serve`, `accept_loop` and `main`, would add a type parameter to all
    /// three to say the same thing.
    ///
    /// It never fails and never returns a `Result`: a check that could not be
    /// made is an [`Auth`] saying so, because the decision table has to be
    /// able to tell "the domain publishes nothing" from "nobody answered",
    /// and an error type collapses the two.
    fn verify(&self, probe: Probe<'_>) -> impl std::future::Future<Output = Auth> + Send;
}

/// The real one: the system resolver, a TCP socket, and port 25.
pub struct Direct<R> {
    pub resolver: R,
    pub out: Outbound,
    /// The SPF, DKIM and DMARC verifier, or `None` when `[auth]` is disabled.
    /// `None` means no lookups, no header and no refusals: see
    /// [`crate::auth::Auth::not_checked`].
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

    async fn verify(&self, probe: Probe<'_>) -> Auth {
        match &self.verifier {
            Some(verifier) => verifier.check(probe).await,
            None => Auth::not_checked(),
        }
    }
}

/// A relay that answers "accepted" and hands the message nowhere.
///
/// It exists for the tests that are about something else — the accept loop,
/// the TLS handshake — and that would otherwise have to reach the network to
/// get past the final dot. It is deliberately not reachable from any
/// configuration: a forwarder that silently discards mail is the worst
/// failure this program has.
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

    async fn verify(&self, _probe: Probe<'_>) -> Auth {
        Auth::not_checked()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::{DnsError, Table};

    /// A multi-line reply has to survive as lines, not only as a sentence.
    ///
    /// Flattened to one line and relayed, the enhanced code is stranded
    /// mid-sentence — `... Please try 5.1.1 double-checking ...` — because
    /// mxhop writes its own code in front of a text that already had one
    /// taken out of the middle of it. A verbose destination (Microsoft's
    /// 5.7.1 texts run to several hundred characters) can also push the
    /// single line past RFC 5321's 512-octet reply limit.
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

    /// What goes on the wire for a multi-line reply: RFC 5321's continuation
    /// syntax, and RFC 3463's enhanced code on each line of it.
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

    /// Equality has to notice a reply that lost its lines.
    ///
    /// `lines` exists so that a multi-line refusal goes back out as
    /// continuation lines; a code path that rebuilds a `Reply` and forgets to
    /// carry them is exactly the regression it was added to catch. While
    /// equality compared only `code`, `enhanced` and `text`, every
    /// `assert_eq!` in this file was blind to that path: the stranded
    /// enhanced code and the over-long line would both come back and no test
    /// would say so.
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

    /// Single-line replies, and mxhop's own, are one line as before: the
    /// continuation syntax is for replies that arrived as several.
    #[test]
    fn a_single_line_reply_is_still_one_line() {
        assert_eq!(
            Reply::ours(451, "4.4.1", "nobody answered").wire(),
            vec!["451 4.4.1 mxhop: nobody answered"]
        );
    }

    /// RFC 5321 §4.5.3.1.5 caps a reply line at 512 octets, CRLF included.
    /// A destination that writes one enormous line is not a reason to write
    /// an illegal one back.
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
        /// Reply 220 to STARTTLS and then never handshake, which is what a
        /// TLS-mangling middlebox does.
        stall_after_starttls: bool,
        /// Read the whole body and then never reply to the final dot.
        stall_at_dot: bool,
        /// Whether this is the session resumed inside TLS. A resumed session
        /// has already had its greeting; see [`Mta::serve`].
        resumed: bool,
        /// Sleep this long before taking each line of the body, so that a
        /// slow but progressing destination can be told from a stalled one.
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
            // RFC 3207 §4.2 puts the session back where it was *after* the
            // greeting, so a real server sends nothing here and waits for
            // EHLO. The fake has to do the same, or it quietly props up a
            // client that waits for a second greeting no destination sends.
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
                            // Holds the connection and never speaks TLS.
                            tokio::time::sleep(Duration::from_secs(30)).await;
                            return;
                        }
                        let Ok(encrypted) = acceptor.accept(io.into_inner()).await else {
                            return;
                        };
                        log.lock().unwrap().encrypted = true;
                        // RFC 3207: the session starts over, so the same
                        // script serves it again.
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
                            // The message is in: a content scan that outruns
                            // the client's patience looks exactly like this,
                            // and the destination may still queue it.
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

    /// Reads the body as it arrives on the wire, and separately with the
    /// stuffing undone. [`wire::read_body`] cannot be used for this because
    /// it is the code under test's own counterpart: a test of byte fidelity
    /// that trusted it would pass on a symmetric mistake.
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

    // ------------------------------------------------------------- a slow DNS

    /// A relay that keeps what the inbound session handed it, so the test
    /// can check the bytes instead of reading them back out of the spool —
    /// a delivered message is no longer stored anywhere.
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

        async fn verify(&self, _probe: Probe<'_>) -> Auth {
            Auth::not_checked()
        }
    }

    /// A resolver that answers correctly, eventually. The question a delivery
    /// budget has to answer is what happens while DNS is thinking, and a
    /// table answers instantly.
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
    async fn a_domain_with_neither_an_exchanger_nor_an_address_is_refused() {
        // A misspelled domain is the commonest bad recipient there is. DNS
        // has answered — it said this name has nothing — so deferring it
        // keeps the message in the queue for five days before telling the
        // sender what DNS already knew.
        let table = Table::default();

        let outcome = deliver(&table, &Pipes::new(&[]), &outbound(), &message(b"hi\r\n")).await;

        assert!(
            matches!(outcome.results[0].verdict, Verdict::Refused(_)),
            "{:?}",
            verdicts(&outcome)
        );
    }

    #[tokio::test]
    async fn an_exchanger_whose_address_will_not_resolve_is_only_deferred() {
        // The same shape of failure, with the resolver unable to answer
        // rather than answering that there is nothing: nothing is known, so
        // nothing may be decided.
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
        // It resolved and refused the connection, which says nothing about
        // whether the mail is deliverable.
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

    #[tokio::test]
    async fn the_client_sends_ehlo_after_the_handshake_without_waiting_for_a_greeting() {
        // RFC 3207 §4.2 resets the session to the state *after* the greeting:
        // Postfix, Exim and Gmail send nothing and wait for EHLO, and so does
        // this project's own inbound server. A client that reads a 220 first
        // spends its whole command budget in silence against every real
        // destination that offers STARTTLS — which is every real one — and
        // never reaches MAIL FROM. The fake above is honest about this now,
        // so the plain `starttls_is_used_when_offered…` test is the thing
        // that turns red if it comes back; this one says so by name.
        let (acceptor, connector) = tls_pair();
        let offering = Mta {
            tls: Some(acceptor),
            ..Mta::default().keywords(&["SIZE 10485760", "8BITMIME", "STARTTLS"])
        };
        let pipes = Pipes::new(&[("203.0.113.1", Script::Serve(offering))]);
        let mut out = outbound();
        out.tls = Some(connector);
        // Short enough that waiting for a greeting that never comes is a
        // failure rather than a slow pass.
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
        // The two halves of the state machine keeping each other honest. The
        // headline bug was that `client::open` read a greeting the server
        // half does not send after a handshake, and every test passed because
        // the only server in the tests was a fake written to match the
        // client. A real destination here is the one thing that could not
        // have agreed with the mistake.
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
            limits: crate::policy::Limits::default(),
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
        // The client says QUIT and does not wait for the 221 — there is
        // nothing left to learn from it — so the server's goodbye lands on a
        // closed pipe. That is what every real session looks like.
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
        // A destination or middlebox that answers 220 to STARTTLS and then
        // sends nothing. With the handshake awaited bare there is no data
        // flowing for TCP to give up on, so `deliver` hangs — and the inbound
        // session waiting on us hangs with it, which makes the overall
        // ceiling a fiction. Classifying it as a TLS failure rather than a
        // timeout is what puts it through the plaintext fallback, which is
        // the right answer for a middlebox that mangles TLS.
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
        // The message is on the wire in full. The destination may well have
        // queued it — a slow content scan, or a reply lost to a reset — so
        // moving to the next host sends a second copy, and the recipient gets
        // the message twice. Nothing about a duplicate is recoverable, and a
        // deferral is.
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
        // One inbound message's destination groups share one deadline. A
        // group that reaches the final dot with less than `end_of_data` left
        // is cut off by `Fail::Spent` *after* the body is on the wire, and
        // the destination may well have taken it: the deferral then asks the
        // sending server to send a message that has already been delivered,
        // and the recipient gets two. A deferral decided before DATA costs a
        // retry; one decided after it costs a duplicate, and nothing undoes a
        // duplicate.
        //
        // The first group goes through with the whole deadline in front of
        // it; the wait then spends most of what is left, which is what a
        // first destination taking its time does to the second group.
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
        // A block list's reply is the only useful thing a refused connection
        // produces, and its URL is the only thing the sender can act on.
        // Filing it as "not an SMTP reply" and then letting a connection
        // refused on the next host overwrite it tells the sender nothing at
        // all. In the next milestone this sentence goes straight back to a
        // stranger's mail server.
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
        // `550 5.1.2 no mail exchanger has an address` is permanent and goes
        // back to the sender as a bounce. Reaching it because a slow MX
        // lookup used up the budget before a single host was looked at
        // bounces mail that is perfectly deliverable, on the strength of
        // nothing having been tried.
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
        // hickory will spend five seconds twice per query against an
        // unresponsive resolver. An MX lookup plus one address lookup per
        // exchanger, all outside the clock, puts a 180 second ceiling tens of
        // seconds past three minutes while the inbound sender waits on us.
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
        // `head` is generated in the next PR, and a head without a trailing
        // CRLF followed by a body beginning with a dot produces a stuffed dot
        // inside a line — a changed byte underneath the sender's DKIM
        // signature, which receivers read as forgery.
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
        // `Budget::body` is a stall timeout. Applied to the whole body it is
        // a throughput floor instead — 60 seconds for 25 MiB demands about
        // 3.5 Mbit/s — and a slow but healthy destination has the message cut
        // off part-written and sent again from the start.
        let slow_reader = Mta {
            read_delay: Some(Duration::from_millis(2)),
            ..Mta::default()
        };
        let pipes = Pipes::new(&[("203.0.113.1", Script::Serve(slow_reader))]);
        // 600 lines of a kilobyte each: bigger than the pipe, so the writes
        // really do block on the reader, and 1.2 seconds of reading at two
        // milliseconds a line — twice what one `body` budget allows.
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

    // ------------------------------------------------------- the small pieces

    #[test]
    fn dot_stuffing_touches_only_the_dot() {
        let mut out = Vec::new();
        let ended_a_line = stuff(b".a\r\nb.\r\n..c\r\n\xffd\r\n", true, &mut out);
        assert_eq!(out, b"..a\r\nb.\r\n...c\r\n\xffd\r\n");
        assert!(ended_a_line);
    }

    #[test]
    fn dot_stuffing_carries_the_line_state_between_chunks() {
        // The head and the body are written by two calls over one byte
        // stream. A head that does not end in CRLF leaves the body's first
        // byte mid-line, and a dot there is data — stuffing it changes a byte
        // the sender signed.
        let mut out = Vec::new();
        let at_line_start = stuff(b"X-Spam-Status: No", true, &mut out);
        assert!(!at_line_start);
        stuff(b".hidden\r\n", at_line_start, &mut out);
        assert_eq!(out, b"X-Spam-Status: No.hidden\r\n");
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
