//! Finding out where a domain's mail goes.
//!
//! Two lookups and one rule: the MX records of a domain, the addresses of a
//! host, and the knowledge that an answer of "no MX records" is not the same
//! as "this domain takes no mail". The first means the domain's own address
//! is its mail exchanger (RFC 5321 §5.1); the second is said explicitly, with
//! a single MX pointing at the root (RFC 7505), and it is permanent. Getting
//! those two confused either strands mail that is deliverable or retries for
//! five days against a domain that told us not to.

use std::future::Future;
use std::net::IpAddr;

use std::fmt;

/// One mail exchanger, as DNS gave it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// The host name, lowercased and with the trailing dot removed.
    pub host: String,
    /// The MX preference. Lower is tried first.
    pub pref: u16,
}

/// Why a lookup produced nothing.
///
/// The split is between an answer and the absence of one: `NotFound` is DNS
/// saying this name has no such records, which is information. `Failed` is
/// DNS not answering, which is not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsError {
    /// NXDOMAIN, or the name exists with no records of this type.
    NotFound,
    /// A timeout, a SERVFAIL, a broken resolver.
    Failed(String),
}

impl fmt::Display for DnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DnsError::NotFound => f.write_str("no such record"),
            DnsError::Failed(e) => write!(f, "lookup failed: {e}"),
        }
    }
}

/// The two questions delivery asks of DNS. A trait so the tests can answer
/// them from a table instead of the network.
pub trait Resolve {
    fn mx(&self, domain: &str) -> impl Future<Output = Result<Vec<Target>, DnsError>> + Send;
    fn addrs(&self, host: &str) -> impl Future<Output = Result<Vec<IpAddr>, DnsError>> + Send;
    /// The name an address claims, for the `Received` header of an inbound
    /// session. One name: a trace records what the peer looked like, and a
    /// list of every PTR record is not a fact about this connection.
    ///
    /// Unverified on purpose — the forward lookup that would confirm it is
    /// another two queries while a sending server waits on us, and nothing is
    /// decided on the strength of this name. It is written down, and the
    /// address beside it in the same header is the part that cannot be
    /// claimed.
    fn ptr(&self, ip: IpAddr) -> impl Future<Output = Result<String, DnsError>> + Send;
}

/// Why a domain cannot be delivered to at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NoRoute {
    /// RFC 7505: a single MX pointing at the root. The domain is saying, in
    /// the only way DNS has of saying it, that it accepts no mail. Retrying
    /// is pointless, so this is permanent.
    NullMx,
    /// The domain does not exist, or exists with neither MX nor address.
    NoSuchDomain,
    /// DNS did not answer. Nothing is known yet, so nothing is decided.
    Unresolvable(String),
}

impl NoRoute {
    /// Whether the sender should be told to give up rather than retry.
    pub fn is_permanent(&self) -> bool {
        matches!(self, NoRoute::NullMx | NoRoute::NoSuchDomain)
    }
}

impl fmt::Display for NoRoute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NoRoute::NullMx => f.write_str("the domain publishes a null MX and accepts no mail"),
            NoRoute::NoSuchDomain => f.write_str("the domain has no mail exchanger and no address"),
            NoRoute::Unresolvable(e) => write!(f, "cannot be resolved: {e}"),
        }
    }
}

/// The hosts to try for a domain, best first.
///
/// Equal preferences are shuffled rather than returned in the order DNS
/// happened to list them: that is what spreads load across a pair of equal
/// mail exchangers, and DNS servers do not all rotate the set for us.
pub async fn targets<R: Resolve>(resolver: &R, domain: &str) -> Result<Vec<Target>, NoRoute> {
    let found = match resolver.mx(domain).await {
        Ok(found) => found,
        Err(DnsError::NotFound) => Vec::new(),
        Err(DnsError::Failed(e)) => return Err(NoRoute::Unresolvable(e)),
    };

    if is_null_mx(&found) {
        return Err(NoRoute::NullMx);
    }

    if found.is_empty() {
        // RFC 5321 §5.1: no MX at all means the domain is its own mail
        // exchanger. Whether it has an address is answered by the connect
        // loop, which has to resolve the host anyway — asking here would be a
        // second lookup for the same answer.
        return Ok(vec![Target {
            host: normalise(domain),
            pref: 0,
        }]);
    }

    let mut found = found;
    shuffle(&mut found);
    // A stable sort after the shuffle keeps preference authoritative and
    // leaves the shuffled order inside each tie.
    found.sort_by_key(|t| t.pref);
    Ok(found)
}

/// RFC 7505: exactly one MX, and its target is the root. Anything else that
/// merely *contains* a root target is a misconfiguration rather than a
/// statement, and the other records are still worth trying.
fn is_null_mx(found: &[Target]) -> bool {
    found.len() == 1 && (found[0].host.is_empty() || found[0].host == ".")
}

fn normalise(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
}

/// A shuffle that needs no dependency and no cryptographic quality: the only
/// thing asked of it is that two mail exchangers of equal preference do not
/// always get tried in the same order.
fn shuffle<T>(items: &mut [T]) {
    if items.len() < 2 {
        return;
    }
    // The counter is what makes two calls in the same millisecond differ.
    // Without it the seed is constant for as long as the clock reads the same,
    // and every message in a burst picks the same exchanger — which is the
    // thing the shuffle exists to prevent.
    static CALLS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let nth = CALLS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut state = crate::envelope::now_unix_ms()
        ^ ((std::process::id() as u64) << 32)
        ^ nth.wrapping_mul(0x9e37_79b9_7f4a_7c15);
    for i in (1..items.len()).rev() {
        // xorshift64; good enough to break a tie, and nothing else rests on
        // it.
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        items.swap(i, (state % (i as u64 + 1)) as usize);
    }
}

// ------------------------------------------------------------------ the real one

/// The resolver the service uses: the system's, through hickory.
pub struct Hickory {
    inner: hickory_resolver::TokioResolver,
}

impl Hickory {
    /// Builds a resolver from the system's own configuration. A forwarder
    /// that invented its own resolver list would stop agreeing with the host
    /// it runs on, which is the first thing an operator checks with `dig`.
    pub fn from_system() -> Result<Self, DnsError> {
        let inner = hickory_resolver::Resolver::builder_tokio()
            .map_err(|e| DnsError::Failed(e.to_string()))?
            .build()
            .map_err(|e| DnsError::Failed(e.to_string()))?;
        Ok(Self { inner })
    }

    /// A resolver that asks exactly one nameserver, for the tests. The two
    /// kinds of A-lookup failure can only be told apart by what a nameserver
    /// actually answers, so the test needs one it can make answer SERVFAIL.
    #[cfg(test)]
    fn against(server: std::net::SocketAddr) -> Self {
        use hickory_resolver::config::{ConnectionConfig, NameServerConfig, ResolverConfig};

        let mut udp = ConnectionConfig::udp();
        udp.port = server.port();
        let config = ResolverConfig::from_parts(
            None,
            Vec::new(),
            vec![{
                let mut ns = NameServerConfig::udp(server.ip());
                ns.connections = vec![udp];
                ns
            }],
        );
        let mut builder = hickory_resolver::Resolver::builder_with_config(
            config,
            hickory_resolver::net::runtime::TokioRuntimeProvider::default(),
        );
        // One question, one answer: no retries, no fallback to TCP and no
        // cache, so the test reads back exactly what it scripted.
        builder.options_mut().attempts = 0;
        builder.options_mut().try_tcp_on_error = false;
        builder.options_mut().cache_size = 0;
        Self {
            inner: builder.build().expect("a resolver"),
        }
    }
}

impl Resolve for Hickory {
    async fn mx(&self, domain: &str) -> Result<Vec<Target>, DnsError> {
        match self.inner.mx_lookup(domain).await {
            Ok(answer) => Ok(answer
                .answers()
                .iter()
                .filter_map(|record| match &record.data {
                    hickory_resolver::proto::rr::RData::MX(mx) => Some(mx),
                    // A CNAME or anything else in the answer section is not a
                    // mail exchanger, and an MX query can come back with
                    // company.
                    _ => None,
                })
                .map(|mx| Target {
                    host: normalise(&mx.exchange.to_utf8()),
                    pref: mx.preference,
                })
                .collect()),
            // "this name has no MX records" is an answer, and a different one
            // from "the resolver did not reply".
            Err(e) if e.is_no_records_found() => Err(DnsError::NotFound),
            Err(e) => Err(DnsError::Failed(e.to_string())),
        }
    }

    /// The A records first and the AAAA records after them, with the two
    /// kinds of A failure kept apart.
    ///
    /// Not `lookup_ip`: its `Ipv4thenIpv6` strategy falls through to AAAA on
    /// *any* A error, SERVFAIL and timeout included. The caller then sees a
    /// host with IPv6 addresses and no IPv4 ones, which is indistinguishable
    /// from a host that publishes only AAAA — and a host that publishes only
    /// AAAA is dialled over IPv6 even with `ipv6 = false`, because the
    /// alternative would be not delivering at all. On a VPS with no matching
    /// IPv6 PTR that earns Gmail's `550-5.7.25`, which is read as a permanent
    /// refusal and relayed to the sender. A transient resolver hiccup must
    /// not be able to bounce somebody's mail, so an A lookup that failed is
    /// reported as a failure and the AAAA query is not used to paper over it.
    async fn addrs(&self, host: &str) -> Result<Vec<IpAddr>, DnsError> {
        let v4 = match self.inner.ipv4_lookup(host).await {
            Ok(answer) => Some(v4_of(&answer)),
            // "this name has no A records" is an answer, and the only one
            // that justifies asking for AAAA instead.
            Err(e) if e.is_no_records_found() => None,
            Err(e) => return Err(DnsError::Failed(e.to_string())),
        };

        let Some(v4) = v4 else {
            return match self.inner.ipv6_lookup(host).await {
                Ok(answer) => Ok(v6_of(&answer)),
                Err(e) if e.is_no_records_found() => Err(DnsError::NotFound),
                Err(e) => Err(DnsError::Failed(e.to_string())),
            };
        };

        // There is a route either way now, so an AAAA lookup that fails costs
        // nothing but the addresses it would have added.
        let v6 = self
            .inner
            .ipv6_lookup(host)
            .await
            .map(|answer| v6_of(&answer))
            .unwrap_or_default();
        Ok(v4.into_iter().chain(v6).collect())
    }

    async fn ptr(&self, ip: IpAddr) -> Result<String, DnsError> {
        match self.inner.reverse_lookup(ip).await {
            Ok(answer) => answer
                .answers()
                .iter()
                .filter_map(|record| match &record.data {
                    hickory_resolver::proto::rr::RData::PTR(ptr) => Some(ptr),
                    _ => None,
                })
                .map(|ptr| normalise(&ptr.0.to_utf8()))
                .next()
                .ok_or(DnsError::NotFound),
            Err(e) if e.is_no_records_found() => Err(DnsError::NotFound),
            Err(e) => Err(DnsError::Failed(e.to_string())),
        }
    }
}

/// The A records of an answer. An A lookup's answer section can carry a
/// CNAME chain as well, which is not an address.
fn v4_of(answer: &hickory_resolver::lookup::Lookup) -> Vec<IpAddr> {
    answer
        .answers()
        .iter()
        .filter_map(|record| match &record.data {
            hickory_resolver::proto::rr::RData::A(a) => Some(IpAddr::V4(a.0)),
            _ => None,
        })
        .collect()
}

fn v6_of(answer: &hickory_resolver::lookup::Lookup) -> Vec<IpAddr> {
    answer
        .answers()
        .iter()
        .filter_map(|record| match &record.data {
            hickory_resolver::proto::rr::RData::AAAA(aaaa) => Some(IpAddr::V6(aaaa.0)),
            _ => None,
        })
        .collect()
}

// ------------------------------------------------------------ the one for tests

/// A resolver with the answers written down. Everything delivery does with
/// DNS is decided by what comes back from these two calls, so a table is
/// enough to drive all of it.
#[derive(Debug, Clone, Default)]
pub struct Table {
    mx: std::collections::BTreeMap<String, Result<Vec<Target>, DnsError>>,
    addrs: std::collections::BTreeMap<String, Result<Vec<IpAddr>, DnsError>>,
    ptrs: std::collections::BTreeMap<IpAddr, Result<String, DnsError>>,
}

impl Table {
    /// `hosts` is `(preference, host)` pairs in the order DNS would list them.
    pub fn mx(mut self, domain: &str, hosts: &[(u16, &str)]) -> Self {
        self.mx.insert(
            normalise(domain),
            Ok(hosts
                .iter()
                .map(|(pref, host)| Target {
                    host: normalise(host),
                    pref: *pref,
                })
                .collect()),
        );
        self
    }

    pub fn mx_error(mut self, domain: &str, e: DnsError) -> Self {
        self.mx.insert(normalise(domain), Err(e));
        self
    }

    pub fn addr(mut self, host: &str, addr: IpAddr) -> Self {
        self.addrs
            .entry(normalise(host))
            .or_insert_with(|| Ok(Vec::new()))
            .as_mut()
            .expect("an address list, not an error")
            .push(addr);
        self
    }

    /// The name an address reverse-resolves to.
    pub fn ptr(mut self, ip: IpAddr, name: &str) -> Self {
        self.ptrs.insert(ip, Ok(normalise(name)));
        self
    }

    pub fn addr_error(mut self, host: &str, e: DnsError) -> Self {
        self.addrs.insert(normalise(host), Err(e));
        self
    }
}

impl Resolve for Table {
    async fn mx(&self, domain: &str) -> Result<Vec<Target>, DnsError> {
        self.mx
            .get(&normalise(domain))
            .cloned()
            .unwrap_or(Err(DnsError::NotFound))
    }

    async fn addrs(&self, host: &str) -> Result<Vec<IpAddr>, DnsError> {
        self.addrs
            .get(&normalise(host))
            .cloned()
            .unwrap_or(Err(DnsError::NotFound))
    }

    async fn ptr(&self, ip: IpAddr) -> Result<String, DnsError> {
        self.ptrs
            .get(&ip)
            .cloned()
            .unwrap_or(Err(DnsError::NotFound))
    }
}

#[cfg(test)]
mod tests {
    // ------------------------------------------ a nameserver that can be rude

    /// What the fake nameserver does with one question.
    #[derive(Clone, Copy)]
    enum Answer {
        /// One address record of the matching type.
        Address,
        /// NOERROR with nothing in it: this name has no records of this type.
        Empty,
        /// SERVFAIL — the resolver did not answer the question.
        ServFail,
    }

    /// A nameserver that answers A and AAAA separately and however it is
    /// told. The whole point of the `addrs` rewrite is which *kind* of A
    /// failure is allowed to fall through to AAAA, and only a real
    /// nameserver's rcode can tell a SERVFAIL from an empty answer — a table
    /// of addresses cannot express the difference at all.
    async fn nameserver(a: Answer, aaaa: Answer) -> std::net::SocketAddr {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("a port");
        let addr = socket.local_addr().expect("the port");

        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                let Ok((n, from)) = socket.recv_from(&mut buf).await else {
                    return;
                };
                if n < 12 {
                    continue;
                }
                // Walk the single question: labels, then qtype and qclass.
                let mut at = 12;
                while at < n && buf[at] != 0 {
                    at += 1 + buf[at] as usize;
                }
                if at + 5 > n {
                    continue;
                }
                let end = at + 5;
                let qtype = u16::from_be_bytes([buf[at + 1], buf[at + 2]]);
                let question = &buf[12..end];

                let reply = match qtype {
                    1 => a,
                    28 => aaaa,
                    _ => Answer::Empty,
                };

                let mut out = Vec::with_capacity(64);
                out.extend_from_slice(&buf[..2]); // the query's id
                // QR, recursion desired and available, and the rcode.
                let rcode: u16 = if matches!(reply, Answer::ServFail) {
                    2
                } else {
                    0
                };
                out.extend_from_slice(&(0x8180 | rcode).to_be_bytes());
                out.extend_from_slice(&1u16.to_be_bytes()); // one question
                let answers: u16 = if matches!(reply, Answer::Address) {
                    1
                } else {
                    0
                };
                out.extend_from_slice(&answers.to_be_bytes());
                out.extend_from_slice(&0u16.to_be_bytes()); // no authorities
                out.extend_from_slice(&0u16.to_be_bytes()); // no additionals
                out.extend_from_slice(question);

                if matches!(reply, Answer::Address) {
                    out.extend_from_slice(&0xc00cu16.to_be_bytes()); // the question's name
                    out.extend_from_slice(&qtype.to_be_bytes());
                    out.extend_from_slice(&1u16.to_be_bytes()); // IN
                    out.extend_from_slice(&60u32.to_be_bytes()); // ttl
                    if qtype == 1 {
                        out.extend_from_slice(&4u16.to_be_bytes());
                        out.extend_from_slice(&[203, 0, 113, 4]);
                    } else {
                        out.extend_from_slice(&16u16.to_be_bytes());
                        let v6: std::net::Ipv6Addr = "2001:db8::6".parse().unwrap();
                        out.extend_from_slice(&v6.octets());
                    }
                }

                let _ = socket.send_to(&out, from).await;
            }
        });

        addr
    }

    #[tokio::test]
    async fn a_servfail_on_the_a_record_is_a_failure_and_not_an_ipv6_only_host() {
        // `lookup_ip`'s default `Ipv4thenIpv6` strategy queries AAAA on *any*
        // A error, SERVFAIL and timeout included. The caller then sees a host
        // with AAAA records and no A records, which is indistinguishable from
        // a host that publishes only AAAA — and such a host is dialled over
        // IPv6 even with `ipv6 = false`, because the alternative is not
        // delivering at all. From a VPS with no matching IPv6 PTR Gmail
        // answers `550-5.7.25`, which is read as permanent and bounced back
        // to the sender. A transient resolver hiccup must not be able to do
        // that.
        let server = nameserver(Answer::ServFail, Answer::Address).await;

        let found = Hickory::against(server).addrs("mx.example.com").await;

        assert!(
            matches!(found, Err(DnsError::Failed(_))),
            "a resolver that did not answer the A question has said nothing, \
             and the AAAA answer must not stand in for it: {found:?}"
        );
    }

    #[tokio::test]
    async fn a_name_with_no_a_record_falls_through_to_its_aaaa_records() {
        // The one A failure that *is* an answer. A destination that publishes
        // only AAAA would otherwise be undeliverable.
        let server = nameserver(Answer::Empty, Answer::Address).await;

        let found = Hickory::against(server)
            .addrs("mx.example.com")
            .await
            .expect("the AAAA records");

        assert_eq!(found, vec!["2001:db8::6".parse::<IpAddr>().unwrap()]);
    }

    #[tokio::test]
    async fn the_a_records_come_first_and_a_broken_aaaa_lookup_costs_nothing() {
        // There is a route either way once the A lookup has answered, so an
        // AAAA query that fails must not take the delivery down with it — and
        // IPv4 has to stay in front, which is the preference the whole of
        // `usable` rests on.
        let server = nameserver(Answer::Address, Answer::ServFail).await;

        let found = Hickory::against(server)
            .addrs("mx.example.com")
            .await
            .expect("the A records");

        assert_eq!(found, vec!["203.0.113.4".parse::<IpAddr>().unwrap()]);
    }

    #[tokio::test]
    async fn a_name_with_neither_kind_of_address_is_not_found() {
        let server = nameserver(Answer::Empty, Answer::Empty).await;

        let found = Hickory::against(server).addrs("mx.example.com").await;

        assert_eq!(
            found,
            Err(DnsError::NotFound),
            "DNS answered that this name has no address, which is information \
             and not a silence"
        );
    }

    use super::*;

    fn hosts(found: &[Target]) -> Vec<&str> {
        found.iter().map(|t| t.host.as_str()).collect()
    }

    #[tokio::test]
    async fn mx_records_come_back_in_preference_order() {
        // DNS lists them however it likes; delivery has to try the lowest
        // preference first or it ignores the domain's own ranking.
        let table = Table::default().mx(
            "example.com",
            &[(30, "third.example.com"), (10, "first.example.com")],
        );

        let found = targets(&table, "example.com").await.unwrap();
        assert_eq!(
            hosts(&found),
            vec!["first.example.com", "third.example.com"]
        );
    }

    #[tokio::test]
    async fn a_domain_without_mx_falls_back_to_its_own_name() {
        let table = Table::default();

        let found = targets(&table, "example.com").await.unwrap();
        assert_eq!(
            found,
            vec![Target {
                host: "example.com".into(),
                pref: 0
            }],
            "RFC 5321 §5.1: no MX means the domain is its own mail exchanger"
        );
    }

    #[tokio::test]
    async fn a_null_mx_is_a_permanent_failure() {
        let table = Table::default().mx("example.com", &[(0, ".")]);

        let e = targets(&table, "example.com").await.unwrap_err();
        assert_eq!(e, NoRoute::NullMx);
        assert!(
            e.is_permanent(),
            "retrying a domain that said it takes no mail wastes five days of queue"
        );
    }

    #[tokio::test]
    async fn a_root_target_among_others_is_a_misconfiguration_not_a_null_mx() {
        let table = Table::default().mx("example.com", &[(0, "."), (10, "mx.example.com")]);

        let found = targets(&table, "example.com").await.unwrap();
        assert!(
            hosts(&found).contains(&"mx.example.com"),
            "one unusable record must not throw away a usable one: {found:?}"
        );
    }

    #[tokio::test]
    async fn a_resolver_that_does_not_answer_is_not_a_permanent_failure() {
        let table = Table::default().mx_error("example.com", DnsError::Failed("timeout".into()));

        let e = targets(&table, "example.com").await.unwrap_err();
        assert!(
            !e.is_permanent(),
            "a broken resolver must not bounce other people's mail: {e:?}"
        );
    }

    #[tokio::test]
    async fn the_trailing_dot_and_the_case_of_a_record_are_normalised() {
        // hickory hands back fully qualified names with the root dot on, and
        // the host name is used both for the TLS name and for logging.
        let table = Table::default().mx("Example.COM.", &[(10, "MX1.Example.COM.")]);

        let found = targets(&table, "example.com").await.unwrap();
        assert_eq!(hosts(&found), vec!["mx1.example.com"]);
    }

    #[tokio::test]
    async fn equal_preferences_do_not_always_come_back_in_the_same_order() {
        // Without a shuffle every message in the queue hits the same one of a
        // pair of equal exchangers.
        let table = Table::default().mx(
            "example.com",
            &[(10, "a.example.com"), (10, "b.example.com")],
        );

        // Twenty tries, all inside one millisecond: a seed that only moves
        // with the clock would give the same order for every one of them.
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..20 {
            let found = targets(&table, "example.com").await.unwrap();
            seen.insert(hosts(&found).join(","));
        }

        assert_eq!(
            seen.len(),
            2,
            "both orders should appear over 20 tries in the same \
             millisecond, saw {seen:?}"
        );
    }

    #[tokio::test]
    async fn preference_still_wins_after_the_shuffle() {
        let table = Table::default().mx(
            "example.com",
            &[
                (20, "c.example.com"),
                (10, "a.example.com"),
                (10, "b.example.com"),
            ],
        );

        for _ in 0..50 {
            let found = targets(&table, "example.com").await.unwrap();
            assert_eq!(found[2].host, "c.example.com", "{found:?}");
        }
    }
}
