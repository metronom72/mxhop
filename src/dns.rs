use std::future::Future;
use std::net::IpAddr;

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub host: String,
    pub pref: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsError {
    NotFound,
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

pub trait Resolve {
    fn mx(&self, domain: &str) -> impl Future<Output = Result<Vec<Target>, DnsError>> + Send;
    fn addrs(&self, host: &str) -> impl Future<Output = Result<Vec<IpAddr>, DnsError>> + Send;
    fn ptr(&self, ip: IpAddr) -> impl Future<Output = Result<String, DnsError>> + Send;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NoRoute {
    NullMx,
    NoSuchDomain,
    Unresolvable(String),
}

impl NoRoute {
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
        return Ok(vec![Target {
            host: normalise(domain),
            pref: 0,
        }]);
    }

    let mut found = found;
    shuffle(&mut found);
    found.sort_by_key(|t| t.pref);
    Ok(found)
}

fn is_null_mx(found: &[Target]) -> bool {
    found.len() == 1 && (found[0].host.is_empty() || found[0].host == ".")
}

fn normalise(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
}

fn shuffle<T>(items: &mut [T]) {
    if items.len() < 2 {
        return;
    }
    static CALLS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let nth = CALLS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut state = crate::envelope::now_unix_ms()
        ^ ((std::process::id() as u64) << 32)
        ^ nth.wrapping_mul(0x9e37_79b9_7f4a_7c15);
    for i in (1..items.len()).rev() {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        items.swap(i, (state % (i as u64 + 1)) as usize);
    }
}

pub struct Hickory {
    inner: hickory_resolver::TokioResolver,
}

impl Hickory {
    pub fn from_system() -> Result<Self, DnsError> {
        let inner = hickory_resolver::Resolver::builder_tokio()
            .map_err(|e| DnsError::Failed(e.to_string()))?
            .build()
            .map_err(|e| DnsError::Failed(e.to_string()))?;
        Ok(Self { inner })
    }

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
                    _ => None,
                })
                .map(|mx| Target {
                    host: normalise(&mx.exchange.to_utf8()),
                    pref: mx.preference,
                })
                .collect()),
            Err(e) if e.is_no_records_found() => Err(DnsError::NotFound),
            Err(e) => Err(DnsError::Failed(e.to_string())),
        }
    }

    async fn addrs(&self, host: &str) -> Result<Vec<IpAddr>, DnsError> {
        let v4 = match self.inner.ipv4_lookup(host).await {
            Ok(answer) => Some(v4_of(&answer)),
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
                .map(|ptr| normalise(&ptr.0.to_ascii()))
                .next()
                .ok_or(DnsError::NotFound),
            Err(e) if e.is_no_records_found() => Err(DnsError::NotFound),
            Err(e) => Err(DnsError::Failed(e.to_string())),
        }
    }
}

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

#[derive(Debug, Clone, Default)]
pub struct Table {
    mx: std::collections::BTreeMap<String, Result<Vec<Target>, DnsError>>,
    addrs: std::collections::BTreeMap<String, Result<Vec<IpAddr>, DnsError>>,
    ptrs: std::collections::BTreeMap<IpAddr, Result<String, DnsError>>,
}

impl Table {
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
    #[derive(Clone, Copy)]
    enum Answer {
        Address,
        Empty,
        ServFail,
    }

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
                out.extend_from_slice(&buf[..2]);
                let rcode: u16 = if matches!(reply, Answer::ServFail) {
                    2
                } else {
                    0
                };
                out.extend_from_slice(&(0x8180 | rcode).to_be_bytes());
                out.extend_from_slice(&1u16.to_be_bytes());
                let answers: u16 = if matches!(reply, Answer::Address) {
                    1
                } else {
                    0
                };
                out.extend_from_slice(&answers.to_be_bytes());
                out.extend_from_slice(&0u16.to_be_bytes());
                out.extend_from_slice(&0u16.to_be_bytes());
                out.extend_from_slice(question);

                if matches!(reply, Answer::Address) {
                    out.extend_from_slice(&0xc00cu16.to_be_bytes());
                    out.extend_from_slice(&qtype.to_be_bytes());
                    out.extend_from_slice(&1u16.to_be_bytes());
                    out.extend_from_slice(&60u32.to_be_bytes());
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

    async fn ptr_nameserver(name: &'static str) -> std::net::SocketAddr {
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

                let mut encoded = Vec::new();
                for label in name.split('.') {
                    encoded.push(label.len() as u8);
                    encoded.extend_from_slice(label.as_bytes());
                }
                encoded.push(0);

                let answers: u16 = u16::from(qtype == 12);
                let mut out = Vec::with_capacity(128);
                out.extend_from_slice(&buf[..2]);
                out.extend_from_slice(&0x8180u16.to_be_bytes());
                out.extend_from_slice(&1u16.to_be_bytes());
                out.extend_from_slice(&answers.to_be_bytes());
                out.extend_from_slice(&0u16.to_be_bytes());
                out.extend_from_slice(&0u16.to_be_bytes());
                out.extend_from_slice(question);

                if answers == 1 {
                    out.extend_from_slice(&0xc00cu16.to_be_bytes());
                    out.extend_from_slice(&12u16.to_be_bytes());
                    out.extend_from_slice(&1u16.to_be_bytes());
                    out.extend_from_slice(&60u32.to_be_bytes());
                    out.extend_from_slice(&(encoded.len() as u16).to_be_bytes());
                    out.extend_from_slice(&encoded);
                }

                let _ = socket.send_to(&out, from).await;
            }
        });

        addr
    }

    #[tokio::test]
    async fn a_reverse_lookup_keeps_an_idna_name_in_its_ascii_form() {
        let server = ptr_nameserver("xn--mller-kva.example.com").await;

        let found = Hickory::against(server)
            .ptr("203.0.113.4".parse().unwrap())
            .await
            .expect("the PTR record");

        assert_eq!(
            found, "xn--mller-kva.example.com",
            "decoded to Unicode this reads m\u{fc}ller.example.com, which is not \
             writable into a trace header and is dropped as unknown"
        );
    }

    #[tokio::test]
    async fn a_servfail_on_the_a_record_is_a_failure_and_not_an_ipv6_only_host() {
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
        let server = nameserver(Answer::Empty, Answer::Address).await;

        let found = Hickory::against(server)
            .addrs("mx.example.com")
            .await
            .expect("the AAAA records");

        assert_eq!(found, vec!["2001:db8::6".parse::<IpAddr>().unwrap()]);
    }

    #[tokio::test]
    async fn the_a_records_come_first_and_a_broken_aaaa_lookup_costs_nothing() {
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
        let table = Table::default().mx("Example.COM.", &[(10, "MX1.Example.COM.")]);

        let found = targets(&table, "example.com").await.unwrap();
        assert_eq!(hosts(&found), vec!["mx1.example.com"]);
    }

    #[tokio::test]
    async fn equal_preferences_do_not_always_come_back_in_the_same_order() {
        let table = Table::default().mx(
            "example.com",
            &[(10, "a.example.com"), (10, "b.example.com")],
        );

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
