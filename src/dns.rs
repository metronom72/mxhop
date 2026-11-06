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
    let mut state = crate::envelope::now_unix_ms() ^ ((std::process::id() as u64) << 32);
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

    async fn addrs(&self, host: &str) -> Result<Vec<IpAddr>, DnsError> {
        match self.inner.lookup_ip(host).await {
            Ok(answer) => Ok(answer.iter().collect()),
            Err(e) if e.is_no_records_found() => Err(DnsError::NotFound),
            Err(e) => Err(DnsError::Failed(e.to_string())),
        }
    }
}

// ------------------------------------------------------------ the one for tests

/// A resolver with the answers written down. Everything delivery does with
/// DNS is decided by what comes back from these two calls, so a table is
/// enough to drive all of it.
#[derive(Debug, Clone, Default)]
pub struct Table {
    mx: std::collections::BTreeMap<String, Result<Vec<Target>, DnsError>>,
    addrs: std::collections::BTreeMap<String, Result<Vec<IpAddr>, DnsError>>,
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
}

#[cfg(test)]
mod tests {
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

        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..200 {
            let found = targets(&table, "example.com").await.unwrap();
            seen.insert(hosts(&found).join(","));
        }

        assert_eq!(
            seen.len(),
            2,
            "both orders should appear over 200 tries, saw {seen:?}"
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
