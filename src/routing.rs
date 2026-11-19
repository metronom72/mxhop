use std::collections::BTreeMap;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Mailbox {
    local: String,
    domain: String,
}

impl Mailbox {
    pub fn parse(s: &str) -> Result<Self, MailboxError> {
        if s.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err(MailboxError::IllegalCharacter);
        }
        let (local, domain) = s.rsplit_once('@').ok_or(MailboxError::NoAt)?;
        if local.is_empty() {
            return Err(MailboxError::EmptyLocal);
        }
        if domain.is_empty() {
            return Err(MailboxError::EmptyDomain);
        }
        if !is_qualified(domain) {
            return Err(MailboxError::DomainNotQualified);
        }
        Ok(Self {
            local: local.to_string(),
            domain: domain.to_ascii_lowercase(),
        })
    }

    pub fn local(&self) -> &str {
        &self.local
    }

    pub fn domain(&self) -> &str {
        &self.domain
    }
}

impl fmt::Display for Mailbox {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.local, self.domain)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MailboxError {
    NoAt,
    EmptyLocal,
    EmptyDomain,
    DomainNotQualified,
    IllegalCharacter,
}

impl fmt::Display for MailboxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            MailboxError::NoAt => "is not an email address (no @)",
            MailboxError::EmptyLocal => "has nothing before the @",
            MailboxError::EmptyDomain => "has nothing after the @",
            MailboxError::DomainNotQualified => "has a domain that is not fully qualified",
            MailboxError::IllegalCharacter => "contains a space or a control character",
        };
        f.write_str(s)
    }
}

pub fn is_qualified(name: &str) -> bool {
    if name.is_empty() || name.len() > 253 {
        return false;
    }
    let labels: Vec<&str> = name.split('.').collect();
    labels.len() >= 2
        && labels.iter().all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        })
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Target {
    pub mailbox: Mailbox,
    pub via: Option<String>,
}

impl Target {
    pub fn new(mailbox: Mailbox) -> Self {
        Self { mailbox, via: None }
    }

    pub fn via(mailbox: Mailbox, host: &str) -> Self {
        Self {
            mailbox,
            via: Some(host.to_ascii_lowercase()),
        }
    }

    pub fn domain(&self) -> &str {
        self.mailbox.domain()
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.via {
            Some(host) => write!(f, "{} via {host}", self.mailbox),
            None => write!(f, "{}", self.mailbox),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route {
    Forward(Vec<Mailbox>),
    Via { to: Mailbox, host: String },
    Reject(String),
}

#[derive(Debug, Clone, Default)]
struct DomainRoutes {
    exact: BTreeMap<String, Route>,
    catch_all: Option<Route>,
}

#[derive(Debug, Clone, Default)]
pub struct Router {
    domains: BTreeMap<String, DomainRoutes>,
}

pub const CATCH_ALL: &str = "*";

impl Router {
    pub fn insert(&mut self, domain: &str, local: &str, route: Route) {
        let domain = self.domains.entry(domain.to_ascii_lowercase()).or_default();
        if local == CATCH_ALL {
            domain.catch_all = Some(route);
        } else {
            domain.exact.insert(local.to_ascii_lowercase(), route);
        }
    }

    pub fn route(&self, domain: &str, local: &str) -> Option<&Route> {
        self.resolve(domain, local).map(|(_, route)| route)
    }

    pub fn resolve(&self, domain: &str, local: &str) -> Option<(&str, &Route)> {
        let domain = self.domains.get(&domain.to_ascii_lowercase())?;
        if let Some((name, route)) = domain.exact.get_key_value(&local.to_ascii_lowercase()) {
            return Some((name.as_str(), route));
        }
        domain.catch_all.as_ref().map(|route| (CATCH_ALL, route))
    }

    pub fn handles_domain(&self, domain: &str) -> bool {
        self.domains.contains_key(&domain.to_ascii_lowercase())
    }

    pub fn domains(&self) -> impl Iterator<Item = &str> {
        self.domains.keys().map(String::as_str)
    }

    pub fn via_hosts(&self) -> BTreeMap<String, Vec<String>> {
        let mut hosts: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (domain, routes) in &self.domains {
            let all = routes
                .exact
                .iter()
                .map(|(local, route)| (local.as_str(), route))
                .chain(routes.catch_all.iter().map(|r| (CATCH_ALL, r)));
            for (local, route) in all {
                if let Route::Via { host, .. } = route {
                    hosts
                        .entry(host.clone())
                        .or_default()
                        .push(format!("{local}@{domain}"));
                }
            }
        }
        hosts
    }

    pub fn alias_count(&self) -> usize {
        self.domains
            .values()
            .map(|d| d.exact.len() + usize::from(d.catch_all.is_some()))
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn forward(to: &str) -> Route {
        Route::Forward(vec![Mailbox::parse(to).unwrap()])
    }

    #[test]
    fn exact_match_wins_over_the_catch_all() {
        let mut r = Router::default();
        r.insert("example.com", "hi", forward("hi@gmail.com"));
        r.insert("example.com", CATCH_ALL, forward("catch@gmail.com"));

        assert_eq!(r.route("example.com", "hi"), Some(&forward("hi@gmail.com")));
    }

    #[test]
    fn the_catch_all_absorbs_unknown_local_parts() {
        let mut r = Router::default();
        r.insert("example.com", CATCH_ALL, forward("catch@gmail.com"));

        assert_eq!(
            r.route("example.com", "anything"),
            Some(&forward("catch@gmail.com"))
        );
    }

    #[test]
    fn without_a_catch_all_an_unknown_local_part_is_not_ours() {
        let mut r = Router::default();
        r.insert("example.com", "hi", forward("hi@gmail.com"));

        assert_eq!(r.route("example.com", "nobody"), None);
    }

    #[test]
    fn a_domain_we_do_not_serve_is_not_ours() {
        let mut r = Router::default();
        r.insert("example.com", CATCH_ALL, forward("catch@gmail.com"));

        assert_eq!(r.route("elsewhere.com", "hi"), None);
    }

    #[test]
    fn lookup_ignores_case_in_both_halves() {
        let mut r = Router::default();
        r.insert("Example.COM", "Hi", forward("hi@gmail.com"));

        assert_eq!(
            r.route("EXAMPLE.com", "hI"),
            Some(&forward("hi@gmail.com")),
            "SMTP domains are case insensitive, and alias names are too"
        );
    }

    #[test]
    fn a_reject_route_comes_back_whole() {
        let mut r = Router::default();
        r.insert(
            "example.com",
            "noreply",
            Route::Reject("550 5.1.1 this address does not accept mail".into()),
        );

        assert_eq!(
            r.route("example.com", "noreply"),
            Some(&Route::Reject(
                "550 5.1.1 this address does not accept mail".into()
            ))
        );
    }

    #[test]
    fn a_mailbox_round_trips_through_display() {
        assert_eq!(
            Mailbox::parse("a.b+tag@mail.example.com")
                .unwrap()
                .to_string(),
            "a.b+tag@mail.example.com"
        );
    }

    #[test]
    fn a_mailbox_needs_both_halves_and_a_qualified_domain() {
        assert_eq!(Mailbox::parse("nobody"), Err(MailboxError::NoAt));
        assert_eq!(
            Mailbox::parse("@example.com"),
            Err(MailboxError::EmptyLocal)
        );
        assert_eq!(Mailbox::parse("hi@"), Err(MailboxError::EmptyDomain));
        assert_eq!(
            Mailbox::parse("hi@localhost"),
            Err(MailboxError::DomainNotQualified),
            "a bare host would make the MX lookup meaningless"
        );
        assert_eq!(
            Mailbox::parse("hi there@example.com"),
            Err(MailboxError::IllegalCharacter)
        );
    }

    #[test]
    fn the_local_part_keeps_its_case_but_the_domain_does_not() {
        let m = Mailbox::parse("First.Last@Example.com").unwrap();
        assert_eq!(m.local(), "First.Last");
        assert_eq!(m.domain(), "example.com");
    }

    #[test]
    fn the_last_at_sign_separates_the_halves() {
        let m = Mailbox::parse("odd@local@example.com").unwrap();
        assert_eq!(m.local(), "odd@local", "RFC 5321 reads from the right");
        assert_eq!(m.domain(), "example.com");
    }

    #[test]
    fn counting_sees_the_catch_all_as_one_alias() {
        let mut r = Router::default();
        r.insert("example.com", "hi", forward("hi@gmail.com"));
        r.insert("example.com", CATCH_ALL, forward("catch@gmail.com"));

        assert_eq!(r.alias_count(), 2);
        assert_eq!(r.domains().collect::<Vec<_>>(), vec!["example.com"]);
    }
}
