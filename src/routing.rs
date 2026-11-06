//! The alias table, and the lookup the SMTP session performs for every
//! recipient.

use std::collections::BTreeMap;
use std::fmt;

/// An address mail can be handed to: a local part and a domain.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Mailbox {
    local: String,
    domain: String,
}

impl Mailbox {
    /// Parses `local@domain`.
    ///
    /// Deliberately narrower than RFC 5321: no quoted local parts, no address
    /// literals, no source routes. They exist, but not in anyone's alias
    /// table, and refusing them here keeps the surface honest.
    pub fn parse(s: &str) -> Result<Self, MailboxError> {
        if s.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err(MailboxError::IllegalCharacter);
        }
        // RFC 5321 reads the separator from the right: the local part may hold
        // an `@`, the domain may not.
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

    /// The local part, with its case preserved — the destination mailbox is
    /// entitled to care about it.
    pub fn local(&self) -> &str {
        &self.local
    }

    /// The domain, always lowercase.
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

/// Whether a name can be looked up in DNS as written: at least two labels,
/// none of them empty, nothing in them that cannot be in a host name.
///
/// A bare `localhost` fails, which is the point — both the HELO name mxhop
/// announces and every destination domain have to be resolvable from the
/// outside, or the MX lookup is meaningless.
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

/// What to do with mail for one local part.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route {
    /// Hand the message to these mailboxes.
    Forward(Vec<Mailbox>),
    /// Refuse it during the SMTP session, with this reply.
    Reject(String),
}

/// The alias table of a single domain.
#[derive(Debug, Clone, Default)]
struct DomainRoutes {
    exact: BTreeMap<String, Route>,
    catch_all: Option<Route>,
}

/// Every domain mxhop accepts mail for.
#[derive(Debug, Clone, Default)]
pub struct Router {
    domains: BTreeMap<String, DomainRoutes>,
}

/// The local part that stands for "everything else in this domain".
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

    /// Looks up one recipient. `None` means mxhop does not handle it, and the
    /// session has to answer 550.
    pub fn route(&self, domain: &str, local: &str) -> Option<&Route> {
        self.resolve(domain, local).map(|(_, route)| route)
    }

    /// Like [`Router::route`], and also says *which* alias answered — the
    /// local part itself, or [`CATCH_ALL`]. The session logs it, and the
    /// configuration check needs it to tell a catch-all loop from an ordinary
    /// hop.
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
