//! Turning a protocol line into a command.
//!
//! Kept separate from the session, and pure, because this is where a mail
//! server meets whatever the internet decides to send it: pipelined lines,
//! lowercase verbs, a space after the colon, `<>`, parameters in any order.

use std::fmt;

/// A command as mxhop understands it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Ehlo(String),
    Helo(String),
    Mail {
        /// `None` is the null sender, `<>`, which every bounce uses.
        from: Option<String>,
        /// What the client claims the message will weigh.
        size: Option<u64>,
        /// Whether the client announced 8-bit content.
        body_8bitmime: bool,
    },
    Rcpt(String),
    Data,
    Rset,
    Noop,
    /// RFC 3207: the client asks to start a TLS handshake. Whether mxhop can
    /// is the session's business, not the parser's.
    StartTls,
    Quit,
    /// `VRFY` and `EXPN` — answered, never obeyed: an alias table is not a
    /// directory for strangers to read.
    Vrfy,
    Help,
    /// A verb mxhop does not implement, kept for the reply.
    Unknown(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandError {
    /// `MAIL`/`RCPT` without the `FROM:`/`TO:` part.
    MissingPath { verb: &'static str },
    /// A path that is not `<address>`.
    MalformedPath { verb: &'static str },
    /// `SIZE=` that is not a number.
    MalformedSize,
    /// A parameter mxhop does not implement.
    UnknownParameter(String),
    /// A non-ASCII envelope, which needs SMTPUTF8 — not advertised in v1.
    NeedsSmtpUtf8,
    /// A verb with arguments it should not have.
    UnexpectedArguments { verb: &'static str },
}

impl fmt::Display for CommandError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CommandError::MissingPath { verb } => {
                write!(f, "501 5.5.4 {verb} needs an address in angle brackets")
            }
            CommandError::MalformedPath { verb } => {
                write!(f, "501 5.1.3 {verb} address is not <local@domain>")
            }
            CommandError::MalformedSize => f.write_str("501 5.5.4 SIZE must be a number"),
            CommandError::UnknownParameter(p) => {
                write!(f, "555 5.5.4 parameter {p} is not implemented")
            }
            CommandError::NeedsSmtpUtf8 => {
                f.write_str("550 5.6.7 this address needs SMTPUTF8, which is not offered")
            }
            CommandError::UnexpectedArguments { verb } => {
                write!(f, "501 5.5.4 {verb} takes no arguments")
            }
        }
    }
}

/// Parses one command line (without its terminator).
pub fn parse(line: &str) -> Result<Command, CommandError> {
    let line = line.trim_end();
    let (verb, rest) = match line.split_once(' ') {
        Some((verb, rest)) => (verb, rest.trim_start()),
        None => (line, ""),
    };

    match verb.to_ascii_uppercase().as_str() {
        "EHLO" => Ok(Command::Ehlo(rest.to_string())),
        "HELO" => Ok(Command::Helo(rest.to_string())),
        "MAIL" => parse_mail(rest),
        "RCPT" => parse_rcpt(rest),
        "DATA" => no_arguments(rest, "DATA", Command::Data),
        "RSET" => no_arguments(rest, "RSET", Command::Rset),
        "QUIT" => no_arguments(rest, "QUIT", Command::Quit),
        "STARTTLS" => no_arguments(rest, "STARTTLS", Command::StartTls),
        // RFC 5321 gives NOOP an optional argument, and some clients use it
        // as a keepalive.
        "NOOP" => Ok(Command::Noop),
        "VRFY" | "EXPN" => Ok(Command::Vrfy),
        "HELP" => Ok(Command::Help),
        other => Ok(Command::Unknown(other.to_string())),
    }
}

fn no_arguments(rest: &str, verb: &'static str, command: Command) -> Result<Command, CommandError> {
    if rest.is_empty() {
        Ok(command)
    } else {
        Err(CommandError::UnexpectedArguments { verb })
    }
}

fn parse_mail(rest: &str) -> Result<Command, CommandError> {
    let after = keyword(rest, "FROM").ok_or(CommandError::MissingPath { verb: "MAIL" })?;
    let (path, params) = path(after).ok_or(CommandError::MalformedPath { verb: "MAIL" })?;

    // An empty path is `<>`: the null sender, which is how every bounce in
    // the world identifies itself.
    let from = if path.is_empty() {
        None
    } else {
        Some(address(path, "MAIL")?)
    };

    let mut size = None;
    let mut body_8bitmime = false;
    for parameter in params.split_whitespace() {
        let (key, value) = parameter.split_once('=').unwrap_or((parameter, ""));
        match key.to_ascii_uppercase().as_str() {
            "SIZE" => size = Some(value.parse().map_err(|_| CommandError::MalformedSize)?),
            "BODY" => match value.to_ascii_uppercase().as_str() {
                "8BITMIME" => body_8bitmime = true,
                "7BIT" => {}
                other => return Err(CommandError::UnknownParameter(format!("BODY={other}"))),
            },
            // Accepting a parameter we do not honour would be a lie about
            // what happens to the message.
            other => return Err(CommandError::UnknownParameter(other.to_string())),
        }
    }

    Ok(Command::Mail {
        from,
        size,
        body_8bitmime,
    })
}

fn parse_rcpt(rest: &str) -> Result<Command, CommandError> {
    let after = keyword(rest, "TO").ok_or(CommandError::MissingPath { verb: "RCPT" })?;
    let (path, params) = path(after).ok_or(CommandError::MalformedPath { verb: "RCPT" })?;

    if let Some(parameter) = params.split_whitespace().next() {
        let key = parameter.split_once('=').map_or(parameter, |(k, _)| k);
        return Err(CommandError::UnknownParameter(key.to_ascii_uppercase()));
    }

    Ok(Command::Rcpt(address(path, "RCPT")?))
}

/// `FROM:` / `TO:`, in any case, with or without a space before the path.
fn keyword<'a>(rest: &'a str, word: &str) -> Option<&'a str> {
    let rest = rest.trim_start();
    let head = rest.get(..word.len())?;
    if !head.eq_ignore_ascii_case(word) {
        return None;
    }
    let after = rest[word.len()..].trim_start();
    Some(after.strip_prefix(':')?.trim_start())
}

/// Splits `<address> PARAMS` into the address and whatever follows.
fn path(s: &str) -> Option<(&str, &str)> {
    let inner = s.trim_start().strip_prefix('<')?;
    let end = inner.find('>')?;
    Some((&inner[..end], inner[end + 1..].trim_start()))
}

fn address(path: &str, verb: &'static str) -> Result<String, CommandError> {
    // SMTPUTF8 is not advertised, so a non-ASCII envelope is something mxhop
    // cannot carry — and saying so is better than mangling it.
    if !path.is_ascii() {
        return Err(CommandError::NeedsSmtpUtf8);
    }
    let (local, domain) = path
        .rsplit_once('@')
        .ok_or(CommandError::MalformedPath { verb })?;
    if local.is_empty() || domain.is_empty() {
        return Err(CommandError::MalformedPath { verb });
    }
    Ok(path.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mail(from: Option<&str>) -> Command {
        Command::Mail {
            from: from.map(str::to_string),
            size: None,
            body_8bitmime: false,
        }
    }

    #[test]
    fn verbs_are_case_insensitive() {
        assert_eq!(
            parse("ehlo mx.test").unwrap(),
            Command::Ehlo("mx.test".into())
        );
        assert_eq!(
            parse("EHLO mx.test").unwrap(),
            Command::Ehlo("mx.test".into())
        );
        assert_eq!(
            parse("eHlO mx.test").unwrap(),
            Command::Ehlo("mx.test".into())
        );
    }

    #[test]
    fn helo_and_ehlo_are_different_commands() {
        assert_eq!(
            parse("HELO mx.test").unwrap(),
            Command::Helo("mx.test".into())
        );
        assert_eq!(
            parse("EHLO mx.test").unwrap(),
            Command::Ehlo("mx.test".into())
        );
    }

    #[test]
    fn a_greeting_without_a_name_is_still_a_greeting() {
        // Plenty of clients send a bare EHLO. Refusing it buys nothing.
        assert_eq!(parse("EHLO").unwrap(), Command::Ehlo(String::new()));
    }

    #[test]
    fn mail_from_takes_an_address_in_brackets() {
        assert_eq!(parse("MAIL FROM:<a@b.com>").unwrap(), mail(Some("a@b.com")));
    }

    #[test]
    fn a_space_after_the_colon_is_tolerated() {
        // Not what RFC 5321 says; what clients do.
        assert_eq!(
            parse("MAIL FROM: <a@b.com>").unwrap(),
            mail(Some("a@b.com"))
        );
    }

    #[test]
    fn the_null_sender_is_a_sender() {
        assert_eq!(
            parse("MAIL FROM:<>").unwrap(),
            mail(None),
            "every bounce in the world arrives this way"
        );
    }

    #[test]
    fn mail_parameters_are_read() {
        assert_eq!(
            parse("MAIL FROM:<a@b.com> SIZE=12345 BODY=8BITMIME").unwrap(),
            Command::Mail {
                from: Some("a@b.com".into()),
                size: Some(12345),
                body_8bitmime: true,
            }
        );
    }

    #[test]
    fn parameters_are_case_insensitive_too() {
        assert_eq!(
            parse("MAIL FROM:<a@b.com> size=1 body=8bitmime").unwrap(),
            Command::Mail {
                from: Some("a@b.com".into()),
                size: Some(1),
                body_8bitmime: true,
            }
        );
    }

    #[test]
    fn body_7bit_is_accepted_and_means_nothing_special() {
        assert_eq!(
            parse("MAIL FROM:<a@b.com> BODY=7BIT").unwrap(),
            mail(Some("a@b.com"))
        );
    }

    #[test]
    fn a_size_that_is_not_a_number_is_refused() {
        assert_eq!(
            parse("MAIL FROM:<a@b.com> SIZE=lots"),
            Err(CommandError::MalformedSize)
        );
    }

    #[test]
    fn a_parameter_we_do_not_implement_is_refused_rather_than_ignored() {
        // Silently ignoring RET or ENVID would be lying about what happened
        // to the message.
        assert_eq!(
            parse("MAIL FROM:<a@b.com> RET=FULL"),
            Err(CommandError::UnknownParameter("RET".into()))
        );
    }

    #[test]
    fn mail_without_a_path_is_refused() {
        assert_eq!(
            parse("MAIL"),
            Err(CommandError::MissingPath { verb: "MAIL" })
        );
        assert_eq!(
            parse("MAIL FROM a@b.com"),
            Err(CommandError::MissingPath { verb: "MAIL" })
        );
    }

    #[test]
    fn a_path_without_brackets_is_refused() {
        assert_eq!(
            parse("MAIL FROM:a@b.com"),
            Err(CommandError::MalformedPath { verb: "MAIL" })
        );
    }

    #[test]
    fn rcpt_to_takes_an_address() {
        assert_eq!(
            parse("RCPT TO:<c@d.com>").unwrap(),
            Command::Rcpt("c@d.com".into())
        );
        assert_eq!(
            parse("rcpt to: <c@d.com>").unwrap(),
            Command::Rcpt("c@d.com".into())
        );
    }

    #[test]
    fn an_empty_recipient_is_refused() {
        assert_eq!(
            parse("RCPT TO:<>"),
            Err(CommandError::MalformedPath { verb: "RCPT" }),
            "a message has to go somewhere"
        );
    }

    #[test]
    fn a_non_ascii_envelope_is_refused_because_smtputf8_is_not_offered() {
        assert_eq!(
            parse("RCPT TO:<почта@example.com>"),
            Err(CommandError::NeedsSmtpUtf8),
            "accepting it would mean handing the destination something we cannot describe"
        );
    }

    #[test]
    fn the_simple_verbs_are_parsed() {
        assert_eq!(parse("DATA").unwrap(), Command::Data);
        assert_eq!(parse("RSET").unwrap(), Command::Rset);
        assert_eq!(parse("NOOP").unwrap(), Command::Noop);
        assert_eq!(parse("QUIT").unwrap(), Command::Quit);
        assert_eq!(parse("VRFY someone").unwrap(), Command::Vrfy);
        assert_eq!(parse("EXPN list").unwrap(), Command::Vrfy);
        assert_eq!(parse("HELP").unwrap(), Command::Help);
    }

    #[test]
    fn noop_may_carry_a_string_but_data_may_not() {
        // RFC 5321: NOOP takes an optional argument; DATA takes none.
        assert_eq!(parse("NOOP keepalive").unwrap(), Command::Noop);
        assert_eq!(
            parse("DATA now"),
            Err(CommandError::UnexpectedArguments { verb: "DATA" })
        );
    }

    /// RFC 3207 §4: STARTTLS takes no parameters. A client that sends one is
    /// talking a protocol mxhop does not know, and the answer has to come
    /// before the handshake rather than inside it.
    #[test]
    fn starttls_takes_no_arguments() {
        assert_eq!(parse("STARTTLS").unwrap(), Command::StartTls);
        assert_eq!(parse("starttls").unwrap(), Command::StartTls);
        assert_eq!(
            parse("STARTTLS now"),
            Err(CommandError::UnexpectedArguments { verb: "STARTTLS" })
        );
    }

    #[test]
    fn an_unknown_verb_comes_back_as_unknown() {
        assert_eq!(
            parse("BREWCOFFEE").unwrap(),
            Command::Unknown("BREWCOFFEE".into())
        );
        assert_eq!(parse("").unwrap(), Command::Unknown(String::new()));
    }

    #[test]
    fn trailing_whitespace_does_not_change_a_command() {
        assert_eq!(parse("QUIT  ").unwrap(), Command::Quit);
        assert_eq!(
            parse("MAIL FROM:<a@b.com>   ").unwrap(),
            mail(Some("a@b.com"))
        );
    }
}
