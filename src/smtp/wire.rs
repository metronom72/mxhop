//! Reading the wire: command lines, and the message body that follows DATA.
//!
//! Two rules decide everything here. A command line has a length limit, and
//! exceeding it has to be an error rather than a silently truncated command.
//! And the body must come out of the socket byte for byte: the only change
//! allowed is removing the dot that the client added to lines starting with
//! one, because a single re-encoded byte invalidates the sender's DKIM
//! signature and turns a forwarded message into a suspected forgery.

use std::fmt;

use tokio::io::{AsyncBufRead, AsyncBufReadExt};

/// RFC 5321 §4.5.3.1.4: 512 octets including CRLF. The limit here is larger
/// because real senders exceed the letter of it and nothing good comes of
/// refusing them, but it is still a limit: an unbounded line is a way to make
/// a server allocate until it dies.
pub const MAX_COMMAND_LINE: usize = 4096;

/// The sequence that ends a message body.
const TERMINATOR: &[u8] = b".";

#[derive(Debug)]
pub enum WireError {
    /// The peer went away mid-command.
    Closed,
    /// A command line longer than [`MAX_COMMAND_LINE`].
    LineTooLong,
    /// A body larger than the configured limit.
    TooLarge {
        limit: u64,
    },
    /// The peer went away before the body ended.
    UnterminatedBody,
    Io(std::io::Error),
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WireError::Closed => f.write_str("connection closed"),
            WireError::LineTooLong => write!(f, "command line longer than {MAX_COMMAND_LINE}"),
            WireError::TooLarge { limit } => write!(f, "message larger than {limit} bytes"),
            WireError::UnterminatedBody => f.write_str("connection closed inside DATA"),
            WireError::Io(e) => write!(f, "{e}"),
        }
    }
}

impl From<std::io::Error> for WireError {
    fn from(e: std::io::Error) -> Self {
        WireError::Io(e)
    }
}

/// Reads one command line and returns it without its terminator.
///
/// A bare LF is accepted as a line ending. It is illegal on the wire, but it
/// arrives, and the alternative is a session that hangs.
pub async fn read_line<R>(reader: &mut R) -> Result<String, WireError>
where
    R: AsyncBufRead + Unpin,
{
    let mut line = Vec::with_capacity(128);
    match raw_line(reader, &mut line, MAX_COMMAND_LINE as u64).await {
        Ok(true) => {
            // A command that is not ASCII cannot be valid; handing it on
            // lossily lets the parser refuse it with a reason.
            Ok(String::from_utf8_lossy(&line).into_owned())
        }
        Ok(false) => Err(WireError::Closed),
        Err(WireError::TooLarge { .. }) => Err(WireError::LineTooLong),
        Err(e) => Err(e),
    }
}

/// Reads a message body up to the lone `.` line, undoing dot-stuffing.
///
/// `limit` is in bytes of the message as stored. Going over it stops the read:
/// the session answers 552 and closes, because draining a message we have
/// already refused is work on behalf of whoever sent it.
pub async fn read_body<R>(reader: &mut R, limit: u64) -> Result<Vec<u8>, WireError>
where
    R: AsyncBufRead + Unpin,
{
    let mut body: Vec<u8> = Vec::new();

    loop {
        let mut line = Vec::new();
        // One line may not exceed what the whole message may: that is what
        // keeps a sender from making us allocate without end.
        if !raw_line(reader, &mut line, limit + 2).await? {
            return Err(WireError::UnterminatedBody);
        }

        if line == TERMINATOR {
            return Ok(body);
        }

        // Undo dot-stuffing, and nothing else. The second dot of `..` belongs
        // to the message.
        let content = if line.first() == Some(&b'.') {
            &line[1..]
        } else {
            &line[..]
        };

        if body.len() as u64 + content.len() as u64 + 2 > limit {
            return Err(WireError::TooLarge { limit });
        }
        body.extend_from_slice(content);
        body.extend_from_slice(b"\r\n");
    }
}

/// Reads one line, terminator stripped. `Ok(false)` means the peer closed
/// with nothing left to read.
///
/// A line ending in a bare LF is accepted and becomes CRLF in the body. That
/// is a change to the bytes, which is otherwise forbidden here, but a bare LF
/// is illegal on the wire and every MTA normalises it; a message carrying one
/// has already lost its signature.
async fn raw_line<R>(reader: &mut R, out: &mut Vec<u8>, cap: u64) -> Result<bool, WireError>
where
    R: AsyncBufRead + Unpin,
{
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return Ok(false);
        }

        match available.iter().position(|b| *b == b'\n') {
            Some(end) => {
                out.extend_from_slice(&available[..end]);
                reader.consume(end + 1);
                if out.last() == Some(&b'\r') {
                    out.pop();
                }
                if out.len() as u64 > cap {
                    return Err(WireError::TooLarge { limit: cap });
                }
                return Ok(true);
            }
            None => {
                let taken = available.len();
                out.extend_from_slice(available);
                reader.consume(taken);
                if out.len() as u64 > cap {
                    return Err(WireError::TooLarge { limit: cap });
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::BufReader;

    fn reader(bytes: &str) -> BufReader<&[u8]> {
        BufReader::new(bytes.as_bytes())
    }

    #[tokio::test]
    async fn a_line_comes_back_without_its_terminator() {
        let mut r = reader("EHLO mx.test\r\n");
        assert_eq!(read_line(&mut r).await.unwrap(), "EHLO mx.test");
    }

    #[tokio::test]
    async fn lines_come_back_one_at_a_time_when_pipelined() {
        // A client that pipelines sends several commands in one packet; each
        // read has to take exactly one of them.
        let mut r = reader("MAIL FROM:<a@b.com>\r\nRCPT TO:<c@d.com>\r\nDATA\r\n");
        assert_eq!(read_line(&mut r).await.unwrap(), "MAIL FROM:<a@b.com>");
        assert_eq!(read_line(&mut r).await.unwrap(), "RCPT TO:<c@d.com>");
        assert_eq!(read_line(&mut r).await.unwrap(), "DATA");
    }

    #[tokio::test]
    async fn a_bare_lf_ends_a_line_too() {
        let mut r = reader("QUIT\n");
        assert_eq!(read_line(&mut r).await.unwrap(), "QUIT");
    }

    #[tokio::test]
    async fn an_empty_line_is_a_line() {
        let mut r = reader("\r\nQUIT\r\n");
        assert_eq!(read_line(&mut r).await.unwrap(), "");
        assert_eq!(read_line(&mut r).await.unwrap(), "QUIT");
    }

    #[tokio::test]
    async fn a_closed_connection_is_not_an_empty_line() {
        let mut r = reader("");
        assert!(matches!(read_line(&mut r).await, Err(WireError::Closed)));
    }

    #[tokio::test]
    async fn an_overlong_line_is_an_error_not_a_truncated_command() {
        let long = "X".repeat(MAX_COMMAND_LINE + 10);
        let script = format!("{long}\r\n");
        let mut r = reader(&script);
        assert!(matches!(
            read_line(&mut r).await,
            Err(WireError::LineTooLong)
        ));
    }

    #[tokio::test]
    async fn a_body_ends_at_the_lone_dot() {
        let mut r = reader("Subject: hi\r\n\r\nbody\r\n.\r\nQUIT\r\n");
        let body = read_body(&mut r, 1024).await.unwrap();

        assert_eq!(
            String::from_utf8(body).unwrap(),
            "Subject: hi\r\n\r\nbody\r\n"
        );
        assert_eq!(
            read_line(&mut r).await.unwrap(),
            "QUIT",
            "and the session continues after it"
        );
    }

    #[tokio::test]
    async fn dot_stuffing_is_undone() {
        let mut r = reader("a\r\n..b\r\n...c\r\n.\r\n");
        let body = read_body(&mut r, 1024).await.unwrap();

        assert_eq!(
            String::from_utf8(body).unwrap(),
            "a\r\n.b\r\n..c\r\n",
            "one dot comes off, the rest belong to the message"
        );
    }

    #[tokio::test]
    async fn body_bytes_are_otherwise_untouched() {
        // Trailing whitespace, a long line, bare 8-bit bytes: all of it is
        // inside somebody's DKIM signature.
        let odd = "From: a@b.com\r\nSubject: =?utf-8?B?0L/RgNC40LLQtdGC?=\r\n\r\n  leading and trailing  \r\n\r\n";
        let script = format!("{odd}.\r\n");
        let mut r = reader(&script);
        let body = read_body(&mut r, 4096).await.unwrap();

        assert_eq!(String::from_utf8(body).unwrap(), odd);
    }

    #[tokio::test]
    async fn eight_bit_bytes_survive() {
        let mut r = BufReader::new(&b"caf\xc3\xa9 \xff\xfe\r\n.\r\n"[..]);
        let body = read_body(&mut r, 1024).await.unwrap();

        assert_eq!(body, b"caf\xc3\xa9 \xff\xfe\r\n");
    }

    #[tokio::test]
    async fn an_empty_body_is_allowed() {
        let mut r = reader(".\r\n");
        assert_eq!(read_body(&mut r, 1024).await.unwrap(), Vec::<u8>::new());
    }

    #[tokio::test]
    async fn a_body_over_the_limit_stops_the_read() {
        let mut r = reader("0123456789\r\n0123456789\r\n.\r\n");
        assert!(matches!(
            read_body(&mut r, 12).await,
            Err(WireError::TooLarge { limit: 12 })
        ));
    }

    #[tokio::test]
    async fn a_body_that_never_ends_is_an_error() {
        let mut r = reader("half a message\r\n");
        assert!(matches!(
            read_body(&mut r, 1024).await,
            Err(WireError::UnterminatedBody)
        ));
    }

    #[tokio::test]
    async fn a_line_inside_the_body_may_be_long() {
        // The command-line limit does not apply to the body: messages have
        // very long lines, base64 among them.
        let long = "Q".repeat(MAX_COMMAND_LINE * 2);
        let script = format!("{long}\r\n.\r\n");
        let mut r = reader(&script);
        let body = read_body(&mut r, 1_000_000).await.unwrap();

        assert_eq!(body.len(), long.len() + 2);
    }

    #[test]
    fn the_terminator_is_what_the_rfc_says() {
        assert_eq!(TERMINATOR, b".");
    }
}
