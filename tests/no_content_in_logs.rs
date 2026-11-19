use std::path::{Path, PathBuf};

const FORBIDDEN: &[&str] = &[
    "body", "stripped", "subject", "headers", "line", "text", "data", "content",
];

const MACROS: &[&str] = &["info!(", "warn!(", "error!(", "debug!(", "trace!("];

fn sources() -> Vec<PathBuf> {
    fn walk(dir: &Path, into: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("read a directory").flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, into);
            } else if path.extension().is_some_and(|e| e == "rs") {
                into.push(path);
            }
        }
    }
    let mut found = Vec::new();
    walk(Path::new("src"), &mut found);
    assert!(found.len() > 5, "the source tree was not found: {found:?}");
    found
}

fn calls(source: &str) -> Vec<(usize, String)> {
    let bytes = source.as_bytes();
    let mut found = Vec::new();

    for macro_name in MACROS {
        let mut from = 0;
        while let Some(at) = source[from..].find(macro_name) {
            let open = from + at + macro_name.len();
            let mut i = open;
            let mut depth = 1usize;
            while depth > 0 && i < bytes.len() {
                match bytes[i] {
                    b'(' => depth += 1,
                    b')' => depth -= 1,
                    b'"' => {
                        i += 1;
                        while i < bytes.len() && bytes[i] != b'"' {
                            if bytes[i] == b'\\' {
                                i += 1;
                            }
                            i += 1;
                        }
                    }
                    _ => {}
                }
                i += 1;
            }
            let end = i.saturating_sub(1).min(bytes.len());
            let line = source[..open].matches('\n').count() + 1;
            found.push((
                line,
                String::from_utf8_lossy(&bytes[open..end]).into_owned(),
            ));
            from = open;
        }
    }
    found
}

fn without_strings(call: &str) -> String {
    let mut out = String::with_capacity(call.len());
    let mut chars = call.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '"' {
            out.push(c);
            continue;
        }
        while let Some(inner) = chars.next() {
            if inner == '\\' {
                chars.next();
                continue;
            }
            if inner == '"' {
                break;
            }
        }
        out.push_str("\"\"");
    }
    out
}

fn mentions(code: &str, word: &str) -> bool {
    let bytes = code.as_bytes();
    let mut from = 0;
    while let Some(at) = code[from..].find(word) {
        let start = from + at;
        let end = start + word.len();
        let before = start
            .checked_sub(1)
            .map(|i| bytes[i] as char)
            .is_none_or(|c| !(c.is_ascii_alphanumeric() || c == '_'));
        let after = bytes
            .get(end)
            .map(|b| *b as char)
            .is_none_or(|c| !(c.is_ascii_alphanumeric() || c == '_' || c == '!'));
        if before && after {
            return true;
        }
        from = end;
    }
    false
}

#[test]
fn nothing_a_sender_wrote_is_ever_put_in_a_log_line() {
    let mut offending = Vec::new();

    for path in sources() {
        let source = std::fs::read_to_string(&path).expect("read a source file");
        for (line, call) in calls(&source) {
            let code = without_strings(&call);
            for word in FORBIDDEN {
                if mentions(&code, word) {
                    offending.push(format!("{}:{line} logs `{word}`", path.display()));
                }
            }
        }
    }

    assert!(
        offending.is_empty(),
        "README promises that a subject, a body and the sender's own headers never \
         reach the log, and these log calls would break that promise. A length or a \
         count is fine — bind it to its own name first, so that what is printed is \
         visible here.\n{}",
        offending.join("\n")
    );
}

#[test]
fn the_scanner_finds_what_it_is_looking_for() {
    let fake = r#"
        info!(%peer, size = body.len(), "a message");
        warn!(id = %envelope.id, "the body said {}", body);
        info!(id = %envelope.id, removed = taken, "mentions a body in prose only");
    "#;

    let mut hits = Vec::new();
    for (line, call) in calls(fake) {
        if mentions(&without_strings(&call), "body") {
            hits.push(line);
        }
    }

    assert_eq!(
        hits.len(),
        2,
        "the first two put a body in the record and the third only says the word \
         inside a string: {hits:?}"
    );
}
