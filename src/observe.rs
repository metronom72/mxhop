use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tracing::{info, warn};

use crate::metrics;
use crate::shutdown::Shutdown;

pub const MAX_REQUEST_LINE: usize = 8 * 1024;

#[derive(Debug)]
pub struct Health {
    listening: AtomicBool,
    queue_writable: AtomicBool,
    resolver_answered: AtomicBool,
    queue_depth: AtomicU64,
    queue_limit: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Ready,
    NotReady(&'static str),
}

impl Health {
    pub fn new(queue_limit: u64) -> Arc<Self> {
        Arc::new(Self {
            listening: AtomicBool::new(false),
            queue_writable: AtomicBool::new(true),
            resolver_answered: AtomicBool::new(true),
            queue_depth: AtomicU64::new(0),
            queue_limit,
        })
    }

    pub fn listening(&self, yes: bool) {
        self.listening.store(yes, Ordering::Relaxed);
    }

    pub fn queue_writable(&self, yes: bool) {
        self.queue_writable.store(yes, Ordering::Relaxed);
    }

    pub fn resolver_answered(&self, yes: bool) {
        self.resolver_answered.store(yes, Ordering::Relaxed);
    }

    pub fn queue_depth(&self, depth: u64) {
        self.queue_depth.store(depth, Ordering::Relaxed);
        metrics::QUEUE_DEPTH.set(depth);
    }

    pub fn verdict(&self) -> Verdict {
        if !self.listening.load(Ordering::Relaxed) {
            return Verdict::NotReady("the SMTP listener is not accepting");
        }
        if !self.queue_writable.load(Ordering::Relaxed) {
            return Verdict::NotReady("the spool cannot be written to");
        }
        if self.queue_depth.load(Ordering::Relaxed) >= self.queue_limit {
            return Verdict::NotReady("the queue is at its limit");
        }
        if !self.resolver_answered.load(Ordering::Relaxed) {
            return Verdict::NotReady("the resolver is not answering");
        }
        Verdict::Ready
    }

    pub fn body(&self) -> String {
        let depth = self.queue_depth.load(Ordering::Relaxed);
        let lines = [
            format!(
                "listener: {}",
                yes_no(self.listening.load(Ordering::Relaxed))
            ),
            format!(
                "spool: {}",
                yes_no(self.queue_writable.load(Ordering::Relaxed))
            ),
            format!("queue: {depth}/{}", self.queue_limit),
            format!(
                "resolver: {}",
                yes_no(self.resolver_answered.load(Ordering::Relaxed))
            ),
        ];
        match self.verdict() {
            Verdict::Ready => format!("ok\n{}\n", lines.join("\n")),
            Verdict::NotReady(why) => format!("not ready: {why}\n{}\n", lines.join("\n")),
        }
    }
}

fn yes_no(yes: bool) -> &'static str {
    if yes { "ok" } else { "no" }
}

pub async fn serve(listener: TcpListener, health: Arc<Health>, mut shutdown: Shutdown) {
    loop {
        let accepted = tokio::select! {
            biased;
            () = shutdown.wait() => {
                info!("the observability listener is stopping");
                return;
            }
            accepted = listener.accept() => accepted,
        };

        let Ok((stream, _)) = accepted else {
            continue;
        };
        let health = Arc::clone(&health);
        tokio::spawn(async move {
            if let Err(e) = answer(stream, &health).await {
                warn!("an observability request failed: {e}");
            }
        });
    }
}

async fn answer(stream: TcpStream, health: &Health) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream.take(MAX_REQUEST_LINE as u64));
    let mut line = String::new();

    let read = tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut line)).await;

    let response = match read {
        Ok(Ok(n)) if n > 0 => route(&line, health),
        _ => Response::text(400, "text/plain", "bad request\n".into()),
    };

    let stream = reader.into_inner().into_inner();
    let mut stream = stream;
    stream.write_all(&response.bytes()).await?;
    stream.flush().await?;
    Ok(())
}

pub struct Response {
    status: u16,
    reason: &'static str,
    content_type: &'static str,
    body: String,
}

impl Response {
    fn text(status: u16, content_type: &'static str, body: String) -> Self {
        let reason = match status {
            200 => "OK",
            400 => "Bad Request",
            404 => "Not Found",
            405 => "Method Not Allowed",
            503 => "Service Unavailable",
            _ => "Unknown",
        };
        Self {
            status,
            reason,
            content_type,
            body,
        }
    }

    pub fn bytes(&self) -> Vec<u8> {
        format!(
            "HTTP/1.1 {} {}\r\n\
             Content-Type: {}\r\n\
             Content-Length: {}\r\n\
             Cache-Control: no-store\r\n\
             Connection: close\r\n\
             \r\n{}",
            self.status,
            self.reason,
            self.content_type,
            self.body.len(),
            self.body
        )
        .into_bytes()
    }

    pub fn status(&self) -> u16 {
        self.status
    }

    pub fn body(&self) -> &str {
        &self.body
    }
}

pub fn route(request_line: &str, health: &Health) -> Response {
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");
    let path = target.split(['?', '#']).next().unwrap_or("");

    if !matches!(method, "GET" | "HEAD") {
        return Response::text(405, "text/plain", "only GET\n".into());
    }

    match path {
        "/metrics" => Response::text(
            200,
            "text/plain; version=0.0.4; charset=utf-8",
            metrics::render(),
        ),
        "/healthz" => match health.verdict() {
            Verdict::Ready => Response::text(200, "text/plain", health.body()),
            Verdict::NotReady(_) => Response::text(503, "text/plain", health.body()),
        },
        _ => Response::text(404, "text/plain", "try /metrics or /healthz\n".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn healthy() -> Arc<Health> {
        let health = Health::new(10_000);
        health.listening(true);
        health
    }

    #[test]
    fn a_fresh_health_is_not_ready_until_the_listener_is_up() {
        let health = Health::new(10);

        assert_eq!(
            health.verdict(),
            Verdict::NotReady("the SMTP listener is not accepting")
        );
        health.listening(true);
        assert_eq!(health.verdict(), Verdict::Ready);
    }

    #[test]
    fn every_condition_the_issue_names_can_make_it_not_ready() {
        let health = healthy();
        assert_eq!(health.verdict(), Verdict::Ready);

        health.queue_writable(false);
        assert_eq!(
            health.verdict(),
            Verdict::NotReady("the spool cannot be written to")
        );
        health.queue_writable(true);

        health.queue_depth(10_000);
        assert_eq!(
            health.verdict(),
            Verdict::NotReady("the queue is at its limit")
        );
        health.queue_depth(0);

        health.resolver_answered(false);
        assert_eq!(
            health.verdict(),
            Verdict::NotReady("the resolver is not answering")
        );
    }

    #[test]
    fn healthz_is_503_when_it_is_not_ready_and_says_which_part() {
        let health = healthy();
        health.queue_writable(false);

        let response = route("GET /healthz HTTP/1.1\r\n", &health);

        assert_eq!(response.status(), 503);
        assert!(response.body().contains("spool: no"), "{}", response.body());
        assert!(
            response.body().contains("listener: ok"),
            "{}",
            response.body()
        );
    }

    #[test]
    fn healthz_is_200_and_metrics_are_the_prometheus_format() {
        let health = healthy();

        assert_eq!(route("GET /healthz HTTP/1.1\r\n", &health).status(), 200);

        let metrics = route("GET /metrics HTTP/1.1\r\n", &health);
        assert_eq!(metrics.status(), 200);
        assert!(
            metrics
                .body()
                .contains("# TYPE mxhop_sessions_total counter")
        );
    }

    #[test]
    fn a_query_string_does_not_hide_the_path() {
        let health = healthy();

        assert_eq!(
            route("GET /metrics?x=1 HTTP/1.1\r\n", &health).status(),
            200
        );
    }

    #[test]
    fn anything_else_is_404_and_anything_but_a_read_is_405() {
        let health = healthy();

        assert_eq!(route("GET / HTTP/1.1\r\n", &health).status(), 404);
        assert_eq!(
            route("GET /../etc/passwd HTTP/1.1\r\n", &health).status(),
            404
        );
        assert_eq!(route("POST /metrics HTTP/1.1\r\n", &health).status(), 405);
        assert_eq!(route("", &health).status(), 405);
    }

    #[test]
    fn the_response_is_a_well_formed_http_message() {
        let health = healthy();
        let bytes = route("GET /healthz HTTP/1.1\r\n", &health).bytes();
        let text = String::from_utf8(bytes).unwrap();
        let (head, body) = text.split_once("\r\n\r\n").expect("a blank line");

        assert!(head.starts_with("HTTP/1.1 200 OK\r\n"), "{head}");
        assert!(
            head.contains(&format!("Content-Length: {}", body.len())),
            "{head}"
        );
        assert!(head.contains("Connection: close"), "{head}");
    }
}
