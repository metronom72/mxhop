use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::net::TcpListener;
use tracing::{info, warn};

use crate::routing::Router;
use crate::smtp::client::Relay;
use crate::smtp::session::{self, SessionConfig};
use crate::spool::Spool;
use crate::srs::Srs;
use crate::tls::Holder;

#[allow(clippy::too_many_arguments)]
pub async fn accept_loop<L>(
    listener: TcpListener,
    config: Arc<SessionConfig>,
    router: Arc<Router>,
    srs: Option<Arc<Srs>>,
    spool: Arc<Spool>,
    relay: Arc<L>,
    tls: Option<Arc<Holder>>,
    mut shutdown: crate::shutdown::Shutdown,
    tracker: crate::shutdown::Tracker,
) where
    L: Relay + Send + Sync + 'static,
{
    loop {
        let accepted = tokio::select! {
            biased;
            () = shutdown.wait() => {
                info!("no longer accepting connections; open sessions are being let finish");
                return;
            }
            accepted = listener.accept() => accepted,
        };

        let (stream, peer) = match accepted {
            Ok(accepted) => accepted,
            Err(e) => {
                warn!("accept failed: {e}");
                continue;
            }
        };

        let acceptor = tls.as_ref().map(|holder| holder.acceptor());

        let config = Arc::clone(&config);
        let router = Arc::clone(&router);
        let srs = srs.clone();
        let spool = Arc::clone(&spool);
        let relay = Arc::clone(&relay);
        let mut shutdown = shutdown.clone();
        let tracker = tracker.clone();
        tokio::spawn(async move {
            let _tracker = tracker;
            let peer = peer.to_string();
            let started = std::time::Instant::now();
            crate::metrics::SESSIONS.hit();
            crate::metrics::SESSIONS_OPEN.set(OPEN.fetch_add(1, Ordering::Relaxed) + 1);
            let _open = Closing;
            match session::serve(
                stream,
                peer.clone(),
                &config,
                &router,
                srs.as_deref(),
                &spool,
                relay.as_ref(),
                acceptor,
                &mut shutdown,
            )
            .await
            {
                Ok(outcome) => {
                    if outcome.tls {
                        crate::metrics::SESSIONS_TLS.hit();
                    }
                    crate::metrics::SESSION_SECONDS.took(started.elapsed());
                    info!(
                        %peer,
                        accepted = outcome.accepted,
                        quit = outcome.quit,
                        tls = outcome.tls,
                        "session ended"
                    )
                }
                Err(e) => {
                    crate::metrics::SESSIONS_FAILED.hit();
                    crate::metrics::SESSION_SECONDS.took(started.elapsed());
                    warn!(%peer, "session failed: {e}")
                }
            }
        });
    }
}

static OPEN: AtomicU64 = AtomicU64::new(0);

struct Closing;

impl Drop for Closing {
    fn drop(&mut self) {
        crate::metrics::SESSIONS_OPEN.set(OPEN.fetch_sub(1, Ordering::Relaxed) - 1);
    }
}
