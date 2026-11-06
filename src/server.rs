//! The accept loop, as a function rather than as part of `main`.
//!
//! It is here so that a test can bind `127.0.0.1:0` and drive the real thing:
//! the snapshot-per-accept that makes a reloaded certificate reach the next
//! connection and not the ones already talking is a property of this loop,
//! and nowhere else.

use std::sync::Arc;

use tokio::net::TcpListener;
use tracing::{info, warn};

use crate::routing::Router;
use crate::smtp::client::Relay;
use crate::smtp::session::{self, SessionConfig};
use crate::spool::Spool;
use crate::tls::Holder;

/// Accepts connections until the listener fails irrecoverably. One failed
/// accept is not a reason to stop serving.
pub async fn accept_loop<L>(
    listener: TcpListener,
    config: Arc<SessionConfig>,
    router: Arc<Router>,
    spool: Arc<Spool>,
    relay: Arc<L>,
    tls: Option<Arc<Holder>>,
) where
    L: Relay + Send + Sync + 'static,
{
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(e) => {
                warn!("accept failed: {e}");
                continue;
            }
        };

        // One snapshot per connection. A session therefore keeps the
        // certificate it started with — so its EHLO stays consistent with
        // what its STARTTLS does — while the next accept sees whatever the
        // last reload installed.
        let acceptor = tls.as_ref().map(|holder| holder.acceptor());

        let config = Arc::clone(&config);
        let router = Arc::clone(&router);
        let spool = Arc::clone(&spool);
        let relay = Arc::clone(&relay);
        tokio::spawn(async move {
            let peer = peer.to_string();
            match session::serve(
                stream,
                peer.clone(),
                &config,
                &router,
                &spool,
                relay.as_ref(),
                acceptor,
            )
            .await
            {
                Ok(outcome) => info!(
                    %peer,
                    accepted = outcome.accepted,
                    quit = outcome.quit,
                    tls = outcome.tls,
                    "session ended"
                ),
                Err(e) => warn!(%peer, "session failed: {e}"),
            }
        });
    }
}
