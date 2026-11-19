use std::sync::Arc;

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

        let acceptor = tls.as_ref().map(|holder| holder.acceptor());

        let config = Arc::clone(&config);
        let router = Arc::clone(&router);
        let srs = srs.clone();
        let spool = Arc::clone(&spool);
        let relay = Arc::clone(&relay);
        tokio::spawn(async move {
            let peer = peer.to_string();
            match session::serve(
                stream,
                peer.clone(),
                &config,
                &router,
                srs.as_deref(),
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
