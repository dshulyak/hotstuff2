use std::net::SocketAddr;
use std::time::Duration;

use async_scoped::TokioScope;
use hotstuff2::sequential::Action;
use hotstuff2::types::{PrivateKey, PublicKey};
use parking_lot::Mutex;
use tokio::sync::mpsc::{self, unbounded_channel};
use tokio::time::sleep;

use crate::context::Context;
use crate::history::History;
use crate::protocol::{self, TokioConsensus, TokioSink};
use crate::quinnext::Connection;
use crate::router::Router;

async fn initiate(
    ctx: &Context,
    endpoint: &quinn::Endpoint,
    peer: SocketAddr,
    history: &Mutex<History>,
    consensus: &protocol::TokioConsensus,
) -> anyhow::Result<()> {
    let conn = match endpoint.connect(peer, "localhost") {
        Ok(conn) => conn,
        Err(err) => {
            anyhow::bail!("failed to connect to peer: {}", err);
        }
    };
    let conn = match ctx.timeout_secs(10).select(conn).await {
        Ok(Ok(conn)) => Connection::new(conn),
        Ok(Err(err)) => {
            anyhow::bail!("establish connection: {}", err);
        }
        Err(err) => {
            anyhow::bail!("task to establish connection: {}", err);
        }
    };
    protocol::sync_initiate(
        ctx,
        history,
        consensus,
        ctx.timeout_secs(10)
            .select(conn.open(protocol::SYNC_PROTOCOL))
            .await??,
    )
    .await?;
    protocol::gossip_initiate(
        ctx,
        consensus,
        ctx.timeout_secs(10)
            .select(conn.open(protocol::GOSSIP_PROTOCOL))
            .await??,
    )
    .await?;
    Ok(())
}

async fn loop_connect(
    ctx: &Context,
    peer: SocketAddr,
    reconnect_interval: Duration,
    endpoint: &quinn::Endpoint,
    history: &Mutex<History>,
    consensus: &protocol::TokioConsensus,
) {
    loop {
        if let Err(err) = initiate(ctx, endpoint, peer, history, consensus).await {
            tracing::warn!(error = ?err, "failed to connect to peer");
        }
        if let Err(_) = ctx.select(sleep(reconnect_interval)).await {
            return;
        }
    }
}

async fn accept(
    ctx: &Context,
    endpoint: &quinn::Endpoint,
    history: &Mutex<History>,
    router: &Router,
) {
    let mut s = unsafe { TokioScope::create(Default::default()) };
    while let Some(conn) = endpoint.accept().await {
        s.spawn(async {
            let conn = match ctx.timeout_secs(10).select(conn).await {
                Ok(Ok(conn)) => Connection::new(conn),
                Ok(Err(err)) => {
                    tracing::debug!(error = ?err, "failed to accept connection");
                    return;
                }
                Err(err) => {
                    tracing::debug!(error = ?err, "task failed");
                    return;
                }
            };
            let mut s = unsafe { TokioScope::create(Default::default()) };
            while let Ok(Ok(stream)) = ctx.select(conn.accept()).await {
                match stream.protocol() {
                    GOSSIP_PROTOCOL => {
                        s.spawn(protocol::gossip_accept(ctx, router, stream));
                    }
                    SYNC_PROTOCOL => {
                        s.spawn(protocol::sync_accept(ctx, history, stream));
                    }
                    default => {
                        tracing::debug!(protocol = ?default, "unknown protocol");
                    }
                }
            }
            s.collect().await;
        });
    }
    s.collect().await;
}

pub struct Node {
    peers: Vec<SocketAddr>,
    history: Mutex<History>,
    router: Router,
    consensus: TokioConsensus,
    endpoint: quinn::Endpoint,
    receiver: mpsc::UnboundedReceiver<Action>,
}

impl Node {
    pub fn init(
        participants: Box<[PublicKey]>,
        keys: Box<[PrivateKey]>,
        peers: Vec<SocketAddr>,
        endpoint: quinn::Endpoint,
    ) -> anyhow::Result<Self> {
        let history = History::new();
        let (sender, receiver) = unbounded_channel();
        let consensus = TokioConsensus::new(
            history.last_view(),
            participants,
            history.lock(),
            history.last_commit(),
            history.voted,
            &keys,
            TokioSink::new(sender),
        );
        Ok(Self {
            peers,
            history: Mutex::new(history),
            router: Router::new(1_000),
            consensus: consensus,
            endpoint,
            receiver: receiver,
        })
    }

    pub async fn run(&mut self, ctx: Context) {
        TokioScope::scope_and_block(|s| {
            s.spawn(protocol::notify_delays(
                &ctx,
                Duration::from_millis(100),
                &self.consensus,
            ));
            s.spawn(protocol::process_actions(
                &ctx,
                &self.history,
                &self.router,
                &self.consensus,
                &mut self.receiver,
            ));
            for peer in &self.peers {
                s.spawn(loop_connect(
                    &ctx,
                    *peer,
                    Duration::from_secs(10),
                    &self.endpoint,
                    &self.history,
                    &self.consensus,
                ));
            }
            s.spawn(accept(&ctx, &self.endpoint, &self.history, &self.router));
        });
    }
}
