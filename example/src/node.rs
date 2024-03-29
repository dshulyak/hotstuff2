use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use async_scoped::TokioScope;
use hotstuff2::sequential::Action;
use hotstuff2::types::{PrivateKey, PublicKey};
use parking_lot::Mutex;
use tokio::sync::mpsc::{self, unbounded_channel};
use tokio::time::sleep;

use crate::context::Context;
use crate::history::History;
use crate::net::{Connection, Router};
use crate::protocol::{self, TokioConsensus, TokioSink};

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

async fn connect(
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
                    protocol::GOSSIP_PROTOCOL => {
                        s.spawn(protocol::gossip_accept(ctx, router, stream));
                    }
                    protocol::SYNC_PROTOCOL => {
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

fn ensure_cert(dir: &PathBuf) -> Result<(Vec<rustls::Certificate>, rustls::PrivateKey)> {
    let cert_path = dir.join("cert.der");
    let key_path = dir.join("key.der");
    if cert_path.exists() && key_path.exists() {
        let cert = std::fs::read(cert_path)?;
        let key = std::fs::read(key_path)?;
        Ok((vec![rustls::Certificate(cert)], rustls::PrivateKey(key)))
    } else {
        let selfsigned = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
        let key = selfsigned.serialize_private_key_der();
        let cert = selfsigned.serialize_der()?;
        std::fs::write(&cert_path, &cert)?;
        std::fs::write(&key_path, &key)?;
        Ok((vec![rustls::Certificate(cert)], rustls::PrivateKey(key)))
    }
}

pub struct Node {
    dir: PathBuf,
    listen: SocketAddr,
    peers: Vec<SocketAddr>,
    history: Mutex<History>,
    router: Router,
    consensus: TokioConsensus,
    receiver: mpsc::UnboundedReceiver<Action>,
    endpoint: quinn::Endpoint,
}

impl Node {
    pub fn init(
        dir: PathBuf,
        listen: SocketAddr,
        genesis: &str,
        participants: Box<[PublicKey]>,
        keys: Box<[PrivateKey]>,
        peers: Vec<SocketAddr>,
    ) -> anyhow::Result<Self> {
        let mut history = History::new();
        if history.empty() {
            history.update(
                None,
                Some(protocol::genesis(genesis)),
                Some(protocol::genesis(genesis)),
            )?
        }
        let (sender, receiver) = unbounded_channel();
        let consensus = TokioConsensus::new(
            history.last_view(),
            participants,
            history.locked(),
            history.last_commit(),
            history.voted(),
            &keys,
            TokioSink::new(sender),
        );
        let (cert, key) = ensure_cert(&dir)?;
        let crypto = rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(cert, key)?;
        Ok(Self {
            dir,
            listen,
            peers,
            history: Mutex::new(history),
            router: Router::new(1_000),
            consensus: consensus,
            receiver: receiver,
            endpoint: quinn::Endpoint::server(
                quinn::ServerConfig::with_crypto(Arc::new(crypto)),
                listen,
            )?,
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
                s.spawn(connect(
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
