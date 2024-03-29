use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use async_scoped::TokioScope;
use hotstuff2::sequential::Action;
use hotstuff2::types::{Certificate, PrivateKey, PublicKey, Vote};
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
            anyhow::bail!("failed to connect to peer {}: {}", peer, err);
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
    tracing::debug!(remote = %conn.remote(),"established connection");
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
        match ctx.select(sleep(reconnect_interval)).await {
            Some(_) => {}
            None => {
                tracing::debug!("task to reconnect to peer is cancelled");
                return;
            }
        }
    }
}

async fn accept(
    ctx: &Context,
    endpoint: &quinn::Endpoint,
    history: &Mutex<History>,
    router: &Router,
) {
    tracing::info!(local = %endpoint.local_addr().unwrap(), "accepting connections");
    let mut s = unsafe { TokioScope::create(Default::default()) };
    while let Some(Some(conn)) = ctx.select(endpoint.accept()).await {
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
            while let Some(Ok(stream)) = ctx.select(conn.accept()).await {
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

fn ensure_cert(dir: &Path) -> Result<(Vec<rustls::Certificate>, rustls::PrivateKey)> {
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
    listen: SocketAddr,
    peers: Vec<SocketAddr>,
    history: Mutex<History>,
    router: Router,
    consensus: TokioConsensus,
    receiver: mpsc::UnboundedReceiver<Action>,
    endpoint: quinn::Endpoint,
    network_delay: Duration,
}

impl Node {
    pub fn init(
        dir: &Path,
        listen: SocketAddr,
        genesis: &str,
        participants: Box<[PublicKey]>,
        keys: Box<[PrivateKey]>,
        peers: Vec<SocketAddr>,
        network_delay: Duration,
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

        let server_crypto = rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(cert, key)?;
        let client_crypto = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_custom_certificate_verifier(SkipServerVerification::new())
            .with_no_client_auth();
        let mut endpoint = quinn::Endpoint::server(
            quinn::ServerConfig::with_crypto(Arc::new(server_crypto)),
            listen,
        )?;
        endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(client_crypto)));
        Ok(Self {
            listen,
            peers,
            history: Mutex::new(history),
            router: Router::new(1_000),
            consensus: consensus,
            receiver: receiver,
            endpoint: endpoint,
            network_delay: network_delay,
        })
    }

    pub(crate) fn last_commit(&self) -> Certificate<Vote> {
        self.history.lock().last_commit()
    }

    pub async fn run(&mut self, ctx: Context) {
        let mut s = unsafe { TokioScope::create(Default::default()) };

        s.spawn(protocol::notify_delays(
            &ctx,
            self.network_delay,
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
                Duration::from_secs(1),
                &self.endpoint,
                &self.history,
                &self.consensus,
            ));
        }
        s.spawn(accept(&ctx, &self.endpoint, &self.history, &self.router));
        s.collect().await;
    }
}

struct SkipServerVerification;

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self)
    }
}

impl rustls::client::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::ServerCertVerified::assertion())
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::VecDeque, net::SocketAddr, time::Duration};

    use async_scoped::TokioScope;
    use futures::join;
    use hotstuff2::types::PrivateKey;
    use tokio::time::sleep;

    use crate::{context, node};

    fn init_tracing() {
        let rst = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .try_init();
        assert!(rst.is_ok());
    }

    #[tokio::test]
    async fn test_sanity() {
        init_tracing();

        let range = (1..=4);
        let pks = range
            .clone()
            .map(|i| {
                let mut seed = [0u8; 32];
                seed[0] = i as u8;
                PrivateKey::from_seed(&mut seed)
            })
            .collect::<Vec<_>>();
        let mut participants = pks.iter().map(|pk| pk.public()).collect::<Vec<_>>();
        participants.sort();

        let listeners = range
            .clone()
            .map(|i| format!("127.0.0.1:{}", 10000 + i).parse().unwrap())
            .collect::<Vec<SocketAddr>>();
        let tempdirs = range
            .clone()
            .map(|_| tempfile::TempDir::with_prefix("test_sanity").unwrap())
            .collect::<Vec<_>>();

        let mut nodes = range
            .clone()
            .map(|i| {
                let listener = listeners[i - 1];
                let pk = [pks[i - 1].clone()];
                node::Node::init(
                    tempdirs[i - 1].path(),
                    listener,
                    "test_sanity",
                    participants.clone().into(),
                    Box::new(pk),
                    listeners
                        .iter()
                        .filter(|sock| listener != **sock)
                        .copied()
                        .collect(),
                    Duration::from_millis(50),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();

        {
            let ctx = context::Context::new();
            let mut s = unsafe { TokioScope::create(Default::default()) };
            for (i, node) in nodes.iter_mut().enumerate() {
                s.spawn(async {
                    node.run(ctx.clone()).await;
                });
            }
            // TODO change test to run until expected number of blocks were comitted
            s.spawn(async {
                sleep(Duration::from_secs(2)).await;
                ctx.cancel();
            });
            s.collect().await;
        }
        let max = nodes
            .iter_mut()
            .map(|node| node.history.lock().last_commit().inner.view)
            .max()
            .unwrap();
        assert!(max > 0.into());
        for node in nodes.iter_mut() {
            let commit = node.history.lock().last_commit().inner.view;
            assert!(commit == max || commit == (max.0 - 1).into());
        }
    }
}
