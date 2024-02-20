use crate::codec::AsyncEncode;

use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use async_trait::async_trait;
use hotstuff2::types::Message;
use parking_lot::Mutex;
use quinn::StreamId;
use tokio::{io::AsyncReadExt, sync::mpsc};

pub(crate) type Protocol = u32;

pub(crate) struct Stream {
    pub(crate) id: StreamId,
    pub(crate) remote: SocketAddr,
    pub(crate) r: quinn::RecvStream,
    pub(crate) w: quinn::SendStream,
}

#[async_trait]
pub trait ProtocolHandler: Send + Sync {
    async fn handle(&self, mut stream: Stream);
}

pub(crate) struct Host {
    gossip_protocol: Box<dyn ProtocolHandler>,
    sync_protocol: Box<dyn ProtocolHandler>,
}

impl Host {
    pub(crate) fn new(
        gossip_protocol: Box<dyn ProtocolHandler>,
        sync_protocol: Box<dyn ProtocolHandler>,
    ) -> Self {
        Self {
            gossip_protocol: gossip_protocol,
            sync_protocol: sync_protocol,
        }
    }

    async fn muxer(&self, mut stream: Stream) {
        match stream.r.read_u32().await {
            Ok(0) => {
                tracing::debug!("gossip");
                self.gossip_protocol.handle(stream).await;
            }
            Ok(1) => {
                tracing::debug!("sync");
                self.sync_protocol.handle(stream).await;
            }
            Ok(other) => {
                tracing::warn!(protocol = ?other, "unknown protocol");
            }
            Err(err) => {
                tracing::warn!(error = ?err, "read error");
            }
        }
    }
}

pub(crate) async fn server(host: Arc<Host>, endpoint: Arc<quinn::Endpoint>) {
    while let Some(conn) = endpoint.accept().await {
        let host = host.clone();
        tokio::spawn(async move {
            if let Ok(conn) = conn.await {
                while let Ok((w, r)) = conn.accept_bi().await {
                    host.muxer(Stream {
                        id: w.id(),
                        r,
                        w,
                        remote: conn.remote_address(),
                    })
                    .await;
                }
            }
        });
    }
}
