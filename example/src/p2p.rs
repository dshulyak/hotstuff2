use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use parking_lot::Mutex;
use tokio::io::AsyncReadExt;

pub(crate) type Protocol = u32;

pub(crate) struct Stream {
    pub(crate) id: usize,
    pub(crate) r: quinn::RecvStream,
    pub(crate) w: quinn::SendStream,
}

#[async_trait]
pub trait ProtocolHandler: Send + Sync {
    async fn handle(&self, mut stream: Stream);
}

pub(crate) struct Host {
    handlers: Mutex<HashMap<Protocol, Arc<dyn ProtocolHandler>>>,
}

impl Host {
    pub(crate) fn new() -> Self {
        Self {
            handlers: Mutex::new(HashMap::new()),
        }
    }

    pub(crate) fn register(&mut self, protocol: Protocol, handler: Box<dyn ProtocolHandler>) {
        self.handlers.lock().insert(protocol, Arc::from(handler));
    }

    pub(crate) async fn handle(&self, mut stream: Stream) {
        let protocol = stream.r.read_u32().await.unwrap();
        let handler = self.handlers.lock().get(&protocol).map(|h| Arc::clone(h));
        if let Some(handler) = handler {
            handler.handle(stream);
        } else {
            tracing::warn!(protocol = ?protocol, "unknown protocol",);
        }
    }
}

pub(crate) async fn run_protocols(host: Arc<Host>, endpoint: &quinn::Endpoint) {
    while let Some(conn) = endpoint.accept().await {
        let host = Arc::clone(&host);
        tokio::spawn(async move {
            if let Ok(conn) = conn.await {
                while let Ok((w, r)) = conn.accept_bi().await {
                    host.handle(Stream {
                        r,
                        w,
                        id: conn.stable_id(),
                    })
                    .await;
                }
            }
        });
    }
}
