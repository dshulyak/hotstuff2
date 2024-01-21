use std::{collections::HashMap, sync::Arc};

use async_scoped::TokioScope;
use parking_lot::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub(crate) type Protocol = u32;

pub(crate) struct Host {
    handlers:
        Mutex<HashMap<Protocol, Arc<dyn Fn(quinn::SendStream, quinn::RecvStream) + Sync + Send>>>,
}

impl Host {
    pub(crate) fn new() -> Self {
        Self {
            handlers: Mutex::new(HashMap::new()),
        }
    }

    pub(crate) fn register(
        &mut self,
        protocol: Protocol,
        handler: Arc<dyn Fn(quinn::SendStream, quinn::RecvStream) + Sync + Send>,
    ) {
        self.handlers.lock().insert(protocol, handler);
    }

    pub(crate) async fn handle(&self, mut w: quinn::SendStream, mut r: quinn::RecvStream) {
        let protocol = r.read_u32().await.unwrap();
        if let Some(handler) = self.handlers.lock().get(&protocol).map(|h| Arc::clone(h)) {
            handler(w, r);
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
                while let Ok((r, w)) = conn.accept_bi().await {
                    host.handle(r, w).await;
                }
            }
        });
    }
}
