use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use async_trait::async_trait;
use hotstuff2::sequential::Consensus;
use hotstuff2::types::Message;
use parking_lot::Mutex;
use tokio::sync::mpsc;

use crate::codec::{AsyncDecode, AsyncEncode};
use crate::node::Sink;
use crate::p2p;

pub struct Gossip {
    gossip: Mutex<HashMap<SocketAddr, (quinn::StreamId, mpsc::Sender<Arc<Message>>)>>,
    consensus: Arc<Consensus<Sink>>,
}

impl Gossip {
    pub fn new(consensus: Arc<Consensus<Sink>>) -> Self {
        Self {
            consensus,
            gossip: Mutex::new(HashMap::new()),
        }
    }

    pub fn broadcast(&self, msg: Arc<Message>) {
        let gossip = self.gossip.lock();
        for sender in gossip.values() {
            if let Err(err) = sender.1.try_send(msg.clone()) {
                tracing::debug!(error = ?err, "failed to send message to peer");
            }
        }
    }

    pub fn use_minimal_stream(
        &self,
        addr: SocketAddr,
        id: quinn::StreamId,
    ) -> Option<mpsc::Receiver<Arc<Message>>> {
        let mut gossip = self.gossip.lock();
        match gossip.get(&addr) {
            Some((existing, _)) if *existing < id => None,
            _ => {
                let (sender, receiver) = mpsc::channel(1000);
                gossip.insert(addr, (id, sender));
                Some(receiver)
            }
        }
    }
}

#[async_trait]
impl p2p::ProtocolHandler for Gossip {
    async fn handle(&self, mut stream: p2p::Stream) {
        tracing::info!(id = %stream.id, peer = %stream.remote, "gossip");
        let minimal = self.use_minimal_stream(stream.remote, stream.id);
        match minimal {
            Some(mut receiver) => {
                let consensus = self.consensus.clone();
                let handle = tokio::spawn(async move {
                    while let Ok(msg) = Message::decode(&mut stream.r).await {
                        if let Err(err) = consensus.on_message(msg) {
                            tracing::warn!(error = ?err, "failed to handle message");
                        }
                    }
                });
                while let Some(msg) = receiver.recv().await {
                    if let Err(err) = msg.encode(&mut stream.w).await {
                        tracing::warn!(error = ?err, "write timed out. peer will be disconnected");
                        self.gossip.lock().remove(&stream.remote);
                    }
                }
                handle.abort();
                _ = handle.await;
            }
            None => {
                tracing::warn!("stream id is not minimal");
            }
        }
    }
}
