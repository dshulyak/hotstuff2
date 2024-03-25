use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use hotstuff2::types::Message;
use parking_lot::Mutex;
use tokio::sync::mpsc;

pub(crate) struct Router {
    per_channel_buffer_size: usize,
    gossip: Mutex<HashMap<SocketAddr, mpsc::Sender<Arc<Message>>>>,
}

impl Router {
    pub(crate) fn new(per_channel_buffer_size: usize) -> Self {
        Self {
            per_channel_buffer_size: per_channel_buffer_size,
            gossip: Mutex::new(HashMap::new()),
        }
    }

    pub(crate) fn register(
        &self,
        addr: SocketAddr,
    ) -> anyhow::Result<mpsc::Receiver<Arc<Message>>> {
        let (sender, receiver) = mpsc::channel(self.per_channel_buffer_size);
        let mut gossip = self.gossip.lock();
        if gossip.contains_key(&addr) {
            anyhow::bail!("peer with address is already registered");
        }
        gossip.insert(addr, sender);
        Ok(receiver)
    }

    pub(crate) fn remove(&self, addr: &SocketAddr) {
        self.gossip.lock().remove(addr);
    }

    pub(crate) fn send_all(&self, msg: Message) {
        let msg = Arc::new(msg);
        self.gossip.lock().retain(|_, sender| {
            if let Err(err) = sender.try_send(msg.clone()) {
                tracing::debug!(error = ?err, "failed to send message");
                return false;
            }
            return true;
        });
    }
}
