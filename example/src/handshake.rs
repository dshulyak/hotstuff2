use std::collections::HashMap;

use async_trait::async_trait;
use hotstuff2::types::PublicKey;
use parking_lot::Mutex;

use crate::codec;
use crate::codec::AsyncDecode;
use crate::p2p;

pub(crate) struct HandshakeProtocol {
    known: Mutex<HashMap<PublicKey, usize>>,
}

impl HandshakeProtocol {
    pub fn new() -> Self {
        Self {
            known: Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl p2p::ProtocolHandler for HandshakeProtocol {
    async fn handle(&self, mut stream: p2p::Stream) {
        let hs = codec::Handshake::decode(&mut stream.r).await;
        match hs {
            Err(err) => {
                tracing::warn!(error = ?err, "failed to decode handshake");
            }
            Ok(hs) => match hs.signature.verify_possesion(&hs.public) {
                Err(err) => {
                    tracing::warn!(error = ?err, "failed to verify signature");
                }
                Ok(()) => {
                    self.known.lock().insert(hs.public, stream.id);
                    tracing::info!("handshake successful");
                }
            },
        }
    }
}
