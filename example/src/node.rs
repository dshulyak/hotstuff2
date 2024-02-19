use std::collections::HashMap;
use std::time::Duration;

use bit_vec::BitVec;
use hotstuff2::sequential::{Action, Actions, Consensus};
use hotstuff2::types::{
    Block, Certificate, Domain, Message, PrivateKey, PublicKey, View, Vote, ID,
};
use parking_lot::Mutex;
use tokio::net::unix::SocketAddr;
use tokio::sync::mpsc;

#[derive(Debug)]
pub(crate) struct Sink(mpsc::UnboundedSender<Action>);

impl Actions for Sink {
    fn send(&self, action: Action) {
        self.0.send(action).unwrap();
    }
}

pub(crate) fn genesis() -> Certificate<Vote> {
    let empty_seed = [0; 32];
    let genesis = Certificate {
        inner: Vote {
            view: View(0),
            block: Block::new(0, ID::from_str("genesis")),
        },
        signature: PrivateKey::from_seed(&empty_seed)
            .sign(Domain::Vote, &[0; 32])
            .into(),
        signers: BitVec::new(),
    };
    genesis
}

pub(crate) struct Broadcaster {
    peers: Mutex<HashMap<PublicKey, mpsc::Sender<Message>>>,
}

impl Broadcaster {
    fn new() -> Self {
        Self {
            peers: Mutex::new(HashMap::new()),
        }
    }

    fn add_peer(&self, peer: PublicKey, sender: mpsc::Sender<Message>) {
        let mut peers = self.peers.lock();
        peers.insert(peer, sender);
    }

    fn broadcast(&self, msg: Message) {
        let mut peers = self.peers.lock();
        peers.retain(|_, sender| {
            if let Err(err) = sender.try_send(msg.clone()) {
                tracing::warn!(error = ?err, "failed to send message to peer. peer will be disconnected");
                false
            } else {
                true
            }
        });
    }
}

pub(crate) struct Config {
    delay: Duration,
    participants: Vec<PublicKey>,
    keys: Vec<PrivateKey>,
    genesis: Certificate<Vote>,
    connect: Vec<SocketAddr>,
}

pub(crate) async fn run(
    config: &Config,
    consensus: &Consensus<Sink>,
    mut receiver: mpsc::UnboundedReceiver<Action>,
    broadcaster: &Broadcaster,
) {
    async_scoped::TokioScope::scope_and_block(|scope| {
        scope.spawn(async {
            let mut interval = tokio::time::interval(config.delay);
            loop {
                interval.tick().await;
                consensus.on_delay();
            }
        });
        scope.spawn(async {
            while let Some(action) = receiver.recv().await {
                match action {
                    Action::Send(msg) => {
                        broadcaster.broadcast(msg);
                    }
                    Action::Propose => {}
                    default => {
                        tracing::warn!("unexpected action: {:?}", default);
                    }
                }
            }
        })
    });
}