use std::time::Duration;
use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use bit_vec::BitVec;
use hotstuff2::sequential::{Action, Actions, Consensus};
use hotstuff2::types::{
    Block, Certificate, Domain, Message, PrivateKey, PublicKey, View, Vote, ID,
};
use parking_lot::Mutex;
use quinn::StreamId;
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

pub(crate) struct Config {
    delay: Duration,
    participants: Vec<PublicKey>,
    keys: Vec<PrivateKey>,
    genesis: Certificate<Vote>,
    connect: Vec<SocketAddr>,
    listener: SocketAddr,
}

pub(crate) type Protocol = u32;

pub(crate) struct Stream {
    pub(crate) id: StreamId,
    pub(crate) remote: SocketAddr,
    pub(crate) r: quinn::RecvStream,
    pub(crate) w: quinn::SendStream,
}

struct Router {
    gossip: Mutex<HashMap<SocketAddr, mpsc::Sender<Arc<Message>>>>,
    sync: Mutex<HashMap<SocketAddr, mpsc::Sender<Arc<Message>>>>,
}

impl Router {
    pub fn new() -> Self {
        Self {
            gossip: Mutex::new(HashMap::new()),
            sync: Mutex::new(HashMap::new()),
        }
    }

    pub fn register_gossip(&self, addr: SocketAddr) -> mpsc::Receiver<Arc<Message>> {
        let (sender, receiver) = mpsc::channel(1000);
        self.gossip.lock().insert(addr, sender);
        receiver
    }

    pub fn register_sync(&self, addr: SocketAddr) -> mpsc::Receiver<Arc<Message>> {
        let (sender, receiver) = mpsc::channel(1000);
        self.sync.lock().insert(addr, sender);
        receiver
    }

    pub fn remove_gossip(&self, addr: &SocketAddr) {
        self.gossip.lock().remove(addr);
    }

    pub fn remove_sync(&self, addr: &SocketAddr) {
        self.sync.lock().remove(addr);
    }

    pub fn gossip(&self, msg: Message) {
        let gossip = self.gossip.lock();
        for sender in gossip.values() {
            if let Err(err) = sender.try_send(Arc::new(msg.clone())) {
                tracing::debug!(error = ?err, "failed to send message to peer");
            }
        }
    }

    pub fn sync(&self, msg: Message) {
        let sync = self.sync.lock();
        for sender in sync.values() {
            if let Err(err) = sender.try_send(Arc::new(msg.clone())) {
                tracing::debug!(error = ?err, "failed to send message to peer");
            }
        }
    }
}

pub struct History {
    voted_view: View,
    locked: Option<Certificate<Vote>>,
    commits: Vec<Certificate<Vote>>,
}

async fn protocol(
    history: Arc<Mutex<History>>,
    router: Arc<Router>,
    consensus: Arc<Consensus<Sink>>,
    stream: Stream,
) -> anyhow::Result<()> {
    // negotiate last synced state
    // both sides write their last locked and commit state, and read it concurrently

    // one that behind, waits for synchronous messages to catchup
    // if they are equally up to date they are both added to the gossip

    // after that both sides register for sync and gossip in the router
    // setup receiver that will emit messages to the stream

    // protocol can terminate without error if peer goes away with eof
    // otherwise it terminates on write timeout
    Ok(())
}

async fn consensus(
    history: Arc<Mutex<History>>,
    router: Arc<Router>,
    consensus: Arc<Consensus<Sink>>,
    mut receiver: mpsc::UnboundedReceiver<Action>,
) -> anyhow::Result<()> {
    // wait for ticks and notify consensus state machine

    // wait for p2p messages and send them to the appropriate peers

    // wait for history updates and persist them before broadcasting messages
    Ok(())
}
