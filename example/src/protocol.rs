use std::time::Duration;
use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use bit_vec::BitVec;
use hotstuff2::sequential::{Action, Actions, Consensus};
use hotstuff2::types::{
    Block, Certificate, Domain, Message, PrivateKey, PublicKey, Sync as SyncMsg, View, Vote, ID,
};
use parking_lot::Mutex;
use quinn::StreamId;
use tokio::select;
use tokio::sync::mpsc;
use tokio_scoped::scope;
use tokio_util::sync::CancellationToken;

use crate::codec::{AsyncDecode, AsyncEncode};

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
    timeout: Duration,
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
}

impl Router {
    pub fn new() -> Self {
        Self {
            gossip: Mutex::new(HashMap::new()),
        }
    }

    pub fn register(&self, addr: SocketAddr) -> mpsc::Receiver<Arc<Message>> {
        let (sender, receiver) = mpsc::channel(1000);
        self.gossip.lock().insert(addr, sender);
        receiver
    }

    pub fn remove(&self, addr: &SocketAddr) {
        self.gossip.lock().remove(addr);
    }

    pub fn gossip(&self, msg: Message, except: Option<SocketAddr>) {
        let gossip = self.gossip.lock();
        for (socket, sender) in gossip.iter() {
            if except.map(|addr| addr == *socket).unwrap_or(false) {
                continue;
            }
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
    mut stream: Stream,
) -> anyhow::Result<()> {
    // negotiate last synced state
    // both sides write their last locked and commit state, and read it concurrently

    // TODO implement reconciliation routine, do it one synchronously and then periodically over original stream.
    // for gossip establish a new stream.
    let local = {
        let history = history.lock();
        let double = history.commits.last().map(|cert| cert.clone());
        SyncMsg {
            locked: history.locked.clone(),
            double: double,
        }
    };
    let mut send = None;
    let mut receive = None;
    scope(|s| {
        s.spawn(async {
            send = Some(local.encode(&mut stream.w).await);
        });
        s.spawn(async {
            receive = Some(SyncMsg::decode(&mut stream.r).await);
        });
    });
    if let Err(err) = send.unwrap() {
        anyhow::bail!("send sync message: {}", err);
    }
    let remote = match receive.unwrap() {
        Ok(remote) => remote,
        Err(err) => anyhow::bail!("receive sync message: {}", err),
    };

    // one that behind, waits for synchronous messages to catchup
    // the other one starts sending sync msgs based on the difference in commit history
    if let Some(mut i) = needs_catchup(&local.double, &remote.double) {
        let mut end = false;
        while !end {
            let next = {
                let history = history.lock();
                let double = history.commits.get(i).map(|cert| cert.clone());
                SyncMsg {
                    locked: {
                        if double.is_some() {
                            None
                        } else {
                            history.locked.clone()
                        }
                    },
                    double,
                }
            };
            if let Err(err) = next.encode(&mut stream.w).await {
                anyhow::bail!("send sync message: {}", err);
            }
            end = next.double.is_none();
            i += 1
        }
    } else if let Some(_) = needs_catchup(&remote.double, &local.double) {
        let mut end = false;
        while !end {
            let sync = match SyncMsg::decode(&mut stream.r).await {
                Ok(sync) => sync,
                Err(err) => {
                    anyhow::bail!("receive sync message: {}", err);
                }
            };
            end = sync.double.is_none();
            if let Err(err) = consensus.on_message(Message::Sync(sync)) {
                tracing::warn!(error = ?err, "failed to process sync message");
            }
        }
    }

    // if they are equally up to date they are both added to the gossip
    // after that both sides register for sync and gossip in the router
    // setup receiver that will emit messages to the stream
    let mut gossip = router.register(stream.remote);
    let cancellation = CancellationToken::new();

    scope(|s| {
        s.spawn(async {
            while let Some(msg) = gossip.recv().await {
                if let Err(err) = msg.encode(&mut stream.w).await {
                    tracing::warn!(error = ?err, "failed to send gossip message");
                    cancellation.cancel();
                    return;
                }
            }
        });
        s.spawn(async {
            select! {
                _ = async {
                    let msg = Message::decode(&mut stream.r).await;
                    match msg {
                        Ok(msg) => {
                            if let Err(err) = consensus.on_message(msg.clone()) {
                                tracing::debug!(error = ?err, "failed to process gossip message");
                            } else {
                                router.gossip(msg, None);
                            }
                        }
                        Err(err) => {
                            tracing::debug!(error = ?err, "failed to receive gossip message");
                        }
                    }
                } => {},
                _ = cancellation.cancelled() => {},
            }
        });
    });

    // protocol can terminate without error if peer goes away with eof
    // otherwise it terminates on write timeout
    Ok(())
}

fn needs_catchup(
    local: &Option<Certificate<Vote>>,
    remote: &Option<Certificate<Vote>>,
) -> Option<usize> {
    match (local, remote) {
        (Some(local), Some(remote)) => {
            if local.inner.block.height <= remote.inner.block.height {
                None
            } else {
                Some(remote.inner.block.height as usize)
            }
        }
        (Some(_), None) => Some(1),
        (None, Some(_)) => None,
        (None, None) => None,
    }
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
