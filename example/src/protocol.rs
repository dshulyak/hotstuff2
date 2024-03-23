use std::collections::BTreeMap;
use std::time::Duration;
use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use async_scoped::TokioScope;
use bit_vec::BitVec;
use hotstuff2::sequential::{Action, Actions, Consensus};
use hotstuff2::types::{
    Block, Certificate, Domain, Message, PrivateKey, PublicKey, Sync as SyncMsg, View, Vote, ID,
};
use parking_lot::Mutex;
use quinn::StreamId;
use tokio::select;
use tokio::sync::mpsc::{self, unbounded_channel};
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
    per_channel_buffer_size: usize,
    gossip: Mutex<HashMap<SocketAddr, mpsc::Sender<Arc<Message>>>>,
}

impl Router {
    fn new(per_channel_buffer_size: usize) -> Self {
        Self {
            per_channel_buffer_size: per_channel_buffer_size,
            gossip: Mutex::new(HashMap::new()),
        }
    }

    fn register(&self, addr: SocketAddr) -> mpsc::Receiver<Arc<Message>> {
        let (sender, receiver) = mpsc::channel(self.per_channel_buffer_size);
        self.gossip.lock().insert(addr, sender);
        receiver
    }

    fn remove(&self, addr: &SocketAddr) {
        self.gossip.lock().remove(addr);
    }

    fn send_all(&self, msg: Message) {
        self.gossip(msg, None)
    }

    fn gossip(&self, msg: Message, except: Option<SocketAddr>) {
        self.gossip.lock().retain(|socket, sender| {
            if except.map(|addr| addr == *socket).unwrap_or(false) {
                return true;
            }
            if let Err(err) = sender.try_send(Arc::new(msg.clone())) {
                tracing::debug!(error = ?err, "failed to send message to peer");
                return false;
            }
            return true;
        });
    }
}

struct History {
    voted: View,
    locked: Option<Certificate<Vote>>,
    commits: BTreeMap<View, Certificate<Vote>>,
}

impl History {
    fn new() -> Self {
        Self {
            voted: View(0),
            locked: None,
            commits: BTreeMap::new(),
        }
    }

    fn last_view(&self) -> View {
        let mut last = self.voted;
        if let Some(locked) = &self.locked {
            last = last.max(locked.inner.view);
        }
        if let Some(commit) = self.commits.last_key_value() {
            last = last.max(*commit.0 + 1);
        }
        last
    }

    fn lock(&self) -> Certificate<Vote> {
        self.locked.as_ref().unwrap().clone()
    }

    fn last_commit(&self) -> Certificate<Vote> {
        self.commits.last_key_value().unwrap().1.clone()
    }
}

async fn protocol(
    cancel: CancellationToken,
    history: &Mutex<History>,
    router: &Router,
    consensus: &Consensus<Sink>,
    mut stream: Stream,
) -> anyhow::Result<()> {
    // negotiate last known state
    // both sides write their last locked and commit state, and read it concurrently

    let local = {
        let history = history.lock();
        SyncMsg {
            locked: history.locked.clone(),
            double: history
                .commits
                .last_key_value()
                .map(|(_, cert)| cert.clone()),
        }
    };

    // TODO implement reconciliation routine, do it one synchronously and then periodically over original stream.
    // for gossip establish a new stream.

    let mut send = None;
    let mut receive = None;

    TokioScope::scope_and_block(|s| {
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
    if let Some(mut i) = needs_boost(&local.double, &remote.double) {
        let mut end = false;
        while !end {
            let next = {
                let history = history.lock();
                let double = history.commits.get(&i).map(|cert| cert.clone());
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
    } else if let Some(_) = needs_boost(&remote.double, &local.double) {
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
    let child = cancel.child_token();

    TokioScope::scope_and_block(|s| {
        s.spawn(async {
            while let Some(msg) = gossip.recv().await {
                if let Err(err) = msg.encode(&mut stream.w).await {
                    tracing::warn!(error = ?err, "failed to send gossip message");
                    break;
                }
            }
            child.cancel();
        });
        s.spawn(async {
            select! {
                _ = async {
                    let msg = Message::decode(&mut stream.r).await;
                    match msg {
                        Ok(msg) => {
                            if let Err(err) = consensus.on_message(msg.clone()) {
                                tracing::debug!(error = ?err, "failed to process gossip message");
                            }
                        }
                        Err(err) => {
                            tracing::debug!(error = ?err, "failed to receive gossip message");
                        }
                    }
                } => {},
                _ = child.cancelled() => {},
            }
        });
    });

    // protocol can terminate without error if peer goes away with eof
    // otherwise it terminates on write timeout
    Ok(())
}

fn needs_boost(
    local: &Option<Certificate<Vote>>,
    remote: &Option<Certificate<Vote>>,
) -> Option<View> {
    match (local, remote) {
        (Some(local), Some(remote)) => {
            if local.inner.block.height <= remote.inner.block.height {
                None
            } else {
                Some(remote.inner.view)
            }
        }
        (Some(_), None) => Some(1.into()),
        (None, Some(_)) => None,
        (None, None) => None,
    }
}

async fn loop_delay(cancel: CancellationToken, interval: Duration, consensus: &Consensus<Sink>) {
    loop {
        select! {
            _ = tokio::time::sleep(interval) => {
                consensus.on_delay();
            },
            _ = cancel.cancelled() => {
                return;
            },
        }
    }
}

async fn loop_actions_handler(
    cancel: CancellationToken,
    history: &Mutex<History>,
    router: &Router,
    consensus: &Consensus<Sink>,
    receiver: &mut mpsc::UnboundedReceiver<Action>,
) {
    loop {
        select! {
            action = receiver.recv() => {
                match action {
                    Some(Action::Send(msg)) => {
                        router.send_all(msg);
                    }
                    Some(Action::StateChange(change)) => {
                        let mut history = history.lock();
                        if let Some(commit) = change.commit {
                            history.commits.insert(commit.view, commit);
                        }
                        if let Some(locked) = change.lock {
                            history.locked = Some(locked);
                        }
                        if let Some(voted) = change.voted {
                            history.voted = voted;
                        }
                    }
                    Some(Action::Propose) => {
                        // here i can plug mempool
                        if let Err(err) = consensus.propose(ID::from_str("test block")) {
                            tracing::error!(error = ?err, "failed to propose block");
                        }
                    }
                    None => {
                        return;
                    }
                }
            },
            _ = cancel.cancelled() => {
                return;
            },
        }
    }
}

async fn connect(
    cancel: CancellationToken,
    endpoint: &quinn::Endpoint,
    peer: SocketAddr,
    history: &Mutex<History>,
    router: &Router,
    consensus: &Consensus<Sink>,
) -> anyhow::Result<()> {
    let conn = match endpoint.connect(peer, "localhost") {
        Ok(conn) => conn,
        Err(err) => {
            anyhow::bail!("failed to connect to peer: {}", err);
        }
    };
    let conn = match conn.await {
        Ok(conn) => conn,
        Err(err) => {
            anyhow::bail!("establish connection: {}", err);
        }
    };
    let (send, receive) = conn.open_bi().await?;
    let stream = Stream {
        id: send.id(),
        remote: peer,
        w: send,
        r: receive,
    };
    protocol(cancel, history, router, consensus, stream).await
}

async fn loop_retriable_connect(
    cancel: CancellationToken,
    peer: SocketAddr,
    reconnect_interval: Duration,
    endpoint: &quinn::Endpoint,
    history: &Mutex<History>,
    router: &Router,
    consensus: &Consensus<Sink>,
) {
    loop {
        if let Err(err) = connect(cancel.clone(), endpoint, peer, history, router, consensus).await
        {
            tracing::warn!(error = ?err, "failed to connect to peer");
        }
        select! {
            _ = tokio::time::sleep(reconnect_interval) => {},
            _ = cancel.cancelled() => {
                return;
            }
        }
    }
}

async fn accept(
    cancel: CancellationToken,
    endpoint: &quinn::Endpoint,
    history: &Mutex<History>,
    router: &Router,
    consensus: &Consensus<Sink>,
) {
    let mut s = unsafe { TokioScope::create(Default::default()) };
    while let Some(conn) = endpoint.accept().await {
        let conn = match conn.await {
            Ok(conn) => conn,
            Err(err) => {
                tracing::warn!(error = ?err, "failed to accept connection");
                continue;
            }
        };
        let (send, receive) = conn.open_bi().await.unwrap();
        let stream = Stream {
            id: send.id(),
            remote: conn.remote_address(),
            w: send,
            r: receive,
        };
        let cancel = cancel.clone();
        s.spawn(async move {
            if let Err(err) = protocol(cancel, history, router, consensus, stream).await {
                tracing::warn!(error = ?err, "failed to handle connection");
            }
        });
    }
    s.collect().await;
}

pub struct Node {
    peers: Vec<SocketAddr>,
    history: Mutex<History>,
    router: Router,
    consensus: Consensus<Sink>,
    endpoint: quinn::Endpoint,
    receiver: mpsc::UnboundedReceiver<Action>,
}

impl Node {
    pub fn init(
        peers: Vec<SocketAddr>,
        participants: Box<[PublicKey]>,
        keys: Box<[PrivateKey]>,
        endpoint: quinn::Endpoint,
    ) -> anyhow::Result<Self> {
        let history = History::new();
        let (sender, receiver) = unbounded_channel();
        let consensus = Consensus::<Sink>::new(
            history.last_view(),
            participants,
            history.lock(),
            history.last_commit(),
            history.voted,
            &keys,
            Sink(sender),
        );
        Ok(Self {
            peers,
            history: Mutex::new(history),
            router: Router::new(10_000),
            consensus: consensus,
            endpoint,
            receiver: receiver,
        })
    }

    pub async fn run(&mut self, cancel: CancellationToken) {
        // TODO it will be better to get rid of scope and stuff Arc everywhere
        let mut s = unsafe { TokioScope::create(Default::default()) };
        s.spawn(loop_delay(
            cancel.clone(),
            Duration::from_millis(100),
            &self.consensus,
        ));
        s.spawn(loop_actions_handler(
            cancel.clone(),
            &self.history,
            &self.router,
            &self.consensus,
            &mut self.receiver,
        ));
        // TODO in accept and connect compare public keys identities
        // public key with a lower value will be responsible for establishing a connection
        for peer in &self.peers {
            s.spawn(loop_retriable_connect(
                cancel.clone(),
                *peer,
                Duration::from_secs(1),
                &self.endpoint,
                &self.history,
                &self.router,
                &self.consensus,
            ));
        }
        s.spawn(accept(
            cancel.clone(),
            &self.endpoint,
            &self.history,
            &self.router,
            &self.consensus,
        ));
        s.collect().await;
    }
}
