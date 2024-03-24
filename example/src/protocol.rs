use std::collections::BTreeMap;
use std::future::Future;
use std::time::Duration;
use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use async_scoped::TokioScope;
use bit_vec::BitVec;
use hotstuff2::sequential::{Action, Actions, Consensus};
use hotstuff2::types::{
    Block, Certificate, Domain, Message, PrivateKey, PublicKey, Sync as SyncMsg, View, Vote, ID,
};
use parking_lot::Mutex;
use tokio::select;
use tokio::sync::mpsc::{self, unbounded_channel};
use tokio::time::sleep;
use tokio_util::sync::{CancellationToken, WaitForCancellationFuture};

use crate::codec::{AsyncDecode, AsyncEncode};

#[derive(Debug)]
pub(crate) struct Sink(mpsc::UnboundedSender<Action>);

impl Actions for Sink {
    fn send(&self, action: Action) {
        self.0
            .send(action)
            .expect("consumer should never be dropped before producer");
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
    ctx: &Context,
    history: &Mutex<History>,
    router: &Router,
    consensus: &Consensus<Sink>,
    conn: quinn::Connection,
    initiator: bool,
) -> anyhow::Result<()> {
    // negotiate last known state
    // both sides write their last locked and commit state, and read it concurrently

    let (mut w, mut r) = if initiator {
        ctx.timeout_secs(1).select(conn.open_bi()).await?
    } else {
        ctx.timeout_secs(1).select(conn.accept_bi()).await?
    }?;

    // TODO implement reconciliation routine, do it once synchronously and then periodically over original stream.
    // for gossip establish a new stream.
    let (_, results) = TokioScope::scope_and_block(|s| {
        s.spawn(async {
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
            match ctx
                .timeout(Duration::from_secs(1))
                .select(local.encode(&mut w))
                .await
            {
                Ok(Ok(())) => Ok(local),
                Ok(Err(err)) => Err(err),
                Err(err) => Err(err),
            }
        });
        s.spawn(async {
            match ctx
                .timeout(Duration::from_secs(1))
                .select(SyncMsg::decode(&mut r))
                .await
            {
                Ok(Ok(remote)) => Ok(remote),
                Ok(Err(err)) => Err(err),
                Err(err) => Err(err),
            }
        });
    });
    let mut results = results.into_iter();
    let local = match results.next() {
        Some(Ok(Ok(local))) => local,
        Some(Ok(Err(err))) => anyhow::bail!("send sync message: {}", err),
        Some(Err(err)) => anyhow::bail!("send sync message: {}", err),
        None => anyhow::bail!("tasks didn't complete"),
    };
    let remote = match results.next() {
        Some(Ok(Ok(remote))) => remote,
        Some(Ok(Err(err))) => anyhow::bail!("receive sync message: {}", err),
        Some(Err(err)) => anyhow::bail!("receive sync message: {}", err),
        None => anyhow::bail!("tasks didn't complete"),
    };

    // one that behind, waits for synchronous messages to catchup
    // the other one starts sending sync msgs based on the difference in commit history
    if let Some(mut i) = needs_sync(&local.double, &remote.double) {
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
            match ctx.timeout_secs(2).select(next.encode(&mut w)).await {
                Ok(Ok(())) => {}
                Ok(Err(err)) => {
                    anyhow::bail!("send sync message: {}", err);
                }
                Err(err) => {
                    anyhow::bail!("send sync message: {}", err);
                }
            }
            end = next.double.is_none();
            i += 1
        }
    } else if let Some(_) = needs_sync(&remote.double, &local.double) {
        let mut end = false;
        while !end {
            let sync = match ctx.timeout_secs(1).select(SyncMsg::decode(&mut r)).await {
                Ok(Ok(sync)) => sync,
                Ok(Err(err)) => {
                    anyhow::bail!("receive sync message: {}", err);
                }
                Err(err) => {
                    anyhow::bail!("receive sync message: {}", err);
                }
            };
            end = sync.double.is_none();
            if let Err(err) = consensus.on_message(Message::Sync(sync)) {
                tracing::warn!(error = ?err, "process sync message");
            }
        }
    }

    let (mut gossip_w, mut gossip_r) = if initiator {
        ctx.timeout_secs(2).select(conn.open_bi()).await?
    } else {
        ctx.timeout_secs(2).select(conn.accept_bi()).await?
    }?;

    // if they are equally up to date they are both added to the gossip
    // after that both sides register for sync and gossip in the router
    // setup receiver that will emit messages to the stream

    let mut gossip = router.register(conn.remote_address());
    let child = ctx.child();
    TokioScope::scope_and_block(|s| {
        s.spawn(async {
            while let Ok(Some(msg)) = child.select(gossip.recv()).await {
                match child
                    .timeout(Duration::from_secs(1))
                    .select(msg.encode(&mut gossip_w))
                    .await
                {
                    Ok(Ok(())) => {}
                    Ok(Err(err)) => {
                        tracing::debug!(error = ?err, "failed to send message to peer");
                        break;
                    }
                    Err(err) => {
                        tracing::debug!(error = ?err, "task to send message was interrupted");
                        break;
                    }
                }
            }
            child.cancel();
        });
        s.spawn(async {
            while let Ok(Ok(msg)) = child.select(Message::decode(&mut gossip_r)).await {
                if let Err(err) = consensus.on_message(msg.clone()) {
                    tracing::warn!(error = ?err, "failed to process gossip message");
                }
            }
        });
    });
    Ok(())
}

fn needs_sync(
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

async fn loop_delay(ctx: &Context, interval: Duration, consensus: &Consensus<Sink>) {
    loop {
        select! {
            _ = sleep(interval) => {
                consensus.on_delay();
            },
            _ = ctx.cancelled() => {
                return;
            },
        }
    }
}

async fn loop_actions_handler(
    ctx: &Context,
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
            _ = ctx.cancelled() => {
                return;
            },
        }
    }
}

async fn connect(
    ctx: &Context,
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
    let conn = match ctx.timeout_secs(1).select(conn).await {
        Ok(Ok(conn)) => conn,
        Ok(Err(err)) => {
            anyhow::bail!("establish connection: {}", err);
        }
        Err(err) => {
            anyhow::bail!("task to establish connection: {}", err);
        }
    };
    protocol(ctx, history, router, consensus, conn, true).await
}

async fn loop_retriable_connect(
    ctx: &Context,
    peer: SocketAddr,
    reconnect_interval: Duration,
    endpoint: &quinn::Endpoint,
    history: &Mutex<History>,
    router: &Router,
    consensus: &Consensus<Sink>,
) {
    loop {
        if let Err(err) = connect(ctx, endpoint, peer, history, router, consensus).await {
            tracing::warn!(error = ?err, "failed to connect to peer");
        }
        if let Err(_) = ctx.select(sleep(reconnect_interval)).await {
            return;
        }
    }
}

async fn accept(
    ctx: &Context,
    endpoint: &quinn::Endpoint,
    history: &Mutex<History>,
    router: &Router,
    consensus: &Consensus<Sink>,
) {
    let mut s = unsafe { TokioScope::create(Default::default()) };
    while let Some(conn) = endpoint.accept().await {
        s.spawn(async {
            let conn = match ctx.timeout(Duration::from_secs(1)).select(conn).await {
                Ok(Ok(conn)) => conn,
                Ok(Err(err)) => {
                    tracing::debug!(error = ?err, "failed to accept connection");
                    return;
                }
                Err(err) => {
                    tracing::debug!(error = ?err, "task failed");
                    return;
                }
            };
            if let Err(err) = protocol(ctx, history, router, consensus, conn, false).await {
                tracing::warn!(error = ?err, "protocol failed");
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
        participants: Box<[PublicKey]>,
        keys: Box<[PrivateKey]>,
        peers: Vec<SocketAddr>,
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
            router: Router::new(1_000),
            consensus: consensus,
            endpoint,
            receiver: receiver,
        })
    }

    pub async fn run(&mut self, ctx: Context) {
        // TODO it will be better to get rid of scope and stuff Arc everywhere
        let mut s = unsafe { TokioScope::create(Default::default()) };
        s.spawn(loop_delay(
            &ctx,
            Duration::from_millis(100),
            &self.consensus,
        ));
        s.spawn(loop_actions_handler(
            &ctx,
            &self.history,
            &self.router,
            &self.consensus,
            &mut self.receiver,
        ));
        // TODO in accept and connect compare public keys identities
        // public key with a lower value will be responsible for establishing a connection
        for peer in &self.peers {
            s.spawn(loop_retriable_connect(
                &ctx,
                *peer,
                Duration::from_secs(1),
                &self.endpoint,
                &self.history,
                &self.router,
                &self.consensus,
            ));
        }
        s.spawn(accept(
            &ctx,
            &self.endpoint,
            &self.history,
            &self.router,
            &self.consensus,
        ));
        s.collect().await;
    }
}

struct Context {
    cancel: CancellationToken,
}

impl Context {
    fn new() -> Self {
        Self {
            cancel: CancellationToken::new(),
        }
    }

    fn child(&self) -> Self {
        let ctx = Context {
            cancel: self.cancel.child_token(),
        };
        ctx
    }

    fn cancel(&self) {
        self.cancel.cancel();
    }

    fn cancelled(&self) -> WaitForCancellationFuture<'_> {
        self.cancel.cancelled()
    }

    fn timeout<'a>(&'a self, timeout: Duration) -> Timeout<'a> {
        Timeout { ctx: self, timeout }
    }

    fn timeout_secs<'a>(&'a self, secs: u64) -> Timeout<'a> {
        self.timeout(Duration::from_secs(secs))
    }

    async fn select<T, F: Future<Output = T>>(&self, f: F) -> anyhow::Result<T> {
        select! {
            _ = self.cancel.cancelled() => {
                anyhow::bail!("cancelled");
            },
            res = f => {
                Ok(res)
            }
        }
    }
}

struct Timeout<'a> {
    ctx: &'a Context,
    timeout: Duration,
}

impl<'a> Timeout<'a> {
    async fn select<T, F: Future<Output = T>>(&self, f: F) -> anyhow::Result<T> {
        select! {
            _ = self.ctx.cancelled() => {
                anyhow::bail!("cancelled");
            },
            _ = sleep(self.timeout) => {
                anyhow::bail!("timeout");
            },
            res = f => {
                Ok(res)
            }
        }
    }
}
