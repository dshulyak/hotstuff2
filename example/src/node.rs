use std::collections::BTreeMap;
use std::future::Future;
use std::time::Duration;
use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use async_scoped::TokioScope;
use bit_vec::BitVec;
use hotstuff2::sequential::{Action, Actions, Consensus};
use hotstuff2::types::{
    AggregateSignature, Block, Certificate, Message, PrivateKey, PublicKey, Signature,
    Sync as SyncMsg, View, Vote, ID,
};
use parking_lot::Mutex;
use tokio::io::{AsyncWriteExt, BufReader, BufWriter};
use tokio::select;
use tokio::sync::mpsc::{self, unbounded_channel};
use tokio::time::sleep;
use tokio_util::sync::{CancellationToken, WaitForCancellationFuture};

use crate::codec::{AsyncDecode, AsyncEncode, Protocol};

const GOSSIP_PROTOCOL: Protocol = Protocol::new(1);
const SYNC_PROTOCOL: Protocol = Protocol::new(2);

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
    Certificate {
        inner: Vote {
            view: View(0),
            block: Block::new(0, ID::from_str("genesis")),
        },
        signature: AggregateSignature::empty(),
        signers: BitVec::new(),
    }
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
        self.gossip.lock().retain(|socket, sender| {
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

    fn sync_state(&self) -> SyncMsg {
        SyncMsg {
            locked: self.locked.clone(),
            double: Some(self.last_commit()),
        }
    }

    fn get(&self, view: View) -> SyncMsg {
        let commit = self.commits.get(&view).cloned();
        if commit.is_none() {
            return SyncMsg {
                locked: self.locked.clone(),
                double: None,
            };
        } else {
            SyncMsg {
                locked: None,
                double: commit,
            }
        }
    }
}

async fn sync_initiate(
    ctx: &Context,
    history: &Mutex<History>,
    consensus: &Consensus<Sink>,
    conn: &Connection,
) -> anyhow::Result<()> {
    let mut stream = ctx
        .timeout_secs(10)
        .select(conn.open(SYNC_PROTOCOL.into()))
        .await??;
    let state = {
        let history = history.lock();
        history.sync_state()
    };
    match ctx
        .timeout_secs(10)
        .select(stream.send_msg(&Message::Sync(state)))
        .await
    {
        Ok(Ok(())) => {}
        Ok(Err(err)) => return Err(err),
        Err(err) => return Err(err),
    }
    while let Ok(Ok(msg)) = ctx.timeout_secs(10).select(stream.recv_msg()).await {
        if let Err(err) = consensus.on_message(msg) {
            tracing::debug!(error = ?err, remote = ?stream.remote(), "failed to process sync message");
        }
    }
    Ok(())
}

async fn sync_accept(ctx: &Context, history: &Mutex<History>, mut stream: MsgStream) {
    let state = match ctx.timeout_secs(10).select(stream.recv_msg()).await {
        Ok(Ok(Message::Sync(state))) => state,
        Ok(Ok(msg)) => {
            tracing::debug!(message = ?msg, "unexpected message");
            return;
        }
        Ok(Err(err)) => {
            tracing::debug!(error = ?err, "failed to decode sync message");
            return;
        }
        Err(err) => {
            tracing::debug!(error = ?err, "failed to receive sync message");
            return;
        }
    };
    let mut end = false;
    while !end {
        let next = {
            let history = history.lock();
            history.get(
                state
                    .locked
                    .as_ref()
                    .map(|v| v.inner.view)
                    .unwrap_or(View(1)),
            )
        };
        end = next.double.is_none();
        match ctx
            .timeout_secs(10)
            .select(stream.send_msg(&Message::Sync(next)))
            .await
        {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                tracing::debug!(error = ?err, "failed to encode sync message");
                return;
            }
            Err(err) => {
                tracing::debug!(error = ?err, "failed to send sync message");
                return;
            }
        };
    }
}

async fn gossip_initiate(
    ctx: &Context,
    consensus: &Consensus<Sink>,
    conn: &Connection,
) -> anyhow::Result<()> {
    let mut stream = ctx
        .timeout_secs(10)
        .select(conn.open(GOSSIP_PROTOCOL.into()))
        .await??;
    while let Ok(Ok(msg)) = ctx.timeout_secs(10).select(stream.recv_msg()).await {
        if let Err(err) = consensus.on_message(msg) {
            tracing::debug!(error = ?err, remote = ?stream.remote(), "failed to process gossip message");
        }
    }
    Ok(())
}

async fn gossip_accept(ctx: &Context, router: &Router, mut stream: MsgStream) {
    let mut msgs = router.register(stream.remote());
    while let Ok(Some(msg)) = ctx.select(msgs.recv()).await {
        match ctx.timeout_secs(10).select(stream.send_msg(&msg)).await {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                tracing::debug!(error = ?err,  "failed to send gossip message");
                break;
            }
            Err(err) => {
                tracing::debug!(error = ?err,  "failed to send gossip message");
                break;
            }
        }
    }
    router.remove(&stream.remote());
}

async fn notify_delays(ctx: &Context, interval: Duration, consensus: &Consensus<Sink>) {
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

async fn process_actions(
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
                        if let Err(err) = consensus.propose(ID::from_str("test block")) {
                            tracing::error!(error = ?err, "propose block");
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

async fn initiate(
    ctx: &Context,
    endpoint: &quinn::Endpoint,
    peer: SocketAddr,
    history: &Mutex<History>,
    consensus: &Consensus<Sink>,
) -> anyhow::Result<()> {
    let conn = match endpoint.connect(peer, "localhost") {
        Ok(conn) => conn,
        Err(err) => {
            anyhow::bail!("failed to connect to peer: {}", err);
        }
    };
    let conn = match ctx.timeout_secs(10).select(conn).await {
        Ok(Ok(conn)) => Connection(conn),
        Ok(Err(err)) => {
            anyhow::bail!("establish connection: {}", err);
        }
        Err(err) => {
            anyhow::bail!("task to establish connection: {}", err);
        }
    };
    sync_initiate(ctx, history, consensus, &conn).await?;
    gossip_initiate(ctx, consensus, &conn).await?;
    Ok(())
}

async fn loop_connect(
    ctx: &Context,
    peer: SocketAddr,
    reconnect_interval: Duration,
    endpoint: &quinn::Endpoint,
    history: &Mutex<History>,
    consensus: &Consensus<Sink>,
) {
    loop {
        if let Err(err) = initiate(ctx, endpoint, peer, history, consensus).await {
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
            let conn = match ctx.timeout_secs(10).select(conn).await {
                Ok(Ok(conn)) => Connection(conn),
                Ok(Err(err)) => {
                    tracing::debug!(error = ?err, "failed to accept connection");
                    return;
                }
                Err(err) => {
                    tracing::debug!(error = ?err, "task failed");
                    return;
                }
            };
            let mut s = unsafe { TokioScope::create(Default::default()) };
            while let Ok(Ok(stream)) = ctx.select(conn.accept()).await {
                match stream.protocol() {
                    GOSSIP_PROTOCOL => {
                        s.spawn(gossip_accept(ctx, router, stream));
                    }
                    SYNC_PROTOCOL => {
                        s.spawn(sync_accept(ctx, history, stream));
                    }
                    default => {
                        tracing::debug!(protocol = ?default, "unknown protocol");
                    }
                }
            }
            s.collect().await;
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
        // TODO it will be better to get rid of scope
        let mut s = unsafe { TokioScope::create(Default::default()) };
        s.spawn(notify_delays(
            &ctx,
            Duration::from_millis(100),
            &self.consensus,
        ));
        s.spawn(process_actions(
            &ctx,
            &self.history,
            &self.router,
            &self.consensus,
            &mut self.receiver,
        ));
        for peer in &self.peers {
            s.spawn(loop_connect(
                &ctx,
                *peer,
                Duration::from_secs(1),
                &self.endpoint,
                &self.history,
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

struct Connection(quinn::Connection);

impl Connection {
    async fn open(&self, proto: Protocol) -> anyhow::Result<MsgStream> {
        let (mut send, recv) = self.0.open_bi().await?;
        proto.encode(&mut send).await?;
        Ok(MsgStream {
            protocol: proto,
            remote: self.0.remote_address(),
            send: BufWriter::new(send),
            recv: BufReader::new(recv),
        })
    }

    async fn accept(&self) -> anyhow::Result<MsgStream> {
        let (send, mut recv) = self.0.accept_bi().await?;
        let proto = Protocol::decode(&mut recv).await?;
        Ok(MsgStream {
            protocol: proto,
            remote: self.0.remote_address(),
            send: BufWriter::new(send),
            recv: BufReader::new(recv),
        })
    }
}

struct MsgStream {
    protocol: Protocol,
    remote: SocketAddr,
    send: BufWriter<quinn::SendStream>,
    recv: BufReader<quinn::RecvStream>,
}

impl MsgStream {
    fn protocol(&self) -> Protocol {
        self.protocol
    }

    fn remote(&self) -> SocketAddr {
        self.remote
    }

    async fn send_msg(&mut self, msg: &Message) -> anyhow::Result<()> {
        msg.encode(&mut self.send).await?;
        self.send.flush().await.map_err(|err| anyhow::anyhow!(err))
    }

    async fn recv_msg(&mut self) -> anyhow::Result<Message> {
        Message::decode(&mut self.recv).await
    }
}
