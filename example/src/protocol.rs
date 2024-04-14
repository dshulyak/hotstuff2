use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use bit_vec::BitVec;
use hotstuff2::sequential::{Action, Actions, Consensus, OnDelay, OnMessage, Proposer};
use hotstuff2::types::{
    AggregateSignature, Block, Certificate, Message, PrivateKey, PublicKey, Sync as SyncMsg, Timeout, View, Vote, ID
};
use rand::{thread_rng, Rng};
use tokio::select;
use tokio::sync::mpsc::{self, Receiver};
use tokio::time::{interval, Instant};

use crate::codec::{AsyncEncode, Hello, Len, ProofOfPossesion, Protocol};
use crate::context::Context;
use crate::history::History;
use crate::net::{MsgStream, Router};

pub(crate) const GOSSIP_PROTOCOL: Protocol = Protocol::new(1);
pub(crate) const SYNC_PROTOCOL: Protocol = Protocol::new(2);

pub(crate) type TokioConsensus = Consensus<TokioSink>;

#[derive(Debug)]
pub(crate) struct TokioSink(mpsc::UnboundedSender<Action>);

impl TokioSink {
    pub(crate) fn new(sender: mpsc::UnboundedSender<Action>) -> Self {
        Self(sender)
    }
}

impl Actions for TokioSink {
    fn send(&self, action: Action) {
        self.0
            .send(action)
            .expect("consumer should never be dropped before producer");
    }
}

pub(crate) fn genesis(genesis: &str) -> Certificate<Vote> {
    Certificate {
        inner: Vote {
            view: View(0),
            block: Block::new(0, ID::default(), genesis.into()),
        },
        signature: AggregateSignature::empty(),
        signers: BitVec::new(),
    }
}

pub(crate) async fn sync_initiate(
    ctx: &Context,
    history: &History,
    consensus: &impl OnMessage,
    mut stream: MsgStream,
) -> anyhow::Result<()> {
    let state = {
        SyncMsg {
            locked: None,
            commit: Some(history.last_commit()),
        }
    };
    match ctx
        .timeout_secs(10)
        .select(stream.send_msg(&Message::Sync(state)))
        .await
    {
        Ok(Ok(())) => {}
        Ok(Err(err)) => anyhow::bail!("encode sync message: {}", err),
        Err(err) => anyhow::bail!("task to sync message: {}", err),
    }
    loop {
        match ctx.timeout_secs(10).select(stream.recv_msg()).await {
            Ok(Ok(msg)) => {
                if let Err(err) = consensus.on_message(msg) {
                    tracing::warn!(error = ?err, remote = ?stream.remote(), "failed to process sync message");
                }
            }
            Ok(Err(err)) => {
                // TODO i need to check that we are on the message boundary
                if err.kind() == std::io::ErrorKind::UnexpectedEof {
                    tracing::debug!(remote = ?stream.remote(), "read stream closed");
                    break;
                }
                anyhow::bail!("decode sync message: {}", err);
            }
            Err(err) => {
                anyhow::bail!("receive sync message: {}", err);
            }
        }
    }
    Ok(())
}

pub(crate) async fn sync_accept(ctx: &Context, history: &History, mut stream: MsgStream) {
    let state = match ctx.timeout_secs(10).select(stream.recv_msg()).await {
        Ok(Ok(Message::Sync(state))) => state,
        Ok(Ok(msg)) => {
            tracing::debug!(message = ?msg, "unexpected message");
            return;
        }
        Ok(Err(err)) => {
            tracing::debug!(error = ?err, "decode sync message");
            return;
        }
        Err(err) => {
            tracing::debug!(error = ?err, "receive sync message");
            return;
        }
    };
    let mut last = state
        .commit
        .as_ref()
        .map(|v| v.inner.view + 1)
        .unwrap_or(View(1));
    tracing::debug!(from_view = %last, remote = %stream.remote(), "requested sync");
    loop {
        let (sync_msg, next) = {
            let commit = history.first_after(last).await;
            let next = commit.as_ref().map(|c| c.inner.view + 1);
            (
                Message::Sync(SyncMsg {
                    commit,
                    locked: None,
                }),
                next,
            )
        };
        match next {
            Some(next) => {
                last = next;
            }
            None => {
                tracing::debug!(last = %last, remote = %stream.remote(), "finished syncing certificates");
                break;
            }
        }
        match ctx
            .timeout_secs(10)
            .select(stream.send_msg(&sync_msg))
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
    if let Some(timeout) = history.timeout() {
        let msg = Message::Timeout(Timeout{
            certificate: timeout,
        });
        match ctx
            .timeout_secs(10)
            .select(stream.send_msg(&msg))
            .await
        {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                tracing::debug!(error = ?err, "failed to encode timeout message");
                return;
            }
            Err(err) => {
                tracing::debug!(error = ?err, "failed to send timeout message");
                return;
            }
        };
    }
}

pub(crate) async fn gossip_initiate(
    ctx: &Context,
    consensus: &impl OnMessage,
    proofs: &[ProofOfPossesion],
    mut stream: MsgStream,
) -> anyhow::Result<()> {
    ctx.timeout_secs(10)
        .select(stream.send(&Hello { proofs: proofs }))
        .await??;
    tracing::debug!(remote = ?stream.remote(), "gossip initiating stream");
    if let Err(err) = consume_messages(ctx, &mut stream, consensus).await {
        tracing::debug!(error = ?err, remote = ?stream.remote(), "failed to consume gossip messages");
    }
    tracing::debug!(remote = ?stream.remote(), "gossip init stream closed");
    Ok(())
}

async fn consume_messages(
    ctx: &Context,
    stream: &mut MsgStream,
    consensus: &impl OnMessage,
) -> anyhow::Result<()> {
    loop {
        let msg = match ctx.select(stream.recv_msg()).await {
            None => {
                return Ok(());
            }
            Some(msg) => msg?,
        };
        
        let start = Instant::now();
        let id = msg.short_id().await.unwrap();
        tracing::debug!(id = %id, remote = ?stream.remote(), msg = %msg, "on gossip message");
        if let Err(err) = consensus.on_message(msg) {
            tracing::warn!(id = %id, error = ?err, remote = ?stream.remote(), "failed to process gossip message");
        }
        let elapsed = start.elapsed();
        if elapsed > Duration::from_millis(10) {
            tracing::warn!(id = %id, remote = ?stream.remote(), elapsed = ?elapsed, "slow gossip message processing");
        } else {
            tracing::debug!(id = %id, remote = ?stream.remote(), elapsed = ?elapsed, "processed gossip message");
        }
    }
}

pub(crate) async fn gossip_accept(ctx: &Context, router: &Router, mut stream: MsgStream) {
    let proofs_count = match ctx.timeout_secs(10).select(stream.recv::<Len>()).await {
        Ok(Ok(count)) => count,
        Ok(Err(err)) => {
            tracing::warn!(error = ?err, remote = %stream.remote(), "failed to read proofs count");
            return;
        }
        Err(err) => {
            tracing::warn!(error = ?err, remote = %stream.remote(), "failed to read proofs count");
            return;
        }
    };

    let mut proofs = Vec::with_capacity(proofs_count.into());
    for _ in 0..proofs_count.into() {
        match ctx
            .timeout_secs(10)
            .select(stream.recv::<ProofOfPossesion>())
            .await
        {
            Ok(Ok(proof)) => {
                if let Err(err) = proof.signature.verify_possesion(&proof.key) {
                    tracing::warn!(error = ?err, remote = %stream.remote(), "invalid proof of possesion");
                    return;
                };
                proofs.push(proof.key);
            }
            Ok(Err(err)) => {
                tracing::warn!(error = ?err, remote = %stream.remote(), "failed to read proof");
                return;
            }
            Err(err) => {
                tracing::warn!(error = ?err, remote = %stream.remote(), "failed to read proof");
                return;
            }
        }
    }

    let mut msgs = {
        match router.register(stream.remote(), proofs.clone().into_iter()) {
            Ok(msgs) => msgs,
            Err(err) => {
                tracing::warn!(error = ?err, "failed to register peer");
                return;
            }
        }
    };
    tracing::debug!(remote = %stream.remote(), "accepted gossip stream");
    if let Err(err) = gossip_messages(ctx, &mut msgs, &mut stream).await {
        tracing::debug!(error = ?err, remote = %stream.remote(), "error in gossip stream");
    }
    tracing::debug!(remote = %stream.remote(), "closing gossip stream");
    router.remove(&stream.remote(), proofs.iter());
}

async fn gossip_messages(
    ctx: &Context,
    msgs: &mut Receiver<Arc<Message>>,
    stream: &mut MsgStream,
) -> anyhow::Result<()> {
    while let Some(Some(msg)) = ctx.select(msgs.recv()).await {
        tracing::debug!(remote = %stream.remote(), "sending gossip message");
        ctx.timeout_secs(10).select(stream.send_msg(&msg)).await??;
    }
    Ok(())
}

pub(crate) async fn notify_delays(
    ctx: &Context,
    network_delay: Duration,
    consensus: &impl OnDelay,
) {
    tracing::info!(delay = ?network_delay, "network delay notifications");
    let start = Instant::now();
    let mut interval = interval(network_delay);
    // it probably doesn't matter, but makes more sense not to fire immediately
    interval.tick().await;
    loop {
        select! {
            _ = interval.tick() => {
                tracing::debug!(elapsed = ?start.elapsed(), "tick on network delay");
                consensus.on_delay();
            },
            _ = ctx.cancelled() => {
                return;
            },
        }
    }
}

pub(crate) async fn process_actions(
    ctx: &Context,
    history: &History,
    router: &Router,
    local: HashSet<PublicKey>,
    consensus: &(impl Proposer + OnMessage),
    receiver: &mut mpsc::UnboundedReceiver<Action>,
) {
    let mut average_latency: f64 = 0.0;
    let mut last = Instant::now();
    while let Some(Some(action)) = ctx.select(receiver.recv()).await {
        match action {
            Action::Send(msg, to) => {
                let id = msg.short_id().await.unwrap();
                if let Some(to) = &to {
                    tracing::debug!(id = %id, msg = %msg, to=%to, "sent direct message");
                } else {
                    tracing::debug!(id = %id, msg = %msg, "sent message");
                }
                match to {
                    None => {
                        if let Err(err) = consensus.on_message(msg.clone()) {
                            tracing::warn!(error = ?err, "failed to validate own message")
                        };
                        router.send_all(msg);
                    }
                    Some(public) => {
                        if local.contains(&public) {
                            if let Err(err) = consensus.on_message(msg.clone()) {
                                tracing::warn!(error = ?err, "failed to validate own message")
                            };
                        } else {
                            if let Err(err) = router.send_to(&public, msg) {
                                tracing::warn!(error = ?err, "failed to send message");
                            }
                        }
                    }
                }
            }
            Action::StateChange(change) => {
                if let Some(commit) = &change.commit {
                    tracing::info_span!("on_block", 
                        view = %commit.inner.view, 
                        height = commit.inner.block.height, 
                        id = %commit.inner.block.id)
                    .in_scope(|| {
                        let latency = Instant::now() - last;
                        tracing::info!(
                            latency = ?latency,
                            average_latency = ?Duration::from_secs_f64(average_latency),
                        );

                        if average_latency == 0.0 {
                            average_latency = latency.as_secs_f64();
                        } else {
                            // 86% of the value is the last 49
                            average_latency += (latency.as_secs_f64() - average_latency) / 25.0;
                        }
                        last = Instant::now();
                    });
                }
                if let Err(err) = history.update(&change).await {
                    tracing::error!(error = ?err, "state change");
                };
            }
            Action::Propose => {
                let id = ID::new(thread_rng().gen::<[u8; 32]>());
                if let Err(err) = consensus.propose(id) {
                    tracing::error!(error = ?err, "propose block");
                }
            }
        }
    }
}

pub(crate) fn generate_proofs(keys: &[PrivateKey]) -> Box<[ProofOfPossesion]> {
    keys.iter()
        .map(|key| ProofOfPossesion {
            key: key.public(),
            signature: key.prove_possession(),
        })
        .collect::<Vec<_>>()
        .into_boxed_slice()
}

#[cfg(test)]
mod tests {
    use std::{
        net::SocketAddr,
        str::FromStr,
        sync::atomic::{AtomicUsize, Ordering},
    };

    use futures::prelude::*;
    use futures::FutureExt;
    use hotstuff2::{
        sequential::StateChange,
        types::{Signature, Signed, Sync as SyncMsg, Wish, SIGNATURE_SIZE},
    };
    use tokio::time::{self, timeout};
    use tokio_test::{assert_ok, io::Builder};

    use crate::history::inmemory;

    use super::*;

    fn genesis_test() -> Certificate<Vote> {
        genesis("test")
    }

    fn cert_from_view(view: View) -> Certificate<Vote> {
        Certificate {
            inner: Vote {
                view: view,
                block: Block::new(view.into(), ID::default(), ID::from_str(&view.to_string())),
            },
            signature: AggregateSignature::empty(),
            signers: BitVec::new(),
        }
    }

    fn init_tracing() {
        let rst = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .try_init();
        assert!(rst.is_ok());
    }

    struct Counter {
        delays: AtomicUsize,
        msgs: AtomicUsize,
        propose: AtomicUsize,
    }

    impl Counter {
        fn new() -> Self {
            Self {
                delays: AtomicUsize::new(0),
                msgs: AtomicUsize::new(0),
                propose: AtomicUsize::new(0),
            }
        }
    }

    impl OnDelay for Counter {
        fn on_delay(&self) {
            self.delays.fetch_add(1, Ordering::Relaxed);
        }
    }

    impl OnMessage for Counter {
        fn on_message(&self, _: Message) -> anyhow::Result<()> {
            self.msgs.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    impl Proposer for Counter {
        fn propose(&self, _: ID) -> anyhow::Result<()> {
            self.propose.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    fn sock(addr: &str) -> SocketAddr {
        SocketAddr::from_str(addr).unwrap()
    }

    fn wish(view: View, signer: u16) -> Signed<Wish> {
        Signed::<Wish> {
            inner: Wish { view: view },
            signer: signer,
            signature: Signature::new([0u8; SIGNATURE_SIZE]),
        }
    }

    #[tokio::test]
    async fn test_notify_delays() {
        init_tracing();
        time::pause();
        let cnt = Counter::new();
        let _ = timeout(
            Duration::from_secs(10),
            notify_delays(&Context::new(), Duration::from_secs(1), &cnt),
        )
        .await;
        assert_eq!(cnt.delays.load(Ordering::Relaxed), 10);
    }

    #[tokio::test]
    async fn test_sync_accept_noop() {
        init_tracing();

        let ctx = Context::new();
        let history = History::new(inmemory().await.unwrap());
        let change = StateChange {
            voted: None,
            locked: Some(genesis_test()),
            commit: Some(genesis_test()),
            timeout: None,
        };
        history.update(&change).await.unwrap();

        let msg = Message::Sync(SyncMsg {
            locked: None,
            commit: Some(history.last_commit()),
        });
        let mut reader = Builder::new();
        reader.read(&msg.encode_to_bytes().await.unwrap());
        let mut writer = Builder::new();

        let stream = MsgStream::new(
            SYNC_PROTOCOL,
            sock("127.0.0.1:3333"),
            Box::new(writer.build()),
            Box::new(reader.build()),
        );

        sync_accept(&ctx, &history, stream).await
    }

    #[tokio::test]
    async fn test_sync_init() {
        init_tracing();

        let ctx = Context::new();
        let history = History::new(inmemory().await.unwrap());
        let change = StateChange {
            voted: None,
            locked: Some(genesis_test()),
            commit: Some(genesis_test()),
            timeout: None,
        };
        history.update(&change).await.unwrap();
        let cnt = Counter::new();

        let mut reader = Builder::new();
        reader.read(
            &Message::Sync(SyncMsg {
                locked: None,
                commit: Some(cert_from_view(1.into())),
            })
            .encode_to_bytes()
            .await
            .unwrap(),
        );
        reader.read(
            &Message::Sync(SyncMsg {
                locked: None,
                commit: Some(cert_from_view(3.into())),
            })
            .encode_to_bytes()
            .await
            .unwrap(),
        );
        let mut writer = Builder::new();
        writer.write(
            &Message::Sync(SyncMsg {
                locked: None,
                commit: Some(history.last_commit()),
            })
            .encode_to_bytes()
            .await
            .unwrap(),
        );

        let stream = MsgStream::new(
            SYNC_PROTOCOL,
            sock("127.0.0.1:3333"),
            Box::new(writer.build()),
            Box::new(reader.build()),
        );
        assert_ok!(sync_initiate(&ctx, &history, &cnt, stream).await);
        assert_eq!(cnt.msgs.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn test_gossip_init() {
        init_tracing();
        let ctx = Context::new();
        let cnt = Counter::new();

        let pks = (0..2)
            .into_iter()
            .map(|i| {
                let mut seed = [0u8; 32];
                seed[0] = i as u8;
                PrivateKey::from_seed(&seed)
            })
            .collect::<Vec<_>>();
        let proofs = generate_proofs(&pks);

        let mut reader = Builder::new();
        let mut writer = Builder::new();

        writer.write(&Hello { proofs: &proofs }.encode_to_bytes().await.unwrap());

        reader.read(
            &Message::Wish(wish(1.into(), 1))
                .encode_to_bytes()
                .await
                .unwrap(),
        );
        reader.read(
            &Message::Wish(wish(1.into(), 2))
                .encode_to_bytes()
                .await
                .unwrap(),
        );

        let stream = MsgStream::new(
            GOSSIP_PROTOCOL,
            sock("127.0.0.1:3333"),
            Box::new(writer.build()),
            Box::new(reader.build()),
        );
        gossip_initiate(&ctx, &cnt, &proofs, stream).await.unwrap();
        assert_eq!(cnt.msgs.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn test_gossip_accept() {
        init_tracing();
        let ctx = Context::new();

        let mut reader = Builder::new();
        let mut writer = Builder::new();

        reader.read(&Len::new(0).encode_to_bytes().await.unwrap());

        let to_send = (1..=3)
            .into_iter()
            .map(|i| Message::Wish(wish(1.into(), i)))
            .collect::<Vec<_>>();
        for msg in to_send.iter() {
            writer.write(&msg.encode_to_bytes().await.unwrap());
        }

        let router = Router::new(100);
        let sock = sock("127.0.0.1:8888");
        let stream = MsgStream::new(
            GOSSIP_PROTOCOL,
            sock.clone(),
            Box::new(writer.build()),
            Box::new(reader.build()),
        );

        let fut = gossip_accept(&ctx, &router, stream);
        let mut stream = Box::pin(fut.into_stream());
        _ = futures::poll!(stream.next());
        for msg in to_send.iter() {
            router.send_all(msg.clone());
        }
        for _ in to_send.iter() {
            _ = futures::poll!(stream.next());
        }
    }
}
