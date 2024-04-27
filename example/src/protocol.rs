use std::borrow::Borrow;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use hotstuff2::pipelined::{
    Consensus, Event, Events, EventsAccess, Message, OnDelay, OnMessage, Proposer,
};
use hotstuff2::types::{
    AggregateSignature, Bitfield, Block, Certificate, PrivateKey, ProofOfPossession, PublicKey,
    View, Vote, ID,
};
use parking_lot::Mutex;
use rand::{thread_rng, Rng};
use tokio::select;
use tokio::sync::mpsc::{self, Receiver};
use tokio::time::{interval, Instant};
use tracing::Instrument;

use crate::context::Context;
use crate::history::History;
use crate::net::{MsgStream, Protocol, Router};
use crate::proto::{self, protocol};

pub(crate) const GOSSIP_PROTOCOL: Protocol = Protocol::new(1);
pub(crate) const SYNC_PROTOCOL: Protocol = Protocol::new(2);

pub(crate) type TokioConsensus = Consensus<TokioSink>;

#[derive(Debug)]
pub(crate) struct TokioSink {
    sender: mpsc::UnboundedSender<Event>,
    receiver: Mutex<Option<mpsc::UnboundedReceiver<Event>>>,
}

impl Events for TokioSink {
    fn new() -> Self {
        let (sender, receiver) = mpsc::unbounded_channel();
        Self {
            sender,
            receiver: Mutex::new(Some(receiver)),
        }
    }

    fn send(&self, event: Event) {
        self.sender
            .send(event)
            .expect("consumer should never be dropped before producer");
    }
}

impl TokioSink {
    fn take_receiver(&self) -> mpsc::UnboundedReceiver<Event> {
        self.receiver
            .lock()
            .take()
            .expect("receiver should be present")
    }
}

pub(crate) fn genesis(genesis: &str) -> Certificate<Vote> {
    Certificate {
        inner: Vote {
            view: View(0),
            block: Block::new(0, ID::default(), genesis.into()),
        },
        signature: AggregateSignature::empty(),
        signers: Bitfield::new(),
    }
}

pub(crate) async fn sync_initiate(
    ctx: &Context,
    history: &History,
    consensus: &impl OnMessage,
    mut stream: MsgStream,
) -> anyhow::Result<()> {
    let cert = history.commit_cert().await?;
    match ctx
        .timeout_secs(10)
        .select(stream.send_payload(Message::Certificate(cert).borrow().into()))
        .await
    {
        Ok(Ok(())) => {}
        Ok(Err(err)) => anyhow::bail!("encode sync message: {}", err),
        Err(err) => anyhow::bail!("task to sync message: {}", err),
    }
    loop {
        match ctx.timeout_secs(10).select(stream.recv_payload()).await {
            Ok(Ok(payload)) => {
                let msg = match payload.borrow().try_into() {
                    Ok(msg) => msg,
                    Err(err) => {
                        tracing::debug!(error = ?err, remote = ?stream.remote(), "decode sync message");
                        return Err(err);
                    }
                };
                tracing::debug!(remote = ?stream.remote(), msg = %msg, "received sync message");
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
    let cert = match ctx.timeout_secs(10).select(stream.recv_payload()).await {
        Ok(Ok(protocol::Payload::Certificate(cert))) => cert,
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
    let cert: Certificate<Vote> = match cert.borrow().try_into() {
        Ok(cert) => cert,
        Err(err) => {
            tracing::debug!(error = ?err, "decode certificate");
            return;
        }
    };
    tracing::debug!(after_height = %cert.block.height, remote = %stream.remote(), "requested sync");
    let chain = match history.load_chain_after(cert.block.height).await {
        Ok(chain) => chain,
        Err(err) => {
            tracing::debug!(error = ?err, "load chain");
            return;
        }
    };
    for cert in chain {
        tracing::debug!(remote = %stream.remote(), height = %cert.block.height, "sending certificate");
        match ctx
            .timeout_secs(10)
            .select(stream.send_payload(Message::Certificate(cert).borrow().into()))
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
    if let Ok(Some(timeout)) = history.timeout().await {
        let msg = Message::Timeout(timeout);
        match ctx
            .timeout_secs(10)
            .select(stream.send_payload(msg.borrow().into()))
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
    proofs: &[ProofOfPossession],
    mut stream: MsgStream,
) -> anyhow::Result<()> {
    ctx.timeout_secs(10)
        .select(stream.send_payload(protocol::Payload::Hello(proto::Hello {
            proofs: proofs.iter().map(|pop| pop.into()).collect::<Vec<_>>(),
        })))
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
        let span = tracing::debug_span!("recv gossip", remote=%stream.remote());
        let msg: Message = match ctx
            .select(stream.recv_payload().instrument(span.clone()))
            .await
        {
            None => {
                return Ok(());
            }
            Some(msg) => msg?.borrow().try_into()?,
        };
        span.in_scope(|| {
            let start = Instant::now();
            tracing::debug!(remote = ?stream.remote(), msg = %msg, "on gossip message");
            if let Err(err) = consensus.on_message(msg) {
                tracing::warn!(error = ?err, remote = ?stream.remote(), "failed to process gossip message");
            }
            let elapsed = start.elapsed();
            if elapsed > Duration::from_millis(10) {
                tracing::warn!(remote = ?stream.remote(), elapsed = ?elapsed, "slow gossip message processing");
            } else {
                tracing::debug!(remote = ?stream.remote(), elapsed = ?elapsed, "processed gossip message");
            }
        });
    }
}

pub(crate) async fn gossip_accept(ctx: &Context, router: &Router, mut stream: MsgStream) {
    let proofs: Vec<ProofOfPossession> = match ctx
        .timeout_secs(10)
        .select(stream.recv_payload())
        .await
    {
        Ok(Ok(protocol::Payload::Hello(hello))) => {
            let rst = hello
                .proofs
                .iter()
                .map(|pop| pop.try_into())
                .collect::<Result<Vec<_>>>();
            match rst {
                Ok(proofs) => {
                    if let Err(err) = proofs
                        .iter()
                        .map(|pop: &ProofOfPossession| pop.verify())
                        .collect::<Result<()>>()
                    {
                        tracing::warn!(error = ?err, remote = %stream.remote(), "invalid proof of possession");
                        return;
                    };
                    proofs
                }
                Err(err) => {
                    tracing::warn!(error = ?err, remote = %stream.remote(), "failed to decode proofs");
                    return;
                }
            }
        }
        Ok(Ok(_)) => {
            tracing::warn!(remote = %stream.remote(), "unexpected message");
            return;
        }
        Ok(Err(err)) => {
            tracing::warn!(error = ?err, remote = %stream.remote(), "failed to read proofs count");
            return;
        }
        Err(err) => {
            tracing::warn!(error = ?err, remote = %stream.remote(), "failed to read proofs count");
            return;
        }
    };

    let publics = proofs
        .iter()
        .map(|pop| pop.public_key.clone())
        .collect::<Vec<_>>();
    let receiver = match router.register(stream.remote(), publics.clone().into_iter()) {
        Ok(msgs) => msgs,
        Err(err) => {
            tracing::warn!(error = ?err, peer = %stream.remote(), "failed to register peer");
            return;
        }
    };
    tracing::debug!(remote = %stream.remote(), "accepted gossip stream");
    if let Err(err) = gossip_messages(ctx, receiver, &mut stream).await {
        tracing::debug!(error = ?err, remote = %stream.remote(), "error in gossip stream");
    }
    tracing::debug!(remote = %stream.remote(), "closing gossip stream");
    router.remove(&stream.remote(), publics.iter());
}

async fn gossip_messages(
    ctx: &Context,
    mut receiver: Receiver<Arc<Message>>,
    stream: &mut MsgStream,
) -> anyhow::Result<()> {
    while let Some(Some(msg)) = ctx.select(receiver.recv()).await {
        let span = tracing::debug_span!("send gossip", remote = %stream.remote());
        ctx.timeout_secs(10)
            .select(stream.send_payload(msg.as_ref().into()).instrument(span))
            .await??;
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

pub(crate) async fn process_events(
    ctx: &Context,
    history: &History,
    router: &Router,
    local: HashSet<PublicKey>,
    consensus: &(impl Proposer + OnMessage + EventsAccess<TokioSink>),
) {
    let mut average_latency: f64 = 0.0;
    let mut last = Instant::now();
    let mut receiver = consensus.events().take_receiver();
    while let Some(Some(action)) = ctx.select(receiver.recv()).await {
        match action {
            Event::Send(msg, to) => {
                if to.is_empty() {
                    if let Err(err) = consensus.on_message(msg.clone()) {
                        tracing::warn!(error = ?err, "failed to validate own message")
                    };
                    router.send_all(msg);
                } else {
                    for dst in to {
                        if local.contains(&dst) {
                            if let Err(err) = consensus.on_message(msg.clone()) {
                                tracing::warn!(error = ?err, "failed to validate own message")
                            };
                        } else {
                            if let Err(err) = router.send_to(&dst, msg.clone()) {
                                tracing::warn!(error = ?err, "failed to send message");
                            }
                        }
                    }
                }
            }
            Event::StateChange {
                voted,
                commit,
                timeout,
                chain,
            } => {
                if let Some(commit) = commit {
                    tracing::info_span!("on_block", height = commit).in_scope(|| {
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
                if let Err(err) = history.update(voted, commit, timeout, chain).await {
                    tracing::error!(error = ?err, "state change");
                };
            }
            Event::ReadyPropose => {
                if let Err(err) = consensus.propose(thread_rng().gen::<[u8; 32]>().into()) {
                    tracing::error!(error = ?err, "propose block");
                }
            }
        }
    }
}

pub(crate) fn generate_proofs(keys: &[PrivateKey]) -> Box<[ProofOfPossession]> {
    keys.iter()
        .map(|key| ProofOfPossession {
            public_key: key.public(),
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
    use hotstuff2::types::{Signature, Signed, SIGNATURE_SIZE};
    use prost::Message as ProtestMessage;
    use tokio::time::{self, timeout};
    use tokio_test::{assert_ok, io::Builder};

    use crate::history::inmemory;

    use super::*;

    fn empty_headers_message(payload: protocol::Payload) -> Vec<u8> {
        let buf = proto::Protocol {
            payload: Some(payload),
            headers: None,
        }
        .encode_length_delimited_to_vec();
        tracing::trace!(message = ?buf, "encoded message");
        buf
    }

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
            signers: Bitfield::new(),
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

    fn wish(view: View, signer: u16) -> Signed<View> {
        Signed::<View> {
            inner: view,
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
        history
            .update(None, None, None, vec![genesis_test()])
            .await
            .unwrap();

        let msg = Message::Certificate(history.commit_cert().await.expect("commit cert"));
        let mut reader = Builder::new();
        reader.read(&empty_headers_message(msg.borrow().into()));
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
        history
            .update(None, None, None, vec![genesis_test()])
            .await
            .unwrap();
        let cnt = Counter::new();

        let mut reader = Builder::new();
        reader.read(&empty_headers_message(
            Message::Certificate(cert_from_view(1.into()))
                .borrow()
                .into(),
        ));
        reader.read(&empty_headers_message(
            Message::Certificate(cert_from_view(2.into()))
                .borrow()
                .into(),
        ));
        let mut writer = Builder::new();

        writer.write(&empty_headers_message(
            Message::Certificate(history.commit_cert().await.expect("commit cert"))
                .borrow()
                .into(),
        ));

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

        let hello = protocol::Payload::Hello(proto::Hello {
            proofs: proofs.iter().map(|pop| pop.into()).collect::<Vec<_>>(),
        });
        writer.write(&empty_headers_message(hello));

        reader.read(&empty_headers_message(
            Message::Wish(wish(1.into(), 1)).borrow().into(),
        ));
        reader.read(&empty_headers_message(
            Message::Wish(wish(1.into(), 2)).borrow().into(),
        ));

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

        reader.read(&empty_headers_message(protocol::Payload::Hello(
            proto::Hello::default(),
        )));

        let to_send = (1..=3)
            .into_iter()
            .map(|i| Message::Wish(wish(1.into(), i)))
            .collect::<Vec<_>>();
        for msg in to_send.iter() {
            writer.write(&empty_headers_message(msg.into()));
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
