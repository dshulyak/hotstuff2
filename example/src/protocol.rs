use std::time::Duration;

use anyhow::anyhow;
use bit_vec::BitVec;
use hotstuff2::sequential::{Action, Actions, Consensus, OnDelay, OnMessage, Proposer};
use hotstuff2::types::{AggregateSignature, Block, Certificate, Message, View, Vote, ID};
use parking_lot::Mutex;
use tokio::select;
use tokio::sync::mpsc;
use tokio::time::{interval, interval_at, sleep, timeout, Instant};

use crate::codec::Protocol;
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

pub(crate) async fn sync_initiate(
    ctx: &Context,
    history: &Mutex<History>,
    consensus: &impl OnMessage,
    mut stream: MsgStream,
) -> anyhow::Result<()> {
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
        Ok(Err(err)) => anyhow::bail!("encode sync message: {}", err),
        Err(err) => anyhow::bail!("task to sync message: {}", err),
    }
    loop {
        match ctx.timeout_secs(10).select(stream.recv_msg()).await {
            Ok(Ok(Message::Sync(state))) => {
                if let Err(err) = consensus.on_message(Message::Sync(state)) {
                    tracing::warn!(error = ?err, remote = ?stream.remote(), "failed to process sync message");
                }
            }
            Ok(Ok(msg)) => {
                anyhow::bail!("unexpected message type");
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

pub(crate) async fn sync_accept(ctx: &Context, history: &Mutex<History>, mut stream: MsgStream) {
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
    let mut last_known = state
        .locked
        .as_ref()
        .map(|v| v.inner.view)
        .unwrap_or(View(1));
    last_known = last_known.max(
        state
            .double
            .as_ref()
            .map(|v| v.inner.view + 1)
            .unwrap_or(View(1)),
    );
    tracing::debug!(from_view = %last_known, remote = %stream.remote(), "requested sync");
    for last in last_known.0.. {
        let next = history.lock().get(last.into());
        if next.locked.is_none() && next.double.is_none() {
            tracing::debug!(last = %last, remote = %stream.remote(), "nothing to sync. exiting sync protocol");
            break;
        }
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

pub(crate) async fn gossip_initiate(
    ctx: &Context,
    consensus: &impl OnMessage,
    mut stream: MsgStream,
) -> anyhow::Result<()> {
    while let Ok(Ok(msg)) = ctx.timeout_secs(10).select(stream.recv_msg()).await {
        if let Err(err) = consensus.on_message(msg) {
            tracing::debug!(error = ?err, remote = ?stream.remote(), "failed to process gossip message");
        }
    }
    Ok(())
}

pub(crate) async fn gossip_accept(ctx: &Context, router: &Router, mut stream: MsgStream) {
    let mut msgs = {
        match router.register(stream.remote()) {
            Ok(msgs) => msgs,
            Err(err) => {
                tracing::warn!(error = ?err, "failed to register peer");
                return;
            }
        }
    };
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
            instant = interval.tick() => {
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
    history: &Mutex<History>,
    router: &Router,
    consensus: &impl Proposer,
    receiver: &mut mpsc::UnboundedReceiver<Action>,
) {
    while let Ok(Some(action)) = ctx.select(receiver.recv()).await {
        match action {
            Action::Send(msg) => {
                router.send_all(msg);
            }
            Action::StateChange(change) => {
                if let Err(err) = history
                    .lock()
                    .update(change.voted, change.lock, change.commit)
                {
                    tracing::error!(error = ?err, "state change");
                };
            }
            Action::Propose => {
                if let Err(err) = consensus.propose(ID::from_str("test block")) {
                    tracing::error!(error = ?err, "propose block");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::SocketAddr,
        str::FromStr,
        sync::atomic::{AtomicUsize, Ordering},
    };

    use hotstuff2::types::{Sync as SyncMsg, ToBytes};
    use parking_lot::lock_api::Mutex;
    use tokio::{
        spawn,
        time::{self, timeout},
    };
    use tokio_test::{assert_ok, io::Builder};

    use crate::codec::{AsyncDecode, AsyncEncode};

    use super::*;

    fn cert_from_view(view: View) -> Certificate<Vote> {
        Certificate {
            inner: Vote {
                view: view,
                block: Block::new(0, ID::from_str(&view.to_string())),
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
        let mut history = History::new();
        history.update(None, None, Some(genesis()));

        let msg = Message::Sync(history.sync_state());
        let mut reader = Builder::new();
        reader.read(&msg.encode_to_bytes().await.unwrap());
        let mut writer = Builder::new();

        let stream = MsgStream::new(
            SYNC_PROTOCOL,
            sock("127.0.0.1:3333"),
            Box::new(writer.build()),
            Box::new(reader.build()),
        );

        sync_accept(&ctx, &Mutex::new(history), stream).await
    }

    #[tokio::test]
    async fn test_sync_init() {
        init_tracing();

        let ctx = Context::new();
        let mut history = History::new();
        history.update(None, None, Some(genesis()));
        let cnt = Counter::new();

        let mut reader = Builder::new();
        reader.read(
            &Message::Sync(SyncMsg {
                locked: None,
                double: Some(cert_from_view(1.into())),
            })
            .encode_to_bytes()
            .await
            .unwrap(),
        );
        reader.read(
            &Message::Sync(SyncMsg {
                locked: None,
                double: Some(cert_from_view(2.into())),
            })
            .encode_to_bytes()
            .await
            .unwrap(),
        );
        let mut writer = Builder::new();
        writer.write(
            &Message::Sync(history.sync_state())
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
        assert_ok!(sync_initiate(&ctx, &Mutex::new(history), &cnt, stream).await);
        assert_eq!(cnt.msgs.load(Ordering::Relaxed), 2);
    }
}
