use std::time::Duration;

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
use crate::quinnext::MsgStream;
use crate::router::Router;

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

pub(crate) async fn sync_accept(ctx: &Context, history: &Mutex<History>, mut stream: MsgStream) {
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
    use std::sync::atomic::{AtomicUsize, Ordering};

    use tokio::{
        spawn,
        time::{self, timeout},
    };

    use super::*;

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
}
