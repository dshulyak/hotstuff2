use std::time::Duration;

use bit_vec::BitVec;
use hotstuff2::sequential::{Action, Actions, Consensus, OnDelay, OnMessage, Proposer};
use hotstuff2::types::{AggregateSignature, Block, Certificate, Message, View, Vote, ID};
use parking_lot::Mutex;
use tokio::select;
use tokio::sync::mpsc;
use tokio::time::{interval, sleep};

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
    let mut interval = interval(network_delay);
    loop {
        select! {
            _ = interval.tick() => {
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
