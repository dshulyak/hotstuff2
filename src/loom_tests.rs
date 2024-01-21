use crate::sequential::{Action, ActionSink, Consensus};
use crate::tests::{gen_genesis, gen_keys};
use crate::types::View;

use loom::sync::mpsc::{channel, Receiver, Sender};
use loom::sync::Arc;
use loom::thread;

#[derive(Debug)]
struct LoomSink {
    sender: Sender<Action>,
    receiver: Receiver<Action>,
}

impl ActionSink for LoomSink {
    fn new() -> Self {
        let (sender, receiver) = channel();
        Self { sender, receiver }
    }
    fn send(&self, action: Action) {
        self.sender.send(action).unwrap();
    }
}

type LConsensus = Consensus<LoomSink>;

#[test]
fn test_timeout() {
    loom::model(|| {});
}
