#![allow(dead_code)]

use std::cell::RefCell;
use std::fmt::Debug;
use std::rc::Rc;

use crate::sequential::{
    self as seq, Actions, OnDelay, OnMessage, Proposer, StateChange, LEADER_TIMEOUT_DELAY,
};
use crate::types::*;

use bit_vec::BitVec;
use parking_lot::Mutex;
use proptest::prelude::*;
use proptest::sample::{subsequence, Subsequence};
use proptest::test_runner::{Config, TestRunner};
use rand::thread_rng;

#[derive(Debug)]
struct DequeSink {
    pub actions: Mutex<Vec<seq::Action>>,
}

impl DequeSink {
    fn new() -> Self {
        Self {
            actions: Mutex::new(Vec::new()),
        }
    }

    fn drain(&self) -> Vec<seq::Action> {
        self.actions.lock().drain(..).collect()
    }
}

impl Actions for Rc<DequeSink> {
    fn send(&self, action: seq::Action) {
        self.actions.lock().push(action);
    }
}

#[derive(Debug)]
struct Consensus {
    c: seq::Consensus<Rc<DequeSink>>,
    sink: Rc<DequeSink>,
}

struct Tester {
    keys: Vec<PrivateKey>,
    genesis: Certificate<Vote>,
}

pub(crate) fn gen_keys(n: usize) -> Vec<PrivateKey> {
    let mut keys: Vec<_> = (0..n)
        .map(|_| {
            let seed = thread_rng().gen::<[u8; 32]>();
            PrivateKey::from_seed(&seed)
        })
        .collect();
    keys.sort_by(|a, b| a.public().cmp(&b.public()));
    keys
}

const GENESIS: &str = "genesis";

pub(crate) fn gen_genesis() -> Certificate<Vote> {
    Certificate {
        inner: Vote {
            view: 0.into(),
            block: Block::new(0, ID::default(), GENESIS.into()),
        },
        signature: AggregateSignature::empty(),
        signers: BitVec::new().into(),
    }
}

impl Tester {
    fn new(n: usize) -> Self {
        Self {
            keys: gen_keys(n),
            genesis: gen_genesis(),
        }
    }

    fn keys(&self) -> Vec<PrivateKey> {
        self.keys.clone()
    }

    fn genesis(&self) -> Certificate<Vote> {
        self.genesis.clone()
    }

    fn active(&self, i: usize) -> Consensus {
        let deq = Rc::new(DequeSink::new());
        let c = seq::Consensus::new(
            View(0),
            self.publics(),
            self.genesis(),
            self.genesis(),
            View(0),
            &self.keys[i..i + 1],
            deq.clone(),
        );
        Consensus { c, sink: deq }
    }

    fn leader(&self, view: View) -> Signer {
        let index = view % self.keys.len() as u64;
        index as Signer
    }

    fn sign<T: ToBytes>(&self, domain: Domain, signer: Signer, message: &T) -> Signature {
        let key = &self.keys[signer as usize];
        key.sign(domain, &message.to_bytes())
    }

    fn publics(&self) -> Box<[PublicKey]> {
        self.keys.iter().map(|key| key.public()).collect()
    }

    fn certify<T: ToBytes + Clone>(
        &self,
        domain: Domain,
        signers: Vec<Signer>,
        message: &T,
    ) -> Certificate<T> {
        let signatures = signers
            .iter()
            .map(|signer| self.sign(domain.clone(), *signer, message))
            .collect::<Vec<_>>();
        let aggregated =
            AggregateSignature::aggregate(signatures.iter()).expect("failed to aggregate");
        let mut bitvec = BitVec::from_elem(self.keys.len(), false);
        for signer in signers {
            bitvec.set(signer as usize, true);
        }
        Certificate {
            inner: message.clone(),
            signature: aggregated,
            signers: bitvec.into(),
        }
    }

    fn certify_view(&self, view: View, signers: Vec<Signer>) -> Certificate<View> {
        self.certify(Domain::Wish, signers, &view)
    }

    fn certify_vote(
        &self,
        view: View,
        height: u64,
        prev: &str,
        id: &str,
        signers: Vec<Signer>,
    ) -> Certificate<Vote> {
        let vote = Vote {
            view,
            block: Block::new(height, prev.into(), id.into()),
        };
        self.certify(Domain::Vote, signers, &vote)
    }

    fn certify_vote2(
        &self,
        view: View,
        height: u64,
        prev: &str,
        id: &str,
        signers: Vec<Signer>,
    ) -> Certificate<Vote> {
        let vote = Vote {
            view,
            block: Block::new(height, ID::from_str(prev), ID::from_str(id)),
        };
        self.certify(Domain::Vote2, signers, &vote)
    }
}

impl Tester {
    fn prepare(
        &self,
        view: View,
        height: u64,
        prev: &str,
        id: &str,
        signers: Vec<Signer>,
    ) -> Message {
        let vote = Vote {
            view,
            block: Block::new(height, ID::from_str(prev), ID::from_str(id)),
        };
        let certificate = self.certify(Domain::Vote, signers, &vote);
        let prepare = Prepare { certificate };
        let leader = self.leader(view);
        let signature = self.sign(Domain::Prepare, leader, &prepare);
        Message::Prepare(Signed {
            inner: prepare,
            signer: leader,
            signature: signature,
        })
    }

    fn propose_first(&self, view: View, id: &str) -> Message {
        let propose = Propose {
            view,
            block: Block::new(1, GENESIS.into(), ID::from_str(id)),
            locked: self.genesis(),
            commit: self.genesis(),
        };
        let leader = self.leader(view);
        let signature = self.sign(Domain::Propose, leader, &propose);
        Message::Propose(Signed {
            inner: propose,
            signer: leader,
            signature: signature,
        })
    }

    fn propose(
        &self,
        view: View,
        height: u64,
        prev: &str,
        id: &str,
        locked: Certificate<Vote>,
        double: Certificate<Vote>,
    ) -> Message {
        let block = Block::new(height, ID::from_str(prev), ID::from_str(id));
        let propose = Propose {
            view,
            block,
            locked,
            commit: double,
        };
        let leader = self.leader(view);
        let signature = self.sign(Domain::Propose, leader, &propose);
        Message::Propose(Signed {
            inner: propose,
            signer: leader,
            signature: signature,
        })
    }

    fn vote(&self, view: View, height: u64, prev: &str, id: &str, signer: Signer) -> Message {
        let block = Block::new(height, prev.into(), id.into());
        let vote = Vote { view, block };
        let signature = self.sign(Domain::Vote, signer, &vote);
        Message::Vote(Signed {
            inner: vote,
            signer,
            signature,
        })
    }

    fn vote2(
        &self,
        view: View,
        height: u64,
        prev: &str,
        id: &str,
        signer: Signer,
        signers: Vec<Signer>,
    ) -> Message {
        let block = Block::new(height, prev.into(), id.into());
        let vote = Vote { view, block };
        let cert = self.certify(Domain::Vote, signers, &vote);
        let signature = self.sign(Domain::Vote2, signer, &vote);
        Message::Vote2(Signed {
            inner: cert,
            signer,
            signature,
        })
    }

    fn wish(&self, view: View, signer: Signer) -> Message {
        let wish = Wish { view };
        let signature = self.sign(Domain::Wish, signer, &wish);
        Message::Wish(Signed {
            inner: wish,
            signer,
            signature,
        })
    }

    fn timeout(&self, view: View, signers: Vec<Signer>) -> Message {
        let certificate = self.certify(Domain::Wish, signers, &view);
        Message::Timeout(Timeout { certificate })
    }

    fn sync_genesis(&self) -> Message {
        self.sync(Some(self.genesis()), Some(self.genesis()))
    }

    fn sync(
        &self,
        locked: Option<Certificate<Vote>>,
        double: Option<Certificate<Vote>>,
    ) -> Message {
        Message::Sync(Sync {
            locked,
            commit: double,
        })
    }
}

#[derive(Debug)]
struct Instance {
    consensus: Consensus,
    signer: Signer,
    actions: Vec<seq::Action>,
}

impl Instance {
    // bootstrap enter specified view and generates lock verificate in that view for block with id
    fn bootstrap(&mut self, tester: &Tester, view: View, id: &str) {
        self.on_message(tester.timeout(view, vec![0, 1, 2]));
        self.send_one(tester.sync_genesis(), 1);
        self.on_message(tester.propose_first(view, id));
        self.timeout(tester.certify_view(view, vec![0, 1, 2]));
        self.voted(view);
        self.send_one(tester.vote(view, 1, GENESIS, id, self.signer), 1);
        self.on_message(tester.prepare(view, 1, GENESIS, id, vec![0, 1, 2]));
        self.lock(tester.certify_vote(view, 1, GENESIS, id, vec![0, 1, 2]));
        self.send_one(
            tester.vote2(view, 1, GENESIS, id, self.signer, vec![0, 1, 2]),
            2,
        );
        self.no_actions();
    }

    fn is_leader(&self, view: View) -> bool {
        self.consensus.c.is_leader(view)
    }

    fn on_message(&mut self, message: Message) {
        self.consensus.c.on_message(message).expect("message:");
    }

    fn on_message_err(&mut self, message: Message) {
        self.consensus
            .c
            .on_message(message)
            .expect_err("expected to fail");
    }

    fn on_tick(&mut self) {
        (0..seq::TIMEOUT).for_each(|_| self.on_delay());
    }

    fn on_delay(&mut self) {
        self.consensus.c.on_delay();
    }

    fn on_propose(&mut self, id: &str) {
        self.consensus.c.propose(ID::from_str(id)).expect("ERROR");
    }

    fn send_all(&mut self, message: Message) {
        self.action(seq::Action::Send(message, None));
    }

    fn send_one(&mut self, message: Message, to: Signer) {
        let public = self.consensus.c.public_key_by_index(to);
        self.action(seq::Action::Send(message, Some(public)));
    }

    fn state_change(
        &mut self,
        lock: Option<Certificate<Vote>>,
        commit: Option<Certificate<Vote>>,
        voted: Option<View>,
        timeout: Option<Certificate<View>>,
    ) {
        self.action(seq::Action::StateChange(StateChange {
            locked: lock,
            commit,
            voted,
            timeout,
        }));
    }

    fn lock(&mut self, lock: Certificate<Vote>) {
        self.state_change(Some(lock), None, None, None)
    }

    fn commit(&mut self, commit: Certificate<Vote>) {
        self.state_change(None, Some(commit), None, None)
    }

    fn voted(&mut self, view: View) {
        self.state_change(None, None, Some(view), None)
    }

    fn timeout(&mut self, cert: Certificate<View>) {
        self.state_change(None, None, None, Some(cert))
    }

    fn propose(&mut self) {
        self.action(seq::Action::Propose);
    }

    fn consume_actions(&mut self) {
        for action in self.consensus.sink.drain() {
            self.actions.push(action);
        }
    }

    fn action(&mut self, action: seq::Action) {
        self.consume_actions();
        assert_eq!(self.actions.drain(0..1).next(), Some(action));
    }

    fn actions(&mut self) -> Vec<seq::Action> {
        self.consume_actions();
        self.actions.drain(..).collect()
    }

    fn no_actions(&mut self) {
        self.consume_actions();
        assert_eq!(self.actions, vec![]);
    }

    fn drain_actions(&mut self) {
        self.consume_actions();
        let _ = self.actions.drain(0..);
    }
}

struct Instances(Vec<Instance>);

impl Instances {
    fn leader(&mut self, view: View) -> &mut Instance {
        self.0
            .iter_mut()
            .filter(|instance| instance.is_leader(view))
            .next()
            .unwrap()
    }

    fn on_message(&mut self, message: Message) {
        self.0
            .iter_mut()
            .for_each(|instance| instance.on_message(message.clone()));
    }

    fn on_tick(&mut self) {
        self.0.iter_mut().for_each(|instance| instance.on_tick());
    }

    fn on_delay(&mut self) {
        self.0.iter_mut().for_each(|instance| instance.on_delay());
    }

    fn action(&mut self, action: seq::Action) {
        self.0
            .iter_mut()
            .for_each(|instance| instance.action(action.clone()));
    }

    fn lock(&mut self, lock: Certificate<Vote>) {
        self.0
            .iter_mut()
            .for_each(|instance| instance.lock(lock.clone()));
    }

    fn voted(&mut self, view: View) {
        self.0.iter_mut().for_each(|instance| instance.voted(view));
    }

    fn timeout(&mut self, cert: Certificate<View>) {
        self.0
            .iter_mut()
            .for_each(|instance| instance.timeout(cert.clone()));
    }

    fn send_all(&mut self, message: Message) {
        self.0
            .iter_mut()
            .for_each(|instance| instance.send_all(message.clone()));
    }

    fn send_one(&mut self, message: Message, to: Signer) {
        self.0
            .iter_mut()
            .for_each(|instance| instance.send_one(message.clone(), to));
    }

    fn no_actions(&mut self) {
        self.0.iter_mut().for_each(|instance| instance.no_actions());
    }

    fn drain_actions(&mut self) {
        self.0
            .iter_mut()
            .for_each(|instance| instance.drain_actions());
    }

    fn for_each(&mut self, f: impl FnMut(&mut Instance)) {
        self.0.iter_mut().for_each(f);
    }

    fn map(&mut self, f: impl FnMut(&mut Instance) -> Message) -> Vec<Message> {
        self.0.iter_mut().map(f).collect()
    }
}

fn gentest(n: usize, f: impl FnOnce(&Tester, &mut Instances)) {
    let cluster = Tester::new(n);
    let instances = (0..n)
        .map(|i| Instance {
            consensus: cluster.active(i),
            signer: i as u16,
            actions: vec![],
        })
        .collect::<Vec<_>>();
    // TODO refactor it without closure, can't recall what i was thinking
    f(&cluster, &mut Instances(instances))
}

#[test]
fn test_bootstrap() {
    gentest(4, |tester, inst: &mut Instances| {
        inst.0[0].bootstrap(tester, 1.into(), "a")
    });
}

#[test]
fn test_commit_one() {
    gentest(4, |tester, inst: &mut Instances| {
        let inst = &mut inst.0[0];
        inst.bootstrap(tester, 1.into(), "a");
        inst.on_message(tester.propose(
            2.into(),
            2,
            "a",
            "b",
            tester.certify_vote(1.into(), 1, GENESIS, "a", vec![0, 1, 2]),
            tester.certify_vote2(1.into(), 1, GENESIS, "a", vec![0, 1, 2]),
        ));
        inst.state_change(
            None,
            Some(tester.certify_vote2(1.into(), 1, GENESIS, "a", vec![0, 1, 2])),
            Some(2.into()),
            None,
        );
        inst.send_one(tester.vote(2.into(), 2, "a", "b", inst.signer), 2);
    });
}

#[test]
fn test_tick_on_epoch_boundary() {
    gentest(4, |tester, inst| {
        let inst = &mut inst.0[3];
        inst.bootstrap(tester, 1.into(), "a");
        inst.on_message(tester.propose(
            2.into(),
            2,
            "a",
            "b",
            tester.certify_vote(1.into(), 1, GENESIS, "a", vec![0, 1, 2]),
            tester.certify_vote2(1.into(), 1, GENESIS, "a", vec![0, 1, 2]),
        ));
        inst.state_change(
            None,
            Some(tester.certify_vote2(1.into(), 1, GENESIS, "a", vec![0, 1, 2])),
            Some(View(2)),
            None,
        );
        inst.drain_actions();
        inst.on_message(tester.prepare(2.into(), 2, "a", "b", vec![1, 2, 3]));
        inst.lock(tester.certify_vote(2.into(), 2, "a", "b", vec![1, 2, 3]));
        inst.drain_actions();

        inst.on_tick();
        inst.consume_actions();
        inst.send_all(tester.wish(3.into(), inst.signer));
        inst.on_message(tester.timeout(3.into(), vec![0, 1, 2]));
        let locked_b = tester.certify_vote(2.into(), 2, "a", "b", vec![1, 2, 3]);
        let double_a = tester.certify_vote2(1.into(), 1, GENESIS, "a", vec![0, 1, 2]);
        inst.send_one(
            tester.sync(Some(locked_b.clone()), Some(double_a.clone())),
            3,
        );
        (0..LEADER_TIMEOUT_DELAY).for_each(|_| inst.on_delay());
        inst.timeout(tester.certify_view(3.into(), vec![0, 1, 2]));
        inst.send_all(tester.propose(3.into(), 2, "a", "b", locked_b.clone(), double_a.clone()));
        inst.on_message(tester.propose(3.into(), 2, "a", "b", locked_b.clone(), double_a.clone()));
        inst.voted(3.into());
        inst.send_one(tester.vote(3.into(), 2, "a", "b", inst.signer), 3);
    });
}

#[test]
fn test_propose_after_delay() {
    gentest(4, |tester, instances| {
        let inst = &mut instances.0[2];
        inst.bootstrap(tester, 1.into(), "a");
        inst.on_tick();
        let locked_a = tester.certify_vote(1.into(), 1, GENESIS, "a", vec![0, 1, 2]);
        inst.send_one(
            tester.sync(Some(locked_a.clone()), Some(tester.genesis())),
            2,
        );

        inst.no_actions();
        (0..LEADER_TIMEOUT_DELAY).for_each(|_| inst.on_delay());
        inst.send_all(tester.propose(
            2.into(),
            1,
            GENESIS,
            "a",
            locked_a.clone(),
            tester.genesis(),
        ));
    })
}

#[test]
fn test_nonleader_on_delay() {
    gentest(4, |tester, instances| {
        // leaders are assigned in round-robin. 0 is leader for view 1, 1 for view 2, etc.
        let inst = &mut instances.0[0];
        inst.bootstrap(tester, 1.into(), "a");
        inst.on_tick();
        let locked_a = tester.certify_vote(1.into(), 1, GENESIS, "a", vec![0, 1, 2]);
        inst.send_one(
            tester.sync(Some(locked_a.clone()), Some(tester.genesis())),
            2,
        );
        inst.on_delay();
        inst.no_actions();
    })
}

#[test]
fn test_on_sync() {
    gentest(4, |tester, instances| {
        let inst = &mut instances.0[0];
        inst.bootstrap(tester, 1.into(), "a");
        inst.on_message(tester.sync(
            Some(tester.certify_vote(2.into(), 2, GENESIS, "a", vec![0, 1, 2])),
            Some(tester.certify_vote2(2.into(), 2, GENESIS, "a", vec![0, 1, 2])),
        ));
    })
}

#[test]
fn test_domain_misuse() {
    gentest(4, |tester, inst: &mut Instances| {
        let inst = &mut inst.0[0];

        inst.bootstrap(tester, 1.into(), "a");
        inst.on_message_err(tester.propose(
            2.into(),
            2,
            "a",
            "b",
            tester.certify_vote(1.into(), 1, GENESIS, "a", vec![0, 1, 2]),
            tester.certify_vote(1.into(), 1, GENESIS, "a", vec![0, 1, 2]),
        ));
        inst.on_message_err(tester.propose(
            2.into(),
            2,
            "a",
            "b",
            tester.certify_vote2(1.into(), 1, GENESIS, "a", vec![0, 1, 2]),
            tester.certify_vote2(1.into(), 1, GENESIS, "a", vec![0, 1, 2]),
        ));
    });
}

#[test]
fn test_aggregate_timeout() {
    gentest(4, |tester, instances| {
        let inst = &mut instances.0[1];
        (0..4)
            .map(|i| tester.wish(1.into(), i as Signer))
            .for_each(|w| inst.on_message(w));
        inst.send_all(tester.timeout(1.into(), vec![0, 1, 2]))
    })
}

#[test]
fn test_repetetive_messages() {
    gentest(4, |tester, instances| {
        let inst = &mut instances.0[2];
        inst.bootstrap(tester, 1.into(), "a");
        let locked_a = tester.certify_vote(1.into(), 1, GENESIS, "a", vec![0, 1, 2]);
        let double_a = tester.certify_vote2(1.into(), 1, GENESIS, "a", vec![0, 1, 2]);
        inst.on_message(tester.propose(2.into(), 2, "a", "b", locked_a.clone(), double_a.clone()));
        inst.on_message(tester.vote(2.into(), 2, "a", "b", 1));
        inst.on_message_err(tester.vote(2.into(), 2, "a", "b", 1));
    })
}

#[test]
fn test_multi_bootstrap() {
    gentest(4, |tester, instances: &mut Instances| {
        instances.on_tick();
        instances.for_each(|i| i.send_all(tester.wish(1.into(), i.signer)));
        instances.on_message(tester.timeout(1.into(), vec![0, 1, 3]));
        instances.send_one(tester.sync_genesis(), 1);
        (0..LEADER_TIMEOUT_DELAY).for_each(|_| instances.on_delay());
        instances.timeout(tester.certify_view(1.into(), vec![0, 1, 3]));
        instances.leader(1.into()).propose();

        instances.no_actions();

        instances.leader(1.into()).on_propose("a");
        instances
            .leader(1.into())
            .send_all(tester.propose_first(1.into(), "a"));
        instances.on_message(tester.propose_first(1.into(), "a"));
        instances.voted(1.into());

        let votes = instances
            .0
            .iter_mut()
            .map(|i| {
                let vote = tester.vote(1.into(), 1, GENESIS, "a", i.signer);
                i.send_one(vote.clone(), 1);
                vote
            })
            .collect::<Vec<_>>();

        instances.no_actions();

        votes.into_iter().for_each(|v| {
            instances.leader(1.into()).on_message(v);
        });
        instances.leader(1.into()).send_all(tester.prepare(
            1.into(),
            1,
            GENESIS,
            "a",
            vec![0, 1, 2],
        ));
        instances.on_message(tester.prepare(1.into(), 1, GENESIS, "a", vec![0, 1, 2]));
        instances.lock(tester.certify_vote(1.into(), 1, GENESIS, "a", vec![0, 1, 2]));
        instances
            .map(|i| {
                let vote = tester.vote2(1.into(), 1, GENESIS, "a", i.signer, vec![0, 1, 2]);
                i.send_one(vote.clone(), 2);
                vote
            })
            .into_iter()
            .for_each(|v| instances.leader(2.into()).on_message(v));

        let leader2 = instances.leader(2.into());
        leader2.propose();
        leader2.on_propose("b");
        leader2.send_all(tester.propose(
            2.into(),
            2,
            "a",
            "b",
            tester.certify_vote(1.into(), 1, GENESIS, "a", vec![0, 1, 2]),
            tester.certify_vote2(1.into(), 1, GENESIS, "a", vec![0, 1, 2]),
        ));

        instances.no_actions();
    })
}

struct SimState {
    inputs: Vec<Vec<Message>>,
    propose: Vec<Option<[u8; 32]>>,
    commits: Vec<Vec<Certificate<Vote>>>,
}

impl SimState {
    fn new(n: usize) -> Self {
        SimState {
            inputs: vec![vec![]; n],
            propose: vec![None; n],
            commits: vec![vec![]; n],
        }
    }

    // node will follow the protocol, except it will randomize messages that it sends out.
    // in a such way that they will appear valid, but violate more subtle rules of the protocol.
    fn randomize_messages(
        &mut self,
        tester: &Tester,
        i: usize,
        inst: &mut Instance,
        runner: &mut TestRunner,
    ) -> bool {
        self.follow_protocol(i, inst);
        let mut acted = true;
        for a in inst.actions() {
            acted = false;
            match a {
                seq::Action::Send(m, _) => {
                    send_random_messages(m, tester, i as Signer, &mut self.inputs, runner)
                }
                // seq::Action::WaitDelay => self.wait_delay[i] = true,
                seq::Action::Propose => {
                    self.propose[i] = Some(thread_rng().gen::<[u8; 32]>());
                }
                seq::Action::StateChange(change) => {
                    if let Some(commit) = change.commit {
                        self.commits[i].push(commit);
                    }
                }
            }
        }
        acted
    }

    fn honest_actions(&mut self, i: usize, inst: &mut Instance) -> bool {
        self.follow_protocol(i, inst);
        let mut acted = true;
        for a in inst.actions() {
            acted = false;
            match a {
                seq::Action::Send(m, _) => self
                    .inputs
                    .iter_mut()
                    .for_each(|input| input.push(m.clone())),
                seq::Action::Propose => {
                    self.propose[i] = Some(thread_rng().gen::<[u8; 32]>());
                }
                seq::Action::StateChange(change) => {
                    if let Some(commit) = change.commit {
                        self.commits[i].push(commit);
                    }
                }
            }
        }
        acted
    }

    fn follow_protocol(&mut self, i: usize, inst: &mut Instance) {
        {
            let msgs = &mut self.inputs[i];
            msgs.iter().for_each(|m| {
                _ = inst.consensus.c.on_message(m.clone());
            });
            msgs.clear();
        }
        inst.on_delay();
        if let Some(p) = self.propose[i].take() {
            inst.consensus.c.propose(ID::new(p)).expect("no error");
        }
    }
}

fn send_random_messages(
    original: Message,
    tester: &Tester,
    signer: Signer,
    inputs: &mut Vec<Vec<Message>>,
    runner: &mut TestRunner,
) {
    let inputs = RefCell::new(inputs);
    match original {
        Message::Wish(w) => {
            let _ = runner.run(
                &(prop_oneof![Just(w.inner.view), Just(w.inner.view + 1)]),
                |view| {
                    let wish = Wish { view };
                    let signature = tester.sign(Domain::Wish, signer, &wish);
                    let msg = Message::Wish(Signed {
                        inner: wish,
                        signer: signer,
                        signature,
                    });
                    inputs.borrow_mut().iter_mut().for_each(|input| {
                        input.push(msg.clone());
                    });
                    Ok(())
                },
            );
        }
        Message::Vote(v) => {
            let _ = runner.run(
                &(
                    Just(v.inner.view),
                    Just(v.inner.block.height),
                    Just(v.inner.block.prev),
                    prop_oneof![
                        Just(v.inner.block.id),
                        any::<[u8; 32]>().prop_map(|id| ID::new(id)),
                    ],
                ),
                |(view, height, prev, id)| {
                    let vote = Vote {
                        view,
                        block: Block { height, prev, id },
                    };
                    let signature = tester.sign(Domain::Vote, signer, &vote);
                    let msg = Message::Vote(Signed {
                        inner: vote,
                        signer: signer,
                        signature,
                    });
                    inputs.borrow_mut().iter_mut().for_each(|input| {
                        input.push(msg.clone());
                    });
                    Ok(())
                },
            );
        }
        Message::Vote2(v) => {
            let _ = runner.run(
                &(prop_oneof![
                    cert_strat(
                        Just(v.inner.inner.clone()),
                        Just(Domain::Vote),
                        keys_strat(tester.keys().clone(), 2),
                    ),
                    Just(v.inner.clone()),
                ]),
                |cert| {
                    let signature = tester.sign(Domain::Vote2, signer, &cert.inner);
                    let msg = Message::Vote2(Signed {
                        inner: cert,
                        signer,
                        signature,
                    });
                    inputs.borrow_mut().iter_mut().for_each(|input| {
                        input.push(msg.clone());
                    });
                    Ok(())
                },
            );
        }
        _ => {
            inputs.borrow_mut().iter_mut().for_each(|input| {
                input.push(original.clone());
            });
        }
    }
}

#[test]
fn test_simulation_honest() {
    gentest(4, |_, instances| {
        let mut sim = SimState::new(instances.0.len());
        for _r in 0..28 {
            for (i, inst) in instances.0.iter_mut().enumerate() {
                sim.honest_actions(i, inst);
            }
        }
        let commit = &sim.commits[0];
        assert_eq!(sim.commits.len(), 4);
        for other in sim.commits.iter() {
            assert_eq!(other, commit);
        }
    });
}

#[test]
fn test_simulation_unavailable() {
    // in this test one of the nodes (4th, last node) will not be voting or performing aggregation when it is a leader.
    // nodes are expected to time out on the turn of this node.
    gentest(4, |_, instances| {
        let steps = 40;
        let expected_height = 3;

        // disconnecting node is a realized by taking a slice of all instances,
        // while every node is a aware of full set of instances.
        let working = &mut instances.0[..3];
        let mut sim = SimState::new(working.len());
        for _r in 0..steps {
            for (i, inst) in working.iter_mut().enumerate() {
                sim.honest_actions(i, inst);
            }
        }
        let commit = &sim.commits[0];
        assert_eq!(sim.commits.len(), expected_height);
        for other in sim.commits.iter() {
            assert_eq!(other, commit);
        }
    });
}

#[test]
fn test_simulation_with_adversary() {
    gentest(4, |tester, instances| {
        let adversary = 3;
        let mut sim = SimState::new(instances.0.len());
        for _r in 0..32 {
            let mut no_actions = true;
            let mut runner = TestRunner::new(Config {
                cases: 10, // 10 random actions per single adversary action
                ..Config::default()
            });
            for (i, inst) in instances.0.iter_mut().enumerate() {
                if i == adversary {
                    if !sim.randomize_messages(tester, i, inst, &mut runner) {
                        no_actions = false;
                    }
                } else {
                    if !sim.honest_actions(i, inst) {
                        no_actions = false;
                    }
                }
            }
            if no_actions {
                for inst in instances.0.iter_mut() {
                    inst.on_tick();
                }
            }
        }
        assert_eq!(sim.commits.len(), 4);
        let first = &sim.commits[0];
        for other in sim.commits.iter() {
            assert_eq!(first.len(), other.len());
            for (a, b) in first.iter().zip(other.iter()) {
                assert_eq!(a, b);
            }
        }
    });
}

#[test]
fn test_simulation_with_partition() {
    // in this test some messages are not delivered or delivered only to the part of the cluster.
    // todo!("like the test above but where honest nodes don't receive messages, but can sync");
}

fn domain_strat() -> impl Strategy<Value = Domain> {
    prop_oneof![
        Just(Domain::Prepare),
        Just(Domain::Vote),
        Just(Domain::Vote2),
        Just(Domain::Propose),
        Just(Domain::Wish),
        Just(Domain::Possesion),
    ]
}

fn wish_strat(
    views: impl Strategy<Value = u64>,
    domains: impl Strategy<Value = Domain>,
    keys: Vec<PrivateKey>,
) -> impl Strategy<Value = Message> {
    (views, domains, 0..keys.len()).prop_map(move |(view, domain, signer)| {
        let msg = Wish { view: View(view) };
        let signature = keys[signer].sign(domain, &msg.to_bytes());
        Message::Wish(Signed {
            inner: msg,
            signer: signer as Signer,
            signature,
        })
    })
}

fn vote_strat(
    views: impl Strategy<Value = u64>,
    keys: Vec<PrivateKey>,
) -> impl Strategy<Value = Message> {
    (
        views,
        0..keys.len(),
        any::<u64>(),
        any::<[u8; 32]>(),
        any::<[u8; 32]>(),
    )
        .prop_map(move |(view, signer, height, prev, id)| {
            let msg = Vote {
                view: View(view),
                block: Block::new(height, prev.into(), id.into()),
            };
            let signature = keys[signer].sign(Domain::Vote, &msg.to_bytes());
            Message::Vote(Signed {
                inner: msg,
                signer: signer as Signer,
                signature,
            })
        })
}

fn cert_strat<T: ToBytes + Debug>(
    msgs: impl Strategy<Value = T>,
    domains: impl Strategy<Value = Domain>,
    keys: Subsequence<(u16, PrivateKey)>,
) -> impl Strategy<Value = Certificate<T>> {
    (msgs, domains, keys).prop_map(|(msg, domain, signers)| {
        let max = signers.iter().map(|(s, _)| *s).max().unwrap_or(0) + 1;
        let mut bits = BitVec::from_elem(max.into(), false);
        signers.iter().for_each(|(s, _)| {
            bits.set((*s).into(), true);
        });
        let signatures: Vec<_> = signers
            .into_iter()
            .map(|(_, key)| key.sign(domain.clone(), &msg.to_bytes()))
            .collect();
        let aggregated = AggregateSignature::aggregate(&signatures).expect("failed to aggregate");
        Certificate {
            inner: msg,
            signers: bits.into(),
            signature: aggregated,
        }
    })
}

fn keys_strat(keys: Vec<PrivateKey>, bound: usize) -> Subsequence<(u16, PrivateKey)> {
    let signers = keys
        .into_iter()
        .enumerate()
        .map(|(signer, pk)| (signer as Signer, pk))
        .collect::<Vec<_>>();
    subsequence(signers.clone(), bound)
}

#[test]
fn test_random_messages() {
    let mut runner = TestRunner::default();
    let keys = (10..20)
        .map(|i: i32| {
            let mut seed = [0; 32];
            seed[..4].copy_from_slice(&i.to_le_bytes());
            PrivateKey::from_seed(&seed)
        })
        .collect::<Vec<_>>();

    gentest(4, |tester, inst: &mut Instances| {
        let inst = RefCell::new(&mut inst.0[0]);
        inst.borrow_mut().bootstrap(tester, View(1), "a");
        runner
            .run(
                &(prop_oneof![
                    vote_strat(any::<u64>(), keys.clone()),
                    vote_strat(Just(2), tester.keys()),
                    wish_strat(Just(2), Just(Domain::Wish), keys.clone()),
                    wish_strat(Just(0), Just(Domain::Wish), tester.keys()),
                    wish_strat(
                        any::<u64>(),
                        prop_oneof![
                            Just(Domain::Prepare),
                            Just(Domain::Vote),
                            Just(Domain::Vote2),
                            Just(Domain::Propose),
                            Just(Domain::Possesion),
                        ],
                        tester.keys()
                    ),
                    cert_strat(
                        Just(View(2)),
                        Just(Domain::Wish),
                        keys_strat(tester.keys().clone(), 4)
                    )
                    .prop_map(|certificate| { Message::Timeout(Timeout { certificate }) }),
                    cert_strat(
                        Just(View(2)),
                        Just(Domain::Vote),
                        keys_strat(tester.keys().clone(), 3)
                    )
                    .prop_map(|certificate| { Message::Timeout(Timeout { certificate }) }),
                ]),
                |msg| {
                    inst.borrow_mut().on_message_err(msg);
                    Ok(())
                },
            )
            .unwrap();
    })
}
