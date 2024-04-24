#![allow(dead_code)]

use std::fmt::Debug;

use crate::sequential::testing::GENESIS;
use crate::sequential::{
    self as seq, OnDelay, OnMessage, Proposer, StateChange, LEADER_TIMEOUT_DELAY,
};
use crate::types::*;

use bit_vec::BitVec;
use proptest::prelude::*;
use rand::thread_rng;

type Consensus = seq::Consensus<seq::testing::Sink>;

struct Tester {
    keys: Vec<PrivateKey>,
    genesis: Certificate<Vote>,
}

impl Tester {
    fn new(n: usize) -> Self {
        Self {
            keys: seq::testing::privates(n),
            genesis: seq::testing::genesis(),
        }
    }

    fn keys(&self) -> Vec<PrivateKey> {
        self.keys.clone()
    }

    fn genesis(&self) -> Certificate<Vote> {
        self.genesis.clone()
    }

    fn active(&self, i: usize) -> Consensus {
        seq::Consensus::new(
            View(0),
            self.publics(),
            self.genesis(),
            self.genesis(),
            View(0),
            &self.keys[i..i + 1],
            seq::testing::Sink::new(),
        )
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
    actions: Vec<seq::Event>,
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
        self.consensus.is_leader(view)
    }

    fn on_message(&mut self, message: Message) {
        self.consensus.on_message(message).expect("message:");
    }

    fn on_message_err(&mut self, message: Message) {
        self.consensus
            .on_message(message)
            .expect_err("expected to fail");
    }

    fn on_tick(&mut self) {
        (0..seq::TIMEOUT).for_each(|_| self.on_delay());
    }

    fn on_delay(&mut self) {
        self.consensus.on_delay();
    }

    fn on_propose(&mut self, id: &str) {
        self.consensus.propose(ID::from_str(id)).expect("ERROR");
    }

    fn send_all(&mut self, message: Message) {
        self.action(seq::Event::Send(message, None));
    }

    fn send_one(&mut self, message: Message, to: Signer) {
        let public = self.consensus.public_key_by_index(to);
        self.action(seq::Event::Send(message, Some(public)));
    }

    fn state_change(
        &mut self,
        lock: Option<Certificate<Vote>>,
        commit: Option<Certificate<Vote>>,
        voted: Option<View>,
        timeout: Option<Certificate<View>>,
    ) {
        self.action(seq::Event::StateChange(StateChange {
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
        self.action(seq::Event::Propose);
    }

    fn consume_actions(&mut self) {
        for action in self.consensus.events().drain() {
            self.actions.push(action);
        }
    }

    fn action(&mut self, action: seq::Event) {
        self.consume_actions();
        assert_eq!(self.actions.drain(0..1).next(), Some(action));
    }

    fn actions(&mut self) -> Vec<seq::Event> {
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

    fn action(&mut self, action: seq::Event) {
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

    fn honest_actions(&mut self, i: usize, inst: &mut Instance) -> bool {
        self.follow_protocol(i, inst);
        let mut acted = true;
        for a in inst.actions() {
            acted = false;
            match a {
                seq::Event::Send(m, _) => self
                    .inputs
                    .iter_mut()
                    .for_each(|input| input.push(m.clone())),
                seq::Event::Propose => {
                    self.propose[i] = Some(thread_rng().gen::<[u8; 32]>());
                }
                seq::Event::StateChange(change) => {
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
                _ = inst.consensus.on_message(m.clone());
            });
            msgs.clear();
        }
        inst.on_delay();
        if let Some(p) = self.propose[i].take() {
            inst.consensus.propose(ID::new(p)).expect("no error");
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
