#![allow(dead_code)]

use bit_vec::BitVec;

use crate::sequential as seq;
use crate::sequential::Action as action;
use crate::types::*;

struct Tester {
    keys: Vec<PrivateKey>,
    genesis: Certificate<Vote>,
}

impl Tester {
    fn new(n: usize) -> Self {
        let mut keys: Vec<_> = (0..n).map(|_| PrivateKey::random()).collect();
        keys.sort_by(|a, b| a.public().cmp(&b.public()));

        let genesis = Certificate {
            inner: Vote {
                view: View(0),
                block: Block::new(0, ID::new([0; 32])),
            },
            signature: PrivateKey::random().sign(Domain::Vote, &[0; 32]).into(),
            signers: BitVec::new(),
        };
        Self { keys, genesis }
    }

    fn genesis(&self) -> Certificate<Vote> {
        self.genesis.clone()
    }

    fn active(&self, i: usize) -> seq::Consensus {
        seq::Consensus::new(
            View(0),
            self.publics(),
            self.genesis(),
            self.genesis(),
            View(0),
            &self.keys[i..i + 1],
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

    fn publics(&self) -> Vec<PublicKey> {
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
            signers: bitvec,
        }
    }

    fn certify_vote(
        &self,
        view: View,
        height: u64,
        id: &str,
        signers: Vec<Signer>,
    ) -> Certificate<Vote> {
        let vote = Vote {
            view,
            block: {
                let mut _id = [0; 32];
                _id[..id.len()].copy_from_slice(id.as_bytes());
                Block::new(height, ID::new(_id))
            },
        };
        self.certify(Domain::Vote, signers, &vote)
    }

    fn certify_vote2(
        &self,
        view: View,
        height: u64,
        id: &str,
        signers: Vec<Signer>,
    ) -> Certificate<Vote> {
        let vote = Vote {
            view,
            block: {
                let mut _id = [0; 32];
                _id[..id.len()].copy_from_slice(id.as_bytes());
                Block::new(height, ID::new(_id))
            },
        };
        self.certify(Domain::Vote2, signers, &vote)
    }
}

impl Tester {
    fn prepare(&self, view: View, height: u64, id: &str, signers: Vec<Signer>) -> Message {
        let vote = Vote {
            view,
            block: {
                let mut _id = [0; 32];
                _id[..id.len()].copy_from_slice(id.as_bytes());
                Block::new(height, ID::new(_id))
            },
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
            block: {
                let mut _id = [0; 32];
                _id[..id.len()].copy_from_slice(id.as_bytes());
                Block::new(1, ID::new(_id))
            },
            locked: self.genesis(),
            double: self.genesis(),
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
        id: &str,
        locked: Certificate<Vote>,
        double: Certificate<Vote>,
    ) -> Message {
        let block = {
            let mut _id = [0; 32];
            _id[..id.len()].copy_from_slice(id.as_bytes());
            Block::new(height, ID::new(_id))
        };
        let propose = Propose {
            view,
            block,
            locked,
            double,
        };
        let leader = self.leader(view);
        let signature = self.sign(Domain::Propose, leader, &propose);
        Message::Propose(Signed {
            inner: propose,
            signer: leader,
            signature: signature,
        })
    }

    fn vote(&self, view: View, height: u64, id: &str, signer: Signer) -> Message {
        let block = {
            let mut _id = [0; 32];
            _id[..id.len()].copy_from_slice(id.as_bytes());
            Block::new(height, ID::new(_id))
        };
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
        id: &str,
        signer: Signer,
        signers: Vec<Signer>,
    ) -> Message {
        let block = {
            let mut _id = [0; 32];
            _id[..id.len()].copy_from_slice(id.as_bytes());
            Block::new(height, ID::new(_id))
        };
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
        Message::Sync(Sync { locked, double })
    }
}

struct Instance {
    consensus: seq::Consensus,
    signer: Signer,
}

impl Instance {
    fn bootstrap(&mut self, tester: &Tester, view: View, id: &str) {
        self.on_message(tester.timeout(view, vec![0, 1, 2]));
        self.reset_ticks();
        self.wait_delay();
        self.send(tester.sync_genesis());
        self.on_message(tester.propose_first(view, id));
        self.action(action::voted(view));
        self.send(tester.vote(view, 1, id, self.signer));
        self.on_message(tester.prepare(view, 1, id, vec![0, 1, 2]));
        self.lock(tester.certify_vote(view, 1, id, vec![0, 1, 2]));
        self.send(tester.vote2(view, 1, id, self.signer, vec![0, 1, 2]));
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
        self.consensus.on_tick();
    }

    fn on_delay(&mut self) {
        self.consensus.on_delay();
    }

    fn on_propose(&mut self, id: &str) {
        let mut _id = [0; 32];
        _id[..id.len()].copy_from_slice(id.as_bytes());
        self.consensus.propose(Some(ID::new(_id))).expect("ERROR");
    }

    fn send(&mut self, message: Message) {
        self.action(seq::Action::Send(message));
    }

    fn lock(&mut self, lock: Certificate<Vote>) {
        self.action(seq::Action::Lock(lock));
    }

    fn commit(&mut self, commit: Certificate<Vote>) {
        self.action(seq::Action::Commit(commit));
    }

    fn voted(&mut self, view: View) {
        self.action(action::voted(view));
    }

    fn reset_ticks(&mut self) {
        self.action(seq::Action::reset_ticks());
    }

    fn wait_delay(&mut self) {
        self.action(seq::Action::wait_delay());
    }

    fn action(&mut self, action: seq::Action) {
        assert_eq!(self.consensus.actions.drain(0..1).next(), Some(action));
    }

    fn actions(&mut self, actions: Vec<seq::Action>) {
        for action in actions {
            self.action(action);
        }
    }

    fn no_actions(&mut self) {
        assert_eq!(self.consensus.actions, vec![]);
    }

    fn drain_actions(&mut self) {
        let _ = self.consensus.actions.drain(0..);
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

    fn send(&mut self, message: Message) {
        self.action(seq::Action::Send(message));
    }

    fn actions(&mut self, actions: Vec<seq::Action>) {
        self.0
            .iter_mut()
            .for_each(|instance| instance.actions(actions.clone()));
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

fn test_one(i: usize, f: impl FnOnce(&Tester, &mut Instance)) {
    let cluster = Tester::new(4);
    let mut instance = Instance {
        consensus: cluster.active(i),
        signer: i as u16,
    };
    f(&cluster, &mut instance)
}

fn test_multi(n: usize, f: impl FnOnce(&Tester, &mut Instances)) {
    let cluster = Tester::new(n);
    let instances = (0..n)
        .map(|i| Instance {
            consensus: cluster.active(i),
            signer: i as u16,
        })
        .collect::<Vec<_>>();
    f(&cluster, &mut Instances(instances))
}

#[test]
fn test_bootstrap() {
    test_one(0, |tester, inst: &mut Instance| {
        inst.bootstrap(tester, 1.into(), "a")
    });
}

#[test]
fn test_commit_one() {
    test_one(0, |tester, inst: &mut Instance| {
        inst.bootstrap(tester, 1.into(), "a");
        inst.on_message(tester.propose(
            2.into(),
            2,
            "b",
            tester.certify_vote(1.into(), 1, "a", vec![0, 1, 2]),
            tester.certify_vote2(1.into(), 1, "a", vec![0, 1, 2]),
        ));
        inst.commit(tester.certify_vote2(1.into(), 1, "a", vec![0, 1, 2]));
        inst.voted(2.into());
        inst.send(tester.vote(2.into(), 2, "b", inst.signer));
    });
}

#[test]
fn test_domain_misuse() {
    test_one(0, |tester, inst: &mut Instance| {
        inst.bootstrap(tester, 1.into(), "a");
        inst.on_message_err(tester.propose(
            2.into(),
            2,
            "b",
            tester.certify_vote(1.into(), 1, "a", vec![0, 1, 2]),
            tester.certify_vote(1.into(), 1, "a", vec![0, 1, 2]),
        ));
        inst.on_message_err(tester.propose(
            2.into(),
            2,
            "b",
            tester.certify_vote2(1.into(), 1, "a", vec![0, 1, 2]),
            tester.certify_vote2(1.into(), 1, "a", vec![0, 1, 2]),
        ));
    });
}

#[test]
fn test_multi_bootstrap() {
    test_multi(4, |tester, instances: &mut Instances| {
        instances.on_tick();
        instances.for_each(|i| i.action(action::send(tester.wish(1.into(), i.signer))));
        instances.on_message(tester.timeout(1.into(), vec![0, 1, 3]));
        instances.action(action::reset_ticks());
        instances.action(action::wait_delay());
        instances.action(action::send(tester.sync_genesis()));
        instances.on_delay();
        instances.leader(1.into()).action(action::propose());

        instances.no_actions();

        instances.leader(1.into()).on_propose("a");
        instances
            .leader(1.into())
            .action(action::send(tester.propose_first(1.into(), "a")));
        instances.on_message(tester.propose_first(1.into(), "a"));
        instances.action(action::voted(1.into()));

        let votes = instances
            .0
            .iter_mut()
            .map(|i| {
                let vote = tester.vote(1.into(), 1, "a", i.signer);
                i.action(action::send(vote.clone()));
                vote
            })
            .collect::<Vec<_>>();

        instances.no_actions();

        votes.into_iter().for_each(|v| {
            instances.leader(1.into()).on_message(v);
        });
        instances
            .leader(1.into())
            .send(tester.prepare(1.into(), 1, "a", vec![0, 1, 2]));
        instances.on_message(tester.prepare(1.into(), 1, "a", vec![0, 1, 2]));
        instances.action(action::lock(tester.certify_vote(
            1.into(),
            1,
            "a",
            vec![0, 1, 2],
        )));
        instances
            .map(|i| {
                let vote = tester.vote2(1.into(), 1, "a", i.signer, vec![0, 1, 2]);
                i.action(action::send(vote.clone()));
                vote
            })
            .into_iter()
            .for_each(|v| instances.leader(2.into()).on_message(v));

        let leader2 = instances.leader(2.into());
        leader2.action(action::propose());
        leader2.on_propose("b");
        leader2.action(action::send(tester.propose(
            2.into(),
            2,
            "b",
            tester.certify_vote(1.into(), 1, "a", vec![0, 1, 2]),
            tester.certify_vote2(1.into(), 1, "a", vec![0, 1, 2]),
        )));

        instances.no_actions();
    })
}
